//! `ccwm serve`: startup sequence, background discovery, graceful shutdown.
//!
//! Order matters. Landlock is applied on the main thread before the Tokio runtime (and therefore any
//! other thread) exists, because it only confines the calling thread and threads created afterwards.

use crate::activity::Classifier;
use crate::clock::{Clock, SystemClock};
use crate::config::{validate_port, Config};
use crate::db::queries;
use crate::db::reader::{Reader, POOL_SIZE};
use crate::db::writer::Writer;
use crate::discovery::mounts::current_fuse_mount_points;
use crate::discovery::status::SharedStatus;
use crate::discovery::walk::ScanOptions;
use crate::error::{Error, Result};
use crate::events::Notifier;
use crate::git::{find_on_path, Git};
use crate::instance::{remove_instance, write_instance, InstanceInfo, InstanceLock};
use crate::paths::{self, current_home, Dirs, EnvVars, Owner};
use crate::sandbox::{self, Policy, SandboxReport};
use crate::service::{Deps, Service, VERSION};
use crate::tracker::{Settings as TrackerSettings, Tracker};
use crate::watch as watch_engine;
use crate::watch::{Monitor, Settings as WatchSettings, SharedMonitor, WatchBackend};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Default, Clone)]
pub struct ServeArgs {
    pub port: Option<u16>,
    pub config: Option<PathBuf>,
}

pub fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("CCWM_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    // Under systemd, journald adds the timestamp; keep lines plain and colour-free there.
    let under_journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(!under_journald && std::env::var_os("NO_COLOR").is_none());
    if under_journald {
        builder.without_time().init();
    } else {
        builder.init();
    }
}

/// Expired browser sessions are purged this often (and once at startup).
const SESSION_PURGE_INTERVAL: Duration = Duration::from_secs(3600);

/// Everything `run` needs that was resolved on the main thread before the sandbox was applied.
struct Prepared {
    uid: u32,
    dirs: Dirs,
    config: Config,
    /// The configuration file as loaded (without command-line overrides): what Settings edits.
    file_config: Config,
    config_path: PathBuf,
    roots: Vec<PathBuf>,
    home: PathBuf,
    session_dir: PathBuf,
    /// The hard boundaries of discovery and watching, in their literal and canonical spellings.
    boundaries: Vec<PathBuf>,
    policy: Policy,
    report: SandboxReport,
    peer_lookup: crate::http::peer::PeerUidLookup,
    peer_method: &'static str,
}

/// Run the daemon until SIGTERM/SIGINT. Called on the main thread.
pub fn serve(args: &ServeArgs) -> Result<()> {
    let uid = nix::unistd::geteuid();
    if uid.is_root() {
        return Err(Error::new(
            "refusing to run as root: run ccwm as your normal user",
        ));
    }
    let uid = uid.as_raw();
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    let home = current_home(uid)?;
    let owner = Owner::current(uid);
    let env = EnvVars::from_process();
    let dirs = Dirs::resolve(&env, &home);
    dirs.ensure(&owner)?;

    // Read before the sandbox exists, so the config's directory is never granted (M1.1, M2).
    let config_path = args.config.clone().unwrap_or_else(|| dirs.config_file());
    let mut config = Config::load(&config_path, &owner)?;
    let file_config = config.clone();
    if let Some(port) = args.port {
        validate_port(port)?;
        config.server.port = port;
    }
    // Canonical directories for the sandbox and the discovery boundaries (they exist now).
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let session_dir = config
        .sessions
        .dir
        .clone()
        .unwrap_or_else(|| paths::session_dir(&env, &home));
    // The home directory in its canonical spelling from here on: discovery, the tracker, the
    // watcher and Git all compare it with canonical paths ("a repository at home is not a
    // project's", `~/snap`, the session rules), and a symlinked home must not defeat them
    // (v0.1.0 review L2).
    let home = canon(&home);
    let roots = if config.discovery.roots.is_empty() {
        vec![home.clone()]
    } else {
        config.discovery.roots.clone()
    };
    let canonical_dirs = Dirs {
        config: canon(&dirs.config),
        data: canon(&dirs.data),
        state: canon(&dirs.state),
        runtime: canon(&dirs.runtime),
    };
    let policy = sandbox::daemon_policy(
        &roots.iter().map(|r| canon(r)).collect::<Vec<_>>(),
        &canon(&session_dir),
        &canonical_dirs,
        config.server.port,
    );
    // ccwm's directories and the session directory are hard boundaries under both spellings:
    // the walks see canonical paths, so with a symlinked XDG parent that resolves into a project
    // the literal path alone would let ccwm watch its own database (review L2).
    let mut boundaries = dirs.hard_boundaries(&session_dir);
    for b in canonical_dirs.hard_boundaries(&canon(&session_dir)) {
        if !boundaries.contains(&b) {
            boundaries.push(b);
        }
    }
    // The TCP peer check's lookup is chosen by a self-test over an ephemeral loopback connection,
    // which only works before the sandbox limits binds to the configured port. Its netlink socket
    // is opened here, once, and reused: the seccomp filter later denies every new socket.
    let (peer_lookup, peer_method) = crate::http::peer::select_lookup();
    let mut report =
        sandbox::apply(&policy).unwrap_or_else(|e| SandboxReport::disabled(e.to_string()));
    report.flag_broad_reads(&policy.read, &canon(&home));

    // Only now (single-threaded so far) start the runtime and everything that spawns threads.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("ccwm-rt")
        .enable_all()
        .build()
        .map_err(|e| Error::io("cannot start the async runtime", &e))?;
    runtime.block_on(run(Prepared {
        uid,
        dirs,
        config,
        file_config,
        config_path,
        roots,
        home,
        session_dir,
        boundaries,
        policy,
        report,
        peer_lookup,
        peer_method,
    }))
}

/// M4: once the listeners are bound, probe from the blocking pool that the daemon cannot write
/// outside its directories or connect out, install the seccomp socket filter on every thread,
/// and probe socket creation from a worker and a blocking-pool thread. Everything that needs a
/// socket or a socket pair must exist before this runs.
async fn deny_sockets_and_probe(home: &Path, report: &mut SandboxReport) {
    let dir = home.to_path_buf();
    let (write, connect) =
        tokio::task::spawn_blocking(move || (sandbox::probe_write(&dir), sandbox::probe_connect()))
            .await
            .unwrap_or_else(|_| ("error:panicked".into(), "error:panicked".into()));
    report.record_daemon_probes(&write, &connect);
    let applied = sandbox::deny_new_sockets();
    let worker = tokio::spawn(async { sandbox::probe_socket() })
        .await
        .unwrap_or_else(|_| "error:panicked".into());
    let blocking = tokio::task::spawn_blocking(sandbox::probe_socket)
        .await
        .unwrap_or_else(|_| "error:panicked".into());
    report.record_seccomp(&applied, &worker, &blocking);
}

/// M1.1 (M4): verify from a worker thread and a blocking-pool thread, both created after the
/// sandbox was applied, that they are confined too.
async fn probe_runtime_threads(policy: &Policy, report: &mut SandboxReport) {
    let target = sandbox::probe_target(policy);
    let t = target.clone();
    let worker = tokio::spawn(async move { sandbox::probe_read(t.as_deref()) })
        .await
        .unwrap_or_else(|_| "error:panicked".into());
    let blocking = tokio::task::spawn_blocking(move || sandbox::probe_read(target.as_deref()))
        .await
        .unwrap_or_else(|_| "error:panicked".into());
    report.record_thread_probes(&worker, &blocking);
}

async fn run(p: Prepared) -> Result<()> {
    let Prepared {
        uid,
        dirs,
        config,
        file_config,
        config_path,
        roots,
        home,
        session_dir,
        boundaries,
        policy,
        mut report,
        peer_lookup,
        peer_method,
    } = p;
    probe_runtime_threads(&policy, &mut report).await;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let _lock = InstanceLock::acquire(&dirs)?;

    let db_path = dirs.db_path();
    let writer = Arc::new(Writer::spawn(&db_path)?);
    let reader = Reader::open(&db_path, POOL_SIZE)?;

    let discovery = SharedStatus::default();
    if let Some(ts) = reader
        .with(|c| queries::get_meta(c, "last_scan_ok_at"))
        .await?
        .and_then(|v| v.parse::<i64>().ok())
    {
        discovery.update(|s| s.last_success_at = Some(ts));
    }

    let wanted = config.server.port;
    let listener = TcpListener::bind(("127.0.0.1", wanted)).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            Error::new(format!("port {wanted} is already in use. Choose another with `ccwm serve --port N` or set [server] port in the config file"))
                .with_exit_code(crate::error::EXIT_PORT_IN_USE)
        } else {
            Error::io(format!("cannot listen on 127.0.0.1:{wanted}"), &e)
        }
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::io("cannot read the bound port", &e))?
        .port();
    let socket = crate::ipc::server::bind(&dirs.socket_path(), uid)?;
    // The signal handlers are registered before the filter: the runtime delivers signals through
    // a socket pair, and the filter denies socketpair() too (v0.1.0 review M1).
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::io("cannot install SIGTERM handler", &e))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| Error::io("cannot install SIGINT handler", &e))?;
    // Both listeners exist: from now on the daemon creates no socket (seccomp, M4).
    deny_sockets_and_probe(&home, &mut report).await;
    tracing::info!("{}", report.summary());
    if !report.unverified.is_empty() {
        tracing::warn!(
            protections = %report.unverified.join(","),
            "a sandbox probe failed for an unexpected reason: these protections are unverified (neither claimed nor withdrawn); see the notes above and `ccwm doctor`"
        );
    }
    tracing::info!(method = peer_method, "tcp peer check");

    // ---- tracking: Git, the single inotify instance, the monitor and the tracker (M2) ----
    let git = Arc::new(Git::detect(
        find_on_path(std::env::var_os("PATH").as_deref()),
        &home,
        config.git.allow_unhardened_status,
    ));
    let gs = git.summary();
    tracing::info!(
        program = gs.program.as_deref().unwrap_or("none"),
        version = gs.version.as_deref().unwrap_or("none"),
        hardened_status = gs.hardened_status,
        "git"
    );
    let (notifier, changes) = Notifier::channel();
    let monitor_state = SharedMonitor::default();
    let (monitor_tx, monitor_rx) = mpsc::channel(1024);
    let (signals_tx, signals_rx) = mpsc::channel(4096);
    let (raw_tx, raw_rx) = mpsc::channel(watch_engine::EVENT_QUEUE);
    let dropped = Arc::new(AtomicBool::new(false));
    let backend: Option<Box<dyn WatchBackend>> = match watch_engine::inotify_backend(
        raw_tx,
        Arc::clone(&dropped),
    ) {
        Ok(w) => Some(Box::new(w)),
        Err(e) => {
            tracing::warn!(error = %e, "cannot create the inotify instance; every project will be polled");
            None
        }
    };
    let canonical_session_dir =
        std::fs::canonicalize(&session_dir).unwrap_or_else(|_| session_dir.clone());
    let claude = Arc::new(crate::claude::cli::Verifier::new(std::env::var_os("PATH")));
    let fuse_mounts = current_fuse_mount_points();
    let max_user_watches = watch_engine::read_max_user_watches();
    let budget = match config.watch.budget {
        0 => watch_engine::default_budget(max_user_watches),
        n => n as usize,
    };
    let canonical_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect();
    let scan_opts = ScanOptions {
        roots: roots.clone(),
        exclude: config.discovery.exclude.clone(),
        max_depth: config.discovery.max_depth,
        same_file_system: config.discovery.same_file_system,
        home: home.clone(),
        boundaries: boundaries.clone(),
        fuse_mounts: fuse_mounts.clone(),
    };
    let rules = Arc::new(crate::watch::tree::RuleStore::default());
    let tracker = Tracker::new(
        Arc::clone(&writer),
        reader.clone(),
        Arc::clone(&clock),
        notifier.clone(),
        discovery.clone(),
        git,
        monitor_tx.clone(),
        monitor_state.clone(),
        TrackerSettings {
            scan: scan_opts,
            uid,
            interval: Duration::from_secs(config.discovery.scan_interval_secs),
            retention_secs: i64::from(config.discovery.missing_retention_days) * 86_400,
            events_per_project: config.activity.events_per_project,
            full_scan: config.discovery.full_scan,
            sessions: Some(crate::tracker::SessionSettings {
                config_dir: canonical_session_dir.clone(),
                temp_dirs: crate::discovery::resolve::temp_dirs(
                    std::env::var_os("TMPDIR").as_deref(),
                ),
                claude: Some(Arc::clone(&claude)),
            }),
            rules: Arc::clone(&rules),
        },
    );
    let monitor = Monitor::new(
        backend,
        WatchSettings {
            roots: canonical_roots,
            home: home.clone(),
            exclude: config.discovery.exclude.clone(),
            boundaries,
            fuse_mounts,
            max_depth: config.discovery.max_depth,
            same_file_system: config.discovery.same_file_system,
            budget,
            max_user_watches,
            debounce: Duration::from_millis(config.watch.debounce_ms),
            events_per_project: config.activity.events_per_project as usize,
            rules,
        },
        Arc::clone(&clock),
        signals_tx,
        monitor_tx,
        monitor_state.clone(),
        Some(notifier.clone()),
    );

    // v0.2: the activity indicator's open sessions, restored before the socket accepts events.
    let presence = Arc::new(crate::presence::Presence::new(
        crate::presence::proc::ProcFs::default(),
        uid,
        std::process::id(),
        Arc::clone(&writer),
        Arc::clone(&clock),
        notifier.clone(),
    ));
    presence.set_show_noninteractive(file_config.indicator.show_noninteractive);
    presence.set_live_first(file_config.indicator.live_first);
    tracker.set_presence(Arc::clone(&presence));
    match presence.restore(&reader).await {
        Ok((0, 0)) => {}
        Ok((restored, dropped)) => {
            tracing::info!(
                restored,
                dropped,
                "open sessions of the activity indicator restored"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot restore the open sessions of the activity indicator")
        }
    }
    // Their projects are known from the database: resolved now, not after the first scan.
    if let Err(e) = tracker.resolve_open_sessions().await {
        tracing::warn!(error = %e, "cannot resolve the open sessions' projects");
    }
    let service = Arc::new(Service::new(Deps {
        clock: Arc::clone(&clock),
        writer: Arc::clone(&writer),
        reader,
        discovery: discovery.clone(),
        sandbox: report,
        port,
        home,
        classifier: Classifier::system(&config.activity),
        monitor: monitor_state,
        notifier,
        tracker: Some(Arc::clone(&tracker)),
        config: file_config,
        config_path: Some(config_path),
        session_dir: canonical_session_dir,
        roots,
        claude: Some(claude),
        peer_lookup: peer_method,
        presence: Arc::clone(&presence),
    }));
    write_instance(
        &dirs,
        &InstanceInfo {
            pid: std::process::id(),
            port,
            version: VERSION.to_string(),
            started_at: clock.now(),
        },
    )?;
    tracing::info!(
        port,
        "listening on http://127.0.0.1:{port} (run `ccwm open` to sign in)"
    );

    let (stop_tx, stop_rx) = watch::channel(false);
    let ipc = tokio::spawn(crate::ipc::server::serve(
        socket,
        Arc::clone(&service),
        uid,
        stop_rx.clone(),
    ));
    let tasks = [
        tokio::spawn(monitor.run(raw_rx, monitor_rx, dropped, stop_rx.clone())),
        tokio::spawn(Arc::clone(&tracker).run_reconciler(stop_rx.clone())),
        tokio::spawn(Arc::clone(&tracker).run_signals(signals_rx, stop_rx.clone())),
        tokio::spawn(Arc::clone(&service).run_publisher(changes, stop_rx.clone())),
        tokio::spawn(Arc::clone(&presence).run_sweeper(stop_rx.clone())),
    ];

    let purge = {
        let (service, clock, mut stop) =
            (Arc::clone(&service), Arc::clone(&clock), stop_rx.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SESSION_PURGE_INTERVAL);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        match service.writer.purge_expired_sessions(clock.now()).await {
                            Ok(n) if n > 0 => {
                                tracing::info!(purged = n, "expired browser sessions removed");
                                service.revalidate_sockets();
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "session purge failed"),
                        }
                    }
                    () = crate::events::until_stopped(&mut stop) => break,
                }
            }
        })
    };

    let shutdown = async move {
        tokio::select! { _ = sigterm.recv() => {}, _ = sigint.recv() => {} }
        tracing::info!("shutting down");
    };
    let served = crate::http::serve(
        listener,
        Arc::clone(&service),
        crate::http::ServeOptions {
            peer_uid: peer_lookup,
            ..crate::http::ServeOptions::new(uid)
        },
        shutdown,
    )
    .await;

    // Graceful teardown: stop discovery and the watchers, close the socket, flush the writer,
    // remove runtime files. The stop goes out before `cancel`, which wakes the reconciler: woken
    // first, it found no stop and started one more reconciliation, which ingested the sessions
    // again during shutdown — right after "Clear session index", too (v0.1.1 review L5).
    let _ = stop_tx.send(true);
    tracker.cancel();
    for t in tasks {
        let _ = t.await;
    }
    let _ = ipc.await;
    let _ = purge.await;
    let flushed = writer.shutdown().await;
    let _ = std::fs::remove_file(dirs.socket_path());
    remove_instance(&dirs);
    served.map_err(|e| Error::io("http server failed", &e))?;
    flushed
}
