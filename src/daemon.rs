//! `ccwm serve`: startup sequence, background discovery, graceful shutdown.
//!
//! Order matters. Landlock is applied on the main thread before the Tokio runtime (and therefore any
//! other thread) exists, because it only confines the calling thread and threads created afterwards.

use crate::clock::{Clock, SystemClock};
use crate::config::{validate_port, Config};
use crate::db::queries;
use crate::db::reader::{Reader, POOL_SIZE};
use crate::db::writer::{ProjectUpsert, Source, Writer};
use crate::discovery::mounts::current_fuse_mount_points;
use crate::discovery::status::SharedStatus;
use crate::discovery::walk::{scan, ScanOptions};
use crate::error::{Error, Result};
use crate::instance::{remove_instance, write_instance, InstanceInfo, InstanceLock};
use crate::paths::{current_home, Dirs, EnvVars};
use crate::sandbox::{self, SandboxReport};
use crate::service::{Service, VERSION};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;

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

fn session_dir(home: &Path) -> PathBuf {
    match std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => home.join(".claude"),
    }
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
    let dirs = Dirs::resolve(&EnvVars::from_process(), &home);
    dirs.ensure(uid)?;

    let config_path = args.config.clone().unwrap_or_else(|| dirs.config_file());
    let mut config = Config::load(&config_path)?;
    if let Some(port) = args.port {
        validate_port(port)?;
        config.server.port = port;
    }
    let roots = if config.discovery.roots.is_empty() {
        vec![home.clone()]
    } else {
        config.discovery.roots.clone()
    };

    // Canonical directories for the sandbox and the discovery boundaries (they exist now).
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let policy = sandbox::daemon_policy(
        &roots.iter().map(|r| canon(r)).collect::<Vec<_>>(),
        &canon(&session_dir(&home)),
        config_path.parent().map(canon).as_deref(),
        &Dirs {
            config: canon(&dirs.config),
            data: canon(&dirs.data),
            state: canon(&dirs.state),
            runtime: canon(&dirs.runtime),
        },
        config.server.port,
    );
    let report = sandbox::apply(&policy).unwrap_or_else(|e| SandboxReport::disabled(e.to_string()));

    // Only now (single-threaded so far) start the runtime and everything that spawns threads.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("ccwm-rt")
        .enable_all()
        .build()
        .map_err(|e| Error::io("cannot start the async runtime", &e))?;
    runtime.block_on(run(uid, dirs, config, roots, home, report))
}

async fn run(
    uid: u32,
    dirs: Dirs,
    config: Config,
    roots: Vec<PathBuf>,
    home: PathBuf,
    report: SandboxReport,
) -> Result<()> {
    tracing::info!("{}", report.summary());
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
        } else {
            Error::io(format!("cannot listen on 127.0.0.1:{wanted}"), &e)
        }
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::io("cannot read the bound port", &e))?
        .port();

    let service = Arc::new(Service::new(
        Arc::clone(&clock),
        Arc::clone(&writer),
        reader,
        discovery.clone(),
        report,
        port,
    ));
    let socket = crate::ipc::server::bind(&dirs.socket_path(), uid)?;
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

    let cancel = Arc::new(AtomicBool::new(false));
    let scan_task = {
        let opts = ScanOptions {
            roots,
            exclude: config.discovery.exclude.clone(),
            max_depth: config.discovery.max_depth,
            same_file_system: config.discovery.same_file_system,
            home,
            boundaries: dirs.hard_boundaries(),
            fuse_mounts: current_fuse_mount_points(),
        };
        let (writer, status, clock, cancel) = (
            Arc::clone(&writer),
            discovery.clone(),
            Arc::clone(&clock),
            Arc::clone(&cancel),
        );
        tokio::task::spawn_blocking(move || {
            let summary = scan(&opts, &cancel, &status, &mut |batch| {
                let now = clock.now();
                let rows = batch
                    .into_iter()
                    .map(|c| ProjectUpsert {
                        canonical_path: c.canonical_path,
                        name: c.name,
                        source: Source::Marker,
                    })
                    .collect();
                writer.upsert_projects_blocking(rows, now).is_ok()
            });
            if !summary.cancelled {
                let now = clock.now();
                if writer
                    .set_meta_blocking("last_scan_ok_at", &now.to_string())
                    .is_ok()
                {
                    status.update(|s| s.last_success_at = Some(now));
                }
                tracing::info!(
                    dirs = summary.dirs_visited,
                    projects = summary.projects_found,
                    "discovery finished"
                );
            }
        })
    };

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::io("cannot install SIGTERM handler", &e))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| Error::io("cannot install SIGINT handler", &e))?;
    let shutdown = async move {
        tokio::select! { _ = sigterm.recv() => {}, _ = sigint.recv() => {} }
        tracing::info!("shutting down");
    };
    let served = crate::http::serve(listener, Arc::clone(&service), shutdown).await;

    // Graceful teardown: stop discovery, close the socket, flush the writer, remove runtime files.
    cancel.store(true, Ordering::Relaxed);
    let _ = stop_tx.send(true);
    let _ = scan_task.await;
    let _ = ipc.await;
    let flushed = writer.shutdown().await;
    let _ = std::fs::remove_file(dirs.socket_path());
    remove_instance(&dirs);
    served.map_err(|e| Error::io("http server failed", &e))?;
    flushed
}
