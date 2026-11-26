//! Command-line interface.

use crate::client;
use crate::daemon::{self, ServeArgs};
use crate::error::{Error, Result};
use crate::paths::{current_home, Dirs, EnvVars, Owner};
use crate::systemd;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

const NOTICE: &str = "CC Workspace Manager is an independent, unofficial open-source project. \
It is not affiliated with or endorsed by Anthropic.";

/// Write to standard output like `print!`, except when the write fails. Rust ignores `SIGPIPE`
/// and `println!` **panics** on a failed write, so `ccwm status | head` ended with a panic
/// message. Here a closed pipe ends the command quietly with status 0 (the reader stopped
/// reading: not an error of ccwm), any other write error with status 1.
pub fn write_stdout(text: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_fmt(text).and_then(|()| out.flush()) {
        std::process::exit(output_error_status(&e));
    }
}

fn output_error_status(e: &std::io::Error) -> i32 {
    i32::from(e.kind() != std::io::ErrorKind::BrokenPipe)
}

/// Write to standard error like `eprint!`, without panicking when it cannot be written:
/// diagnostics that cannot be delivered are dropped and the command goes on.
pub fn write_stderr(text: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = err.write_fmt(text).and_then(|()| err.flush());
}

/// `print!` / `println!` / `eprint!` / `eprintln!` through [`write_stdout`] and [`write_stderr`]:
/// every command prints with these, never with the standard macros.
macro_rules! out {
    ($($arg:tt)*) => { $crate::cli::write_stdout(format_args!($($arg)*)) };
}
macro_rules! outln {
    ($($arg:tt)*) => { $crate::cli::write_stdout(format_args!("{}\n", format_args!($($arg)*))) };
}
macro_rules! err {
    ($($arg:tt)*) => { $crate::cli::write_stderr(format_args!($($arg)*)) };
}
macro_rules! errln {
    ($($arg:tt)*) => { $crate::cli::write_stderr(format_args!("{}\n", format_args!($($arg)*))) };
}
pub(crate) use {err, out};

#[derive(Debug, Parser)]
#[command(
    name = "ccwm",
    version,
    about = "Discover, track, and resume your Claude Code projects.",
    after_help = NOTICE,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon in the foreground (this is what systemd runs).
    Serve {
        /// TCP port on 127.0.0.1 (default 8765, or [server] port in the config file).
        #[arg(long)]
        port: Option<u16>,
        /// Path to config.toml (default: $XDG_CONFIG_HOME/ccwm/config.toml).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Open the dashboard in your browser, signed in via a single-use link.
    Open {
        /// Print the URL instead of opening a browser.
        #[arg(long)]
        print: bool,
    },
    /// Show the systemd unit's state and the running daemon's state (verified over the Unix socket).
    Status,
    /// Ask the daemon to rescan now and wait until the scan has finished.
    Scan,
    /// Start the ccwm.service user unit (`systemctl --user start`).
    Start,
    /// Stop the ccwm.service user unit (`systemctl --user stop`).
    Stop,
    /// Restart the ccwm.service user unit (`systemctl --user restart`).
    Restart,
    /// Check the installation and the running daemon; suggests fixes, never applies them.
    Doctor,
    /// Install or remove the systemd user unit.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Browser sign-in management.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Write ~/.config/systemd/user/ccwm.service, then `daemon-reload` and `enable --now`.
    Install,
    /// `disable --now` and remove the unit; your data is kept unless --purge is given.
    Uninstall {
        /// Also delete ccwm's configuration, database and state (asks for confirmation).
        /// Project files and Claude Code sessions are never touched.
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthAction {
    /// Sign out every browser session.
    RevokeAll,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { port, config } => {
            daemon::init_logging();
            daemon::serve(&ServeArgs { port, config })
        }
        Command::Open { print } => open(print),
        Command::Status => status(),
        Command::Scan => scan(),
        Command::Start => unit_command("start"),
        Command::Stop => unit_command("stop"),
        Command::Restart => unit_command("restart"),
        Command::Doctor => crate::doctor::run(),
        Command::Service {
            action: ServiceAction::Install,
        } => service_install(),
        Command::Service {
            action: ServiceAction::Uninstall { purge },
        } => service_uninstall(purge),
        Command::Auth {
            action: AuthAction::RevokeAll,
        } => revoke_all(),
    }
}

fn daemon_dirs() -> Result<(Dirs, u32)> {
    let uid = nix::unistd::geteuid().as_raw();
    let home = current_home(uid)?;
    Ok((Dirs::resolve(&EnvVars::from_process(), &home), uid))
}

/// The daemon's socket after verifying the runtime directory (no TCP, ever).
fn daemon_socket() -> Result<(std::path::PathBuf, u32)> {
    let (dirs, uid) = daemon_dirs()?;
    dirs.verify_runtime(&Owner::current(uid))?;
    Ok((dirs.socket_path(), uid))
}

/// How long the CLI waits for a daemon that is still starting (it holds the instance lock, but
/// its socket is not accepting yet).
pub const STARTUP_WAIT: Duration = Duration::from_secs(5);

/// The first request of a command. If the daemon is not reachable, the CLI waits (up to
/// [`STARTUP_WAIT`]) only when the instance lock is held, i.e. a daemon is starting; with no
/// lock holder it fails at once. Every other error (wrong owner, impostor, protocol) fails at
/// once too.
fn first_call(op: &str) -> Result<(std::path::PathBuf, u32, serde_json::Value)> {
    let call = || {
        daemon_socket()
            .and_then(|(socket, uid)| client::call(&socket, uid, op).map(|v| (socket, uid, v)))
    };
    match call() {
        Err(e) if e.is_not_running() => {
            let starting = daemon_dirs().is_ok_and(|(d, _)| crate::instance::lock_held(&d));
            if !starting {
                return Err(e);
            }
            errln!(
                "Waiting up to {} s for the ccwm daemon to start…",
                STARTUP_WAIT.as_secs()
            );
            retry_while_starting(STARTUP_WAIT, Duration::from_millis(100), call)
        }
        other => other,
    }
}

/// Run `attempt` until it succeeds, fails with anything but "not running", or `wait` is over
/// (then its last error is returned). Sleeps `step`, doubling up to 500 ms, between attempts.
pub fn retry_while_starting<T>(
    wait: Duration,
    step: Duration,
    mut attempt: impl FnMut() -> Result<T>,
) -> Result<T> {
    let deadline = std::time::Instant::now() + wait;
    let mut delay = step;
    loop {
        match attempt() {
            Err(e) if e.is_not_running() && std::time::Instant::now() + delay <= deadline => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            other => return other,
        }
    }
}

fn status() -> Result<()> {
    outln!(
        "{}",
        systemd::status_line(&systemd::Systemctl::find(systemd::path_var().as_deref()))
    );
    let (socket, uid, st) = first_call("service.status")?;
    out!("{}", format_status(&st));
    if let Ok(d) = client::call(&socket, uid, "discovery.status") {
        out!("{}", format_sessions(&d));
        out!("{}", format_unreadable(&d));
    }
    if let Some(warning) = commit_mismatch(st.get("commit").and_then(|v| v.as_str())) {
        errln!("warning: {warning}");
    }
    Ok(())
}

/// A warning when the daemon was built from a different commit than this CLI.
pub fn commit_mismatch(daemon: Option<&str>) -> Option<String> {
    let ours = crate::service::COMMIT;
    match daemon {
        Some(theirs) if theirs == ours && ours != "unknown" => None,
        Some(theirs) => Some(format!(
            "the running daemon was built from commit {theirs}, this ccwm from {ours}; restart the daemon to run the same build"
        )),
        None => Some(format!(
            "the running daemon does not report its build commit (this ccwm is {ours}); restart it"
        )),
    }
}

fn s<'a>(v: &'a serde_json::Value, path: &str) -> std::borrow::Cow<'a, str> {
    match v.pointer(path) {
        Some(serde_json::Value::String(x)) => x.as_str().into(),
        Some(serde_json::Value::Null) | None => "unknown".into(),
        Some(other) => other.to_string().into(),
    }
}

/// A Unix time from the status as local date and time ("unknown" when absent).
fn when(v: &serde_json::Value, path: &str) -> String {
    v.pointer(path)
        .and_then(serde_json::Value::as_i64)
        .and_then(|t| jiff::Timestamp::from_second(t).ok())
        .map_or_else(
            || "unknown".to_string(),
            |t| {
                t.to_zoned_datetime(
                    jiff::tz::TimeZone::try_system().unwrap_or(jiff::tz::TimeZone::UTC),
                )
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string()
            },
        )
}

/// Human-readable summary of `service.status` (systemd state arrives with `ccwm start`, M4).
pub fn format_status(v: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "ccwm daemon {} (commit {}) running, port {}, up {}s\n",
        s(v, "/version"),
        s(v, "/commit"),
        s(v, "/port"),
        s(v, "/uptime_s")
    ));
    out.push_str(&format!(
        "  discovery: {}, last scan {}, next scan {}\n",
        s(v, "/discovery/phase"),
        when(v, "/discovery/last_success_at"),
        when(v, "/discovery/next_scan_at")
    ));
    out.push_str(&format!(
        "  monitoring: {}, {} watches (budget {}), projects: {} watched, {} partly watched, {} polled{}\n",
        s(v, "/monitoring/watcher"),
        s(v, "/monitoring/watches"),
        s(v, "/monitoring/budget"),
        s(v, "/monitoring/watched_projects"),
        s(v, "/monitoring/partial_projects"),
        s(v, "/monitoring/polled_projects"),
        if v.pointer("/monitoring/degraded") == Some(&serde_json::Value::Bool(true)) {
            " (DEGRADED)"
        } else {
            ""
        }
    ));
    if let Some(advice) = v.pointer("/monitoring/advice").and_then(|a| a.as_array()) {
        for a in advice.iter().filter_map(|a| a.as_str()) {
            out.push_str(&format!("    ! {a}\n"));
        }
    }
    out.push_str(&ignore_rules_limited(string_list(
        &v["monitoring"],
        "ignore_rules_limited",
    )));
    out.push_str(&format!(
        "  git: {} {} (hardened status: {})\n",
        s(v, "/git/program"),
        s(v, "/git/version"),
        s(v, "/git/hardened_status")
    ));
    out.push_str(&format!(
        "  claude: {} {} (resume supported: {})\n",
        s(v, "/claude/state"),
        s(v, "/claude/version"),
        s(v, "/claude/resume_supported")
    ));
    out.push_str(&format!(
        "  sandbox: {} (abi {}, filesystem {}, network {}, seccomp {})\n",
        s(v, "/sandbox/status"),
        s(v, "/sandbox/abi"),
        sandbox_claim(&v["sandbox"], "filesystem"),
        s(v, "/sandbox/network"),
        s(v, "/sandbox/seccomp")
    ));
    let unverified = string_list(&v["sandbox"], "unverified");
    if !unverified.is_empty() {
        out.push_str(&format!(
            "    ! unverified (a probe failed for an unexpected reason; neither enforced nor withdrawn): {}\n",
            unverified.join(", ")
        ));
    }
    out
}

/// The strings of the array `key` of a status object (empty when absent).
pub fn string_list<'a>(v: &'a serde_json::Value, key: &str) -> Vec<&'a str> {
    v.get(key)
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default()
}

/// How many names [`ignore_rules_limited`] shows.
const LIMITED_SHOWN: usize = 8;

/// The projects the limit on ignore rules across projects holds back (v0.1.1 review M2): their
/// file events are judged without some of their rules, their scans with all of them.
fn ignore_rules_limited(names: Vec<&str>) -> String {
    if names.is_empty() {
        return String::new();
    }
    let more = names.len().saturating_sub(LIMITED_SHOWN);
    let shown = names[..names.len() - more].join(", ");
    let rest = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    format!(
        "    ! ignore rules limited: {} project(s) ({shown}{rest}) lack some of their ignore rules because all projects together have more than the limit; changes to the files those rules ignore count as activity in them, but their scans still use all of their rules\n",
        names.len()
    )
}

/// A yes/no protection of the sandbox report (`filesystem`, `signal`, …) for display: `true`,
/// `false`, or `unverified` when its probe failed for an unexpected reason (it is then listed in
/// `unverified`, and the report claims and withdraws nothing about it).
pub fn sandbox_claim(report: &serde_json::Value, kind: &str) -> String {
    if string_list(report, "unverified").contains(&kind) {
        return crate::sandbox::UNVERIFIED.to_string();
    }
    report
        .get(kind)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        .to_string()
}

/// How long `ccwm scan` waits for the scan to finish.
/// `n folder` / `n folders`.
pub fn folders(n: u64) -> String {
    format!("{n} folder{}", if n == 1 { "" } else { "s" })
}

/// The session index and the marker scan's scope (from `discovery.status`). Sessions that
/// belong to no project are broken down by reason and by the folders most of them were started
/// in (e.g. `831 excluded (~/.claude-mem/observer-sessions)`).
pub fn format_sessions(d: &serde_json::Value) -> String {
    let n = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let mut reasons: Vec<(&str, u64)> = d
        .pointer("/sessions/unassigned")
        .and_then(|u| u.as_object())
        .map(|o| o.iter().map(|(k, v)| (k.as_str(), n(v))).collect())
        .unwrap_or_default();
    reasons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let folders: Vec<(&str, Option<&str>, u64)> = d
        .pointer("/sessions/unassigned_folders")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .map(|f| {
                    (
                        f.get("reason").and_then(|r| r.as_str()).unwrap_or(""),
                        f.get("folder").and_then(|r| r.as_str()),
                        f.get("sessions").map_or(0, n),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let total: u64 = reasons.iter().map(|r| r.1).sum();
    let duplicates = d.pointer("/sessions/duplicate_ids").map_or(0, n);
    let cut = d.pointer("/sessions/listing_cut") == Some(&serde_json::Value::Bool(true));
    let mut out = format!(
        "  sessions: {} ({} files, {} indexed{}{})\n",
        s(d, "/sessions/state"),
        s(d, "/sessions/files"),
        s(d, "/sessions/indexed"),
        if total == 0 {
            String::new()
        } else {
            format!("; {total} not in a project")
        },
        if duplicates == 0 {
            String::new()
        } else {
            format!("; {duplicates} duplicate session files skipped")
        }
    );
    if cut {
        out.push_str(&format!(
            "    ! more than {} session files: the rest is not indexed, and sessions in the folders the limit cut off stay in the index after their file is deleted\n",
            crate::claude::locate::MAX_FILES
        ));
    }
    for (reason, count) in reasons {
        let label = reason.replace('_', " ");
        let mut listed = 0;
        for (_, folder, k) in folders.iter().filter(|f| f.0 == reason) {
            listed += k;
            match folder {
                Some(f) => out.push_str(&format!("    {k} {label} ({f})\n")),
                None => out.push_str(&format!("    {k} {label} (no folder recorded)\n")),
            }
        }
        match count.saturating_sub(listed) {
            0 => {}
            rest if listed == 0 => out.push_str(&format!("    {rest} {label}\n")),
            rest => out.push_str(&format!("    {rest} {label} (other folders)\n")),
        }
    }
    let dev_roots: Vec<&str> = d
        .get("dev_roots")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    out.push_str(&match s(d, "/scope").as_ref() {
        "dev_roots" if dev_roots.is_empty() => {
            "  marker scan: development roots (none yet)\n".to_string()
        }
        "dev_roots" => format!(
            "  marker scan: development roots {}\n",
            dev_roots.join(", ")
        ),
        "full" => "  marker scan: every root\n".to_string(),
        _ => String::new(),
    });
    out
}

/// The folders the last scan could not read (from `discovery.status`), or nothing.
pub fn format_unreadable(d: &serde_json::Value) -> String {
    let count: u64 = ["permission", "vanished", "changed", "other"]
        .iter()
        .filter_map(|k| {
            d.pointer(&format!("/skipped/{k}"))
                .and_then(serde_json::Value::as_u64)
        })
        .sum();
    if count == 0 {
        return String::new();
    }
    let mut out = format!("  {} could not be read in the last scan:\n", folders(count));
    let listed = d
        .get("unreadable")
        .and_then(|u| u.as_array())
        .cloned()
        .unwrap_or_default();
    for u in &listed {
        out.push_str(&format!("    {} ({})\n", s(u, "/path"), s(u, "/reason")));
    }
    let shown = u64::try_from(listed.len()).unwrap_or(u64::MAX);
    if count > shown {
        out.push_str(&format!("    … and {} more\n", count - shown));
    }
    out
}

const SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

fn scan() -> Result<()> {
    let (socket, uid, accepted) = first_call("scan.refresh")?;
    let target = accepted
        .get("done_at_scans_finished")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::new("the daemon's response was incomplete"))?;
    outln!("Scan requested.");
    let deadline = std::time::Instant::now() + SCAN_WAIT;
    let mut last_line = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let st = client::call(&socket, uid, "discovery.status")?;
        let phase = st.get("phase").and_then(|v| v.as_str()).unwrap_or("");
        let finished = st.get("scans_finished").and_then(serde_json::Value::as_u64);
        let line = format!(
            "{phase}: {} folders checked, {} projects found",
            s(&st, "/dirs_visited"),
            s(&st, "/projects_found")
        );
        if line != last_line {
            outln!("{line}");
            last_line = line;
        }
        if finished.is_some_and(|n| n >= target) {
            outln!("Scan finished.");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(
                "the scan did not finish within 10 minutes (it keeps running in the daemon)",
            ));
        }
    }
}

/// How long `ccwm start|restart|service install` wait for the daemon to answer on its socket.
const SERVICE_START_WAIT: Duration = Duration::from_secs(10);
/// How long `ccwm stop` waits for the daemon to release its lock (the unit's TimeoutStopSec).
const SERVICE_STOP_WAIT: Duration = Duration::from_secs(10);

/// Wait until a daemon answers `ping` over the Unix socket (verified peer), or give up.
fn wait_until_running(wait: Duration) -> Result<serde_json::Value> {
    retry_while_starting(wait, Duration::from_millis(100), || {
        daemon_socket().and_then(|(socket, uid)| client::call(&socket, uid, "ping"))
    })
}

/// Wait until nobody holds the instance lock (the daemon exited), or give up.
fn wait_until_stopped(dirs: &Dirs, wait: Duration) -> bool {
    let deadline = std::time::Instant::now() + wait;
    while crate::instance::lock_held(dirs) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

fn report_running(verb: &str) -> Result<()> {
    match wait_until_running(SERVICE_START_WAIT) {
        Ok(ping) => {
            outln!(
                "ccwm {} ({verb}). Open the dashboard with `ccwm open`.",
                s(&ping, "/version")
            );
            Ok(())
        }
        Err(e) => Err(Error::new(format!(
            "ccwm.service did not answer within {} s ({e}). See `systemctl --user status ccwm` and `journalctl --user -u ccwm`",
            SERVICE_START_WAIT.as_secs()
        ))),
    }
}

/// `ccwm start|stop|restart`: `systemctl --user <verb> ccwm.service`, then wait for the result.
fn unit_command(verb: &str) -> Result<()> {
    let systemctl = systemd::Systemctl::find(systemd::path_var().as_deref())?;
    systemctl.require_installed()?;
    systemctl.run(&[verb, systemd::UNIT_NAME])?;
    if verb == "stop" {
        let (dirs, _) = daemon_dirs()?;
        if wait_until_stopped(&dirs, SERVICE_STOP_WAIT) {
            outln!("ccwm stopped.");
            return Ok(());
        }
        return Err(Error::new(
            "ccwm.service stopped, but a ccwm daemon still holds the instance lock: one runs outside systemd (`ccwm serve`); stop it there",
        ));
    }
    report_running(if verb == "start" {
        "started"
    } else {
        "restarted"
    })
}

fn service_install() -> Result<()> {
    let (_, uid) = daemon_dirs()?;
    let home = current_home(uid)?;
    let env = EnvVars::from_process();
    let binary = home.join(systemd::BINARY_IN_HOME);
    let executable = std::fs::metadata(&binary).is_ok_and(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    });
    if !executable {
        let this = std::env::current_exe()
            .map_or_else(|_| "ccwm".to_string(), |p| p.display().to_string());
        return Err(Error::new(format!(
            "the unit runs {}, which does not exist. Install the binary first (scripts/install.sh does both), e.g. `install -D -m 0755 {this} {}`",
            binary.display(),
            binary.display()
        )));
    }
    let systemctl = systemd::Systemctl::find(systemd::path_var().as_deref())?;
    let unit_dir = systemd::unit_dir(&env, &home);
    let written = systemd::write_unit(&unit_dir, &Owner::current(uid))?;
    let unit = unit_dir.join(systemd::UNIT_NAME);
    match written {
        systemd::UnitWrite::Created => outln!("Installed {}", unit.display()),
        systemd::UnitWrite::Updated => outln!("Updated {}", unit.display()),
        systemd::UnitWrite::Unchanged => outln!("{} is up to date", unit.display()),
    }
    systemctl.run(&["daemon-reload"])?;
    let was_active = systemctl.states().is_ok_and(|(a, _)| a == "active");
    systemctl.run(&["enable", "--now", systemd::UNIT_NAME])?;
    if was_active && written != systemd::UnitWrite::Unchanged {
        outln!("The service was already running: `ccwm restart` applies the new unit.");
    }
    report_running("running")?;
    let user = systemd::user_name(uid);
    let linger = systemd::linger_enabled(user.as_deref());
    if let Some(hint) = systemd::linger_hint(linger, user.as_deref()) {
        outln!("{hint}");
    }
    Ok(())
}

fn service_uninstall(purge: bool) -> Result<()> {
    let (dirs, uid) = daemon_dirs()?;
    let home = current_home(uid)?;
    let env = EnvVars::from_process();
    let unit = systemd::unit_dir(&env, &home).join(systemd::UNIT_NAME);
    let systemctl = systemd::Systemctl::find(systemd::path_var().as_deref())?;
    if systemctl.installed()? {
        systemctl.run(&["disable", "--now", systemd::UNIT_NAME])?;
    }
    match std::fs::remove_file(&unit) {
        Ok(()) => outln!("Removed {}", unit.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            outln!("{} is not installed", unit.display());
        }
        Err(e) => return Err(Error::io(format!("cannot remove {}", unit.display()), &e)),
    }
    systemctl.run(&["daemon-reload"])?;
    if systemctl.installed()? {
        outln!(
            "note: the user manager still knows ccwm.service from another location (not installed by ccwm); left alone"
        );
    }
    if !purge {
        outln!(
            "Your ccwm data is kept ({}, {}, {}). `ccwm service uninstall --purge` deletes it.",
            dirs.config.display(),
            dirs.data.display(),
            dirs.state.display()
        );
        return Ok(());
    }
    if !wait_until_stopped(&dirs, SERVICE_STOP_WAIT) {
        return Err(Error::new(
            "a ccwm daemon is still running (outside systemd?); stop it before purging its data",
        ));
    }
    let list: Vec<String> = dirs
        .all()
        .iter()
        .map(|d| format!("  {}", d.display()))
        .collect();
    let prompt = format!(
        "This deletes ccwm's configuration, database and state:\n{}\nYour projects and Claude Code sessions are not touched.",
        list.join("\n")
    );
    if !systemd::confirm(&prompt, &mut std::io::stdin().lock()) {
        return Err(Error::new(
            "not confirmed: none of your ccwm data was deleted (the service itself is uninstalled; `ccwm service install` brings it back)",
        ));
    }
    for d in systemd::purge_dirs(&dirs, uid)? {
        outln!("Deleted {}", d.display());
    }
    Ok(())
}

fn revoke_all() -> Result<()> {
    let (_, _, r) = first_call("auth.revoke_all")?;
    let n = r
        .get("revoked")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    outln!(
        "Signed out {n} browser session{}. Run `ccwm open` to sign in again.",
        if n == 1 { "" } else { "s" }
    );
    Ok(())
}

fn open(print_only: bool) -> Result<()> {
    let (_, _, issued) = first_call("auth.bootstrap")?;
    let token = issued.get("bootstrap_token").and_then(|v| v.as_str());
    let port = issued
        .get("port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok());
    let (Some(token), Some(port)) = (token, port) else {
        return Err(Error::new("the daemon's response was incomplete"));
    };
    let url = format!("http://127.0.0.1:{port}/#bt={token}");
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    if print_only || !has_display {
        outln!("{url}");
        return Ok(());
    }
    // The single-use link stays out of the terminal when a browser could be launched.
    match std::process::Command::new("xdg-open")
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => {
            outln!(
                "Opening the dashboard in your browser (the sign-in link is single-use and expires in {} seconds).",
                crate::auth::bootstrap::BOOTSTRAP_TTL_SECS
            );
            Ok(())
        }
        Err(_) => {
            outln!("{url}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_carries_the_unofficial_notice() {
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("independent, unofficial")
                && help.contains("not affiliated with or endorsed by Anthropic")
        );
    }

    #[test]
    fn parses_serve_and_open() {
        let c = Cli::try_parse_from(["ccwm", "serve", "--port", "9000", "--config", "/x/c.toml"])
            .unwrap();
        assert!(matches!(
            c.command,
            Command::Serve {
                port: Some(9000),
                config: Some(_)
            }
        ));
        let c = Cli::try_parse_from(["ccwm", "open", "--print"]).unwrap();
        assert!(matches!(c.command, Command::Open { print: true }));
        assert!(matches!(
            Cli::try_parse_from(["ccwm", "status"]).unwrap().command,
            Command::Status
        ));
        assert!(matches!(
            Cli::try_parse_from(["ccwm", "scan"]).unwrap().command,
            Command::Scan
        ));
        assert!(Cli::try_parse_from(["ccwm", "serve", "--port", "99999"]).is_err());
        assert!(Cli::try_parse_from(["ccwm", "bogus"]).is_err());
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn commit_mismatch_warns_unless_both_builds_are_known_and_equal() {
        let ours = crate::service::COMMIT;
        if ours != "unknown" {
            assert_eq!(commit_mismatch(Some(ours)), None);
        }
        let w = commit_mismatch(Some("0000000000aa")).unwrap();
        assert!(w.contains("0000000000aa") && w.contains(ours) && w.contains("restart"));
        assert!(commit_mismatch(None).unwrap().contains("does not report"));
        assert!(commit_mismatch(Some("unknown")).is_some() || ours == "unknown");
    }

    #[test]
    fn a_closed_output_pipe_is_not_an_error_other_write_failures_are() {
        use std::io::{Error, ErrorKind};
        assert_eq!(output_error_status(&Error::from(ErrorKind::BrokenPipe)), 0);
        assert_eq!(
            output_error_status(&Error::from_raw_os_error(32)),
            0,
            "EPIPE"
        );
        assert_eq!(output_error_status(&Error::from(ErrorKind::StorageFull)), 1);
    }

    #[test]
    fn status_text_shows_the_key_facts_and_unknowns_as_unknown() {
        let v = serde_json::json!({
            "version": "0.1.0", "commit": "abc", "port": 8765, "uptime_s": 5,
            "discovery": {"phase": "idle", "last_success_at": null, "next_scan_at": 10},
            "monitoring": {"watcher": "inotify", "watches": 3, "budget": 8192, "watched_projects": 2,
                           "partial_projects": 4, "polled_projects": 1, "degraded": true, "advice": ["raise it"]},
            "git": {"program": "/usr/bin/git", "version": "2.43.0", "hardened_status": true},
            "sandbox": {"status": "fully_enforced", "abi": 8, "filesystem": true, "network": "tcp_only", "seccomp": "socket_denied"}
        });
        let t = format_status(&v);
        for want in [
            "commit abc",
            "port 8765",
            "last scan unknown",
            "(DEGRADED)",
            "2 watched, 4 partly watched, 1 polled",
            "! raise it",
            "2.43.0",
            "filesystem true, network tcp_only, seccomp socket_denied)",
        ] {
            assert!(t.contains(want), "{want} in {t}");
        }
        assert!(!t.contains("unverified"), "{t}");
    }

    /// v0.1.1 review M2: the projects that the limit on ignore rules across projects holds back
    /// are named (a long list is shortened); none, no line.
    #[test]
    fn status_text_names_the_projects_whose_ignore_rules_are_limited() {
        let status = |names: Vec<String>| {
            format_status(&serde_json::json!({
                "monitoring": {"ignore_rules_limited": names}
            }))
        };
        let t = status(vec!["alpha".into(), "beta".into()]);
        assert!(
            t.contains("! ignore rules limited: 2 project(s) (alpha, beta) lack some of their ignore rules"),
            "{t}"
        );
        assert!(
            t.contains("their scans still use all of their rules"),
            "{t}"
        );
        let many: Vec<String> = (0..11).map(|i| format!("p{i:02}")).collect();
        let t = status(many);
        assert!(
            t.contains("11 project(s) (p00, p01, p02, p03, p04, p05, p06, p07 and 3 more)"),
            "{t}"
        );
        assert!(!status(Vec::new()).contains("ignore rules limited"));
        assert!(!format_status(&serde_json::json!({})).contains("ignore rules limited"));
    }

    /// v0.1.1 review I2: a session listing cut off at the file limit shows in `ccwm status`.
    #[test]
    fn status_text_says_when_the_session_listing_was_cut_off() {
        let cut = format_sessions(&serde_json::json!({
            "sessions": {"state": "ok", "files": 100_000, "indexed": 100_000, "listing_cut": true}
        }));
        assert!(
            cut.contains("! more than 100000 session files: the rest is not indexed"),
            "{cut}"
        );
        let whole = format_sessions(&serde_json::json!({
            "sessions": {"state": "ok", "files": 9, "indexed": 9, "listing_cut": false}
        }));
        assert!(!whole.contains("session files:"), "{whole}");
    }

    /// A protection whose probe failed for an unexpected reason is shown as unverified, not as
    /// `false` (withdrawn) and not as enforced.
    #[test]
    fn status_text_names_unverified_protections() {
        let v = serde_json::json!({
            "sandbox": {"status": "fully_enforced", "abi": 8, "filesystem": false,
                        "network": "unverified", "seccomp": "unverified",
                        "unverified": ["filesystem", "tcp", "udp", "unix_socket_connect_by_path"]}
        });
        let t = format_status(&v);
        assert!(
            t.contains("filesystem unverified, network unverified, seccomp unverified)\n"),
            "{t}"
        );
        assert!(
            t.contains("! unverified (a probe failed for an unexpected reason; neither enforced nor withdrawn): filesystem, tcp, udp, unix_socket_connect_by_path\n"),
            "{t}"
        );
        let report = &v["sandbox"];
        assert_eq!(sandbox_claim(report, "filesystem"), "unverified");
        assert_eq!(
            sandbox_claim(report, "signal"),
            "false",
            "absent: not claimed"
        );
        assert!(string_list(report, "notes").is_empty());
    }

    #[test]
    fn sessions_and_scan_scope_are_summarized() {
        let d = serde_json::json!({
            "scope": "dev_roots", "dev_roots": ["~/dev", "~/work"],
            "sessions": {"state": "ok", "files": 9, "indexed": 9,
                         "unassigned": {"home": 1, "outside_roots": 2}}
        });
        let text = format_sessions(&d);
        assert!(
            text.contains("sessions: ok (9 files, 9 indexed; 3 not in a project)\n")
                && text.contains("    2 outside roots\n    1 home\n"),
            "{text}"
        );
        assert!(text.contains("development roots ~/dev, ~/work"), "{text}");
        let full = format_sessions(
            &serde_json::json!({"scope": "full", "sessions": {"state": "missing", "files": 0, "indexed": 0, "unassigned": {}}}),
        );
        assert!(
            full.contains("sessions: missing (0 files, 0 indexed)") && full.contains("every root"),
            "{full}"
        );
    }

    #[test]
    fn unassigned_sessions_are_broken_down_by_reason_and_folder() {
        let d = serde_json::json!({
            "scope": "full",
            "sessions": {"state": "ok", "files": 900, "indexed": 899, "duplicate_ids": 1,
                         "unassigned": {"excluded": 840, "home": 2, "container": 3},
                         "unassigned_folders": [
                             {"reason": "excluded", "folder": "~/.claude-mem/observer-sessions", "sessions": 831},
                             {"reason": "container", "folder": "~/dev", "sessions": 3},
                             {"reason": "home", "folder": "~", "sessions": 2},
                             {"reason": "excluded", "folder": "~/.config/x", "sessions": 4}
                         ]}
        });
        let text = format_sessions(&d);
        assert_eq!(
            text,
            "  sessions: ok (900 files, 899 indexed; 845 not in a project; 1 duplicate session files skipped)\n\
             \x20   831 excluded (~/.claude-mem/observer-sessions)\n\
             \x20   4 excluded (~/.config/x)\n\
             \x20   5 excluded (other folders)\n\
             \x20   3 container (~/dev)\n\
             \x20   2 home (~)\n\
             \x20 marker scan: every root\n"
        );
    }

    #[test]
    fn unreadable_folders_are_listed_with_correct_plurals() {
        assert_eq!(folders(1), "1 folder");
        assert_eq!(folders(0), "0 folders");
        assert_eq!(folders(2), "2 folders");
        let none = serde_json::json!({"skipped": {"permission": 0}, "unreadable": []});
        assert_eq!(format_unreadable(&none), "");
        let one = serde_json::json!({"skipped": {"permission": 1, "excluded": 9},
            "unreadable": [{"path": "~/locked", "reason": "permission"}]});
        assert_eq!(
            format_unreadable(&one),
            "  1 folder could not be read in the last scan:\n    ~/locked (permission)\n"
        );
        let many = serde_json::json!({"skipped": {"permission": 2, "vanished": 1, "changed": 1, "other": 1},
            "unreadable": [{"path": "~/a", "reason": "permission"}, {"path": "/srv/b", "reason": "vanished"}]});
        let t = format_unreadable(&many);
        assert!(t.starts_with("  5 folders could not be read"), "{t}");
        assert!(
            t.contains("    /srv/b (vanished)\n") && t.ends_with("    … and 3 more\n"),
            "{t}"
        );
    }

    #[test]
    fn the_first_call_waits_only_for_a_daemon_that_is_not_running_yet() {
        let step = Duration::from_millis(1);
        let mut n = 0;
        let r = retry_while_starting(Duration::from_secs(5), step, || {
            n += 1;
            if n < 4 {
                Err(Error::not_running("starting"))
            } else {
                Ok(n)
            }
        });
        assert_eq!(r.unwrap(), 4, "succeeds once the daemon answers");

        let started = std::time::Instant::now();
        let mut n = 0;
        let r: Result<()> = retry_while_starting(Duration::from_millis(50), step, || {
            n += 1;
            Err(Error::not_running("never"))
        });
        assert!(r.unwrap_err().is_not_running());
        assert!(
            n > 1 && started.elapsed() < Duration::from_secs(2),
            "gives up after the wait"
        );

        let mut n = 0;
        let r: Result<()> = retry_while_starting(Duration::from_secs(5), step, || {
            n += 1;
            Err(Error::new(
                "refusing to talk to the process on the ccwm socket",
            ))
        });
        assert!(
            r.is_err() && n == 1,
            "other errors (e.g. an impostor) fail at once"
        );
    }
}
