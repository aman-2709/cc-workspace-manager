//! `ccwm doctor` (REQUIREMENTS.md §13): checks the installation and the running daemon and
//! suggests fixes. It **never applies** one (no `sysctl`, no `chmod`, no `loginctl`).
//!
//! What only the daemon knows (the active Landlock and seccomp protections, its `claude` check,
//! which runs inside its sandbox, its watch budget) comes from `service.status` over the
//! verified Unix socket. Without a running daemon those checks say so instead of guessing; the
//! local checks (permissions, limits, Git, the session directory, the port, systemd, lingering)
//! run either way. Each evaluation is a pure function of what was gathered, so it is unit-tested.

use crate::client;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::paths::{self, current_home, Dirs, EnvVars, Owner};
use crate::systemd;
use serde_json::Value;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// A suggested fix (never applied by ccwm).
    pub fix: Option<String>,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
        fix: None,
    }
}

impl Check {
    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

fn s<'a>(v: &'a Value, path: &str) -> &'a str {
    v.pointer(path).and_then(Value::as_str).unwrap_or("unknown")
}

fn n(v: &Value, path: &str) -> Option<u64> {
    v.pointer(path).and_then(Value::as_u64)
}

pub fn format(checks: &[Check]) -> String {
    let mut out = String::from("ccwm doctor (suggestions only; nothing is changed)\n");
    for c in checks {
        out.push_str(&format!(
            "  [{:>4}] {}: {}\n",
            c.level.tag(),
            c.name,
            c.detail
        ));
        if let Some(fix) = &c.fix {
            out.push_str(&format!("         fix: {fix}\n"));
        }
    }
    out
}

// ---- evaluations (pure) -------------------------------------------------------------------

/// The daemon, as seen over the Unix socket.
pub fn daemon(ping: &std::result::Result<Value, String>, not_running: bool) -> Check {
    match ping {
        Ok(p) => {
            let mut c = check(
                "daemon",
                Level::Ok,
                format!(
                    "running, version {} (commit {}), verified over the Unix socket",
                    s(p, "/version"),
                    s(p, "/commit")
                ),
            );
            if let Some(w) = crate::cli::commit_mismatch(p.get("commit").and_then(Value::as_str)) {
                c.level = Level::Warn;
                c.detail.push_str(&format!("; {w}"));
            }
            c
        }
        Err(e) if not_running => check("daemon", Level::Warn, format!("not running ({e})"))
            .fix("`ccwm start` (systemd) or `ccwm serve` (foreground)"),
        Err(e) => check("daemon", Level::Fail, e.clone()),
    }
}

/// The session activity indicator (REQUIREMENTS.md §21.10): informational only — hooks are
/// opt-in, so none received is no failure. No settings file is read.
pub fn hooks(status: Option<&Value>) -> Check {
    let Some(h) = status else {
        return check(
            "hooks",
            Level::Info,
            "the daemon is not running: hook events cannot be checked",
        );
    };
    match h.get("last_event_at").and_then(Value::as_i64) {
        None => check(
            "hooks",
            Level::Info,
            "no hook event since the daemon started; the session activity indicator is opt-in (`ccwm hooks print`)",
        ),
        Some(_) => check(
            "hooks",
            Level::Info,
            format!(
                "last hook event {}; {} received, {} refused; {} open session(s)",
                crate::cli::when(h, "/last_event_at"),
                n(h, "/received").unwrap_or(0),
                ["malformed", "no_claude_ancestor", "pid_mismatch", "limit"]
                    .iter()
                    .filter_map(|k| n(h, &format!("/refused/{k}")))
                    .sum::<u64>(),
                n(h, "/open").unwrap_or(0) + n(h, "/hidden_noninteractive").unwrap_or(0),
            ),
        ),
    }
}

/// The TCP port: the daemon's, or (no daemon) whether the configured one is free.
pub fn port(status: Option<&Value>, configured: u16, free: Option<bool>) -> Check {
    if let Some(st) = status {
        return check(
            "port",
            Level::Ok,
            format!(
                "the daemon listens on 127.0.0.1:{} (TCP peer check: {})",
                n(st, "/port").unwrap_or(0),
                s(st, "/peer_lookup")
            ),
        );
    }
    match free {
        Some(true) => check("port", Level::Ok, format!("127.0.0.1:{configured} is free")),
        Some(false) => check(
            "port",
            Level::Fail,
            format!(
                "127.0.0.1:{configured} is used by another process: ccwm would exit with code {} (it never picks another port)",
                crate::error::EXIT_PORT_IN_USE
            ),
        )
        .fix(format!("find it with `ss -ltnp 'sport = :{configured}'`, or choose another port: [server] port in config.toml or `ccwm serve --port N`")),
        None => check("port", Level::Info, format!("could not test 127.0.0.1:{configured}")),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Inotify {
    pub max_user_watches: Option<u64>,
    pub max_user_instances: Option<u64>,
    /// Instances and watches held by all of this user's processes.
    pub instances_used: Option<u64>,
    pub watches_used: Option<u64>,
}

pub const SYSCTL_FIX: &str = "raise the limits (needs an administrator), e.g. `echo fs.inotify.max_user_watches=524288 | sudo tee /etc/sysctl.d/90-inotify.conf && sudo sysctl --system` (and max_user_instances likewise); ccwm never changes them";

pub fn inotify(i: &Inotify, monitoring: Option<&Value>) -> Check {
    let show = |v: Option<u64>| v.map_or_else(|| "unknown".to_string(), |x| x.to_string());
    let mut detail = format!(
        "max_user_watches {}, max_user_instances {}; this user's processes hold {} instances and {} watches",
        show(i.max_user_watches),
        show(i.max_user_instances),
        show(i.instances_used),
        show(i.watches_used)
    );
    let mut level = Level::Ok;
    let mut fix = None;
    if let Some(m) = monitoring {
        detail.push_str(&format!(
            "; ccwm: {} watches of a budget of {}, {} watched / {} partly watched / {} polled projects",
            n(m, "/watches").unwrap_or(0),
            n(m, "/budget").unwrap_or(0),
            n(m, "/watched_projects").unwrap_or(0),
            n(m, "/partial_projects").unwrap_or(0),
            n(m, "/polled_projects").unwrap_or(0),
        ));
        if m.get("watcher").and_then(Value::as_str) != Some("inotify") {
            level = Level::Fail;
            detail.push_str("; the daemon has NO inotify instance (every project is polled)");
            fix = Some(SYSCTL_FIX.to_string());
        } else if m.get("degraded") == Some(&Value::Bool(true)) {
            level = Level::Warn;
            let advice: Vec<&str> = m
                .get("advice")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            detail.push_str("; monitoring is DEGRADED");
            if !advice.is_empty() {
                detail.push_str(&format!(" ({})", advice.join("; ")));
            }
            fix = Some(SYSCTL_FIX.to_string());
        }
    } else if let (Some(max), Some(used)) = (i.max_user_instances, i.instances_used) {
        if used >= max {
            level = Level::Fail;
            detail.push_str("; no inotify instance is left: ccwm would poll every project");
            fix = Some(SYSCTL_FIX.to_string());
        }
    }
    Check {
        name: "inotify",
        level,
        detail,
        fix,
    }
}

pub fn git(local: &crate::git::GitSummary, daemon: Option<&Value>) -> Check {
    let Some(version) = &local.version else {
        return check(
            "git",
            Level::Warn,
            "git not found on PATH: Git status is not shown (everything else works)",
        )
        .fix("install git (2.41.0 or later)");
    };
    let mut c = if local.hardened_status {
        check(
            "git",
            Level::Ok,
            format!(
                "{} {version}: hardened worktree status available (tested on 2.43.0)",
                local.program.as_deref().unwrap_or("git")
            ),
        )
    } else if local.unhardened_status_allowed {
        check(
            "git",
            Level::Warn,
            format!("git {version} is older than 2.41.0: worktree status runs UNHARDENED (git.allow_unhardened_status = true)"),
        )
        .fix("upgrade git to 2.41.0 or later and remove git.allow_unhardened_status")
    } else {
        check(
            "git",
            Level::Warn,
            format!("git {version} is older than 2.41.0: worktree status is disabled (it cannot be hardened)"),
        )
        .fix("upgrade git to 2.41.0 or later")
    };
    if let Some(d) = daemon {
        if d.get("version").and_then(Value::as_str) != Some(version.as_str()) {
            c.detail.push_str(&format!(
                "; the daemon uses {} {}",
                s(d, "/program"),
                s(d, "/version")
            ));
        }
    }
    c
}

/// `claude`: the daemon's sandboxed check; locally only located (never run outside the sandbox).
pub fn claude(daemon: Option<&Value>, local: Option<&Path>) -> Check {
    let local_s = local.map(|p| p.display().to_string());
    let Some(d) = daemon else {
        return check(
            "claude",
            Level::Info,
            match &local_s {
                Some(p) => format!("found at {p}; the daemon verifies `--resume` support inside its sandbox when it runs"),
                None => "not on this shell's PATH; resume commands are still shown, with a warning".into(),
            },
        );
    };
    let state = s(d, "/state");
    match state {
        "verified" => check(
            "claude",
            Level::Ok,
            format!("{} {}, `--resume` supported (checked by the daemon, in its sandbox)", s(d, "/program"), s(d, "/version")),
        ),
        "not_found" => {
            let c = check(
                "claude",
                Level::Warn,
                "the daemon cannot find `claude` on its PATH: resume commands carry a warning",
            );
            match local_s {
                Some(p) => c.fix(format!(
                    "your shell finds {p}: add its directory to the service's PATH with `systemctl --user edit ccwm` ([Service] Environment=PATH=…), then `ccwm restart`"
                )),
                None => c.fix("install Claude Code, then `ccwm restart`"),
            }
        }
        "no_resume" => check("claude", Level::Warn, format!("{} {} does not list `--resume`", s(d, "/program"), s(d, "/version")))
            .fix("update Claude Code"),
        other => check(
            "claude",
            Level::Warn,
            format!("{} could not be checked ({other})", s(d, "/program")),
        )
        .fix("a `claude` outside your home and the system paths cannot be executed inside the sandbox; see docs/troubleshooting.md"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionDir {
    Readable { projects: Option<usize> },
    Missing,
    Unreadable(String),
}

pub fn sessions(dir: &Path, found: &SessionDir, discovery: Option<&Value>) -> Check {
    let mut c = match found {
        SessionDir::Readable {
            projects: Some(k),
        } => check(
            "sessions",
            Level::Ok,
            format!("{} is readable ({k} project folders)", dir.display()),
        ),
        SessionDir::Readable { projects: None } => check(
            "sessions",
            Level::Warn,
            format!("{} has no projects/ folder yet (no Claude Code sessions)", dir.display()),
        ),
        SessionDir::Missing => check(
            "sessions",
            Level::Warn,
            format!("{} does not exist: only CLAUDE.md markers discover projects", dir.display()),
        )
        .fix("set [sessions] dir in config.toml (or CLAUDE_CONFIG_DIR) if Claude Code keeps its data elsewhere"),
        SessionDir::Unreadable(e) => check(
            "sessions",
            Level::Fail,
            format!("{} cannot be read: {e}", dir.display()),
        ),
    };
    if let Some(d) = discovery {
        c.detail.push_str(&format!(
            "; daemon: {} ({} files, {} indexed)",
            s(d, "/sessions/state"),
            n(d, "/sessions/files").unwrap_or(0),
            n(d, "/sessions/indexed").unwrap_or(0)
        ));
    }
    c
}

/// One of ccwm's directories (or files): must be ours and private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    /// `None`: does not exist (yet).
    pub uid_mode: Option<(u32, u32)>,
    pub dir: bool,
    /// `Owner::verify_trusted` on the path and its ancestors.
    pub trusted: std::result::Result<(), String>,
}

pub fn permissions(entries: &[Entry], uid: u32) -> Check {
    let mut problems = Vec::new();
    let mut fixes = Vec::new();
    for e in entries {
        if let Err(msg) = &e.trusted {
            problems.push(msg.clone());
            continue;
        }
        let Some((owner, mode)) = e.uid_mode else {
            continue;
        };
        let want = if e.dir { 0o700 } else { 0o600 };
        if owner != uid {
            problems.push(format!("{} is owned by uid {owner}", e.path.display()));
        } else if mode & 0o077 != 0 {
            problems.push(format!(
                "{} has mode {:o} (want {want:o})",
                e.path.display(),
                mode & 0o7777
            ));
            fixes.push(format!("chmod {want:o} {}", e.path.display()));
        }
    }
    if problems.is_empty() {
        return check(
            "permissions",
            Level::Ok,
            "ccwm's directories are 0700 and its files 0600, owned by you, with trusted ancestors",
        );
    }
    let c = check("permissions", Level::Fail, problems.join("; "));
    if fixes.is_empty() {
        c
    } else {
        c.fix(fixes.join(" && "))
    }
}

/// Landlock, seccomp and the daemon's own probes (from its report), or what the kernel offers.
pub fn sandbox(report: Option<&Value>, lsm: Option<&str>) -> Check {
    let Some(r) = report else {
        let listed = lsm.is_some_and(|l| l.split(',').any(|m| m.trim() == "landlock"));
        return if listed {
            check(
                "sandbox",
                Level::Info,
                "Landlock is enabled in this kernel; the active protections (ABI, filesystem, TCP, seccomp) are reported once the daemon runs",
            )
        } else {
            check(
                "sandbox",
                Level::Warn,
                "Landlock is not listed in /sys/kernel/security/lsm: ccwm would run without filesystem and TCP confinement",
            )
            .fix("use a kernel with Landlock enabled (Linux 6.7+ for TCP rules; add `landlock` to the lsm= boot parameter); see docs/troubleshooting.md")
        };
    };
    let abi = n(r, "/abi").map_or_else(|| "none".to_string(), |a| a.to_string());
    let claim = |kind| crate::cli::sandbox_claim(r, kind);
    let unverified = crate::cli::string_list(r, "unverified");
    let detail = format!(
        "Landlock {} (ABI {abi}; filesystem {}, network {}, abstract sockets {}, signals {}); seccomp {}; daemon probes: write {}, connect {}, socket {}/{}; unconfined: [{}]; unverified: [{}]",
        s(r, "/status"),
        claim("filesystem"),
        s(r, "/network"),
        claim("abstract_unix_socket"),
        claim("signal"),
        s(r, "/seccomp"),
        s(r, "/daemon_probes/write"),
        s(r, "/daemon_probes/connect"),
        s(r, "/daemon_probes/socket_worker"),
        s(r, "/daemon_probes/socket_blocking"),
        crate::cli::string_list(r, "unconfined").join(", "),
        unverified.join(", ")
    );
    if !unverified.is_empty() {
        return check("sandbox", Level::Warn, detail).fix(
            "a probe failed for an unexpected reason, so these protections are neither confirmed nor disproved; the reason is in the daemon's log and in `GET /api/v1/service/status` (sandbox.notes); see docs/troubleshooting.md",
        );
    }
    let full = s(r, "/status") == "fully_enforced"
        && s(r, "/network") == "tcp_only"
        && s(r, "/seccomp") == "socket_denied";
    if full {
        check("sandbox", Level::Ok, detail)
    } else {
        check("sandbox", Level::Warn, detail)
            .fix("see the notes in `GET /api/v1/service/status` (sandbox.notes) and docs/troubleshooting.md")
    }
}

pub fn linger(enabled: Option<bool>, user: Option<&str>) -> Check {
    match enabled {
        Some(true) => check("lingering", Level::Ok, "enabled: the user service starts at boot"),
        Some(false) => check(
            "lingering",
            Level::Info,
            "disabled: the user service starts when you log in and stops at your last logout",
        )
        .fix(format!(
            "to start at boot: `loginctl enable-linger {}` (may need administrator authorization; ccwm never runs it)",
            user.unwrap_or("$USER")
        )),
        None => check("lingering", Level::Info, "unknown (user name not found)"),
    }
}

// ---- gathering (side effects: reads, one `git --version`, one bind test) -------------------

/// Instances and watches held by this user's processes (`/proc/<pid>/fd` → `anon_inode:inotify`,
/// watches counted in `/proc/<pid>/fdinfo/<fd>`).
pub fn inotify_usage(uid: u32) -> (u64, u64) {
    let (mut instances, mut watches) = (0, 0);
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return (0, 0);
    };
    for p in procs.flatten() {
        let name = p.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if p.metadata().map(|m| m.uid()).ok() != Some(uid) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|t| t.as_os_str() == "anon_inode:inotify") {
                instances += 1;
                if let Ok(info) =
                    std::fs::read_to_string(p.path().join("fdinfo").join(fd.file_name()))
                {
                    watches += info
                        .lines()
                        .filter(|l| l.starts_with("inotify wd:"))
                        .count() as u64;
                }
            }
        }
    }
    (instances, watches)
}

fn read_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn entry(path: &Path, owner: &Owner) -> Entry {
    let md = std::fs::symlink_metadata(path).ok();
    Entry {
        path: path.to_path_buf(),
        uid_mode: md.as_ref().map(|m| (m.uid(), m.mode())),
        dir: md.as_ref().is_none_or(std::fs::Metadata::is_dir),
        trusted: owner.verify_trusted(path).map_err(|e| e.to_string()),
    }
}

fn session_dir_state(dir: &Path) -> SessionDir {
    match std::fs::read_dir(dir) {
        Ok(_) => SessionDir::Readable {
            projects: std::fs::read_dir(dir.join("projects"))
                .ok()
                .map(|d| d.flatten().filter(|e| e.path().is_dir()).count()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SessionDir::Missing,
        Err(e) => SessionDir::Unreadable(e.to_string()),
    }
}

/// Gather everything and evaluate it.
pub fn checks() -> Result<Vec<Check>> {
    let uid = nix::unistd::geteuid().as_raw();
    let home = current_home(uid)?;
    let env = EnvVars::from_process();
    let dirs = Dirs::resolve(&env, &home);
    let owner = Owner::current(uid);
    let mut out = Vec::new();

    let call = |op: &str| {
        dirs.verify_runtime(&owner)
            .and_then(|()| client::call(&dirs.socket_path(), uid, op))
    };
    let ping = call("ping");
    let not_running = ping.as_ref().err().is_some_and(Error::is_not_running);
    out.push(daemon(
        &ping.as_ref().map(Value::clone).map_err(ToString::to_string),
        not_running,
    ));
    let status = ping.is_ok().then(|| call("service.status").ok()).flatten();
    let discovery = ping
        .is_ok()
        .then(|| call("discovery.status").ok())
        .flatten();

    let systemctl = systemd::Systemctl::find(systemd::path_var().as_deref());
    let line = systemd::status_line(&systemctl);
    let unit_ok = line.contains(" active ");
    out.push(check(
        "systemd",
        if unit_ok { Level::Ok } else { Level::Info },
        line.trim_start_matches("systemd: ").to_string(),
    ));
    let user = systemd::user_name(uid);
    out.push(linger(
        systemd::linger_enabled(user.as_deref()),
        user.as_deref(),
    ));

    let config = Config::load(&dirs.config_file(), &owner);
    let configured = config.as_ref().map_or(8765, |c| c.server.port);
    let free =
        status.is_none().then(
            || match std::net::TcpListener::bind(("127.0.0.1", configured)) {
                Ok(_) => Some(true),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Some(false),
                Err(_) => None,
            },
        );
    out.push(port(status.as_ref(), configured, free.flatten()));
    if let Err(e) = &config {
        out.push(check("config", Level::Fail, e.to_string()));
    }

    let (instances, watches) = inotify_usage(uid);
    out.push(inotify(
        &Inotify {
            max_user_watches: read_u64("/proc/sys/fs/inotify/max_user_watches"),
            max_user_instances: read_u64("/proc/sys/fs/inotify/max_user_instances"),
            instances_used: Some(instances),
            watches_used: Some(watches),
        },
        status.as_ref().and_then(|s| s.get("monitoring")),
    ));

    let allow_unhardened = config.as_ref().is_ok_and(|c| c.git.allow_unhardened_status);
    let local_git = crate::git::Git::detect(
        crate::git::find_on_path(systemd::path_var().as_deref()),
        &home,
        allow_unhardened,
    )
    .summary();
    out.push(git(&local_git, status.as_ref().and_then(|s| s.get("git"))));
    out.push(claude(
        status
            .as_ref()
            .and_then(|s| s.get("claude"))
            .filter(|c| !c.is_null()),
        paths::find_executable("claude", systemd::path_var().as_deref()).as_deref(),
    ));

    let session_dir = config
        .as_ref()
        .ok()
        .and_then(|c| c.sessions.dir.clone())
        .unwrap_or_else(|| paths::session_dir(&env, &home));
    out.push(sessions(
        &session_dir,
        &session_dir_state(&session_dir),
        discovery.as_ref(),
    ));
    out.push(hooks(status.as_ref().and_then(|s| s.get("hooks"))));

    let mut entries: Vec<Entry> = dirs.all().iter().map(|d| entry(d, &owner)).collect();
    for f in [
        dirs.db_path(),
        dirs.data.join(format!("{}-wal", paths::DB_NAME)),
        dirs.data.join(format!("{}-shm", paths::DB_NAME)),
        dirs.config_file(),
    ] {
        entries.push(entry(&f, &owner));
    }
    out.push(permissions(&entries, uid));

    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").ok();
    out.push(sandbox(
        status.as_ref().and_then(|s| s.get("sandbox")),
        lsm.as_deref(),
    ));
    Ok(out)
}

pub fn run() -> Result<()> {
    let checks = checks()?;
    crate::cli::out!("{}", format(&checks));
    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    if failed > 0 {
        return Err(Error::new(format!(
            "{failed} check{} failed",
            if failed == 1 { "" } else { "s" }
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_daemon_check_separates_not_running_from_impostors() {
        let ok = daemon(
            &Ok(json!({"version": "0.1.0", "commit": crate::service::COMMIT})),
            false,
        );
        assert_eq!(
            ok.level,
            if crate::service::COMMIT == "unknown" {
                Level::Warn
            } else {
                Level::Ok
            }
        );
        let down = daemon(&Err("no runtime directory".into()), true);
        assert_eq!(down.level, Level::Warn);
        assert!(down.fix.unwrap().contains("ccwm start"));
        let impostor = daemon(
            &Err("refusing to talk to the process on the ccwm socket".into()),
            false,
        );
        assert_eq!(impostor.level, Level::Fail);
        let old = daemon(
            &Ok(json!({"version": "0.1.0", "commit": "000000000000"})),
            false,
        );
        assert_eq!(old.level, Level::Warn);
        assert!(old.detail.contains("restart"));
    }

    #[test]
    fn a_used_port_fails_with_the_dedicated_exit_code() {
        let used = port(None, 8765, Some(false));
        assert_eq!(used.level, Level::Fail);
        assert!(used.detail.contains("code 10") && used.fix.is_some());
        assert_eq!(port(None, 8765, Some(true)).level, Level::Ok);
        let running = port(
            Some(&json!({"port": 9000, "peer_lookup": "sock_diag"})),
            8765,
            None,
        );
        assert!(running.detail.contains("127.0.0.1:9000") && running.detail.contains("sock_diag"));
    }

    #[test]
    fn inotify_degradation_and_exhaustion_suggest_the_sysctl_but_never_run_it() {
        let limits = Inotify {
            max_user_watches: Some(65536),
            max_user_instances: Some(128),
            instances_used: Some(109),
            watches_used: Some(4000),
        };
        let fine = inotify(
            &limits,
            Some(&json!({"watcher": "inotify", "watches": 40, "budget": 16384, "degraded": false})),
        );
        assert_eq!(fine.level, Level::Ok);
        assert!(
            fine.detail.contains("max_user_watches 65536") && fine.detail.contains("109 instances")
        );
        let degraded = inotify(
            &limits,
            Some(
                &json!({"watcher": "inotify", "degraded": true, "advice": ["raise max_user_watches"]}),
            ),
        );
        assert_eq!(degraded.level, Level::Warn);
        assert!(degraded.detail.contains("raise max_user_watches"));
        assert!(degraded.fix.as_deref().unwrap().contains("sysctl"));
        let none = inotify(&limits, Some(&json!({"watcher": "none"})));
        assert_eq!(none.level, Level::Fail);
        let full = Inotify {
            instances_used: Some(128),
            ..limits
        };
        assert_eq!(inotify(&full, None).level, Level::Fail);
        assert_eq!(inotify(&limits, None).level, Level::Ok);
    }

    #[test]
    fn git_versions_and_the_hardening_gate() {
        use crate::git::GitSummary;
        let g = |version: Option<&str>, hardened, allowed| GitSummary {
            program: Some("/usr/bin/git".into()),
            version: version.map(str::to_string),
            hardened_status: hardened,
            unhardened_status_allowed: allowed,
        };
        assert_eq!(git(&g(Some("2.43.0"), true, false), None).level, Level::Ok);
        let old = git(&g(Some("2.39.0"), false, false), None);
        assert!(old.level == Level::Warn && old.detail.contains("disabled"));
        let risky = git(&g(Some("2.39.0"), false, true), None);
        assert!(risky.detail.contains("UNHARDENED"));
        assert_eq!(git(&g(None, false, false), None).level, Level::Warn);
        let differs = git(
            &g(Some("2.43.0"), true, false),
            Some(&json!({"program": "/opt/git", "version": "2.45.0"})),
        );
        assert!(differs.detail.contains("/opt/git 2.45.0"));
    }

    #[test]
    fn claude_is_judged_by_the_daemons_sandboxed_check_and_only_located_here() {
        let here = Path::new("/home/u/.local/bin/claude");
        let info = claude(None, Some(here));
        assert_eq!(info.level, Level::Info);
        assert!(info.detail.contains("inside its sandbox"));
        let ok = claude(
            Some(&json!({"state": "verified", "program": "/x/claude", "version": "2.1"})),
            None,
        );
        assert_eq!(ok.level, Level::Ok);
        let path = claude(Some(&json!({"state": "not_found"})), Some(here));
        assert_eq!(path.level, Level::Warn);
        assert!(path.fix.unwrap().contains("systemctl --user edit ccwm"));
        assert_eq!(
            claude(Some(&json!({"state": "failed", "program": "/opt/c"})), None).level,
            Level::Warn
        );
    }

    #[test]
    fn session_directory_states() {
        let d = Path::new("/h/.claude");
        assert_eq!(
            sessions(d, &SessionDir::Readable { projects: Some(3) }, None).level,
            Level::Ok
        );
        assert_eq!(
            sessions(d, &SessionDir::Readable { projects: None }, None).level,
            Level::Warn
        );
        assert_eq!(sessions(d, &SessionDir::Missing, None).level, Level::Warn);
        assert_eq!(
            sessions(d, &SessionDir::Unreadable("EACCES".into()), None).level,
            Level::Fail
        );
        let with = sessions(
            d,
            &SessionDir::Readable { projects: Some(1) },
            Some(&json!({"sessions": {"state": "ok", "files": 7, "indexed": 7}})),
        );
        assert!(with.detail.contains("7 files, 7 indexed"));
    }

    #[test]
    fn permissions_need_private_modes_owned_by_us() {
        let ok = |p: &str, dir, mode| Entry {
            path: PathBuf::from(p),
            uid_mode: Some((1000, mode)),
            dir,
            trusted: Ok(()),
        };
        let fine = [ok("/d", true, 0o40700), ok("/d/ccwm.db", false, 0o100600)];
        assert_eq!(permissions(&fine, 1000).level, Level::Ok);
        let loose = [ok("/d", true, 0o40750)];
        let c = permissions(&loose, 1000);
        assert_eq!(c.level, Level::Fail);
        assert_eq!(c.fix.as_deref(), Some("chmod 700 /d"));
        let foreign = [Entry {
            uid_mode: Some((0, 0o40700)),
            ..ok("/d", true, 0)
        }];
        assert!(permissions(&foreign, 1000)
            .detail
            .contains("owned by uid 0"));
        let untrusted = [Entry {
            trusted: Err("/x has mode 777".into()),
            ..ok("/x", true, 0)
        }];
        assert!(permissions(&untrusted, 1000).detail.contains("mode 777"));
        let absent = [Entry {
            uid_mode: None,
            ..ok("/later", true, 0)
        }];
        assert_eq!(
            permissions(&absent, 1000).level,
            Level::Ok,
            "created privately on start"
        );
    }

    #[test]
    fn the_sandbox_check_reports_what_the_daemon_verified() {
        let full = json!({"status": "fully_enforced", "abi": 8, "filesystem": true, "network": "tcp_only",
                          "abstract_unix_socket": true, "signal": true, "seccomp": "socket_denied",
                          "daemon_probes": {"write": "eacces", "connect": "eacces", "socket_worker": "eperm", "socket_blocking": "eperm"},
                          "unconfined": []});
        let c = sandbox(Some(&full), None);
        assert_eq!(c.level, Level::Ok, "{}", c.detail);
        assert!(c.detail.contains("ABI 8") && c.detail.contains("seccomp socket_denied"));
        let mut partial = full.clone();
        partial["seccomp"] = json!("not_applied");
        assert_eq!(sandbox(Some(&partial), None).level, Level::Warn);
        // A probe that failed for an unexpected reason: shown as unverified, with its own advice,
        // never as enforced and never as withdrawn.
        let mut odd = full.clone();
        odd["filesystem"] = json!(false);
        odd["unverified"] = json!(["filesystem"]);
        odd["daemon_probes"]["write"] = json!("error:Unsupported");
        let c = sandbox(Some(&odd), None);
        assert_eq!(c.level, Level::Warn);
        assert!(
            c.detail.contains("filesystem unverified, network tcp_only")
                && c.detail.contains("write error:Unsupported")
                && c.detail
                    .contains("unconfined: []; unverified: [filesystem]"),
            "{}",
            c.detail
        );
        assert!(c.fix.unwrap().contains("neither confirmed nor disproved"));
        assert_eq!(
            sandbox(None, Some("lockdown,capability,landlock,yama,apparmor")).level,
            Level::Info
        );
        assert_eq!(
            sandbox(None, Some("capability,apparmor")).level,
            Level::Warn
        );
        assert_eq!(sandbox(None, None).level, Level::Warn);
    }

    #[test]
    fn lingering_is_suggested_never_enabled() {
        assert_eq!(linger(Some(true), Some("u")).level, Level::Ok);
        let off = linger(Some(false), Some("alice"));
        assert!(off.fix.unwrap().contains("loginctl enable-linger alice"));
    }

    #[test]
    fn output_lists_every_check_with_its_fix() {
        let text = format(&[
            check("a", Level::Ok, "fine"),
            check("b", Level::Fail, "broken").fix("do x"),
        ]);
        assert!(
            text.contains("[  ok] a: fine\n")
                && text.contains("[FAIL] b: broken\n         fix: do x\n"),
            "{text}"
        );
        assert!(text.starts_with("ccwm doctor (suggestions only; nothing is changed)"));
    }
}
