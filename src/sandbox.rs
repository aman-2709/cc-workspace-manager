//! Landlock self-sandbox (REQUIREMENTS.md §11.5).
//!
//! `apply` must run on the main thread **before any other thread exists**: `landlock_restrict_self`
//! confines only the calling thread and the threads/processes it creates afterwards. `apply` checks
//! that `/proc/self/task` has exactly one entry and otherwise reports `not_enforced`. After the
//! runtime starts, the daemon probes a worker thread and a blocking-pool thread
//! ([`SandboxReport::record_thread_probes`]). The ruleset is inherited by child processes (git,
//! `claude --version`), which must be built with [`child_command`] so that session IPC endpoints
//! (D-Bus, agents) are not advertised to them. The [`SandboxReport`] states what is actually
//! enforced, never what was requested.

use crate::error::{Error, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

/// ABI whose access rights we request: filesystem rules (V1–V3) and TCP bind/connect (V4). Newer
/// kernels are used in best-effort mode; newer access rights (device ioctls, `ResolveUnix` in V9)
/// are not requested in v0.1.
const TARGET_ABI: ABI = ABI::V4;
/// Scopes (V6): abstract Unix sockets and signals cannot reach processes outside the sandbox.
const SCOPE_ABI: ABI = ABI::V6;

/// System locations the daemon and its children (git, claude) need to read and execute.
pub const SYSTEM_READ_PATHS: [&str; 7] =
    ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin", "/proc"];

/// Environment variables that point a process at session IPC endpoints (message buses, agents,
/// display servers, service managers). Removed from every child's environment, together with any
/// other `DBUS_*` variable: Landlock does not confine `connect()` on path-based Unix sockets.
pub const IPC_ENV_VARS: [&str; 18] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "DBUS_STARTER_ADDRESS",
    "DBUS_STARTER_BUS_TYPE",
    "XDG_RUNTIME_DIR", // sd-bus falls back to $XDG_RUNTIME_DIR/bus
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "SESSION_MANAGER",
    "AT_SPI_BUS_ADDRESS",
    "PULSE_SERVER",
    "NOTIFY_SOCKET",
    "LISTEN_FDS",
    "LISTEN_PID",
    "LISTEN_FDNAMES",
];

/// What Landlock never confines in v0.1, whatever the kernel: always listed in the report.
pub const ALWAYS_UNCONFINED: [&str; 2] = ["udp", "unix_socket_connect_by_path"];

#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Readable and executable (discovery roots, session dir, system paths).
    pub read: Vec<PathBuf>,
    /// Readable and writable (ccwm's own config/data/state/runtime directories).
    pub read_write: Vec<PathBuf>,
    /// The only TCP port the process may bind (`None`/`0`: any bind is denied or, for 0, ephemeral).
    pub tcp_bind_port: Option<u16>,
}

/// Outcome of one confinement probe (a read of a directory outside every rule).
pub const PROBE_DENIED: &str = "eacces";
pub const PROBE_ALLOWED: &str = "allowed";
pub const PROBE_SKIPPED: &str = "skipped";
pub const PROBE_NOT_RUN: &str = "not_run";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadProbes {
    /// A Tokio worker thread.
    pub worker: String,
    /// A Tokio blocking-pool thread (where discovery and SQLite run).
    pub blocking: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SandboxReport {
    /// Landlock ABI version the running kernel supports (as understood by this build); `None` if unavailable.
    pub abi: Option<u8>,
    /// `fully_enforced`, `partially_enforced` or `not_enforced`.
    pub status: &'static str,
    /// Filesystem access is confined (writes only under ccwm's directories; reads only under the allowed paths).
    pub filesystem: bool,
    /// `tcp_only`: all TCP `connect` is denied and TCP `bind` is limited to the configured port.
    /// UDP and other socket families are not confined (see `unconfined`). `none`: no network rules.
    pub network: &'static str,
    /// Connecting to abstract Unix sockets created outside the sandbox is denied (ABI 6).
    pub abstract_unix_socket: bool,
    /// Sending signals to processes outside the sandbox is denied (ABI 6).
    pub signal: bool,
    pub no_new_privs: bool,
    /// Threads in the process when the ruleset was applied (must be 1); `None` if unknown.
    pub threads_at_apply: Option<usize>,
    /// Confinement verified from threads created after `apply`.
    pub thread_probes: ThreadProbes,
    /// Read rules that are `/` or an ancestor of the home directory (read confinement is weak).
    pub broad_read_rules: Vec<String>,
    /// Kinds of access that are not confined.
    pub unconfined: Vec<&'static str>,
    pub notes: Vec<String>,
}

impl SandboxReport {
    pub fn disabled(reason: impl Into<String>) -> Self {
        let mut r = Self {
            abi: None,
            status: "not_enforced",
            filesystem: false,
            network: "none",
            abstract_unix_socket: false,
            signal: false,
            no_new_privs: false,
            threads_at_apply: None,
            thread_probes: ThreadProbes {
                worker: PROBE_NOT_RUN.into(),
                blocking: PROBE_NOT_RUN.into(),
            },
            broad_read_rules: Vec::new(),
            unconfined: Vec::new(),
            notes: vec![reason.into()],
        };
        r.unconfined = r.compute_unconfined();
        r
    }

    fn enforced(&self) -> bool {
        self.status != "not_enforced"
    }

    fn compute_unconfined(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        if !self.filesystem {
            out.push("filesystem");
        }
        if self.network != "tcp_only" {
            out.push("tcp");
        }
        out.extend(ALWAYS_UNCONFINED);
        if !self.abstract_unix_socket {
            out.push("abstract_unix_socket");
        }
        if !self.signal {
            out.push("signal");
        }
        out
    }

    /// Withdraw every claim (used when a check shows the confinement cannot be relied on).
    fn downgrade(&mut self, note: String) {
        self.status = "not_enforced";
        self.filesystem = false;
        self.network = "none";
        self.abstract_unix_socket = false;
        self.signal = false;
        self.notes.push(note);
        self.unconfined = self.compute_unconfined();
    }

    /// Record the probes run on a worker and a blocking-pool thread after the runtime started. A
    /// probe that was not denied means those threads are not confined: the report then claims nothing.
    pub fn record_thread_probes(&mut self, worker: &str, blocking: &str) {
        self.thread_probes = ThreadProbes {
            worker: worker.to_string(),
            blocking: blocking.to_string(),
        };
        if !self.enforced() {
            return;
        }
        if worker == PROBE_SKIPPED || blocking == PROBE_SKIPPED {
            self.notes.push(
                "thread probes skipped: a read rule covers / so there is no path outside the read set to probe".into(),
            );
            return;
        }
        if worker != PROBE_DENIED || blocking != PROBE_DENIED {
            self.downgrade(format!(
                "a runtime thread is not confined (worker probe: {worker}, blocking probe: {blocking})"
            ));
        }
    }

    /// Note read rules that make read confinement meaningless or weak (M1.1, finding M2).
    pub fn flag_broad_reads(&mut self, read: &[PathBuf], home: &Path) {
        let broad = broad_read_rules(read, home);
        if broad.is_empty() {
            return;
        }
        let list: Vec<String> = broad.iter().map(|p| p.display().to_string()).collect();
        self.notes.push(format!(
            "read rules {} are / or an ancestor of the home directory: read confinement is weak",
            list.join(", ")
        ));
        self.broad_read_rules = list;
    }

    pub fn summary(&self) -> String {
        format!(
            "landlock {}: abi={} filesystem={} network={} abstract_unix_socket={} signal={} threads_at_apply={} probes={}/{} unconfined={}{}",
            self.status,
            self.abi
                .map_or_else(|| "none".to_string(), |a| a.to_string()),
            self.filesystem,
            self.network,
            self.abstract_unix_socket,
            self.signal,
            self.threads_at_apply
                .map_or_else(|| "unknown".to_string(), |n| n.to_string()),
            self.thread_probes.worker,
            self.thread_probes.blocking,
            self.unconfined.join(","),
            if self.notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", self.notes.join("; "))
            }
        )
    }
}

fn rw_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::MakeSock
        | AccessFs::Truncate
        | AccessFs::Refer
}

fn err<E: std::fmt::Display>(what: &str, e: E) -> Error {
    Error::new(format!("landlock: {what}: {e}"))
}

/// Number of threads in this process (`/proc/self/task` entries).
pub fn thread_count() -> std::io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}

/// Build and enforce the ruleset on the calling thread. Paths that do not exist are skipped. If
/// the process is not single-threaded (or that cannot be verified), the ruleset is still applied
/// to this thread but the report claims nothing.
pub fn apply(policy: &Policy) -> Result<SandboxReport> {
    let threads = thread_count().ok();
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| err("handle fs access", e))?
        .handle_access(AccessNet::from_all(TARGET_ABI))
        .map_err(|e| err("handle net access", e))?
        .scope(Scope::from_all(SCOPE_ABI))
        .map_err(|e| err("scope", e))?
        .create()
        .map_err(|e| err("create ruleset", e))?;

    for (paths, access) in [
        (&policy.read, AccessFs::from_read(TARGET_ABI)),
        (&policy.read_write, rw_access()),
    ] {
        for path in paths {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(|e| err(&format!("allow {}", path.display()), e))?;
            }
        }
    }
    if let Ok(fd) = PathFd::new("/dev/null") {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                fd,
                AccessFs::ReadFile | AccessFs::WriteFile,
            ))
            .map_err(|e| err("allow /dev/null", e))?;
    }
    if let Some(port) = policy.tcp_bind_port {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::BindTcp))
            .map_err(|e| err("allow tcp bind", e))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| err("restrict self", e))?;
    Ok(report_from(
        status.ruleset,
        status.landlock,
        status.no_new_privs,
        threads,
    ))
}

/// Pure: turn what the kernel reported (and the thread count) into claims.
pub fn report_from(
    ruleset: RulesetStatus,
    landlock: LandlockStatus,
    no_new_privs: bool,
    threads_at_apply: Option<usize>,
) -> SandboxReport {
    let abi = match landlock {
        LandlockStatus::Available { effective_abi, .. } => Some(effective_abi as u8),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => None,
    };
    let enforced = !matches!(ruleset, RulesetStatus::NotEnforced);
    let status = match ruleset {
        RulesetStatus::FullyEnforced => "fully_enforced",
        RulesetStatus::PartiallyEnforced => "partially_enforced",
        RulesetStatus::NotEnforced => "not_enforced",
    };
    let tcp = enforced && abi.is_some_and(|a| a >= 4);
    let scoped = enforced && abi.is_some_and(|a| a >= 6);
    let mut report = SandboxReport {
        abi,
        status,
        filesystem: enforced,
        network: if tcp { "tcp_only" } else { "none" },
        abstract_unix_socket: scoped,
        signal: scoped,
        no_new_privs,
        threads_at_apply,
        thread_probes: ThreadProbes {
            worker: PROBE_NOT_RUN.into(),
            blocking: PROBE_NOT_RUN.into(),
        },
        broad_read_rules: Vec::new(),
        unconfined: Vec::new(),
        notes: Vec::new(),
    };
    if !enforced {
        report.notes.push("Landlock is unavailable or disabled on this kernel: no filesystem or network confinement".to_string());
    } else {
        if !tcp {
            report.notes.push(
                "TCP confinement needs Landlock ABI 4 (Linux 6.7+): network access is not restricted"
                    .to_string(),
            );
        }
        if !scoped {
            report.notes.push(
                "abstract Unix socket and signal scoping need Landlock ABI 6 (Linux 6.12+)"
                    .to_string(),
            );
        }
    }
    report.unconfined = report.compute_unconfined();
    match threads_at_apply {
        Some(1) => {}
        Some(n) if enforced => report.downgrade(format!(
            "{n} threads existed when the sandbox was applied; threads other than the caller are unconfined"
        )),
        None if enforced => report.downgrade(
            "cannot verify that the process was single-threaded when the sandbox was applied"
                .to_string(),
        ),
        _ => {}
    }
    report
}

/// The allow-list for the daemon (§11.5). The config file is read before the sandbox is applied,
/// so its directory is deliberately **not** granted.
pub fn daemon_policy(
    roots: &[PathBuf],
    session_dir: &Path,
    dirs: &crate::paths::Dirs,
    tcp_port: u16,
) -> Policy {
    let mut read: Vec<PathBuf> = SYSTEM_READ_PATHS.iter().map(PathBuf::from).collect();
    read.extend(roots.iter().cloned());
    read.push(session_dir.to_path_buf());
    Policy {
        read,
        read_write: dirs.all().iter().map(|p| p.to_path_buf()).collect(),
        tcp_bind_port: Some(tcp_port),
    }
}

/// Read rules that are `/` or a strict ancestor of `home`.
pub fn broad_read_rules(read: &[PathBuf], home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = read
        .iter()
        .filter(|r| r.as_path() == Path::new("/") || (home.starts_with(r) && r.as_path() != home))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A directory that no rule of `policy` covers, to probe confinement with a harmless read.
/// `None` if a rule covers `/` (then every path is readable and there is nothing to probe).
pub fn probe_target(policy: &Policy) -> Option<PathBuf> {
    let root = Path::new("/");
    let covered = policy
        .read
        .iter()
        .chain(&policy.read_write)
        .any(|p| p.as_path() == root);
    (!covered).then(|| root.to_path_buf())
}

/// Read `target` (a directory outside the read set) and classify the outcome.
pub fn probe_read(target: Option<&Path>) -> String {
    let Some(target) = target else {
        return PROBE_SKIPPED.into();
    };
    match std::fs::read_dir(target) {
        Ok(_) => PROBE_ALLOWED.into(),
        Err(e) if e.raw_os_error() == Some(nix::errno::Errno::EACCES as i32) => PROBE_DENIED.into(),
        Err(e) => format!("error:{:?}", e.kind()),
    }
}

/// Names to remove from a child's inherited environment: [`IPC_ENV_VARS`] plus every `DBUS_*`.
pub fn ipc_env_names(current: impl Iterator<Item = OsString>) -> Vec<OsString> {
    let mut names: Vec<OsString> = IPC_ENV_VARS.iter().map(OsString::from).collect();
    for name in current {
        if name.as_encoded_bytes().starts_with(b"DBUS_") && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// A `Command` for a child of the daemon (git, `claude`), with session IPC variables removed from
/// its environment. Every child the daemon spawns must be created here.
pub fn child_command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    for name in ipc_env_names(std::env::vars_os().map(|(k, _)| k)) {
        cmd.env_remove(name);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available(abi: ABI) -> LandlockStatus {
        LandlockStatus::Available {
            effective_abi: abi,
            kernel_abi: None,
        }
    }

    #[test]
    fn report_for_full_enforcement_on_abi6_single_threaded() {
        let r = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V6),
            true,
            Some(1),
        );
        assert_eq!(
            (r.status, r.filesystem, r.network, r.abi),
            ("fully_enforced", true, "tcp_only", Some(6))
        );
        assert!(r.abstract_unix_socket && r.signal);
        assert!(r.notes.is_empty(), "{:?}", r.notes);
        assert_eq!(r.unconfined, ALWAYS_UNCONFINED.to_vec());
    }

    #[test]
    fn abi4_confines_tcp_but_not_scopes() {
        let r = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V4),
            true,
            Some(1),
        );
        assert_eq!(r.network, "tcp_only");
        assert!(!r.abstract_unix_socket && !r.signal);
        assert!(r.unconfined.contains(&"abstract_unix_socket") && r.unconfined.contains(&"signal"));
        assert!(r.notes.iter().any(|n| n.contains("ABI 6")));
    }

    #[test]
    fn report_never_claims_network_on_old_abi() {
        let r = report_from(
            RulesetStatus::PartiallyEnforced,
            available(ABI::V3),
            true,
            Some(1),
        );
        assert!(r.filesystem && r.network == "none");
        assert!(r.notes[0].contains("ABI 4"));
        assert!(r.unconfined.contains(&"tcp"));
    }

    #[test]
    fn report_for_unavailable_landlock_claims_nothing() {
        let r = report_from(
            RulesetStatus::NotEnforced,
            LandlockStatus::NotImplemented,
            false,
            Some(1),
        );
        assert_eq!(
            (r.status, r.filesystem, r.network, r.abi),
            ("not_enforced", false, "none", None)
        );
        assert!(r.summary().contains("unavailable"));
        assert!(r.unconfined.contains(&"filesystem"));
    }

    #[test]
    fn more_than_one_thread_at_apply_means_not_enforced() {
        let r = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V8),
            true,
            Some(3),
        );
        assert_eq!(
            (r.status, r.filesystem, r.network),
            ("not_enforced", false, "none")
        );
        assert!(!r.abstract_unix_socket && !r.signal);
        assert!(r.notes.iter().any(|n| n.contains("3 threads")));
        let r = report_from(RulesetStatus::FullyEnforced, available(ABI::V8), true, None);
        assert_eq!(r.status, "not_enforced");
        assert!(r.notes.iter().any(|n| n.contains("cannot verify")));
    }

    #[test]
    fn thread_probes_downgrade_the_report_unless_denied() {
        let base = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V8),
            true,
            Some(1),
        );
        let mut ok = base.clone();
        ok.record_thread_probes(PROBE_DENIED, PROBE_DENIED);
        assert_eq!(ok.status, "fully_enforced");
        assert_eq!(ok.thread_probes.blocking, PROBE_DENIED);

        let mut bad = base.clone();
        bad.record_thread_probes(PROBE_DENIED, PROBE_ALLOWED);
        assert_eq!((bad.status, bad.filesystem), ("not_enforced", false));
        assert!(bad.notes.iter().any(|n| n.contains("not confined")));

        let mut odd = base.clone();
        odd.record_thread_probes("error:NotFound", PROBE_DENIED);
        assert_eq!(odd.status, "not_enforced");

        let mut skipped = base;
        skipped.record_thread_probes(PROBE_SKIPPED, PROBE_SKIPPED);
        assert_eq!(skipped.status, "fully_enforced");
        assert!(skipped.notes.iter().any(|n| n.contains("skipped")));
    }

    #[test]
    fn broad_read_rules_are_root_or_strict_ancestors_of_home() {
        let home = Path::new("/home/u");
        let read: Vec<PathBuf> = ["/usr", "/home/u", "/home", "/", "/home/u/dev", "/srv"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(
            broad_read_rules(&read, home),
            vec![PathBuf::from("/"), PathBuf::from("/home")]
        );
        let mut r = SandboxReport::disabled("x");
        r.flag_broad_reads(&read, home);
        assert_eq!(r.broad_read_rules, ["/", "/home"]);
        assert!(r.notes.iter().any(|n| n.contains("ancestor of the home")));
        let mut clean = SandboxReport::disabled("x");
        clean.flag_broad_reads(&read[..2], home);
        assert!(clean.broad_read_rules.is_empty() && clean.notes.len() == 1);
    }

    #[test]
    fn daemon_policy_contents_without_any_config_dir_grant() {
        let dirs =
            crate::paths::Dirs::resolve(&crate::paths::EnvVars::default(), Path::new("/home/u"));
        let p = daemon_policy(
            &[PathBuf::from("/home/u")],
            Path::new("/home/u/.claude"),
            &dirs,
            8765,
        );
        let mut want: Vec<PathBuf> = SYSTEM_READ_PATHS.iter().map(PathBuf::from).collect();
        want.extend([PathBuf::from("/home/u"), PathBuf::from("/home/u/.claude")]);
        assert_eq!(
            p.read, want,
            "exactly the system paths, roots and session dir"
        );
        assert_eq!(p.read_write.len(), 4);
        assert!(!p.read_write.contains(&PathBuf::from("/home/u")));
        assert_eq!(p.tcp_bind_port, Some(8765));
        assert!(broad_read_rules(&p.read, Path::new("/home/u")).is_empty());
    }

    #[test]
    fn probe_target_is_root_unless_root_is_a_rule() {
        let mut p = Policy {
            read: vec![PathBuf::from("/usr")],
            ..Policy::default()
        };
        assert_eq!(probe_target(&p), Some(PathBuf::from("/")));
        p.read.push(PathBuf::from("/"));
        assert_eq!(probe_target(&p), None);
        assert_eq!(probe_read(None), PROBE_SKIPPED);
    }

    #[test]
    fn child_environment_drops_ipc_variables() {
        let names = ipc_env_names(
            ["PATH", "DBUS_FOO", "HOME", "DBUS_SESSION_BUS_ADDRESS"]
                .iter()
                .map(OsString::from),
        );
        for v in IPC_ENV_VARS {
            assert!(names.contains(&OsString::from(v)), "{v}");
        }
        assert!(names.contains(&OsString::from("DBUS_FOO")));
        assert!(
            !names.contains(&OsString::from("PATH")) && !names.contains(&OsString::from("HOME"))
        );
        assert_eq!(
            names
                .iter()
                .filter(|n| *n == "DBUS_SESSION_BUS_ADDRESS")
                .count(),
            1
        );
        let cmd = child_command("/bin/true");
        for v in IPC_ENV_VARS {
            assert!(
                cmd.get_envs().any(|(k, val)| k == v && val.is_none()),
                "{v} is not removed"
            );
        }
    }
}
