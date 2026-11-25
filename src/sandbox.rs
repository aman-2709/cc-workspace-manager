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
//!
//! **Seccomp (M4).** Once the TCP and Unix listeners are bound, [`deny_new_sockets`] installs a
//! seccomp filter on every thread (TSYNC) that makes `socket()` and `socketpair()` fail with
//! `EPERM` for **every** family, and denies `io_uring` (which can create sockets without
//! `socket()`). Children inherit it. Whatever needs a socket is created before the filter: the
//! listeners, the TCP peer check's `NETLINK_SOCK_DIAG` socket (`http::peer::SockDiag`) and the
//! runtime's signal pipe. This closes what Landlock ABI ≤ 8 leaves open: new UDP sockets and
//! `connect()`/`sendto()` to path-based Unix sockets (a datagram socket pair could be pointed at
//! one: v0.1.0 review M1).
//! **Daemon-level probes (M4).** The running daemon also tries, from its blocking pool, a write
//! outside its directories ([`probe_write`]) and an outbound TCP connect ([`probe_connect`]),
//! and, after the filter, creating sockets from a worker and a blocking thread
//! ([`probe_socket`]). A probe that is not denied withdraws the matching claim; a probe that
//! fails for an **unexpected** reason proves nothing, so the protection is reported as
//! `unverified`: neither claimed nor withdrawn.

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

/// What Landlock never confines in v0.1, whatever the kernel; listed in the report unless the
/// seccomp filter ([`deny_new_sockets`]) is active, which closes both.
pub const UNCONFINED_BY_LANDLOCK: [&str; 2] = ["udp", "unix_socket_connect_by_path"];

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
/// Outcome of a socket-creation probe that the seccomp filter denied.
pub const PROBE_EPERM: &str = "eperm";
/// `seccomp` values: the filter is active and verified, installed but not verified, or not active.
pub const SECCOMP_ACTIVE: &str = "socket_denied";
pub const SECCOMP_INACTIVE: &str = "not_applied";
/// `status`, `network` and `seccomp` value of a protection whose probe failed for an unexpected
/// reason: it is neither claimed nor withdrawn (see [`SandboxReport::unverified`]).
pub const UNVERIFIED: &str = "unverified";

/// Probes run by the daemon itself (M4), after the listeners are bound.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DaemonProbes {
    /// An anonymous file (`O_TMPFILE`) created in the home directory, outside ccwm's directories.
    pub write: String,
    /// A TCP connect to a loopback port.
    pub connect: String,
    /// Creating a UDP socket, a Unix socket and a socket pair after the seccomp filter, from a
    /// worker thread…
    pub socket_worker: String,
    /// …and from a blocking-pool thread.
    pub socket_blocking: String,
}

impl Default for DaemonProbes {
    fn default() -> Self {
        Self {
            write: PROBE_NOT_RUN.into(),
            connect: PROBE_NOT_RUN.into(),
            socket_worker: PROBE_NOT_RUN.into(),
            socket_blocking: PROBE_NOT_RUN.into(),
        }
    }
}

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
    /// `fully_enforced`, `partially_enforced` or `not_enforced`; `unverified` when the thread
    /// probes failed for an unexpected reason.
    pub status: &'static str,
    /// Filesystem access is confined (writes only under ccwm's directories; reads only under the allowed paths).
    pub filesystem: bool,
    /// `tcp_only`: all TCP `connect` is denied and TCP `bind` is limited to the configured port.
    /// UDP and other socket families are not confined by Landlock (see `seccomp`). `none`: no
    /// network rules. `unverified`: rules were applied, the connect probe was inconclusive.
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
    /// `socket_denied`: the seccomp filter blocks every new socket and socket pair on every
    /// thread and in children; `unverified`: installed, but the socket probes were inconclusive;
    /// `not_applied` otherwise.
    pub seccomp: &'static str,
    /// What the running daemon's own probes showed.
    pub daemon_probes: DaemonProbes,
    /// Read rules that are `/` or an ancestor of the home directory (read confinement is weak).
    pub broad_read_rules: Vec<String>,
    /// Kinds of access that are not confined.
    pub unconfined: Vec<&'static str>,
    /// Kinds of access whose protection was applied but whose probe failed for an unexpected
    /// reason: not claimed (the fields above say `false`/`unverified`) and not in `unconfined`.
    pub unverified: Vec<&'static str>,
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
            seccomp: SECCOMP_INACTIVE,
            daemon_probes: DaemonProbes::default(),
            broad_read_rules: Vec::new(),
            unconfined: Vec::new(),
            unverified: Vec::new(),
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
        if self.seccomp != SECCOMP_ACTIVE {
            out.extend(UNCONFINED_BY_LANDLOCK);
        }
        if !self.abstract_unix_socket {
            out.push("abstract_unix_socket");
        }
        if !self.signal {
            out.push("signal");
        }
        out.retain(|kind| !self.unverified.contains(kind));
        out
    }

    /// What Landlock is currently claimed to confine, by the names `unconfined` uses.
    fn landlock_claims(&self) -> Vec<&'static str> {
        [
            (self.filesystem, "filesystem"),
            (self.network == "tcp_only", "tcp"),
            (self.abstract_unix_socket, "abstract_unix_socket"),
            (self.signal, "signal"),
        ]
        .into_iter()
        .filter_map(|(claimed, kind)| claimed.then_some(kind))
        .collect()
    }

    /// Withdraw every Landlock claim (a check showed the confinement cannot be relied on). A
    /// disproof outranks "unverified": nothing of Landlock stays in `unverified`.
    fn downgrade(&mut self, note: String) {
        self.status = "not_enforced";
        self.filesystem = false;
        self.network = "none";
        self.abstract_unix_socket = false;
        self.signal = false;
        self.unverified
            .retain(|kind| UNCONFINED_BY_LANDLOCK.contains(kind));
        self.notes.push(note);
        self.unconfined = self.compute_unconfined();
    }

    /// Stop claiming `kinds` **without** withdrawing them: their probe failed for an unexpected
    /// reason, which proves neither the confinement nor its absence. They are listed in
    /// `unverified` instead of `unconfined`.
    fn unverify(&mut self, kinds: &[&'static str], note: String) {
        for kind in kinds {
            match *kind {
                "filesystem" => self.filesystem = false,
                "tcp" => self.network = UNVERIFIED,
                "abstract_unix_socket" => self.abstract_unix_socket = false,
                "signal" => self.signal = false,
                _ => self.seccomp = UNVERIFIED, // the two kinds of UNCONFINED_BY_LANDLOCK
            }
            if !self.unverified.contains(kind) {
                self.unverified.push(kind);
            }
        }
        self.notes.push(note);
        self.unconfined = self.compute_unconfined();
    }

    /// Record the probes run on a worker and a blocking-pool thread after the runtime started. A
    /// probe that was not denied means those threads are not confined: the report then claims
    /// nothing. A probe that failed for another reason leaves every Landlock claim `unverified`.
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
        } else if worker == PROBE_ALLOWED || blocking == PROBE_ALLOWED {
            self.downgrade(format!(
                "a runtime thread is not confined (worker probe: {worker}, blocking probe: {blocking})"
            ));
        } else if worker != PROBE_DENIED || blocking != PROBE_DENIED {
            self.status = UNVERIFIED;
            self.unverify(
                &self.landlock_claims(),
                format!(
                    "a thread probe failed unexpectedly (worker: {worker}, blocking: {blocking}): the confinement of the runtime threads is unverified"
                ),
            );
        }
    }

    /// Record the daemon's write and connect probes (run after the listeners are bound). A write
    /// outside ccwm's directories that succeeded withdraws every claim; a connect that was not
    /// denied withdraws the TCP claim. An error other than `EACCES` (e.g. a file system without
    /// `O_TMPFILE`) proves nothing either way: that protection becomes `unverified`.
    pub fn record_daemon_probes(&mut self, write: &str, connect: &str) {
        self.daemon_probes.write = write.to_string();
        self.daemon_probes.connect = connect.to_string();
        match write {
            PROBE_DENIED => {}
            PROBE_ALLOWED => {
                if self.filesystem || self.unverified.contains(&"filesystem") {
                    self.downgrade(
                        "the daemon could write outside its directories (write probe allowed)"
                            .into(),
                    );
                }
            }
            other if self.filesystem => self.unverify(
                &["filesystem"],
                format!("the write probe failed unexpectedly ({other}): filesystem confinement is unverified"),
            ),
            _ => {}
        }
        match connect {
            PROBE_DENIED => {}
            PROBE_ALLOWED => {
                if self.network != "none" {
                    self.network = "none";
                    self.unverified.retain(|kind| *kind != "tcp");
                    self.notes.push(
                        "the daemon could open a TCP connection (connect probe allowed)".into(),
                    );
                    self.unconfined = self.compute_unconfined();
                }
            }
            other if self.network == "tcp_only" => self.unverify(
                &["tcp"],
                format!("the connect probe failed unexpectedly ({other}): TCP confinement is unverified"),
            ),
            _ => {}
        }
    }

    /// Record the seccomp filter: `applied` is the result of [`deny_new_sockets`]; the probes ran
    /// afterwards on a worker and a blocking-pool thread. The filter is claimed only if it was
    /// applied and both probes were denied with `EPERM`; a socket that could be created withdraws
    /// it; any other probe outcome leaves it `unverified`.
    pub fn record_seccomp(&mut self, applied: &Result<()>, worker: &str, blocking: &str) {
        self.daemon_probes.socket_worker = worker.to_string();
        self.daemon_probes.socket_blocking = blocking.to_string();
        match applied {
            Ok(()) if worker == PROBE_EPERM && blocking == PROBE_EPERM => {
                self.seccomp = SECCOMP_ACTIVE;
            }
            Ok(()) if socket_created(worker) || socket_created(blocking) => {
                self.seccomp = SECCOMP_INACTIVE;
                self.notes.push(format!(
                    "the seccomp filter was installed but socket creation was not denied (worker: {worker}, blocking: {blocking})"
                ));
            }
            Ok(()) => {
                self.unverify(
                    &UNCONFINED_BY_LANDLOCK,
                    format!(
                        "a socket probe failed unexpectedly (worker: {worker}, blocking: {blocking}): the seccomp filter is unverified"
                    ),
                );
            }
            Err(e) => {
                self.seccomp = SECCOMP_INACTIVE;
                self.notes.push(format!("seccomp filter not applied: {e}"));
            }
        }
        self.unconfined = self.compute_unconfined();
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
            "landlock {}: abi={} filesystem={} network={} abstract_unix_socket={} signal={} threads_at_apply={} probes={}/{} daemon_probes=write:{},connect:{},socket:{}/{} seccomp={} unconfined={} unverified={}{}",
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
            self.daemon_probes.write,
            self.daemon_probes.connect,
            self.daemon_probes.socket_worker,
            self.daemon_probes.socket_blocking,
            self.seccomp,
            self.unconfined.join(","),
            self.unverified.join(","),
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
        seccomp: SECCOMP_INACTIVE,
        daemon_probes: DaemonProbes::default(),
        broad_read_rules: Vec::new(),
        unconfined: Vec::new(),
        unverified: Vec::new(),
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

/// Classify a probe's I/O outcome: `EACCES` is a denial; success is `allowed`.
fn classify(result: std::io::Result<()>) -> String {
    match result {
        Ok(()) => PROBE_ALLOWED.into(),
        Err(e) if e.raw_os_error() == Some(nix::errno::Errno::EACCES as i32) => PROBE_DENIED.into(),
        Err(e) => format!("error:{:?}", e.kind()),
    }
}

/// Try to create an anonymous file (`O_TMPFILE`: no directory entry, gone when closed, so a
/// probe that is *allowed* changes nothing visible) in `dir`, a directory outside ccwm's own.
pub fn probe_write(dir: &Path) -> String {
    use std::os::unix::fs::OpenOptionsExt;
    classify(
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_TMPFILE.bits())
            .mode(0o600)
            .open(dir)
            .map(drop),
    )
}

/// The loopback address the connect probe targets: port 1 (tcpmux), where nothing normally
/// listens, so an unconfined probe gets `ECONNREFUSED` (counted as allowed) and talks to no one.
pub const CONNECT_PROBE_TARGET: ([u8; 4], u16) = ([127, 0, 0, 1], 1);

/// Try an outbound TCP connect to a loopback port. Landlock (ABI ≥ 4) denies it with `EACCES`
/// before anything is sent.
pub fn probe_connect() -> String {
    let (ip, port) = CONNECT_PROBE_TARGET;
    let addr = std::net::SocketAddr::from((ip, port));
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)) {
        Ok(_) => PROBE_ALLOWED.into(),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PROBE_ALLOWED.into(),
        Err(e) => classify(Err(e)),
    }
}

/// Try to create a UDP socket (bound to an ephemeral loopback port), an unbound Unix datagram
/// socket and a Unix datagram socket pair. [`PROBE_EPERM`] only if the seccomp filter denied all
/// three; `allowed` (with details unless all three succeeded) if any could be created; `error:…`
/// if none was created but one failed for another reason, which proves nothing.
pub fn probe_socket() -> String {
    use std::os::unix::net::UnixDatagram;
    classify_sockets(&[
        ("udp", std::net::UdpSocket::bind(("127.0.0.1", 0)).map(drop)),
        ("unix", UnixDatagram::unbound().map(drop)),
        ("socketpair", UnixDatagram::pair().map(drop)),
    ])
}

fn classify_sockets(attempts: &[(&str, std::io::Result<()>)]) -> String {
    let eperm = |r: &std::io::Result<()>| {
        r.as_ref()
            .is_err_and(|e| e.raw_os_error() == Some(nix::errno::Errno::EPERM as i32))
    };
    if attempts.iter().all(|(_, r)| eperm(r)) {
        return PROBE_EPERM.into();
    }
    if attempts.iter().all(|(_, r)| r.is_ok()) {
        return PROBE_ALLOWED.into();
    }
    let detail: Vec<String> = attempts
        .iter()
        .map(|(what, r)| match r {
            Ok(()) => format!("{what}=ok"),
            Err(_) if eperm(r) => format!("{what}={PROBE_EPERM}"),
            Err(e) => format!("{what}={:?}", e.kind()),
        })
        .collect();
    let outcome = if attempts.iter().any(|(_, r)| r.is_ok()) {
        PROBE_ALLOWED
    } else {
        "error"
    };
    format!("{outcome}:{}", detail.join(","))
}

/// Whether a [`probe_socket`] outcome shows that a socket could be created.
fn socket_created(outcome: &str) -> bool {
    outcome == PROBE_ALLOWED
        || outcome
            .strip_prefix(PROBE_ALLOWED)
            .is_some_and(|rest| rest.starts_with(':'))
}

/// x32 system calls carry this bit with the x86_64 audit architecture.
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// The system calls [`socket_filter`] denies with `EPERM`, whatever their arguments: `socket()`
/// and `socketpair()` of every family (what the daemon needs is created before the filter; a
/// datagram socket pair could be pointed at a path-based socket), `io_uring` (which can create
/// sockets without `socket()`), and the x32 entry points of `socket`, `socketpair` and
/// `io_uring_setup`.
pub fn denied_syscalls() -> [i64; 8] {
    use nix::libc;
    [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        X32_SYSCALL_BIT | libc::SYS_socket,
        X32_SYSCALL_BIT | libc::SYS_socketpair,
        X32_SYSCALL_BIT | libc::SYS_io_uring_setup,
    ]
}

/// The seccomp program of [`deny_new_sockets`] (separate so tests can build it without
/// installing it).
pub fn socket_filter() -> Result<seccompiler::BpfProgram> {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    let e =
        |what: &str, err: seccompiler::BackendError| Error::new(format!("seccomp: {what}: {err}"));
    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else {
        return Err(Error::new(
            "seccomp: only x86_64 is supported by this build",
        ));
    };
    // An empty rule list matches unconditionally: no family, type or protocol is exempt.
    let rules = denied_syscalls()
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    let errno = u32::try_from(nix::libc::EPERM).unwrap_or(1);
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(errno),
        arch,
    )
    .map_err(|x| e("filter", x))?
    .try_into()
    .map_err(|x| e("compile", x))
}

/// Install [`socket_filter`] on **every** thread of the process (TSYNC); threads and children
/// created afterwards inherit it. Call it once the listeners are bound and everything else that
/// needs a socket exists (the peer check's netlink socket, the runtime's signal pipe): from then
/// on the daemon can create none.
pub fn deny_new_sockets() -> Result<()> {
    let program = socket_filter()?;
    seccompiler::apply_filter_all_threads(&program).map_err(|e| Error::new(format!("seccomp: {e}")))
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
        assert_eq!(r.unconfined, UNCONFINED_BY_LANDLOCK.to_vec());
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

        // An unexpected failure proves nothing: every Landlock claim is unverified, none withdrawn.
        for (worker, blocking) in [
            ("error:NotFound", PROBE_DENIED),
            (PROBE_DENIED, "error:panicked"),
            ("error:NotFound", "error:NotFound"),
        ] {
            let mut odd = base.clone();
            odd.record_thread_probes(worker, blocking);
            assert_eq!((odd.status, odd.filesystem), (UNVERIFIED, false));
            assert_eq!(odd.network, UNVERIFIED);
            assert!(!odd.abstract_unix_socket && !odd.signal);
            assert_eq!(
                odd.unverified,
                ["filesystem", "tcp", "abstract_unix_socket", "signal"]
            );
            assert_eq!(odd.unconfined, UNCONFINED_BY_LANDLOCK.to_vec());
            assert!(odd.notes.iter().any(|n| n.contains("failed unexpectedly")));
            assert!(odd
                .summary()
                .contains("unverified=filesystem,tcp,abstract_unix_socket,signal"));
        }
        // One thread that could read outranks an unexpected failure on the other.
        let mut mixed = base.clone();
        mixed.record_thread_probes("error:NotFound", PROBE_ALLOWED);
        assert_eq!(mixed.status, "not_enforced");
        assert!(mixed.unverified.is_empty() && mixed.unconfined.contains(&"filesystem"));

        // On ABI 4 only what was claimed can become unverified (scopes stay unconfined).
        let mut abi4 = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V4),
            true,
            Some(1),
        );
        abi4.record_thread_probes("error:NotFound", PROBE_DENIED);
        assert_eq!(abi4.unverified, ["filesystem", "tcp"]);
        assert!(abi4.unconfined.contains(&"signal") && !abi4.unconfined.contains(&"tcp"));

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

    fn enforced_v8() -> SandboxReport {
        let mut r = report_from(
            RulesetStatus::FullyEnforced,
            available(ABI::V8),
            true,
            Some(1),
        );
        r.record_thread_probes(PROBE_DENIED, PROBE_DENIED);
        r
    }

    #[test]
    fn daemon_write_and_connect_probes_withdraw_only_what_they_disprove() {
        let mut ok = enforced_v8();
        ok.record_daemon_probes(PROBE_DENIED, PROBE_DENIED);
        assert_eq!((ok.status, ok.network), ("fully_enforced", "tcp_only"));
        assert_eq!(ok.daemon_probes.write, PROBE_DENIED);
        assert!(ok
            .summary()
            .contains("daemon_probes=write:eacces,connect:eacces"));

        let mut wrote = enforced_v8();
        wrote.record_daemon_probes(PROBE_ALLOWED, PROBE_DENIED);
        assert_eq!(
            (wrote.status, wrote.filesystem, wrote.network),
            ("not_enforced", false, "none")
        );
        assert!(wrote
            .notes
            .iter()
            .any(|n| n.contains("write probe allowed")));

        let mut connected = enforced_v8();
        connected.record_daemon_probes(PROBE_DENIED, PROBE_ALLOWED);
        assert_eq!(
            (connected.status, connected.filesystem),
            ("fully_enforced", true)
        );
        assert_eq!(connected.network, "none");
        assert!(connected.unconfined.contains(&"tcp"));

        // Unexpected failures: each protection is unverified, neither claimed nor withdrawn.
        let mut odd = enforced_v8();
        odd.record_daemon_probes("error:Unsupported", "error:TimedOut");
        assert_eq!(
            (odd.status, odd.filesystem, odd.network),
            ("fully_enforced", false, UNVERIFIED)
        );
        assert_eq!(odd.unverified, ["filesystem", "tcp"]);
        assert!(!odd.unconfined.contains(&"filesystem") && !odd.unconfined.contains(&"tcp"));
        assert!(odd.abstract_unix_socket && odd.signal, "not probed here");
        assert_eq!(
            odd.notes
                .iter()
                .filter(|n| n.contains("failed unexpectedly"))
                .count(),
            2
        );

        let mut write_only = enforced_v8();
        write_only.record_daemon_probes("error:Unsupported", PROBE_DENIED);
        assert_eq!(write_only.unverified, ["filesystem"]);
        assert_eq!(write_only.network, "tcp_only");

        // A later disproof moves an unverified protection to unconfined.
        let mut later = enforced_v8();
        later.thread_probes.worker = PROBE_NOT_RUN.into();
        later.record_thread_probes("error:NotFound", PROBE_DENIED);
        let mut connected = later.clone();
        connected.record_daemon_probes(PROBE_DENIED, PROBE_ALLOWED);
        assert_eq!(connected.network, "none");
        assert!(connected.unconfined.contains(&"tcp") && !connected.unverified.contains(&"tcp"));
        assert!(
            connected.unverified.contains(&"filesystem"),
            "still unverified"
        );
        later.record_daemon_probes(PROBE_ALLOWED, PROBE_DENIED);
        assert_eq!(later.status, "not_enforced");
        assert!(later.unverified.is_empty() && later.unconfined.contains(&"filesystem"));

        let mut off = SandboxReport::disabled("no landlock");
        off.record_daemon_probes(PROBE_ALLOWED, "error:TimedOut");
        assert_eq!(
            off.daemon_probes.write, PROBE_ALLOWED,
            "recorded, nothing to withdraw"
        );
        assert!(off.unverified.is_empty(), "nothing was claimed");
    }

    #[test]
    fn seccomp_is_claimed_only_when_applied_and_both_socket_probes_were_denied() {
        let mut r = enforced_v8();
        assert!(r.unconfined.contains(&"udp"));
        r.record_seccomp(&Ok(()), PROBE_EPERM, PROBE_EPERM);
        assert_eq!(r.seccomp, SECCOMP_ACTIVE);
        assert!(r.unconfined.is_empty(), "{:?}", r.unconfined);
        assert!(r.summary().contains("seccomp=socket_denied unconfined="));

        for created in [PROBE_ALLOWED, "allowed:udp=eperm,unix=eperm,socketpair=ok"] {
            let mut half = enforced_v8();
            half.record_seccomp(&Ok(()), PROBE_EPERM, created);
            assert_eq!(half.seccomp, SECCOMP_INACTIVE, "{created}");
            assert_eq!(half.unconfined, UNCONFINED_BY_LANDLOCK.to_vec());
            assert!(half.unverified.is_empty());
        }

        // No socket was created, but a probe did not end in EPERM either: unverified.
        for odd in [
            "error:udp=eperm,unix=eperm,socketpair=Uncategorized",
            "error:panicked",
        ] {
            let mut unverified = enforced_v8();
            unverified.record_seccomp(&Ok(()), odd, PROBE_EPERM);
            assert_eq!(unverified.seccomp, UNVERIFIED, "{odd}");
            assert_eq!(unverified.unverified, UNCONFINED_BY_LANDLOCK.to_vec());
            assert!(
                unverified.unconfined.is_empty(),
                "{:?}",
                unverified.unconfined
            );
            assert!(unverified.summary().contains(
                "seccomp=unverified unconfined= unverified=udp,unix_socket_connect_by_path"
            ));
            assert_eq!(unverified.status, "fully_enforced", "Landlock is untouched");
        }

        let mut failed = enforced_v8();
        failed.record_seccomp(
            &Err(Error::new("seccomp: EINVAL")),
            PROBE_ALLOWED,
            PROBE_ALLOWED,
        );
        assert_eq!(failed.seccomp, SECCOMP_INACTIVE);
        assert!(failed.notes.iter().any(|n| n.contains("not applied")));

        // Without Landlock, seccomp still closes UDP and Unix sockets.
        let mut bare = SandboxReport::disabled("no landlock");
        bare.record_seccomp(&Ok(()), PROBE_EPERM, PROBE_EPERM);
        assert!(!bare.unconfined.contains(&"udp") && bare.unconfined.contains(&"filesystem"));
    }

    #[test]
    fn the_socket_filter_compiles_and_probes_classify_outcomes() {
        let program = socket_filter().unwrap();
        assert!(!program.is_empty());
        // No exception for any family: socket and socketpair are denied whatever their arguments
        // (the denials themselves are exercised in tests/sandbox.rs).
        use nix::libc;
        let denied = denied_syscalls();
        for nr in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            0x4000_0000 | libc::SYS_socket,
            0x4000_0000 | libc::SYS_socketpair,
            0x4000_0000 | libc::SYS_io_uring_setup,
        ] {
            assert!(denied.contains(&nr), "syscall {nr} is not denied");
        }
        let eperm = || Err(std::io::Error::from_raw_os_error(libc::EPERM));
        let emfile = || Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        let classify = |a, b, c| classify_sockets(&[("udp", a), ("unix", b), ("socketpair", c)]);
        assert_eq!(classify(eperm(), eperm(), eperm()), PROBE_EPERM);
        assert_eq!(classify(Ok(()), Ok(()), Ok(())), PROBE_ALLOWED);
        let pair_only = classify(eperm(), eperm(), Ok(()));
        assert_eq!(pair_only, "allowed:udp=eperm,unix=eperm,socketpair=ok");
        let odd = classify(eperm(), emfile(), eperm());
        assert_eq!(odd, "error:udp=eperm,unix=Uncategorized,socketpair=eperm");
        assert!(socket_created(PROBE_ALLOWED) && socket_created(&pair_only));
        assert!(!socket_created(&odd) && !socket_created(PROBE_EPERM));
        assert!(!socket_created("error:panicked") && !socket_created("allowedness"));
        // Unconfined test process: everything is allowed (the real denials are checked in
        // tests/sandbox.rs, which installs the filter in a child).
        assert_eq!(probe_socket(), PROBE_ALLOWED);
        assert_eq!(
            probe_connect(),
            PROBE_ALLOWED,
            "connection refused counts as allowed"
        );
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe_write(dir.path()), PROBE_ALLOWED);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "an allowed write probe leaves nothing behind"
        );
    }
}
