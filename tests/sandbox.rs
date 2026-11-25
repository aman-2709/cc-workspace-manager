//! Security acceptance test 11: Landlock denies writes outside ccwm's directories and outbound
//! connects, for the process itself, for threads created afterwards and for child processes, while
//! the allowed operations still work.
//!
//! This test has its own `main` (`harness = false` in Cargo.toml): libtest runs every test on a
//! spawned thread, but `sandbox::apply` must run while the process is single-threaded (it reports
//! `not_enforced` otherwise, finding M4). The confined part runs in a re-executed copy of this
//! binary (`child` mode) that applies the **real** `sandbox::daemon_policy()` on its main thread,
//! exactly like `ccwm serve`, and reports each probe's errno on stdout as `PROBE key=value`.
//! Grandchildren (`op` mode) check that the ruleset is inherited.
//!
//! The `seccomp` child mode (M4) installs the real socket filter ([`sandbox::deny_new_sockets`])
//! after the Landlock ruleset, like `ccwm serve` does once its listeners are bound, and checks
//! that a thread created *before* the filter (TSYNC), threads created after it and grandchildren
//! cannot create sockets, that the peer check's `NETLINK_SOCK_DIAG` socket still works, and that
//! the daemon-level write and connect probes are denied.
//!
//! The real daemon's own confinement (its worker and blocking-pool thread probes) is checked in
//! `tests/process.rs`. Set `CCWM_REQUIRE_LANDLOCK=1` to fail instead of skip when Landlock is
//! unavailable.

use cc_workspace_manager::paths::Dirs;
use cc_workspace_manager::sandbox::{self, UNCONFINED_BY_LANDLOCK};
use nix::errno::Errno;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

const ENV_MODE: &str = "CCWM_SANDBOX_CHILD_MODE";
const ENV_ROOT: &str = "CCWM_SANDBOX_CHILD_ROOT";
const ENV_PORTS: &str = "CCWM_SANDBOX_CHILD_PORTS"; // "<listener port>,<allowed bind port>"
const ENV_ABSTRACT: &str = "CCWM_SANDBOX_CHILD_ABSTRACT";
const REQUIRE: &str = "CCWM_REQUIRE_LANDLOCK";

// ---- probe helpers ------------------------------------------------------------------------------

fn probe(key: &str, value: impl std::fmt::Display) {
    println!("PROBE {key}={value}");
}

/// `ok`, or the errno name (`EACCES`, `EPERM`, …) of the failure.
fn outcome<T>(r: io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => match e.raw_os_error() {
            Some(code) => format!("{:?}", Errno::from_raw(code)),
            None => format!("error:{:?}", e.kind()),
        },
    }
}

/// Run one operation in a grandchild (this binary in `op` mode) and return its outcome line.
fn in_grandchild(op: &str, arg: &str) -> String {
    match Command::new(std::env::current_exe().unwrap())
        .env(ENV_MODE, "op")
        .args([op, arg])
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => format!("spawn:{}", outcome::<()>(Err(e))),
    }
}

struct Layout {
    root: PathBuf,
    rw: PathBuf,
    ro: PathBuf,
    outside: PathBuf,
    exe_dir: PathBuf,
}

impl Layout {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            rw: root.join("rw"),
            ro: root.join("ro"),
            outside: root.join("outside"),
            exe_dir: std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
        }
    }

    /// ccwm's four directories live under `rw`; the discovery root is `ro` (plus this binary's
    /// directory, so the confined process may re-execute itself for the grandchild probes).
    fn dirs(&self) -> Dirs {
        Dirs {
            config: self.rw.join("config"),
            data: self.rw.join("data"),
            state: self.rw.join("state"),
            runtime: self.rw.join("run"),
        }
    }
}

// ---- child modes --------------------------------------------------------------------------------

fn child_op(args: &[String]) {
    let (op, arg) = (args[0].as_str(), args[1].as_str());
    let result = match op {
        "write" => outcome(fs::write(arg, b"x")),
        "read" => outcome(fs::read(arg)),
        "connect" => outcome(TcpStream::connect((
            "127.0.0.1",
            arg.parse::<u16>().unwrap(),
        ))),
        "udp" => outcome(std::net::UdpSocket::bind(("127.0.0.1", 0))),
        "unix_connect" => outcome(UnixStream::connect(arg)),
        _ => "bad-op".into(),
    };
    println!("{result}");
}

fn child_main(mode: &str) {
    let l = Layout::new(Path::new(&std::env::var(ENV_ROOT).unwrap()));
    let ports: Vec<u16> = std::env::var(ENV_PORTS)
        .unwrap()
        .split(',')
        .map(|p| p.parse().unwrap())
        .collect();
    let (listener_port, allowed_port) = (ports[0], ports[1]);

    if mode == "threaded" {
        // M4: a thread that already exists when the sandbox is applied must make the report claim nothing.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let report = sandbox::apply(&policy(&l, allowed_port)).unwrap();
        probe("report", serde_json::to_string(&report).unwrap());
        drop(tx);
        t.join().unwrap();
        return;
    }

    // For the seccomp mode: a loopback connection made before the sandbox (as the daemon's
    // listeners are), for the peer check's netlink lookup under the filter.
    let pre = (mode == "seccomp").then(|| {
        let server = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        (server, client)
    });
    let policy = policy(&l, allowed_port);
    let report = sandbox::apply(&policy).unwrap();
    probe("report", serde_json::to_string(&report).unwrap());
    if let Some(connection) = pre {
        seccomp_probes(&l, &connection);
        return;
    }
    if mode == "ephemeral" {
        probe("bind_ephemeral", outcome(TcpListener::bind("127.0.0.1:0")));
        return;
    }
    let data = l.dirs().data;
    probe("write_inside", outcome(fs::write(data.join("a"), b"x")));
    probe(
        "write_outside",
        outcome(fs::write(l.outside.join("a"), b"x")),
    );
    probe(
        "write_in_readonly_root",
        outcome(fs::write(l.ro.join("new"), b"x")),
    );
    probe("read_allowed", outcome(fs::read(l.ro.join("f"))));
    probe("read_outside", outcome(fs::read(l.outside.join("f"))));
    probe(
        "unix_socket_bind_inside",
        outcome(UnixListener::bind(l.dirs().runtime.join("s.sock"))),
    );
    probe("devnull_write", outcome(fs::write("/dev/null", b"x")));
    probe(
        "tcp_connect",
        outcome(TcpStream::connect(("127.0.0.1", listener_port))),
    );
    probe(
        "tcp_bind_allowed_port",
        outcome(TcpListener::bind(("127.0.0.1", allowed_port))),
    );
    probe(
        "tcp_bind_other_port",
        outcome(TcpListener::bind(("127.0.0.1", 0))),
    );
    // Documented residual risk: path-based Unix sockets can be connected to anywhere (ABI <= 8).
    probe(
        "unix_connect_by_path_outside",
        outcome(UnixStream::connect(l.outside.join("u.sock"))),
    );
    // Scoped (ABI 6): abstract sockets and signals cannot reach processes outside the sandbox.
    let abstract_name = std::env::var(ENV_ABSTRACT).unwrap();
    probe(
        "abstract_unix_connect",
        outcome(
            UnixAddr::from_abstract_name(abstract_name.as_bytes())
                .and_then(|a| UnixStream::connect_addr(&a)),
        ),
    );
    probe(
        "signal_parent",
        outcome(nix::sys::signal::kill(nix::unistd::getppid(), None).map_err(io::Error::from)),
    );
    // Threads created after `apply` are confined too.
    let target = sandbox::probe_target(&policy);
    probe(
        "thread_probe",
        std::thread::spawn(move || sandbox::probe_read(target.as_deref()))
            .join()
            .unwrap(),
    );
    // Children inherit the ruleset (errno checked in the grandchild itself).
    probe(
        "grandchild_write_outside",
        in_grandchild("write", l.outside.join("g").to_str().unwrap()),
    );
    probe(
        "grandchild_read_outside",
        in_grandchild("read", l.outside.join("f").to_str().unwrap()),
    );
    probe(
        "grandchild_tcp_connect",
        in_grandchild("connect", &listener_port.to_string()),
    );
    probe(
        "grandchild_write_inside",
        in_grandchild("write", data.join("g").to_str().unwrap()),
    );
    git_probes(&l, listener_port);
    // A system binary can still be executed (git and claude live under the system paths).
    probe(
        "exec_system_binary",
        outcome(
            sandbox::child_command("/bin/sh")
                .args(["-c", "exit 0"])
                .status()
                .and_then(|s| {
                    s.success()
                        .then_some(())
                        .ok_or_else(|| io::Error::other("sh failed"))
                }),
        ),
    );
}

/// After the Landlock ruleset (the daemon's order): the seccomp socket filter and what it denies.
fn seccomp_probes(l: &Layout, (server, client): &(TcpListener, TcpStream)) {
    // Daemon-level probes before the filter (they need socket()).
    probe("daemon_write_outside", sandbox::probe_write(&l.outside));
    probe("daemon_write_readonly_root", sandbox::probe_write(&l.ro));
    probe("daemon_write_inside", sandbox::probe_write(&l.dirs().data));
    probe("daemon_connect", sandbox::probe_connect());
    // A thread that exists before the filter is installed (TSYNC must cover it).
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<String>();
    let early = std::thread::spawn(move || {
        go_rx.recv().unwrap();
        done_tx.send(sandbox::probe_socket()).unwrap();
    });
    let applied = sandbox::deny_new_sockets();
    probe(
        "seccomp_applied",
        outcome(applied.map_err(io::Error::other)),
    );
    probe("socket_main", sandbox::probe_socket());
    go_tx.send(()).unwrap();
    probe("socket_thread_created_before", done_rx.recv().unwrap());
    early.join().unwrap();
    probe(
        "socket_thread_created_after",
        std::thread::spawn(sandbox::probe_socket).join().unwrap(),
    );
    probe(
        "unix_connect_by_path_outside",
        outcome(UnixStream::connect(l.outside.join("u.sock"))),
    );
    probe("socketpair", outcome(UnixStream::pair()));
    probe(
        "netlink_route",
        outcome(
            nix::sys::socket::socket(
                nix::sys::socket::AddressFamily::Netlink,
                nix::sys::socket::SockType::Datagram,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
                nix::sys::socket::SockProtocol::NetlinkRoute,
            )
            .map_err(io::Error::from),
        ),
    );
    let me = nix::unistd::geteuid().as_raw();
    probe(
        "netlink_sock_diag",
        match cc_workspace_manager::http::peer::sock_diag_query(
            client.local_addr().unwrap(),
            server.local_addr().unwrap(),
        ) {
            Ok(Some(uid)) if uid == me => "ok".to_string(),
            other => format!("{other:?}"),
        },
    );
    probe("grandchild_udp", in_grandchild("udp", ""));
    probe(
        "grandchild_unix_connect",
        in_grandchild("unix_connect", l.outside.join("u.sock").to_str().unwrap()),
    );
    probe(
        "exec_after_filter",
        outcome(
            sandbox::child_command("/bin/sh")
                .args(["-c", "exit 0"])
                .status()
                .and_then(|s| {
                    s.success()
                        .then_some(())
                        .ok_or_else(|| io::Error::other("sh failed"))
                }),
        ),
    );
}

/// Test 11, Git-subprocess variant: Git started by the confined process cannot connect out or
/// write outside ccwm's directories, while ccwm's hardened inspection still works.
fn git_probes(l: &Layout, listener_port: u16) {
    let Some(git) = cc_workspace_manager::git::find_on_path(std::env::var_os("PATH").as_deref())
    else {
        probe("git", "missing");
        return;
    };
    let classify = |out: io::Result<std::process::Output>| match out {
        Ok(o) if o.status.success() => "ok".to_string(),
        Ok(o) if String::from_utf8_lossy(&o.stderr).contains("Permission denied") => {
            "EACCES".to_string()
        }
        Ok(o) => format!(
            "failed:{}",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .next()
                .unwrap_or("")
        ),
        Err(e) => outcome::<()>(Err(e)),
    };
    // Plain Git, protocols allowed: only the kernel can stop this connect.
    probe(
        "git_connect",
        classify(
            sandbox::child_command(&git)
                .args(["-c", "protocol.allow=always", "ls-remote"])
                .arg(format!("git://127.0.0.1:{listener_port}/x"))
                .env("GIT_TERMINAL_PROMPT", "0")
                .output(),
        ),
    );
    probe(
        "git_write_outside",
        classify(
            sandbox::child_command(&git)
                .args(["init", "-q"])
                .arg(l.outside.join("gitrepo"))
                .output(),
        ),
    );
    let g = cc_workspace_manager::git::Git::detect(Some(git), &l.ro, false);
    probe("git_inspect", g.inspect(&l.ro.join("repo")).state.as_str());
}

/// The daemon's own policy builder, fed with this layout.
fn policy(l: &Layout, port: u16) -> sandbox::Policy {
    sandbox::daemon_policy(
        &[l.ro.clone(), l.exe_dir.clone()],
        &l.ro.join("claude"),
        &l.dirs(),
        port,
    )
}

// ---- parent side ----------------------------------------------------------------------------------

struct Setup {
    _dir: tempfile::TempDir,
    layout: Layout,
    listener: TcpListener,
    _unix: UnixListener,
    _abstract: UnixListener,
    abstract_name: String,
    allowed_port: u16,
}

fn setup() -> Setup {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let layout = Layout::new(&root);
    for d in [&layout.ro, &layout.outside, &layout.ro.join("claude")] {
        fs::create_dir_all(d).unwrap();
    }
    for d in layout.dirs().all() {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(layout.ro.join("f"), b"data").unwrap();
    // A real repository inside the readable root, for the confined Git inspection.
    let repo = layout.ro.join("repo");
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("file"), b"x").unwrap();
    for args in [
        &["init", "-q"][..],
        &["add", "file"][..],
        &[
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "x",
        ][..],
    ] {
        let _ = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &layout.ro)
            .output();
    }
    fs::write(layout.outside.join("f"), b"data").unwrap();
    let unix = UnixListener::bind(layout.outside.join("u.sock")).unwrap();
    let abstract_name = format!("ccwm-sandbox-test-{}", std::process::id());
    let abstract_listener =
        UnixListener::bind_addr(&UnixAddr::from_abstract_name(abstract_name.as_bytes()).unwrap())
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // something the child must NOT reach
    let allowed_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    Setup {
        _dir: t,
        layout,
        listener,
        _unix: unix,
        _abstract: abstract_listener,
        abstract_name,
        allowed_port,
    }
}

fn run_child(mode: &str, s: &Setup) -> HashMap<String, String> {
    let out = Command::new(std::env::current_exe().unwrap())
        .env(ENV_MODE, mode)
        .env(ENV_ROOT, &s.layout.root)
        .env(
            ENV_PORTS,
            format!(
                "{},{}",
                s.listener.local_addr().unwrap().port(),
                s.allowed_port
            ),
        )
        .env(ENV_ABSTRACT, &s.abstract_name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix("PROBE "))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn report(p: &HashMap<String, String>) -> serde_json::Value {
    serde_json::from_str(&p["report"]).unwrap()
}

/// `false` (skip) if Landlock is not enforced here, unless `CCWM_REQUIRE_LANDLOCK=1`.
fn enforced(p: &HashMap<String, String>) -> bool {
    let r = report(p);
    if r["filesystem"] == true {
        return true;
    }
    assert!(
        std::env::var(REQUIRE).as_deref() != Ok("1"),
        "{REQUIRE}=1 but Landlock is not enforced: {r}"
    );
    eprintln!(
        "NOTICE: Landlock is not enforced on this kernel; skipping confinement assertions: {r}"
    );
    false
}

fn landlock_confines_the_process_threads_and_children() {
    let s = setup();
    let p = run_child("main", &s);
    if !enforced(&p) {
        return;
    }
    let want =
        |k: &str, v: &str| assert_eq!(p.get(k).map(String::as_str), Some(v), "probe {k}: {p:#?}");
    let r = report(&p);
    assert_eq!(r["threads_at_apply"], 1);
    assert_eq!(r["status"], "fully_enforced", "{r}");

    want("write_inside", "ok");
    want("write_outside", "EACCES");
    want("write_in_readonly_root", "EACCES");
    want("read_allowed", "ok");
    want("read_outside", "EACCES");
    want("unix_socket_bind_inside", "ok");
    want("devnull_write", "ok");
    want("thread_probe", sandbox::PROBE_DENIED);
    want("grandchild_write_outside", "EACCES");
    want("grandchild_read_outside", "EACCES");
    want("grandchild_write_inside", "ok");
    want("exec_system_binary", "ok");
    assert!(!s.layout.outside.join("a").exists() && !s.layout.outside.join("g").exists());

    // Residual risk, asserted so that a kernel/policy change is noticed and the docs updated.
    want("unix_connect_by_path_outside", "ok");
    for u in UNCONFINED_BY_LANDLOCK {
        assert!(
            r["unconfined"].as_array().unwrap().iter().any(|v| v == u),
            "{u}: {r}"
        );
    }

    if p.get("git").map(String::as_str) == Some("missing") {
        assert!(std::env::var_os("CI").is_none(), "git is required in CI");
        eprintln!("NOTICE: git not installed; Git-subprocess variant of test 11 skipped");
    } else {
        want("git_write_outside", "EACCES");
        assert!(!s.layout.outside.join("gitrepo").exists());
        want("git_inspect", "ok");
        if r["network"] == "tcp_only" {
            want("git_connect", "EACCES");
            s.listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(s.listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
                "a confined Git process reached the listener"
            );
        }
    }

    if r["network"] == "tcp_only" {
        want("tcp_connect", "EACCES");
        want("tcp_bind_allowed_port", "ok");
        want("tcp_bind_other_port", "EACCES");
        want("grandchild_tcp_connect", "EACCES");
    } else {
        eprintln!(
            "NOTICE: Landlock network rules unavailable (ABI < 4); skipping network assertions"
        );
    }
    if r["abstract_unix_socket"] == true {
        want("abstract_unix_connect", "EPERM");
        want("signal_parent", "EPERM");
    } else {
        eprintln!("NOTICE: Landlock scopes unavailable (ABI < 6); skipping scope assertions");
        want("abstract_unix_connect", "ok");
    }
}

fn ephemeral_bind_is_allowed_only_when_port_zero_is_granted() {
    // The daemon with `--port 0` (tests) grants port 0; here we grant a fixed port and check that
    // an ephemeral bind is then denied, documenting why `--port 0` needs the explicit rule.
    let s = setup();
    let p = run_child("ephemeral", &s);
    if !enforced(&p) {
        return;
    }
    if report(&p)["network"] == "tcp_only" {
        assert_eq!(p["bind_ephemeral"], "EACCES");
    }
}

fn a_second_thread_at_apply_time_makes_the_report_claim_nothing() {
    let s = setup();
    let p = run_child("threaded", &s);
    let r = report(&p);
    assert_eq!(r["status"], "not_enforced", "{r}");
    assert_eq!(r["filesystem"], false);
    assert_eq!(r["network"], "none");
    assert!(r["threads_at_apply"].as_u64().unwrap() >= 2, "{r}");
}

/// M4: the seccomp socket filter (installed after Landlock, on every thread) closes the two
/// residuals Landlock leaves open, keeps the peer check's netlink lookup working, and the
/// daemon-level write/connect probes are denied by Landlock.
fn the_seccomp_filter_denies_new_sockets_everywhere_but_the_peer_check() {
    let s = setup();
    let p = run_child("seccomp", &s);
    let want =
        |k: &str, v: &str| assert_eq!(p.get(k).map(String::as_str), Some(v), "probe {k}: {p:#?}");
    want("seccomp_applied", "ok");
    for k in [
        "socket_main",
        "socket_thread_created_before",
        "socket_thread_created_after",
    ] {
        want(k, sandbox::PROBE_EPERM);
    }
    want("unix_connect_by_path_outside", "EPERM");
    want("netlink_route", "EPERM");
    want("grandchild_udp", "EPERM");
    want("grandchild_unix_connect", "EPERM");
    want("socketpair", "ok");
    want("exec_after_filter", "ok");
    want("netlink_sock_diag", "ok");
    if !enforced(&p) {
        return;
    }
    want("daemon_write_outside", sandbox::PROBE_DENIED);
    want("daemon_write_readonly_root", sandbox::PROBE_DENIED);
    want("daemon_write_inside", sandbox::PROBE_ALLOWED);
    if report(&p)["network"] == "tcp_only" {
        want("daemon_connect", sandbox::PROBE_DENIED);
    }
    assert_eq!(
        fs::read_dir(&s.layout.outside).unwrap().count(),
        2,
        "nothing created outside (only the fixture file and socket)"
    );
}

fn child_processes_do_not_inherit_session_ipc_variables() {
    // Safe: this harness-less test binary is single-threaded here.
    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus");
    std::env::set_var("DBUS_EXTRA_THING", "x");
    std::env::set_var("SSH_AUTH_SOCK", "/nonexistent/agent");
    std::env::set_var("CCWM_KEEP_ME", "kept");
    let out = sandbox::child_command("/usr/bin/env").output().unwrap();
    let env = String::from_utf8_lossy(&out.stdout);
    for gone in [
        "DBUS_SESSION_BUS_ADDRESS=",
        "DBUS_EXTRA_THING=",
        "SSH_AUTH_SOCK=",
        "XDG_RUNTIME_DIR=",
    ] {
        assert!(
            !env.lines().any(|l| l.starts_with(gone)),
            "{gone} leaked:\n{env}"
        );
    }
    assert!(env.lines().any(|l| l == "CCWM_KEEP_ME=kept"));
    for k in [
        "DBUS_SESSION_BUS_ADDRESS",
        "DBUS_EXTRA_THING",
        "SSH_AUTH_SOCK",
        "CCWM_KEEP_ME",
    ] {
        std::env::remove_var(k);
    }
}

fn main() {
    if let Ok(mode) = std::env::var(ENV_MODE) {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if mode == "op" {
            child_op(&args);
        } else {
            child_main(&mode);
        }
        return;
    }
    let tests: [(&str, fn()); 5] = [
        (
            "landlock_confines_the_process_threads_and_children",
            landlock_confines_the_process_threads_and_children,
        ),
        (
            "ephemeral_bind_is_allowed_only_when_port_zero_is_granted",
            ephemeral_bind_is_allowed_only_when_port_zero_is_granted,
        ),
        (
            "a_second_thread_at_apply_time_makes_the_report_claim_nothing",
            a_second_thread_at_apply_time_makes_the_report_claim_nothing,
        ),
        (
            "the_seccomp_filter_denies_new_sockets_everywhere_but_the_peer_check",
            the_seccomp_filter_denies_new_sockets_everywhere_but_the_peer_check,
        ),
        (
            "child_processes_do_not_inherit_session_ipc_variables",
            child_processes_do_not_inherit_session_ipc_variables,
        ),
    ];
    // `cargo test -- <filter>` passes the filter; flags such as --nocapture are ignored here.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let mut failed = Vec::new();
    for (name, test) in tests {
        if filter.as_deref().is_some_and(|f| !name.contains(f)) {
            continue;
        }
        match catch_unwind(AssertUnwindSafe(test)) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(name);
            }
        }
    }
    if failed.is_empty() {
        println!("test result: ok");
    } else {
        println!("test result: FAILED: {failed:?}");
        std::process::exit(1);
    }
}
