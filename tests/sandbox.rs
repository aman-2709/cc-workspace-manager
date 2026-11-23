//! Security acceptance test 11: Landlock denies writes outside ccwm's directories and outbound
//! connects, for the process itself and for its children, while the allowed operations still work.
//!
//! Landlock is irreversible, so the confined part runs in a re-executed copy of this test binary
//! (`sandbox_child`), which reports probe results on stdout as `PROBE key=value` lines.

use cc_workspace_manager::sandbox::{self, Policy, SYSTEM_READ_PATHS};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

const ENV_MODE: &str = "CCWM_SANDBOX_CHILD_MODE";
const ENV_ROOT: &str = "CCWM_SANDBOX_CHILD_ROOT";
const ENV_PORTS: &str = "CCWM_SANDBOX_CHILD_PORTS"; // "<listener port>,<allowed bind port>"

fn probe(key: &str, value: impl std::fmt::Display) {
    println!("PROBE {key}={value}");
}

fn denied<T>(r: std::io::Result<T>) -> &'static str {
    match r {
        Ok(_) => "allowed",
        Err(e) if e.kind() == ErrorKind::PermissionDenied => "denied",
        Err(e) => Box::leak(format!("error:{:?}", e.kind()).into_boxed_str()),
    }
}

fn shell_status(cmd: &str, script: &str) -> &'static str {
    match Command::new(cmd).args(["-c", script]).status() {
        Ok(s) if s.success() => "allowed",
        Ok(_) => "denied",
        Err(_) => "unavailable",
    }
}

/// Child entry point. Does nothing unless re-executed by the parent test below.
#[test]
fn sandbox_child() {
    let Ok(mode) = std::env::var(ENV_MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var(ENV_ROOT).unwrap());
    let ports: Vec<u16> = std::env::var(ENV_PORTS)
        .unwrap()
        .split(',')
        .map(|p| p.parse().unwrap())
        .collect();
    let (listener_port, allowed_port) = (ports[0], ports[1]);
    let (rw, ro, outside) = (root.join("rw"), root.join("ro"), root.join("outside"));

    let mut read: Vec<PathBuf> = SYSTEM_READ_PATHS.iter().map(PathBuf::from).collect();
    read.push(ro.clone());
    let report = sandbox::apply(&Policy {
        read,
        read_write: vec![rw.clone()],
        tcp_bind_port: Some(allowed_port),
    })
    .unwrap();
    probe("report", serde_json::to_string(&report).unwrap());

    if mode == "ephemeral" {
        probe("bind_ephemeral", denied(TcpListener::bind("127.0.0.1:0")));
        return;
    }
    probe("write_inside", denied(fs::write(rw.join("a"), b"x")));
    probe("write_outside", denied(fs::write(outside.join("a"), b"x")));
    probe(
        "write_in_readonly_dir",
        denied(fs::write(ro.join("new"), b"x")),
    );
    probe("read_allowed", denied(fs::read(ro.join("f"))));
    probe("read_outside", denied(fs::read(outside.join("f"))));
    probe(
        "unix_socket_bind_inside",
        denied(UnixListener::bind(rw.join("s.sock"))),
    );
    probe("devnull_write", denied(fs::write("/dev/null", b"x")));
    probe(
        "tcp_connect",
        denied(TcpStream::connect(("127.0.0.1", listener_port))),
    );
    probe(
        "tcp_bind_allowed_port",
        denied(TcpListener::bind(("127.0.0.1", allowed_port))),
    );
    probe(
        "tcp_bind_other_port",
        denied(TcpListener::bind(("127.0.0.1", 0))),
    );
    // Children inherit the ruleset.
    probe(
        "child_write_inside",
        shell_status("/bin/sh", &format!("echo x > '{}'", rw.join("c").display())),
    );
    probe(
        "child_write_outside",
        shell_status(
            "/bin/sh",
            &format!("echo x > '{}'", outside.join("c").display()),
        ),
    );
    probe(
        "child_tcp_connect",
        shell_status(
            "/bin/bash",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{listener_port}"),
        ),
    );
}

fn run_child(mode: &str, root: &std::path::Path, ports: (u16, u16)) -> HashMap<String, String> {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sandbox_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENV_MODE, mode)
        .env(ENV_ROOT, root)
        .env(ENV_PORTS, format!("{},{}", ports.0, ports.1))
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
        .filter_map(|l| l.split_once("PROBE ").map(|(_, rest)| rest))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn setup() -> (tempfile::TempDir, TcpListener, u16) {
    let t = tempfile::tempdir().unwrap();
    for d in ["rw", "ro", "outside"] {
        fs::create_dir(t.path().join(d)).unwrap();
    }
    fs::write(t.path().join("ro/f"), b"data").unwrap();
    fs::write(t.path().join("outside/f"), b"data").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // something the child must NOT reach
    (t, listener, free_port())
}

fn enforced(probes: &HashMap<String, String>) -> bool {
    let report: serde_json::Value = serde_json::from_str(&probes["report"]).unwrap();
    if report["filesystem"] != true {
        eprintln!("NOTICE: Landlock is not enforced on this kernel; skipping confinement assertions: {report}");
        return false;
    }
    true
}

#[test]
fn landlock_confines_the_process_and_its_children() {
    let (t, listener, allowed) = setup();
    let p = run_child(
        "main",
        t.path(),
        (listener.local_addr().unwrap().port(), allowed),
    );
    if !enforced(&p) {
        return;
    }
    let want =
        |k: &str, v: &str| assert_eq!(p.get(k).map(String::as_str), Some(v), "probe {k}: {p:#?}");

    want("write_inside", "allowed");
    want("write_outside", "denied");
    want("write_in_readonly_dir", "denied");
    want("read_allowed", "allowed");
    want("read_outside", "denied");
    want("unix_socket_bind_inside", "allowed");
    want("devnull_write", "allowed");
    want("child_write_inside", "allowed");
    want("child_write_outside", "denied");
    assert!(!t.path().join("outside/a").exists() && !t.path().join("outside/c").exists());

    let report: serde_json::Value = serde_json::from_str(&p["report"]).unwrap();
    if report["network"] == true {
        want("tcp_connect", "denied");
        want("tcp_bind_allowed_port", "allowed");
        want("tcp_bind_other_port", "denied");
        want("child_tcp_connect", "denied");
    } else {
        eprintln!(
            "NOTICE: Landlock network rules unavailable (ABI < 4); skipping network assertions"
        );
    }
}

#[test]
fn ephemeral_bind_is_allowed_only_when_port_zero_is_granted() {
    // The daemon with `--port 0` (tests) grants port 0; here we grant a fixed port and check that
    // an ephemeral bind is then denied, documenting why `--port 0` needs the explicit rule.
    let (t, listener, allowed) = setup();
    let p = run_child(
        "ephemeral",
        t.path(),
        (listener.local_addr().unwrap().port(), allowed),
    );
    if !enforced(&p) {
        return;
    }
    let report: serde_json::Value = serde_json::from_str(&p["report"]).unwrap();
    if report["network"] == true {
        assert_eq!(p["bind_ephemeral"], "denied");
    }
}
