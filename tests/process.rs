//! End-to-end tests with the real `ccwm` binary in a synthetic environment (never the real home).
//! Covers: serve + open + browser auth flow, SIGTERM shutdown, restart cache, single instance,
//! port collision, the CLI refusing an impostor TCP listener, file permissions, no secrets in logs,
//! and read-only behaviour on the monitored tree (acceptance tests 1, 6, 11 at process level).

mod common;

use cc_workspace_manager::synth::{self, SynthEnv};
use common::{snapshot, snapshot_excluding};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ccwm");

fn command(env: &SynthEnv) -> Command {
    let mut c = Command::new(BIN);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("NO_COLOR", "1");
    for (k, v) in env.env_pairs() {
        c.env(k, v);
    }
    c
}

struct Daemon {
    child: Child,
    log: Arc<Mutex<String>>,
    port: u16,
    /// The daemon's own pid (from `instance.json`): differs from `child` when it runs under a
    /// wrapper (strace, unshare).
    daemon_pid: i32,
}

impl Daemon {
    fn start(env: &SynthEnv, extra: &[&str]) -> Self {
        Self::start_with_env(env, extra, &[])
    }

    fn start_with_env(env: &SynthEnv, extra: &[&str], vars: &[(&str, &str)]) -> Self {
        Self::start_wrapped(env, extra, vars, &[])
    }

    /// Start `ccwm serve` as `wrapper… ccwm serve …` when `wrapper` is not empty.
    fn start_wrapped(
        env: &SynthEnv,
        extra: &[&str],
        vars: &[(&str, &str)],
        wrapper: &[String],
    ) -> Self {
        let mut c = match wrapper.split_first() {
            None => command(env),
            Some((program, args)) => {
                let mut c = Command::new(program);
                c.env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("NO_COLOR", "1")
                    .args(args)
                    .arg(BIN);
                for (k, v) in env.env_pairs() {
                    c.env(k, v);
                }
                c
            }
        };
        for (k, v) in vars {
            c.env(k, v);
        }
        c.args(["serve", "--port", "0"])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let stderr = child.stderr.take().unwrap();
        let sink = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut l = sink.lock().unwrap();
                l.push_str(&line);
                l.push('\n');
            }
        });
        let info_path = env.runtime_dir.join("ccwm/instance.json");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(info) = cc_workspace_manager::instance::read_instance(&info_path) {
                if info.pid == child.id() || (!wrapper.is_empty() && info.pid != 0) {
                    return Self {
                        child,
                        log,
                        port: info.port,
                        daemon_pid: i32::try_from(info.pid).unwrap(),
                    };
                }
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("daemon exited early ({status}):\n{}", log.lock().unwrap());
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not start:\n{}",
                log.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn pid(&self) -> i32 {
        self.daemon_pid
    }

    /// SIGTERM and wait for the exit status.
    fn stop(mut self) -> (Option<i32>, String) {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid()),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "daemon ignored SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        };
        std::thread::sleep(Duration::from_millis(50)); // let the log reader drain
        (status.code(), self.log.lock().unwrap().clone())
    }

    fn http(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, HashMap<String, String>, String) {
        http(self.port, method, path, headers, body)
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn open_url(&self, env: &SynthEnv) -> String {
        let out = command(env).args(["open", "--print"]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// The whole browser flow: `ccwm open --print` -> fragment -> exchange.
    fn login(&self, env: &SynthEnv) -> String {
        let url = self.open_url(env);
        let token = url.split("#bt=").nth(1).expect("fragment").to_string();
        let origin = self.origin();
        let (status, _, body) = self.http(
            "POST",
            "/api/v1/auth/exchange",
            &[("Origin", &origin), ("Content-Type", "application/json")],
            &format!(r#"{{"bootstrap_token":"{token}"}}"#),
        );
        assert_eq!(status, 200, "{body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["session_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn get_json(&self, token: &str, path: &str) -> serde_json::Value {
        let (s, _, b) = self.http(
            "GET",
            path,
            &[("Authorization", &format!("Bearer {token}"))],
            "",
        );
        assert_eq!(s, 200, "{path}: {b}");
        serde_json::from_str(&b).unwrap()
    }

    fn wait_scan_done(&self, token: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let st = self.get_json(token, "/api/v1/discovery/status");
            if st["phase"] == "idle"
                && !st["last_success_at"].is_null()
                && st["roots"].as_array().is_some_and(|r| !r.is_empty())
            {
                return;
            }
            assert!(Instant::now() < deadline, "discovery did not finish: {st}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // A wrapper's death would leave the daemon running: kill the daemon itself too, but only
        // while the child (wrapper or daemon) still runs, so the pid cannot have been reused.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.daemon_pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Minimal HTTP/1.1 client over `std::net` (HTTP client crates are banned, even for tests).
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, HashMap<String, String>, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let hdrs = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    (status, hdrs, body.to_string())
}

const REQUIRE_LANDLOCK: &str = "CCWM_REQUIRE_LANDLOCK";

fn sandbox_report(env: &SynthEnv) -> serde_json::Value {
    cc_workspace_manager::client::call(
        &env.runtime_dir.join("ccwm/ccwm.sock"),
        nix::unistd::geteuid().as_raw(),
        "service.status",
    )
    .unwrap()["sandbox"]
        .clone()
}

/// Every claim the daemon makes about itself, checked exactly (EACCES probes, single thread).
fn assert_daemon_confined(r: &serde_json::Value) {
    if r["filesystem"] != true {
        assert!(
            std::env::var(REQUIRE_LANDLOCK).as_deref() != Ok("1"),
            "{REQUIRE_LANDLOCK}=1 but the daemon is not confined: {r}"
        );
        eprintln!("NOTICE: Landlock not enforced on this kernel: {r}");
        return;
    }
    assert_eq!(r["status"], "fully_enforced", "{r}");
    assert_eq!(r["threads_at_apply"], 1, "{r}");
    assert_eq!(r["thread_probes"]["worker"], "eacces", "{r}");
    assert_eq!(r["thread_probes"]["blocking"], "eacces", "{r}");
    assert_eq!(r["no_new_privs"], true, "{r}");
    assert!(
        r["network"] == "tcp_only" || r["abi"].as_u64() < Some(4),
        "{r}"
    );
    for u in cc_workspace_manager::sandbox::ALWAYS_UNCONFINED {
        assert!(
            r["unconfined"].as_array().unwrap().iter().any(|v| v == u),
            "{r}"
        );
    }
}

fn names(v: &serde_json::Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["path"].as_str().unwrap().to_string())
        .collect()
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn serve_open_browser_flow_security_checks_and_clean_shutdown() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 12).unwrap();
    let tree_before = snapshot(&env.home);
    let d = Daemon::start(&env, &[]);

    // `ccwm open --print` yields a single-use link with the daemon's real port.
    let url = d.open_url(&env);
    assert!(
        url.starts_with(&format!("http://127.0.0.1:{}/#bt=", d.port)),
        "{url}"
    );
    assert_eq!(url.split("#bt=").nth(1).unwrap().len(), 43);

    // The first link is spent by exchanging it; the second use fails.
    let origin = d.origin();
    let token = url.split("#bt=").nth(1).unwrap();
    let body = format!(r#"{{"bootstrap_token":"{token}"}}"#);
    let post = |b: &str| {
        d.http(
            "POST",
            "/api/v1/auth/exchange",
            &[("Origin", &origin), ("Content-Type", "application/json")],
            b,
        )
    };
    let (s, _, resp) = post(&body);
    assert_eq!(s, 200);
    let session = serde_json::from_str::<serde_json::Value>(&resp).unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(post(&body).0, 401, "bootstrap tokens are single-use");

    // Acceptance: unauthenticated, wrong-Host and wrong-Origin requests are rejected (real sockets).
    assert_eq!(d.http("GET", "/api/v1/projects", &[], "").0, 401);
    assert_eq!(
        d.http(
            "GET",
            "/api/v1/projects",
            &[("Authorization", "Bearer nope")],
            ""
        )
        .0,
        401
    );
    let bearer = format!("Bearer {session}");
    assert_eq!(
        d.http(
            "GET",
            "/api/v1/projects",
            &[("Host", "evil.example"), ("Authorization", &bearer)],
            ""
        )
        .0,
        421
    );
    assert_eq!(
        d.http(
            "GET",
            "/api/v1/projects",
            &[
                ("Origin", "http://evil.example"),
                ("Authorization", &bearer)
            ],
            ""
        )
        .0,
        403
    );
    assert_eq!(
        d.http(
            "POST",
            "/api/v1/auth/logout",
            &[("Authorization", &bearer)],
            ""
        )
        .0,
        403,
        "state change without Origin"
    );
    let (s, h, _) = d.http("GET", "/", &[], "");
    assert_eq!(s, 200);
    assert!(h["content-security-policy"].contains(&format!("ws://127.0.0.1:{}", d.port)));

    // Discovery found exactly the synthetic projects.
    d.wait_scan_done(&session);
    let mut all = Vec::new();
    let mut cursor = String::new();
    loop {
        let page = d.get_json(&session, &format!("/api/v1/projects?limit=7{cursor}"));
        all.extend(names(&page));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = format!("&cursor={c}"),
            None => break,
        }
    }
    let home = env.home.to_str().unwrap();
    let mut expected: Vec<String> = env
        .expected_projects(12)
        .iter()
        .map(|p| format!("{home}/{p}"))
        .collect();
    expected.sort_by_key(|p| p.rsplit('/').next().unwrap().to_lowercase());
    let mut got = all.clone();
    got.sort();
    expected.sort();
    assert_eq!(got, expected);
    assert_eq!(
        d.get_json(&session, "/api/v1/stats")["total_projects"],
        expected.len()
    );

    // Rotation and logout over real sockets.
    let (s, _, b) = d.http(
        "POST",
        "/api/v1/auth/rotate",
        &[("Origin", &origin), ("Authorization", &bearer)],
        "",
    );
    assert_eq!(s, 200, "{b}");
    let rotated = serde_json::from_str::<serde_json::Value>(&b).unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        d.http(
            "POST",
            "/api/v1/auth/logout",
            &[
                ("Origin", &origin),
                ("Authorization", &format!("Bearer {rotated}"))
            ],
            ""
        )
        .0,
        204
    );
    assert_eq!(
        d.http(
            "GET",
            "/api/v1/stats",
            &[("Authorization", &format!("Bearer {rotated}"))],
            ""
        )
        .0,
        401
    );

    // Private files, socket and directories.
    let rt = env.runtime_dir.join("ccwm");
    assert_eq!(mode(&rt), 0o700);
    assert_eq!(mode(&rt.join("ccwm.sock")), 0o600);
    assert_eq!(mode(&rt.join("instance.json")), 0o600);
    assert_eq!(mode(&env.data_home.join("ccwm")), 0o700);
    assert_eq!(mode(&env.data_home.join("ccwm/ccwm.db")), 0o600);
    assert_eq!(mode(&env.state_home.join("ccwm")), 0o700);
    assert_eq!(mode(&env.config_home.join("ccwm")), 0o700);

    // WAL/SHM exist while the daemon runs and are as private as the database.
    for f in ["ccwm.db-wal", "ccwm.db-shm"] {
        assert_eq!(mode(&env.data_home.join("ccwm").join(f)), 0o600, "{f}");
    }

    // Test 11 in the real daemon: the report comes from the daemon's own daemon_policy(), and its
    // worker and blocking-pool threads were probed after the runtime started.
    let report = sandbox_report(&env);
    assert_daemon_confined(&report);
    assert!(d.log.lock().unwrap().contains("landlock"));

    // Graceful shutdown: exit 0, runtime files removed.
    let (code, log) = d.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(!rt.join("ccwm.sock").exists() && !rt.join("instance.json").exists());

    // Secrets never reach the logs; the monitored tree is untouched (acceptance tests 1 and 8-lite).
    for secret in [token, &session, &rotated] {
        assert!(!log.contains(secret), "token leaked into the log");
    }
    assert_eq!(
        snapshot(&env.home),
        tree_before,
        "ccwm modified the monitored tree"
    );
}

#[test]
fn restart_serves_cached_projects_even_when_the_tree_is_gone() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 5).unwrap();
    let first = Daemon::start(&env, &[]);
    let s1 = first.login(&env);
    first.wait_scan_done(&s1);
    let before = first.get_json(&s1, "/api/v1/projects?limit=200");
    let n = before["total"].as_u64().unwrap();
    assert!(n >= 13, "{n}");
    assert_eq!(first.stop().0, Some(0));

    // Move the home away: a fresh scan finds nothing, so anything served comes from the cache.
    std::fs::rename(&env.home, t.path().join("gone")).unwrap();
    std::fs::create_dir(&env.home).unwrap();
    let second = Daemon::start(&env, &[]);
    let s2 = second.login(&env);
    // Served from the cache: same projects, ids and order, whether or not the new scan (which
    // finds nothing) has already marked them missing.
    let all = "/api/v1/projects?limit=200&include_missing=1";
    let after = second.get_json(&s2, all);
    assert_eq!(
        after["total"].as_u64(),
        Some(n),
        "cached projects are served immediately after a restart"
    );
    assert_eq!(names(&after), names(&before), "same projects, same order");
    assert_eq!(
        before["items"][0]["id"], after["items"][0]["id"],
        "ids survive a restart"
    );
    second.wait_scan_done(&s2);
    // M2: projects that were not found are marked missing, never deleted (§4.5).
    let visible = second.get_json(&s2, "/api/v1/projects?limit=200");
    assert_eq!(
        visible["total"], 0,
        "missing projects are hidden by default"
    );
    let kept = second.get_json(&s2, all);
    assert_eq!(kept["total"].as_u64(), Some(n));
    assert!(kept["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["missing_since"].is_i64()));
    assert_eq!(
        second.get_json(&s2, "/api/v1/stats")["missing"].as_u64(),
        Some(n)
    );
    assert_eq!(second.stop().0, Some(0));
}

#[test]
fn a_second_daemon_in_the_same_environment_refuses_to_start() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let d = Daemon::start(&env, &[]);
    let out = command(&env)
        .args(["serve", "--port", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already running"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The first daemon is unharmed and still owns its socket.
    assert!(d.http("GET", "/api/v1/health", &[], "").0 == 200);
    assert!(!d.login(&env).is_empty());
    assert_eq!(d.stop().0, Some(0));
}

#[test]
fn port_collision_fails_fast_with_a_clear_message() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let out = command(&env)
        .args(["serve", "--port", &port.to_string()])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("port {port} is already in use")) && err.contains("--port"),
        "{err}"
    );
}

#[test]
fn open_refuses_an_impostor_tcp_listener_and_sends_it_nothing() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    // No daemon. An impostor listens on a port and even leaves a fake instance.json pointing at it.
    let impostor = TcpListener::bind("127.0.0.1:0").unwrap();
    impostor.set_nonblocking(true).unwrap();
    let port = impostor.local_addr().unwrap().port();
    let rt = env.runtime_dir.join("ccwm");
    std::fs::DirBuilder::new().mode_700().create(&rt).unwrap();
    std::fs::write(
        rt.join("instance.json"),
        format!(r#"{{"pid":1,"port":{port},"version":"0.1.0","started_at":0}}"#),
    )
    .unwrap();

    let out = command(&env).args(["open", "--print"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not running"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "no URL may be printed without a verified daemon"
    );
    assert!(
        matches!(impostor.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the impostor must receive no connection at all"
    );
}

#[test]
fn open_without_any_runtime_directory_explains_how_to_start_the_daemon() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let out = command(&env).args(["open"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is the daemon running"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn serve_refuses_unsafe_directories() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let data = env.data_home.join("ccwm");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = command(&env)
        .args(["serve", "--port", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("chmod 700"), "{err}");
    assert_eq!(
        mode(&data),
        0o755,
        "an existing directory is never silently changed"
    );
}

#[test]
fn serve_rejects_bad_config_and_bad_port_arguments() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let cfg = t.path().join("bad.toml");
    std::fs::write(&cfg, "[server]\nprot = 1\n").unwrap();
    let out = command(&env)
        .args(["serve", "--config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid config"));
    let out = command(&env)
        .args(["serve", "--port", "80"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed"));
}

#[test]
fn explicit_roots_in_the_config_are_honoured() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let only = env.home.join("dev/alpha");
    let cfg = t.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!("[discovery]\nroots = [\"{}\"]\n", only.display()),
    )
    .unwrap();
    let d = Daemon::start(&env, &["--config", cfg.to_str().unwrap()]);
    let s = d.login(&env);
    d.wait_scan_done(&s);
    let page = d.get_json(&s, "/api/v1/projects");
    assert_eq!(names(&page), [only.to_str().unwrap().to_string()]);
    assert_eq!(d.stop().0, Some(0));
}

/// All project paths, following the cursor.
fn all_paths(d: &Daemon, session: &str) -> Vec<String> {
    let mut all = Vec::new();
    let mut cursor = String::new();
    loop {
        let page = d.get_json(session, &format!("/api/v1/projects?limit=7{cursor}"));
        all.extend(names(&page));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = format!("&cursor={c}"),
            None => break,
        }
    }
    all.sort();
    all
}

fn expected_paths(env: &SynthEnv, bulk: usize) -> Vec<String> {
    let home = env.home.to_str().unwrap();
    let mut v: Vec<String> = env
        .expected_projects(bulk)
        .iter()
        .map(|p| format!("{home}/{p}"))
        .collect();
    v.sort();
    v
}

/// Tests 1, 7 and L7 in the layout the real defaults produce: ccwm's XDG directories (and the Claude
/// config directory) inside the walked home, under non-hidden names so only the hard boundaries keep
/// discovery out. Runs at CCWM_LOG=trace: no token may reach the log at any level (8-lite).
#[test]
fn xdg_and_claude_dirs_inside_home_are_never_walked_and_trace_logs_hold_no_secrets() {
    let t = common::tempdir();
    let env = synth::generate_with(&t.path().join("e"), 4, synth::Layout::InsideHome).unwrap();
    let skip = env.ccwm_dirs().to_vec();
    let before = snapshot_excluding(&env.home, &skip);
    let d = Daemon::start_with_env(&env, &[], &[("CCWM_LOG", "trace")]);
    let url = d.open_url(&env);
    let bootstrap = url.split("#bt=").nth(1).unwrap().to_string();
    let origin = d.origin();
    let (s, _, body) = d.http(
        "POST",
        "/api/v1/auth/exchange",
        &[("Origin", &origin), ("Content-Type", "application/json")],
        &format!(r#"{{"bootstrap_token":"{bootstrap}"}}"#),
    );
    assert_eq!(s, 200, "{body}");
    let session = serde_json::from_str::<serde_json::Value>(&body).unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    d.wait_scan_done(&session);
    assert_eq!(
        all_paths(&d, &session),
        expected_paths(&env, 4),
        "ccwm's own directories and the Claude config directory are hard boundaries"
    );
    let (s, _, b) = d.http(
        "POST",
        "/api/v1/auth/rotate",
        &[
            ("Origin", &origin),
            ("Authorization", &format!("Bearer {session}")),
        ],
        "",
    );
    assert_eq!(s, 200, "{b}");
    let rotated = serde_json::from_str::<serde_json::Value>(&b).unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_daemon_confined(&sandbox_report(&env));
    let (code, log) = d.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(
        log.contains("tcp peer check") && log.contains("socket request"),
        "debug/trace events were not logged:\n{log}"
    );
    for secret in [&bootstrap, &session, &rotated] {
        assert!(
            !log.contains(secret.as_str()),
            "a token reached the trace log"
        );
    }
    assert_eq!(
        snapshot_excluding(&env.home, &skip),
        before,
        "ccwm modified something outside its own directories"
    );
}

/// L4 / test 7: XDG variables and the config path must not let another user steer the daemon.
#[test]
fn untrusted_xdg_directories_and_config_files_are_refused() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let refused = |c: &mut Command| {
        let out = c.output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // A world-writable XDG_DATA_HOME: another user could swap ccwm's data directory.
    let open_dir = t.path().join("world");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = refused(
        command(&env)
            .env("XDG_DATA_HOME", &open_dir)
            .args(["serve", "--port", "0"]),
    );
    assert!(err.contains("other users"), "{err}");
    assert!(!open_dir.join("ccwm").exists(), "nothing was created there");

    // A world-writable config file, and a trusted-looking path whose directory is world-writable.
    let cfg = t.path().join("c.toml");
    std::fs::write(&cfg, "[server]\nport = 0\n").unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = refused(command(&env).args(["serve", "--config", cfg.to_str().unwrap()]));
    assert!(err.contains("untrusted config"), "{err}");
    let inner = open_dir.join("c.toml");
    std::fs::write(&inner, "[server]\nport = 0\n").unwrap();
    std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = refused(command(&env).args(["serve", "--config", inner.to_str().unwrap()]));
    assert!(err.contains("untrusted config"), "{err}");
    // A symlinked config whose target lives in the world-writable directory.
    let link = t.path().join("link.toml");
    std::os::unix::fs::symlink(&inner, &link).unwrap();
    let err = refused(command(&env).args(["serve", "--config", link.to_str().unwrap()]));
    assert!(err.contains("untrusted config"), "{err}");
    // A directory or FIFO is not a config file.
    let fifo = t.path().join("fifo.toml");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
    let err = refused(command(&env).args(["serve", "--config", fifo.to_str().unwrap()]));
    assert!(err.contains("regular file"), "{err}");
}

/// M2: a --config elsewhere adds no read rule; a root that is an ancestor of home is flagged.
#[test]
fn broad_read_rules_are_reported_and_the_config_directory_is_not_granted() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let cfg_dir = t.path().join("cfg");
    std::fs::DirBuilder::new()
        .mode_700()
        .create(&cfg_dir)
        .unwrap();
    let cfg = cfg_dir.join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "[discovery]\nroots = [\"{}\"]\n",
            env.home.join("dev/alpha").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
    let d = Daemon::start(&env, &["--config", cfg.to_str().unwrap()]);
    let r = sandbox_report(&env);
    assert_eq!(r["broad_read_rules"], serde_json::json!([]), "{r}");
    assert_daemon_confined(&r);
    assert_eq!(d.stop().0, Some(0));

    std::fs::write(
        &cfg,
        format!("[discovery]\nroots = [\"{}\"]\n", env.root.display()),
    )
    .unwrap();
    let d = Daemon::start(&env, &["--config", cfg.to_str().unwrap()]);
    let r = sandbox_report(&env);
    let want = std::fs::canonicalize(&env.root).unwrap();
    assert_eq!(r["broad_read_rules"], serde_json::json!([want]), "{r}");
    assert!(
        r["notes"].to_string().contains("ancestor of the home"),
        "{r}"
    );
    assert_eq!(d.stop().0, Some(0));
}

/// L5: with every TCP connection slot held by idle clients, the CLI channel still works and the
/// excess client waits in the kernel backlog instead of costing the daemon a file descriptor.
#[test]
fn the_unix_socket_stays_usable_while_tcp_connections_are_saturated() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let d = Daemon::start(&env, &[]);
    // M2: let the first reconciliation (directory walks, Git pipes) settle before counting.
    wait_scans_finished(&env, 1);
    std::thread::sleep(Duration::from_millis(500));
    let fds_before = std::fs::read_dir(format!("/proc/{}/fd", d.pid()))
        .unwrap()
        .count();
    let idle: Vec<TcpStream> = (0..cc_workspace_manager::http::MAX_CONNECTIONS + 20)
        .map(|_| TcpStream::connect(("127.0.0.1", d.port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    let url = d.open_url(&env);
    assert!(url.contains("#bt="), "{url}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the CLI was slowed down"
    );
    let fds_during = std::fs::read_dir(format!("/proc/{}/fd", d.pid()))
        .unwrap()
        .count();
    assert!(
        // Slack 4 (< the 20 excess clients): background work may hold a few descriptors briefly.
        fds_during <= fds_before + cc_workspace_manager::http::MAX_CONNECTIONS + 4,
        "TCP clients beyond the cap must not hold descriptors: {fds_before} -> {fds_during}"
    );
    drop(idle);
    // Slots are released: a normal request works again.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if d.http("GET", "/api/v1/health", &[], "").0 == 200 {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(d.stop().0, Some(0));
}

trait Mode700 {
    fn mode_700(&mut self) -> &mut Self;
}
impl Mode700 for std::fs::DirBuilder {
    fn mode_700(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}

// ---- M2: live updates, Git status, read-only monitoring, security acceptance test 5 ---------------

fn socket_call(env: &SynthEnv, op: &str) -> serde_json::Value {
    cc_workspace_manager::client::call(
        &env.runtime_dir.join("ccwm/ccwm.sock"),
        nix::unistd::geteuid().as_raw(),
        op,
    )
    .unwrap()
}

fn wait_until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait until discovery has finished `n` reconciliations, over the socket.
fn wait_scans_finished(env: &SynthEnv, n: u64) {
    wait_until("a finished reconciliation", 30, || {
        socket_call(env, "discovery.status")["scans_finished"].as_u64() >= Some(n)
    });
}

/// Request a reconciliation over the socket and wait until exactly that one has finished.
fn refresh_and_wait(env: &SynthEnv) {
    let target = socket_call(env, "scan.refresh")["done_at_scans_finished"]
        .as_u64()
        .unwrap();
    wait_scans_finished(env, target);
}

/// `true` if the real inotify watcher is active; otherwise a notice (or a failure with
/// `CCWM_REQUIRE_INOTIFY=1`): this host has few inotify instances left.
fn inotify_active(env: &SynthEnv) -> bool {
    let st = socket_call(env, "service.status");
    if st["monitoring"]["watcher"] == "inotify" {
        return true;
    }
    assert!(
        std::env::var("CCWM_REQUIRE_INOTIFY").as_deref() != Ok("1"),
        "no inotify instance: {st}"
    );
    eprintln!("NOTICE: the daemon could not create an inotify instance; live checks skipped");
    false
}

fn project_by_name<'a>(page: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {page}"))
}

/// M2 acceptance: editing a file moves its project to the top live; a new `CLAUDE.md` in a
/// watched area registers a project without a reload; Git status is correct. Over the real
/// daemon's WebSocket.
#[test]
fn m2_acceptance_live_updates_and_git_status() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 6).unwrap();
    let real_git = synth::init_git(&env).unwrap();
    let d = Daemon::start(&env, &[]);
    let token = d.login(&env);
    d.wait_scan_done(&token);

    if real_git {
        // Git status is correct (and credentials never leave the daemon).
        wait_until("git status of the synthetic repositories", 30, || {
            let page = d.get_json(&token, "/api/v1/projects?limit=200");
            ["monorepo", "beta", "inner"]
                .iter()
                .all(|n| project_by_name(&page, n)["git"]["state"] == "ok")
        });
        let page = d.get_json(&token, "/api/v1/projects?limit=200");
        let git = |n: &str| project_by_name(&page, n)["git"].clone();
        assert_eq!(
            (
                git("monorepo")["untracked"].as_i64(),
                git("monorepo")["dirty"].as_bool()
            ),
            (Some(1), Some(true)),
            "NOTES.txt is untracked"
        );
        assert_eq!(git("monorepo")["branch"], "main");
        assert_eq!(
            git("beta")["untracked"],
            1,
            "the nested repository shows as untracked"
        );
        assert_eq!(
            (
                git("inner")["staged"].as_i64(),
                git("inner")["modified"].as_i64(),
                git("inner")["untracked"].as_i64()
            ),
            (Some(0), Some(0), Some(0))
        );
        assert_eq!(project_by_name(&page, "alpha")["git"]["state"], "not_git");
        let mono_id = project_by_name(&page, "monorepo")["id"]
            .as_str()
            .unwrap()
            .to_string();
        let detail = d.get_json(&token, &format!("/api/v1/projects/{mono_id}"));
        assert_eq!(
            detail["git_detail"]["remote_url"],
            "https://example.invalid/monorepo.git"
        );
        let dirty = d.get_json(&token, "/api/v1/projects?dirty=1&limit=200");
        let mut dirty_names: Vec<&str> = dirty["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        dirty_names.sort_unstable();
        assert_eq!(dirty_names, ["beta", "monorepo"]);
        assert!(!page.to_string().contains("synthetic-password"));
        assert!(!detail.to_string().contains("synthetic-password"));
    } else {
        eprintln!("NOTICE: git is not installed; Git status checks skipped");
    }

    if !inotify_active(&env) {
        return;
    }
    wait_until("every project watched", 30, || {
        let m = &socket_call(&env, "service.status")["monitoring"];
        m["polled_projects"] == 0 && m["watched_projects"].as_u64() >= Some(14)
    });
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", d.port).parse().unwrap();
    let mut ws = common::WsClient::connect(addr, d.port, Some(&d.origin())).unwrap();
    ws.send_text(&format!(r#"{{"type":"auth","token":"{token}"}}"#));
    assert_eq!(ws.recv_json(Duration::from_secs(5))["type"], "ready");
    let wait_event =
        |ws: &mut common::WsClient, what: &str, pred: &dyn Fn(&serde_json::Value) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                assert!(Instant::now() < deadline, "no live event: {what}");
                if let Some(common::Frame::Text(t)) = ws.recv(Duration::from_secs(1)) {
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                    if pred(&v) {
                        return v;
                    }
                }
            }
        };

    // Editing a file moves its project to the top, live. (Timestamps have one-second resolution
    // and ties sort by name: edit in a later second than the synthetic files were written.)
    std::thread::sleep(Duration::from_millis(1100));
    let target = env.home.join("bulk/proj-0002");
    std::fs::write(target.join("notes.md"), "edited\n").unwrap();
    let ev = wait_event(&mut ws, "edit in proj-0002", &|v| {
        v["type"] == "project"
            && v["project"]["name"] == "proj-0002"
            && v["project"]["activity"]["kind"] == "observed"
    });
    assert_eq!(ev["project"]["activity"]["path"], "notes.md");
    assert_eq!(ev["project"]["activity"]["status"], "today");
    let top = d.get_json(&token, "/api/v1/projects?limit=1");
    assert_eq!(
        top["items"][0]["name"], "proj-0002",
        "the edited project is first"
    );

    // A new CLAUDE.md in a watched area registers a project without a reload.
    let fresh = env.home.join("dev/fresh-project");
    std::fs::create_dir(&fresh).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    std::fs::write(fresh.join("CLAUDE.md"), "# fresh\n").unwrap();
    let ev = wait_event(&mut ws, "new project", &|v| {
        v["type"] == "project" && v["project"]["name"] == "fresh-project"
    });
    assert_eq!(ev["project"]["display_path"], "~/dev/fresh-project");
    assert_eq!(ev["project"]["sources"], serde_json::json!(["marker"]));
    let (code, log) = d.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(!log.contains(&token), "token leaked into the log");
}

/// Acceptance tests 1 and 3 at process level, for M2: discovery, watching, Git and a manual
/// reconciliation (`ccwm scan`) leave the monitored tree (including every `.git`) and the
/// Claude config directory byte-identical, with mtimes and modes.
#[test]
fn acceptance_1_and_3_monitoring_git_and_reconciliation_modify_nothing() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 4).unwrap();
    let real_git = synth::init_git(&env).unwrap();
    let home_before = snapshot(&env.home);
    let claude_before = snapshot(&env.claude_dir);
    let d = Daemon::start(&env, &[]);
    let token = d.login(&env);
    d.wait_scan_done(&token);
    if real_git {
        wait_until("git inspected", 30, || {
            let page = d.get_json(&token, "/api/v1/projects?limit=200");
            project_by_name(&page, "monorepo")["git"]["state"] == "ok"
        });
    }
    let out = command(&env).arg("scan").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Scan finished"));
    // A second scan right after the first (same second) must also be recognised as finished.
    let again = command(&env).arg("scan").output().unwrap();
    assert!(again.status.success());
    assert!(String::from_utf8_lossy(&again.stdout).contains("Scan finished"));
    std::thread::sleep(Duration::from_millis(1500)); // Git refreshes after the reconciliation
    let status = command(&env).arg("status").output().unwrap();
    let text = String::from_utf8_lossy(&status.stdout);
    assert!(
        status.status.success() && text.contains(&format!("port {}", d.port)),
        "{text}"
    );
    assert!(
        !String::from_utf8_lossy(&status.stderr).contains("warning"),
        "same build: no commit warning"
    );
    assert_eq!(d.stop().0, Some(0));
    assert_eq!(
        snapshot(&env.home),
        home_before,
        "the monitored tree changed"
    );
    assert_eq!(
        snapshot(&env.claude_dir),
        claude_before,
        "the Claude directory changed"
    );
}

/// Lines of an `strace -e trace=connect` log that connect anywhere but loopback or a Unix socket.
fn non_loopback_connects(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| l.contains("connect("))
        .filter(|l| !connect_is_local(l))
        .map(str::to_string)
        .collect()
}

fn connect_is_local(line: &str) -> bool {
    let quoted = |prefix: &str| {
        line.split_once(prefix)
            .and_then(|(_, rest)| rest.split('"').next())
            .map(str::to_string)
    };
    if line.contains("sa_family=AF_UNIX") || line.contains("sa_family=AF_UNSPEC") {
        return true;
    }
    if line.contains("sa_family=AF_INET,") {
        return quoted("inet_addr(\"").is_some_and(|a| a.starts_with("127."));
    }
    if line.contains("sa_family=AF_INET6") {
        return quoted("inet_pton(AF_INET6, \"")
            .is_some_and(|a| a == "::1" || a.starts_with("::ffff:127."));
    }
    false // anything else (other families, unparsable lines) counts as a violation
}

#[test]
fn the_connect_log_classifier_flags_every_non_loopback_connect() {
    let log = r#"
100 connect(3, {sa_family=AF_UNIX, sun_path="/run/user/1000/ccwm/ccwm.sock"}, 110) = 0
101 connect(4, {sa_family=AF_INET, sin_port=htons(8765), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
102 connect(5, {sa_family=AF_INET6, sin6_port=htons(1), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
103 connect(6, {sa_family=AF_INET6, sin6_port=htons(1), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:127.0.0.2", &sin6_addr), sin6_scope_id=0}, 28) = 0
104 connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 EACCES (Permission denied)
105 connect(8, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28 <unfinished ...>
106 <... connect resumed>) = -1 ENETUNREACH
107 connect(9, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
108 connect(10, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("1.1.1.1")}, 16) = 0
109 execve("/usr/bin/git", ["git", "status"], 0x0 /* 6 vars */) = 0
"#;
    let bad = non_loopback_connects(log);
    let pids: Vec<&str> = bad.iter().map(|l| l.split(' ').next().unwrap()).collect();
    assert_eq!(pids, ["104", "105", "107", "108"], "{bad:#?}");
}

/// Which isolation security acceptance test 5 can use on this host: a network namespace
/// (`unshare`, mapping the current user: ccwm refuses to run as root) and/or `strace`. Each is
/// probed with the exact wrapper it would run.
fn test5_wrapper(log: &Path) -> Option<(Vec<String>, &'static str)> {
    let works = |argv: &[&str]| {
        Command::new(argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let log = log.to_str().unwrap();
    let strace = [
        "strace",
        "-f",
        "-qq",
        "-e",
        "trace=connect,execve",
        "-o",
        log,
    ];
    let netns = [
        "unshare",
        "--user",
        "--map-current-user",
        "--keep-caps",
        "--net",
        "--",
        "sh",
        "-c",
        "ip link set lo up && exec \"$@\"",
        "sh",
    ];
    let has_strace = works(&[&strace[..], &["true"]].concat());
    let has_netns = works(&[&netns[..], &["true"]].concat());
    let own = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
    match (has_netns, has_strace) {
        (true, true) => Some((
            [own(&netns), own(&strace)].concat(),
            "network namespace + strace",
        )),
        (false, true) => Some((own(&strace), "strace (no network namespace on this host)")),
        (true, false) => Some((own(&netns), "network namespace (no strace)")),
        (false, false) => None,
    }
}

/// Security acceptance test 5: through a discovery, live-watch, Git and reconciliation cycle, the
/// daemon and its Git subprocesses attempt no non-loopback connect (strace), and/or run in a
/// network namespace with only loopback. Skipped with a notice when neither is available.
/// (The session cycle joins in M3, when sessions are parsed.)
#[test]
fn acceptance_5_no_external_network_connections() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 3).unwrap();
    let real_git = synth::init_git(&env).unwrap();
    // Make Git's network paths tempting: remotes over https and ssh.
    if real_git {
        let beta = env.home.join("dev/beta");
        let out = Command::new("git")
            .current_dir(&beta)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &env.home)
            .args([
                "remote",
                "add",
                "origin",
                "ssh://git@example.invalid/beta.git",
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let log_path = t.path().join("connect.log");
    let Some((wrapper, variant)) = test5_wrapper(&log_path) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "test 5 needs strace or unprivileged network namespaces in CI"
        );
        eprintln!("NOTICE: security acceptance test 5 skipped: neither unshare (network namespace) nor strace is usable here");
        return;
    };
    eprintln!("NOTICE: security acceptance test 5 variant: {variant}");
    let d = Daemon::start_wrapped(&env, &[], &[], &wrapper);
    wait_scans_finished(&env, 1);
    // Live: an edit in a Git project (activity + Git refresh) and a new project.
    std::fs::write(env.home.join("dev/beta/CLAUDE.md"), "# beta, edited\n").unwrap();
    let fresh = env.home.join("dev/t5-new");
    std::fs::create_dir(&fresh).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    std::fs::write(fresh.join("CLAUDE.md"), "# new\n").unwrap();
    std::thread::sleep(Duration::from_secs(3));
    // Reconciliation over the socket, then let the Git refreshes run.
    refresh_and_wait(&env);
    std::thread::sleep(Duration::from_secs(2));
    let (code, daemon_log) = d.stop();
    assert_eq!(code, Some(0), "{daemon_log}");
    if variant.contains("strace") {
        let log = std::fs::read_to_string(&log_path).unwrap();
        let bad = non_loopback_connects(&log);
        assert!(
            bad.is_empty(),
            "non-loopback connect attempts:\n{}",
            bad.join("\n")
        );
        if real_git {
            let git_runs = log
                .lines()
                .filter(|l| l.contains("execve(") && l.contains("git\""))
                .count();
            assert!(
                git_runs >= 3,
                "Git subprocesses were not traced ({git_runs} execs)"
            );
        }
        let connects = log.lines().filter(|l| l.contains("connect(")).count();
        eprintln!(
            "NOTICE: test 5: {connects} connect() calls traced, all loopback or Unix sockets"
        );
    }
}
