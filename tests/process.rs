//! End-to-end tests with the real `ccwm` binary in a synthetic environment (never the real home).
//! Covers: serve + open + browser auth flow, SIGTERM shutdown, restart cache, single instance,
//! port collision, the CLI refusing an impostor TCP listener, file permissions, no secrets in logs,
//! and read-only behaviour on the monitored tree (acceptance tests 1, 6, 11 at process level).

mod common;

use cc_workspace_manager::synth::{self, SynthEnv};
use common::snapshot;
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
}

impl Daemon {
    fn start(env: &SynthEnv, extra: &[&str]) -> Self {
        let mut c = command(env);
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
                if info.pid == child.id() {
                    return Self {
                        child,
                        log,
                        port: info.port,
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
        i32::try_from(self.child.id()).unwrap()
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
    let t = tempfile::tempdir().unwrap();
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

    // The sandbox report is visible in the log and over the socket; NoNewPrivs proves Landlock ran.
    let status = command(&env).args(["open", "--print"]).output().unwrap();
    assert!(status.status.success());
    let proc_status = std::fs::read_to_string(format!("/proc/{}/status", d.pid())).unwrap();
    let report = cc_workspace_manager::client::call(
        &rt.join("ccwm.sock"),
        nix::unistd::geteuid().as_raw(),
        "service.status",
    )
    .unwrap();
    let fs_enforced = report["sandbox"]["filesystem"] == true;
    if fs_enforced {
        assert!(
            proc_status
                .lines()
                .any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1')),
            "{proc_status}"
        );
    } else {
        eprintln!(
            "NOTICE: Landlock not enforced on this kernel: {}",
            report["sandbox"]
        );
    }
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
    let t = tempfile::tempdir().unwrap();
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
    let after = second.get_json(&s2, "/api/v1/projects?limit=200");
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
    assert_eq!(second.stop().0, Some(0));
}

#[test]
fn a_second_daemon_in_the_same_environment_refuses_to_start() {
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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
    let t = tempfile::tempdir().unwrap();
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

trait Mode700 {
    fn mode_700(&mut self) -> &mut Self;
}
impl Mode700 for std::fs::DirBuilder {
    fn mode_700(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}
