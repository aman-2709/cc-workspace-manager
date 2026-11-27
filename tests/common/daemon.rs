//! The real `ccwm` binary in a synthetic environment (never the real home): CLI commands, a
//! daemon started with `ccwm serve --port 0`, a minimal HTTP client, socket calls. Shared by
//! `tests/process.rs` and `tests/hooks.rs`.

use cc_workspace_manager::synth::SynthEnv;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_ccwm");

/// A CLI command in the synthetic environment. `PATH` starts with a stub `systemctl` that
/// knows nothing, so `ccwm status` never asks the real user manager (tests/service.rs has a
/// working stand-in).
pub fn command(env: &SynthEnv) -> Command {
    let stub = env.root.join("stub-bin");
    if !stub.join("systemctl").exists() {
        std::fs::create_dir_all(&stub).unwrap();
        super::write_executable(&stub.join("systemctl"), "#!/bin/sh\nexit 1\n");
    }
    let mut c = Command::new(BIN);
    c.env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", stub.display()))
        .env("NO_COLOR", "1");
    for (k, v) in env.env_pairs() {
        c.env(k, v);
    }
    c
}

pub struct Daemon {
    pub child: Child,
    pub log: Arc<Mutex<String>>,
    pub port: u16,
    /// The daemon's own pid (from `instance.json`): differs from `child` when it runs under a
    /// wrapper (strace).
    pub daemon_pid: i32,
}

impl Daemon {
    pub fn start(env: &SynthEnv, extra: &[&str]) -> Self {
        Self::start_with_env(env, extra, &[])
    }

    pub fn start_with_env(env: &SynthEnv, extra: &[&str], vars: &[(&str, &str)]) -> Self {
        Self::start_wrapped(env, extra, vars, &[])
    }

    /// Start `ccwm serve` as `wrapper… ccwm serve …` when `wrapper` is not empty.
    pub fn start_wrapped(
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

    pub fn pid(&self) -> i32 {
        self.daemon_pid
    }

    /// SIGTERM and wait for the exit status.
    pub fn stop(mut self) -> (Option<i32>, String) {
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

    pub fn http(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, HashMap<String, String>, String) {
        http(self.port, method, path, headers, body)
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn open_url(&self, env: &SynthEnv) -> String {
        let out = command(env).args(["open", "--print"]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// The whole browser flow: `ccwm open --print` -> fragment -> exchange.
    pub fn login(&self, env: &SynthEnv) -> String {
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

    pub fn get_json(&self, token: &str, path: &str) -> serde_json::Value {
        let (s, _, b) = self.http(
            "GET",
            path,
            &[("Authorization", &format!("Bearer {token}"))],
            "",
        );
        assert_eq!(s, 200, "{path}: {b}");
        serde_json::from_str(&b).unwrap()
    }

    pub fn wait_scan_done(&self, token: &str) {
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
pub fn http(
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

pub fn socket_call(env: &SynthEnv, op: &str) -> serde_json::Value {
    cc_workspace_manager::client::call(
        &env.runtime_dir.join("ccwm/ccwm.sock"),
        nix::unistd::geteuid().as_raw(),
        op,
    )
    .unwrap()
}

pub fn wait_until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
