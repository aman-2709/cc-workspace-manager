//! Service management end to end (REQUIREMENTS.md §13, M4) with the real `ccwm` binary in a
//! synthetic environment: `scripts/install.sh` / `scripts/uninstall.sh`, `ccwm service
//! install|uninstall [--purge]`, `ccwm start|stop|restart|status|doctor|auth revoke-all`.
//!
//! systemd is replaced by a stand-in `systemctl` first on `PATH` (the real user manager is never
//! asked anything): it records every call and really starts and stops the *installed* binary
//! (`~/.local/bin/ccwm serve`) with the synthetic environment, so every CLI path, the unit file
//! and the scripts run for real. What it cannot show — that systemd accepts the unit and runs the
//! daemon under its directives — was verified separately with transient user units
//! (ARCHITECTURE.md §13) and `systemd-analyze verify` (below).
//!
//! Also security acceptance tests **2** and **10**, `uninstall --purge` part: after a full ingest,
//! uninstalling with `--purge` leaves the projects and the Claude Code session files
//! byte-identical (mode, mtime, ctime, inode, content) and removes exactly ccwm's directories.

mod common;

use cc_workspace_manager::synth::{self, SynthEnv};
use common::{snapshot, snapshot_excluding};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ccwm");

/// The stand-in `systemctl --user …`. State lives in `$CCWM_FAKE_SYSTEMD`; the unit counts as
/// installed while the file `ccwm service install` writes exists.
const FAKE_SYSTEMCTL: &str = r#"#!/bin/sh
state="$CCWM_FAKE_SYSTEMD"
echo "$*" >>"$state/calls"
[ "$1" = "--user" ] || { echo "fake systemctl: --user expected" >&2; exit 64; }
shift
unit="$XDG_CONFIG_HOME/systemd/user/ccwm.service"
info="$XDG_RUNTIME_DIR/ccwm/instance.json"
pid() { sed -n 's/.*"pid":\([0-9]*\).*/\1/p' "$info" 2>/dev/null; }
start() {
    if [ -f "$state/active" ]; then return 0; fi
    # The installed binary, as ExecStart=%h/.local/bin/ccwm serve (port 0: 8765 may be taken).
    setsid "$HOME/.local/bin/ccwm" serve --port 0 >>"$state/daemon.log" 2>&1 </dev/null &
    touch "$state/active"
}
stop() {
    p=$(pid)
    if [ -n "$p" ]; then
        kill -TERM "$p" 2>/dev/null
        i=0
        while kill -0 "$p" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    fi
    rm -f "$state/active"
}
case "$1" in
show) if [ -f "$unit" ]; then echo loaded; else echo not-found; fi ;;
is-active) if [ -f "$state/active" ]; then echo active; else echo inactive; exit 3; fi ;;
is-enabled) if [ -f "$state/enabled" ]; then echo enabled; else echo disabled; exit 1; fi ;;
daemon-reload | reset-failed) ;;
enable) touch "$state/enabled"; [ "$2" = "--now" ] && start ;;
disable) rm -f "$state/enabled"; [ "$2" = "--now" ] && stop ;;
start) start ;;
stop) stop ;;
restart) stop; start ;;
*) echo "fake systemctl: unexpected $*" >&2; exit 64 ;;
esac
exit 0
"#;

struct World {
    _t: tempfile::TempDir,
    env: SynthEnv,
    fake_bin: PathBuf,
    state: PathBuf,
}

impl World {
    fn new() -> Self {
        let t = common::tempdir();
        let env = synth::generate(&t.path().join("e"), 2).unwrap();
        let fake_bin = t.path().join("fake-bin");
        let state = t.path().join("fake-systemd");
        std::fs::create_dir_all(&fake_bin).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let systemctl = fake_bin.join("systemctl");
        std::fs::write(&systemctl, FAKE_SYSTEMCTL).unwrap();
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        // ~/.local/bin exists already (as on most systems), so installing does not change home.
        std::fs::create_dir_all(env.home.join(".local/bin")).unwrap();
        Self {
            _t: t,
            env,
            fake_bin,
            state,
        }
    }

    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.fake_bin.display()))
            .env("NO_COLOR", "1")
            .env("CCWM_FAKE_SYSTEMD", &self.state);
        for (k, v) in self.env.env_pairs() {
            c.env(k, v);
        }
        c
    }

    /// Run with `input` on stdin; returns (exit code, stdout + stderr).
    fn run(&self, mut c: Command, input: &str) -> (Option<i32>, String) {
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let Output {
            status,
            stdout,
            stderr,
        } = child.wait_with_output().unwrap();
        (
            status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ),
        )
    }

    fn ccwm(&self, args: &[&str]) -> (Option<i32>, String) {
        self.ccwm_input(args, "")
    }

    fn ccwm_input(&self, args: &[&str], input: &str) -> (Option<i32>, String) {
        let mut c = self.command(BIN);
        c.args(args);
        self.run(c, input)
    }

    fn script(&self, name: &str, args: &[&str], input: &str) -> (Option<i32>, String) {
        let mut c = self.command("/bin/sh");
        c.arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scripts")
                .join(name),
        )
        .args(args);
        self.run(c, input)
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.state.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn unit(&self) -> PathBuf {
        self.env
            .config_home
            .join("systemd/user")
            .join(cc_workspace_manager::systemd::UNIT_NAME)
    }

    fn installed_bin(&self) -> PathBuf {
        self.env.home.join(".local/bin/ccwm")
    }

    fn socket_call(&self, op: &str) -> serde_json::Value {
        cc_workspace_manager::client::call(
            &self.env.runtime_dir.join("ccwm/ccwm.sock"),
            nix::unistd::geteuid().as_raw(),
            op,
        )
        .unwrap()
    }

    fn daemon_pid(&self) -> Option<i32> {
        cc_workspace_manager::instance::read_instance(
            &self.env.runtime_dir.join("ccwm/instance.json"),
        )
        .map(|i| i32::try_from(i.pid).unwrap())
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.state.join("daemon.log")).unwrap_or_default()
    }
}

impl Drop for World {
    /// Never leave a daemon behind, even when an assertion failed.
    fn drop(&mut self) {
        if let Some(pid) = self.daemon_pid() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }
}

fn wait_until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn service_commands_without_an_installed_unit_explain_what_to_do() {
    let w = World::new();
    for verb in ["start", "stop", "restart"] {
        let (code, out) = w.ccwm(&[verb]);
        assert_eq!(code, Some(1), "{verb}: {out}");
        assert!(
            out.contains("not installed") && out.contains("ccwm service install"),
            "{verb}: {out}"
        );
    }
    let (code, out) = w.ccwm(&["status"]);
    assert_eq!(code, Some(1));
    assert!(out.contains("systemd: ccwm.service not installed"), "{out}");
    assert!(out.contains("is the daemon running?"), "{out}");
    // The unit names a binary that must exist first.
    let (code, out) = w.ccwm(&["service", "install"]);
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains(".local/bin/ccwm") && out.contains("install.sh"),
        "{out}"
    );
    assert!(!w.unit().exists(), "nothing written");
    // Without systemctl at all.
    let mut c = w.command(BIN);
    c.env("PATH", "/nonexistent").arg("start");
    let (code, out) = w.run(c, "");
    assert_eq!(code, Some(1));
    assert!(
        out.contains("systemctl was not found") && out.contains("ccwm serve"),
        "{out}"
    );
    // Uninstalling what is not installed is fine (idempotent).
    let (code, out) = w.script("uninstall.sh", &[], "");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("nothing to remove"), "{out}");
}

#[test]
fn install_start_stop_restart_status_doctor_uninstall_and_purge_acceptance_2_and_10() {
    let w = World::new();
    let skip = [w.env.home.join(".local/bin")];
    let claude_before = snapshot(&w.env.claude_dir);
    let home_before = snapshot_excluding(&w.env.home, &skip);

    // install.sh: binary copied, unit written, daemon-reload + enable --now, daemon answers.
    let (code, out) = w.script("install.sh", &[BIN], "");
    assert_eq!(code, Some(0), "{out}\n{}", w.daemon_log());
    assert!(
        out.contains("Installed") && out.contains("(running)"),
        "{out}"
    );
    // The hint about starting at boot is printed unless lingering is already enabled for the
    // user the test runs as. That is the real machine's state (`/var/lib/systemd/linger`), which
    // no synthetic environment changes: off on a developer machine, on for a CI runner's user.
    // Both states of the hint itself are unit-tested in `systemd.rs`.
    let user = cc_workspace_manager::systemd::user_name(nix::unistd::geteuid().as_raw());
    let lingering = cc_workspace_manager::systemd::linger_enabled(user.as_deref());
    assert_eq!(
        out.contains("loginctl enable-linger"),
        lingering != Some(true),
        "the lingering hint does not match this machine's state ({lingering:?}): {out}"
    );
    assert_eq!(
        std::fs::read_to_string(w.unit()).unwrap(),
        cc_workspace_manager::systemd::unit_text()
    );
    assert_eq!(
        std::fs::metadata(w.installed_bin())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    let calls = w.calls();
    let reload = calls
        .iter()
        .position(|c| c == "--user daemon-reload")
        .unwrap();
    let enable = calls
        .iter()
        .position(|c| c == "--user enable --now ccwm.service")
        .unwrap();
    assert!(reload < enable, "{calls:?}");
    assert!(
        !calls.iter().any(|c| c.contains("linger")),
        "lingering is never changed: {calls:?}"
    );
    let first_pid = w.daemon_pid().unwrap();

    // The unit file itself passes systemd's own verification (where systemd-analyze exists).
    if Path::new("/usr/bin/systemd-analyze").exists() {
        let out = Command::new("/usr/bin/systemd-analyze")
            .args(["--user", "verify"])
            .arg(w.unit())
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        // %h resolves to the real home, where ~/.local/bin/ccwm need not exist: the only
        // complaint allowed is about that executable.
        let complaints: Vec<&str> = err
            .lines()
            .filter(|l| !l.contains(".local/bin/ccwm") && !l.trim().is_empty())
            .collect();
        assert!(complaints.is_empty(), "systemd-analyze: {err}");
    }

    let (code, out) = w.ccwm(&["status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.starts_with("systemd: ccwm.service active (enabled)\n"),
        "{out}"
    );
    assert!(out.contains("ccwm daemon 0.1.0"), "{out}");

    // Running install.sh again: idempotent, and an upgrade restarts the running service.
    let (code, out) = w.script("install.sh", &[BIN], "");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("is up to date"), "{out}");
    assert!(w.calls().iter().any(|c| c == "--user restart ccwm.service"));
    wait_until("the restarted daemon", 15, || {
        w.daemon_pid().is_some_and(|p| p != first_pid)
    });

    // stop / start / restart through systemctl.
    let (code, out) = w.ccwm(&["stop"]);
    assert_eq!((code, out.trim()), (Some(0), "ccwm stopped."), "{out}");
    assert!(!cc_workspace_manager::instance::lock_held(
        &cc_workspace_manager::paths::Dirs {
            config: w.env.config_home.join("ccwm"),
            data: w.env.data_home.join("ccwm"),
            state: w.env.state_home.join("ccwm"),
            runtime: w.env.runtime_dir.join("ccwm"),
        }
    ));
    let (code, out) = w.ccwm(&["start"]);
    assert_eq!(code, Some(0), "{out}\n{}", w.daemon_log());
    assert!(out.contains("(started)"), "{out}");
    let (code, out) = w.ccwm(&["restart"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("(restarted)"), "{out}");

    // A full ingest before uninstalling (acceptance 2/10 compare after it).
    wait_until("a finished scan with every session indexed", 30, || {
        let d = w.socket_call("discovery.status");
        d["scans_finished"].as_u64() >= Some(1)
            && d["sessions"]["files"].as_u64().is_some_and(|f| f > 0)
            && d["sessions"]["files"] == d["sessions"]["indexed"]
    });

    let (code, out) = w.ccwm(&["doctor"]);
    assert_eq!(code, Some(0), "{out}");
    for want in [
        "[  ok] daemon: running",
        "[  ok] systemd: ccwm.service active (enabled)",
        "[  ok] permissions:",
        "TCP peer check: sock_diag",
    ] {
        assert!(out.contains(want), "{want}: {out}");
    }
    let (code, out) = w.ccwm(&["auth", "revoke-all"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.starts_with("Signed out 0 browser sessions."), "{out}");

    // uninstall.sh keeps the data.
    let (code, out) = w.script("uninstall.sh", &[], "");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("Your ccwm data is kept"), "{out}");
    assert!(!w.unit().exists() && !w.installed_bin().exists());
    assert!(w
        .calls()
        .iter()
        .any(|c| c == "--user disable --now ccwm.service"));
    assert!(w.env.data_home.join("ccwm/ccwm.db").exists(), "data kept");
    assert!(w.env.config_home.join("ccwm").exists());

    // --purge asks first; anything but "yes" deletes nothing.
    let (code, out) = w.script("install.sh", &[BIN], "");
    assert_eq!(code, Some(0), "{out}");
    let (code, out) = w.script("uninstall.sh", &["--purge"], "no\n");
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("Type 'yes'")
            && out.contains("none of your ccwm data was deleted")
            && out.contains("the service itself is uninstalled"),
        "{out}"
    );
    assert!(w.env.data_home.join("ccwm/ccwm.db").exists());
    let (code, out) = w.script("uninstall.sh", &["--purge"], "yes\n");
    assert_eq!(code, Some(0), "{out}");
    for dir in w.env.ccwm_dirs() {
        assert!(!dir.exists(), "{} purged: {out}", dir.display());
        assert!(out.contains(&format!("Deleted {}", dir.display())), "{out}");
    }
    assert!(!w.installed_bin().exists() && !w.unit().exists());
    let (code, out) = w.script("uninstall.sh", &["--purge"], "");
    assert_eq!(code, Some(1), "nothing left to locate the data with: {out}");
    let (code, out) = w.script("uninstall.sh", &[], "");
    assert_eq!(code, Some(0), "idempotent: {out}");

    // Acceptance 2 and 10: session files and project data byte-identical after the purge.
    assert_eq!(
        snapshot(&w.env.claude_dir),
        claude_before,
        "session files changed"
    );
    assert_eq!(
        snapshot_excluding(&w.env.home, &skip),
        home_before,
        "project data changed"
    );
    assert!(!w.daemon_log().contains("panicked"), "{}", w.daemon_log());
}
