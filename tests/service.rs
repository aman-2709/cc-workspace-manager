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
        Self::with_layout(synth::Layout::Separate)
    }

    /// `layout` says where ccwm's XDG directories live relative to the home folder.
    fn with_layout(layout: synth::Layout) -> Self {
        let t = common::tempdir();
        let env = synth::generate_with(&t.path().join("e"), 2, layout).unwrap();
        let fake_bin = t.path().join("fake-bin");
        let state = t.path().join("fake-systemd");
        std::fs::create_dir_all(&fake_bin).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        common::write_executable(&fake_bin.join("systemctl"), FAKE_SYSTEMCTL);
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

    /// The parents of ccwm's four directories (`$XDG_CONFIG_HOME`, …), in the order of
    /// [`SynthEnv::ccwm_dirs`].
    fn xdg_parents(&self) -> [&Path; 4] {
        let e = &self.env;
        [&e.config_home, &e.data_home, &e.state_home, &e.runtime_dir]
    }
}

/// The names in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
    } else {
        common::skipped_coverage(
            "systemd-analyze is not installed; the unit file was not verified by systemd",
        );
    }

    let (code, out) = w.ccwm(&["status"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.starts_with("systemd: ccwm.service active (enabled)\n"),
        "{out}"
    );
    assert!(
        out.contains(concat!("ccwm daemon ", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );

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

/// v0.1.0 review, test-coverage gap 4: `--purge` with ccwm's directories **inside** the home
/// folder, each next to another application's data (the real layout: `~/.config/ccwm` beside
/// `~/.config/<everything else>`). The purge removes exactly the four `ccwm` directories: their
/// parents stay, the neighbours stay byte-identical, and so do the projects and the session
/// files. With the directories outside home (the other test) a purge that took a whole XDG
/// directory would go unnoticed.
#[test]
fn purge_removes_exactly_ccwms_directories_when_they_live_inside_the_home_folder() {
    let w = World::with_layout(synth::Layout::InsideHome);
    for parent in w.xdg_parents() {
        let neighbour = parent.join("other-app");
        std::fs::create_dir(&neighbour).unwrap();
        std::fs::write(neighbour.join("data"), "SYNTHETIC not ccwm's").unwrap();
        assert!(parent.starts_with(&w.env.home), "{}", parent.display());
    }
    let (code, out) = w.script("install.sh", &[BIN], "");
    assert_eq!(code, Some(0), "{out}\n{}", w.daemon_log());
    wait_until("a finished scan", 30, || {
        w.socket_call("discovery.status")["scans_finished"].as_u64() >= Some(1)
    });
    // What must survive, taken while the daemon runs (it never writes there).
    let neighbours = |w: &World| -> Vec<Vec<String>> {
        w.xdg_parents()
            .iter()
            .map(|p| snapshot(&p.join("other-app")))
            .collect()
    };
    let (neighbours_before, projects_before, sessions_before) = (
        neighbours(&w),
        snapshot(&w.env.home.join("dev")),
        snapshot(&w.env.claude_dir),
    );
    for dir in w.env.ccwm_dirs() {
        assert!(dir.is_dir(), "control: {} exists before", dir.display());
    }

    let (code, out) = w.script("uninstall.sh", &["--purge"], "yes\n");
    assert_eq!(code, Some(0), "{out}");
    for dir in w.env.ccwm_dirs() {
        assert!(!dir.exists(), "{} purged: {out}", dir.display());
    }
    // Each parent is still there and holds what it held, minus `ccwm` (the configuration
    // directory also keeps the now empty `systemd/user` the unit was in).
    let left: Vec<Vec<String>> = w.xdg_parents().iter().map(|p| names_in(p)).collect();
    assert_eq!(
        left,
        [
            vec!["other-app", "systemd"],
            vec!["other-app"],
            vec!["other-app"],
            vec!["other-app"],
        ]
    );
    assert_eq!(neighbours(&w), neighbours_before, "a neighbour changed");
    assert_eq!(
        snapshot(&w.env.home.join("dev")),
        projects_before,
        "project data changed"
    );
    assert_eq!(
        snapshot(&w.env.claude_dir),
        sessions_before,
        "session files changed"
    );
}

/// v0.1.0 review, test-coverage gap 4: `--purge` refuses while a daemon still holds the
/// instance lock (one started outside systemd, which `disable --now` cannot stop): nothing is
/// deleted, the question is not even asked, and the daemon keeps running on its data. Control:
/// once that daemon has stopped, the same command deletes the directories.
#[test]
fn purge_is_refused_while_a_daemon_outside_systemd_holds_the_lock() {
    let w = World::new();
    let mut c = w.command(BIN);
    c.args(["serve", "--port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut daemon = c.spawn().unwrap();
    wait_until("the daemon", 15, || w.daemon_pid().is_some());
    wait_until("a finished scan", 30, || {
        w.socket_call("discovery.status")["scans_finished"].as_u64() >= Some(1)
    });
    let db = w.env.data_home.join("ccwm/ccwm.db");
    assert!(db.exists());

    let (code, out) = w.ccwm_input(&["service", "uninstall", "--purge"], "yes\n");
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("a ccwm daemon is still running") && out.contains("stop it before purging"),
        "{out}"
    );
    assert!(!out.contains("Type 'yes'"), "asked before refusing: {out}");
    assert!(!out.contains("Deleted "), "{out}");
    for dir in w.env.ccwm_dirs() {
        assert!(dir.is_dir(), "{} was removed: {out}", dir.display());
    }
    assert!(db.exists());
    // The daemon still runs and answers on its socket (`socket_call` panics otherwise).
    w.socket_call("ping");
    assert_eq!(daemon.try_wait().unwrap(), None, "the daemon was stopped");

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(daemon.id()).unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert_eq!(daemon.wait().unwrap().code(), Some(0));
    let (code, out) = w.ccwm_input(&["service", "uninstall", "--purge"], "yes\n");
    assert_eq!(code, Some(0), "{out}");
    for dir in w.env.ccwm_dirs() {
        assert!(!dir.exists(), "{} purged: {out}", dir.display());
    }
}

/// v0.1.0 review, test-coverage gap 8: the path a release takes, end to end.
/// `scripts/package-release.sh` builds the archive and `SHA256SUMS`; `sha256sum -c` accepts
/// them (and rejects a changed archive); the archive is reproducible and holds exactly the
/// documented files with fixed modes and owner 0; and `scripts/install.sh` run **from the
/// extracted archive, without an argument** (the README's instructions) installs the `ccwm`
/// next to it and starts the service.
///
/// The packaged "binary" is a small stand-in that reports the version and otherwise runs the
/// real test binary: compressing the 140 MB debug binary would take most of a minute. The
/// archive is named for the musl target because the script always names it so.
#[test]
fn the_release_archive_verifies_is_reproducible_and_installs_from_its_own_layout() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let w = World::new();
    let work = w._t.path().join("release");
    std::fs::create_dir(&work).unwrap();
    let stand_in = work.join("ccwm-stand-in");
    common::write_executable(
        &stand_in,
        &format!(
            "#!/bin/sh\ncase \"$1\" in --version) echo 'ccwm {VERSION}' ;; *) exec '{BIN}' \"$@\" ;; esac\n"
        ),
    );
    let licenses = work.join("THIRD_PARTY_LICENSES");
    std::fs::write(&licenses, "SYNTHETIC third-party licenses\n").unwrap();
    let package = |version: &str, out: &Path| -> (Option<i32>, String) {
        let mut c = w.command("/bin/sh");
        c.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/package-release.sh"))
            .arg(&stand_in)
            .arg(version)
            .arg(&licenses)
            .arg(out)
            // A fixed time: reproducible, and independent of the checkout's Git history.
            .env("SOURCE_DATE_EPOCH", "1800000000");
        w.run(c, "")
    };
    let tool = |program: &str, args: &[&str], dir: &Path| -> (bool, String) {
        let out = Command::new(program)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };
    let name = format!("ccwm-{VERSION}-x86_64-unknown-linux-musl");
    let archive = format!("{name}.tar.gz");

    // Refused: a version the binary does not report, and a missing input.
    let (code, out) = package("9.9.9", &work.join("wrong"));
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("binary reports 'ccwm ") && !work.join("wrong").exists(),
        "{out}"
    );

    let dist = work.join("dist");
    let (code, out) = package(VERSION, &dist);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(names_in(&dist), ["SHA256SUMS".to_string(), archive.clone()]);
    let (ok, out) = tool("sha256sum", &["-c", "SHA256SUMS"], &dist);
    assert!(ok && out.contains(&format!("{archive}: OK")), "{out}");

    // Reproducible: the same inputs give the same bytes.
    let again = work.join("dist-again");
    assert_eq!(package(VERSION, &again).0, Some(0));
    let bytes = std::fs::read(dist.join(&archive)).unwrap();
    assert_eq!(std::fs::read(again.join(&archive)).unwrap(), bytes);
    // Control: a changed archive does not pass the check.
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 0xff;
    std::fs::write(again.join(&archive), changed).unwrap();
    let (ok, out) = tool("sha256sum", &["-c", "SHA256SUMS"], &again);
    assert!(!ok && out.contains("FAILED"), "{out}");

    // Exactly the documented files, with fixed modes, owned by 0/0.
    let (ok, listing) = tool("tar", &["--numeric-owner", "-tvzf", &archive], &dist);
    assert!(ok, "{listing}");
    let entries: Vec<(String, String, String)> = listing
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (
                f[0].to_string(),
                f[1].to_string(),
                f.last().unwrap().to_string(),
            )
        })
        .collect();
    let expect = |mode: &str, path: &str| {
        (
            mode.to_string(),
            "0/0".to_string(),
            format!("{name}/{path}"),
        )
    };
    assert_eq!(
        entries,
        [
            expect("drwxr-xr-x", ""),
            expect("-rw-r--r--", "CHANGELOG.md"),
            expect("-rw-r--r--", "LICENSE"),
            expect("-rw-r--r--", "README.md"),
            expect("-rw-r--r--", "SECURITY.md"),
            expect("-rw-r--r--", "THIRD_PARTY_LICENSES"),
            expect("-rwxr-xr-x", "ccwm"),
            expect("drwxr-xr-x", "scripts/"),
            expect("-rwxr-xr-x", "scripts/install.sh"),
            expect("-rwxr-xr-x", "scripts/uninstall.sh"),
        ],
        "{listing}"
    );

    // Install from the extracted archive, as the README says: no argument, from its folder.
    let (ok, out) = tool("tar", &["-xzf", &archive], &dist);
    assert!(ok, "{out}");
    let extracted = dist.join(&name);
    let run_script = |script: &str, args: &[&str], input: &str| {
        let mut c = w.command(extracted.join("scripts").join(script));
        c.args(args).current_dir(&extracted);
        w.run(c, input)
    };
    let (code, out) = run_script("install.sh", &[], "");
    assert_eq!(code, Some(0), "{out}\n{}", w.daemon_log());
    assert!(
        out.contains(&format!("(ccwm {VERSION})")) && out.contains("(running)"),
        "{out}"
    );
    assert_eq!(
        std::fs::read(w.installed_bin()).unwrap(),
        std::fs::read(extracted.join("ccwm")).unwrap(),
        "the ccwm of the archive is what was installed"
    );
    assert!(w.unit().exists());
    wait_until("the installed daemon", 15, || w.daemon_pid().is_some());
    let (code, out) = run_script("uninstall.sh", &["--purge"], "yes\n");
    assert_eq!(code, Some(0), "{out}");
    assert!(!w.installed_bin().exists() && !w.unit().exists());
    for dir in w.env.ccwm_dirs() {
        assert!(!dir.exists(), "{} purged: {out}", dir.display());
    }
}
