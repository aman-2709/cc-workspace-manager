//! v0.2 stop 1 at process level (REQUIREMENTS.md §21.3–§21.7, §21.9, §21.11): the real `ccwm`
//! binary in a synthetic environment, with a **fake** Claude Code process tree (`bash` started with
//! `argv[0]` = `claude`, which runs each hook through `sh -c` as Claude Code does; never the real
//! `claude`).
//!
//! These tests run inside whatever process tree started `cargo test` — possibly a real Claude Code
//! session, which the daemon's walk would find. So every hook that must be accepted runs under a
//! fake `claude` (the nearest one wins), and the hook that must find none is detached first
//! (`setsid -f`: its parent becomes init or the session's subreaper).

mod common;

use cc_workspace_manager::claude::hook::guarded_command;
use cc_workspace_manager::synth::{self, SynthEnv};
use common::daemon::{command, socket_call, wait_until, Daemon, BIN};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const SID: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
const SID2: &str = "2b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
const SID3: &str = "3b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
/// Text from the skipped fields of the fixtures: must reach no log, database, request or output.
const SKIPPED_CANARIES: [&str; 4] = [
    "SYNTHETIC-PROMPT-CANARY",
    "SYNTHETIC-ASSISTANT-CANARY",
    "SYNTHETIC-TOOL-CANARY",
    "SYNTHETIC-CRON-CANARY",
];

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hooks/2.1.332")
            .join(name),
    )
    .unwrap()
}

fn synth_env(t: &tempfile::TempDir) -> SynthEnv {
    synth::generate(&t.path().join("e"), 0).unwrap()
}

/// `dash` (Ubuntu's `sh`, which Claude Code runs hooks with), or a notice (a failure in CI).
fn dash() -> Option<PathBuf> {
    let found = ["/usr/bin/dash", "/bin/dash"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists());
    if found.is_none() {
        common::skipped_coverage("dash is not installed: the hook snippet is not run by dash");
    }
    found
}

/// Run `ccwm hook <event>` directly (no daemon in these tests) with `stdin` and return (status,
/// stdout, stderr, time taken).
fn run_hook(env: &SynthEnv, event: &str, stdin: &str) -> (Option<i32>, Vec<u8>, String, Duration) {
    let started = Instant::now();
    let mut child = command(env)
        .args(["hook", event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
        started.elapsed(),
    )
}

#[test]
fn without_a_daemon_the_hook_exits_0_at_once_and_prints_nothing_on_stdout() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let (status, stdout, stderr, took) = run_hook(&env, "Stop", &fixture("Stop.json"));
    assert_eq!(status, Some(0));
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("not running") && stderr.lines().count() == 1,
        "{stderr}"
    );
    assert!(took < Duration::from_millis(800), "{took:?}");
    // Every path ends the same way: a wrong argument, garbage, an event not used, no argument,
    // extra arguments, an argument that would be a usage error for clap.
    for (args, input) in [
        (&["Stop"][..], "garbage"),
        (&["SessionEnd"], fixture("Stop.json").as_str()),
        (
            &["Notification"],
            fixture("Notification-auth_success.json").as_str(),
        ),
        (&[], fixture("Stop.json").as_str()),
        (&["Stop", "--bogus", "extra"], fixture("Stop.json").as_str()),
        (&["--help"], ""),
        (
            &["PostToolUse"],
            fixture("PostToolUse-subagent.json").as_str(),
        ),
    ] {
        let mut child = command(&env)
            .arg("hook")
            .args(args)
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
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(err.lines().count() <= 1, "{args:?}: {err}");
        for c in SKIPPED_CANARIES {
            assert!(!err.contains(c), "{args:?}: {err}");
        }
    }
}

/// A stdin that never closes: the watchdog ends the hook with status 0 after 1 s. A stdin that
/// stays open *after* a complete event does not hold the hook up.
#[test]
fn a_stdin_that_never_closes_ends_the_hook_after_one_second() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let spawn = || {
        command(&env)
            .args(["hook", "Stop"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let wait = |mut child: Child| {
        let started = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "the hook hangs");
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        (status.code(), out, started.elapsed())
    };
    let mut silent = spawn();
    let keep_open = silent.stdin.take().unwrap();
    let (status, stdout, took) = wait(silent);
    drop(keep_open);
    assert_eq!(status, Some(0));
    assert!(stdout.is_empty());
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(3),
        "{took:?}"
    );

    let mut complete = spawn();
    let mut stdin = complete.stdin.take().unwrap();
    stdin.write_all(fixture("Stop.json").as_bytes()).unwrap();
    let (status, stdout, took) = wait(complete);
    drop(stdin);
    assert_eq!(status, Some(0));
    assert!(stdout.is_empty());
    assert!(
        took < Duration::from_millis(800),
        "parsing stops at the end of the event: {took:?}"
    );
}

/// A daemon socket that accepts and never answers: the socket part ends at 100 ms, the hook
/// exits 0 well before the 1 s watchdog, and what it sent holds no skipped field.
#[test]
fn a_daemon_that_never_answers_costs_the_hook_100_ms() {
    use std::os::unix::fs::DirBuilderExt;
    let t = common::tempdir();
    let env = synth_env(&t);
    let run = env.runtime_dir.join("ccwm");
    std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(run.join("ccwm.sock")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.contains(&b'\n') {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        tx.send(got).unwrap();
        std::thread::sleep(Duration::from_secs(3)); // never answers
    });
    let (status, stdout, stderr, took) =
        run_hook(&env, "UserPromptSubmit", &fixture("UserPromptSubmit.json"));
    assert_eq!(status, Some(0));
    assert!(stdout.is_empty());
    assert!(stderr.contains("within 100 ms"), "{stderr}");
    assert!(took < Duration::from_millis(700), "{took:?}");
    let sent = String::from_utf8(rx.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    let request: serde_json::Value = serde_json::from_str(&sent).unwrap();
    assert_eq!(request["op"], "hook.event");
    assert_eq!(request["event"], "UserPromptSubmit");
    for c in SKIPPED_CANARIES {
        assert!(!sent.contains(c), "{sent}");
    }
}

/// `ccwm hooks print`: the snippet on stdout and nothing else; each command, run by dash, exits
/// 0 with ccwm present, missing, or replaced by a stand-in that fails loudly, and prints nothing
/// on stdout where ccwm is real or missing.
#[test]
fn the_printed_hooks_are_safe_when_ccwm_is_present_missing_or_broken() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let out = command(&env).args(["hooks", "print"]).output().unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning: this ccwm is") && stderr.contains(".local/bin/ccwm"),
        "{stderr}"
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let bin = std::fs::canonicalize(BIN).unwrap();
    let expected = cc_workspace_manager::claude::hook::snippet(&bin).unwrap();
    assert_eq!(text, expected, "stdout is exactly the snippet");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut commands = Vec::new();
    for (event, entries) in v["hooks"].as_object().unwrap() {
        for e in entries.as_array().unwrap() {
            let cmd = e["hooks"][0]["command"].as_str().unwrap().to_string();
            assert_eq!(cmd, guarded_command(bin.to_str().unwrap(), event));
            commands.push((event.clone(), cmd));
        }
    }
    assert_eq!(commands.len(), 10);
    let Some(dash) = dash() else { return };
    let broken = env.root.join("broken-ccwm");
    common::write_executable(
        &broken,
        "#!/bin/sh\necho STDOUT-OF-A-BROKEN-CCWM\necho oops >&2\nexit 2\n",
    );
    let bin = bin.to_str().unwrap();
    for (event, cmd) in &commands {
        for (variant, command_text, stdout_empty) in [
            ("present", cmd.clone(), true),
            ("missing", cmd.replace(bin, "/nonexistent/ccwm"), true),
            ("broken", cmd.replace(bin, broken.to_str().unwrap()), false),
        ] {
            let mut c = std::process::Command::new(&dash);
            c.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args(["-c", &command_text])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (k, v) in env.env_pairs() {
                c.env(k, v);
            }
            let mut child = c.spawn().unwrap();
            let _ = child
                .stdin
                .take()
                .unwrap()
                .write_all(fixture("Stop.json").as_bytes());
            let out = child.wait_with_output().unwrap();
            assert_eq!(out.status.code(), Some(0), "{event} {variant}");
            if stdout_empty {
                assert!(out.stdout.is_empty(), "{event} {variant}: {:?}", out.stdout);
            }
            if variant == "missing" {
                assert!(
                    out.stderr.is_empty(),
                    "{event}: a missing ccwm is not called"
                );
            }
        }
    }
}

// ---- a real daemon and a fake Claude Code process tree -------------------------------------

/// The fake `claude`: `bash` with `argv[0]` = `claude`, running `fake-claude.sh <mode> <hold>
/// <n>`: `CLAUDE_PID` per `mode` (`self` = its own pid, `none`, or a given pid), then hooks
/// `0..n` (`hook-<i>.cmd` with `hook-<i>.json` on stdin) through `sh -c` as Claude Code does,
/// each exit status and stdout size appended to `results`, then it stays alive `hold` seconds.
struct FakeClaude {
    dir: PathBuf,
    script: PathBuf,
}

impl FakeClaude {
    fn new(env: &SynthEnv, name: &str) -> Self {
        let dir = env.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-claude.sh");
        common::write_executable(
            &script,
            r#"#!/bin/bash
set -u
here=$(dirname "$0")
[ "$1" = -p ] && shift
mode=$1 hold=$2 n=$3
case "$mode" in
  self) export CLAUDE_PID=$$ ;;
  none) unset CLAUDE_PID ;;
  *) export CLAUDE_PID=$mode ;;
esac
i=0
while [ "$i" -lt "$n" ]; do
  sh -c "$(cat "$here/hook-$i.cmd")" < "$here/hook-$i.json" > "$here/out-$i"
  echo "$? $(wc -c < "$here/out-$i")" >> "$here/results"
  i=$((i + 1))
done
sleep "$hold"
"#,
        );
        Self { dir, script }
    }

    /// Start it with `hooks` (event, input) and `argv` options (`-p` for a non-interactive one).
    fn start(
        &self,
        env: &SynthEnv,
        mode: &str,
        hold: u32,
        hooks: &[(&str, String)],
        options: &[&str],
    ) -> Child {
        let _ = std::fs::remove_file(self.dir.join("results"));
        for (i, (event, input)) in hooks.iter().enumerate() {
            std::fs::write(
                self.dir.join(format!("hook-{i}.cmd")),
                guarded_command(BIN, event),
            )
            .unwrap();
            std::fs::write(self.dir.join(format!("hook-{i}.json")), input).unwrap();
        }
        let mut c = std::process::Command::new("/bin/bash");
        c.arg0("claude")
            .arg(&self.script)
            .args(options)
            .args([mode, &hold.to_string(), &hooks.len().to_string()])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        for (k, v) in env.env_pairs() {
            c.env(k, v);
        }
        c.spawn().unwrap()
    }

    /// Wait until all `n` hooks ran; every one exited 0 with nothing on stdout.
    fn wait_hooks(&self, n: usize) {
        let results = self.dir.join("results");
        wait_until("the fake claude's hooks", 20, || {
            std::fs::read_to_string(&results).is_ok_and(|r| r.lines().count() == n)
        });
        let r = std::fs::read_to_string(&results).unwrap();
        assert!(
            r.lines().all(|l| l == "0 0"),
            "status and stdout size of each hook: {r}"
        );
    }
}

fn kill_group(child: &mut Child) {
    let pid = i32::try_from(child.id()).unwrap();
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    );
    let _ = child.wait();
}

fn events(env: &SynthEnv) -> serde_json::Value {
    socket_call(env, "hooks.events")
}

/// (event, detail, session, CLAUDE_PID sent, outcome) of the log entries after `skip`.
fn log(env: &SynthEnv, skip: usize) -> Vec<(String, String, String, String, String)> {
    let s = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => "-".into(),
    };
    events(env)["events"]
        .as_array()
        .unwrap()
        .iter()
        .skip(skip)
        .map(|e| {
            (
                s(&e["event"]),
                s(&e["detail"]),
                s(&e["session_id"]),
                s(&e["claude_pid_sent"]),
                s(&e["outcome"]),
            )
        })
        .collect()
}

fn entry(
    event: &str,
    detail: &str,
    sid: &str,
    sent: &str,
    outcome: &str,
) -> (String, String, String, String, String) {
    (
        event.into(),
        detail.into(),
        sid.into(),
        sent.into(),
        outcome.into(),
    )
}

fn with_session(input: &str, sid: &str) -> String {
    input.replace(SID, sid)
}

/// The whole path, both walk paths and every refusal, at process level: a fake Claude Code
/// sends a session's events through the printed hook commands; the daemon finds the fake
/// `claude` with and without `CLAUDE_PID`, refuses a wrong `CLAUDE_PID` and a hook outside any
/// Claude Code tree, marks a `-p` session non-interactive, closes a session at `SessionEnd`, and
/// closes one within a sweep after its process is killed. Every hook exits 0 with nothing on
/// stdout; no skipped field reaches the trace log, the database, the debug log or
/// `ccwm hooks events`, and the cwd reaches no log.
#[test]
fn a_fake_claude_tree_reports_through_the_printed_hooks() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let d = Daemon::start_with_env(&env, &[], &[("CCWM_LOG", "trace")]);

    // 1. With CLAUDE_PID: a whole turn, accepted.
    let fake = FakeClaude::new(&env, "fake1");
    let turn = [
        ("SessionStart", fixture("SessionStart.json")),
        ("UserPromptSubmit", fixture("UserPromptSubmit.json")),
        (
            "Notification",
            fixture("Notification-permission_prompt.json"),
        ),
        ("PostToolUse", fixture("PostToolUse.json")),
        ("PostToolUseFailure", fixture("PostToolUseFailure.json")),
        ("PostToolBatch", fixture("PostToolBatch.json")),
        ("PostToolUse", fixture("PostToolUse-subagent.json")), // not sent
        ("Notification", fixture("Notification-auth_success.json")), // not sent
        ("Stop", fixture("Stop.json")),
        ("StopFailure", fixture("StopFailure.json")),
        ("Notification", fixture("Notification-idle_prompt.json")),
    ];
    let mut first = fake.start(&env, "self", 60, &turn, &[]);
    fake.wait_hooks(turn.len());
    let mut want = vec![
        entry("SessionStart", "startup", SID, "true", "opened"),
        entry("UserPromptSubmit", "-", SID, "true", "accepted"),
        entry("Notification", "permission_prompt", SID, "true", "accepted"),
        entry("PostToolUse", "-", SID, "true", "accepted"),
        entry("PostToolUseFailure", "-", SID, "true", "accepted"),
        entry("PostToolBatch", "-", SID, "true", "accepted"),
        entry("Stop", "-", SID, "true", "accepted"),
        entry("StopFailure", "-", SID, "true", "accepted"),
        entry("Notification", "idle_prompt", SID, "true", "accepted"),
    ];
    assert_eq!(log(&env, 0), want);
    assert_eq!(events(&env)["open"], 1);

    // 2. Without CLAUDE_PID: the walk's result is used.
    let fake2 = FakeClaude::new(&env, "fake2");
    let mut second = fake2.start(
        &env,
        "none",
        60,
        &[(
            "SessionStart",
            with_session(&fixture("SessionStart.json"), SID2),
        )],
        &[],
    );
    fake2.wait_hooks(1);
    want.push(entry("SessionStart", "startup", SID2, "false", "opened"));
    assert_eq!(log(&env, 0), want);

    // 3. CLAUDE_PID naming another process (this test): refused.
    let fake3 = FakeClaude::new(&env, "fake3");
    let me = std::process::id().to_string();
    let mut third = fake3.start(
        &env,
        &me,
        0,
        &[("Stop", with_session(&fixture("Stop.json"), SID3))],
        &[],
    );
    fake3.wait_hooks(1);
    let _ = third.wait();
    want.push(entry("Stop", "-", SID3, "true", "refused: pid_mismatch"));
    assert_eq!(log(&env, 0), want);

    // 4. A hook outside any Claude Code tree (detached: its parent is init or a subreaper).
    let input = env.root.join("detached.json");
    std::fs::write(&input, with_session(&fixture("Stop.json"), SID3)).unwrap();
    let status = std::process::Command::new("setsid")
        .args(["-f", "sh", "-c", &guarded_command(BIN, "Stop")])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(env.env_pairs())
        .stdin(std::fs::File::open(&input).unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    wait_until("the detached hook's event", 10, || {
        log(&env, 0).len() == want.len() + 1
    });
    want.push(entry(
        "Stop",
        "-",
        SID3,
        "false",
        "refused: no_claude_ancestor",
    ));
    assert_eq!(log(&env, 0), want);

    // 5. A non-interactive (`-p`) session is marked.
    let fake4 = FakeClaude::new(&env, "fake4");
    let mut fourth = fake4.start(
        &env,
        "self",
        60,
        &[(
            "UserPromptSubmit",
            with_session(&fixture("UserPromptSubmit.json"), SID3),
        )],
        &["-p"],
    );
    fake4.wait_hooks(1);
    want.push(entry(
        "UserPromptSubmit",
        "-",
        SID3,
        "true",
        "opened (non-interactive)",
    ));
    assert_eq!(log(&env, 0), want);
    let v = events(&env);
    assert_eq!(
        (v["open"].as_u64(), v["open_noninteractive"].as_u64()),
        (Some(3), Some(1))
    );
    assert_eq!(
        (
            v["received"].as_u64(),
            v["refused"]["pid_mismatch"].as_u64(),
            v["refused"]["no_claude_ancestor"].as_u64()
        ),
        (Some(13), Some(1), Some(1))
    );

    // 6. SessionEnd closes; killing a fake claude closes its session within one sweep.
    let fake5 = FakeClaude::new(&env, "fake5");
    let mut fifth = fake5.start(
        &env,
        "self",
        0,
        &[(
            "SessionEnd",
            with_session(&fixture("SessionEnd.json"), SID3),
        )],
        &["-p"],
    );
    fake5.wait_hooks(1);
    let _ = fifth.wait();
    // The `-p` claude (fake4) is another process: its session is closed by the event all the
    // same (the session ended).
    want.push(entry("SessionEnd", "-", SID3, "true", "closed"));
    assert_eq!(log(&env, 0), want);
    kill_group(&mut second);
    let killed = Instant::now();
    wait_until("the sweep", 12, || events(&env)["open"] == 1);
    assert!(
        killed.elapsed() < Duration::from_secs(11),
        "within a sweep: {:?}",
        killed.elapsed()
    );
    want.push(entry("-", "-", SID2, "-", "closed: process gone"));
    assert_eq!(log(&env, 0), want);

    // `ccwm hooks events` shows it all, with the session ids and nothing else from the events.
    let out = command(&env).args(["hooks", "events"]).output().unwrap();
    assert!(out.status.success());
    let shown = String::from_utf8(out.stdout).unwrap();
    assert!(
        shown.contains("Open sessions: 1 (0 non-interactive)"),
        "{shown}"
    );
    assert!(
        shown.contains("refused: 1 no_claude_ancestor, 1 pid_mismatch"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("{SID2}  -           closed: process gone")),
        "{shown}"
    );
    assert!(shown.contains("permission_prompt"), "{shown}");

    kill_group(&mut first);
    kill_group(&mut fourth);
    let (code, log_text) = d.stop();
    assert_eq!(code, Some(0), "{log_text}");
    assert!(
        log_text.contains("hook event"),
        "trace logging is on: {log_text}"
    );
    let mut stores = vec![
        ("trace log", log_text.into_bytes()),
        ("ccwm hooks events", shown.into_bytes()),
    ];
    for name in ["ccwm.db", "ccwm.db-wal", "ccwm.db-shm"] {
        if let Ok(bytes) = std::fs::read(env.data_home.join("ccwm").join(name)) {
            stores.push((name, bytes));
        }
    }
    for (what, bytes) in &stores {
        let text = String::from_utf8_lossy(bytes);
        for c in SKIPPED_CANARIES.iter().chain(&[
            "SYNTHETIC-TRANSCRIPT-CANARY",
            "SYNTHETIC-TITLE-CANARY",
            "sk-ant-",
        ]) {
            assert!(!text.contains(c), "{c} in the {what}");
        }
    }
    // The cwd is stored with an open session (by design), but never logged.
    assert!(!String::from_utf8_lossy(&stores[0].1).contains("/home/synthetic/dev/alpha"));
}

/// A daemon restart restores a session whose process still runs (and drops one whose process
/// ended meanwhile); "Clear session index" forgets them (O16). The process killed after the
/// restart is closed by the sweep.
#[test]
fn a_restart_restores_open_sessions_whose_process_still_runs() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let d = Daemon::start(&env, &[]);
    let alive = FakeClaude::new(&env, "alive");
    let mut keeps = alive.start(
        &env,
        "self",
        120,
        &[("SessionStart", fixture("SessionStart.json"))],
        &[],
    );
    alive.wait_hooks(1);
    let ends = FakeClaude::new(&env, "ends");
    let mut ended = ends.start(
        &env,
        "none",
        120,
        &[("Stop", with_session(&fixture("Stop.json"), SID2))],
        &[],
    );
    ends.wait_hooks(1);
    assert_eq!(events(&env)["open"], 2);
    assert_eq!(d.stop().0, Some(0));
    kill_group(&mut ended);

    let d = Daemon::start(&env, &[]);
    let v = events(&env);
    assert_eq!(
        (v["open"].as_u64(), v["received"].as_u64()),
        (Some(1), Some(0)),
        "{v}"
    );
    let mut outcomes: Vec<(String, String)> =
        log(&env, 0).into_iter().map(|e| (e.2, e.4)).collect();
    outcomes.sort();
    assert_eq!(
        outcomes,
        [
            (SID.to_string(), "restored".to_string()),
            (
                SID2.to_string(),
                "dropped at start: process gone".to_string()
            )
        ]
    );
    kill_group(&mut keeps);
    wait_until("the sweep", 12, || events(&env)["open"] == 0);
    assert_eq!(
        log(&env, 2),
        [entry("-", "-", SID, "-", "closed: process gone")]
    );
    assert_eq!(d.stop().0, Some(0));

    // Persisted again, then "Clear session index" forgets it (memory and database).
    let d = Daemon::start(&env, &[]);
    let mut again = alive.start(
        &env,
        "self",
        120,
        &[("SessionStart", fixture("SessionStart.json"))],
        &[],
    );
    alive.wait_hooks(1);
    assert_eq!(events(&env)["open"], 1);
    let token = d.login(&env);
    let origin = d.origin();
    let (status, _, body) = d.http(
        "POST",
        "/api/v1/session-index/clear",
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Origin", &origin),
            ("Content-Type", "application/json"),
        ],
        "{}",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(events(&env)["open"], 0);
    assert_eq!(d.stop().0, Some(0));
    let d = Daemon::start(&env, &[]);
    assert_eq!(events(&env)["open"], 0, "nothing left to restore");
    kill_group(&mut again);
    assert_eq!(d.stop().0, Some(0));
}
