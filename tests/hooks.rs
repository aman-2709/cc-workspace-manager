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
use common::daemon::{command, socket_call, wait_until, wrapped_command, Daemon, BIN};
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

/// v0.2 review L5: `ccwm hook` makes no NSS lookup (REQUIREMENTS.md §21.3) — with a private
/// runtime directory and a `$HOME` that qualifies it opens neither `/etc/passwd` nor `/etc/group`
/// nor `nsswitch.conf`, and asks no nscd or sssd, from start to the daemon's answer (a stand-in
/// listener here). The control: a group-writable runtime ancestor needs the private-group lookup,
/// and the same trace sees it.
#[test]
fn the_hook_makes_no_user_or_group_database_lookup() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let t = common::tempdir();
    let env = synth_env(&t);
    let probe = std::process::Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=openat", "-o", "/dev/null", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        common::skipped_coverage(
            "strace is not usable here: the NSS check of `ccwm hook` is skipped",
        );
        return;
    }
    let run = env.runtime_dir.join("ccwm");
    std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(run.join("ccwm.sock")).unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { return };
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !got.contains(&b'\n') {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(b"{\"ok\":{\"accepted\":true}}\n");
        }
    });
    let traced = |name: &str| -> (String, String) {
        let log = t.path().join(format!("{name}.strace"));
        let strace = [
            "strace",
            "-f",
            "-qq",
            "-s",
            "256",
            "-e",
            "trace=open,openat,connect",
            "-o",
            log.to_str().unwrap(),
        ]
        .map(String::from);
        let mut child = wrapped_command(&env, &strace)
            .args(["hook", "Stop"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(fixture("Stop.json").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stdout.is_empty());
        (
            std::fs::read_to_string(&log).unwrap(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    const NSS: [&str; 5] = [
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "nscd",
        "/var/lib/sss",
    ];
    let (trace, stderr) = traced("private");
    assert!(stderr.is_empty(), "the event was accepted: {stderr}");
    assert!(
        trace.contains("ccwm.sock"),
        "the trace saw the socket: {trace}"
    );
    for f in NSS {
        assert!(!trace.contains(f), "{f} in\n{trace}");
    }
    // Control: a group-writable ancestor of the runtime directory needs the private group.
    std::fs::set_permissions(&env.runtime_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let (trace, _) = traced("group-writable");
    assert!(
        NSS[..3].iter().any(|f| trace.contains(f)),
        "the lookup is visible to the trace:\n{trace}"
    );
}

/// `ccwm hooks print`: the snippet on stdout and nothing else; each command, run by dash, exits
/// 0 with ccwm present, missing, or replaced by a stand-in that fails loudly, and prints nothing
/// on stdout in every case (the stand-in's stdout is discarded, its stderr stays visible).
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
        for (variant, command_text) in [
            ("present", cmd.clone()),
            ("missing", cmd.replace(bin, "/nonexistent/ccwm")),
            ("broken", cmd.replace(bin, broken.to_str().unwrap())),
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
            assert!(out.stdout.is_empty(), "{event} {variant}: {:?}", out.stdout);
            if variant == "broken" {
                assert_eq!(out.stderr, b"oops\n", "{event}: its stderr stays visible");
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

/// v0.2 review I7: `ccwm hooks events --follow` waits for a restarted daemon and says so,
/// instead of ending with an error at the first poll that finds no daemon.
#[test]
fn hooks_events_follow_waits_for_a_restarted_daemon() {
    let t = common::tempdir();
    let env = synth_env(&t);
    let first = Daemon::start(&env, &[]);
    let mut follow = command(&env)
        .args(["hooks", "events", "--follow"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    for pipe in [
        Box::new(follow.stdout.take().unwrap()) as Box<dyn Read + Send>,
        Box::new(follow.stderr.take().unwrap()),
    ] {
        let out = std::sync::Arc::clone(&out);
        std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
    }
    let shown = |what: &str| out.lock().unwrap().contains(what);
    wait_until("the follow header", 10, || shown("Hook events since"));
    // Timestamps are whole seconds: the next daemon must start in a later second.
    std::thread::sleep(Duration::from_millis(1100));
    drop(first);
    wait_until("the wait notice", 10, || shown("not reachable; waiting"));
    let _second = Daemon::start(&env, &[]);
    wait_until("the restart notice", 10, || {
        shown("-- the daemon restarted")
    });
    assert!(
        matches!(follow.try_wait(), Ok(None)),
        "--follow still runs:\n{}",
        out.lock().unwrap()
    );
    let _ = follow.kill();
    let _ = follow.wait();
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
        entry("SessionStart", "startup", SID, "true", "opened: waiting"),
        entry("UserPromptSubmit", "-", SID, "true", "→ working"),
        entry(
            "Notification",
            "permission_prompt",
            SID,
            "true",
            "→ needs_approval",
        ),
        entry("PostToolUse", "-", SID, "true", "→ working"),
        entry("PostToolUseFailure", "-", SID, "true", "unchanged: working"),
        entry("PostToolBatch", "-", SID, "true", "unchanged: working"),
        entry("Stop", "-", SID, "true", "→ waiting"),
        entry("StopFailure", "-", SID, "true", "unchanged: waiting"),
        entry(
            "Notification",
            "idle_prompt",
            SID,
            "true",
            "unchanged: waiting",
        ),
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
    want.push(entry(
        "SessionStart",
        "startup",
        SID2,
        "false",
        "opened: waiting",
    ));
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
        "opened: working (non-interactive)",
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

    // 6. SessionEnd from another process than the session's is ignored (v0.2 review L1);
    // killing a fake claude closes its session within one sweep.
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
    // The session is the `-p` claude's (fake4), which still runs: the event of another process
    // (the same session resumed elsewhere, then left) does not close it there.
    want.push(entry(
        "SessionEnd",
        "-",
        SID3,
        "true",
        "ignored (another process)",
    ));
    assert_eq!(log(&env, 0), want);
    assert_eq!(events(&env)["open"], 3);
    kill_group(&mut second);
    let killed = Instant::now();
    wait_until("the sweep", 12, || events(&env)["open"] == 2);
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
        shown.contains("Open sessions: 2 (1 non-interactive)"),
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
            (SID.to_string(), "restored: unknown".to_string()),
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

// ---- stop 2: states, projects, recorded facts, the toggle --------------------------------------

/// A fake `claude` (`bash` with `argv[0]` `claude`, `CLAUDE_PID=$$`) that runs one hook per line
/// written to its control FIFO (`<event> <input file>`), through the printed guarded command, and
/// stays alive until `exit` or it is killed. One process for a whole session, as Claude Code.
struct StepClaude {
    dir: PathBuf,
    child: Child,
    done: usize,
}

impl StepClaude {
    fn start(env: &SynthEnv, name: &str, options: &[&str]) -> Self {
        let dir = env.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("step-claude.sh");
        common::write_executable(
            &script,
            r#"#!/bin/bash
set -u
here=$(dirname "$0")
export CLAUDE_PID=$$
n=0
while read -r event input < "$here/ctl"; do
  [ "$event" = exit ] && break
  cmd=$(cat "$here/cmd-$event")
  sh -c "$cmd" < "$input" > "$here/out-$n"
  echo "$? $(wc -c < "$here/out-$n")" >> "$here/results"
  n=$((n + 1))
done
"#,
        );
        let ctl = dir.join("ctl");
        nix::unistd::mkfifo(&ctl, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        for event in cc_workspace_manager::claude::hook::EVENT_NAMES {
            std::fs::write(
                dir.join(format!("cmd-{event}")),
                guarded_command(BIN, event),
            )
            .unwrap();
        }
        let mut c = std::process::Command::new("/bin/bash");
        c.arg0("claude")
            .arg(&script)
            .args(options)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .envs(env.env_pairs())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = c.spawn().unwrap();
        Self {
            dir,
            child,
            done: 0,
        }
    }

    /// Run one hook with `input` and wait until it exited (0, nothing on stdout).
    fn step(&mut self, event: &str, input: &str) {
        let file = self.dir.join(format!("in-{}", self.done));
        std::fs::write(&file, input).unwrap();
        std::fs::write(
            self.dir.join("ctl"),
            format!("{event} {}\n", file.display()),
        )
        .unwrap();
        self.done += 1;
        let results = self.dir.join("results");
        let n = self.done;
        wait_until("the hook", 10, || {
            std::fs::read_to_string(&results).is_ok_and(|r| r.lines().count() == n)
        });
        let last = std::fs::read_to_string(&results)
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_string();
        assert_eq!(last, "0 0", "{event}: status and stdout size");
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for StepClaude {
    fn drop(&mut self) {
        kill_group(&mut self.child);
    }
}

const P2: &str = "7a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c62";

/// The hook input of `file` for session `sid`, in the project at `cwd`, with `prompt` as its
/// prompt id (where it has one).
fn input(file: &str, sid: &str, cwd: &Path, prompt: &str) -> String {
    fixture(file)
        .replace(SID, sid)
        .replace("/home/synthetic/dev/alpha", cwd.to_str().unwrap())
        .replace("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", prompt)
}

fn project<'a>(page: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name} in {page}"))
}

fn live_state(d: &Daemon, token: &str, name: &str) -> Option<String> {
    let page = d.get_json(token, "/api/v1/projects?limit=200");
    project(&page, name)["live"]["state"]
        .as_str()
        .map(str::to_string)
}

fn wait_live(d: &Daemon, token: &str, name: &str, want: Option<&str>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let got = live_state(d, token, name);
        if got.as_deref() == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name}: live {got:?}, want {want:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// REQUIREMENTS.md §21.6–§21.8 at process level: a fake Claude Code session in a synthetic
/// project goes through every state; the daemon resolves the session's project from its cwd,
/// publishes each change over the WebSocket, learns an interruption that no hook reports from
/// the session file (§21.2a), shows the state in the session list, and closes the session when
/// its process is killed.
#[test]
fn a_session_goes_through_every_state_in_the_api_and_the_websocket() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let d = Daemon::start(&env, &[]);
    let token = d.login(&env);
    d.wait_scan_done(&token);
    let alpha = env.home.join("dev/alpha");
    let page = d.get_json(&token, "/api/v1/projects?limit=200");
    let alpha_id = project(&page, "alpha")["id"].as_str().unwrap().to_string();
    assert_eq!(project(&page, "alpha")["live"], serde_json::Value::Null);

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", d.port).parse().unwrap();
    let mut ws = common::WsClient::connect(addr, d.port, Some(&d.origin())).unwrap();
    ws.send_text(&format!(r#"{{"type":"auth","token":"{token}"}}"#));
    assert_eq!(ws.recv_json(Duration::from_secs(5))["type"], "ready");

    let sid = "4b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    let mut claude = StepClaude::start(&env, "step1", &[]);
    claude.step("SessionStart", &input("SessionStart.json", sid, &alpha, P2));
    // The project comes from the session's cwd; the change is published live.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "no live update for alpha");
        if let Some(common::Frame::Text(text)) = ws.recv(Duration::from_secs(1)) {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            if v["type"] == "project"
                && v["project"]["id"] == alpha_id.as_str()
                && v["project"]["live"]["state"] == "waiting"
            {
                assert_eq!(v["project"]["live"]["sessions"], 1);
                break;
            }
        }
    }
    claude.step(
        "UserPromptSubmit",
        &input("UserPromptSubmit.json", sid, &alpha, P2),
    );
    wait_live(&d, &token, "alpha", Some("working"));
    claude.step(
        "Notification",
        &input("Notification-permission_prompt.json", sid, &alpha, P2),
    );
    wait_live(&d, &token, "alpha", Some("needs_approval"));
    let page = d.get_json(&token, "/api/v1/projects?limit=200&live=waiting");
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "Waiting for me");
    assert!(project(&page, "alpha")["live"]["needs_approval_since"].is_i64());
    claude.step("PostToolUse", &input("PostToolUse.json", sid, &alpha, P2));
    wait_live(&d, &token, "alpha", Some("working"));
    claude.step("Stop", &input("Stop.json", sid, &alpha, P2));
    wait_live(&d, &token, "alpha", Some("waiting"));

    // A new prompt, then "No" in a permission dialog: no hook says so, the session file does.
    let p3 = "8a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c63";
    claude.step(
        "UserPromptSubmit",
        &input("UserPromptSubmit.json", sid, &alpha, p3),
    );
    claude.step(
        "Notification",
        &input("Notification-permission_prompt.json", sid, &alpha, p3),
    );
    wait_live(&d, &token, "alpha", Some("needs_approval"));
    let sessions = env.claude_dir.join("projects/-synthetic-dev-alpha-o11");
    std::fs::create_dir_all(&sessions).unwrap();
    let now = jiff::Timestamp::now();
    let ts = |s: i64| (now + jiff::SignedDuration::from_secs(s)).to_string();
    let rec = |v: serde_json::Value| format!("{v}\n");
    let file = [
        rec(serde_json::json!({"type": "user", "sessionId": sid, "timestamp": ts(-5), "cwd": alpha, "promptId": p3, "promptSource": "typed",
            "message": {"role": "user", "content": "SYNTHETIC-PROMPT-CANARY"}})),
        rec(serde_json::json!({"type": "assistant", "sessionId": sid, "timestamp": ts(-4), "cwd": alpha,
            "message": {"role": "assistant", "stop_reason": "tool_use", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "SYNTHETIC-TOOL-CANARY"}}]}})),
        rec(serde_json::json!({"type": "user", "sessionId": sid, "timestamp": ts(-1), "cwd": alpha, "promptId": p3,
            "toolUseResult": "User rejected tool use", "toolDenialKind": "user-rejected", "toolDenialBeforeRun": true,
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "is_error": true, "content": "SYNTHETIC-TOOL-CANARY"}]}})),
        rec(serde_json::json!({"type": "user", "sessionId": sid, "timestamp": ts(0), "cwd": alpha, "promptId": p3, "rowSource": "harness",
            "message": {"role": "user", "content": [{"type": "text", "text": "[Request interrupted by user for tool use]"}]}})),
    ]
    .concat();
    std::fs::write(sessions.join(format!("{sid}.jsonl")), file).unwrap();
    wait_live(&d, &token, "alpha", Some("waiting"));
    let log = events(&env)["events"].to_string();
    assert!(
        log.contains("interrupted (session file): → waiting"),
        "{log}"
    );
    // The session file made the session indexed: the session list shows its state.
    let list = d.get_json(
        &token,
        &format!("/api/v1/projects/{alpha_id}/sessions?limit=1"),
    );
    assert_eq!(list["items"][0]["id"], sid);
    assert_eq!(list["items"][0]["live"]["state"], "waiting", "{list}");

    // The process ends without SessionEnd: closed within one sweep.
    let pid = claude.pid();
    drop(claude);
    assert!(nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
        None
    )
    .is_err());
    wait_live(&d, &token, "alpha", None);
    let list = d.get_json(
        &token,
        &format!("/api/v1/projects/{alpha_id}/sessions?limit=1"),
    );
    assert_eq!(list["items"][0]["live"], serde_json::Value::Null);
    let (code, log) = d.stop();
    assert_eq!(code, Some(0), "{log}");
    assert!(!log.contains("SYNTHETIC-PROMPT-CANARY") && !log.contains("SYNTHETIC-TOOL-CANARY"));
}

/// A restart shows an open session as "unknown" (never guessed) in its project at once; a `-p`
/// session is hidden until the Settings toggle is on, which applies without a restart.
#[test]
fn a_restart_shows_unknown_and_non_interactive_sessions_wait_for_the_toggle() {
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let d = Daemon::start(&env, &[]);
    let token = d.login(&env);
    d.wait_scan_done(&token);
    let (alpha, beta) = (env.home.join("dev/alpha"), env.home.join("dev/beta"));
    let mut interactive = StepClaude::start(&env, "i", &[]);
    interactive.step(
        "UserPromptSubmit",
        &input("UserPromptSubmit.json", SID, &alpha, P2),
    );
    wait_live(&d, &token, "alpha", Some("working"));
    let mut print = StepClaude::start(&env, "p", &["-p"]);
    print.step(
        "UserPromptSubmit",
        &input("UserPromptSubmit.json", SID2, &beta, P2),
    );
    // Hidden: in no aggregate, count or filter; counted in the status.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(live_state(&d, &token, "beta"), None);
    let stats = d.get_json(&token, "/api/v1/stats");
    assert_eq!(stats["live"]["open"], 1);
    let hooks = &d.get_json(&token, "/api/v1/service/status")["hooks"];
    assert_eq!(hooks["hidden_noninteractive"], 1);
    let origin = d.origin();
    let put = |on: bool| {
        let (s, _, b) = d.http(
            "PUT",
            "/api/v1/settings",
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("Origin", &origin),
                ("Content-Type", "application/json"),
            ],
            &format!(r#"{{"indicator":{{"show_noninteractive":{on}}}}}"#),
        );
        assert_eq!(s, 200, "{b}");
    };
    put(true);
    wait_live(&d, &token, "beta", Some("working"));
    put(false);
    wait_live(&d, &token, "beta", None);

    // A restart: the sessions whose process still runs are back, state unknown, in their
    // projects without waiting for a scan.
    assert_eq!(d.stop().0, Some(0));
    let d = Daemon::start(&env, &[]);
    let token = d.login(&env);
    wait_live(&d, &token, "alpha", Some("unknown"));
    assert_eq!(live_state(&d, &token, "beta"), None, "still hidden");
    // The next event tells the state again.
    interactive.step("Stop", &input("Stop.json", SID, &alpha, P2));
    wait_live(&d, &token, "alpha", Some("waiting"));
    drop(print);
    drop(interactive);
    wait_live(&d, &token, "alpha", None);
    assert_eq!(d.stop().0, Some(0));
}
