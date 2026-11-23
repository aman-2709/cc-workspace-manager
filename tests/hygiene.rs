//! Security acceptance test 9: runtime data and credentials cannot be committed by accident, while
//! reviewed synthetic fixtures and authored files can.

use std::path::Path;
use std::process::Command;

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn is_ignored(path: &str) -> bool {
    Command::new("git")
        .args(["check-ignore", "--quiet", "--no-index", "--", path])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
        .status()
        .expect("git check-ignore")
        .code()
        == Some(0)
}

#[test]
fn runtime_data_credentials_and_session_records_are_ignored() {
    if !git_available() {
        eprintln!("NOTICE: git is not installed; skipping the .gitignore hygiene check");
        return;
    }
    let must_be_ignored = [
        "ccwm.db",
        "data/ccwm.db",
        "ccwm.db-wal",
        "ccwm.db-shm",
        "x.sqlite",
        "x.sqlite3",
        "ccwm.db-journal",
        "some-journal",
        "ccwm.sock",
        "ccwm.lock",
        "instance.json",
        "cli.token",
        "state/cli.token",
        "session.token",
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "id_ed25519.pub",
        "server.pem",
        "server.key",
        "credentials.json",
        ".credentials.json",
        "secrets.toml",
        "config.toml",
        "config.local.toml",
        "ccwm.local.toml",
        ".claude/settings.local.json",
        "session.jsonl",
        "any/where/session.jsonl",
        "projects/-home-u-dev/11111111-2222-4333-8444-555555555555.jsonl",
        ".claude/projects/x/y.jsonl",
        "history.jsonl",
        "tests/session.jsonl",
        "tests/fixtures-not/session.jsonl",
        "target/debug/ccwm",
        "run.log",
        "logs/ccwm.log",
        "excalidraw.log",
        "bench-results/2026-01-01.json",
        "perf.data",
        "flamegraph.svg",
        "dist/ccwm.tar.gz",
        "ccwm-0.1.0-x86_64-unknown-linux-musl.tar.gz",
        "SHA256SUMS",
        ".idea/workspace.xml",
        ".vscode/settings.json",
        "x.swp",
        ".DS_Store",
        "synthetic-env/home/dev/CLAUDE.md",
    ];
    let must_be_tracked = [
        "Cargo.toml",
        "Cargo.lock",
        "config.example.toml",
        "deny.toml",
        ".gitignore",
        "REQUIREMENTS.md",
        "ARCHITECTURE.md",
        "src/main.rs",
        "web/app.js",
        "scripts/inspect-session-schema.py",
        "tests/fixtures/sessions/2.1.331/basic.jsonl",
        "tests/fixtures/sessions/2.1.331/nested/deep.jsonl",
        "tests/fixtures/README.md",
        "tests/ui/app.test.js",
    ];
    let wrongly_visible: Vec<_> = must_be_ignored.iter().filter(|p| !is_ignored(p)).collect();
    assert!(
        wrongly_visible.is_empty(),
        "these must be git-ignored but are not: {wrongly_visible:?}"
    );
    let wrongly_ignored: Vec<_> = must_be_tracked.iter().filter(|p| is_ignored(p)).collect();
    assert!(
        wrongly_ignored.is_empty(),
        "these must NOT be ignored: {wrongly_ignored:?}"
    );
}

#[test]
fn nothing_sensitive_is_tracked_or_staged() {
    if !git_available() || !Path::new(env!("CARGO_MANIFEST_DIR")).join(".git").exists() {
        eprintln!("NOTICE: not a git checkout; skipping the tracked-files check");
        return;
    }
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    let files = String::from_utf8_lossy(&out.stdout).into_owned();
    for f in files.split('\0').filter(|f| !f.is_empty()) {
        let lower = f.to_ascii_lowercase();
        let bad = lower.ends_with(".db")
            || lower.ends_with(".sqlite")
            || lower.ends_with(".sock")
            || lower.ends_with(".token")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.contains(".env")
            || (lower.ends_with(".jsonl") && !lower.starts_with("tests/fixtures/"));
        assert!(!bad, "{f} must not be tracked");
    }
}
