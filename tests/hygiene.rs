//! Security acceptance test 9: runtime data and credentials cannot be committed by accident, while
//! reviewed synthetic fixtures and authored files can.

use cc_workspace_manager::paths;
use std::path::Path;
use std::process::Command;

const REPO: &str = env!("CARGO_MANIFEST_DIR");

/// Without git the check cannot run: a notice locally, a failure in CI (`CI` is set by GitHub
/// Actions and most CI systems), so the hygiene gate can never be skipped silently there.
fn git_available() -> bool {
    let ok = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(
            std::env::var_os("CI").is_none(),
            "git is required for the hygiene checks in CI"
        );
        eprintln!("NOTICE: git is not installed; skipping the .gitignore hygiene check");
    }
    ok
}

/// Every file name ccwm creates at runtime, taken from the constants it actually uses.
fn runtime_names() -> Vec<&'static str> {
    vec![
        paths::DB_NAME,
        paths::DB_WAL_NAME,
        paths::DB_SHM_NAME,
        paths::SOCKET_NAME,
        paths::LOCK_NAME,
        paths::INSTANCE_NAME,
        paths::INSTANCE_TMP_NAME,
        paths::CONFIG_NAME,
        paths::CONFIG_TMP_NAME,
    ]
}

fn is_ignored(path: &str) -> bool {
    Command::new("git")
        .args(["check-ignore", "--quiet", "--no-index", "--", path])
        .current_dir(Path::new(REPO))
        .status()
        .expect("git check-ignore")
        .code()
        == Some(0)
}

#[test]
fn every_runtime_file_name_is_ignored_wherever_it_appears() {
    if !git_available() {
        return;
    }
    assert_eq!(paths::DB_WAL_NAME, format!("{}-wal", paths::DB_NAME));
    assert_eq!(paths::DB_SHM_NAME, format!("{}-shm", paths::DB_NAME));
    let mut visible = Vec::new();
    for name in runtime_names() {
        // `config.toml` is a common name (`.cargo/config.toml` must stay committable): it (and
        // its staged `.tmp`) is ignored at the root and inside any `ccwm/` directory, where ccwm
        // keeps it.
        let dirs: &[&str] = if name == paths::CONFIG_NAME || name == paths::CONFIG_TMP_NAME {
            &["", "ccwm/", ".config/ccwm/", "x/ccwm/"]
        } else {
            &["", "data/ccwm/", "x/y/", ".config/ccwm/", "run/ccwm/"]
        };
        for dir in dirs {
            let p = format!("{dir}{name}");
            if !is_ignored(&p) {
                visible.push(p);
            }
        }
    }
    assert!(visible.is_empty(), "runtime files not ignored: {visible:?}");
}

/// A synthetic environment generated *inside* the repository leaves nothing for Git to pick up.
#[test]
fn a_synthetic_environment_created_inside_the_repository_is_ignored() {
    if !git_available() {
        return;
    }
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Path::new(REPO).join(format!("hygiene-synth-{}", std::process::id()));
    let _cleanup = Cleanup(dir.clone());
    let env = cc_workspace_manager::synth::generate(&dir, 2).unwrap();
    std::fs::write(dir.join("env"), "HOME=x\n").unwrap(); // what ccwm-synth writes
    std::fs::write(env.home.join("dev/alpha/notes.txt"), "x").unwrap();
    let out = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard", "--"])
        .arg(&dir)
        .current_dir(REPO)
        .output()
        .unwrap();
    assert!(out.status.success());
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(listed.trim().is_empty(), "visible to git:\n{listed}");
}

#[test]
fn runtime_data_credentials_and_session_records_are_ignored() {
    if !git_available() {
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
        "instance.json.tmp",
        "ccwm-synth-0001/env",
        "ccwm-synth-0001/home/dev/alpha/CLAUDE.md",
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
        ".cargo/config.toml",
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
    if !git_available() || !Path::new(REPO).join(".git").exists() {
        eprintln!("NOTICE: not a git checkout; skipping the tracked-files check");
        return;
    }
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(REPO)
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
