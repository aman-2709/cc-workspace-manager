//! Verification of the `claude` command line (REQUIREMENTS.md §8): locate `claude` on `PATH`, run
//! `claude --version` and `claude --help` (5 s each) and check that `--resume` is offered. The
//! result is cached by binary path, size and mtime and recomputed only when the binary changed;
//! it never runs per request. The children are built with [`crate::sandbox::child_command`] and
//! inherit the daemon's Landlock sandbox (no TCP connect, read-only outside ccwm's directories).

use crate::git::run::{run, RunError};
use serde::Serialize;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_VERSION_CHARS: usize = 100;
/// Best-effort requests to Claude Code not to update itself or send anything while it only
/// prints its version and help (any TCP connect is denied by the sandbox anyway).
const QUIET_ENV: [(&str, &str); 4] = [
    ("DISABLE_AUTOUPDATER", "1"),
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("DISABLE_TELEMETRY", "1"),
    ("NO_COLOR", "1"),
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CliState {
    /// `--version` and `--help` ran and `--help` lists `--resume`.
    Verified,
    /// No executable `claude` on `PATH`.
    NotFound,
    /// It could not be run (e.g. outside the sandbox's read set) or failed.
    Failed,
    TimedOut,
    /// It ran, but `--help` does not mention `--resume`.
    NoResume,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CliCheck {
    pub state: CliState,
    pub program: Option<String>,
    /// First line of `claude --version`, shortened.
    pub version: Option<String>,
    pub resume_supported: Option<bool>,
}

impl CliCheck {
    pub fn verified(&self) -> bool {
        self.state == CliState::Verified
    }
}

/// Runs the check when the located binary changed; otherwise returns the cached result.
pub struct Verifier {
    path_env: Option<OsString>,
    cache: Mutex<Option<(Key, CliCheck)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    program: PathBuf,
    size: u64,
    mtime_ns: i64,
}

impl Verifier {
    /// `path_env`: the daemon's `PATH` (captured at startup).
    pub fn new(path_env: Option<OsString>) -> Self {
        Self {
            path_env,
            cache: Mutex::new(None),
        }
    }

    /// The cached result, if any (never runs anything).
    pub fn cached(&self) -> Option<CliCheck> {
        self.cache.lock().ok()?.as_ref().map(|(_, c)| c.clone())
    }

    /// Re-check if `claude` appeared, disappeared or changed (blocking: call on a blocking thread).
    pub fn refresh(&self) -> CliCheck {
        let program = crate::paths::find_executable("claude", self.path_env.as_deref());
        let key = program.as_ref().and_then(|p| {
            let md = std::fs::metadata(p).ok()?;
            Some(Key {
                program: p.clone(),
                size: md.len(),
                mtime_ns: md.mtime().saturating_mul(1_000_000_000) + md.mtime_nsec(),
            })
        });
        if let Ok(g) = self.cache.lock() {
            if let Some((k, c)) = g.as_ref() {
                if key.as_ref() == Some(k) || (key.is_none() && c.state == CliState::NotFound) {
                    return c.clone();
                }
            }
        }
        let check = match &key {
            None => CliCheck {
                state: CliState::NotFound,
                program: None,
                version: None,
                resume_supported: None,
            },
            Some(k) => verify(&k.program),
        };
        tracing::info!(state = ?check.state, version = check.version.as_deref().unwrap_or("unknown"), "claude command line checked");
        if let Ok(mut g) = self.cache.lock() {
            *g = Some((
                key.unwrap_or(Key {
                    program: PathBuf::new(),
                    size: 0,
                    mtime_ns: 0,
                }),
                check.clone(),
            ));
        }
        check
    }
}

fn invoke(program: &PathBuf, arg: &str) -> Result<String, CliState> {
    let mut cmd = crate::sandbox::child_command(program);
    cmd.arg(arg).envs(QUIET_ENV).current_dir("/");
    match run(cmd, TIMEOUT, MAX_OUTPUT) {
        Ok(o) if o.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(_) | Err(RunError::Spawn(_) | RunError::TooLarge) => Err(CliState::Failed),
        Err(RunError::Timeout) => Err(CliState::TimedOut),
    }
}

/// Run `--version` and `--help` once.
pub fn verify(program: &PathBuf) -> CliCheck {
    let mut check = CliCheck {
        state: CliState::Failed,
        program: Some(program.display().to_string()),
        version: None,
        resume_supported: None,
    };
    match invoke(program, "--version") {
        Ok(out) => {
            check.version = out
                .lines()
                .next()
                .map(|l| l.trim().chars().take(MAX_VERSION_CHARS).collect())
                .filter(|v: &String| !v.is_empty());
        }
        Err(state) => {
            check.state = state;
            return check;
        }
    }
    match invoke(program, "--help") {
        Ok(help) => {
            let resume = help.contains("--resume");
            check.resume_supported = Some(resume);
            check.state = if resume {
                CliState::Verified
            } else {
                CliState::NoResume
            };
        }
        Err(state) => check.state = state,
    }
    check
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake(dir: &std::path::Path, body: &str) {
        let p = dir.join("claude");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn verifies_version_and_resume_support_and_caches_by_binary() {
        let t = tempfile::tempdir().unwrap();
        let count = t.path().join("count");
        fake(
            t.path(),
            &format!(
                r#"printf x >> '{}'
case "$1" in --version) printf '9.9.9 (Claude Code)\n' ;; --help) printf '  -r, --resume [id]  Resume\n' ;; esac"#,
                count.display()
            ),
        );
        let v = Verifier::new(Some(t.path().as_os_str().to_owned()));
        let c = v.refresh();
        assert_eq!(c.state, CliState::Verified);
        assert_eq!(c.version.as_deref(), Some("9.9.9 (Claude Code)"));
        assert_eq!(c.resume_supported, Some(true));
        assert_eq!(v.refresh(), c, "cached");
        assert_eq!(
            std::fs::read_to_string(&count).unwrap(),
            "xx",
            "run once, not per call"
        );
        assert_eq!(v.cached(), Some(c));
    }

    #[test]
    fn missing_failing_slow_and_resume_less_binaries_are_reported() {
        let none = tempfile::tempdir().unwrap();
        assert_eq!(
            Verifier::new(Some(none.path().as_os_str().to_owned()))
                .refresh()
                .state,
            CliState::NotFound
        );
        assert_eq!(Verifier::new(None).refresh().state, CliState::NotFound);
        let t = tempfile::tempdir().unwrap();
        fake(t.path(), "exit 3");
        assert_eq!(verify(&t.path().join("claude")).state, CliState::Failed);
        fake(t.path(), "printf 'help without the flag\\n'");
        let c = verify(&t.path().join("claude"));
        assert_eq!(
            (c.state, c.resume_supported),
            (CliState::NoResume, Some(false))
        );
        fake(t.path(), "exec sleep 30");
        let started = std::time::Instant::now();
        assert_eq!(verify(&t.path().join("claude")).state, CliState::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
