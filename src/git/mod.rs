//! The only module that runs `git` (REQUIREMENTS.md §6).
//!
//! Allowlisted invocations only (`--version`, `rev-parse`, `config --get-regexp` for filter drivers,
//! `status --porcelain=v2`, `log -1` with a fixed format, `config --get`), each with the hardening
//! flags, an empty environment plus the six §6 variables, no shell, a 5 s timeout that kills the
//! process group, and bounded output. Every `status` passes `--attr-source=<empty tree>` and nulls
//! every filter driver Git reports in any scope; a driver name that `-c` cannot express safely
//! disables status for that repository (fail closed). These flags are mitigations, **not a sandbox**:
//! the Landlock ruleset the daemon applied is inherited by every Git process.

pub mod parse;
pub mod run;

use parse::{Commit, Files, Version};
use run::{Output, RunError};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Concurrent Git processes (§6).
pub const MAX_CONCURRENT: usize = 4;
const MAX_STDOUT: usize = 8 * 1024 * 1024;
/// Git's built-in empty tree: `--attr-source` reads attributes from it, so worktree
/// `.gitattributes` cannot select a filter driver (and nothing is written to the object store).
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Global options on every invocation (§6). `--no-pager` is extra belt and braces: Git has no
/// terminal here, so it would not page anyway.
pub const BASE_ARGS: [&str; 10] = [
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
];

/// What we know about Git for one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Everything that could be read was read.
    Ok,
    NotGit,
    /// No usable `git` executable.
    GitMissing,
    /// Git refused the repository (`safe.directory`, dubious ownership). Never overridden.
    UnsafeRepository,
    /// Worktree status not run: Git is older than 2.41.0 and `git.allow_unhardened_status` is off.
    StatusDisabledOldGit,
    /// Worktree status not run: a filter driver name cannot be neutralized safely.
    StatusDisabledUnsafeConfig,
    Timeout,
    Error,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotGit => "not_git",
            Self::GitMissing => "git_missing",
            Self::UnsafeRepository => "unsafe_repository",
            Self::StatusDisabledOldGit => "status_disabled_old_git",
            Self::StatusDisabledUnsafeConfig => "status_disabled_unsafe_config",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Ok,
            Self::NotGit,
            Self::GitMissing,
            Self::UnsafeRepository,
            Self::StatusDisabledOldGit,
            Self::StatusDisabledUnsafeConfig,
            Self::Timeout,
            Self::Error,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

/// Worktree status (counts are exact; file lists are capped, see [`parse::MAX_LISTED_FILES`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WorkTree {
    pub staged: u32,
    pub modified: u32,
    pub untracked: u32,
    pub files: Files,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub state: State,
    pub branch: Option<String>,
    pub detached: bool,
    pub upstream: Option<String>,
    pub ahead: Option<u32>,
    pub behind: Option<u32>,
    /// `None` when status was not run (disabled, refused, error).
    pub worktree: Option<WorkTree>,
    pub head: Option<Commit>,
    /// Sanitized (no credentials).
    pub remote_url: Option<String>,
}

impl Info {
    pub fn only(state: State) -> Self {
        Self {
            state,
            branch: None,
            detached: false,
            upstream: None,
            ahead: None,
            behind: None,
            worktree: None,
            head: None,
            remote_url: None,
        }
    }
}

/// The located `git` executable and what it supports. Detected once at startup.
#[derive(Debug, Clone)]
pub struct Git {
    program: Option<PathBuf>,
    version: Option<Version>,
    allow_unhardened: bool,
    home: PathBuf,
    path_env: OsString,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitSummary {
    pub program: Option<String>,
    pub version: Option<String>,
    /// Worktree status runs with `--attr-source` (Git ≥ 2.41.0).
    pub hardened_status: bool,
    /// Worktree status runs although it cannot be hardened (`git.allow_unhardened_status`).
    pub unhardened_status_allowed: bool,
}

/// First executable `git` on `path` (absolute entries only).
pub fn find_on_path(path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join("git"))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

impl Git {
    /// Locate `git` (`program`, normally from [`find_on_path`]) and read its version.
    pub fn detect(program: Option<PathBuf>, home: &Path, allow_unhardened: bool) -> Self {
        let mut path_env = OsString::new();
        if let Some(dir) = program.as_deref().and_then(Path::parent) {
            path_env.push(dir);
            path_env.push(":");
        }
        path_env.push("/usr/bin:/bin");
        let mut git = Self {
            program,
            version: None,
            allow_unhardened,
            home: home.to_path_buf(),
            path_env,
        };
        git.version = git
            .run(Path::new("/"), &["--version"])
            .ok()
            .filter(Output::success)
            .and_then(|o| parse::parse_version(&String::from_utf8_lossy(&o.stdout)));
        if git.version.is_none() {
            git.program = None; // not a working git
        }
        git
    }

    pub fn available(&self) -> bool {
        self.program.is_some()
    }

    pub fn hardened(&self) -> bool {
        self.version.is_some_and(|v| v >= parse::MIN_HARDENED)
    }

    pub fn summary(&self) -> GitSummary {
        GitSummary {
            program: self.program.as_ref().map(|p| p.display().to_string()),
            version: self.version.map(|Version(a, b, c)| format!("{a}.{b}.{c}")),
            hardened_status: self.available() && self.hardened(),
            unhardened_status_allowed: self.available()
                && !self.hardened()
                && self.allow_unhardened,
        }
    }

    /// The exact command line for `args` in `dir`: base flags, then `args`; empty environment plus
    /// the §6 variables; built with [`crate::sandbox::child_command`] like every daemon child.
    pub fn command(&self, dir: &Path, args: &[&str]) -> Option<std::process::Command> {
        let program = self.program.as_ref()?;
        let mut cmd = crate::sandbox::child_command(program);
        cmd.env_clear()
            .env("PATH", &self.path_env)
            .env("HOME", &self.home)
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .current_dir(dir)
            .args(BASE_ARGS)
            .args(args);
        Some(cmd)
    }

    fn run(&self, dir: &Path, args: &[&str]) -> Result<Output, RunError> {
        let cmd = self
            .command(dir, args)
            .ok_or_else(|| RunError::Spawn(std::io::Error::other("git is not available")))?;
        run::run(cmd, TIMEOUT, MAX_STDOUT)
    }

    /// Inspect the repository containing `dir` (blocking; at most five Git processes).
    pub fn inspect(&self, dir: &Path) -> Info {
        if !self.available() {
            return Info::only(State::GitMissing);
        }
        match self.inspect_inner(dir) {
            Ok(info) => info,
            Err(state) => Info::only(state),
        }
    }

    fn inspect_inner(&self, dir: &Path) -> Result<Info, State> {
        // 1. Is this a work tree, and which?
        let top = self.checked(dir, &["rev-parse", "--show-toplevel"])?;
        let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim_end_matches('\n'));
        // A repository at the home directory (dotfiles) is not this project's repository.
        if top == self.home && dir != self.home {
            return Err(State::NotGit);
        }
        let mut info = Info::only(State::Ok);

        // 2. Worktree status, hardened (or explicitly allowed unhardened).
        if !self.hardened() && !self.allow_unhardened {
            info.state = State::StatusDisabledOldGit;
            info.branch = self.branch_without_status(dir);
        } else {
            match self.status(dir)? {
                Some(st) => {
                    info.branch = st.branch;
                    info.detached = st.detached;
                    info.upstream = st.upstream;
                    info.ahead = st.ahead;
                    info.behind = st.behind;
                    info.worktree = Some(WorkTree {
                        staged: st.staged,
                        modified: st.modified,
                        untracked: st.untracked,
                        files: st.files,
                    });
                }
                None => {
                    info.state = State::StatusDisabledUnsafeConfig;
                    info.branch = self.branch_without_status(dir);
                }
            }
        }

        // 3. Latest commit (none on an unborn branch). Signatures are never verified: that would
        // run `gpg.program`, which repository config can choose.
        info.head = self
            .run(
                dir,
                &[
                    "log",
                    "-1",
                    "--no-show-signature",
                    "--no-notes",
                    "--format=%H%x00%s%x00%an%x00%at",
                ],
            )
            .ok()
            .filter(Output::success)
            .and_then(|o| parse::parse_log(&o.stdout));

        // 4. Remote URL of the upstream remote (else origin), sanitized.
        let remote = info
            .branch
            .as_deref()
            .filter(|_| info.upstream.is_some())
            .and_then(|b| self.config_get(dir, &format!("branch.{b}.remote")))
            .filter(|r| r != ".")
            .unwrap_or_else(|| "origin".to_string());
        info.remote_url = self
            .config_get(dir, &format!("remote.{remote}.url"))
            .map(|u| parse::sanitize_remote_url(&u));
        Ok(info)
    }

    /// Run and classify failures (no repository, refused repository, timeout, other errors).
    fn checked(&self, dir: &Path, args: &[&str]) -> Result<Output, State> {
        match self.run(dir, args) {
            Ok(o) if o.success() => Ok(o),
            Ok(o) => Err(classify_failure(&o.stderr_text())),
            Err(RunError::Timeout) => Err(State::Timeout),
            Err(_) => Err(State::Error),
        }
    }

    /// `None` means a filter driver cannot be neutralized (status disabled, fail closed).
    fn status(&self, dir: &Path) -> Result<Option<parse::Status>, State> {
        let drivers = match self.run(
            dir,
            &[
                "config",
                "-z",
                "--get-regexp",
                r"^filter\..*\.(clean|smudge|process)$",
            ],
        ) {
            Ok(o) if o.success() => parse::filter_driver_names(&o.stdout),
            Ok(o) if o.code == Some(1) => Vec::new(), // no matching keys
            Ok(o) => return Err(classify_failure(&o.stderr_text())),
            Err(RunError::Timeout) => return Err(State::Timeout),
            Err(_) => return Err(State::Error),
        };
        if !drivers.iter().all(|n| parse::neutralizable(n)) {
            return Ok(None);
        }
        let args = status_args(&drivers, self.hardened());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.checked(dir, &refs)?;
        parse::parse_status(&out.stdout)
            .map(Some)
            .ok_or(State::Error)
    }

    fn branch_without_status(&self, dir: &Path) -> Option<String> {
        self.run(dir, &["rev-parse", "--abbrev-ref", "HEAD"])
            .ok()
            .filter(Output::success)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|b| !b.is_empty() && b != "HEAD")
            .map(|b| parse::clean(&b, 255))
    }

    fn config_get(&self, dir: &Path, key: &str) -> Option<String> {
        if key.chars().any(char::is_control) {
            return None;
        }
        self.run(dir, &["config", "--get", key])
            .ok()
            .filter(Output::success)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
            .filter(|v| !v.is_empty())
    }
}

/// The `status` invocation: no-op overrides for every filter driver, then `--attr-source`
/// (when supported), then the subcommand. Paths are limited to the project (`-- .`).
pub fn status_args(drivers: &[String], hardened: bool) -> Vec<String> {
    let mut args = Vec::new();
    for name in drivers {
        for var in ["clean", "smudge", "process"] {
            args.push("-c".to_string());
            args.push(format!("filter.{name}.{var}="));
        }
        args.push("-c".to_string());
        args.push(format!("filter.{name}.required=false"));
    }
    if hardened {
        args.push(format!("--attr-source={EMPTY_TREE}"));
    }
    args.extend(
        [
            "status",
            "--porcelain=v2",
            "--branch",
            "--ignore-submodules=all",
            "-z",
            "--",
            ".",
        ]
        .map(String::from),
    );
    args
}

/// Map Git's stderr on failure to a state. Only these phrases are inspected (with `LC_ALL=C`).
pub fn classify_failure(stderr: &str) -> State {
    if stderr.contains("not a git repository") {
        State::NotGit
    } else if stderr.contains("dubious ownership") || stderr.contains("safe.directory") {
        State::UnsafeRepository
    } else {
        State::Error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_strings_roundtrip() {
        for s in [
            State::Ok,
            State::NotGit,
            State::GitMissing,
            State::UnsafeRepository,
            State::StatusDisabledOldGit,
            State::StatusDisabledUnsafeConfig,
            State::Timeout,
            State::Error,
        ] {
            assert_eq!(State::parse(s.as_str()), Some(s));
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::Value::String(s.as_str().into())
            );
        }
        assert_eq!(State::parse("bogus"), None);
    }

    #[test]
    fn failures_are_classified_from_known_messages_only() {
        assert_eq!(
            classify_failure(
                "fatal: not a git repository (or any of the parent directories): .git"
            ),
            State::NotGit
        );
        assert_eq!(
            classify_failure("fatal: detected dubious ownership in repository at '/x'\nTo add an exception … safe.directory"),
            State::UnsafeRepository
        );
        assert_eq!(classify_failure("fatal: something else"), State::Error);
    }

    #[test]
    fn status_arguments_null_every_driver_and_use_the_empty_tree() {
        let args = status_args(&["lfs".into(), "a.b".into()], true);
        let joined = args.join(" ");
        for want in [
            "-c filter.lfs.clean=",
            "-c filter.lfs.smudge=",
            "-c filter.lfs.process=",
            "-c filter.lfs.required=false",
            "-c filter.a.b.clean=",
            "--attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904 status --porcelain=v2 --branch --ignore-submodules=all -z -- .",
        ] {
            assert!(joined.contains(want), "{want} missing in {joined}");
        }
        assert!(!status_args(&[], false).join(" ").contains("attr-source"));
    }

    #[test]
    fn command_uses_an_empty_environment_and_the_base_flags() {
        let git = Git {
            program: Some(PathBuf::from("/usr/bin/git")),
            version: Some(Version(2, 43, 0)),
            allow_unhardened: false,
            home: PathBuf::from("/home/u"),
            path_env: "/usr/bin:/bin".into(),
        };
        let cmd = git.command(Path::new("/p"), &["status"]).unwrap();
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .filter(|(_, v)| v.is_some())
            .collect();
        let mut names: Vec<&str> = envs.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "GIT_CONFIG_NOSYSTEM",
                "GIT_OPTIONAL_LOCKS",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "LC_ALL",
                "PATH"
            ]
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&args[..BASE_ARGS.len()], BASE_ARGS);
        assert_eq!(args.last().map(String::as_str), Some("status"));
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/p")));
    }

    #[test]
    fn a_missing_git_is_reported_not_spawned() {
        let git = Git::detect(None, Path::new("/home/u"), false);
        assert!(!git.available());
        assert_eq!(git.inspect(Path::new("/")).state, State::GitMissing);
        let git = Git::detect(
            Some(PathBuf::from("/nonexistent/git")),
            Path::new("/home/u"),
            false,
        );
        assert!(!git.available() && git.summary().program.is_none());
    }
}
