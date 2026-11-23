//! Synthetic environment generator (REQUIREMENTS.md §19). Builds a throw-away `HOME`, XDG
//! directories and a Claude config directory populated with **invented** projects and sessions, so
//! `ccwm` can be run and tested without ever touching a real home directory or `~/.claude`.
//! Shared by the integration tests and the `ccwm-synth` tool.

use std::fs;
use std::io;
use std::os::unix::fs::{symlink, DirBuilderExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SynthEnv {
    pub root: PathBuf,
    pub home: PathBuf,
    pub config_home: PathBuf,
    pub data_home: PathBuf,
    pub state_home: PathBuf,
    pub runtime_dir: PathBuf,
    pub claude_dir: PathBuf,
}

impl SynthEnv {
    /// The variables that point a process at this environment.
    pub fn env_pairs(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("HOME", self.home.clone()),
            ("XDG_CONFIG_HOME", self.config_home.clone()),
            ("XDG_DATA_HOME", self.data_home.clone()),
            ("XDG_STATE_HOME", self.state_home.clone()),
            ("XDG_RUNTIME_DIR", self.runtime_dir.clone()),
            ("CLAUDE_CONFIG_DIR", self.claude_dir.clone()),
        ]
    }

    /// Project directories (relative to `home`) that marker discovery must find.
    pub fn expected_projects(&self, bulk: usize) -> Vec<String> {
        let mut v: Vec<String> = [
            "dev/alpha",
            "dev/beta",
            "dev/beta/packages/inner",
            "dev/gamma",
            "dev/monorepo",
            "dev/with space",
            "dev/deep/er/still/delta",
            "dev/nested-plain",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        v.extend((0..bulk).map(|i| format!("bulk/proj-{i:04}")));
        v.sort();
        v
    }
}

fn mkdir(p: &Path) -> io::Result<()> {
    fs::create_dir_all(p)
}

fn write(p: &Path, text: &str) -> io::Result<()> {
    if let Some(parent) = p.parent() {
        mkdir(parent)?;
    }
    fs::write(p, text)
}

fn project(home: &Path, rel: &str) -> io::Result<PathBuf> {
    let dir = home.join(rel);
    write(
        &dir.join("CLAUDE.md"),
        &format!("# {rel}\nSynthetic project for testing.\n"),
    )?;
    Ok(dir)
}

fn git_dir(dir: &Path) -> io::Result<()> {
    mkdir(&dir.join(".git"))?;
    write(&dir.join(".git/HEAD"), "ref: refs/heads/main\n")
}

/// Generate the environment under `root` (which must not exist or be empty). `bulk` extra trivial
/// projects are added under `home/bulk/` for load and pagination tests.
pub fn generate(root: &Path, bulk: usize) -> io::Result<SynthEnv> {
    if root.exists() && fs::read_dir(root)?.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is not empty", root.display()),
        ));
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let root = fs::canonicalize(root)?;
    let env = SynthEnv {
        home: root.join("home"),
        config_home: root.join("c"),
        data_home: root.join("d"),
        state_home: root.join("s"),
        runtime_dir: root.join("r"),
        claude_dir: root.join("claude"),
        root,
    };
    // XDG_RUNTIME_DIR must already exist and be private, like /run/user/<uid>.
    for d in [
        &env.config_home,
        &env.data_home,
        &env.state_home,
        &env.runtime_dir,
    ] {
        fs::DirBuilder::new().mode(0o700).create(d)?;
    }
    mkdir(&env.home)?;
    let home = &env.home;

    // Projects.
    project(home, "dev/alpha")?;
    let beta = project(home, "dev/beta")?;
    git_dir(&beta)?;
    let inner = project(home, "dev/beta/packages/inner")?;
    git_dir(&inner)?;
    let gamma = home.join("dev/gamma");
    write(&gamma.join("AGENTS.md"), "# agents\n")?;
    symlink("AGENTS.md", gamma.join("CLAUDE.md"))?;
    let mono = project(home, "dev/monorepo")?;
    git_dir(&mono)?;
    project(home, "dev/monorepo/services/api")?; // nested instruction file, not a project
    project(home, "dev/with space")?;
    project(home, "dev/deep/er/still/delta")?;
    project(home, "dev/nested-plain")?;
    project(home, "dev/nested-plain/sub")?; // nested instruction file, not a project
    for i in 0..bulk {
        project(home, &format!("bulk/proj-{i:04}"))?;
    }

    // Things that must NOT be found.
    write(
        &home.join("CLAUDE.md"),
        "# the home directory is never a project\n",
    )?;
    write(&home.join("dev/decoys/claude.md"), "wrong case\n")?;
    write(&home.join("dev/decoys/CLAUDE.MD"), "wrong case\n")?;
    mkdir(&home.join("dev/decoys/CLAUDE.md.d"))?;
    for hidden in [
        ".cache/x",
        ".claude/x",
        ".config/x",
        ".local/share/x",
        ".venv/x",
    ] {
        project(home, hidden)?;
    }
    for generated in [
        "node_modules/pkg",
        "target/debug",
        "build/out",
        "dist/out",
        "venv/lib",
        "__pycache__/m",
    ] {
        project(&home.join("dev/noise"), generated)?;
    }
    project(home, "snap/firefox")?;
    let outside = env.root.join("outside-tree");
    project(&outside, "escaped")?;
    symlink(&outside, home.join("dev/link-to-outside"))?;
    symlink(home, home.join("dev/loop-to-home"))?;
    write(&home.join("dev/shared/secret.md"), "outside the project\n")?;
    mkdir(&home.join("dev/escape"))?;
    symlink("../shared/secret.md", home.join("dev/escape/CLAUDE.md"))?; // marker symlink escaping its directory
    mkdir(&home.join("dev/abs-escape"))?;
    symlink("/etc/hostname", home.join("dev/abs-escape/CLAUDE.md"))?;

    // A synthetic Claude config directory with an invented session (used from M3 on).
    let enc = "-synthetic-home-dev-alpha";
    let session = "11111111-2222-4333-8444-555555555555";
    let cwd = home.join("dev/alpha");
    let line = |ty: &str, extra: &str| {
        format!(
            r#"{{"type":"{ty}","sessionId":"{session}","cwd":"{}","timestamp":"2026-01-01T00:00:00.000Z","version":"0.0.0-synthetic"{extra}}}"#,
            cwd.display()
        )
    };
    let records = [
        line("user", r#","message":{"role":"user","content":"SYNTHETIC first prompt"},"promptSource":"typed","isSidechain":false"#),
        line("assistant", r#","message":{"role":"assistant","content":[{"type":"text","text":"SYNTHETIC reply"}]}"#),
        line("user", r#","message":{"role":"user","content":[{"type":"tool_result","content":"x"}]},"toolUseResult":{}"#),
        r#"{"type":"ai-title","sessionId":"11111111-2222-4333-8444-555555555555","aiTitle":"Synthetic title"}"#.to_string(),
    ];
    write(
        &env.claude_dir
            .join("projects")
            .join(enc)
            .join(format!("{session}.jsonl")),
        &(records.join("\n") + "\n"),
    )?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_an_isolated_environment() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("env");
        let env = generate(&root, 3).unwrap();
        for (_, p) in env.env_pairs() {
            assert!(
                p.starts_with(&env.root),
                "{} escapes the synthetic root",
                p.display()
            );
        }
        assert!(env.home.join("dev/alpha/CLAUDE.md").is_file());
        assert!(env.claude_dir.join("projects").is_dir());
        assert_eq!(env.expected_projects(3).len(), 11);
    }

    #[test]
    fn refuses_a_non_empty_directory() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("x"), "x").unwrap();
        assert!(generate(t.path(), 0).is_err());
    }
}
