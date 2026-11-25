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

    /// ccwm's own four directories (`<xdg>/ccwm`), which ccwm may write.
    pub fn ccwm_dirs(&self) -> [PathBuf; 4] {
        [
            self.config_home.join("ccwm"),
            self.data_home.join("ccwm"),
            self.state_home.join("ccwm"),
            self.runtime_dir.join("ccwm"),
        ]
    }

    /// Project directories (relative to `home`) that marker discovery must find.
    pub fn expected_marker_projects(&self, bulk: usize) -> Vec<String> {
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

    /// Every project the daemon must register: the marker projects plus those known only from
    /// sessions ([`SESSION_ONLY_PROJECTS`]).
    pub fn expected_projects(&self, bulk: usize) -> Vec<String> {
        let mut v = self.expected_marker_projects(bulk);
        v.extend(SESSION_ONLY_PROJECTS.iter().map(ToString::to_string));
        v.sort();
        v
    }
}

/// Projects of the synthetic home that have sessions but no `CLAUDE.md` (relative to home).
pub const SESSION_ONLY_PROJECTS: [&str; 1] = ["dev/session-only"];

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

/// Where the XDG and Claude config directories live relative to the walked home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Next to `home/` (`c/ d/ s/ r/ claude/`).
    Separate,
    /// Inside the walked home under **non-hidden** names (like the real default
    /// `~/.local/share/ccwm`, but not pruned by the hidden-directory rule), each ccwm directory and
    /// the Claude config directory seeded with a decoy `CLAUDE.md` that must never be registered.
    InsideHome,
}

/// Generate the environment under `root` (which must not exist or be empty). `bulk` extra trivial
/// projects are added under `home/bulk/` for load and pagination tests.
pub fn generate(root: &Path, bulk: usize) -> io::Result<SynthEnv> {
    generate_with(root, bulk, Layout::Separate)
}

pub fn generate_with(root: &Path, bulk: usize, layout: Layout) -> io::Result<SynthEnv> {
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
    // Whatever directory the environment is created in (even inside a repository), Git ignores it.
    fs::write(
        root.join(".gitignore"),
        "# synthetic ccwm environment: never commit\n*\n",
    )?;
    let home = root.join("home");
    let base = match layout {
        Layout::Separate => root.clone(),
        Layout::InsideHome => home.clone(),
    };
    let name = |separate: &str, inside: &str| {
        base.join(match layout {
            Layout::Separate => separate,
            Layout::InsideHome => inside,
        })
    };
    let env = SynthEnv {
        config_home: name("c", "xdg-config"),
        data_home: name("d", "xdg-data"),
        state_home: name("s", "xdg-state"),
        runtime_dir: name("r", "xdg-run"),
        claude_dir: name("claude", "claude-config"),
        home,
        root,
    };
    mkdir(&env.home)?;
    // XDG_RUNTIME_DIR must already exist and be private, like /run/user/<uid>.
    for d in [
        &env.config_home,
        &env.data_home,
        &env.state_home,
        &env.runtime_dir,
    ] {
        fs::DirBuilder::new().mode(0o700).create(d)?;
    }
    let home = &env.home;
    if layout == Layout::InsideHome {
        for d in env.ccwm_dirs() {
            fs::DirBuilder::new().mode(0o700).create(&d)?;
            write(&d.join("CLAUDE.md"), "# decoy: ccwm's own directory\n")?;
        }
        write(
            &env.claude_dir.join("CLAUDE.md"),
            "# decoy: the Claude config directory\n",
        )?;
        write(
            &env.claude_dir.join("projects/-decoy/CLAUDE.md"),
            "# decoy inside the Claude config directory\n",
        )?;
    }

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

    // A project known only from its Claude Code sessions (no CLAUDE.md), with a Git root above
    // the recorded cwd; and the session fixture corpus (cwds point into this home).
    mkdir(&home.join("dev/session-only/src"))?;
    git_dir(&home.join("dev/session-only"))?;
    write(&home.join("dev/session-only/src/main.rs"), "fn main() {}\n")?;
    mkdir(&home.join("dev/alpha/src"))?;
    mkdir(&home.join("dev/beta/packages/inner/src"))?;
    install_sessions(&env.claude_dir, home)?;
    Ok(env)
}

/// The versioned synthetic session corpus (`tests/fixtures/sessions/<version>/projects/…`),
/// embedded so the generator and the tests share one set of fixtures. `@HOME@` stands for the
/// synthetic home directory.
pub const SESSION_FIXTURES: [(&str, &str); 9] = [
    (
        "2.1.331/projects/-synthetic-dev-alpha/11111111-2222-4333-8444-555555555555.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-alpha/11111111-2222-4333-8444-555555555555.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-alpha/11111111-2222-4333-8444-555555555555/subagents/agent-a1b2c3.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-alpha/11111111-2222-4333-8444-555555555555/subagents/agent-a1b2c3.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-alpha/22222222-3333-4444-8555-666666666666.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-alpha/22222222-3333-4444-8555-666666666666.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-alpha/memory/notes.md",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-alpha/memory/notes.md"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-deleted/55555555-6666-4777-8888-999999999999.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-deleted/55555555-6666-4777-8888-999999999999.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-gamma/66666666-7777-4888-8999-aaaaaaaaaaaa.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-gamma/66666666-7777-4888-8999-aaaaaaaaaaaa.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-dev-session-only-src/33333333-4444-4555-8666-777777777777.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-dev-session-only-src/33333333-4444-4555-8666-777777777777.jsonl"),
    ),
    (
        "2.1.331/projects/-synthetic-home/44444444-5555-4666-8777-888888888888.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.331/projects/-synthetic-home/44444444-5555-4666-8777-888888888888.jsonl"),
    ),
    (
        "2.1.220/projects/-synthetic-dev-beta-packages-inner-src/77777777-8888-4999-8aaa-bbbbbbbbbbbb.jsonl",
        include_str!("../tests/fixtures/sessions/2.1.220/projects/-synthetic-dev-beta-packages-inner-src/77777777-8888-4999-8aaa-bbbbbbbbbbbb.jsonl"),
    ),
];

/// Copy the session corpus into `claude_dir` (every version's `projects/` merged), with
/// `@HOME@` replaced by `home` (JSON-escaped). Also adds the non-session entries Claude Code
/// keeps there (an alias file), which must be skipped.
pub fn install_sessions(claude_dir: &Path, home: &Path) -> io::Result<()> {
    let quoted = serde_json::to_string(&home.to_string_lossy())
        .map_err(|e| io::Error::other(e.to_string()))?;
    let escaped = &quoted[1..quoted.len() - 1];
    for (rel, text) in SESSION_FIXTURES {
        let (_, inside) = rel
            .split_once('/')
            .ok_or_else(|| io::Error::other("fixture path without a version"))?;
        write(&claude_dir.join(inside), &text.replace("@HOME@", escaped))?;
    }
    write(
        &claude_dir.join("projects/-synthetic-dev-alpha/.session-aliases"),
        "synthetic\n",
    )
}

/// Turn the synthetic Git projects (`dev/beta`, its nested `packages/inner`, `dev/monorepo`) into
/// real repositories with one commit each, using `git` from `PATH`. Returns `false` (and leaves
/// the placeholder `.git` directories) when Git is not installed. Only the synthetic tree is
/// written; Git runs with the synthetic `HOME` and no system configuration.
pub fn init_git(env: &SynthEnv) -> io::Result<bool> {
    let Some(git) = crate::git::find_on_path(std::env::var_os("PATH").as_deref()) else {
        return Ok(false);
    };
    let run = |dir: &Path, args: &[&str]| -> io::Result<()> {
        let out = std::process::Command::new(&git)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &env.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Synthetic Author")
            .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
            .env("GIT_COMMITTER_NAME", "Synthetic Author")
            .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .current_dir(dir)
            .args(args)
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    };
    let home = &env.home;
    for (rel, files) in [
        ("dev/beta/packages/inner", &["CLAUDE.md"][..]),
        ("dev/beta", &["CLAUDE.md"][..]),
        ("dev/monorepo", &["CLAUDE.md", "services/api/CLAUDE.md"][..]),
        ("dev/session-only", &["src/main.rs"][..]),
    ] {
        let dir = home.join(rel);
        fs::remove_dir_all(dir.join(".git"))?;
        run(&dir, &["init", "-q", "-b", "main"])?;
        let mut add = vec!["add", "--"];
        add.extend_from_slice(files);
        run(&dir, &add)?;
        run(
            &dir,
            &[
                "commit",
                "-q",
                "-m",
                &format!("Synthetic initial commit of {rel}"),
            ],
        )?;
    }
    // A remote with credentials in the URL: ccwm must store and show it without them.
    run(
        &home.join("dev/monorepo"),
        &[
            "remote",
            "add",
            "origin",
            "https://synthetic-user:synthetic-password@example.invalid/monorepo.git",
        ],
    )?;
    // Uncommitted work in monorepo so the "uncommitted changes" filter has something to show.
    fs::write(
        home.join("dev/monorepo/NOTES.txt"),
        "synthetic uncommitted file\n",
    )?;
    Ok(true)
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
        assert_eq!(env.expected_projects(3).len(), 12);
        let alpha = env
            .claude_dir
            .join("projects/-synthetic-dev-alpha/11111111-2222-4333-8444-555555555555.jsonl");
        let text = fs::read_to_string(alpha).unwrap();
        assert!(!text.contains("@HOME@"));
        assert!(text.contains(&format!("\"cwd\":\"{}/dev/alpha\"", env.home.display())));
    }

    #[test]
    fn inside_home_layout_puts_every_xdg_dir_under_the_walked_home() {
        let t = tempfile::tempdir().unwrap();
        let env = generate_with(&t.path().join("env"), 0, Layout::InsideHome).unwrap();
        for (k, p) in env.env_pairs() {
            if k != "HOME" {
                assert!(p.starts_with(&env.home), "{k} = {}", p.display());
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                assert!(!name.starts_with('.'), "{k} must not be hidden");
            }
        }
        for d in env.ccwm_dirs() {
            assert!(d.join("CLAUDE.md").is_file());
        }
        assert!(env.claude_dir.join("CLAUDE.md").is_file());
    }

    #[test]
    fn init_git_makes_real_repositories_when_git_exists() {
        let t = tempfile::tempdir().unwrap();
        let env = generate(&t.path().join("env"), 0).unwrap();
        if !init_git(&env).unwrap() {
            eprintln!("NOTICE: git not installed; placeholder .git directories kept");
            return;
        }
        for rel in ["dev/beta", "dev/beta/packages/inner", "dev/monorepo"] {
            assert!(env.home.join(rel).join(".git/HEAD").is_file(), "{rel}");
            assert!(env.home.join(rel).join(".git/objects").is_dir(), "{rel}");
        }
        assert!(env.home.join("dev/monorepo/NOTES.txt").is_file());
    }

    #[test]
    fn refuses_a_non_empty_directory() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("x"), "x").unwrap();
        assert!(generate(t.path(), 0).is_err());
    }
}
