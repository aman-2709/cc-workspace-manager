//! The Git module against real temporary repositories (REQUIREMENTS.md §6, §16).
//!
//! Security acceptance test **3** (`.git/index`, `.git/config` and refs unchanged after every Git
//! operation) and **4** (malicious configurations cannot execute commands: each vector writes a
//! sentinel file that must not appear). Every vector Git can reach with our commands has a
//! **control** run with plain Git that proves the sentinel would appear without the mitigations.
//! Promisor partial clones (a lazy fetch during `status`/`log` reaching `ext::`, `uploadpack` or
//! `core.sshCommand`) are covered with the `HEAD` object removed.
//! Skipped with a notice if `git` is not installed (a failure in CI).

mod common;

use cc_workspace_manager::git::{find_on_path, parse, Git, Info, State};
use common::{snapshot, Promisor, PROMISORS};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    sentinels: PathBuf,
}

fn real_git() -> Option<PathBuf> {
    let git = find_on_path(std::env::var_os("PATH").as_deref());
    if git.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "git is required in CI for the Git tests"
        );
        eprintln!("NOTICE: git is not installed; skipping Git tests");
    }
    git
}

fn fx() -> Option<Fx> {
    real_git()?;
    let t = common::tempdir();
    let root = fs::canonicalize(t.path()).unwrap();
    let home = root.join("home");
    let sentinels = root.join("sentinels");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&sentinels).unwrap();
    Some(Fx {
        _t: t,
        root,
        home,
        sentinels,
    })
}

impl Fx {
    /// Plain Git for setting up fixtures and for control runs (no ccwm hardening).
    fn git_cmd(&self, dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Synthetic Author")
            .env("GIT_AUTHOR_EMAIL", "author@example.invalid")
            .env("GIT_COMMITTER_NAME", "Synthetic Author")
            .env("GIT_COMMITTER_EMAIL", "author@example.invalid")
            .env("LC_ALL", "C")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap()
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.git_cmd(dir, args);
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A repository with one commit on `main` containing `file.txt`.
    fn repo(&self, rel: &str) -> PathBuf {
        let dir = self.root.join(rel);
        fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q", "-b", "main"]);
        fs::write(dir.join("file.txt"), "one\n").unwrap();
        self.git(&dir, &["add", "file.txt"]);
        self.git(&dir, &["commit", "-q", "-m", "first commit"]);
        dir
    }

    fn ccwm_git(&self) -> Git {
        Git::detect(real_git(), &self.home, false)
    }

    /// An executable that records that it ran, then behaves like a pass-through filter.
    fn sentinel_script(&self, name: &str) -> (PathBuf, PathBuf) {
        self.sentinel_script_with(name, "cat\nexit 0")
    }

    /// Like [`Self::sentinel_script`] with a custom body after the `touch`.
    fn sentinel_script_with(&self, name: &str, body: &str) -> (PathBuf, PathBuf) {
        common::sentinel_script(&self.sentinels, name, body)
    }

    /// Make `file.txt` stat-dirty (same content, new mtime) so status must re-hash it, which is
    /// when Git runs clean filters.
    fn stat_dirty(&self, dir: &Path) {
        let f = dir.join("file.txt");
        let t = fs::metadata(&f).unwrap().modified().unwrap() + std::time::Duration::from_secs(7);
        fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
}

fn git_dir_snapshot(dir: &Path) -> Vec<String> {
    snapshot(&dir.join(".git"))
}

// ---- status correctness -----------------------------------------------------------------------

#[test]
fn clean_dirty_staged_untracked_and_commit_details() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let g = f.ccwm_git();
    let info = g.inspect(&r);
    assert_eq!(info.state, State::Ok);
    assert_eq!(info.branch.as_deref(), Some("main"));
    let wt = info.worktree.clone().unwrap();
    assert_eq!((wt.staged, wt.modified, wt.untracked), (0, 0, 0));
    let head = info.head.unwrap();
    assert_eq!(head.subject, "first commit");
    assert_eq!(head.author, "Synthetic Author");
    assert_eq!(head.hash, f.git(&r, &["rev-parse", "HEAD"]).trim());
    assert!(info.remote_url.is_none());

    fs::write(r.join("file.txt"), "changed\n").unwrap();
    fs::write(r.join("staged.txt"), "s\n").unwrap();
    f.git(&r, &["add", "staged.txt"]);
    fs::write(r.join("new.txt"), "n\n").unwrap();
    let wt = g.inspect(&r).worktree.unwrap();
    assert_eq!((wt.staged, wt.modified, wt.untracked), (1, 1, 1));
    assert_eq!(wt.files.staged, ["staged.txt"]);
    assert_eq!(wt.files.modified, ["file.txt"]);
    assert_eq!(wt.files.untracked, ["new.txt"]);
}

#[test]
fn detached_head_unborn_branch_and_worktrees() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let g = f.ccwm_git();
    f.git(&r, &["checkout", "-q", "--detach"]);
    let info = g.inspect(&r);
    assert_eq!(info.state, State::Ok);
    assert!(info.detached && info.branch.is_none());
    assert!(info.head.is_some());

    let unborn = f.root.join("unborn");
    fs::create_dir(&unborn).unwrap();
    f.git(&unborn, &["init", "-q", "-b", "trunk"]);
    let info = g.inspect(&unborn);
    assert_eq!(info.state, State::Ok);
    assert_eq!(info.branch.as_deref(), Some("trunk"));
    assert!(info.head.is_none(), "no commit yet");

    f.git(&r, &["checkout", "-q", "main"]);
    let wt = f.root.join("wt");
    f.git(
        &r,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            wt.to_str().unwrap(),
        ],
    );
    let info = g.inspect(&wt);
    assert_eq!(info.state, State::Ok);
    assert_eq!(info.branch.as_deref(), Some("feature"));
}

#[test]
fn not_git_home_repositories_and_project_subdirectories() {
    let Some(f) = fx() else { return };
    let g = f.ccwm_git();
    let plain = f.root.join("plain");
    fs::create_dir(&plain).unwrap();
    assert_eq!(g.inspect(&plain).state, State::NotGit);

    // A dotfiles repository at $HOME is not the repository of a project below it.
    f.git(&f.home, &["init", "-q"]);
    let below_home = f.home.join("dev/p");
    fs::create_dir_all(&below_home).unwrap();
    assert_eq!(g.inspect(&below_home).state, State::NotGit);

    // A project in a subdirectory of a repository: status is limited to the project.
    let r = f.repo("mono");
    fs::create_dir_all(r.join("app")).unwrap();
    fs::write(r.join("app/a.txt"), "a\n").unwrap();
    fs::write(r.join("outside.txt"), "o\n").unwrap();
    let wt = g.inspect(&r.join("app")).worktree.unwrap();
    assert_eq!(wt.untracked, 1);
    assert_eq!(
        wt.files.untracked,
        ["app/"],
        "untracked directories are collapsed"
    );
}

#[test]
fn upstream_ahead_behind_and_sanitized_remote_of_the_upstream_remote() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let first = f.git(&r, &["rev-parse", "HEAD"]).trim().to_string();
    fs::write(r.join("file.txt"), "two\n").unwrap();
    f.git(&r, &["commit", "-q", "-am", "second"]);
    f.git(
        &r,
        &[
            "remote",
            "add",
            "origin",
            "https://user:secret@example.invalid/o.git",
        ],
    );
    f.git(
        &r,
        &[
            "remote",
            "add",
            "up",
            "https://ghp_canary123@example.invalid/up.git?x=1",
        ],
    );
    // A remote-tracking ref one commit behind, without any network access.
    f.git(&r, &["update-ref", "refs/remotes/up/main", &first]);
    f.git(&r, &["config", "branch.main.remote", "up"]);
    f.git(&r, &["config", "branch.main.merge", "refs/heads/main"]);
    let info = f.ccwm_git().inspect(&r);
    assert_eq!(info.upstream.as_deref(), Some("up/main"));
    assert_eq!((info.ahead, info.behind), (Some(1), Some(0)));
    assert_eq!(
        info.remote_url.as_deref(),
        Some("https://example.invalid/up.git")
    );
    // Without an upstream, origin is used.
    f.git(&r, &["config", "--unset", "branch.main.remote"]);
    assert_eq!(
        f.ccwm_git().inspect(&r).remote_url.as_deref(),
        Some("https://example.invalid/o.git")
    );
}

/// A stand-in `git` (a shell script) for states we cannot produce for real as one user.
fn fake_git(f: &Fx, name: &str, body: &str) -> PathBuf {
    let p = f.root.join(name);
    common::write_executable(
        &p,
        &format!("#!/bin/sh\ncase \"$*\" in *--version*) echo 'git version 2.43.0'; exit 0;; esac\n{body}\n"),
    );
    p
}

#[test]
fn a_refused_repository_is_reported_never_overridden() {
    let Some(f) = fx() else { return };
    // Git refuses repositories owned by another user (`safe.directory`); only root could create
    // one, so a stand-in reproduces Git's exact message.
    let fake = fake_git(
        &f,
        "git-dubious",
        "echo \"fatal: detected dubious ownership in repository at '$PWD'\" >&2\necho \"To add an exception for this directory, call: git config --global --add safe.directory '$PWD'\" >&2\nexit 128",
    );
    let g = Git::detect(Some(fake), &f.home, false);
    assert_eq!(g.inspect(&f.root).state, State::UnsafeRepository);
}

#[test]
fn a_hanging_git_times_out_and_is_killed() {
    let Some(f) = fx() else { return };
    let fake = fake_git(&f, "git-hang", "exec sleep 60");
    let g = Git::detect(Some(fake), &f.home, false);
    let started = std::time::Instant::now();
    assert_eq!(g.inspect(&f.root).state, State::Timeout);
    let took = started.elapsed();
    assert!(
        took >= cc_workspace_manager::git::TIMEOUT && took < std::time::Duration::from_secs(8),
        "{took:?}"
    );
}

#[test]
fn git_older_than_2_41_disables_worktree_status_unless_allowed() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    fs::write(r.join("new.txt"), "n\n").unwrap();
    let real = real_git().unwrap();
    let old = f.root.join("git-old");
    common::write_executable(
        &old,
        &format!(
            "#!/bin/sh\ncase \"$*\" in *--version*) echo 'git version 2.40.1'; exit 0;; esac\nexec '{}' \"$@\"\n",
            real.display()
        ),
    );

    let g = Git::detect(Some(old.clone()), &f.home, false);
    assert!(!g.summary().hardened_status);
    let info = g.inspect(&r);
    assert_eq!(info.state, State::StatusDisabledOldGit);
    assert_eq!(
        info.branch.as_deref(),
        Some("main"),
        "rev-parse still works"
    );
    assert!(info.worktree.is_none() && info.head.is_some());

    let allowed = Git::detect(Some(old), &f.home, true);
    assert!(allowed.summary().unhardened_status_allowed);
    let info = allowed.inspect(&r);
    assert_eq!(info.state, State::Ok);
    assert_eq!(info.worktree.unwrap().untracked, 1);
}

// ---- security acceptance test 3 -----------------------------------------------------------------

#[test]
fn acceptance_3_git_metadata_is_unchanged_by_every_operation() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    fs::write(r.join("untracked.txt"), "u\n").unwrap();
    f.git(
        &r,
        &["remote", "add", "origin", "https://example.invalid/x.git"],
    );
    let g = f.ccwm_git();

    // Control: plain `git status` rewrites the index of a stat-dirty file, so the snapshot can
    // see the kind of change we forbid.
    let control = f.repo("control");
    f.stat_dirty(&control);
    let before = git_dir_snapshot(&control);
    f.git(&control, &["status", "--porcelain"]);
    assert_ne!(
        git_dir_snapshot(&control),
        before,
        "control: plain git status should refresh the index"
    );

    f.stat_dirty(&r);
    let before = git_dir_snapshot(&r);
    for _ in 0..3 {
        let info = g.inspect(&r);
        assert_eq!(info.state, State::Ok);
        f.stat_dirty(&r);
    }
    // Detached HEAD and a worktree as well.
    let wt = f.root.join("wt");
    f.git(
        &r,
        &["worktree", "add", "-q", "--detach", wt.to_str().unwrap()],
    );
    let before_wt = git_dir_snapshot(&r);
    let _ = before; // the worktree add above changed .git by design; compare from here on
    assert_eq!(g.inspect(&wt).state, State::Ok);
    assert_eq!(g.inspect(&r).state, State::Ok);
    assert_eq!(
        git_dir_snapshot(&r),
        before_wt,
        ".git (index, config, refs, objects) changed"
    );
    let index = fs::read(r.join(".git/index")).unwrap();
    let config = fs::read(r.join(".git/config")).unwrap();
    f.stat_dirty(&r);
    g.inspect(&r);
    assert_eq!(fs::read(r.join(".git/index")).unwrap(), index);
    assert_eq!(fs::read(r.join(".git/config")).unwrap(), config);
}

// ---- security acceptance test 4 -----------------------------------------------------------------

/// Run ccwm's inspection, then assert the sentinel never appeared and nothing in `.git` changed.
fn assert_not_executed(f: &Fx, dir: &Path, sentinel: &Path, what: &str) -> Info {
    let before = git_dir_snapshot(dir);
    let info = f.ccwm_git().inspect(dir);
    assert!(
        !sentinel.exists(),
        "{what}: the malicious command was executed"
    );
    assert_eq!(git_dir_snapshot(dir), before, "{what}: .git changed");
    assert_ne!(info.state, State::GitMissing);
    info
}

#[test]
fn acceptance_4_core_fsmonitor_is_never_run() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (script, sentinel) = f.sentinel_script("fsmonitor");
    f.git(&r, &["config", "core.fsmonitor", script.to_str().unwrap()]);
    // Control.
    f.git(&r, &["status", "--porcelain"]);
    assert!(
        sentinel.exists(),
        "control: plain git status runs core.fsmonitor"
    );
    fs::remove_file(&sentinel).unwrap();
    assert_not_executed(&f, &r, &sentinel, "core.fsmonitor");
}

/// Set up a filter driver `evil` (clean, smudge and process) that writes `sentinel`.
fn evil_filter(f: &Fx, r: &Path, script: &Path, scope: &str) {
    let s = script.to_str().unwrap();
    for var in ["clean", "smudge"] {
        f.git(r, &["config", scope, &format!("filter.evil.{var}"), s]);
    }
}

#[test]
fn acceptance_4_clean_filters_via_gitattributes_and_info_attributes_are_never_run() {
    let Some(f) = fx() else { return };
    for (via, setup) in [
        ("worktree .gitattributes", 0),
        (".git/info/attributes", 1),
        ("global attributes and global filter", 2),
    ] {
        let r = f.repo(&format!("r{setup}"));
        let (script, sentinel) = f.sentinel_script(&format!("filter{setup}"));
        match setup {
            0 => {
                evil_filter(&f, &r, &script, "--local");
                fs::write(r.join(".gitattributes"), "* filter=evil\n").unwrap();
            }
            1 => {
                evil_filter(&f, &r, &script, "--local");
                fs::create_dir_all(r.join(".git/info")).unwrap();
                fs::write(r.join(".git/info/attributes"), "* filter=evil\n").unwrap();
            }
            _ => {
                evil_filter(&f, &r, &script, "--global");
                let attrs = f.home.join("global-attributes");
                fs::write(&attrs, "* filter=evil\n").unwrap();
                f.git(
                    &r,
                    &[
                        "config",
                        "--global",
                        "core.attributesFile",
                        attrs.to_str().unwrap(),
                    ],
                );
            }
        }
        f.stat_dirty(&r);
        f.git(&r, &["status", "--porcelain"]);
        assert!(
            sentinel.exists(),
            "control ({via}): plain git status runs the clean filter"
        );
        fs::remove_file(&sentinel).unwrap();
        f.stat_dirty(&r);
        assert_not_executed(&f, &r, &sentinel, via);
        if setup == 2 {
            f.git(&r, &["config", "--global", "--unset", "filter.evil.clean"]);
            f.git(&r, &["config", "--global", "--unset", "filter.evil.smudge"]);
            f.git(
                &r,
                &["config", "--global", "--unset", "core.attributesFile"],
            );
        }
    }
}

#[test]
fn acceptance_4_long_running_process_filters_are_never_started() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (script, sentinel) = f.sentinel_script("process");
    f.git(
        &r,
        &["config", "filter.evil.process", script.to_str().unwrap()],
    );
    f.git(&r, &["config", "filter.evil.required", "true"]);
    fs::create_dir_all(r.join(".git/info")).unwrap();
    fs::write(r.join(".git/info/attributes"), "* filter=evil\n").unwrap();
    f.stat_dirty(&r);
    let _ = f.git_cmd(&r, &["status", "--porcelain"]); // fails (bad protocol) but starts it
    assert!(
        sentinel.exists(),
        "control: plain git status starts the process filter"
    );
    fs::remove_file(&sentinel).unwrap();
    f.stat_dirty(&r);
    assert_not_executed(&f, &r, &sentinel, "filter.<name>.process");
}

#[test]
fn acceptance_4_includes_and_include_if_pulling_in_vectors_are_neutralized() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (fsm, fsm_sentinel) = f.sentinel_script("inc-fsmonitor");
    let (flt, flt_sentinel) = f.sentinel_script("inc-filter");
    let inc = f.root.join("evil.inc");
    fs::write(
        &inc,
        format!(
            "[core]\n\tfsmonitor = {}\n[filter \"incl\"]\n\tclean = {}\n",
            fsm.display(),
            flt.display()
        ),
    )
    .unwrap();
    f.git(&r, &["config", "include.path", inc.to_str().unwrap()]);
    let inc2 = f.root.join("evil2.inc");
    fs::write(
        &inc2,
        format!("[filter \"cond\"]\n\tclean = {}\n", flt.display()),
    )
    .unwrap();
    f.git(
        &r,
        &[
            "config",
            &format!("includeIf.gitdir:{}/.git.path", r.display()),
            inc2.to_str().unwrap(),
        ],
    );
    fs::write(
        r.join(".gitattributes"),
        "*.txt filter=incl\n*.md filter=cond\n",
    )
    .unwrap();
    fs::create_dir_all(r.join(".git/info")).unwrap();
    fs::write(r.join(".git/info/attributes"), "* filter=incl\n").unwrap();
    f.stat_dirty(&r);
    f.git(&r, &["status", "--porcelain"]);
    assert!(
        fsm_sentinel.exists() && flt_sentinel.exists(),
        "control: includes are honoured by plain git"
    );
    fs::remove_file(&fsm_sentinel).unwrap();
    fs::remove_file(&flt_sentinel).unwrap();
    f.stat_dirty(&r);
    assert_not_executed(&f, &r, &fsm_sentinel, "include.path core.fsmonitor");
    assert!(!flt_sentinel.exists(), "include/includeIf filter executed");
}

/// `diff.external`, textconv and the pager are reached only by commands ccwm never runs (`diff`,
/// a terminal); the controls prove the vectors are live. (`core.sshCommand` is reached by
/// `status` through a promisor lazy fetch: see the partial-clone tests below.)
#[test]
fn acceptance_4_diff_external_textconv_and_pager_are_not_reached() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (ext, ext_s) = f.sentinel_script("diff-external");
    let (tc, tc_s) = f.sentinel_script("textconv");
    let (pager, pager_s) = f.sentinel_script("pager");
    f.git(&r, &["config", "diff.external", ext.to_str().unwrap()]);
    f.git(&r, &["config", "diff.tc.textconv", tc.to_str().unwrap()]);
    f.git(&r, &["config", "core.pager", pager.to_str().unwrap()]);
    f.git(&r, &["config", "pager.status", "true"]);
    fs::write(r.join(".gitattributes"), "* diff=tc\n").unwrap();
    fs::write(r.join("file.txt"), "changed\n").unwrap();

    let _ = f.git_cmd(&r, &["diff"]);
    assert!(ext_s.exists(), "control: git diff runs diff.external");
    let _ = f.git_cmd(&r, &["diff", "--no-ext-diff"]);
    assert!(
        tc_s.exists(),
        "control: git diff --textconv runs the textconv driver"
    );
    for s in [&ext_s, &tc_s] {
        fs::remove_file(s).unwrap();
    }
    for (s, what) in [
        (&ext_s, "diff.external"),
        (&tc_s, "textconv"),
        (&pager_s, "core.pager / pager.status"),
    ] {
        assert_not_executed(&f, &r, s, what);
    }
}

impl Fx {
    /// A promisor partial clone whose `HEAD` commit object was removed, so `status` and `log -1`
    /// need an object only the promisor remote has. Returns the repository and the sentinel.
    fn promisor_repo(&self, vector: Promisor) -> (PathBuf, PathBuf) {
        let name = format!("{vector:?}").to_lowercase();
        let r = self.repo(&format!("promisor-{name}"));
        // A helper that records it ran and fails at once (Git must not wait for it).
        let (script, sentinel) = self.sentinel_script_with(&format!("promisor-{name}"), "exit 1");
        common::make_promisor(&r, vector, &script, &|args| self.git(&r, args));
        (r, sentinel)
    }

    /// Plain Git (no ccwm hardening) plus the given environment and options: `status`, then the
    /// `log -1` ccwm runs. Used for controls and to check each defense on its own.
    fn status_and_log_with(&self, dir: &Path, env: &[(&str, &str)], opts: &[&str]) {
        for args in [
            &["status", "--porcelain=v2", "--branch", "-z", "--", "."][..],
            &[
                "log",
                "-1",
                "--no-show-signature",
                "--no-notes",
                "--format=%H",
            ][..],
        ] {
            let mut c = Command::new("git");
            c.env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", &self.home)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("LC_ALL", "C")
                .envs(env.iter().copied())
                .current_dir(dir)
                .args(opts)
                .args(args)
                .stdin(std::process::Stdio::null());
            let _ = c.output().unwrap(); // fails either way: the object is missing
        }
    }
}

/// Security acceptance test 4, promisor vector: with the `HEAD` object missing, plain `status`
/// (a command ccwm runs) lazily fetches through the repository's transport and executes the
/// helper; ccwm's `status`/`log` never do, and report the degraded `partial_clone` state.
#[test]
fn acceptance_4_promisor_lazy_fetch_never_runs_a_transport() {
    let Some(f) = fx() else { return };
    for vector in PROMISORS {
        let (r, sentinel) = f.promisor_repo(vector);
        f.status_and_log_with(&r, &[], &[]);
        assert!(
            sentinel.exists(),
            "control ({vector:?}): plain git status/log runs the promisor transport"
        );
        fs::remove_file(&sentinel).unwrap();
        assert_not_executed(&f, &r, &sentinel, &format!("promisor {vector:?}"));
        let info = f.ccwm_git().inspect(&r);
        assert!(
            !sentinel.exists(),
            "{vector:?}: executed on a second inspection"
        );
        assert_eq!(info.state, State::PartialClone, "{vector:?}");
        assert!(info.worktree.is_none() && info.head.is_none(), "{vector:?}");
        assert_eq!(info.branch.as_deref(), Some("main"), "{vector:?}");
        assert!(
            info.remote_url.is_some(),
            "{vector:?}: the remote is still read"
        );
    }
}

/// Defense in depth: each of the three transport blocks stops every promisor vector on its own
/// (the per-protocol `-c` denies, the empty `GIT_ALLOW_PROTOCOL`, and `GIT_NO_LAZY_FETCH`, the
/// last only where this Git honors it).
#[test]
fn each_transport_block_alone_stops_the_promisor_vectors() {
    let Some(f) = fx() else { return };
    let protocol_denies: Vec<&str> = cc_workspace_manager::git::BASE_ARGS
        .windows(2)
        .filter(|w| w[0] == "-c" && w[1].starts_with("protocol."))
        .flat_map(|w| [w[0], w[1]])
        .collect();
    let honors_no_lazy_fetch = {
        let Some(probe) = fx() else { return };
        let (r, _) = probe.promisor_repo(Promisor::Ext);
        let out = Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &probe.home)
            .env("LC_ALL", "C")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ALLOW_PROTOCOL", "")
            .current_dir(&r)
            .args(["log", "-1"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stderr).contains("lazy fetching disabled")
    };
    if !honors_no_lazy_fetch {
        eprintln!("NOTICE: this Git ignores GIT_NO_LAZY_FETCH; checking the other two blocks only");
    }
    /// One defense: its name, the environment it adds and the options it adds.
    struct Layer<'a> {
        what: &'a str,
        env: Vec<(&'a str, &'a str)>,
        opts: Vec<&'a str>,
    }
    let mut layers = vec![
        Layer {
            what: "-c protocol.<name>.allow=never",
            env: vec![],
            opts: protocol_denies,
        },
        Layer {
            what: "GIT_ALLOW_PROTOCOL=",
            env: vec![("GIT_ALLOW_PROTOCOL", "")],
            opts: vec![],
        },
    ];
    if honors_no_lazy_fetch {
        layers.push(Layer {
            what: "GIT_NO_LAZY_FETCH=1",
            env: vec![("GIT_NO_LAZY_FETCH", "1")],
            opts: vec![],
        });
    }
    for vector in PROMISORS {
        let (r, sentinel) = f.promisor_repo(vector);
        for l in &layers {
            f.status_and_log_with(&r, &l.env, &l.opts);
            assert!(
                !sentinel.exists(),
                "{} alone did not stop {vector:?}",
                l.what
            );
        }
    }
}

#[test]
fn acceptance_4_signature_verification_program_is_never_run() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (gpg, sentinel) = f.sentinel_script("gpg");
    // A commit carrying a (fake) signature header, written without any gpg.
    let tree = f.git(&r, &["rev-parse", "HEAD^{tree}"]);
    let parent = f.git(&r, &["rev-parse", "HEAD"]);
    let body = format!(
        "tree {}\nparent {}\nauthor A <a@example.invalid> 1700000000 +0000\ncommitter A <a@example.invalid> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\nsigned commit\n",
        tree.trim(),
        parent.trim()
    );
    let obj = r.join("commit.obj");
    fs::write(&obj, body).unwrap();
    let id = f.git(
        &r,
        &["hash-object", "-t", "commit", "-w", obj.to_str().unwrap()],
    );
    fs::remove_file(&obj).unwrap();
    f.git(&r, &["update-ref", "refs/heads/main", id.trim()]);
    f.git(&r, &["config", "log.showSignature", "true"]);
    f.git(&r, &["config", "gpg.program", gpg.to_str().unwrap()]);
    let _ = f.git_cmd(&r, &["log", "-1", "--format=%s"]);
    assert!(
        sentinel.exists(),
        "control: git log runs gpg.program with log.showSignature"
    );
    fs::remove_file(&sentinel).unwrap();
    assert_not_executed(&f, &r, &sentinel, "log.showSignature + gpg.program");
    assert_eq!(
        f.ccwm_git().inspect(&r).head.unwrap().subject,
        "signed commit"
    );
}

#[test]
fn acceptance_4_a_filter_name_that_cannot_be_neutralized_disables_status() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    let (script, sentinel) = f.sentinel_script("eqname");
    // `-c filter.x=y.clean=` would set the key `filter.x`, leaving this driver active.
    f.git(
        &r,
        &["config", "filter.x=y.clean", script.to_str().unwrap()],
    );
    fs::create_dir_all(r.join(".git/info")).unwrap();
    fs::write(r.join(".git/info/attributes"), "* filter=x=y\n").unwrap();
    f.stat_dirty(&r);
    f.git(&r, &["status", "--porcelain"]);
    assert!(sentinel.exists(), "control: plain git status runs it");
    fs::remove_file(&sentinel).unwrap();
    f.stat_dirty(&r);
    let info = assert_not_executed(&f, &r, &sentinel, "filter name containing '='");
    assert_eq!(info.state, State::StatusDisabledUnsafeConfig);
    assert!(info.worktree.is_none());
    assert_eq!(info.branch.as_deref(), Some("main"));
}

// ---- v0.1.0 review H1: arbitrary bytes in filter-driver names ------------------------------------

/// A small deterministic generator (xorshift64*): the fuzz-style tests need arbitrary bytes that
/// are the same on every run, not a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A driver name of 1 to 8 pieces: printable ASCII, a multi-byte character, or any byte a
    /// config file can hold in a subsection name (everything but NUL and newline).
    fn driver_name(&mut self) -> Vec<u8> {
        let mut name = Vec::new();
        for _ in 0..=self.below(8) {
            match self.below(4) {
                0 | 1 => name.push(0x21 + self.below(0x5e) as u8),
                2 => {
                    let chars = ['\u{e9}', '\u{65e5}', '\u{fffd}', '\u{1f600}', '\u{85}'];
                    let c = chars[self.below(chars.len() as u64) as usize];
                    name.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                }
                _ => {
                    let b = 1 + self.below(255) as u8;
                    name.push(if b == b'\n' { 0xff } else { b });
                }
            }
        }
        name
    }
}

/// What §6 allows as a `-c filter.<name>.<var>=` override: the name exactly, or nothing.
fn exactly_representable(name: &[u8]) -> bool {
    std::str::from_utf8(name)
        .is_ok_and(|n| !n.is_empty() && !n.contains('=') && !n.chars().any(char::is_control))
}

/// The parser on raw `git config -z` output: a list is returned only when every name survives the
/// round trip unchanged; one name that does not refuses the whole list.
#[test]
fn filter_driver_names_are_exact_or_refused_for_arbitrary_bytes() {
    let mut rng = Rng(0x00c0_ffee_5eed_0001);
    let (mut exact, mut refused) = (0, 0);
    for _ in 0..20_000 {
        let name = rng.driver_name();
        let var = ["clean", "smudge", "process"][rng.below(3) as usize];
        let mut raw = b"filter.lfs.clean\ngit-lfs clean\0filter.".to_vec();
        raw.extend_from_slice(&name);
        raw.extend_from_slice(format!(".{var}\nprogram\0").as_bytes());
        match parse::filter_driver_names(&raw) {
            Some(names) => {
                assert!(exactly_representable(&name), "accepted {name:?}");
                let bytes: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
                assert_eq!(bytes, [b"lfs".as_slice(), name.as_slice()]);
                exact += 1;
            }
            None => {
                assert!(!exactly_representable(&name), "refused {name:?}");
                refused += 1;
            }
        }
    }
    assert!(
        exact > 1_000 && refused > 1_000,
        "{exact} exact, {refused} refused"
    );
}

/// One driver `name` in the repository's own config, selected by `.git/info/attributes` (which
/// `--attr-source` does not neutralize). `base` is the config `git init` wrote.
fn install_named_filter(r: &Path, base: &[u8], name: &[u8], script: &Path) {
    let mut config = base.to_vec();
    config.extend_from_slice(b"[filter \"");
    for b in name {
        if matches!(b, b'"' | b'\\') {
            config.push(b'\\');
        }
        config.push(*b);
    }
    config.extend_from_slice(format!("\"]\n\tclean = {}\n", script.display()).as_bytes());
    fs::write(r.join(".git/config"), config).unwrap();
    let mut attributes = b"* filter=".to_vec();
    attributes.extend_from_slice(name);
    attributes.push(b'\n');
    fs::write(r.join(".git/info/attributes"), attributes).unwrap();
}

/// Security acceptance test 4, fuzz-style (v0.1.0 review H1): a clean filter under a driver name
/// of arbitrary bytes never runs. A name `-c` carries exactly is neutralized (`Ok`); any other
/// name disables worktree status (`status_disabled_unsafe_config`), never an approximated
/// override. Every name has a **control** run with plain `git status`; the counters prove both
/// outcomes were exercised with a vector that is live without the mitigation.
#[test]
fn acceptance_4_filter_driver_names_of_arbitrary_bytes_never_run() {
    let Some(f) = fx() else { return };
    let r = f.repo("r");
    fs::create_dir_all(r.join(".git/info")).unwrap();
    let base = fs::read(r.join(".git/config")).unwrap();
    let (script, sentinel) = f.sentinel_script("fuzzname");

    let mut names: Vec<Vec<u8>> = [
        b"evil".as_slice(),
        b"ev\xffil",               // the review's demonstration: invalid UTF-8
        b"caf\xe9",                // the review's demonstration: Latin-1
        "caf\u{e9}".as_bytes(),    // the same word in UTF-8: representable
        "ev\u{fffd}il".as_bytes(), // what a lossy decode of `ev\xffil` would have named
        b"x=y",
        b"a\x1bb",
        b"a\x7fb",
        b"\xc3",
        b"\xf0\x9f\x98",
        b"with\"quote",
        b"back\\slash",
        b"a.b.clean",
        b"-c",
        b"'$(touch x)'",
    ]
    .iter()
    .map(|n| n.to_vec())
    .collect();
    let mut rng = Rng(0x00c0_ffee_5eed_0002);
    names.extend((0..150).map(|_| rng.driver_name()));

    // Live controls per outcome: [neutralized, refused as not UTF-8, refused for another reason].
    let mut live = [0usize; 3];
    for name in &names {
        let what = format!("filter driver named {:?}", String::from_utf8_lossy(name));
        install_named_filter(&r, &base, name, &script);

        // Control: does plain Git run this driver? (Not for every name: an attribute value ends
        // at white space, so such a name cannot be selected.)
        f.stat_dirty(&r);
        let control = f.git_cmd(&r, &["status", "--porcelain"]);
        assert!(control.status.success(), "control for the {what} failed");
        let is_live = sentinel.exists();
        let _ = fs::remove_file(&sentinel);

        f.stat_dirty(&r);
        let info = assert_not_executed(&f, &r, &sentinel, &what);
        let class = if exactly_representable(name) {
            assert_eq!(info.state, State::Ok, "{what}");
            assert!(info.worktree.is_some(), "{what}");
            0
        } else {
            assert_eq!(info.state, State::StatusDisabledUnsafeConfig, "{what}");
            assert!(info.worktree.is_none(), "{what}");
            assert_eq!(info.branch.as_deref(), Some("main"), "{what}");
            if std::str::from_utf8(name).is_err() {
                1
            } else {
                2
            }
        };
        live[class] += usize::from(is_live);
    }
    assert!(
        live.iter().all(|n| *n >= 5),
        "too few live controls (neutralized, not UTF-8, otherwise refused): {live:?}"
    );
}
