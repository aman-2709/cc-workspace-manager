//! Marker discovery over synthetic directory trees.

mod common;

use cc_workspace_manager::discovery::status::{Phase, SharedStatus};
use cc_workspace_manager::discovery::walk::{scan, Candidate, ScanOptions, ScanSummary};
use common::snapshot;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

struct Fixture {
    _t: tempfile::TempDir,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap().join("home");
    fs::create_dir(&home).unwrap();
    Fixture { _t: t, home }
}

impl Fixture {
    fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.home.join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }
    fn marker(&self, rel: &str) -> PathBuf {
        let d = self.mkdir(rel);
        fs::write(d.join("CLAUDE.md"), "# x\n").unwrap();
        d
    }
    fn git(&self, rel: &str) {
        fs::create_dir_all(self.home.join(rel).join(".git")).unwrap();
    }
    fn opts(&self) -> ScanOptions {
        ScanOptions {
            roots: vec![self.home.clone()],
            exclude: vec![],
            max_depth: 10,
            same_file_system: true,
            home: self.home.clone(),
            boundaries: vec![],
            fuse_mounts: vec![],
        }
    }
    fn run(&self, opts: &ScanOptions) -> (Vec<String>, ScanSummary) {
        let (c, s, _) = self.run_full(opts);
        (c, s)
    }
    fn run_full(&self, opts: &ScanOptions) -> (Vec<String>, ScanSummary, Vec<usize>) {
        let mut batches = Vec::new();
        let mut all: Vec<Candidate> = Vec::new();
        let status = SharedStatus::default();
        let summary = scan(opts, &AtomicBool::new(false), &status, &mut |b| {
            batches.push(b.len());
            all.extend(b);
            true
        });
        assert_eq!(status.snapshot().phase, Phase::Idle);
        let home = self.home.to_str().unwrap().to_string();
        let rel = all
            .into_iter()
            .map(|c| {
                c.canonical_path
                    .strip_prefix(&home)
                    .map(|r| r.trim_start_matches('/').to_string())
                    .unwrap_or(c.canonical_path)
            })
            .collect();
        (rel, summary, batches)
    }
}

#[test]
fn finds_exact_markers_only() {
    let f = fixture();
    f.marker("alpha");
    f.marker("deep/er/beta");
    let d = f.mkdir("lower");
    fs::write(d.join("claude.md"), "x").unwrap();
    let d = f.mkdir("upper");
    fs::write(d.join("CLAUDE.MD"), "x").unwrap();
    let d = f.mkdir("dirnamed");
    fs::create_dir(d.join("CLAUDE.md")).unwrap();
    let d = f.mkdir("agents");
    fs::write(d.join("AGENTS.md"), "x").unwrap();
    let (found, s) = f.run(&f.opts());
    assert_eq!(found, ["alpha", "deep/er/beta"]);
    assert_eq!(s.projects_found, 2);
}

#[test]
fn a_directory_named_claude_md_is_still_walked() {
    let f = fixture();
    let d = f.mkdir("odd");
    fs::create_dir(d.join("CLAUDE.md")).unwrap();
    fs::write(d.join("CLAUDE.md").join("CLAUDE.md"), "x").unwrap();
    let (found, _) = f.run(&f.opts());
    assert_eq!(found, ["odd/CLAUDE.md"]);
}

#[test]
fn home_itself_is_never_a_project_but_its_children_are() {
    let f = fixture();
    fs::write(f.home.join("CLAUDE.md"), "x").unwrap();
    f.marker("proj");
    let (found, _) = f.run(&f.opts());
    assert_eq!(found, ["proj"]);
}

#[test]
fn hidden_default_excluded_and_user_excluded_directories_are_pruned() {
    let f = fixture();
    for d in [
        ".cache/p",
        ".claude/p",
        ".hidden/p",
        "node_modules/p",
        "target/p",
        "build/p",
        "dist/p",
        "venv/p",
        "__pycache__/p",
        "VirtualBox VMs/p",
        "snap/p",
        "vendor/p",
    ] {
        f.marker(d);
    }
    f.marker("work/snap/ok"); // `snap` is only excluded directly under home
    f.marker("keep");
    let mut o = f.opts();
    o.exclude = vec!["vendor/".into()];
    let (found, s) = f.run(&o);
    assert_eq!(found, ["keep", "work/snap/ok"]);
    assert!(s.skipped.excluded >= 11);
}

#[test]
fn nested_projects_follow_the_git_root_rule() {
    let f = fixture();
    // A (non-git) containing B (non-git): B is an instruction file of A.
    f.marker("a");
    f.marker("a/b");
    // C (git) containing D (no git): D belongs to C.
    f.marker("c");
    f.git("c");
    f.marker("c/d");
    // E (non-git) containing F (own git root): F is separate.
    f.marker("e");
    f.marker("e/f");
    f.git("e/f");
    // G (git) containing H (own git root): H is separate.
    f.marker("g");
    f.git("g");
    f.marker("g/h");
    f.git("g/h");
    // Deeper descendant of a registered project is still nested.
    f.marker("a/x/y/z");
    let (found, _) = f.run(&f.opts());
    assert_eq!(found, ["a", "c", "e", "e/f", "g", "g/h"]);
}

#[test]
fn nested_decision_does_not_depend_on_directory_entry_order() {
    // "Abc" sorts before "CLAUDE.md" in byte order: the child must still see its parent as a project.
    let f = fixture();
    f.marker("p");
    f.marker("p/Abc");
    f.marker("p/zzz");
    let (found, _) = f.run(&f.opts());
    assert_eq!(found, ["p"]);
}

#[test]
fn symlinked_marker_rules() {
    let f = fixture();
    // inside the same directory: accepted
    let d = f.mkdir("ok");
    fs::write(d.join("AGENTS.md"), "x").unwrap();
    symlink("AGENTS.md", d.join("CLAUDE.md")).unwrap();
    // target in a subdirectory of the project: accepted
    let d = f.mkdir("ok2");
    fs::create_dir(d.join("docs")).unwrap();
    fs::write(d.join("docs/c.md"), "x").unwrap();
    symlink("docs/c.md", d.join("CLAUDE.md")).unwrap();
    // escapes via ..: rejected
    let d = f.mkdir("escape");
    fs::write(f.home.join("outside.md"), "x").unwrap();
    symlink("../outside.md", d.join("CLAUDE.md")).unwrap();
    // absolute outside: rejected
    let d = f.mkdir("abs");
    symlink("/etc/hostname", d.join("CLAUDE.md")).unwrap();
    // points at a directory: rejected
    let d = f.mkdir("todir");
    fs::create_dir(d.join("sub")).unwrap();
    symlink("sub", d.join("CLAUDE.md")).unwrap();
    // dangling: rejected
    let d = f.mkdir("dangling");
    symlink("missing.md", d.join("CLAUDE.md")).unwrap();
    // loop: rejected
    let d = f.mkdir("loop");
    symlink("CLAUDE.md", d.join("CLAUDE.md")).unwrap();
    // two-step chain that leaves the directory: rejected
    let d = f.mkdir("chain");
    symlink("../outside.md", d.join("hop")).unwrap();
    symlink("hop", d.join("CLAUDE.md")).unwrap();
    let (found, s) = f.run(&f.opts());
    assert_eq!(found, ["ok", "ok2"]);
    assert_eq!(s.skipped.rejected_markers, 6);
}

#[test]
fn symlinked_directories_are_not_followed_and_loops_terminate() {
    let f = fixture();
    let target = f.marker("real");
    symlink(&target, f.home.join("link-to-real")).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::write(elsewhere.path().join("CLAUDE.md"), "x").unwrap();
    symlink(elsewhere.path(), f.home.join("link-out")).unwrap();
    let d = f.mkdir("loopy");
    symlink(&f.home, d.join("up")).unwrap();
    symlink(".", d.join("self")).unwrap();
    let (found, _) = f.run(&f.opts());
    assert_eq!(found, ["real"]);
}

#[test]
fn non_utf8_names_are_skipped_and_counted() {
    let f = fixture();
    let bad = f.home.join(OsStr::from_bytes(b"bad-\xff-name"));
    fs::create_dir(&bad).unwrap();
    fs::write(bad.join("CLAUDE.md"), "x").unwrap();
    f.marker("good");
    let (found, s) = f.run(&f.opts());
    assert_eq!(found, ["good"]);
    assert_eq!(s.skipped.non_utf8, 1);
}

#[test]
fn max_depth_limits_the_walk() {
    let f = fixture();
    f.marker("a/b/c");
    f.marker("one");
    let mut o = f.opts();
    o.max_depth = 2;
    assert_eq!(f.run(&o).0, ["one"]);
    o.max_depth = 3;
    assert_eq!(f.run(&o).0, ["a/b/c", "one"]);
}

#[test]
fn unreadable_directories_are_counted_and_do_not_abort() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let f = fixture();
    f.marker("good");
    let locked = f.mkdir("locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let (found, s) = f.run(&f.opts());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(found, ["good"]);
    assert_eq!(s.skipped.permission, 1);
}

#[test]
fn hard_boundaries_reject_roots_and_prune_inside_trees() {
    let f = fixture();
    f.marker("good");
    let ccwm = f.mkdir("ccwm-data");
    fs::write(ccwm.join("CLAUDE.md"), "x").unwrap();
    let mut o = f.opts();
    o.boundaries = vec![ccwm.clone()];
    assert_eq!(f.run(&o).0, ["good"]);

    let status = SharedStatus::default();
    let mut o2 = f.opts();
    o2.roots = vec![PathBuf::from("/proc"), ccwm.clone()];
    o2.boundaries = vec![PathBuf::from("/proc"), ccwm];
    let s = scan(&o2, &AtomicBool::new(false), &status, &mut |_| true);
    assert_eq!(s.dirs_visited, 0);
    let snap = status.snapshot();
    assert!(
        snap.roots.iter().all(|r| r.state == "forbidden"),
        "{:?}",
        snap.roots
    );
}

#[test]
fn roots_outside_home_missing_roots_and_overlaps() {
    let f = fixture();
    let ext = tempfile::tempdir().unwrap();
    let ext_p = fs::canonicalize(ext.path()).unwrap();
    fs::create_dir(ext_p.join("p")).unwrap();
    fs::write(ext_p.join("p/CLAUDE.md"), "x").unwrap();
    f.marker("inside");
    let file_root = f.home.join("file");
    fs::write(&file_root, "x").unwrap();
    let mut o = f.opts();
    o.roots = vec![
        f.home.clone(),
        ext_p.clone(),
        f.home.join("inside"),
        f.home.join("nope"),
        file_root,
    ];
    let status = SharedStatus::default();
    let mut found = Vec::new();
    scan(&o, &AtomicBool::new(false), &status, &mut |b| {
        found.extend(b.into_iter().map(|c| c.canonical_path));
        true
    });
    found.sort();
    let mut expected = vec![
        f.home.join("inside").to_str().unwrap().to_string(),
        ext_p.join("p").to_str().unwrap().to_string(),
    ];
    expected.sort();
    assert_eq!(found, expected);
    let states: Vec<_> = status.snapshot().roots.iter().map(|r| r.state).collect();
    assert_eq!(states, ["ok", "ok", "ok", "missing", "not_a_directory"]);
}

#[test]
fn an_explicit_root_that_is_itself_a_project_is_registered() {
    let f = fixture();
    let p = f.marker("solo");
    let mut o = f.opts();
    o.roots = vec![p];
    assert_eq!(f.run(&o).0, ["solo"]);
}

#[test]
fn candidates_stream_in_batches_and_status_tracks_progress() {
    let f = fixture();
    for i in 0..150 {
        f.marker(&format!("p{i:03}"));
    }
    let (found, s, batches) = f.run_full(&f.opts());
    assert_eq!(found.len(), 150);
    assert_eq!(s.projects_found, 150);
    assert!(
        batches.len() >= 3 && batches.iter().all(|&n| n <= 64),
        "{batches:?}"
    );
    assert!(s.dirs_visited >= 151);
}

#[test]
fn cancel_flag_and_sink_failure_stop_the_scan() {
    let f = fixture();
    for i in 0..200 {
        f.marker(&format!("p{i:03}"));
    }
    let cancel = AtomicBool::new(true);
    let s = scan(&f.opts(), &cancel, &SharedStatus::default(), &mut |_| true);
    assert!(s.cancelled && s.projects_found == 0);

    let mut calls = 0;
    let s = scan(
        &f.opts(),
        &AtomicBool::new(false),
        &SharedStatus::default(),
        &mut |_| {
            calls += 1;
            false
        },
    );
    assert!(s.cancelled);
    assert_eq!(calls, 1);
    assert!(s.projects_found < 200);
}

#[test]
fn discovery_never_modifies_the_tree() {
    // Security acceptance test 1 (discovery part): hash every entry, including mtimes and modes.
    let f = fixture();
    f.marker("a");
    f.marker("a/b");
    f.git("a/b");
    f.marker(".hidden/x");
    f.mkdir("node_modules/m");
    symlink("CLAUDE.md", f.home.join("a").join("link")).unwrap();
    let before = snapshot(&f.home);
    f.run(&f.opts());
    f.run(&f.opts());
    assert_eq!(snapshot(&f.home), before);
}

#[test]
fn the_synthetic_environment_yields_exactly_the_expected_projects() {
    let t = tempfile::tempdir().unwrap();
    let env = cc_workspace_manager::synth::generate(&t.path().join("e"), 25).unwrap();
    let before = snapshot(&env.root);
    let opts = ScanOptions {
        roots: vec![env.home.clone()],
        exclude: vec![],
        max_depth: 10,
        same_file_system: true,
        home: env.home.clone(),
        boundaries: vec![],
        fuse_mounts: vec![],
    };
    let mut found = Vec::new();
    let s = scan(
        &opts,
        &AtomicBool::new(false),
        &SharedStatus::default(),
        &mut |b| {
            found.extend(b.into_iter().map(|c| {
                c.canonical_path
                    .strip_prefix(env.home.to_str().unwrap())
                    .unwrap()
                    .trim_start_matches('/')
                    .to_string()
            }));
            true
        },
    );
    found.sort();
    assert_eq!(found, env.expected_projects(25));
    assert!(
        s.skipped.rejected_markers >= 2,
        "escaping symlinked markers are rejected: {:?}",
        s.skipped
    );
    assert_eq!(
        snapshot(&env.root),
        before,
        "discovery must not modify the environment (acceptance test 1)"
    );
}

#[test]
fn roots_that_reach_a_hard_boundary_by_dotdot_or_symlink_are_forbidden() {
    // Security acceptance test 7 (path traversal and symlink escapes), root inputs.
    let f = fixture();
    let sneaky = f.mkdir("a/b");
    let dotdot = sneaky.join("../../../../../../../../proc");
    symlink("/proc", f.home.join("proc-link")).unwrap();
    symlink("/sys/kernel", f.home.join("sys-link")).unwrap();
    for root in [
        dotdot,
        f.home.join("proc-link"),
        f.home.join("sys-link"),
        PathBuf::from("/proc/self/../self"),
        PathBuf::from("/dev/./"),
    ] {
        let mut o = f.opts();
        o.roots = vec![root.clone()];
        o.boundaries = ["/proc", "/sys", "/dev", "/run"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let status = SharedStatus::default();
        let s = scan(&o, &AtomicBool::new(false), &status, &mut |_| true);
        assert_eq!(s.dirs_visited, 0, "{} was walked", root.display());
        assert_eq!(
            status.snapshot().roots[0].state,
            "forbidden",
            "{}",
            root.display()
        );
    }
}

/// L7: Claude Code's config directory is a hard boundary even when it is not hidden, with the
/// boundaries built exactly as the daemon builds them.
#[test]
fn a_non_hidden_claude_config_dir_and_xdg_dirs_inside_home_are_hard_boundaries() {
    use cc_workspace_manager::paths::{session_dir, Dirs, EnvVars};
    let f = fixture();
    f.marker("dev/real");
    let env = EnvVars {
        xdg_config_home: Some(f.home.join("xdg-config").into()),
        xdg_data_home: Some(f.home.join("xdg-data").into()),
        xdg_state_home: Some(f.home.join("xdg-state").into()),
        xdg_runtime_dir: Some(f.home.join("xdg-run").into()),
        claude_config_dir: Some(f.home.join("claude-cfg").into()),
    };
    let dirs = Dirs::resolve(&env, &f.home);
    let claude = session_dir(&env, &f.home);
    for d in dirs.all() {
        f.marker(d.strip_prefix(&f.home).unwrap().to_str().unwrap());
    }
    f.marker("claude-cfg");
    f.marker("claude-cfg/projects/-x");
    f.marker("xdg-config/other-app"); // not ccwm's: an ordinary directory
    let mut o = f.opts();
    o.boundaries = dirs.hard_boundaries(&claude);
    let (mut found, s) = f.run(&o);
    found.sort();
    assert_eq!(found, ["dev/real", "xdg-config/other-app"]);
    assert!(s.skipped.excluded >= 5, "{:?}", s.skipped);

    // The same through a symlinked spelling of CLAUDE_CONFIG_DIR (boundaries are canonicalized).
    symlink(f.home.join("claude-cfg"), f.home.join("cfg-link")).unwrap();
    let mut o = f.opts();
    o.boundaries = dirs.hard_boundaries(&f.home.join("cfg-link"));
    let (found, _) = f.run(&o);
    assert!(
        !found.iter().any(|p| p.starts_with("claude-cfg")),
        "{found:?}"
    );

    // A root inside the Claude config directory is refused outright.
    let mut o = f.opts();
    o.roots = vec![f.home.join("claude-cfg/projects")];
    o.boundaries = dirs.hard_boundaries(&claude);
    let status = SharedStatus::default();
    scan(&o, &AtomicBool::new(false), &status, &mut |_| true);
    assert_eq!(status.snapshot().roots[0].state, "forbidden");
}

/// Acceptance test 1 for the inside-home layout, through the scanner alone.
#[test]
fn the_inside_home_synthetic_layout_yields_exactly_the_expected_projects() {
    use cc_workspace_manager::paths::{session_dir, Dirs, EnvVars};
    use cc_workspace_manager::synth::{generate_with, Layout};
    let t = tempfile::tempdir().unwrap();
    let env = generate_with(&t.path().join("e"), 3, Layout::InsideHome).unwrap();
    let vars = EnvVars {
        xdg_config_home: Some(env.config_home.clone().into()),
        xdg_data_home: Some(env.data_home.clone().into()),
        xdg_state_home: Some(env.state_home.clone().into()),
        xdg_runtime_dir: Some(env.runtime_dir.clone().into()),
        claude_config_dir: Some(env.claude_dir.clone().into()),
    };
    let dirs = Dirs::resolve(&vars, &env.home);
    let before = snapshot(&env.root);
    let opts = ScanOptions {
        roots: vec![env.home.clone()],
        exclude: vec![],
        max_depth: 10,
        same_file_system: true,
        home: env.home.clone(),
        boundaries: dirs.hard_boundaries(&session_dir(&vars, &env.home)),
        fuse_mounts: vec![],
    };
    let mut found = Vec::new();
    scan(
        &opts,
        &AtomicBool::new(false),
        &SharedStatus::default(),
        &mut |b| {
            found.extend(b.into_iter().map(|c| {
                c.canonical_path
                    .strip_prefix(env.home.to_str().unwrap())
                    .unwrap()
                    .trim_start_matches('/')
                    .to_string()
            }));
            true
        },
    );
    found.sort();
    assert_eq!(found, env.expected_projects(3));
    assert_eq!(snapshot(&env.root), before);
}

/// Test 7 / M3: another user swaps walked directories for symlinks to somewhere else, as fast as
/// possible, while discovery runs. The walk must never enter a symlink's target. (Probabilistic by
/// nature; with the old path-based walk this fails within the first few hundred scans. The
/// deterministic version of the race is in `discovery::dirfd` unit tests.)
#[test]
fn a_directory_swapped_for_a_symlink_during_the_walk_is_never_followed() {
    use nix::fcntl::{renameat2, RenameFlags, AT_FDCWD};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    const PAIRS: usize = 8;
    let f = fixture();
    let outside = f.home.parent().unwrap().join("outside");
    fs::create_dir_all(outside.join("only-outside")).unwrap();
    fs::write(outside.join("only-outside/CLAUDE.md"), "x").unwrap();
    let stash = f.mkdir(".stash");
    let mut pairs = Vec::new();
    for p in 0..PAIRS {
        f.marker(&format!("shared/sub{p}/inner"));
        for i in 0..10 {
            f.mkdir(&format!("shared/sub{p}/inner/d{i}"));
        }
        symlink(&outside, stash.join(format!("sub{p}"))).unwrap();
        pairs.push((
            f.home.join(format!("shared/sub{p}")),
            stash.join(format!("sub{p}")),
        ));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut swaps = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for (a, b) in &pairs {
                    // Atomic exchange: each name is always the real directory or the symlink.
                    if renameat2(AT_FDCWD, a, AT_FDCWD, b, RenameFlags::RENAME_EXCHANGE).is_ok() {
                        swaps += 1;
                    }
                }
            }
            swaps
        })
    };
    let mut changed = 0;
    for _ in 0..3000 {
        let (found, s) = f.run(&f.opts());
        assert!(
            found.iter().all(|p| !p.contains("only-outside")),
            "the walk followed a swapped-in symlink: {found:?}"
        );
        changed += s.skipped.changed;
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = swapper.join().unwrap();
    assert!(swaps > 0, "the swapper never ran");
    eprintln!("swaps={swaps} changed-directory skips observed={changed}");
}
