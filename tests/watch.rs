//! The watch engine (REQUIREMENTS.md §5.1/§5.2, §16 "Monitoring") with a recording fake backend,
//! so every rule is exercised deterministically and without using an inotify instance (this host
//! has very few left). The real inotify path is covered by `tests/tracker.rs` and `tests/process.rs`.

use cc_workspace_manager::clock::FakeClock;
use cc_workspace_manager::discovery::exclusions::Exclusions;
use cc_workspace_manager::watch::tree::{self, TreeOptions};
use cc_workspace_manager::watch::{
    Cmd, Monitor, Monitoring, Owner, PollReason, Settings, SharedMonitor, Signal, WatchBackend,
    WatchError, WatchProject,
};
use notify::event::{CreateKind, DataChange, EventKind, ModifyKind, RemoveKind, RenameMode};
use notify::Event;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Records watches; fails with `KernelLimit` once `kernel_max` watches exist. `attempts` counts
/// every call, refused or not.
#[derive(Clone, Default)]
struct Fake {
    watched: Arc<Mutex<HashSet<PathBuf>>>,
    kernel_max: Option<usize>,
    attempts: Arc<std::sync::atomic::AtomicUsize>,
}

impl WatchBackend for Fake {
    fn watch(&mut self, dir: &Path) -> Result<(), WatchError> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut w = self.watched.lock().unwrap();
        if self.kernel_max.is_some_and(|m| w.len() >= m) {
            return Err(WatchError::KernelLimit);
        }
        w.insert(dir.to_path_buf());
        Ok(())
    }
    fn unwatch(&mut self, dir: &Path) {
        self.watched.lock().unwrap().remove(dir);
    }
}

struct Fx {
    _t: tempfile::TempDir,
    home: PathBuf,
    monitor: Monitor,
    signals: mpsc::Receiver<Signal>,
    cmds: mpsc::Receiver<Cmd>,
    shared: SharedMonitor,
    fake: Fake,
}

const DEBOUNCE: Duration = Duration::from_millis(50);

fn mkfile(p: &Path) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, "x").unwrap();
}

fn fx_with(budget: usize, fake: Option<Fake>) -> Fx {
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap().join("home");
    fs::create_dir_all(&home).unwrap();
    let (sig_tx, signals) = mpsc::channel(1024);
    let (cmd_tx, cmds) = mpsc::channel(1024);
    let shared = SharedMonitor::default();
    let settings = Settings {
        roots: vec![home.clone()],
        home: home.clone(),
        exclude: vec![],
        boundaries: vec![],
        fuse_mounts: vec![],
        max_depth: 10,
        same_file_system: true,
        budget,
        max_user_watches: Some(65_536),
        debounce: DEBOUNCE,
        events_per_project: 200,
    };
    let backend = fake.clone().map(|f| Box::new(f) as Box<dyn WatchBackend>);
    let monitor = Monitor::new(
        backend,
        settings,
        Arc::new(FakeClock::new(1_000)),
        sig_tx,
        cmd_tx,
        shared.clone(),
        None,
    );
    Fx {
        _t: t,
        home,
        monitor,
        signals,
        cmds,
        shared,
        fake: fake.unwrap_or_default(),
    }
}

fn fx() -> Fx {
    fx_with(1000, Some(Fake::default()))
}

impl Fx {
    /// A project with `CLAUDE.md`, a `.git` directory and the given extra files.
    fn project(&self, rel: &str, files: &[&str]) -> PathBuf {
        let root = self.home.join(rel);
        mkfile(&root.join("CLAUDE.md"));
        fs::create_dir_all(root.join(".git")).unwrap();
        for f in files {
            mkfile(&root.join(f));
        }
        root
    }

    fn tree(&self, root: &Path, others: &[PathBuf]) -> tree::Tree {
        let ex = Exclusions::new(&self.home, &self.home, &[], &[], &[]).unwrap();
        let others: HashSet<PathBuf> = others.iter().cloned().collect();
        tree::walk(
            root,
            &TreeOptions {
                exclusions: &ex,
                other_projects: &others,
                max_depth: 10,
                same_file_system: true,
                git_aware: true,
                repo_root: None,
                now: i64::MAX,
                max_entries: tree::MAX_ENTRIES,
            },
        )
        .unwrap()
    }

    fn plan(&mut self, projects: &[(&str, &Path)]) {
        let roots: Vec<PathBuf> = projects.iter().map(|(_, p)| p.to_path_buf()).collect();
        let plan = projects
            .iter()
            .map(|(id, root)| {
                let others: Vec<PathBuf> = roots.iter().filter(|r| r != root).cloned().collect();
                WatchProject {
                    id: (*id).to_string(),
                    tree: self.tree(root, &others),
                }
            })
            .collect();
        self.monitor.on_cmd(Cmd::Plan(plan));
    }

    fn event(&mut self, kind: EventKind, paths: &[&Path]) {
        let mut e = Event::new(kind);
        for p in paths {
            e = e.add_path(p.to_path_buf());
        }
        self.monitor.on_raw(Ok(e));
    }

    fn modify(&mut self, p: &Path) {
        self.event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            &[p],
        );
    }

    /// Flush everything due (as if the debounce window had passed) and collect the signals.
    fn flush(&mut self) -> Vec<Signal> {
        self.monitor
            .flush_due(Instant::now() + Duration::from_secs(5));
        let mut out = Vec::new();
        while let Ok(s) = self.signals.try_recv() {
            out.push(s);
        }
        out
    }

    fn watched(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .monitor
            .watched_dirs()
            .into_iter()
            .map(|(p, _)| {
                p.strip_prefix(&self.home)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        v.sort();
        v
    }

    /// Process the monitor's own follow-up commands (finished walks of new directories).
    async fn drain_cmds(&mut self) {
        while let Ok(Some(c)) =
            tokio::time::timeout(Duration::from_millis(500), self.cmds.recv()).await
        {
            self.monitor.on_cmd(c);
        }
    }
}

fn activity(signals: &[Signal]) -> Vec<(String, Option<String>, usize, bool)> {
    signals
        .iter()
        .filter_map(|s| match s {
            Signal::Activity {
                id,
                path,
                events,
                git,
                ..
            } => Some((id.clone(), path.clone(), events.len(), *git)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn non_recursive_watches_only_on_eligible_directories() {
    let mut f = fx();
    let p = f.project(
        "dev/p",
        &[
            "src/a.rs",
            "src/deep/b.rs",
            "node_modules/x/y.js",
            ".cache/c",
            "out/gen",
            "nested/CLAUDE.md",
        ],
    );
    fs::write(p.join(".gitignore"), "out/\n").unwrap();
    let nested = p.join("nested");
    fs::create_dir_all(nested.join(".git")).unwrap();
    fs::create_dir_all(nested.join("lib")).unwrap();
    f.plan(&[("p", &p), ("n", &nested)]);
    assert_eq!(
        f.watched(),
        [
            "dev",
            "dev/p",
            "dev/p/.git",
            "dev/p/nested",
            "dev/p/nested/.git",
            "dev/p/nested/lib",
            "dev/p/src",
            "dev/p/src/deep",
        ]
    );
    let owners: Vec<(PathBuf, Owner)> = f.monitor.watched_dirs();
    let owner_of = |rel: &str| {
        owners
            .iter()
            .find(|(d, _)| d == &f.home.join(rel))
            .map(|(_, o)| o.clone())
    };
    assert_eq!(owner_of("dev"), Some(Owner::Parent(0)));
    assert_eq!(
        owner_of("dev/p/nested/lib"),
        Some(Owner::Project("n".into()))
    );
    assert_eq!(owner_of("dev/p/src"), Some(Owner::Project("p".into())));
    assert_eq!(
        f.fake.watched.lock().unwrap().len(),
        8,
        "one backend watch each, nothing recursive"
    );
    let st = f.shared.snapshot();
    assert_eq!(
        (
            st.watches,
            st.watched_projects,
            st.polled_projects,
            st.degraded
        ),
        (8, 2, 0, false)
    );
    assert_eq!(f.shared.of("p"), Some((Monitoring::Watched, None)));
}

impl Fx {
    fn mode(&self, id: &str) -> (Monitoring, Option<PollReason>) {
        self.shared.of(id).unwrap()
    }

    /// Unwatched subtree roots of a partly watched project, relative to the home directory.
    fn subtrees(&self, id: &str) -> Vec<String> {
        self.shared
            .poll_target(id)
            .map(|t| {
                t.subtrees
                    .iter()
                    .map(|d| {
                        d.strip_prefix(&self.home)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[tokio::test]
async fn the_budget_goes_breadth_first_and_only_unwatched_subtrees_are_polled() {
    // Budget 3: both roots and their parent. Both projects are *partly* watched (live at the
    // root), not polled as a whole; the unwatched subtrees are what reconciliation checks.
    let mut f = fx_with(3, Some(Fake::default()));
    let a = f.project("a", &["s1/x", "s2/deep/y"]);
    let b = f.project("b", &["s1/x"]);
    f.plan(&[("a", &a), ("b", &b)]); // `a` is the most recently active (first)
    assert_eq!(f.watched(), ["", "a", "b"]);
    assert_eq!(f.mode("a"), (Monitoring::Partial, Some(PollReason::Budget)));
    assert_eq!(f.mode("b"), (Monitoring::Partial, Some(PollReason::Budget)));
    assert_eq!(
        f.subtrees("a"),
        ["a/.git", "a/s1", "a/s2"],
        "a/s2/deep is inside a/s2"
    );
    assert_eq!(f.subtrees("b"), ["b/.git", "b/s1"]);
    let st = f.shared.snapshot();
    assert!(st.degraded);
    assert_eq!(
        (st.watched_projects, st.partial_projects, st.polled_projects),
        (0, 2, 0)
    );
    assert!(
        st.advice.iter().any(|a| a.contains("budget")),
        "{:?}",
        st.advice
    );

    // Room for every root, the parent and every top-level directory, not for `a/s2/deep`.
    let mut f = fx_with(8, Some(Fake::default()));
    let a = f.project("a", &["s1/x", "s2/deep/y"]);
    let b = f.project("b", &["s1/x"]);
    f.plan(&[("a", &a), ("b", &b)]);
    assert_eq!(
        f.mode("b"),
        (Monitoring::Watched, None),
        "b's top level fits before a's depth"
    );
    assert_eq!(f.mode("a"), (Monitoring::Partial, Some(PollReason::Budget)));
    assert_eq!(f.subtrees("a"), ["a/s2/deep"]);
    assert!(f.shared.poll_target("b").is_none());
}

#[tokio::test]
async fn deeper_directories_go_to_the_most_recent_project_first() {
    // Roots 2 + parent 1 + top level (.git, d) 2 each = 7; one more for the deeper level.
    let mut f = fx_with(8, Some(Fake::default()));
    let old = f.project("old", &["d/e/x"]);
    let new = f.project("new", &["d/e/x"]);
    f.plan(&[("new", &new), ("old", &old)]);
    assert_eq!(f.mode("new"), (Monitoring::Watched, None));
    assert_eq!(
        f.mode("old"),
        (Monitoring::Partial, Some(PollReason::Budget))
    );
    assert_eq!(f.subtrees("old"), ["old/d/e"]);
}

/// The real-home failure: one huge project used to take the whole budget and every other
/// project was polled. Now every small project gets its root and top-level directories first.
#[tokio::test]
async fn one_huge_project_cannot_starve_the_small_ones() {
    let mut f = fx_with(150, Some(Fake::default()));
    let mut files: Vec<String> = (0..50).map(|i| format!("d{i:02}/a/b/c/f")).collect();
    files.push("top.txt".into());
    let refs: Vec<&str> = files.iter().map(String::as_str).collect();
    let huge = f.project("dev/huge", &refs); // 1 + .git + 50 + 150 directories
    let small: Vec<PathBuf> = (0..20)
        .map(|i| f.project(&format!("dev/small{i:02}"), &["src/x"]))
        .collect();
    let ids: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
    let mut plan: Vec<(&str, &Path)> = vec![("huge", &huge)]; // the most recent
    plan.extend(
        ids.iter()
            .map(String::as_str)
            .zip(small.iter().map(PathBuf::as_path)),
    );
    f.plan(&plan);

    for id in &ids {
        assert_eq!(f.mode(id), (Monitoring::Watched, None), "{id}");
    }
    assert_eq!(
        f.mode("huge"),
        (Monitoring::Partial, Some(PollReason::Budget))
    );
    let w = f.watched();
    assert_eq!(w.len(), 150);
    for i in 0..50 {
        assert!(
            w.contains(&format!("dev/huge/d{i:02}")),
            "top level d{i:02} of the huge project"
        );
    }
    let subtrees = f.subtrees("huge");
    assert!(!subtrees.is_empty());
    for s in &subtrees {
        assert!(!w.contains(s), "{s} is watched but listed as unwatched");
        assert!(
            Path::new(s).components().count() >= 4,
            "only deeper levels: {s}"
        );
        assert!(
            !subtrees
                .iter()
                .any(|o| o != s && Path::new(s).starts_with(o)),
            "{s} is inside another listed subtree"
        );
    }
    let st = f.shared.snapshot();
    assert_eq!(
        (st.watched_projects, st.partial_projects, st.polled_projects),
        (20, 1, 0)
    );
}

#[tokio::test]
async fn retrying_unwatched_subtrees_settles_the_project_once_they_fit() {
    let mut f = fx_with(5, Some(Fake::default()));
    let a = f.project("a", &["s1/x"]);
    let b = f.project("b", &[]);
    f.plan(&[("b", &b), ("a", &a)]); // roots a, b, parent, b/.git, a/.git = 5
    assert_eq!(f.subtrees("a"), ["a/s1"]);
    // Nothing freed yet: the retry is refused again and the subtree stays listed.
    let retry = |f: &mut Fx| {
        let dirs = vec![a.join("s1")];
        f.monitor.on_cmd(Cmd::Retry {
            id: "a".into(),
            roots: dirs.clone(),
            dirs,
        });
    };
    retry(&mut f);
    assert_eq!(f.mode("a"), (Monitoring::Partial, Some(PollReason::Budget)));
    assert_eq!(f.subtrees("a"), ["a/s1"]);
    // `b` goes away (its watches are freed): the retry succeeds and `a` is fully watched.
    f.monitor.on_cmd(Cmd::Remove("b".into()));
    retry(&mut f);
    assert_eq!(f.mode("a"), (Monitoring::Watched, None));
    assert!(f.shared.poll_target("a").is_none());
    // A retried subtree that vanished is forgotten.
    let mut f = fx_with(4, Some(Fake::default()));
    let a = f.project("a", &["s1/x", "s2/x"]);
    f.plan(&[("a", &a)]); // a, parent, .git, s1
    assert_eq!(f.subtrees("a"), ["a/s2"]);
    f.monitor.on_cmd(Cmd::Retry {
        id: "a".into(),
        roots: vec![a.join("s2")],
        dirs: vec![],
    });
    assert_eq!(f.mode("a"), (Monitoring::Watched, None));
}

#[tokio::test]
async fn removing_an_unwatched_subtree_settles_the_project() {
    let mut f = fx_with(4, Some(Fake::default()));
    let a = f.project("a", &["s1/x", "s2/x"]);
    f.plan(&[("a", &a)]);
    assert_eq!(f.subtrees("a"), ["a/s2"]);
    fs::remove_dir_all(a.join("s2")).unwrap();
    f.event(EventKind::Remove(RemoveKind::Folder), &[&a.join("s2")]);
    assert_eq!(f.mode("a"), (Monitoring::Watched, None));
}

#[tokio::test]
async fn kernel_limits_and_a_missing_inotify_instance_mean_polled_mode() {
    // The kernel refuses after two watches: the root is live, the rest is polled, and the
    // kernel is not asked again for every remaining directory.
    let fake = Fake {
        kernel_max: Some(2),
        ..Fake::default()
    };
    let mut f = fx_with(1000, Some(fake.clone()));
    let a = f.project("a", &["s/x", "t/x", "u/x/y"]);
    f.plan(&[("a", &a)]);
    assert_eq!(
        f.mode("a"),
        (Monitoring::Partial, Some(PollReason::KernelLimit))
    );
    assert_eq!(
        fake.attempts.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "root, parent, then one refused attempt"
    );
    assert!(f
        .shared
        .snapshot()
        .advice
        .iter()
        .any(|a| a.contains("max_user_watches")));

    // No watch at all: the project is polled as a whole.
    let mut f = fx_with(
        1000,
        Some(Fake {
            kernel_max: Some(0),
            ..Fake::default()
        }),
    );
    let a = f.project("a", &["s/x"]);
    f.plan(&[("a", &a)]);
    assert_eq!(
        f.mode("a"),
        (Monitoring::Polled, Some(PollReason::KernelLimit))
    );
    assert!(
        f.shared.poll_target("a").is_none(),
        "polled projects are walked whole"
    );
    assert_eq!(f.shared.snapshot().polled_projects, 1);

    let mut f = fx_with(1000, None);
    let a = f.project("a", &[]);
    f.plan(&[("a", &a)]);
    let st = f.shared.snapshot();
    assert_eq!(st.watcher, "unavailable");
    assert_eq!(
        f.mode("a"),
        (Monitoring::Polled, Some(PollReason::WatcherUnavailable))
    );
    assert!(st.degraded && st.watches == 0);
}

/// §5.1: gitignored directories are never watched, including ones created at runtime (walked
/// with the project's rules, not from scratch).
#[tokio::test]
async fn gitignored_directories_are_never_watched_even_when_created_later() {
    let mut f = fx();
    let p = f.project("p", &["src/a", "logs/today/x", "src/gen/out/x"]);
    fs::write(p.join(".gitignore"), "logs/\nout/\n").unwrap();
    f.plan(&[("p", &p)]);
    assert_eq!(f.watched(), ["", "p", "p/.git", "p/src", "p/src/gen"]);
    // A new directory with an ignored subdirectory appears.
    fs::create_dir_all(p.join("tools/out/deep")).unwrap();
    fs::create_dir_all(p.join("tools/keep")).unwrap();
    f.event(EventKind::Create(CreateKind::Folder), &[&p.join("tools")]);
    f.drain_cmds().await;
    let w = f.watched();
    assert!(
        w.contains(&"p/tools".to_string()) && w.contains(&"p/tools/keep".to_string()),
        "{w:?}"
    );
    assert!(!w.iter().any(|d| d.contains("out")), "{w:?}");
}

#[tokio::test]
async fn events_are_debounced_per_project_and_coalesced() {
    let mut f = fx();
    let p = f.project("p", &["src/a.rs", "src/b.rs"]);
    f.plan(&[("p", &p)]);
    f.modify(&p.join("src/a.rs"));
    f.modify(&p.join("src/b.rs"));
    f.modify(&p.join("src/a.rs"));
    // Not before the window closes.
    f.monitor.flush_due(Instant::now());
    assert!(
        f.signals.try_recv().is_err(),
        "emitted before the debounce window"
    );
    let s = f.flush();
    assert_eq!(
        activity(&s),
        [("p".to_string(), Some("src/a.rs".to_string()), 3, true)]
    );
    assert!(f.flush().is_empty(), "flushed once");
}

#[tokio::test]
async fn gitignored_excluded_and_git_metadata_changes_are_not_activity() {
    let mut f = fx();
    let p = f.project("p", &["src/a.rs", "debug.log"]);
    fs::write(p.join(".gitignore"), "*.log\n").unwrap();
    f.plan(&[("p", &p)]);
    f.modify(&p.join("debug.log"));
    f.event(
        EventKind::Create(CreateKind::Folder),
        &[&p.join("node_modules")],
    );
    fs::create_dir(p.join("node_modules")).unwrap();
    assert!(
        activity(&f.flush()).is_empty(),
        "ignored file / excluded directory"
    );
    f.modify(&p.join(".git/index"));
    f.modify(&p.join(".git/index.lock"));
    let s = f.flush();
    assert_eq!(s, [Signal::Git { id: "p".into() }], "only a Git refresh");
    f.modify(&p.join("src/a.rs"));
    assert_eq!(activity(&f.flush()).len(), 1);
}

#[tokio::test]
async fn activity_in_a_nested_project_is_attributed_only_to_it() {
    let mut f = fx();
    let outer = f.project("outer", &["a.txt"]);
    let inner = f.project("outer/inner", &["b.txt"]);
    f.plan(&[("outer", &outer), ("inner", &inner)]);
    f.modify(&inner.join("b.txt"));
    let s = activity(&f.flush());
    assert_eq!(s.len(), 1);
    assert_eq!(
        (s[0].0.as_str(), s[0].1.as_deref()),
        ("inner", Some("b.txt"))
    );
}

#[tokio::test]
async fn paired_renames_are_moves_and_unpaired_ones_removals() {
    let mut f = fx();
    let p = f.project("dev/p", &[]);
    f.plan(&[("p", &p)]);
    let to = f.home.join("dev/q");
    let name = |m| EventKind::Modify(ModifyKind::Name(m));
    for (mode, path) in [(RenameMode::From, &p), (RenameMode::To, &to)] {
        let e = Event::new(name(mode)).add_path(path.clone()).set_tracker(7);
        f.monitor.on_raw(Ok(e));
    }
    let both = Event::new(name(RenameMode::Both))
        .add_path(p.clone())
        .add_path(to.clone())
        .set_tracker(7);
    f.monitor.on_raw(Ok(both));
    let s = f.flush();
    assert_eq!(
        s,
        [Signal::Moved {
            from: p.clone(),
            to: to.clone()
        }]
    );
    assert!(
        f.shared.of("p").is_none()
            || f.monitor
                .watched_dirs()
                .iter()
                .all(|(d, _)| !d.starts_with(&p))
    );

    // A rename out of the watched area (no partner) is the project disappearing.
    let mut f = fx();
    let p = f.project("dev/p", &[]);
    f.plan(&[("p", &p)]);
    let e = Event::new(name(RenameMode::From))
        .add_path(p.clone())
        .set_tracker(9);
    f.monitor.on_raw(Ok(e));
    let s = f.flush();
    assert_eq!(s, [Signal::Vanished { id: "p".into() }]);
}

#[tokio::test]
async fn deleting_a_project_root_vanishes_it_and_drops_its_watches() {
    let mut f = fx();
    let p = f.project("dev/p", &["src/x"]);
    f.plan(&[("p", &p)]);
    f.event(EventKind::Remove(RemoveKind::Folder), &[&p]);
    assert_eq!(f.flush(), [Signal::Vanished { id: "p".into() }]);
    assert_eq!(
        f.watched(),
        ["dev"],
        "only the sibling-detection watch remains"
    );
    assert!(f.shared.of("p").is_none());
}

#[tokio::test]
async fn new_markers_and_directories_trigger_discovery() {
    let mut f = fx();
    let p = f.project("dev/p", &[]);
    f.plan(&[("p", &p)]);
    // A new sibling directory appears in the watched parent: watched one level deep, discovered.
    let sib = f.home.join("dev/new");
    fs::create_dir(&sib).unwrap();
    f.event(EventKind::Create(CreateKind::Folder), &[&sib]);
    assert!(f.watched().contains(&"dev/new".to_string()));
    // CLAUDE.md appears in it.
    mkfile(&sib.join("CLAUDE.md"));
    f.event(
        EventKind::Create(CreateKind::File),
        &[&sib.join("CLAUDE.md")],
    );
    let s = f.flush();
    assert_eq!(
        s,
        [Signal::Discover(sib.clone()), Signal::Discover(sib.clone())]
    );
    // Hidden directories in the sibling area are neither watched nor discovered.
    let hidden = f.home.join("dev/.hidden");
    fs::create_dir(&hidden).unwrap();
    f.event(EventKind::Create(CreateKind::Folder), &[&hidden]);
    assert!(f.flush().is_empty());
    assert!(!f.watched().contains(&"dev/.hidden".to_string()));
}

#[tokio::test]
async fn new_subdirectories_inside_a_project_are_walked_and_watched() {
    let mut f = fx();
    let p = f.project("p", &[]);
    f.plan(&[("p", &p)]);
    mkfile(&p.join("pkg/sub/f.rs"));
    fs::create_dir_all(p.join("pkg/node_modules/x")).unwrap();
    f.event(EventKind::Create(CreateKind::Folder), &[&p.join("pkg")]);
    f.drain_cmds().await;
    let w = f.watched();
    assert!(
        w.contains(&"p/pkg".to_string()) && w.contains(&"p/pkg/sub".to_string()),
        "{w:?}"
    );
    assert!(!w.iter().any(|d| d.contains("node_modules")));
    let s = f.flush();
    assert!(
        s.contains(&Signal::Discover(p.join("pkg"))),
        "a cloned repository may be a nested project"
    );
    let a = activity(&s);
    assert_eq!(a.len(), 1, "a new directory is activity");
    assert_eq!(a[0].1, None, "…but not a modified file");
    // A nested project appearing (CLAUDE.md next to a new .git) is discovered.
    f.event(
        EventKind::Create(CreateKind::Folder),
        &[&p.join("pkg/sub/.git")],
    );
    assert!(f.flush().contains(&Signal::Discover(p.join("pkg/sub"))));
}

#[tokio::test]
async fn overflow_triggers_a_rescan_until_recovered_and_gitignore_edits_a_rewalk() {
    let mut f = fx();
    let p = f.project("p", &["a"]);
    f.plan(&[("p", &p)]);
    let overflow = Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
    f.monitor.on_raw(Ok(overflow));
    assert_eq!(f.flush(), [Signal::Rescan]);
    f.monitor.on_cmd(Cmd::Remove("none".into())); // commands publish the snapshot
    let st = f.shared.snapshot();
    assert!(st.recovering_overflow && st.degraded && st.overflows == 1);
    f.monitor.on_cmd(Cmd::OverflowRecovered);
    f.monitor.on_cmd(Cmd::Remove("none".into()));
    assert!(!f.shared.snapshot().recovering_overflow);

    f.modify(&p.join(".gitignore"));
    let s = f.flush();
    assert!(s.contains(&Signal::Rewalk { id: "p".into() }), "{s:?}");
}
