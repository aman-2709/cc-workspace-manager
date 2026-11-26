//! The tracker over the full stack (temp database, real inotify, real Git): reconciliation,
//! live activity, live project registration, missing/revived, moves (paired rename and the
//! fallback matcher across a restart), Git refresh, ignore and the retention purge
//! (REQUIREMENTS.md §4.5, §5, §16 "Lifecycle" / "Monitoring").
//!
//! One inotify instance per stack; tests take a global lock because this host has few instances
//! left. If no instance can be created the tests print a notice and pass, unless
//! `CCWM_REQUIRE_INOTIFY=1`.

mod common;

use cc_workspace_manager::clock::{Clock, FakeClock, SystemClock};
use cc_workspace_manager::db::queries::{self, Tracked};
use cc_workspace_manager::db::reader::Reader;
use cc_workspace_manager::db::writer::Writer;
use cc_workspace_manager::discovery::status::SharedStatus;
use cc_workspace_manager::discovery::walk::ScanOptions;
use cc_workspace_manager::events::Notifier;
use cc_workspace_manager::git::{find_on_path, Git};
use cc_workspace_manager::synth;
use cc_workspace_manager::tracker::{
    Control, SessionSettings as TrackerSessions, Settings as TrackerSettings, Tracker,
};
use cc_workspace_manager::watch::{self, Monitor, Monitoring, SharedMonitor, WatchBackend};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch as tokio_watch};

fn inotify_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// How a test stack is configured.
#[derive(Clone)]
struct Opts {
    budget: usize,
    /// Walk every root at every reconciliation (the M2 behaviour these tests were written for).
    full_scan: bool,
    /// Claude Code's config directory: enables the session integration.
    claude_dir: Option<PathBuf>,
    /// Ignore rules all projects may keep together (the daemon's limit by default).
    ignore_rules: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            budget: 1000,
            full_scan: true,
            claude_dir: None,
            ignore_rules: watch::tree::MAX_GITIGNORE_PATTERNS_TOTAL,
        }
    }
}

struct Stack {
    tracker: Arc<Tracker>,
    status: SharedStatus,
    reader: Reader,
    writer: Arc<Writer>,
    monitor: SharedMonitor,
    clock: Arc<FakeClock>,
    /// The limit on ignore rules across projects, as the tracker and the monitor share it.
    ignore_budget: Arc<watch::tree::IgnoreBudget>,
    stop: tokio_watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

const RETENTION: i64 = 3600;

fn git(dir: &Path, home: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "A")
        .env("GIT_AUTHOR_EMAIL", "a@example.invalid")
        .env("GIT_COMMITTER_NAME", "A")
        .env("GIT_COMMITTER_EMAIL", "a@example.invalid")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn has_git() -> bool {
    find_on_path(std::env::var_os("PATH").as_deref()).is_some()
}

fn marker(dir: &Path, text: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("CLAUDE.md"), text).unwrap();
}

/// M2 review L2: notify requests `IN_ONLYDIR` but falls back to a plain watch on `ENOTDIR`; the
/// backend must still refuse anything that is not a directory, and never follow a symlink.
#[tokio::test]
async fn the_inotify_backend_watches_only_real_directories() {
    let _g = inotify_lock().lock().await;
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let (raw_tx, mut raw_rx) = mpsc::channel(64);
    let mut backend = match watch::inotify_backend(raw_tx, Arc::new(AtomicBool::new(false))) {
        Ok(w) => w,
        Err(e) => {
            assert!(
                std::env::var("CCWM_REQUIRE_INOTIFY").as_deref() != Ok("1"),
                "no inotify instance: {e}"
            );
            eprintln!("NOTICE: no inotify instance available ({e}); skipping");
            return;
        }
    };
    let dir = root.join("d");
    fs::create_dir(&dir).unwrap();
    let file = root.join("f");
    fs::write(&file, "x").unwrap();
    let link = root.join("l");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    assert_eq!(backend.watch(&dir), Ok(()));
    assert_eq!(
        backend.watch(&file),
        Err(watch::WatchError::Gone),
        "a regular file is never watched"
    );
    assert_eq!(
        backend.watch(&link),
        Err(watch::WatchError::Gone),
        "a symlink to a directory is never watched"
    );
    assert_eq!(
        backend.watch(&root.join("missing")),
        Err(watch::WatchError::Gone)
    );
    // The refused file really has no watch: writing to it produces no event.
    fs::write(&file, "changed").unwrap();
    fs::write(dir.join("inside"), "y").unwrap();
    let mut paths = Vec::new();
    while let Ok(Some(Ok(ev))) =
        tokio::time::timeout(Duration::from_millis(300), raw_rx.recv()).await
    {
        paths.extend(ev.paths);
    }
    assert!(paths.iter().any(|p| p.starts_with(&dir)), "{paths:?}");
    assert!(!paths.iter().any(|p| p == &file), "{paths:?}");
}

impl Stack {
    /// `None` if no inotify instance could be created (notice printed).
    async fn start(home: &Path, data: &Path, clock: Arc<FakeClock>) -> Option<Self> {
        Self::start_with_budget(home, data, clock, 1000).await
    }

    /// `None` if no inotify instance could be created (notice printed).
    async fn start_with_budget(
        home: &Path,
        data: &Path,
        clock: Arc<FakeClock>,
        budget: usize,
    ) -> Option<Self> {
        Self::start_with(
            home,
            data,
            clock,
            Opts {
                budget,
                ..Opts::default()
            },
        )
        .await
    }

    /// `None` if no inotify instance could be created (notice printed).
    async fn start_with(
        home: &Path,
        data: &Path,
        clock: Arc<FakeClock>,
        opts: Opts,
    ) -> Option<Self> {
        let budget = opts.budget;
        let ignore_budget = Arc::new(watch::tree::IgnoreBudget::new(opts.ignore_rules));
        let db = data.join("t.db");
        let writer = Arc::new(Writer::spawn(&db).unwrap());
        let reader = Reader::open(&db, 2).unwrap();
        let (notifier, mut changes) = Notifier::channel();
        tokio::spawn(async move { while changes.recv().await.is_some() {} });
        let monitor_state = SharedMonitor::default();
        let (monitor_tx, monitor_rx) = mpsc::channel(1024);
        let (signals_tx, signals_rx) = mpsc::channel(4096);
        let (raw_tx, raw_rx) = mpsc::channel(watch::EVENT_QUEUE);
        let dropped = Arc::new(AtomicBool::new(false));
        let backend: Box<dyn WatchBackend> =
            match watch::inotify_backend(raw_tx, Arc::clone(&dropped)) {
                Ok(w) => Box::new(w),
                Err(e) => {
                    assert!(
                        std::env::var("CCWM_REQUIRE_INOTIFY").as_deref() != Ok("1"),
                        "no inotify instance: {e}"
                    );
                    eprintln!("NOTICE: no inotify instance available ({e}); skipping");
                    return None;
                }
            };
        let scan = ScanOptions {
            roots: vec![home.to_path_buf()],
            exclude: vec![],
            max_depth: 10,
            same_file_system: true,
            home: home.to_path_buf(),
            boundaries: vec![data.to_path_buf()],
            fuse_mounts: vec![],
        };
        let status = SharedStatus::default();
        let tracker = Tracker::new(
            Arc::clone(&writer),
            reader.clone(),
            clock.clone(),
            notifier.clone(),
            status.clone(),
            Arc::new(Git::detect(
                find_on_path(std::env::var_os("PATH").as_deref()),
                home,
                false,
            )),
            monitor_tx.clone(),
            monitor_state.clone(),
            TrackerSettings {
                scan,
                uid: nix::unistd::geteuid().as_raw(),
                interval: Duration::from_secs(3600),
                retention_secs: RETENTION,
                events_per_project: 50,
                full_scan: opts.full_scan,
                sessions: opts.claude_dir.map(|d| TrackerSessions {
                    config_dir: d,
                    temp_dirs: vec![],
                    claude: None,
                }),
                ignore_budget: Arc::clone(&ignore_budget),
            },
        );
        let monitor = Monitor::new(
            Some(backend),
            watch::Settings {
                roots: vec![home.to_path_buf()],
                home: home.to_path_buf(),
                exclude: vec![],
                boundaries: vec![data.to_path_buf()],
                fuse_mounts: vec![],
                max_depth: 10,
                same_file_system: true,
                budget,
                max_user_watches: None,
                debounce: Duration::from_millis(100),
                events_per_project: 50,
                ignore_budget: Arc::clone(&ignore_budget),
            },
            clock.clone(),
            signals_tx,
            monitor_tx,
            monitor_state.clone(),
            Some(notifier),
        );
        let (stop, stop_rx) = tokio_watch::channel(false);
        let tasks = vec![
            tokio::spawn(monitor.run(raw_rx, monitor_rx, dropped, stop_rx.clone())),
            tokio::spawn(Arc::clone(&tracker).run_reconciler(stop_rx.clone())),
            tokio::spawn(Arc::clone(&tracker).run_signals(signals_rx, stop_rx)),
        ];
        Some(Self {
            tracker,
            status,
            reader,
            writer,
            monitor: monitor_state,
            clock,
            ignore_budget,
            stop,
            tasks,
        })
    }

    async fn stop(self) {
        self.tracker.cancel();
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        let _ = self.writer.shutdown().await;
    }

    async fn tracked(&self) -> Vec<Tracked> {
        self.reader.with(queries::tracked_projects).await.unwrap()
    }

    async fn by_path(&self, p: &Path) -> Option<Tracked> {
        let p = p.to_str().unwrap().to_string();
        self.tracked().await.into_iter().find(|t| t.path == p)
    }

    async fn row(&self, id: &str) -> queries::ProjectRow {
        let id = id.to_string();
        self.reader
            .with(move |c| queries::get_project(c, &id))
            .await
            .unwrap()
            .unwrap()
    }

    /// Poll `cond` until it holds (or fail after `secs`).
    async fn wait<F, Fut>(&self, what: &str, secs: u64, mut cond: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while !cond().await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for: {what}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_registered(&self, p: &Path) -> Tracked {
        self.wait(&format!("{} registered", p.display()), 15, || async {
            self.by_path(p).await.is_some_and(|t| !t.missing)
        })
        .await;
        self.by_path(p).await.unwrap()
    }

    async fn wait_watched(&self, id: &str) {
        self.wait("project watched", 15, || async {
            self.monitor
                .of(id)
                .is_some_and(|m| m.0 == Monitoring::Watched)
        })
        .await;
    }
}

struct Env {
    _t: tempfile::TempDir,
    home: PathBuf,
    data: PathBuf,
}

fn env() -> Env {
    let t = common::tempdir();
    let root = fs::canonicalize(t.path()).unwrap();
    let home = root.join("home");
    let data = root.join("data");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&data).unwrap();
    Env { _t: t, home, data }
}

fn now_clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::new(SystemClock.now()))
}

#[tokio::test]
async fn live_activity_new_projects_missing_revived_and_renames() {
    let _g = inotify_lock().lock().await;
    let e = env();
    let alpha = e.home.join("dev/alpha");
    marker(&alpha, "# alpha");
    fs::write(alpha.join("old.txt"), "o").unwrap();
    let beta = e.home.join("dev/beta");
    marker(&beta, "# beta");
    let Some(s) = Stack::start(&e.home, &e.data, now_clock()).await else {
        return;
    };
    let a = s.wait_registered(&alpha).await;
    let b = s.wait_registered(&beta).await;
    s.wait_watched(&a.id).await;
    s.wait_watched(&b.id).await;
    let row = s.row(&a.id).await;
    assert_eq!(
        row.activity_kind.as_deref(),
        Some("inferred"),
        "initial timestamp from the walk"
    );

    // Editing a file is observed live and recorded with its relative path.
    s.clock.advance(100);
    fs::create_dir_all(alpha.join("src")).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await; // the new directory gets its watch
    fs::write(alpha.join("src/main.rs"), "fn main() {}").unwrap();
    s.wait("observed activity on the new file", 10, || async {
        let r = s.row(&a.id).await;
        r.activity_kind.as_deref() == Some("observed")
            && r.activity_path.as_deref() == Some("src/main.rs")
    })
    .await;
    let top = s.tracked().await;
    assert_eq!(
        top[0].id, a.id,
        "the edited project is the most recently active"
    );

    // A new CLAUDE.md in a watched area registers a project without a rescan.
    let gamma = e.home.join("dev/gamma");
    fs::create_dir(&gamma).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    fs::write(gamma.join("CLAUDE.md"), "# gamma").unwrap();
    let g = s.wait_registered(&gamma).await;

    // Deleting a project makes it missing; recreating it revives the same id.
    fs::remove_dir_all(&beta).unwrap();
    s.wait("beta missing", 10, || async {
        s.by_path(&beta).await.is_some_and(|t| t.missing)
    })
    .await;
    marker(&beta, "# beta again");
    // Unwatched now (the old watch died with the directory): the parent watch sees it return.
    let b2 = s.wait_registered(&beta).await;
    assert_eq!(b2.id, b.id, "revived, same id");

    // A paired rename keeps the id and updates the path.
    let gamma2 = e.home.join("dev/gamma-renamed");
    s.wait_watched(&g.id).await;
    fs::rename(&gamma, &gamma2).unwrap();
    let moved = s.wait_registered(&gamma2).await;
    assert_eq!(moved.id, g.id, "a renamed project keeps its id");
    assert!(s.by_path(&gamma).await.is_none());

    // A nested project with its own Git root appears live; activity inside it is its own.
    let inner = alpha.join("packages/inner");
    fs::create_dir_all(&inner).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    fs::create_dir(inner.join(".git")).unwrap();
    fs::write(inner.join("CLAUDE.md"), "# inner").unwrap();
    let i = s.wait_registered(&inner).await;
    s.wait_watched(&i.id).await;
    // The marker was created while `inner` was still part of alpha (correctly alpha's activity);
    // let that debounced event land before taking the baseline.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let alpha_before = s.row(&a.id).await.activity_path;
    s.clock.advance(100);
    fs::write(inner.join("lib.rs"), "x").unwrap();
    s.wait("inner activity", 10, || async {
        s.row(&i.id).await.activity_path.as_deref() == Some("lib.rs")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        s.row(&a.id).await.activity_path,
        alpha_before,
        "never attributed to the parent"
    );
    s.stop().await;
}

/// A partly watched project: reconciliation walks only its unwatched subtrees, finds a change
/// there by mtime (inferred), and keeps the watched part live.
#[tokio::test]
async fn reconciliation_polls_the_unwatched_subtrees_of_a_partly_watched_project() {
    let _g = inotify_lock().lock().await;
    let e = env();
    let p = e.home.join("dev/p");
    marker(&p, "# p");
    fs::create_dir_all(p.join("top")).unwrap();
    fs::create_dir_all(p.join("deep/x/y")).unwrap();
    // Budget: the root, its parent `dev`, and the top level (`top`, `deep`); `deep/x` is not.
    let Some(s) = Stack::start_with_budget(&e.home, &e.data, now_clock(), 4).await else {
        return;
    };
    let t = s.wait_registered(&p).await;
    s.wait("partly watched", 15, || async {
        s.monitor
            .of(&t.id)
            .is_some_and(|m| m.0 == Monitoring::Partial)
    })
    .await;
    let target = s.monitor.poll_target(&t.id).unwrap();
    assert_eq!(target.subtrees, [p.join("deep/x")]);

    // The watched part is live.
    s.clock.advance(100);
    fs::write(p.join("top/live.txt"), "l").unwrap();
    s.wait("observed activity in the watched part", 10, || async {
        let r = s.row(&t.id).await;
        r.activity_kind.as_deref() == Some("observed")
            && r.activity_path.as_deref() == Some("top/live.txt")
    })
    .await;

    // A change in the unwatched subtree is found by the next reconciliation (mtime, inferred).
    s.clock.advance(1000);
    let hidden = p.join("deep/x/y/new.txt");
    fs::write(&hidden, "n").unwrap();
    let at = s.clock.now() - 5;
    fs::File::options()
        .write(true)
        .open(&hidden)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(at.try_into().unwrap()))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_ne!(
        s.row(&t.id).await.activity_path.as_deref(),
        Some("deep/x/y/new.txt"),
        "not seen live: no watch there"
    );
    s.tracker.request_refresh();
    s.wait("the polled subtree's change", 15, || async {
        let r = s.row(&t.id).await;
        r.activity_path.as_deref() == Some("deep/x/y/new.txt")
            && r.activity_kind.as_deref() == Some("inferred")
            && r.activity_at == Some(at)
    })
    .await;
    assert_eq!(
        s.monitor.of(&t.id).unwrap().0,
        Monitoring::Partial,
        "still no room for the subtree"
    );
    s.stop().await;
}

#[tokio::test]
async fn git_status_follows_edits_and_ignore_stops_monitoring() {
    if !has_git() {
        eprintln!("NOTICE: git not installed; skipping");
        return;
    }
    let _g = inotify_lock().lock().await;
    let e = env();
    let r = e.home.join("repo");
    marker(&r, "# repo");
    git(&r, &e.home, &["init", "-q", "-b", "main"]);
    git(&r, &e.home, &["add", "CLAUDE.md"]);
    git(&r, &e.home, &["commit", "-q", "-m", "init"]);
    let Some(s) = Stack::start(&e.home, &e.data, now_clock()).await else {
        return;
    };
    let p = s.wait_registered(&r).await;
    s.wait("git cache", 15, || async {
        s.row(&p.id)
            .await
            .git
            .is_some_and(|g| g.state == "ok" && g.modified == Some(0))
    })
    .await;
    s.wait_watched(&p.id).await;
    fs::write(r.join("CLAUDE.md"), "# changed").unwrap();
    s.wait("modified after edit", 15, || async {
        s.row(&p.id)
            .await
            .git
            .is_some_and(|g| g.modified == Some(1))
    })
    .await;
    git(&r, &e.home, &["commit", "-q", "-am", "second"]);
    s.wait("clean after commit", 15, || async {
        s.row(&p.id)
            .await
            .git
            .is_some_and(|g| g.modified == Some(0) && g.head_subject.as_deref() == Some("second"))
    })
    .await;

    // Ignoring a project stops monitoring it; un-ignoring brings it back.
    s.writer.set_ignored(&p.path, true, 1).await.unwrap();
    s.tracker
        .on_control(Control::Ignored(p.id.clone()))
        .await
        .unwrap();
    s.wait("unwatched", 5, || async { s.monitor.of(&p.id).is_none() })
        .await;
    s.writer.set_ignored(&p.path, false, 2).await.unwrap();
    s.tracker
        .on_control(Control::Unignored(p.id.clone()))
        .await
        .unwrap();
    s.wait_watched(&p.id).await;
    s.stop().await;
}

/// The limit on ignore rules across projects, through the real tracker and monitor: with room
/// for six rules and two projects of four rules each, the project walked first keeps its rules
/// and the other one's `.gitignore` is skipped and counted. When the first project is no longer
/// monitored its share is free: the other project's next walk keeps its rules, and the first
/// one, monitored again, is now the one without room.
#[tokio::test]
async fn projects_share_one_limit_on_ignore_rules_first_come_first_served() {
    let _g = inotify_lock().lock().await;
    let e = env();
    const RULES: &str = "one.tmp\ntwo.tmp\nthree.tmp\nfour.tmp\n";
    let roots = [e.home.join("a"), e.home.join("b")];
    for r in &roots {
        marker(r, "# project");
        fs::create_dir(r.join(".git")).unwrap(); // a work tree: `.gitignore` applies
        fs::write(r.join(".gitignore"), RULES).unwrap();
    }
    let opts = Opts {
        ignore_rules: 6,
        ..Opts::default()
    };
    let Some(s) = Stack::start_with(&e.home, &e.data, now_clock(), opts).await else {
        return;
    };
    let skipped = || s.monitor.snapshot().ignore_files_skipped;
    let (a, b) = (
        s.wait_registered(&roots[0]).await,
        s.wait_registered(&roots[1]).await,
    );
    s.wait_watched(&a.id).await;
    s.wait_watched(&b.id).await;
    assert_eq!(skipped(), 1, "{:?}", s.monitor.snapshot().advice);
    assert_eq!(s.ignore_budget.total(), 4, "one project's rules are kept");
    let advice = s.monitor.snapshot().advice.join(" ");
    assert!(
        advice.contains("1 .gitignore or .git/info/exclude file(s) were skipped")
            && advice.contains("all projects together have more than"),
        "{advice}"
    );
    // The keeper has the whole limit as its room; the other one only what the keeper leaves.
    let (keeper, loser) = if s.ignore_budget.room(&roots[0]) == 6 {
        (&a, &b)
    } else {
        (&b, &a)
    };
    assert_eq!(s.ignore_budget.room(Path::new(&keeper.path)), 6);
    assert_eq!(s.ignore_budget.room(Path::new(&loser.path)), 2);

    // The keeper is ignored: its rules are gone, and the loser's next walk (its `.gitignore`
    // was written again) finds room.
    s.writer.set_ignored(&keeper.path, true, 1).await.unwrap();
    s.tracker
        .on_control(Control::Ignored(keeper.id.clone()))
        .await
        .unwrap();
    s.wait("unwatched", 5, || async {
        s.monitor.of(&keeper.id).is_none()
    })
    .await;
    fs::write(Path::new(&loser.path).join(".gitignore"), RULES).unwrap();
    s.wait("the other project's rules to be kept", 15, || async {
        skipped() == 0 && s.ignore_budget.room(Path::new(&loser.path)) == 6
    })
    .await;
    assert_eq!(s.ignore_budget.total(), 4);

    // Monitored again, the former keeper is the one without room: first come, first served.
    s.writer.set_ignored(&keeper.path, false, 2).await.unwrap();
    s.tracker
        .on_control(Control::Unignored(keeper.id.clone()))
        .await
        .unwrap();
    s.wait_watched(&keeper.id).await;
    assert_eq!(skipped(), 1);
    assert_eq!(s.ignore_budget.total(), 4);
    assert_eq!(s.ignore_budget.room(Path::new(&keeper.path)), 2);
    s.stop().await;
}

#[tokio::test]
async fn moves_while_stopped_are_recognised_and_missing_projects_are_purged() {
    let _g = inotify_lock().lock().await;
    let e = env();
    let plain = e.home.join("a/plain");
    marker(&plain, "# unique plain content");
    let gone = e.home.join("a/gone");
    marker(&gone, "# will disappear");
    let with_git = e.home.join("a/repo");
    if has_git() {
        marker(&with_git, "# repo");
        git(&with_git, &e.home, &["init", "-q", "-b", "main"]);
        git(&with_git, &e.home, &["add", "."]);
        git(&with_git, &e.home, &["commit", "-q", "-m", "x"]);
        git(
            &with_git,
            &e.home,
            &[
                "remote",
                "add",
                "origin",
                "https://u:secret@example.invalid/r.git",
            ],
        );
    }
    let clock = now_clock();
    let Some(s) = Stack::start(&e.home, &e.data, clock.clone()).await else {
        return;
    };
    let p = s.wait_registered(&plain).await;
    let g = s.wait_registered(&gone).await;
    let repo = if has_git() {
        let t = s.wait_registered(&with_git).await;
        s.wait("git cached", 15, || async {
            s.row(&t.id).await.git.is_some()
        })
        .await;
        assert_eq!(
            s.row(&t.id).await.git.unwrap().remote_url.as_deref(),
            Some("https://example.invalid/r.git"),
            "stored without credentials"
        );
        Some(t)
    } else {
        None
    };
    s.stop().await;

    // While ccwm is not running: move two projects, delete one.
    let plain2 = e.home.join("b/plain-moved");
    fs::create_dir_all(e.home.join("b")).unwrap();
    fs::rename(&plain, &plain2).unwrap();
    let repo2 = e.home.join("b/repo-moved");
    if has_git() {
        fs::rename(&with_git, &repo2).unwrap();
    }
    fs::remove_dir_all(&gone).unwrap();

    let Some(s) = Stack::start(&e.home, &e.data, clock.clone()).await else {
        return;
    };
    // The new path is registered first, then merged into the missing project's id.
    s.wait("plain move recognised", 15, || async {
        s.by_path(&plain2).await.is_some_and(|t| t.id == p.id)
    })
    .await;
    if let Some(t) = repo {
        s.wait("repository move recognised", 15, || async {
            s.by_path(&repo2).await.is_some_and(|x| x.id == t.id)
        })
        .await;
    }
    s.wait("one row per project", 5, || async {
        s.tracked().await.len() == if has_git() { 3 } else { 2 }
    })
    .await;
    s.wait("gone is missing", 10, || async {
        s.by_path(&gone).await.is_some_and(|t| t.missing)
    })
    .await;
    assert!(
        s.by_path(&plain).await.is_none(),
        "no stale row at the old path"
    );

    // After the retention period the missing project is purged at the next reconciliation.
    s.clock.advance(RETENTION + 1);
    s.tracker.request_refresh();
    s.wait("purged", 15, || async {
        !s.tracked().await.iter().any(|t| t.id == g.id)
    })
    .await;
    s.stop().await;
}

// ---- M3: sessions as the primary discovery source -------------------------------------------

impl Stack {
    async fn sessions(&self) -> Vec<queries::SessionState> {
        self.reader.with(queries::session_states).await.unwrap()
    }

    async fn session(&self, id: &str) -> Option<queries::SessionState> {
        self.sessions().await.into_iter().find(|s| s.id == id)
    }

    async fn wait_scans(&self, n: u64) {
        self.wait(&format!("{n} reconciliations"), 20, || async {
            self.status.snapshot().scans_finished >= n
        })
        .await;
    }
}

fn session_line(id: &str, ts: &str, cwd: &Path, text: &str) -> String {
    format!(
        "{}\n",
        serde_json::json!({"type": "user", "sessionId": id, "timestamp": ts, "cwd": cwd,
                           "promptSource": "typed", "message": {"role": "user", "content": text}})
    )
}

/// The synthetic corpus: projects from session cwds (also one without `CLAUDE.md`), the first
/// cwd resolved upward, home and vanished cwds unassigned, subagent files ignored; then live:
/// a new session in a new directory registers its project, an append updates the aggregates, a
/// deleted session file leaves the index while its project stays. No prompt text is stored.
#[tokio::test]
async fn sessions_register_projects_live_and_follow_appends_and_deletions() {
    let _g = inotify_lock().lock().await;
    let t = common::tempdir();
    let env = synth::generate(&t.path().join("e"), 0).unwrap();
    let home = fs::canonicalize(&env.home).unwrap();
    let claude = fs::canonicalize(&env.claude_dir).unwrap();
    let data = t.path().join("data");
    fs::create_dir(&data).unwrap();
    let Some(s) = Stack::start_with(
        &home,
        &data,
        now_clock(),
        Opts {
            full_scan: false,
            claude_dir: Some(claude.clone()),
            ..Opts::default()
        },
    )
    .await
    else {
        return;
    };
    s.wait_scans(1).await;
    let so = s.wait_registered(&home.join("dev/session-only")).await;
    assert_eq!(
        s.row(&so.id).await.sources,
        ["session"],
        "found from its session only"
    );
    assert_eq!(s.row(&so.id).await.sessions.count, 1);
    let alpha = s.by_path(&home.join("dev/alpha")).await.unwrap();
    let a = s.row(&alpha.id).await;
    assert_eq!(a.sources, ["marker", "session"]);
    assert_eq!(a.sessions.count, 2);
    assert_eq!(
        a.sessions.latest_title.as_deref(),
        Some("Alpha tests, continued"),
        "the most recent session's title"
    );
    let inner = s
        .by_path(&home.join("dev/beta/packages/inner"))
        .await
        .unwrap();
    assert_eq!(
        s.row(&inner.id).await.sessions.count,
        1,
        "cwd …/inner/src resolved upward"
    );
    assert!(
        s.by_path(&home.join("dev/beta/packages/inner/src"))
            .await
            .is_none()
            && s.by_path(&home.join("dev/session-only/src"))
                .await
                .is_none()
            && s.by_path(&home).await.is_none(),
        "neither the cwd itself nor home is registered"
    );

    let all = s.sessions().await;
    assert_eq!(
        all.len(),
        7,
        "top-level files only (the subagent transcript is skipped)"
    );
    let a1 = s
        .session("11111111-2222-4333-8444-555555555555")
        .await
        .unwrap();
    assert_eq!(
        a1.aggregate.continued_in.as_deref(),
        Some("22222222-3333-4444-8555-666666666666")
    );
    assert_eq!(
        a1.aggregate.title.as_deref(),
        Some("Alpha config parser and tests")
    );
    assert_eq!(
        a1.aggregate.started_at,
        Some(1_795_165_199),
        "minimum, not the first line"
    );
    let a2 = s
        .session("22222222-3333-4444-8555-666666666666")
        .await
        .unwrap();
    assert_eq!(
        a2.aggregate.derived_from,
        ["11111111-2222-4333-8444-555555555555"]
    );
    assert_eq!(
        a2.aggregate.first_cwd.as_deref(),
        home.join("dev/alpha").to_str()
    );
    assert_eq!(
        a2.aggregate.last_cwd.as_deref(),
        home.join("dev/alpha/src").to_str()
    );
    let edge = s
        .session("66666666-7777-4888-8999-aaaaaaaaaaaa")
        .await
        .unwrap();
    let c = edge.aggregate.counts;
    assert_eq!((c.malformed, c.unknown, c.foreign), (1, 2, 1));
    assert!(!edge.aggregate.is_sidechain);
    let st = s.status.snapshot().sessions;
    assert_eq!(st.state, "ok");
    assert_eq!((st.files, st.indexed), (7, 7));
    assert_eq!(st.unassigned.get("home"), Some(&1));
    assert_eq!(st.unassigned.get("nonexistent"), Some(&1));
    assert!(
        st.skipped_entries >= 3,
        "subagent dir, memory, aliases: {st:?}"
    );

    // Live: a new session in a new project directory.
    let live = home.join("dev/live-proj");
    fs::create_dir_all(live.join(".git")).unwrap();
    let new_id = "abcdef01-2345-4678-89ab-cdef01234567";
    let new_dir = claude.join("projects/-synthetic-dev-live-proj");
    fs::create_dir(&new_dir).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let file = new_dir.join(format!("{new_id}.jsonl"));
    fs::write(
        &file,
        session_line(
            new_id,
            "2026-11-24T10:00:00.000Z",
            &live,
            "SYNTHETIC-LIVE-PROMPT",
        ),
    )
    .unwrap();
    let lp = s.wait_registered(&live).await;
    assert_eq!(s.row(&lp.id).await.sources, ["session"]);

    // Live: an append is parsed from the checkpoint.
    let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
    use std::io::Write;
    f.write_all(
        session_line(
            new_id,
            "2026-11-24T12:00:00.000Z",
            &live,
            "SYNTHETIC-LIVE-2",
        )
        .as_bytes(),
    )
    .unwrap();
    s.wait("append parsed", 10, || async {
        s.session(new_id)
            .await
            .is_some_and(|x| x.aggregate.last_activity_at == Some(1_795_521_600))
    })
    .await;
    let cp = s.session(new_id).await.unwrap().checkpoint;
    assert_eq!(cp.offset, fs::metadata(&file).unwrap().len());

    // A deleted session file leaves the index; its project stays.
    fs::remove_file(claude.join(
        "projects/-synthetic-dev-session-only-src/33333333-4444-4555-8666-777777777777.jsonl",
    ))
    .unwrap();
    s.wait("session forgotten", 10, || async {
        s.session("33333333-4444-4555-8666-777777777777")
            .await
            .is_none()
    })
    .await;
    let kept = s.by_path(&home.join("dev/session-only")).await.unwrap();
    assert!(
        !kept.missing,
        "projects persist after their sessions are gone"
    );
    assert_eq!(s.row(&kept.id).await.sessions.count, 0);

    // Not one byte of prompt text, tool output or account data in the database.
    s.writer.flush().await.unwrap();
    let mut db = Vec::new();
    for suffix in ["t.db", "t.db-wal"] {
        db.extend(fs::read(data.join(suffix)).unwrap_or_default());
    }
    for canary in [
        "SYNTHETIC first prompt",
        "SYNTHETIC last prompt in alpha",
        "SYNTHETIC-LIVE-PROMPT",
        "SYNTHETIC tool output",
        "SYNTHETIC queued text",
        "SYNTHETIC-CANARY-API-BLOB",
        "SYNTHETIC-CANARY-ACCOUNT",
        "SYNTHETIC assistant reply",
        "SYNTHETIC attachment body",
        "SYNTHETIC wire input",
    ] {
        assert!(
            !db.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "{canary} stored"
        );
    }
    s.stop().await;
}

/// After the first launch's full marker scan, later reconciliations walk only the development
/// roots (parents of session-discovered projects); "scan entire home" restores full scans.
/// Projects persist when their marker is deleted.
#[tokio::test]
async fn after_the_first_full_scan_only_development_roots_are_walked() {
    let _g = inotify_lock().lock().await;
    let e = env();
    let claude = e.home.join(".claude");
    let app = e.home.join("dev/app");
    fs::create_dir_all(app.join(".git")).unwrap();
    let enc = claude.join("projects/-dev-app");
    fs::create_dir_all(&enc).unwrap();
    let sid = "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e";
    fs::write(
        enc.join(format!("{sid}.jsonl")),
        session_line(sid, "2026-11-24T09:00:00.000Z", &app, "x"),
    )
    .unwrap();
    let old = e.home.join("far/old");
    marker(&old, "# old");
    let opts = |full| Opts {
        full_scan: full,
        claude_dir: Some(claude.clone()),
        ..Opts::default()
    };
    let clock = now_clock();
    let Some(s) = Stack::start_with(&e.home, &e.data, clock.clone(), opts(false)).await else {
        return;
    };
    s.wait_scans(1).await;
    s.wait_registered(&app).await;
    s.wait_registered(&old).await;
    assert_eq!(
        s.status.snapshot().scope,
        "full",
        "the first launch walks everything"
    );
    s.stop().await;

    // While stopped: one marker project next to the session project, one far away.
    let sibling = e.home.join("dev/sibling");
    marker(&sibling, "# sibling");
    let far = e.home.join("far/new");
    marker(&far, "# new");
    fs::remove_file(old.join("CLAUDE.md")).unwrap();

    let Some(s) = Stack::start_with(&e.home, &e.data, clock.clone(), opts(false)).await else {
        return;
    };
    s.wait_scans(1).await;
    let st = s.status.snapshot();
    assert_eq!(st.scope, "dev_roots");
    assert_eq!(st.dev_roots, ["~/dev"]);
    s.wait_registered(&sibling).await;
    assert!(
        s.by_path(&far).await.is_none(),
        "outside the development roots"
    );
    let o = s.by_path(&old).await.unwrap();
    assert!(!o.missing, "a project persists when its marker is deleted");
    s.stop().await;

    let Some(s) = Stack::start_with(&e.home, &e.data, clock, opts(true)).await else {
        return;
    };
    s.wait_scans(1).await;
    assert_eq!(s.status.snapshot().scope, "full");
    s.wait_registered(&far).await;
    s.stop().await;
}

/// M3.1 through the real ingest: a session in a container folder (`~/dev`, no Git, no marker)
/// registers nothing, before and after the projects below it are known (M3 review M4); a session
/// in a nested marker folder without Git (`monorepo/services/api`) belongs to the monorepo on the
/// first launch already; a session in an excluded folder is read only up to its first cwd; and a
/// session file copied into a second directory is indexed once (M3 review L4).
#[tokio::test]
async fn containers_nested_markers_excluded_folders_and_duplicates_in_the_ingest() {
    let _g = inotify_lock().lock().await;
    let e = env();
    let h = &e.home;
    let claude = h.join(".claude");
    marker(&h.join("dev/app-a"), "# a");
    marker(&h.join("dev/app-b"), "# b");
    let mono = h.join("dev/monorepo");
    fs::create_dir_all(mono.join(".git")).unwrap();
    marker(&mono, "# mono");
    marker(&mono.join("services/api"), "# api");
    let observer = h.join(".tool/observer-sessions");
    fs::create_dir_all(&observer).unwrap();
    let session = |dir: &str, id: &str, cwd: &Path, extra: usize| {
        let enc = claude.join("projects").join(dir);
        fs::create_dir_all(&enc).unwrap();
        let mut body = session_line(id, "2026-11-24T09:00:00.000Z", cwd, "x");
        for i in 0..extra {
            body.push_str(&session_line(
                id,
                &format!("2026-11-24T10:{:02}:00.000Z", i % 60),
                cwd,
                "SYNTHETIC-NEVER-READ",
            ));
        }
        fs::write(enc.join(format!("{id}.jsonl")), body).unwrap();
        enc.join(format!("{id}.jsonl"))
    };
    let dev_sid = "d0d0d0d0-0000-4000-8000-000000000001";
    let api_sid = "d0d0d0d0-0000-4000-8000-000000000002";
    let obs_sid = "d0d0d0d0-0000-4000-8000-000000000003";
    session("-dev", dev_sid, &h.join("dev"), 0);
    session(
        "-dev-monorepo-services-api",
        api_sid,
        &mono.join("services/api"),
        0,
    );
    let obs_file = session("-tool-observer", obs_sid, &observer, 50);
    // The same file copied into a second directory (and an upper-case copy: not a session).
    let copy = claude.join("projects/-dev-monorepo-copy");
    fs::create_dir_all(&copy).unwrap();
    fs::copy(
        claude.join(format!(
            "projects/-dev-monorepo-services-api/{api_sid}.jsonl"
        )),
        copy.join(format!("{api_sid}.jsonl")),
    )
    .unwrap();
    fs::copy(
        copy.join(format!("{api_sid}.jsonl")),
        copy.join(format!("{}.jsonl", api_sid.to_uppercase())),
    )
    .unwrap();
    let opts = Opts {
        full_scan: false,
        claude_dir: Some(claude.clone()),
        ..Opts::default()
    };
    let clock = now_clock();
    let Some(s) = Stack::start_with(h, &e.data, clock.clone(), opts.clone()).await else {
        return;
    };
    s.wait_scans(1).await;
    // Umbrella first: the markers below ~/dev were only on disk when the session was resolved.
    s.wait_registered(&h.join("dev/app-a")).await;
    s.wait_registered(&h.join("dev/app-b")).await;
    assert!(
        s.by_path(&h.join("dev")).await.is_none(),
        "~/dev is no project"
    );
    let dev = s.session(dev_sid).await.unwrap();
    assert_eq!(
        (dev.project_id.as_deref(), dev.unassigned.as_deref()),
        (None, Some("container"))
    );
    // The nested marker folder belongs to the monorepo.
    let m = s.wait_registered(&mono).await;
    assert!(s.by_path(&mono.join("services/api")).await.is_none());
    assert_eq!(
        s.session(api_sid).await.unwrap().project_id,
        Some(m.id.clone())
    );
    // Excluded: read up to its first cwd only.
    let obs = s.session(obs_sid).await.unwrap();
    assert_eq!(obs.unassigned.as_deref(), Some("excluded"));
    assert!(obs.checkpoint.partial);
    assert_eq!(obs.aggregate.counts.lines, 1, "nothing after the first cwd");
    assert!(obs.checkpoint.offset < fs::metadata(&obs_file).unwrap().len());
    // One file per id; the upper-case copy is not a session at all.
    let st = s.status.snapshot().sessions;
    assert_eq!(st.duplicate_ids, 1, "{st:?}");
    assert_eq!(st.indexed, 3);
    assert_eq!(st.unassigned.get("container"), Some(&1));
    assert_eq!(st.unassigned.get("excluded"), Some(&1));
    assert!(
        st.unassigned_folders
            .iter()
            .any(|f| f.reason == "container" && f.folder.as_deref() == Some("~/dev")),
        "{st:?}"
    );
    s.stop().await;

    // Projects first: they are registered now; the ~/dev session is resolved again.
    let Some(s) = Stack::start_with(h, &e.data, clock, opts).await else {
        return;
    };
    s.wait_scans(1).await;
    assert!(s.by_path(&h.join("dev")).await.is_none());
    assert_eq!(
        s.session(dev_sid).await.unwrap().unassigned.as_deref(),
        Some("container")
    );
    let obs = s.session(obs_sid).await.unwrap();
    assert_eq!(obs.aggregate.counts.lines, 1, "still not read further");
    s.stop().await;
}
