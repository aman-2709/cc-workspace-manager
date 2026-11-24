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
use cc_workspace_manager::tracker::{Control, Settings as TrackerSettings, Tracker};
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

struct Stack {
    tracker: Arc<Tracker>,
    reader: Reader,
    writer: Arc<Writer>,
    monitor: SharedMonitor,
    clock: Arc<FakeClock>,
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
        let tracker = Tracker::new(
            Arc::clone(&writer),
            reader.clone(),
            clock.clone(),
            notifier.clone(),
            SharedStatus::default(),
            Arc::new(Git::detect(
                find_on_path(std::env::var_os("PATH").as_deref()),
                home,
                false,
            )),
            monitor_tx.clone(),
            monitor_state.clone(),
            TrackerSettings {
                scan,
                interval: Duration::from_secs(3600),
                retention_secs: RETENTION,
                events_per_project: 50,
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
            reader,
            writer,
            monitor: monitor_state,
            clock,
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
