//! Keeps the project list and its activity, Git, session and monitoring state current
//! (REQUIREMENTS.md §4.5, §5, §6, §7): the reconciliation loop, the handling of the monitor's
//! [`Signal`]s, the Git refresh queue and the session ingest ([`sessions`]). The only component
//! that combines discovery, the tree walk, Git, sessions and the watch engine; the transports
//! reach it only through [`Control`] messages from the service.

mod sessions;

use crate::clock::Clock;
use crate::db::queries::{self, Tracked};
use crate::db::reader::Reader;
use crate::db::writer::{Activity, ActivityKind, ProjectUpsert, Source, Upserted, Writer};
use crate::discovery::exclusions::Exclusions;
use crate::discovery::status::SharedStatus;
use crate::discovery::walk::{scan_scope, scan_subtree, Candidate, ScanOptions, Scope, Subtree};
use crate::error::Result;
use crate::events::Notifier;
use crate::git::Git;
use crate::watch::tree::{self, Tree, TreeOptions};
use crate::watch::{Cmd, SharedMonitor, Signal, WatchProject};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Notify, Semaphore};

/// Requests from the service layer (HTTP and Unix-socket transports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Coalesced reconciliation (`POST /refresh`, `ccwm scan`).
    Refresh,
    Ignored(String),
    Unignored(String),
}

#[derive(Clone)]
pub struct Settings {
    pub scan: ScanOptions,
    /// The daemon's user: only a `.git` it owns makes a Git work tree (as for Git itself).
    pub uid: u32,
    /// Initial values of the settings that can change while running ([`Live`]).
    pub interval: Duration,
    pub retention_secs: i64,
    pub events_per_project: u32,
    /// Walk every root at every reconciliation ("Scan entire home"); otherwise only the first
    /// reconciliation ever walks everything, later ones only the development roots (§4.5).
    pub full_scan: bool,
    /// The session integration; `None` disables it (tests of the M2 machinery).
    pub sessions: Option<SessionSettings>,
    /// The limit on ignore rules across projects; the monitor's settings hold the same one.
    pub ignore_budget: Arc<tree::IgnoreBudget>,
}

#[derive(Clone)]
pub struct SessionSettings {
    /// Claude Code's config directory (canonical); sessions are under `projects/`.
    pub config_dir: PathBuf,
    /// Temporary directories (see [`crate::discovery::resolve::temp_dirs`]).
    pub temp_dirs: Vec<PathBuf>,
    /// The `claude` CLI check, refreshed at each reconciliation.
    pub claude: Option<Arc<crate::claude::cli::Verifier>>,
}

/// Settings `PUT /settings` changes without a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Live {
    pub interval: Duration,
    pub retention_secs: i64,
    pub full_scan: bool,
}

/// Development roots are walked this many levels deep (configured roots and home: one level).
pub const DEV_ROOT_DEPTH: usize = 3;
/// `meta` key: the first full marker scan has completed.
const FULL_SCAN_DONE: &str = "full_scan_done_at";

/// Longest wait between failed reconciliations (exponential back-off from `interval`).
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

pub struct Tracker {
    writer: Arc<Writer>,
    reader: Reader,
    clock: Arc<dyn Clock>,
    notifier: Notifier,
    status: SharedStatus,
    monitor: mpsc::Sender<Cmd>,
    monitor_state: SharedMonitor,
    pub git: Arc<GitQueue>,
    settings: Settings,
    refresh: Notify,
    /// `(a reconciliation is running, reconciliations finished)`, changed together.
    progress: Mutex<(bool, u64)>,
    rescan_all: AtomicBool,
    cancel: Arc<AtomicBool>,
    live: Mutex<Live>,
    /// Session ingests never overlap (reconciliation and live session events).
    session_lock: tokio::sync::Mutex<()>,
}

impl Tracker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        writer: Arc<Writer>,
        reader: Reader,
        clock: Arc<dyn Clock>,
        notifier: Notifier,
        status: SharedStatus,
        git: Arc<Git>,
        monitor: mpsc::Sender<Cmd>,
        monitor_state: SharedMonitor,
        settings: Settings,
    ) -> Arc<Self> {
        let queue = Arc::new(GitQueue {
            git,
            slots: Arc::new(Semaphore::new(crate::git::MAX_CONCURRENT)),
            state: Mutex::new(HashMap::new()),
            writer: Arc::clone(&writer),
            reader: reader.clone(),
            clock: Arc::clone(&clock),
            notifier: notifier.clone(),
        });
        let live = Live {
            interval: settings.interval,
            retention_secs: settings.retention_secs,
            full_scan: settings.full_scan,
        };
        Arc::new(Self {
            writer,
            reader,
            clock,
            notifier,
            status,
            monitor,
            monitor_state,
            git: queue,
            settings,
            refresh: Notify::new(),
            progress: Mutex::new((false, 0)),
            rescan_all: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            live: Mutex::new(live),
            session_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn live(&self) -> Live {
        self.live.lock().map(|l| *l).unwrap_or(Live {
            interval: self.settings.interval,
            retention_secs: self.settings.retention_secs,
            full_scan: self.settings.full_scan,
        })
    }

    /// Apply changed live settings; a new interval takes effect after the current wait.
    pub fn set_live(&self, live: Live) {
        if let Ok(mut l) = self.live.lock() {
            *l = live;
        }
        self.refresh.notify_one();
    }

    /// Ask for a reconciliation soon; requests during a scan coalesce into one more scan.
    /// Returns the value of `scans_finished` at which the requested scan has finished.
    pub fn request_refresh(&self) -> u64 {
        let target = self
            .progress
            .lock()
            .map(|p| p.1 + if p.0 { 2 } else { 1 })
            .unwrap_or(u64::MAX);
        self.refresh.notify_one();
        target
    }

    fn set_reconciling(&self, running: bool) {
        if let Ok(mut p) = self.progress.lock() {
            p.0 = running;
            if !running {
                p.1 += 1;
                let n = p.1;
                self.status.update(|s| s.scans_finished = n);
            }
        }
    }

    /// Stop a running scan (shutdown).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.refresh.notify_one();
    }

    // ---- reconciliation loop ----------------------------------------------------------------

    /// Reconcile at startup, then every `interval` or on request, never overlapping; back off on
    /// errors.
    pub async fn run_reconciler(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut first = true;
        let mut delay = self.live().interval;
        loop {
            if *stop.borrow() {
                break;
            }
            self.set_reconciling(true);
            let outcome = self.reconcile(first).await;
            self.set_reconciling(false);
            match outcome {
                Ok(()) => {
                    first = false;
                    delay = self.live().interval;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "reconciliation failed; backing off");
                    delay = (delay * 2).min(MAX_BACKOFF);
                }
            }
            let next = self.clock.now() + i64::try_from(delay.as_secs()).unwrap_or(i64::MAX);
            self.status.update(|s| s.next_scan_at = Some(next));
            self.notifier.status();
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = self.refresh.notified() => {}
                () = crate::events::until_stopped(&mut stop) => break,
            }
        }
    }

    async fn reconcile(self: &Arc<Self>, first: bool) -> Result<()> {
        let rescan_all = self.rescan_all.swap(false, Ordering::Relaxed);
        self.check_claude().await;
        // Sessions first (the primary source): they also decide the development roots.
        let mut rows = self.ingest_sessions(None).await?;
        let full = self.live().full_scan || !self.full_scan_done().await?;
        let (summary, scanned) = self.scan_markers(full).await?;
        if summary.cancelled {
            return Ok(());
        }
        if full {
            let _ = self
                .writer
                .set_meta(FULL_SCAN_DONE, &self.clock.now().to_string())
                .await;
        }
        rows.extend(scanned);
        let now = self.clock.now();
        let tracked = self.tracked().await?;

        // Missing: a present project whose directory is gone, unless its root is unavailable (an
        // unmounted disk must not make all its projects missing). Projects persist otherwise,
        // even when their marker or their session files are deleted (§4.5).
        let failed: Vec<PathBuf> = self
            .status
            .snapshot()
            .roots
            .iter()
            .filter(|r| r.state != "ok")
            .map(|r| std::fs::canonicalize(&r.path).unwrap_or_else(|_| PathBuf::from(&r.path)))
            .collect();
        let unavailable = |t: &Tracked| failed.iter().any(|f| Path::new(&t.path).starts_with(f));
        let lost: Vec<String> = tracked
            .iter()
            .filter(|t| !t.missing && !is_dir(&t.path) && !unavailable(t))
            .map(|t| t.id.clone())
            .collect();
        for id in self.writer.mark_missing(lost, now).await? {
            self.unwatch(&id).await;
            self.notifier.project(&id);
        }
        // Revived: a missing project whose directory is back.
        let back: Vec<String> = tracked
            .iter()
            .filter(|t| t.missing && is_dir(&t.path))
            .map(|t| t.id.clone())
            .collect();
        for id in self.writer.revive(back, now).await? {
            self.notifier.project(&id);
            rows.push(Upserted {
                id,
                canonical_path: String::new(),
                inserted: false,
                revived: true,
            });
        }

        // New and revived projects: walk, Git, move matching, watches.
        let mut seen = HashSet::new();
        let fresh: Vec<&Upserted> = rows
            .iter()
            .filter(|r| (r.inserted || r.revived) && seen.insert(r.id.clone()))
            .collect();
        if first {
            self.plan_all(&fresh).await?;
        } else {
            for row in fresh {
                self.enroll(&row.id, row.inserted).await?;
            }
            self.refresh_polled(rescan_all).await?;
        }

        let retention = now - self.live().retention_secs;
        for id in self.writer.purge_missing(retention).await? {
            self.notifier.removed(&id);
        }
        if self
            .writer
            .set_meta("last_scan_ok_at", &now.to_string())
            .await
            .is_ok()
        {
            self.status.update(|s| s.last_success_at = Some(now));
        }
        if rescan_all {
            let _ = self.monitor.send(Cmd::OverflowRecovered).await;
        }
        tracing::info!(
            dirs = summary.dirs_visited,
            projects = summary.projects_found,
            full,
            "reconciliation finished"
        );
        Ok(())
    }

    async fn full_scan_done(&self) -> Result<bool> {
        Ok(self
            .reader
            .with(|c| queries::get_meta(c, FULL_SCAN_DONE))
            .await?
            .is_some())
    }

    /// Present projects that can be the outer project of the nested rule in a marker scan:
    /// those with a Git work tree or a `CLAUDE.md` at their root. A session-only project (e.g.
    /// `~/dev` from an older ccwm) never makes the markers below it nested (M3 review, M4).
    /// Metadata only (`lstat` of two names per project).
    fn nesting_projects(tracked: &[Tracked]) -> Vec<&Tracked> {
        tracked
            .iter()
            .filter(|t| !t.missing && crate::discovery::resolve::is_anchored(Path::new(&t.path)))
            .collect()
    }

    fn known_paths(tracked: &[Tracked]) -> HashSet<String> {
        Self::nesting_projects(tracked)
            .into_iter()
            .map(|t| t.path.clone())
            .collect()
    }

    /// A nesting project strictly contains `dir`.
    fn inside_project(tracked: &[Tracked], dir: &Path) -> bool {
        Self::nesting_projects(tracked)
            .iter()
            .any(|t| dir.starts_with(&t.path) && dir != Path::new(&t.path))
    }

    /// Canonical configured roots with their exclusion rules.
    fn root_exclusions(&self) -> Vec<(PathBuf, Exclusions)> {
        let s = &self.settings.scan;
        s.roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .filter_map(|r| {
                Exclusions::new(&r, &s.home, &s.exclude, &s.boundaries, &s.fuse_mounts)
                    .ok()
                    .map(|e| (r, e))
            })
            .collect()
    }

    /// The development roots (§4.5): parents of session-discovered projects inside a configured
    /// root, walked [`DEV_ROOT_DEPTH`] levels deep (a configured root or home: one level).
    async fn dev_roots(&self, tracked: &[Tracked]) -> Result<Vec<Subtree>> {
        let parents = self.reader.with(queries::session_project_parents).await?;
        let roots = self.root_exclusions();
        let home = std::fs::canonicalize(&self.settings.scan.home)
            .unwrap_or_else(|_| self.settings.scan.home.clone());
        let mut out = Vec::new();
        for p in parents {
            let Ok(start) = std::fs::canonicalize(&p) else {
                continue;
            };
            let Some((root, ex)) = roots
                .iter()
                .filter(|(r, _)| start.starts_with(r))
                .max_by_key(|(r, _)| r.as_os_str().len())
            else {
                continue;
            };
            if ex.is_under_boundary(&start) {
                continue;
            }
            let inside_project = Self::inside_project(tracked, &start);
            let max_rel_depth = Some(if start == *root || start == home {
                1
            } else {
                DEV_ROOT_DEPTH
            });
            out.push(Subtree {
                root: root.clone(),
                start,
                inside_project,
                max_rel_depth,
            });
        }
        out.dedup_by(|a, b| a.start == b.start);
        Ok(out)
    }

    /// The marker scan: every root (`full`) or the development roots.
    async fn scan_markers(
        self: &Arc<Self>,
        full: bool,
    ) -> Result<(crate::discovery::walk::ScanSummary, Vec<Upserted>)> {
        let tracked = self.tracked().await?;
        let known = Self::known_paths(&tracked);
        let dev = if full {
            Vec::new()
        } else {
            self.dev_roots(&tracked).await?
        };
        let home = self.settings.scan.home.clone();
        self.status.update(|s| {
            s.scope = if full { "full" } else { "dev_roots" };
            s.dev_roots = dev
                .iter()
                .map(|d| crate::view::display_path(&d.start.to_string_lossy(), &home))
                .collect();
        });
        let me = Arc::clone(self);
        let res = tokio::task::spawn_blocking(move || {
            let mut rows = Vec::new();
            let scope = if full {
                Scope::Full
            } else {
                Scope::DevRoots(&dev)
            };
            let summary = scan_scope(
                &me.settings.scan,
                &known,
                scope,
                &me.cancel,
                &me.status,
                &mut |batch| me.store_candidates_blocking(batch, &mut rows),
            );
            me.notifier.status();
            (summary, rows)
        })
        .await
        .map_err(|e| crate::error::Error::new(format!("scan task failed: {e}")))?;
        Ok(res)
    }

    async fn check_claude(&self) {
        let Some(v) = self
            .settings
            .sessions
            .as_ref()
            .and_then(|s| s.claude.clone())
        else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || v.refresh()).await;
    }

    fn store_candidates_blocking(&self, batch: Vec<Candidate>, rows: &mut Vec<Upserted>) -> bool {
        let upserts = batch.into_iter().map(upsert_of).collect();
        match self
            .writer
            .upsert_projects_blocking(upserts, self.clock.now())
        {
            Ok(summary) => {
                for r in &summary.rows {
                    if r.inserted || r.revived {
                        self.notifier.project(&r.id); // progressive publication (§4.5)
                    }
                }
                self.notifier.status();
                rows.extend(summary.rows);
                true
            }
            Err(_) => false,
        }
    }

    async fn tracked(&self) -> Result<Vec<Tracked>> {
        self.reader.with(queries::tracked_projects).await
    }

    /// First reconciliation: walk every present project, record inferred activity, then hand the
    /// monitor one plan ordered by recency (roots first), then refresh Git for everything.
    async fn plan_all(self: &Arc<Self>, fresh: &[&Upserted]) -> Result<()> {
        let tracked = self.tracked().await?;
        let live: Vec<&Tracked> = tracked
            .iter()
            .filter(|t| !t.missing && !t.ignored)
            .collect();
        let jobs: Vec<(String, PathBuf)> = live
            .iter()
            .map(|t| (t.id.clone(), PathBuf::from(&t.path)))
            .collect();
        let trees = self.walk_many(jobs, &tracked).await;
        let mut plan = Vec::new();
        for (id, tree) in trees {
            self.record_inferred(&id, tree.newest.as_ref()).await;
            plan.push(WatchProject { id, tree });
        }
        plan.sort_by_key(|p| std::cmp::Reverse(p.tree.newest.as_ref().map(|n| n.0)));
        let _ = self.monitor.send(Cmd::Plan(plan)).await;
        let inserted: HashSet<&str> = fresh
            .iter()
            .filter(|r| r.inserted)
            .map(|r| r.id.as_str())
            .collect();
        let any_missing = tracked.iter().any(|t| t.missing);
        for t in live {
            if any_missing && inserted.contains(t.id.as_str()) {
                // A new project might be a moved missing one: needs its Git state first.
                self.enroll(&t.id, true).await?;
            } else {
                self.git.request(&t.id);
            }
        }
        Ok(())
    }

    /// Polled projects (and, after an overflow, every project) are walked for newer file times,
    /// their Git state refreshed, and their watches retried. A partly watched project is walked
    /// only in its unwatched subtrees (its watched part is live), then those are retried.
    async fn refresh_polled(self: &Arc<Self>, all: bool) -> Result<()> {
        use crate::watch::{Monitoring, PollReason};
        let tracked = self.tracked().await?;
        let mut whole: Vec<(String, PathBuf)> = Vec::new();
        let mut partial: Vec<(String, PathBuf, crate::watch::PollTarget)> = Vec::new();
        for t in tracked.iter().filter(|t| !t.missing && !t.ignored) {
            let job = (t.id.clone(), PathBuf::from(&t.path));
            match (all, self.monitor_state.of(&t.id)) {
                (false, Some((Monitoring::Watched, _))) => {}
                (false, Some((Monitoring::Partial, reason)))
                    if reason != Some(PollReason::Truncated) =>
                {
                    if let Some(target) = self.monitor_state.poll_target(&t.id) {
                        partial.push((job.0, job.1, target));
                    } else {
                        whole.push(job);
                    }
                }
                _ => whole.push(job),
            }
        }
        if !whole.is_empty() {
            let trees = self.walk_many(whole, &tracked).await;
            let mut plan = Vec::new();
            for (id, tree) in trees {
                self.record_inferred(&id, tree.newest.as_ref()).await;
                self.git.request(&id);
                plan.push(WatchProject { id, tree });
            }
            if all {
                let _ = self.monitor.send(Cmd::Plan(plan)).await;
            } else {
                for p in plan {
                    let _ = self.monitor.send(Cmd::Add(p)).await;
                }
            }
        }
        if !partial.is_empty() {
            for (id, newest, roots, dirs) in self.walk_subtrees(partial, &tracked).await {
                self.record_inferred(&id, newest.as_ref()).await;
                self.git.request(&id);
                let _ = self.monitor.send(Cmd::Retry { id, roots, dirs }).await;
            }
        }
        Ok(())
    }

    /// Walk the unwatched subtrees of partly watched projects (blocking thread): per project
    /// the newest file found, the subtree roots, and their directories shallow first (`.git` is
    /// retried as a watch, never walked).
    async fn walk_subtrees(
        &self,
        jobs: Vec<(String, PathBuf, crate::watch::PollTarget)>,
        tracked: &[Tracked],
    ) -> Vec<(String, Option<(i64, String)>, Vec<PathBuf>, Vec<PathBuf>)> {
        let ctx = self.walk_context(tracked);
        let now = self.clock.now();
        tokio::task::spawn_blocking(move || {
            jobs.into_iter()
                .map(|(id, root, target)| {
                    let mut newest: Option<(i64, String)> = None;
                    let mut dirs = Vec::new();
                    for sub in &target.subtrees {
                        if *sub == root.join(".git") {
                            dirs.push(sub.clone());
                            continue;
                        }
                        let Some(t) = ctx.walk_from(&root, sub, &target.ignore, now) else {
                            continue; // vanished: forgotten by the retry
                        };
                        if t.newest
                            .as_ref()
                            .is_some_and(|n| newest.as_ref().is_none_or(|m| n.0 > m.0))
                        {
                            newest = t.newest;
                        }
                        dirs.extend(t.dirs);
                    }
                    dirs.sort_by_key(|d| d.components().count());
                    (id, newest, target.subtrees, dirs)
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// Walk several project trees, one after another, on a blocking thread.
    async fn walk_many(
        &self,
        jobs: Vec<(String, PathBuf)>,
        tracked: &[Tracked],
    ) -> Vec<(String, Tree)> {
        let ctx = self.walk_context(tracked);
        let now = self.clock.now();
        tokio::task::spawn_blocking(move || {
            jobs.into_iter()
                .filter_map(|(id, path)| ctx.walk(&path, now).map(|t| (id, t)))
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    fn walk_context(&self, tracked: &[Tracked]) -> WalkContext {
        let s = &self.settings.scan;
        // Projects that are no longer monitored keep no rules: their part of the limit across
        // projects is free again before anything is walked.
        let monitored: HashSet<&Path> = tracked
            .iter()
            .filter(|t| !t.missing && !t.ignored)
            .map(|t| Path::new(&t.path))
            .collect();
        self.settings
            .ignore_budget
            .retain(|root| monitored.contains(root));
        WalkContext {
            budget: Arc::clone(&self.settings.ignore_budget),
            roots: self.root_exclusions(),
            others: tracked
                .iter()
                .filter(|t| !t.missing)
                .map(|t| PathBuf::from(&t.path))
                .collect(),
            home: s.home.clone(),
            uid: self.settings.uid,
            max_depth: s.max_depth,
            same_file_system: s.same_file_system,
        }
    }

    async fn record_inferred(&self, id: &str, newest: Option<&(i64, String)>) {
        let Some((at, path)) = newest else {
            return;
        };
        let activity = Activity {
            at: *at,
            kind: ActivityKind::Inferred,
            path: Some(path.clone()),
        };
        if let Ok(true) = self
            .writer
            .record_activity(id, activity, Vec::new(), self.settings.events_per_project)
            .await
        {
            self.notifier.project(id);
        }
    }

    /// Bring one project into monitoring: walk, inferred activity, Git, move matching (for a new
    /// project), watches.
    async fn enroll(self: &Arc<Self>, id: &str, inserted: bool) -> Result<()> {
        let Some(row) = self
            .reader
            .with({
                let id = id.to_string();
                move |c| queries::get_project(c, &id)
            })
            .await?
        else {
            return Ok(());
        };
        if row.ignored || row.missing_since.is_some() {
            return Ok(());
        }
        let tracked = self.tracked().await?;
        let path = PathBuf::from(&row.path);
        let Some((_, tree)) = self
            .walk_many(vec![(id.to_string(), path.clone())], &tracked)
            .await
            .pop()
        else {
            return Ok(());
        };
        let info = self.git.inspect_now(&path).await;
        let mut id = id.to_string();
        if inserted && tracked.iter().any(|t| t.missing) {
            if let Some(old) = self.match_move(&id, &info).await? {
                let name = path
                    .file_name()
                    .map_or_else(|| row.path.clone(), |n| n.to_string_lossy().into_owned());
                self.writer
                    .move_project(&old, &row.path, &name, self.clock.now())
                    .await?;
                tracing::info!("a missing project was found at a new path (same content)");
                self.notifier.removed(&id);
                id = old;
            }
        }
        self.writer.store_git(&id, info, self.clock.now()).await?;
        self.record_inferred(&id, tree.newest.as_ref()).await;
        self.notifier.project(&id);
        let ignored = self
            .reader
            .with({
                let id = id.clone();
                move |c| queries::get_project(c, &id)
            })
            .await?
            .is_some_and(|r| r.ignored);
        if !ignored {
            let _ = self.monitor.send(Cmd::Add(WatchProject { id, tree })).await;
        }
        Ok(())
    }

    /// The unique missing project that `new_id` is a moved copy of, if any (§4.5 fallback).
    async fn match_move(&self, new_id: &str, info: &crate::git::Info) -> Result<Option<String>> {
        let (new_id, head, remote) = (
            new_id.to_string(),
            info.head.as_ref().map(|h| h.hash.clone()),
            info.remote_url.clone(),
        );
        let found = self
            .reader
            .with(move |c| queries::move_sources(c, &new_id, head.as_deref(), remote.as_deref()))
            .await?;
        Ok(match found.as_slice() {
            [one] => Some(one.clone()),
            _ => None, // none, or ambiguous: never guess
        })
    }

    async fn unwatch(&self, id: &str) {
        let _ = self.monitor.send(Cmd::Remove(id.to_string())).await;
    }

    // ---- signals and controls ---------------------------------------------------------------

    /// Handle the monitor's signals in order until `stop`.
    pub async fn run_signals(
        self: Arc<Self>,
        mut signals: mpsc::Receiver<Signal>,
        mut stop: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                () = crate::events::until_stopped(&mut stop) => break,
                s = signals.recv() => {
                    let Some(s) = s else { break };
                    if let Err(e) = self.on_signal(s).await {
                        tracing::warn!(error = %e, "handling a filesystem change failed");
                    }
                }
            }
        }
    }

    pub async fn on_control(self: &Arc<Self>, c: Control) -> Result<()> {
        match c {
            Control::Refresh => {
                self.request_refresh();
            }
            Control::Ignored(id) => self.unwatch(&id).await,
            Control::Unignored(id) => self.enroll(&id, false).await?,
        }
        Ok(())
    }

    pub async fn on_signal(self: &Arc<Self>, s: Signal) -> Result<()> {
        match s {
            Signal::Activity {
                id,
                at,
                path,
                events,
                git,
            } => {
                let activity = Activity {
                    at,
                    kind: ActivityKind::Observed,
                    path,
                };
                if self
                    .writer
                    .record_activity(&id, activity, events, self.settings.events_per_project)
                    .await?
                {
                    self.notifier.project(&id);
                }
                if git {
                    self.git.request(&id);
                }
            }
            Signal::Git { id } => self.git.request(&id),
            Signal::Rewalk { id } => self.enroll(&id, false).await?,
            Signal::Discover(dir) => self.discover(&dir).await?,
            Signal::Vanished { id } => {
                for id in self.writer.mark_missing(vec![id], self.clock.now()).await? {
                    self.notifier.project(&id);
                }
            }
            Signal::Moved { from, to } => self.moved(&from, &to).await?,
            Signal::Rescan => {
                self.rescan_all.store(true, Ordering::Relaxed);
                self.request_refresh();
            }
            Signal::Sessions(dirs) => {
                for row in self.ingest_sessions(Some(dirs)).await? {
                    if row.inserted || row.revived {
                        tracing::info!("new project registered from a session");
                        self.enroll(&row.id, row.inserted).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Re-discover one directory with the scan rules; register and enroll what it yields.
    async fn discover(self: &Arc<Self>, dir: &Path) -> Result<()> {
        let candidates = self.scan_dir(dir).await?;
        if candidates.is_empty() {
            return Ok(());
        }
        let upserts = candidates.into_iter().map(upsert_of).collect();
        let summary = self
            .writer
            .upsert_projects(upserts, self.clock.now())
            .await?;
        for row in summary.rows.iter().filter(|r| r.inserted || r.revived) {
            tracing::info!("new project registered from a filesystem event");
            self.notifier.project(&row.id);
            self.enroll(&row.id, row.inserted).await?;
        }
        self.notifier.status();
        Ok(())
    }

    /// Candidates a full scan would register at or below `dir`.
    async fn scan_dir(&self, dir: &Path) -> Result<Vec<Candidate>> {
        let s = &self.settings.scan;
        let Some(root) = s
            .roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .filter(|r| dir.starts_with(r))
            .max_by_key(|r| r.as_os_str().len())
        else {
            return Ok(Vec::new());
        };
        let tracked = self.tracked().await?;
        let inside_project = Self::inside_project(&tracked, dir);
        let sub = Subtree {
            root,
            start: dir.to_path_buf(),
            inside_project,
            max_rel_depth: None,
        };
        let opts = s.clone();
        let cancel = Arc::clone(&self.cancel);
        let known = Self::known_paths(&tracked);
        Ok(tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            scan_subtree(&opts, &sub, &known, &cancel, &mut |b| {
                out.extend(b);
                true
            });
            out
        })
        .await
        .unwrap_or_default())
    }

    /// A paired rename moved `from` to `to`: every project at or below `from` keeps its id if the
    /// new location still qualifies, else it becomes missing.
    async fn moved(self: &Arc<Self>, from: &Path, to: &Path) -> Result<()> {
        let tracked = self.tracked().await?;
        let still: HashSet<String> = self
            .scan_dir(to)
            .await?
            .into_iter()
            .map(|c| c.canonical_path)
            .collect();
        for t in tracked.iter().filter(|t| !t.missing) {
            let Ok(rel) = Path::new(&t.path).strip_prefix(from) else {
                continue;
            };
            // `join("")` would append a trailing slash: the root itself moves to `to` exactly.
            let new_path = if rel.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(rel)
            };
            let Some(new) = new_path.to_str().filter(|p| still.contains(*p)) else {
                for id in self
                    .writer
                    .mark_missing(vec![t.id.clone()], self.clock.now())
                    .await?
                {
                    self.notifier.project(&id);
                }
                continue;
            };
            let name = new_path
                .file_name()
                .map_or_else(|| new.to_string(), |n| n.to_string_lossy().into_owned());
            if let Some(dup) = self
                .writer
                .move_project(&t.id, new, &name, self.clock.now())
                .await?
            {
                self.unwatch(&dup).await;
                self.notifier.removed(&dup);
            }
            tracing::info!("a project directory was renamed; its id is kept");
            self.notifier.project(&t.id);
            self.enroll(&t.id, false).await?;
        }
        Ok(())
    }
}

fn is_dir(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn upsert_of(c: Candidate) -> ProjectUpsert {
    ProjectUpsert {
        canonical_path: c.canonical_path,
        name: c.name,
        source: Source::Marker,
        marker_hash: c.marker_hash,
    }
}

/// Everything a tree walk needs, owned so it can move to a blocking thread.
struct WalkContext {
    budget: Arc<tree::IgnoreBudget>,
    roots: Vec<(PathBuf, Exclusions)>,
    others: HashSet<PathBuf>,
    home: PathBuf,
    /// The user whose `.git` directories count as work trees (the daemon's).
    uid: u32,
    max_depth: usize,
    same_file_system: bool,
}

impl WalkContext {
    fn walk(&self, root: &Path, now: i64) -> Option<Tree> {
        self.walk_from(root, root, &tree::GitIgnore::default(), now)
    }

    /// The part of project `root` at and below `start`, with the project's known rules `base`
    /// (see [`tree::walk_from`]).
    fn walk_from(
        &self,
        root: &Path,
        start: &Path,
        base: &tree::GitIgnore,
        now: i64,
    ) -> Option<Tree> {
        let (discovery_root, ex) = self
            .roots
            .iter()
            .filter(|(r, _)| root.starts_with(r))
            .max_by_key(|(r, _)| r.as_os_str().len())?;
        let mut others = self.others.clone();
        others.remove(root);
        let repo = tree::git_worktree_root(root, discovery_root, &self.home, self.uid);
        // A full walk replaces the project's rules: it reserves its share of the limit across
        // projects and settles for what it kept. A subtree walk keeps nothing.
        let full = start == root;
        let max_patterns = if full {
            self.budget.reserve(root)
        } else {
            self.budget.room(root)
        };
        let opts = TreeOptions {
            exclusions: ex,
            other_projects: &others,
            max_depth: self.max_depth,
            same_file_system: self.same_file_system,
            git_aware: repo.is_some(),
            repo_root: repo.as_deref(),
            now,
            max_entries: tree::MAX_ENTRIES,
            max_patterns,
        };
        let tree = tree::walk_from(root, start, base, &opts).ok();
        if full {
            let kept = tree.as_ref().map_or(0, |t| t.ignore.patterns());
            self.budget.settle(root, kept);
        }
        tree
    }
}

/// Git refreshes: at most [`crate::git::MAX_CONCURRENT`] processes at a time, one refresh per
/// project at a time; a request during a refresh schedules exactly one more.
pub struct GitQueue {
    git: Arc<Git>,
    slots: Arc<Semaphore>,
    /// Project id -> "refresh again when done".
    state: Mutex<HashMap<String, bool>>,
    writer: Arc<Writer>,
    reader: Reader,
    clock: Arc<dyn Clock>,
    notifier: Notifier,
}

impl GitQueue {
    pub fn summary(&self) -> crate::git::GitSummary {
        self.git.summary()
    }

    pub fn in_flight(&self) -> usize {
        self.state.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Inspect `path` now (bounded by the concurrency limit).
    pub async fn inspect_now(&self, path: &Path) -> crate::git::Info {
        let Ok(_permit) = self.slots.acquire().await else {
            return crate::git::Info::only(crate::git::State::Error);
        };
        let (git, path) = (Arc::clone(&self.git), path.to_path_buf());
        tokio::task::spawn_blocking(move || git.inspect(&path))
            .await
            .unwrap_or_else(|_| crate::git::Info::only(crate::git::State::Error))
    }

    pub fn request(self: &Arc<Self>, id: &str) {
        {
            let Ok(mut st) = self.state.lock() else {
                return;
            };
            if let Some(again) = st.get_mut(id) {
                *again = true;
                return;
            }
            st.insert(id.to_string(), false);
        }
        let (me, id) = (Arc::clone(self), id.to_string());
        tokio::spawn(async move {
            loop {
                me.refresh_once(&id).await;
                let Ok(mut st) = me.state.lock() else {
                    return;
                };
                match st.get_mut(&id) {
                    Some(again) if *again => *again = false,
                    _ => {
                        st.remove(&id);
                        return;
                    }
                }
            }
        });
    }

    async fn refresh_once(&self, id: &str) {
        let path = {
            let id = id.to_string();
            self.reader
                .with(move |c| queries::project_path(c, &id))
                .await
        };
        let Ok(Some(path)) = path else { return };
        let info = self.inspect_now(Path::new(&path)).await;
        if self
            .writer
            .store_git(id, info, self.clock.now())
            .await
            .is_ok()
        {
            self.notifier.project(id);
        }
    }
}
