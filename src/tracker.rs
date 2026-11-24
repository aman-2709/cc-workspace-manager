//! Keeps the project list and its activity, Git and monitoring state current (REQUIREMENTS.md §4.5,
//! §5, §6): the reconciliation loop, the handling of the monitor's [`Signal`]s, and the Git
//! refresh queue. The only component that combines discovery, the tree walk, Git and the watch
//! engine; the transports reach it only through [`Control`] messages from the service.

use crate::clock::Clock;
use crate::db::queries::{self, Tracked};
use crate::db::reader::Reader;
use crate::db::writer::{Activity, ActivityKind, ProjectUpsert, Source, Upserted, Writer};
use crate::discovery::exclusions::Exclusions;
use crate::discovery::status::SharedStatus;
use crate::discovery::walk::{scan, scan_subtree, Candidate, ScanOptions, Subtree};
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
    pub interval: Duration,
    pub retention_secs: i64,
    pub events_per_project: u32,
}

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
        })
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
        let mut delay = self.settings.interval;
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
                    delay = self.settings.interval;
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
        let (summary, rows) = self.scan_all().await?;
        if summary.cancelled {
            return Ok(());
        }
        let now = self.clock.now();
        let tracked = self.tracked().await?;

        // Missing: registered, present, not found, and not under a root that failed to scan
        // (an unmounted disk must not make all its projects missing).
        let found: HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        let failed: Vec<PathBuf> = self
            .status
            .snapshot()
            .roots
            .iter()
            .filter(|r| r.state != "ok")
            .map(|r| std::fs::canonicalize(&r.path).unwrap_or_else(|_| PathBuf::from(&r.path)))
            .collect();
        let lost: Vec<String> = tracked
            .iter()
            .filter(|t| !t.missing && !found.contains(t.id.as_str()))
            .filter(|t| !failed.iter().any(|f| Path::new(&t.path).starts_with(f)))
            .map(|t| t.id.clone())
            .collect();
        for id in self.writer.mark_missing(lost, now).await? {
            self.unwatch(&id).await;
            self.notifier.project(&id);
        }

        // New and revived projects: walk, Git, move matching, watches.
        let fresh: Vec<&Upserted> = rows.iter().filter(|r| r.inserted || r.revived).collect();
        if first {
            self.plan_all(&fresh).await?;
        } else {
            for row in fresh {
                self.enroll(&row.id, row.inserted).await?;
            }
            self.refresh_polled(rescan_all).await?;
        }

        let retention = now - self.settings.retention_secs;
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
            "reconciliation finished"
        );
        Ok(())
    }

    /// The full discovery scan on a blocking thread; batches are stored as they arrive.
    async fn scan_all(
        self: &Arc<Self>,
    ) -> Result<(crate::discovery::walk::ScanSummary, Vec<Upserted>)> {
        let me = Arc::clone(self);
        let res = tokio::task::spawn_blocking(move || {
            let mut rows = Vec::new();
            let summary = scan(&me.settings.scan, &me.cancel, &me.status, &mut |batch| {
                me.store_candidates_blocking(batch, &mut rows)
            });
            me.notifier.status();
            (summary, rows)
        })
        .await
        .map_err(|e| crate::error::Error::new(format!("scan task failed: {e}")))?;
        Ok(res)
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
            self.record_inferred(&id, &tree).await;
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
    /// their Git state refreshed, and their watches retried.
    async fn refresh_polled(self: &Arc<Self>, all: bool) -> Result<()> {
        let tracked = self.tracked().await?;
        let ids: Vec<(String, PathBuf)> = tracked
            .iter()
            .filter(|t| !t.missing && !t.ignored)
            .filter(|t| {
                all || self
                    .monitor_state
                    .of(&t.id)
                    .is_none_or(|(m, _)| m == crate::watch::Monitoring::Polled)
            })
            .map(|t| (t.id.clone(), PathBuf::from(&t.path)))
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let trees = self.walk_many(ids, &tracked).await;
        let mut plan = Vec::new();
        for (id, tree) in trees {
            self.record_inferred(&id, &tree).await;
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
        Ok(())
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
        let roots = s
            .roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .filter_map(|r| {
                Exclusions::new(&r, &s.home, &s.exclude, &s.boundaries, &s.fuse_mounts)
                    .ok()
                    .map(|e| (r, e))
            })
            .collect();
        WalkContext {
            roots,
            others: tracked
                .iter()
                .filter(|t| !t.missing)
                .map(|t| PathBuf::from(&t.path))
                .collect(),
            home: s.home.clone(),
            max_depth: s.max_depth,
            same_file_system: s.same_file_system,
        }
    }

    async fn record_inferred(&self, id: &str, tree: &Tree) {
        let Some((at, path)) = &tree.newest else {
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
        self.record_inferred(&id, &tree).await;
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
        let inside_project = tracked
            .iter()
            .filter(|t| !t.missing)
            .any(|t| dir.starts_with(&t.path) && dir != Path::new(&t.path));
        let sub = Subtree {
            root,
            start: dir.to_path_buf(),
            inside_project,
        };
        let opts = s.clone();
        let cancel = Arc::clone(&self.cancel);
        Ok(tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            scan_subtree(&opts, &sub, &cancel, &mut |b| {
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
    roots: Vec<(PathBuf, Exclusions)>,
    others: HashSet<PathBuf>,
    home: PathBuf,
    max_depth: usize,
    same_file_system: bool,
}

impl WalkContext {
    fn walk(&self, root: &Path, now: i64) -> Option<Tree> {
        let (_, ex) = self
            .roots
            .iter()
            .filter(|(r, _)| root.starts_with(r))
            .max_by_key(|(r, _)| r.as_os_str().len())?;
        let mut others = self.others.clone();
        others.remove(root);
        let opts = TreeOptions {
            exclusions: ex,
            other_projects: &others,
            max_depth: self.max_depth,
            same_file_system: self.same_file_system,
            git_aware: tree::in_git_worktree(root, &self.home),
            now,
            max_entries: tree::MAX_ENTRIES,
        };
        tree::walk(root, &opts).ok()
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
