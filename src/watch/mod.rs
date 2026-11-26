//! Filesystem monitoring (REQUIREMENTS.md §5.1/§5.2): **one** inotify instance for the whole
//! daemon, **non-recursive** watches on eligible directories only, a watch budget, degraded
//! ("polled") mode, per-project debouncing and the meaningful-activity rules.
//!
//! The [`Monitor`] is an actor: it owns the notify watcher and the watch table, receives raw
//! events and [`Cmd`]s, and emits [`Signal`]s for the tracker (activity to record, Git caches to
//! refresh, directories to re-discover, projects that vanished or moved). It never touches the
//! database and never reads file contents. Directory walks run on the blocking pool.

pub mod tree;

use crate::clock::Clock;
use crate::db::writer::{EventKind as FileEventKind, FileEvent};
use crate::discovery::exclusions::Exclusions;
use crate::discovery::walk::MARKER_NAME;
use notify::event::{CreateKind, EventKind, ModifyKind, RenameMode};
use notify::{Config as NotifyConfig, EventKindMask, RecursiveMode, WatchPathConfig, Watcher};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch as tokio_watch};
use tokio::time::Instant;
use tree::{GitIgnore, Tree, TreeOptions};

/// Raw events buffered between notify's thread and the monitor; when full, events are dropped
/// and handled like a kernel queue overflow (§5.1).
pub const EVENT_QUEUE: usize = 8192;
/// The budget when `max_user_watches` cannot be read.
pub const FALLBACK_BUDGET: usize = 8192;
/// An unpaired half of a rename is acted on after this long (notify pairs halves by cookie).
const RENAME_PAIRING: Duration = Duration::from_millis(200);
/// Directories created in a sibling-detection area are watched this many levels deep.
const PARENT_AREA_LEVELS: u8 = 1;

pub fn read_max_user_watches() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 25 % of `max_user_watches` (§5.1; the pool is shared with IDEs and other tools, so ccwm never
/// takes more by default); [`FALLBACK_BUDGET`] if the limit cannot be read.
pub fn default_budget(max_user_watches: Option<u64>) -> usize {
    max_user_watches.map_or(FALLBACK_BUDGET, |m| {
        usize::try_from(m / 4).unwrap_or(usize::MAX)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Monitoring {
    /// Every eligible directory has a watch: changes are observed live.
    Watched,
    /// The root and part of the tree are watched; the subtrees without a watch are checked at
    /// each reconciliation (mtimes), the rest is live.
    Partial,
    /// The root has no watch (or there is no inotify instance): the whole project is checked at
    /// each reconciliation.
    Polled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PollReason {
    /// The watch budget is used up.
    Budget,
    /// The kernel refused more watches (`max_user_watches`).
    KernelLimit,
    /// The inotify instance could not be created (`max_user_instances`).
    WatcherUnavailable,
    /// The tree is larger than one walk examines.
    Truncated,
}

/// A project to watch, with its freshly walked tree.
#[derive(Debug)]
pub struct WatchProject {
    pub id: String,
    pub tree: Tree,
}

pub enum Cmd {
    /// Replace every project watch. Breadth first: every project's root, then the roots'
    /// parents (sibling detection), then every project's `.git` and top-level directories, then
    /// the deeper directories project by project in the given order (most recent first).
    Plan(Vec<WatchProject>),
    /// Add or replace one project.
    Add(WatchProject),
    Remove(String),
    /// Try again to watch a partly watched project's unwatched subtrees: `roots` are the subtree
    /// roots being retried (forgotten first, e.g. if they vanished), `dirs` their directories
    /// as walked now, shallow first.
    Retry {
        id: String,
        roots: Vec<PathBuf>,
        dirs: Vec<PathBuf>,
    },
    /// The reconciliation triggered by an overflow has finished.
    OverflowRecovered,
    /// Watch exactly these session directories (Claude Code's `projects/` first, then its
    /// `<encoded-dir>` children), non-recursively; others watched for sessions are dropped.
    WatchSessions(Vec<PathBuf>),
    /// Internal: a walk of a directory created at runtime finished. `rules_out_of_date`: it met
    /// an ignore file that the project's rules do not hold ([`Tree::rules_out_of_date`]).
    Walked {
        owner: Owner,
        tree: Tree,
        rules_out_of_date: bool,
    },
}

/// What the tracker must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Meaningful activity (debounced). `path`: the latest modified *file* (`None` if only
    /// directories changed). `git`: the project's Git state may have changed too.
    Activity {
        id: String,
        at: i64,
        path: Option<String>,
        events: Vec<FileEvent>,
        git: bool,
    },
    /// Only Git metadata changed (`.git/HEAD`, index, refs…): refresh the Git cache.
    Git { id: String },
    /// Re-walk the project (its `.gitignore` changed).
    Rewalk { id: String },
    /// A directory (or a `CLAUDE.md` / `.git` in it) appeared: re-discover it with the scan rules.
    Discover(PathBuf),
    /// The project's root directory disappeared.
    Vanished { id: String },
    /// A directory was renamed (both halves seen): projects at or below `from` moved to `to`.
    Moved { from: PathBuf, to: PathBuf },
    /// Events were lost (`IN_Q_OVERFLOW` or our queue was full): reconcile everything.
    Rescan,
    /// Session files changed in these `<encoded-dir>` directories (debounced); Claude Code's
    /// `projects/` directory itself in the list means "every session".
    Sessions(Vec<PathBuf>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Project(String),
    /// Sibling detection: the parent of a project (level 0) or a directory created below one.
    Parent(u8),
    /// Claude Code's session directories (`projects/` and its children).
    Sessions,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MonitorStatus {
    /// `inotify` or `unavailable`.
    pub watcher: &'static str,
    pub watches: usize,
    pub budget: usize,
    pub max_user_watches: Option<u64>,
    /// Every eligible directory watched.
    pub watched_projects: usize,
    /// Root watched, some subtrees checked at each reconciliation.
    pub partial_projects: usize,
    /// No root watch: the whole project is checked at each reconciliation.
    pub polled_projects: usize,
    pub overflows: u64,
    pub recovering_overflow: bool,
    /// Projects with debounced events not yet recorded.
    pub pending_projects: usize,
    /// Session directories watched (live session updates; otherwise found at each scan).
    pub session_watches: usize,
    /// `.gitignore` / `.git/info/exclude` files not read because of a limit (per file, per
    /// project or across projects), over all projects (their rules do not apply; see
    /// [`tree::MAX_GITIGNORE_BYTES`] and [`tree::MAX_GITIGNORE_PATTERNS_TOTAL`]).
    pub ignore_files_skipped: u64,
    /// The names of the projects that lack ignore rules because of the limit across projects
    /// (sorted): file events in them are judged without those rules; their scans use them.
    pub ignore_rules_limited: Vec<String>,
    /// Real failures only: no inotify instance, a queue overflow being recovered, or projects
    /// without any watch (polled). Partly watched projects are normal operation (§5.1).
    pub degraded: bool,
    /// Guidance (shown by the UI banner and `ccwm doctor`); never applied automatically.
    pub advice: Vec<String>,
    #[serde(skip)]
    pub projects: HashMap<String, (Monitoring, Option<PollReason>)>,
    /// What reconciliation polls for partly watched projects (absent: the whole project).
    #[serde(skip)]
    pub poll_targets: HashMap<String, PollTarget>,
}

/// The unwatched part of a partly watched project.
#[derive(Debug, Clone)]
pub struct PollTarget {
    /// Roots of the subtrees without a watch, shallowest first.
    pub subtrees: Vec<PathBuf>,
    /// The project's ignore rules, for walking the subtrees with the project's rules.
    pub ignore: Arc<GitIgnore>,
}

#[derive(Debug, Clone, Default)]
pub struct SharedMonitor(Arc<Mutex<MonitorStatus>>);

impl SharedMonitor {
    pub fn snapshot(&self) -> MonitorStatus {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// `(monitoring, reason)` of a project; `None` if it is not monitored (ignored, missing, new).
    pub fn of(&self, id: &str) -> Option<(Monitoring, Option<PollReason>)> {
        self.0.lock().ok()?.projects.get(id).copied()
    }

    /// The subtrees to poll for a partly watched project; `None`: poll the whole project.
    pub fn poll_target(&self, id: &str) -> Option<PollTarget> {
        self.0.lock().ok()?.poll_targets.get(id).cloned()
    }

    fn set(&self, s: MonitorStatus) {
        if let Ok(mut g) = self.0.lock() {
            *g = s;
        }
    }
}

/// Inputs of the monitor that do not change while it runs.
#[derive(Clone)]
pub struct Settings {
    /// Canonical discovery roots (for the exclusion rules of directories created at runtime).
    pub roots: Vec<PathBuf>,
    pub home: PathBuf,
    pub exclude: Vec<String>,
    pub boundaries: Vec<PathBuf>,
    pub fuse_mounts: Vec<PathBuf>,
    pub max_depth: usize,
    pub same_file_system: bool,
    pub budget: usize,
    pub max_user_watches: Option<u64>,
    pub debounce: Duration,
    pub events_per_project: usize,
    /// The ignore rules the projects keep (the tracker's walks use the same store; the monitor
    /// only reports which projects lack theirs).
    pub rules: Arc<tree::RuleStore>,
}

/// The watcher abstraction the monitor needs; [`notify::INotifyWatcher`] in production.
pub trait WatchBackend: Send {
    /// Add a non-recursive watch on a directory, never following a symlink.
    fn watch(&mut self, dir: &Path) -> Result<(), WatchError>;
    fn unwatch(&mut self, dir: &Path);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchError {
    /// `ENOSPC`: the kernel's per-user limit.
    KernelLimit,
    /// The directory vanished or is not a directory.
    Gone,
    Other,
}

impl WatchBackend for notify::INotifyWatcher {
    /// `IN_DONT_FOLLOW` (no dereference). notify first asks for `IN_ONLYDIR` but, on `ENOTDIR`,
    /// silently retries without it (notify 9 `add_single_watch`), so a directory swapped for a
    /// regular file would be watched as that file: the path must still be a directory after the
    /// watch was added, else the watch is dropped. This narrows the swap window; it does not
    /// close it (watches are added by path, SECURITY.md).
    fn watch(&mut self, dir: &Path) -> Result<(), WatchError> {
        let cfg =
            WatchPathConfig::new(RecursiveMode::NonRecursive).with_dereference_symlinks(false);
        Watcher::watch_with(self, dir, cfg).map_err(|e| match e.kind {
            notify::ErrorKind::MaxFilesWatch => WatchError::KernelLimit,
            notify::ErrorKind::PathNotFound => WatchError::Gone,
            _ => WatchError::Other,
        })?;
        if !is_dir(dir) {
            let _ = Watcher::unwatch(self, dir);
            return Err(WatchError::Gone);
        }
        Ok(())
    }
    fn unwatch(&mut self, dir: &Path) {
        let _ = Watcher::unwatch(self, dir);
    }
}

/// Raw events from the backend: notify's results, or a synthetic overflow.
pub type RawEvent = notify::Result<notify::Event>;

/// Create the single inotify instance. Events go to `tx`; if it is full, `dropped` is set
/// (treated like `IN_Q_OVERFLOW`). `None` if the instance cannot be created.
pub fn inotify_backend(
    tx: mpsc::Sender<RawEvent>,
    dropped: Arc<AtomicBool>,
) -> Result<notify::INotifyWatcher, notify::Error> {
    let handler = move |ev: RawEvent| {
        if tx.try_send(ev).is_err() {
            dropped.store(true, Ordering::Relaxed);
        }
    };
    let cfg = NotifyConfig::default()
        .with_follow_symlinks(false)
        .with_event_kinds(EventKindMask::CORE);
    notify::INotifyWatcher::new(handler, cfg)
}

struct ProjectState {
    root: PathBuf,
    git_dir: Option<PathBuf>,
    ignore: Arc<GitIgnore>,
    git_aware: bool,
    /// Why part (or all) of the project is not watched; the first reason wins.
    polled: Option<PollReason>,
    /// The walk stopped at the entry limit: unknown parts, so the whole project is polled.
    truncated: bool,
    /// Ignore files of the project's last full walk that a size limit skipped.
    ignore_files_skipped: u64,
    /// Roots of the subtrees that got no watch because of a limit (the root itself when it has
    /// none). Only subtree roots: nothing below a refused directory is listed or watched.
    refused: HashSet<PathBuf>,
}

impl ProjectState {
    fn mode(&self, has_backend: bool) -> (Monitoring, Option<PollReason>) {
        if !has_backend || self.refused.contains(&self.root) {
            (Monitoring::Polled, self.polled)
        } else if self.polled.is_some() {
            (Monitoring::Partial, self.polled)
        } else {
            (Monitoring::Watched, None)
        }
    }

    fn inside_refused(&self, dir: &Path) -> bool {
        dir.ancestors().skip(1).any(|a| self.refused.contains(a))
    }
}

#[derive(Default)]
struct Pending {
    first: Option<Instant>,
    /// Meaningful activity happened (`at` is valid).
    active: bool,
    at: i64,
    path: Option<String>,
    events: Vec<FileEvent>,
    git: bool,
    rewalk: bool,
}

/// One half of a rename, waiting for its partner.
struct RenameHalf {
    since: Instant,
    from: Option<PathBuf>,
    to: Option<PathBuf>,
}

/// A normalized filesystem change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change {
    Created { path: PathBuf, dir: bool },
    Modified(PathBuf),
    Removed(PathBuf),
}

/// What clients are told about (a `monitoring` event) when it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    watches: usize,
    partial: usize,
    polled: usize,
    recovering: bool,
    overflows: u64,
    projects: usize,
}

pub struct Monitor {
    backend: Option<Box<dyn WatchBackend>>,
    settings: Settings,
    roots: Vec<(PathBuf, Exclusions)>,
    clock: Arc<dyn Clock>,
    watches: HashMap<PathBuf, Owner>,
    projects: HashMap<String, ProjectState>,
    by_root: HashMap<PathBuf, String>,
    pending: HashMap<String, Pending>,
    renames: HashMap<usize, RenameHalf>,
    overflows: u64,
    recovering: bool,
    signals: mpsc::Sender<Signal>,
    self_tx: mpsc::Sender<Cmd>,
    shared: SharedMonitor,
    notifier: Option<crate::events::Notifier>,
    /// Last published summary, to notify clients only on change.
    last_summary: Option<Summary>,
    /// Projects, watches or degraded state changed since the last full publication.
    dirty: bool,
    /// Claude Code's `projects/` directory (from the last `WatchSessions`).
    sessions_root: Option<PathBuf>,
    /// Session directories with changes not yet signalled, and when the first one came.
    session_pending: Option<(Instant, HashSet<PathBuf>)>,
}

impl Monitor {
    /// `backend`: `None` when the inotify instance could not be created (every project polled).
    pub fn new(
        backend: Option<Box<dyn WatchBackend>>,
        settings: Settings,
        clock: Arc<dyn Clock>,
        signals: mpsc::Sender<Signal>,
        self_tx: mpsc::Sender<Cmd>,
        shared: SharedMonitor,
        notifier: Option<crate::events::Notifier>,
    ) -> Self {
        let roots = settings
            .roots
            .iter()
            .filter_map(|r| {
                Exclusions::new(
                    r,
                    &settings.home,
                    &settings.exclude,
                    &settings.boundaries,
                    &settings.fuse_mounts,
                )
                .ok()
                .map(|e| (r.clone(), e))
            })
            .collect();
        let m = Self {
            backend,
            settings,
            roots,
            clock,
            watches: HashMap::new(),
            projects: HashMap::new(),
            by_root: HashMap::new(),
            pending: HashMap::new(),
            renames: HashMap::new(),
            overflows: 0,
            recovering: false,
            signals,
            self_tx,
            shared,
            notifier,
            last_summary: None,
            dirty: true,
            sessions_root: None,
            session_pending: None,
        };
        let mut m = m;
        m.publish();
        m
    }

    /// Run until `stop` turns true. `dropped` is the backend's "queue full" flag.
    pub async fn run(
        mut self,
        mut events: mpsc::Receiver<RawEvent>,
        mut cmds: mpsc::Receiver<Cmd>,
        dropped: Arc<AtomicBool>,
        mut stop: tokio_watch::Receiver<bool>,
    ) {
        loop {
            let deadline = self.next_deadline();
            tokio::select! {
                biased;
                () = crate::events::until_stopped(&mut stop) => break,
                Some(cmd) = cmds.recv() => self.on_cmd(cmd),
                Some(ev) = events.recv() => self.on_raw(ev),
                () = sleep_until_opt(deadline) => {}
            }
            if dropped.swap(false, Ordering::Relaxed) {
                self.on_overflow();
            }
            self.flush_due(Instant::now());
            self.publish();
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        let debounce = self
            .pending
            .values()
            .filter_map(|p| p.first)
            .min()
            .map(|t| t + self.settings.debounce);
        let rename = self
            .renames
            .values()
            .map(|r| r.since + RENAME_PAIRING)
            .min();
        let sessions = self
            .session_pending
            .as_ref()
            .map(|(t, _)| *t + self.settings.debounce);
        [debounce, rename, sessions].into_iter().flatten().min()
    }

    // ---- commands -------------------------------------------------------------------------------

    pub fn on_cmd(&mut self, cmd: Cmd) {
        self.dirty = true;
        self.apply(cmd);
        self.publish();
    }

    fn apply(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Plan(projects) => self.plan(projects),
            Cmd::Add(p) => {
                self.remove_project(&p.id);
                self.plan_more(vec![p]);
            }
            Cmd::Remove(id) => self.remove_project(&id),
            Cmd::Retry { id, roots, dirs } => self.retry(&id, &roots, &dirs),
            Cmd::OverflowRecovered => self.recovering = false,
            Cmd::WatchSessions(dirs) => self.watch_sessions(dirs),
            Cmd::Walked {
                owner,
                tree,
                rules_out_of_date,
            } => self.watch_new_tree(&owner, &tree, rules_out_of_date),
        }
    }

    /// Session watches come before project watches in the budget: they are few (one per
    /// project directory of Claude Code) and make new sessions appear live.
    fn watch_sessions(&mut self, dirs: Vec<PathBuf>) {
        self.sessions_root = dirs.first().cloned();
        let wanted: HashSet<&PathBuf> = dirs.iter().collect();
        let stale: Vec<PathBuf> = self
            .watches
            .iter()
            .filter(|(d, o)| **o == Owner::Sessions && !wanted.contains(d))
            .map(|(d, _)| d.clone())
            .collect();
        for d in stale {
            self.drop_watch(&d);
        }
        for d in &dirs {
            if self.add_watch(d, Owner::Sessions).is_err() {
                break; // a limit: the rest is found at each reconciliation
            }
        }
    }

    fn plan(&mut self, projects: Vec<WatchProject>) {
        let ids: Vec<String> = self.projects.keys().cloned().collect();
        for id in ids {
            self.remove_project(&id);
        }
        self.plan_more(projects);
    }

    /// Budget allocation, breadth first (see [`Cmd::Plan`]): every project gets its root (and its
    /// `.git` and top-level directories) before any project gets deeper directories. Once a limit
    /// is hit, the remaining directories are refused without asking the kernel again; a project
    /// whose root is watched but not all of its tree is *partly* watched.
    fn plan_more(&mut self, projects: Vec<WatchProject>) {
        for p in &projects {
            self.by_root.insert(p.tree.root.clone(), p.id.clone());
            let git_aware = p.tree.git_dir.is_some() || !p.tree.ignore.is_empty();
            self.projects.insert(
                p.id.clone(),
                ProjectState {
                    root: p.tree.root.clone(),
                    git_dir: p.tree.git_dir.clone(),
                    ignore: Arc::clone(&p.tree.ignore),
                    git_aware,
                    polled: p.tree.truncated.then_some(PollReason::Truncated),
                    truncated: p.tree.truncated,
                    ignore_files_skipped: p.tree.ignore_files_skipped,
                    refused: HashSet::new(),
                },
            );
        }
        let mut limit = self
            .backend
            .is_none()
            .then_some(PollReason::WatcherUnavailable);
        for p in &projects {
            self.watch_dir(&p.id, &p.tree.root, &mut limit);
        }
        for p in &projects {
            if let Some(parent) = p.tree.root.parent() {
                if limit.is_none() && self.within_roots(parent) {
                    if let Err(reason) = self.add_watch(parent, Owner::Parent(0)) {
                        limit = Some(reason);
                    }
                }
            }
        }
        let depth = |p: &WatchProject, d: &Path| {
            d.strip_prefix(&p.tree.root)
                .map_or(usize::MAX, |r| r.components().count())
        };
        for p in &projects {
            let top = p
                .tree
                .git_dir
                .iter()
                .chain(p.tree.dirs.iter().skip(1).filter(|d| depth(p, d) == 1));
            for d in top {
                self.watch_dir(&p.id, d, &mut limit);
            }
        }
        for p in &projects {
            let mut deeper: Vec<&PathBuf> =
                p.tree.dirs.iter().filter(|d| depth(p, d) > 1).collect();
            deeper.sort_by_key(|d| depth(p, d)); // stable: preorder within a level
            for d in deeper {
                self.watch_dir(&p.id, d, &mut limit);
            }
        }
    }

    /// Watch `dir` for project `id`, or refuse it when a limit is (or gets) reached: `limit`
    /// carries the first limit hit during this command, so later directories do not ask the
    /// kernel again. Directories inside a refused subtree are skipped.
    fn watch_dir(&mut self, id: &str, dir: &Path, limit: &mut Option<PollReason>) {
        let Some(state) = self.projects.get(id) else {
            return;
        };
        if state.inside_refused(dir) {
            return;
        }
        let result = match *limit {
            Some(reason) => Err(reason),
            None => self.add_watch(dir, Owner::Project(id.to_string())),
        };
        if let Err(reason) = result {
            *limit = Some(reason);
            if let Some(state) = self.projects.get_mut(id) {
                state.refused.insert(dir.to_path_buf());
                state.polled.get_or_insert(reason);
            }
        }
    }

    /// Reconciliation polled a partly watched project's subtrees: try to watch them again.
    fn retry(&mut self, id: &str, roots: &[PathBuf], dirs: &[PathBuf]) {
        let Some(state) = self.projects.get_mut(id) else {
            return;
        };
        for r in roots {
            state.refused.remove(r);
        }
        let mut limit = None;
        for d in dirs {
            self.watch_dir(id, d, &mut limit);
        }
        self.settle(id);
    }

    /// A project with nothing refused (and a complete tree) is fully watched again.
    fn settle(&mut self, id: &str) {
        if self.backend.is_none() {
            return;
        }
        if let Some(state) = self.projects.get_mut(id) {
            if state.refused.is_empty() && !state.truncated {
                state.polled = None;
            }
        }
    }

    /// `Err(reason)` if the directory cannot be watched because of a limit.
    fn add_watch(&mut self, dir: &Path, owner: Owner) -> Result<(), PollReason> {
        if self.watches.contains_key(dir) {
            return Ok(());
        }
        let Some(backend) = self.backend.as_mut() else {
            return Err(PollReason::WatcherUnavailable);
        };
        if self.watches.len() >= self.settings.budget {
            return Err(PollReason::Budget);
        }
        match backend.watch(dir) {
            Ok(()) => {
                self.watches.insert(dir.to_path_buf(), owner);
                self.dirty = true;
                Ok(())
            }
            Err(WatchError::KernelLimit) => Err(PollReason::KernelLimit),
            Err(WatchError::Gone | WatchError::Other) => Ok(()), // nothing to watch there
        }
    }

    fn remove_project(&mut self, id: &str) {
        let Some(p) = self.projects.remove(id) else {
            return;
        };
        self.dirty = true;
        self.by_root.remove(&p.root);
        self.pending.remove(id);
        let owner = Owner::Project(id.to_string());
        let dirs: Vec<PathBuf> = self
            .watches
            .iter()
            .filter(|(_, o)| **o == owner)
            .map(|(d, _)| d.clone())
            .collect();
        for d in dirs {
            self.drop_watch(&d);
        }
    }

    fn drop_watch(&mut self, dir: &Path) {
        if self.watches.remove(dir).is_some() {
            self.dirty = true;
            if let Some(b) = self.backend.as_mut() {
                b.unwatch(dir);
            }
        }
    }

    /// Forget watches at or below `dir` (it was deleted or moved away; the kernel dropped them).
    fn forget_below(&mut self, dir: &Path) {
        let gone: Vec<PathBuf> = self
            .watches
            .keys()
            .filter(|d| d.starts_with(dir))
            .cloned()
            .collect();
        for d in gone {
            self.drop_watch(&d);
        }
    }

    /// A directory created at runtime was walked: watch it and its eligible subdirectories,
    /// shallow first (refusals make the project partly watched). When the walk met ignore files
    /// that the project's rules do not hold, the project is walked again (debounced, like a
    /// changed `.gitignore`): that full walk reads them within the limit across projects, and
    /// from then on they apply to the events in the new directory.
    fn watch_new_tree(&mut self, owner: &Owner, tree: &Tree, rules_out_of_date: bool) {
        let Owner::Project(id) = owner else {
            return;
        };
        if !self.projects.contains_key(id) {
            return; // removed meanwhile
        }
        let mut dirs: Vec<&PathBuf> = tree.dirs.iter().collect();
        dirs.sort_by_key(|d| d.components().count());
        let mut limit = None;
        for d in dirs {
            self.watch_dir(id, d, &mut limit);
        }
        if rules_out_of_date {
            self.pending_mut(id).rewalk = true;
        }
    }

    // ---- events ---------------------------------------------------------------------------------

    pub fn on_raw(&mut self, ev: RawEvent) {
        self.handle_raw(ev);
        self.publish();
    }

    fn handle_raw(&mut self, ev: RawEvent) {
        let Ok(ev) = ev else { return };
        if ev.need_rescan() {
            self.on_overflow();
            return;
        }
        let now = Instant::now();
        match ev.kind {
            EventKind::Create(kind) => {
                for p in ev.paths {
                    let dir = match kind {
                        CreateKind::Folder => true,
                        CreateKind::File => false,
                        _ => is_dir(&p),
                    };
                    self.on_change(Change::Created { path: p, dir });
                }
            }
            EventKind::Modify(ModifyKind::Name(mode)) => {
                let tracker = ev.attrs.tracker();
                match (mode, tracker) {
                    (RenameMode::Both, Some(t)) if ev.paths.len() == 2 => {
                        self.renames.remove(&t);
                        self.on_rename(&ev.paths[0], &ev.paths[1]);
                    }
                    (RenameMode::From, Some(t)) => {
                        let half = self.renames.entry(t).or_insert(RenameHalf {
                            since: now,
                            from: None,
                            to: None,
                        });
                        half.from = ev.paths.into_iter().next();
                    }
                    (RenameMode::To, Some(t)) => {
                        let half = self.renames.entry(t).or_insert(RenameHalf {
                            since: now,
                            from: None,
                            to: None,
                        });
                        half.to = ev.paths.into_iter().next();
                    }
                    // A watched directory moved itself (`IN_MOVE_SELF`): its parent's watch
                    // reports the rename, if the parent is watched.
                    (RenameMode::From, None) => {}
                    _ => {
                        for p in ev.paths {
                            if p.exists() {
                                let dir = is_dir(&p);
                                self.on_change(Change::Created { path: p, dir });
                            } else {
                                self.on_change(Change::Removed(p));
                            }
                        }
                    }
                }
            }
            EventKind::Modify(ModifyKind::Metadata(_)) | EventKind::Access(_) => {}
            EventKind::Modify(_) | EventKind::Any => {
                for p in ev.paths {
                    self.on_change(Change::Modified(p));
                }
            }
            EventKind::Remove(_) => {
                for p in ev.paths {
                    self.on_change(Change::Removed(p));
                }
            }
            EventKind::Other => {}
        }
    }

    fn on_overflow(&mut self) {
        self.dirty = true;
        self.overflows += 1;
        self.recovering = true;
        self.signal(Signal::Rescan);
    }

    /// Both halves of a rename were seen.
    fn on_rename(&mut self, from: &Path, to: &Path) {
        let moves_projects = self.by_root.keys().any(|r| r.starts_with(from));
        if moves_projects {
            // notify already dropped the watches below `from`; the tracker re-enrolls at `to`.
            let ids: Vec<String> = self
                .by_root
                .iter()
                .filter(|(r, _)| r.starts_with(from))
                .map(|(_, id)| id.clone())
                .collect();
            for id in ids {
                self.remove_project(&id);
            }
            self.forget_below(from);
            self.signal(Signal::Moved {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            });
            return;
        }
        self.on_change(Change::Removed(from.to_path_buf()));
        let dir = is_dir(to);
        self.on_change(Change::Created {
            path: to.to_path_buf(),
            dir,
        });
    }

    /// Resolve rename halves whose partner never came.
    fn expire_renames(&mut self, now: Instant) {
        let due: Vec<usize> = self
            .renames
            .iter()
            .filter(|(_, r)| now >= r.since + RENAME_PAIRING)
            .map(|(t, _)| *t)
            .collect();
        for t in due {
            if let Some(half) = self.renames.remove(&t) {
                if let Some(from) = half.from {
                    self.on_change(Change::Removed(from));
                }
                if let Some(to) = half.to {
                    let dir = is_dir(&to);
                    self.on_change(Change::Created { path: to, dir });
                }
            }
        }
    }

    fn project_of(&self, path: &Path) -> Option<(String, PathBuf)> {
        path.ancestors()
            .find_map(|a| self.by_root.get(a).map(|id| (id.clone(), a.to_path_buf())))
    }

    fn within_roots(&self, path: &Path) -> bool {
        self.roots.iter().any(|(r, _)| path.starts_with(r))
    }

    fn exclusions_for(&self, path: &Path) -> Option<&Exclusions> {
        self.roots
            .iter()
            .filter(|(r, _)| path.starts_with(r))
            .max_by_key(|(r, _)| r.as_os_str().len())
            .map(|(_, e)| e)
    }

    /// A directory a full scan would enter (exclusions of its configured root).
    fn eligible_dir(&self, path: &Path) -> bool {
        let Some(ex) = self.exclusions_for(path) else {
            return false;
        };
        path.file_name()
            .is_some_and(|n| ex.exclude_dir(path, n).is_none())
            && path.to_str().is_some()
    }

    fn on_change(&mut self, change: Change) {
        let path = match &change {
            Change::Created { path, .. } | Change::Modified(path) | Change::Removed(path) => {
                path.clone()
            }
        };
        if path.to_str().is_none() {
            return; // non-UTF-8 names are never tracked
        }
        if self.on_session_change(&path, &change) {
            return;
        }
        match self.project_of(&path) {
            Some((id, root)) if path == root => self.on_project_root(&id, &change),
            Some((id, root)) => self.on_in_project(&id, &root, &path, &change),
            None => self.on_parent_area(&path, &change),
        }
    }

    /// A change in a watched session directory: debounce it into a [`Signal::Sessions`].
    /// `true` if the path belongs to the session tree (and nothing else may handle it).
    fn on_session_change(&mut self, path: &Path, change: &Change) -> bool {
        let Some(root) = self.sessions_root.clone() else {
            return false;
        };
        if !path.starts_with(&root) {
            return false;
        }
        let parent = path.parent().unwrap_or(path);
        let dir = if path == root {
            root.clone() // the directory itself (removed or replaced): everything
        } else if parent == root {
            match change {
                // A new `<encoded-dir>`: watch it now, then ingest it.
                Change::Created { dir: true, .. } => {
                    let _ = self.add_watch(path, Owner::Sessions);
                    path.to_path_buf()
                }
                Change::Removed(_) => {
                    self.forget_below(path);
                    root.clone()
                }
                _ => return true,
            }
        } else if self.watches.get(parent) == Some(&Owner::Sessions) {
            parent.to_path_buf()
        } else {
            return true; // deeper (subagent transcripts…): not sessions in v0.1
        };
        let now = Instant::now();
        self.session_pending
            .get_or_insert_with(|| (now, HashSet::new()))
            .1
            .insert(dir);
        true
    }

    fn on_project_root(&mut self, id: &str, change: &Change) {
        match change {
            Change::Removed(_) => {
                self.remove_project(id);
                self.signal(Signal::Vanished { id: id.to_string() });
            }
            Change::Created { path, .. } => self.signal(Signal::Discover(path.clone())),
            Change::Modified(_) => {}
        }
    }

    fn on_in_project(&mut self, id: &str, root: &Path, path: &Path, change: &Change) {
        let Ok(rel) = path.strip_prefix(root) else {
            return;
        };
        let Some(state) = self.projects.get(id) else {
            return;
        };
        let (git_dir, ignore, git_aware) = (
            state.git_dir.clone(),
            Arc::clone(&state.ignore),
            state.git_aware,
        );
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Git metadata: invalidate the Git cache, never activity (§5.2).
        if git_dir.as_deref().is_some_and(|g| path.starts_with(g))
            || rel
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == ".git")
        {
            if !name.ends_with(".lock") {
                self.pending_mut(id).git = true;
            }
            // `.git` itself appearing in the root: the project became a Git project.
            if rel == Path::new(".git") {
                self.pending_mut(id).rewalk = true;
            }
            return;
        }
        let parent = path.parent().unwrap_or(root);
        // A nested project may be appearing: a marker, or a `.git` next to a marker.
        if (name == MARKER_NAME || name == ".git") && parent != root {
            if matches!(change, Change::Created { .. }) {
                self.signal(Signal::Discover(parent.to_path_buf()));
            }
            if name == ".git" {
                return;
            }
        }
        let (is_dir, kind) = match change {
            Change::Created { dir, .. } => (*dir, FileEventKind::Create),
            Change::Modified(_) => (false, FileEventKind::Modify),
            Change::Removed(_) => (false, FileEventKind::Delete),
        };
        if matches!(change, Change::Removed(_)) {
            self.forget_below(path);
            let had = self.projects.get_mut(id).is_some_and(|s| {
                let before = s.refused.len();
                s.refused.retain(|r| !r.starts_with(path));
                s.refused.len() != before
            });
            if had {
                self.dirty = true;
                self.settle(id);
            }
        }
        if is_dir {
            if !self.eligible_dir(path) || (git_aware && ignore.is_ignored(path, true)) {
                return; // e.g. a new node_modules or a gitignored build directory
            }
            self.walk_new_dir(id, path, git_aware);
            self.signal(Signal::Discover(path.to_path_buf()));
        } else if git_aware && ignore.is_ignored(path, false) {
            return;
        }
        let now = self.clock.now();
        let rel = rel.to_string_lossy().into_owned();
        let limit = self.settings.events_per_project;
        let p = self.pending_mut(id);
        p.active = true;
        p.at = now;
        if !is_dir {
            p.path = Some(rel.clone());
        }
        if p.events.len() >= limit {
            p.events.remove(0);
        }
        p.events.push(FileEvent {
            at: now,
            kind,
            path: rel,
        });
        if name == ".gitignore" {
            p.rewalk = true;
        }
        if git_aware || git_dir.is_some() {
            p.git = true; // a worktree change can change `git status`
        }
    }

    fn on_parent_area(&mut self, path: &Path, change: &Change) {
        let parent = path.parent().unwrap_or(path);
        let level = match self.watches.get(parent) {
            Some(Owner::Parent(l)) => *l,
            _ => return,
        };
        match change {
            Change::Created { dir: true, .. } if self.eligible_dir(path) => {
                // Subdirectories created before this watch existed are not watched; the discovery
                // below finds any project in them, and reconciliation covers the rest.
                if level < PARENT_AREA_LEVELS {
                    let _ = self.add_watch(path, Owner::Parent(level + 1));
                }
                self.signal(Signal::Discover(path.to_path_buf()));
            }
            Change::Created { .. } | Change::Modified(_)
                if path.file_name().and_then(|n| n.to_str()) == Some(MARKER_NAME) =>
            {
                self.signal(Signal::Discover(parent.to_path_buf()));
            }
            Change::Removed(_) => self.forget_below(path),
            _ => {}
        }
    }

    /// Walk a directory created inside project `id` with the project's rules (exclusions, its
    /// ignore layers, depth counted from the project root), then watch the result.
    ///
    /// Each such walk runs on a blocking thread of its own, and a moved-in tree or a checkout
    /// brings many directories at once. So the walk holds no more rules than the project does:
    /// it takes over the layers of unchanged files and compiles nothing beyond them (v0.1.1
    /// review M1: with the project's room in the limit instead, 24 directories of 4,900
    /// expensive rules each took the daemon past 2 GiB). An ignore file it leaves out marks the
    /// project's rules out of date ([`Cmd::Walked`]).
    fn walk_new_dir(&self, id: &str, dir: &Path, git_aware: bool) {
        let (Some(ex), Some(state)) = (self.exclusions_for(dir), self.projects.get(id)) else {
            return;
        };
        let ex = Exclusions::clone(ex);
        let mut others: HashSet<PathBuf> = self.by_root.keys().cloned().collect();
        others.remove(&state.root);
        let (root, ignore, owner) = (
            state.root.clone(),
            Arc::clone(&state.ignore),
            Owner::Project(id.to_string()),
        );
        let (dir, tx, max_depth, same_fs, now) = (
            dir.to_path_buf(),
            self.self_tx.clone(),
            self.settings.max_depth,
            self.settings.same_file_system,
            self.clock.now(),
        );
        tokio::task::spawn_blocking(move || {
            let opts = TreeOptions {
                exclusions: &ex,
                other_projects: &others,
                max_depth,
                same_file_system: same_fs,
                git_aware,
                repo_root: None,
                now,
                max_entries: tree::MAX_ENTRIES,
                max_patterns: ignore.patterns(),
                // A subtree walk starts from the project's rules: they are what it reuses.
                reuse: None,
            };
            if let Ok(tree) = tree::walk_from(&root, &dir, &ignore, &opts) {
                let rules_out_of_date = tree.rules_out_of_date(&ignore);
                let _ = tx.blocking_send(Cmd::Walked {
                    owner,
                    tree,
                    rules_out_of_date,
                });
            }
        });
    }

    fn pending_mut(&mut self, id: &str) -> &mut Pending {
        let p = self.pending.entry(id.to_string()).or_default();
        if p.first.is_none() {
            p.first = Some(Instant::now());
        }
        p
    }

    /// Emit the debounced signals of every project whose window has passed.
    pub fn flush_due(&mut self, now: Instant) {
        self.expire_renames(now);
        let debounce = self.settings.debounce;
        if self
            .session_pending
            .as_ref()
            .is_some_and(|(first, _)| now >= *first + debounce)
        {
            if let Some((_, dirs)) = self.session_pending.take() {
                let mut dirs: Vec<PathBuf> = dirs.into_iter().collect();
                dirs.sort();
                self.signal(Signal::Sessions(dirs));
            }
        }
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| p.first.is_some_and(|f| now >= f + debounce))
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            let Some(p) = self.pending.remove(&id) else {
                continue;
            };
            if p.rewalk {
                self.signal(Signal::Rewalk { id: id.clone() });
            }
            if p.active {
                self.signal(Signal::Activity {
                    id,
                    at: p.at,
                    path: p.path,
                    events: p.events,
                    git: p.git,
                });
            } else if p.git {
                self.signal(Signal::Git { id });
            }
        }
    }

    fn signal(&self, s: Signal) {
        // The tracker drains signals quickly; if it cannot keep up, reconciliation covers it.
        let _ = self.signals.try_send(s);
    }

    /// Publish the status: in full when something changed, otherwise only the pending count.
    fn publish(&mut self) {
        if !self.dirty {
            if let Ok(mut g) = self.shared.0.lock() {
                g.pending_projects = self.pending.len();
            }
            return;
        }
        self.dirty = false;
        let has_backend = self.backend.is_some();
        let mut projects = HashMap::with_capacity(self.projects.len());
        let mut poll_targets = HashMap::new();
        let (mut partial, mut polled) = (0, 0);
        for (id, p) in &self.projects {
            let mode = p.mode(has_backend);
            match mode.0 {
                Monitoring::Watched => {}
                Monitoring::Partial => {
                    partial += 1;
                    if !p.truncated {
                        let mut subtrees: Vec<PathBuf> = p.refused.iter().cloned().collect();
                        subtrees.sort_by_key(|d| (d.components().count(), d.clone()));
                        poll_targets.insert(
                            id.clone(),
                            PollTarget {
                                subtrees,
                                ignore: Arc::clone(&p.ignore),
                            },
                        );
                    }
                }
                Monitoring::Polled => polled += 1,
            }
            projects.insert(id.clone(), mode);
        }
        let mut advice = Vec::new();
        if self.backend.is_none() {
            advice.push("The inotify instance could not be created (fs.inotify.max_user_instances is exhausted): every project is polled at each reconciliation. Close other watching tools or raise the limit (sudo sysctl fs.inotify.max_user_instances=…).".to_string());
        }
        let reasons: HashSet<PollReason> =
            self.projects.values().filter_map(|p| p.polled).collect();
        if reasons.contains(&PollReason::Budget) {
            advice.push(format!("The watch budget ({} watches, 25 % of fs.inotify.max_user_watches by default) is used up: every project root is watched first, then top-level folders, then deeper folders of the most recently active projects; folders without a watch are checked at each scan. Raise [watch] budget in config.toml, or exclude large generated folders.", self.settings.budget));
        }
        if reasons.contains(&PollReason::KernelLimit) {
            advice.push("The kernel's inotify watch limit (fs.inotify.max_user_watches) is reached: folders without a watch are checked at each scan. Raise it with sudo sysctl fs.inotify.max_user_watches=… (ccwm never changes kernel limits).".to_string());
        }
        if reasons.contains(&PollReason::Truncated) {
            advice.push(
                "Some project trees are too large to walk completely: they are partly watched (the part that was walked is watched live; the whole tree is checked at each scan).".to_string(),
            );
        }
        let ignore_files_skipped: u64 =
            self.projects.values().map(|p| p.ignore_files_skipped).sum();
        let mut ignore_rules_limited: Vec<String> = self
            .projects
            .values()
            .filter(|p| self.settings.rules.lacks_rules(&p.root))
            .map(|p| {
                p.root
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            })
            .collect();
        ignore_rules_limited.sort();
        if ignore_files_skipped > 0 {
            advice.push(format!(
                "{ignore_files_skipped} .gitignore or .git/info/exclude file(s) were skipped: larger than {} KiB, or the project has more than {} KiB or {} rules of ignore files, or all projects together have more than {} rules (the most recently active projects keep theirs). Their rules do not apply, so files they would ignore count as activity; only the scans of a project that the limit across projects holds back use all of its rules (compiled for that scan alone).",
                tree::MAX_GITIGNORE_BYTES / 1024,
                tree::MAX_GITIGNORE_TOTAL_BYTES / 1024,
                tree::MAX_GITIGNORE_PATTERNS,
                tree::MAX_GITIGNORE_PATTERNS_TOTAL
            ));
        }
        if self.recovering {
            advice.push(
                "File events were lost (queue overflow); a full reconciliation is catching up."
                    .to_string(),
            );
        }
        let summary = Summary {
            watches: self.watches.len() / 64, // coarse: watch counts move constantly
            partial,
            polled,
            recovering: self.recovering,
            overflows: self.overflows,
            projects: projects.len(),
        };
        if self.last_summary != Some(summary) {
            self.last_summary = Some(summary);
            if let Some(n) = &self.notifier {
                n.status();
            }
        }
        self.shared.set(MonitorStatus {
            watcher: if self.backend.is_some() {
                "inotify"
            } else {
                "unavailable"
            },
            watches: self.watches.len(),
            budget: self.settings.budget,
            max_user_watches: self.settings.max_user_watches,
            watched_projects: projects.len() - partial - polled,
            partial_projects: partial,
            polled_projects: polled,
            overflows: self.overflows,
            recovering_overflow: self.recovering,
            pending_projects: self.pending.len(),
            session_watches: self
                .watches
                .values()
                .filter(|o| **o == Owner::Sessions)
                .count(),
            ignore_files_skipped,
            ignore_rules_limited,
            degraded: !has_backend || polled > 0 || self.recovering,
            advice,
            projects,
            poll_targets,
        });
    }

    /// Watched directories and their owners (tests and diagnostics).
    pub fn watched_dirs(&self) -> Vec<(PathBuf, Owner)> {
        let mut v: Vec<(PathBuf, Owner)> = self
            .watches
            .iter()
            .map(|(p, o)| (p.clone(), o.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

fn is_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_is_a_quarter_of_the_kernel_limit_without_a_fixed_ceiling() {
        assert_eq!(default_budget(Some(65_536)), 16_384);
        assert_eq!(default_budget(Some(8192)), 2048);
        assert_eq!(default_budget(Some(1_048_576)), 262_144, "no 8192 ceiling");
        assert_eq!(default_budget(None), FALLBACK_BUDGET);
        assert_eq!(default_budget(Some(3)), 0);
    }
}
