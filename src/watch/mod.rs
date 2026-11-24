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
pub const MAX_DEFAULT_BUDGET: usize = 8192;
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

/// `min(8192, 25 % of max_user_watches)` (§5.1); 8192 if the limit cannot be read.
pub fn default_budget(max_user_watches: Option<u64>) -> usize {
    max_user_watches
        .map(|m| usize::try_from(m / 4).unwrap_or(usize::MAX))
        .map_or(MAX_DEFAULT_BUDGET, |q| q.min(MAX_DEFAULT_BUDGET))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Monitoring {
    /// Every eligible directory has a watch: changes are observed live.
    Watched,
    /// Some or all directories are not watched: changes are found by reconciliation (mtimes).
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
    /// Replace every project watch: allocate the budget to the projects' roots first, then their
    /// parent directories, then the rest of each tree in the given order (most recent first).
    Plan(Vec<WatchProject>),
    /// Add or replace one project.
    Add(WatchProject),
    Remove(String),
    /// The reconciliation triggered by an overflow has finished.
    OverflowRecovered,
    /// Internal: a walk of a directory created at runtime finished.
    Walked {
        owner: Owner,
        tree: Tree,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Project(String),
    /// Sibling detection: the parent of a project (level 0) or a directory created below one.
    Parent(u8),
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MonitorStatus {
    /// `inotify` or `unavailable`.
    pub watcher: &'static str,
    pub watches: usize,
    pub budget: usize,
    pub max_user_watches: Option<u64>,
    pub watched_projects: usize,
    pub polled_projects: usize,
    pub overflows: u64,
    pub recovering_overflow: bool,
    /// Projects with debounced events not yet recorded.
    pub pending_projects: usize,
    pub degraded: bool,
    /// Guidance (shown by the UI banner and `ccwm doctor`); never applied automatically.
    pub advice: Vec<String>,
    #[serde(skip)]
    pub projects: HashMap<String, (Monitoring, Option<PollReason>)>,
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
    fn watch(&mut self, dir: &Path) -> Result<(), WatchError> {
        let cfg =
            WatchPathConfig::new(RecursiveMode::NonRecursive).with_dereference_symlinks(false);
        Watcher::watch_with(self, dir, cfg).map_err(|e| match e.kind {
            notify::ErrorKind::MaxFilesWatch => WatchError::KernelLimit,
            notify::ErrorKind::PathNotFound => WatchError::Gone,
            _ => WatchError::Other,
        })
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
    polled: Option<PollReason>,
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
    last_summary: Option<(usize, usize, bool, u64, usize)>,
    /// Projects, watches or degraded state changed since the last full publication.
    dirty: bool,
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
        match (debounce, rename) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
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
            Cmd::OverflowRecovered => self.recovering = false,
            Cmd::Walked { owner, tree } => self.watch_new_tree(&owner, &tree),
        }
    }

    fn plan(&mut self, projects: Vec<WatchProject>) {
        let ids: Vec<String> = self.projects.keys().cloned().collect();
        for id in ids {
            self.remove_project(&id);
        }
        self.plan_more(projects);
    }

    /// Budget allocation: roots of all `projects`, then their parents, then the rest of each tree
    /// in order. A project whose tree does not fit entirely is polled.
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
                },
            );
        }
        if self.backend.is_none() {
            for p in &projects {
                self.set_polled(&p.id, PollReason::WatcherUnavailable);
            }
            return;
        }
        for p in &projects {
            if let Err(reason) = self.add_watch(&p.tree.root, Owner::Project(p.id.clone())) {
                self.set_polled(&p.id, reason);
            }
        }
        for p in &projects {
            if let Some(parent) = p.tree.root.parent() {
                if self.within_roots(parent) {
                    let _ = self.add_watch(parent, Owner::Parent(0));
                }
            }
        }
        for p in &projects {
            let owner = Owner::Project(p.id.clone());
            let dirs = p.tree.git_dir.iter().chain(p.tree.dirs.iter().skip(1));
            for d in dirs {
                if let Err(reason) = self.add_watch(d, owner.clone()) {
                    self.set_polled(&p.id, reason);
                    break;
                }
            }
        }
    }

    fn set_polled(&mut self, id: &str, reason: PollReason) {
        if let Some(p) = self.projects.get_mut(id) {
            if p.polled.is_none() {
                p.polled = Some(reason);
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

    fn watch_new_tree(&mut self, owner: &Owner, tree: &Tree) {
        let owner_ok = match owner {
            Owner::Project(id) => self.projects.contains_key(id),
            Owner::Parent(_) => true,
        };
        if !owner_ok {
            return;
        }
        for d in &tree.dirs {
            if let Err(reason) = self.add_watch(d, owner.clone()) {
                if let Owner::Project(id) = owner {
                    let id = id.clone();
                    self.set_polled(&id, reason);
                }
                break;
            }
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
        match self.project_of(&path) {
            Some((id, root)) if path == root => self.on_project_root(&id, &change),
            Some((id, root)) => self.on_in_project(&id, &root, &path, &change),
            None => self.on_parent_area(&path, &change),
        }
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
        }
        if is_dir {
            if !self.eligible_dir(path) || (git_aware && ignore.is_ignored(path, true)) {
                return; // e.g. a new node_modules or a gitignored build directory
            }
            self.walk_new_dir(Owner::Project(id.to_string()), path, git_aware);
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

    fn walk_new_dir(&self, owner: Owner, dir: &Path, git_aware: bool) {
        let Some(ex) = self.exclusions_for(dir) else {
            return;
        };
        let ex = Exclusions::clone(ex);
        let others: HashSet<PathBuf> = self.by_root.keys().cloned().collect();
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
                now,
                max_entries: tree::MAX_ENTRIES,
            };
            if let Ok(tree) = tree::walk(&dir, &opts) {
                let _ = tx.blocking_send(Cmd::Walked { owner, tree });
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
        let mut projects = HashMap::with_capacity(self.projects.len());
        let mut polled = 0;
        for (id, p) in &self.projects {
            let m = if p.polled.is_some() {
                polled += 1;
                Monitoring::Polled
            } else {
                Monitoring::Watched
            };
            projects.insert(id.clone(), (m, p.polled));
        }
        let mut advice = Vec::new();
        if self.backend.is_none() {
            advice.push("The inotify instance could not be created (fs.inotify.max_user_instances is exhausted): every project is polled at each reconciliation. Close other watching tools or raise the limit (sudo sysctl fs.inotify.max_user_instances=…).".to_string());
        }
        let reasons: HashSet<PollReason> =
            self.projects.values().filter_map(|p| p.polled).collect();
        if reasons.contains(&PollReason::Budget) {
            advice.push(format!("The watch budget ({}) is used up: the least recently active projects are polled. Raise [watch] budget in config.toml.", self.settings.budget));
        }
        if reasons.contains(&PollReason::KernelLimit) {
            advice.push("The kernel's inotify watch limit (fs.inotify.max_user_watches) is reached: some projects are polled. Raise it with sudo sysctl fs.inotify.max_user_watches=… (ccwm never changes kernel limits).".to_string());
        }
        if reasons.contains(&PollReason::Truncated) {
            advice.push(
                "Some project trees are too large to walk completely: they are polled.".to_string(),
            );
        }
        if self.recovering {
            advice.push(
                "File events were lost (queue overflow); a full reconciliation is catching up."
                    .to_string(),
            );
        }
        let polled_total = polled;
        let summary = (
            self.watches.len() / 64, // coarse: watch counts move constantly
            polled_total,
            self.recovering,
            self.overflows,
            projects.len(),
        );
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
            watched_projects: projects.len() - polled,
            polled_projects: polled,
            overflows: self.overflows,
            recovering_overflow: self.recovering,
            pending_projects: self.pending.len(),
            degraded: self.backend.is_none() || polled > 0 || self.recovering,
            advice,
            projects,
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
    fn default_budget_is_a_quarter_capped_at_8192() {
        assert_eq!(default_budget(Some(65_536)), 8192);
        assert_eq!(default_budget(Some(8192)), 2048);
        assert_eq!(default_budget(Some(1_000_000)), 8192);
        assert_eq!(default_budget(None), 8192);
        assert_eq!(default_budget(Some(3)), 0);
    }
}
