//! The marker-discovery walk (REQUIREMENTS.md §4).
//!
//! An iterative preorder DFS (not `ignore::Walk`: that hides `.git`, interleaves files with
//! sub-directories, and so cannot answer "does a registered project already contain me?"
//! deterministically). Only directory entries and metadata are read. Every directory is opened by
//! descriptor relative to its parent and verified by `(dev, ino)` ([`super::dirfd`]), so a
//! directory swapped for a symlink mid-walk is skipped, never followed. Excluded directories are
//! pruned before descending; nothing here ever writes.

use super::dirfd::{DirHandle, Identity, Kind, OpenError};
use super::exclusions::Exclusions;
use super::status::{Phase, RootStatus, SharedStatus, Skipped};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MARKER_NAME: &str = "CLAUDE.md";
const BATCH_SIZE: usize = 64;
const BATCH_INTERVAL: Duration = Duration::from_millis(250);
const PROGRESS_EVERY_DIRS: u64 = 64;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub max_depth: usize,
    pub same_file_system: bool,
    pub home: PathBuf,
    pub boundaries: Vec<PathBuf>,
    pub fuse_mounts: Vec<PathBuf>,
}

impl ScanOptions {
    /// Canonicalize the home directory and add canonical forms of the hard boundaries, so symlinked
    /// prefixes (`/home -> /data/home`) cannot defeat the comparisons.
    fn normalized(&self) -> Self {
        let mut o = self.clone();
        o.home = fs::canonicalize(&self.home).unwrap_or_else(|_| self.home.clone());
        for b in &self.boundaries {
            if let Ok(c) = fs::canonicalize(b) {
                if !o.boundaries.contains(&c) {
                    o.boundaries.push(c);
                }
            }
        }
        o
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub canonical_path: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanSummary {
    pub dirs_visited: u64,
    pub projects_found: u64,
    pub skipped: Skipped,
    pub cancelled: bool,
}

fn record_io_error(skipped: &mut Skipped, e: &io::Error) {
    match e.kind() {
        io::ErrorKind::PermissionDenied => skipped.permission += 1,
        io::ErrorKind::NotFound => skipped.vanished += 1,
        _ => skipped.other += 1,
    }
}

/// How to open a frame's directory.
enum Open {
    /// A walk root, already opened.
    Root(DirHandle),
    /// `name` inside `parent`, which must still be the directory `expected` that was listed.
    Child {
        parent: Rc<DirHandle>,
        name: OsString,
        expected: Identity,
    },
}

struct Frame {
    open: Open,
    /// Built from the root's canonical path and the entry names; never resolved through symlinks.
    path: PathBuf,
    depth: usize,
    /// A registered project already contains this directory.
    inside_project: bool,
}

struct Walker<'a> {
    opts: &'a ScanOptions,
    cancel: &'a AtomicBool,
    status: &'a SharedStatus,
    sink: &'a mut dyn FnMut(Vec<Candidate>) -> bool,
    summary: ScanSummary,
    batch: Vec<Candidate>,
    last_flush: Instant,
    seen: HashSet<String>,
    roots: Vec<RootStatus>,
}

/// Walk every configured root, streaming batches of project candidates to `sink`
/// (which returns `false` to abort, e.g. when the database writer is gone).
pub fn scan(
    opts: &ScanOptions,
    cancel: &AtomicBool,
    status: &SharedStatus,
    sink: &mut dyn FnMut(Vec<Candidate>) -> bool,
) -> ScanSummary {
    let opts = &opts.normalized();
    status.update(|s| {
        s.phase = Phase::Scanning;
        s.dirs_visited = 0;
        s.projects_found = 0;
        s.skipped = Skipped::default();
    });
    let mut w = Walker {
        opts,
        cancel,
        status,
        sink,
        summary: ScanSummary::default(),
        batch: Vec::new(),
        last_flush: Instant::now(),
        seen: HashSet::new(),
        roots: Vec::new(),
    };
    for root in &opts.roots {
        if w.summary.cancelled {
            break;
        }
        w.scan_root(root);
    }
    w.flush();
    let (summary, roots) = (w.summary.clone(), w.roots);
    status.update(|s| {
        s.phase = Phase::Idle;
        s.dirs_visited = summary.dirs_visited;
        s.projects_found = summary.projects_found;
        s.skipped = summary.skipped.clone();
        s.roots = roots;
    });
    summary
}

impl Walker<'_> {
    fn root_state(&self, root: &Path) -> Result<PathBuf, &'static str> {
        let canonical = fs::canonicalize(root).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => "missing",
            _ => "unreadable",
        })?;
        if canonical.to_str().is_none() {
            return Err("non_utf8");
        }
        if self
            .opts
            .boundaries
            .iter()
            .any(|b| canonical == *b || canonical.starts_with(b))
        {
            return Err("forbidden");
        }
        match fs::metadata(&canonical) {
            Ok(m) if m.is_dir() => Ok(canonical),
            Ok(_) => Err("not_a_directory"),
            Err(_) => Err("unreadable"),
        }
    }

    fn count_open_error(&mut self, e: OpenError) {
        match e {
            OpenError::Replaced => self.summary.skipped.changed += 1,
            OpenError::Io(e) => record_io_error(&mut self.summary.skipped, &e),
        }
    }

    fn scan_root(&mut self, root: &Path) {
        let display = root.to_string_lossy().into_owned();
        let canonical = match self.root_state(root) {
            Ok(c) => c,
            Err(state) => {
                self.roots.push(RootStatus {
                    path: display,
                    state,
                });
                return;
            }
        };
        let exclusions = match Exclusions::new(
            &canonical,
            &self.opts.home,
            &self.opts.exclude,
            &self.opts.boundaries,
            &self.opts.fuse_mounts,
        ) {
            Ok(e) => e,
            Err(_) => {
                self.roots.push(RootStatus {
                    path: display,
                    state: "unreadable",
                });
                return;
            }
        };
        let handle = match DirHandle::open_root(&canonical) {
            Ok(h) => h,
            Err(e) => {
                self.count_open_error(e);
                self.roots.push(RootStatus {
                    path: display,
                    state: "unreadable",
                });
                return;
            }
        };
        self.roots.push(RootStatus {
            path: display,
            state: "ok",
        });
        let root_dev = handle.identity().dev;

        let mut stack = vec![Frame {
            open: Open::Root(handle),
            path: canonical,
            depth: 0,
            inside_project: false,
        }];
        while let Some(frame) = stack.pop() {
            if self.cancel.load(Ordering::Relaxed) {
                self.summary.cancelled = true;
                return;
            }
            self.visit(frame, &exclusions, root_dev, &mut stack);
        }
    }

    fn visit(
        &mut self,
        frame: Frame,
        exclusions: &Exclusions,
        root_dev: u64,
        stack: &mut Vec<Frame>,
    ) {
        self.summary.dirs_visited += 1;
        if self
            .summary
            .dirs_visited
            .is_multiple_of(PROGRESS_EVERY_DIRS)
        {
            self.publish_progress();
        }
        let mut dir = match frame.open {
            Open::Root(h) => h,
            Open::Child {
                parent,
                name,
                expected,
            } => match parent.open_child(&name, expected) {
                Ok(h) => h,
                Err(e) => {
                    self.count_open_error(e);
                    return;
                }
            },
        };
        let (entries, errors) = dir.entries();
        for e in &errors {
            record_io_error(&mut self.summary.skipped, e);
        }

        let mut marker_valid = false;
        let mut has_git = false;
        let mut subdirs: Vec<(OsString, Identity)> = Vec::new();
        for entry in entries {
            if entry.name == ".git" {
                has_git = true; // any kind: a .git file marks a worktree or submodule
            }
            match entry.kind {
                Kind::File if entry.name == MARKER_NAME => marker_valid = true,
                Kind::Symlink if entry.name == MARKER_NAME => {
                    if dir.symlink_resolves_to_file_beneath(&entry.name) {
                        marker_valid = true;
                    } else {
                        self.summary.skipped.rejected_markers += 1;
                    }
                }
                // (a *directory* named CLAUDE.md is not a marker; it is walked like any other)
                Kind::Dir(id) => subdirs.push((entry.name, id)),
                Kind::File | Kind::Symlink | Kind::Other => {}
            }
        }

        let mut inside_project = frame.inside_project;
        if marker_valid && frame.path != self.opts.home && (!inside_project || has_git) {
            self.register(&frame.path);
            inside_project = true;
        }

        if frame.depth >= self.opts.max_depth {
            return;
        }
        subdirs.sort_by(|a, b| a.0.cmp(&b.0));
        let dir = Rc::new(dir);
        for (name, id) in subdirs.into_iter().rev() {
            if name.to_str().is_none() {
                self.summary.skipped.non_utf8 += 1;
                continue;
            }
            let child = frame.path.join(&name);
            if exclusions.exclude_dir(&child, &name).is_some()
                || (self.opts.same_file_system && id.dev != root_dev)
            {
                self.summary.skipped.excluded += 1;
                continue;
            }
            stack.push(Frame {
                open: Open::Child {
                    parent: Rc::clone(&dir),
                    name,
                    expected: id,
                },
                path: child,
                depth: frame.depth + 1,
                inside_project,
            });
        }
    }

    fn register(&mut self, dir: &Path) {
        let Some(path) = dir.to_str() else { return };
        if !self.seen.insert(path.to_string()) {
            return; // overlapping roots
        }
        let name = dir
            .file_name()
            .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned());
        self.summary.projects_found += 1;
        self.batch.push(Candidate {
            canonical_path: path.to_string(),
            name,
        });
        if self.batch.len() >= BATCH_SIZE || self.last_flush.elapsed() >= BATCH_INTERVAL {
            self.flush();
        }
    }

    fn flush(&mut self) {
        self.last_flush = Instant::now();
        self.publish_progress();
        if self.batch.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.batch);
        if !(self.sink)(batch) {
            self.summary.cancelled = true;
            self.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn publish_progress(&self) {
        let (dirs, found, skipped) = (
            self.summary.dirs_visited,
            self.summary.projects_found,
            self.summary.skipped.clone(),
        );
        self.status.update(|s| {
            s.dirs_visited = dirs;
            s.projects_found = found;
            s.skipped = skipped;
        });
    }
}
