//! The bounded walk of one project's tree (REQUIREMENTS.md §5): which directories may be watched,
//! the newest meaningful file (the *inferred* activity timestamp), and the in-process gitignore
//! matcher used to judge live events.
//!
//! Same safety rules as discovery: every directory is opened by descriptor relative to its parent
//! and verified by `(dev, ino)`; symlinks are never followed; excluded, gitignored and nested-project
//! directories are pruned before descending. File contents read: `.gitignore` files and
//! `.git/info/exclude`, nothing else, bounded per file and per project (a file over a limit is
//! skipped and counted, never read in part).

use crate::discovery::dirfd::{DirHandle, Identity, Kind};
use crate::discovery::exclusions::Exclusions;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

/// Directory entries examined per project walk (larger trees are truncated and reported).
pub const MAX_ENTRIES: usize = 100_000;
/// A `.gitignore` or `.git/info/exclude` larger than this is not read: its rules do not apply
/// and it is counted in [`Tree::ignore_files_skipped`] (v0.1.0 review M2).
pub const MAX_GITIGNORE_BYTES: u64 = 256 * 1024;
/// All ignore files of one project together; a file that would take the project past this is
/// skipped the same way. A repository chooses how many `.gitignore` files it has.
pub const MAX_GITIGNORE_TOTAL_BYTES: u64 = 1024 * 1024;
/// All ignore rules of one project together; a file that would take the project past this is
/// skipped too. This is the limit that bounds memory: the compiled rules stay in memory for as
/// long as the project is tracked, and a rule that needs a regular expression (`*1?b[c-d]*.x`)
/// costs about 15 KiB and 0.25 ms to compile (measured, release build, `ignore` 0.4), i.e. about
/// 1 MiB of memory per KiB of file. 5,000 such rules are about 75 MiB and 1.2 s; literal rules
/// cost almost nothing.
pub const MAX_GITIGNORE_PATTERNS: usize = 5_000;
/// All ignore rules of **all** projects together ([`RuleStore`]). The limits above bound one
/// project, and a directory tree chooses how many projects it holds (each needs only a marker):
/// without this limit, memory grew with their number. The rules go to the most recently active
/// projects first; a file that does not fit any more is skipped and counted like any other. At
/// 17-20 KiB per rule that needs a regular expression this is 350-400 MiB in the worst case
/// (measured: docs/benchmarks.md); ordinary rules cost a small fraction of that.
pub const MAX_GITIGNORE_PATTERNS_TOTAL: usize = 20_000;

/// What identifies the content of an ignore file without reading it: a file whose device, inode,
/// size, modification time and change time are unchanged is taken to hold the same rules, and
/// its compiled rules are reused.
///
/// The change time is the one a rewrite cannot avoid: the kernel sets it at every write and
/// whenever the modification time is set, and nothing can set it back. With it, a file rewritten
/// in place to the same size with its modification time restored is seen as changed. What is
/// left unseen: a rewrite to the same size within the file system's timestamp resolution of the
/// file's previous change (milliseconds on ext4 and tmpfs), until the file changes again or the
/// daemon restarts. A change of the change time alone (a `chmod`, a new hard link) compiles the
/// file again, which is harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    /// Seconds and nanoseconds.
    mtime: (i64, i64),
    /// Seconds and nanoseconds.
    ctime: (i64, i64),
}

impl FileId {
    fn of(file: &std::fs::File) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let md = file.metadata().ok()?;
        Some(Self {
            dev: md.dev(),
            ino: md.ino(),
            size: md.size(),
            mtime: (md.mtime(), md.mtime_nsec()),
            ctime: (md.ctime(), md.ctime_nsec()),
        })
    }
}

/// Gitignore rules of one project: `.git/info/exclude` of its repository (lowest priority), then
/// `.gitignore` files from the repository's root down, deeper ones overriding shallower ones.
/// Approximates Git (documented differences: no `core.excludesFile`; rules above the
/// repository root never apply).
///
/// The compiled rules of each file are shared (`Arc`): a later walk of the project takes over
/// the layers of files that did not change instead of compiling them again, and a copy of the
/// rules costs one pointer per file.
#[derive(Debug, Default, Clone)]
pub struct GitIgnore {
    /// Sorted by rank, lowest priority first. Only layers whose directory is an ancestor of a
    /// path apply to it, and those are ordered by depth, so one sorted list serves every path.
    layers: Vec<Arc<Layer>>,
}

#[derive(Debug)]
struct Layer {
    dir: PathBuf,
    /// (depth of `dir`, 0 for `info/exclude` / 1 for `.gitignore`).
    rank: (usize, u8),
    rules: Gitignore,
    /// Size of the file the rules came from (counted against [`MAX_GITIGNORE_TOTAL_BYTES`]).
    bytes: u64,
    /// The file's rule lines (every line that can hold a rule): what the limits on rules count,
    /// before anything is compiled.
    rule_lines: usize,
    /// The file the rules were read from (`None`: rules given as text, never reused).
    file: Option<FileId>,
}

impl Layer {
    fn is(&self, dir: &Path, rank: (usize, u8)) -> bool {
        self.dir == dir && self.rank == rank
    }
}

/// See [`Layer::rank`].
fn rank(dir: &Path, exclude_file: bool) -> (usize, u8) {
    (dir.components().count(), u8::from(!exclude_file))
}

/// Every line that can hold a rule (not blank, not a comment): counted before compiling.
fn rule_lines(text: &[u8]) -> usize {
    text.split(|b| *b == b'\n')
        .filter(|line| !line.starts_with(b"#") && !line.trim_ascii().is_empty())
        .count()
}

/// Why an ignore file was skipped (its rules do not apply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skipped {
    /// A limit of the file or of its project ([`MAX_GITIGNORE_BYTES`],
    /// [`MAX_GITIGNORE_TOTAL_BYTES`], [`MAX_GITIGNORE_PATTERNS`]).
    ByProject,
    /// Only the walk's allowance ([`TreeOptions::max_patterns`], the limit across projects):
    /// the project's own limits would have let it in.
    ByAllowance,
}

/// What one walk carries from ignore file to ignore file, besides the rules collected so far.
struct Admission<'a> {
    /// Rules the project may keep ([`TreeOptions::max_patterns`]).
    allowance: usize,
    /// The files this walk skipped only because of `allowance`. They still count towards the
    /// project's own limits, so that those decide the same way whatever the allowance is, and
    /// the number of rules the project wants does not depend on what it was allowed.
    denied_bytes: u64,
    denied_rules: usize,
    /// The layers of the project's previous rules ([`TreeOptions::reuse`]) by location.
    reuse: HashMap<(&'a Path, (usize, u8)), &'a Arc<Layer>>,
}

impl<'a> Admission<'a> {
    fn new(o: &TreeOptions<'a>) -> Self {
        let layers = o.reuse.map_or(&[][..], |g| &g.layers[..]);
        Self {
            allowance: o.max_patterns,
            denied_bytes: 0,
            denied_rules: 0,
            reuse: layers
                .iter()
                .map(|l| ((l.dir.as_path(), l.rank), l))
                .collect(),
        }
    }
}

impl GitIgnore {
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        for l in self.layers.iter().rev() {
            if !path.starts_with(&l.dir) || path == l.dir {
                continue;
            }
            match l.rules.matched(path, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        false
    }

    /// Compile `text` as the rules of `dir`'s `.gitignore` (or `info/exclude` when
    /// `exclude_file`). `None` if it holds no usable rule.
    fn compile(
        dir: &Path,
        exclude_file: bool,
        text: &[u8],
        file: Option<FileId>,
    ) -> Option<Arc<Layer>> {
        let mut b = GitignoreBuilder::new(dir);
        for line in String::from_utf8_lossy(text).lines() {
            let _ = b.add_line(None, line); // an invalid pattern is skipped, like Git does
        }
        let rules = b.build().ok()?;
        (rules.num_ignores() + rules.num_whitelists() > 0).then(|| {
            Arc::new(Layer {
                dir: dir.to_path_buf(),
                rank: rank(dir, exclude_file),
                rules,
                bytes: u64::try_from(text.len()).unwrap_or(u64::MAX),
                rule_lines: rule_lines(text),
                file,
            })
        })
    }

    /// Put `layer` in the place of the layer of its location (if any).
    fn set(&mut self, dir: &Path, rank: (usize, u8), layer: Option<Arc<Layer>>) {
        self.layers.retain(|l| !l.is(dir, rank));
        if let Some(layer) = layer {
            let at = self.layers.partition_point(|l| l.rank <= rank);
            self.layers.insert(at, layer);
        }
    }

    /// Add (or replace) the rules of `dir`'s `.gitignore` (or `info/exclude` when
    /// `exclude_file`), given as text.
    #[cfg(test)]
    fn add(&mut self, dir: &Path, exclude_file: bool, text: &[u8]) {
        let layer = Self::compile(dir, exclude_file, text, None);
        self.set(dir, rank(dir, exclude_file), layer);
    }

    /// Number of rules in all layers, as the limits count them (rule lines).
    pub fn patterns(&self) -> usize {
        self.layers.iter().map(|l| l.rule_lines).sum()
    }

    /// Read `name` through `handle` (the descriptor of the directory that holds it) as the
    /// `.gitignore` of `dir` (or its `info/exclude` when `exclude_file`) and add its rules.
    ///
    /// `Some` when the file was **skipped**: it is larger than [`MAX_GITIGNORE_BYTES`], or it
    /// would take the project past [`MAX_GITIGNORE_TOTAL_BYTES`] or [`MAX_GITIGNORE_PATTERNS`],
    /// or past the walk's allowance. A skipped file is not read beyond the limit, nothing of it
    /// is compiled, and none of its rules apply (not even its first ones).
    ///
    /// A file that is unchanged ([`FileId`]) since its rules were compiled — for this project's
    /// current rules, or for the ones in `adm.reuse` — is not read at all: its layer is taken
    /// over, and the limits decide from the numbers recorded with it, exactly as for a fresh read.
    fn load(
        &mut self,
        dir: &Path,
        exclude_file: bool,
        handle: &DirHandle,
        name: &str,
        adm: &mut Admission,
    ) -> Option<Skipped> {
        use std::io::Read;
        let rank = rank(dir, exclude_file);
        // Absent, or not a readable regular file: nothing to skip.
        let file = handle.open_regular(OsStr::new(name))?;
        let id = FileId::of(&file)?;
        let known = self
            .layers
            .iter()
            .find(|l| l.is(dir, rank))
            .or_else(|| adm.reuse.get(&(dir, rank)).copied())
            .filter(|l| l.file == Some(id))
            .cloned();
        // The layer this file replaces does not count against the project's totals.
        let (kept_bytes, kept_rules) = self
            .layers
            .iter()
            .filter(|l| !l.is(dir, rank))
            .fold((0u64, 0usize), |(b, r), l| (b + l.bytes, r + l.rule_lines));
        let limit = MAX_GITIGNORE_BYTES
            .min(MAX_GITIGNORE_TOTAL_BYTES.saturating_sub(kept_bytes + adm.denied_bytes));
        let rules_left = MAX_GITIGNORE_PATTERNS.saturating_sub(kept_rules + adm.denied_rules);
        let (bytes, rule_lines, text) = match &known {
            Some(l) => (l.bytes, l.rule_lines, None),
            // Too large by its size alone: not read.
            None if id.size > limit => (id.size, 0, None),
            None => {
                // One byte past the limit shows that a file that grew meanwhile is too large.
                let mut text = Vec::new();
                file.take(limit + 1).read_to_end(&mut text).ok()?;
                let bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
                (bytes, rule_lines(&text), Some(text))
            }
        };
        if bytes > limit || rule_lines > rules_left {
            self.set(dir, rank, None);
            return Some(Skipped::ByProject);
        }
        if rule_lines > adm.allowance.saturating_sub(kept_rules) {
            adm.denied_bytes += bytes;
            adm.denied_rules += rule_lines;
            self.set(dir, rank, None);
            return Some(Skipped::ByAllowance);
        }
        let layer = known.or_else(|| Self::compile(dir, exclude_file, &text?, Some(id)));
        self.set(dir, rank, layer);
        None
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

/// The ignore rules that the monitored projects keep, shared by everything that walks project
/// trees. It does two things:
///
/// - **The limit across projects** ([`MAX_GITIGNORE_PATTERNS_TOTAL`]). Every walk gets its
///   allowance here, and all projects together never hold more than the limit: a full walk
///   [`begin`](Self::begin)s with what the others leave (reserved for it until it
///   [`settle`](Self::settle)s, so two walks at once cannot both take the last room).
///   **Who** holds the rules when they do not fit all is decided by recency, not by who came
///   first: [`rebalance`](Self::rebalance) names the projects to walk again so that the most
///   recently active ones have theirs. That outcome is a function of the projects alone (their
///   last activity, their path as the tie-break, the rules they want), not of when they were
///   walked.
/// - **Reuse.** It keeps each project's rules of its last full walk, and hands them to the next
///   one, which takes over the compiled rules of every ignore file that did not change (same
///   device, inode, size, modification time and change time). Without it every scan of a project without watches compiled all its rules
///   again (memory several times the kept size in a glibc build). A project that is no longer
///   monitored is dropped ([`retain`](Self::retain)), and with it its rules.
#[derive(Debug)]
pub struct RuleStore {
    limit: usize,
    projects: Mutex<HashMap<PathBuf, Kept>>,
}

/// What one project keeps.
#[derive(Debug)]
struct Kept {
    /// The project's last activity (seconds): more recent comes first. `None` (unknown) comes
    /// last.
    recency: Option<i64>,
    /// The rules of its last full walk.
    rules: Arc<GitIgnore>,
    /// The rules it would keep if only its own limits applied ([`Tree::ignore_rules_wanted`]).
    wanted: usize,
    /// The allowance of its last full walk.
    walked_with: usize,
    /// Set while a full walk runs: the walk's allowance, counted instead of `rules`.
    reserved: Option<usize>,
}

impl Kept {
    fn held(&self) -> usize {
        self.reserved.unwrap_or_else(|| self.rules.patterns())
    }
}

/// What a full walk gets from [`RuleStore::begin`].
#[derive(Debug)]
pub struct Grant {
    /// For [`TreeOptions::max_patterns`].
    pub max_patterns: usize,
    /// For [`TreeOptions::reuse`]: the project's rules of its last full walk.
    pub reuse: Option<Arc<GitIgnore>>,
}

impl Default for RuleStore {
    fn default() -> Self {
        Self::new(MAX_GITIGNORE_PATTERNS_TOTAL)
    }
}

impl RuleStore {
    /// A store that lets all projects together keep `limit` rules.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            projects: Mutex::new(HashMap::new()),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut HashMap<PathBuf, Kept>) -> T) -> T {
        // A panic while the lock was held leaves numbers that are still usable.
        f(&mut self.projects.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// What the other projects leave of the limit, at most [`MAX_GITIGNORE_PATTERNS`].
    fn room_in(&self, projects: &HashMap<PathBuf, Kept>, root: &Path) -> usize {
        let others: usize = projects
            .iter()
            .filter(|(r, _)| r.as_path() != root)
            .map(|(_, k)| k.held())
            .sum();
        MAX_GITIGNORE_PATTERNS.min(self.limit.saturating_sub(others))
    }

    /// The rules project `root` may hold in a walk that keeps nothing (a subtree walk, which
    /// starts from the project's rules).
    pub fn room(&self, root: &Path) -> usize {
        self.with(|projects| self.room_in(projects, root))
    }

    /// Start a full walk of project `root`, last active at `recency`: what it may keep — what
    /// the other projects leave of the limit, and no more than `at_most` — and its previous
    /// rules to reuse. The allowance stays reserved for it until [`settle`](Self::settle).
    pub fn begin(&self, root: &Path, recency: Option<i64>, at_most: usize) -> Grant {
        self.with(|projects| {
            let max_patterns = at_most.min(self.room_in(projects, root));
            let kept = projects.entry(root.to_path_buf()).or_insert_with(|| Kept {
                recency,
                rules: Arc::default(),
                wanted: 0,
                walked_with: 0,
                reserved: None,
            });
            kept.recency = recency;
            kept.reserved = Some(max_patterns);
            Grant {
                max_patterns,
                reuse: (!kept.rules.is_empty()).then(|| Arc::clone(&kept.rules)),
            }
        })
    }

    /// The full walk of `root` that [`begin`](Self::begin) started is over; `tree` is its result
    /// (`None`: the walk failed, the project keeps nothing).
    pub fn settle(&self, root: &Path, tree: Option<&Tree>) {
        self.with(|projects| {
            let walked = projects.get_mut(root).zip(tree);
            match walked {
                // A project that wants no rules has no part in the limit.
                Some((kept, tree)) if tree.ignore_rules_wanted > 0 => {
                    kept.walked_with = kept.reserved.take().unwrap_or(0);
                    kept.rules = Arc::clone(&tree.ignore);
                    kept.wanted = tree.ignore_rules_wanted;
                }
                _ => {
                    projects.remove(root);
                }
            }
        });
    }

    /// Forget the projects whose root `keep` rejects (no longer monitored), and their rules.
    pub fn retain(&self, keep: impl Fn(&Path) -> bool) {
        self.with(|projects| projects.retain(|root, _| keep(root)));
    }

    /// The last activity of project `root` is now `recency` (its place in the order).
    pub fn set_recency(&self, root: &Path, recency: Option<i64>) {
        self.with(|projects| {
            if let Some(kept) = projects.get_mut(root) {
                kept.recency = recency;
            }
        });
    }

    /// The projects whose rules are not what the order of recency gives them, each with the
    /// allowance to walk it again with ([`begin`](Self::begin)'s `at_most`), in the order to do
    /// it: first the projects that hold more than their share (least recent first), then the
    /// ones that may hold more than they were allowed (most recent first). Giving up before
    /// taking keeps all projects together within the limit throughout. Empty when every project
    /// has the rules it wants, which is the normal state.
    ///
    /// The shares: most recently active first (unknown last; the path decides between equals),
    /// each project gets all the rules it wants while they fit in what is left of the limit;
    /// the first one that does not fit completely gets what is left, the ones after it nothing.
    pub fn rebalance(&self) -> Vec<(PathBuf, usize)> {
        self.with(|projects| {
            let mut order: Vec<(&PathBuf, &Kept)> = projects.iter().collect();
            // Known before unknown, later before earlier, then by path.
            order.sort_by_key(|(root, kept)| (std::cmp::Reverse(kept.recency), *root));
            let mut left = self.limit;
            let (mut give_up, mut take) = (Vec::new(), Vec::new());
            for (root, kept) in order {
                let share = kept.wanted.min(left);
                left = if share < kept.wanted { 0 } else { left - share };
                if kept.reserved.is_some() {
                    continue; // being walked right now: it settles first
                }
                let has = kept.rules.patterns();
                if has > share {
                    give_up.push((root.clone(), share));
                } else if has < kept.wanted && share > kept.walked_with {
                    take.push((root.clone(), share));
                }
            }
            give_up.reverse();
            give_up.extend(take);
            give_up
        })
    }

    /// Some project does not have all the rules it wants: the only state in which
    /// [`rebalance`](Self::rebalance) can have anything to do.
    pub fn contended(&self) -> bool {
        self.with(|projects| projects.values().any(|k| k.rules.patterns() < k.wanted))
    }

    /// Project `root` does not have all the rules it wants.
    pub fn lacks_rules(&self, root: &Path) -> bool {
        self.with(|projects| {
            projects
                .get(root)
                .is_some_and(|k| k.rules.patterns() < k.wanted)
        })
    }

    /// Rules project `root` keeps (0: none, or not a project of the store).
    pub fn kept(&self, root: &Path) -> usize {
        self.with(|projects| projects.get(root).map_or(0, |k| k.rules.patterns()))
    }

    /// Rules counted for all projects together (kept or reserved); never above the limit.
    pub fn total(&self) -> usize {
        self.with(|projects| projects.values().map(Kept::held).sum())
    }
}

/// The root of the Git work tree containing `root`: `root` or its nearest ancestor with a `.git`,
/// searched no higher than `boundary` (the project's discovery root) and below `home` (a
/// repository at `home` itself, e.g. dotfiles, does not count; same rule as the Git module). The
/// `.git` must belong to user `uid`, as Git itself requires (`safe.directory`): otherwise there
/// is no work tree for ccwm. Without both rules, another user's `/srv/.git` + `/srv/.gitignore`
/// above a root such as `/srv/code` would hide the activity of every project below it on hosts
/// without Landlock (v0.1.0 review L6).
pub fn git_worktree_root(root: &Path, boundary: &Path, home: &Path, uid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let (dir, git) = root
        .ancestors()
        .take_while(|a| a.starts_with(boundary) && *a != home && a.parent().is_some())
        .find_map(|a| {
            std::fs::symlink_metadata(a.join(".git"))
                .ok()
                .map(|m| (a, m))
        })?;
    (git.uid() == uid).then(|| dir.to_path_buf())
}

/// Whether `root` lies in a Git work tree ([`git_worktree_root`]).
pub fn in_git_worktree(root: &Path, boundary: &Path, home: &Path, uid: u32) -> bool {
    git_worktree_root(root, boundary, home, uid).is_some()
}

pub struct TreeOptions<'a> {
    pub exclusions: &'a Exclusions,
    /// Other projects' roots: their subtrees belong to them (§4.4), never to this project.
    pub other_projects: &'a HashSet<PathBuf>,
    pub max_depth: usize,
    pub same_file_system: bool,
    /// Apply `.gitignore` rules (the project is in a Git work tree).
    pub git_aware: bool,
    /// The work tree's root when it lies above the project root: its `info/exclude` and the
    /// `.gitignore` files from it down to the project root apply too. `None`: the project root.
    pub repo_root: Option<&'a Path>,
    /// File times after this are clamped to it (a future mtime must not pin a project on top).
    pub now: i64,
    pub max_entries: usize,
    /// Ignore rules the project may hold: [`MAX_GITIGNORE_PATTERNS`], or less when the limit
    /// across projects leaves it less ([`RuleStore`]).
    pub max_patterns: usize,
    /// The rules the project has from its last full walk: the compiled rules of every ignore
    /// file that did not change since are taken over instead of being compiled again.
    pub reuse: Option<&'a GitIgnore>,
}

#[derive(Debug)]
pub struct Tree {
    pub root: PathBuf,
    /// Eligible directories in preorder, the walk's start first (the root for a full walk).
    pub dirs: Vec<PathBuf>,
    /// `<root>/.git` when it is a directory (watched for HEAD/index/ref changes, never for activity).
    pub git_dir: Option<PathBuf>,
    /// Newest meaningful file: (mtime, path relative to the root).
    pub newest: Option<(i64, String)>,
    pub ignore: Arc<GitIgnore>,
    /// The entry limit was reached: the tree is only partly known.
    pub truncated: bool,
    /// Directories that could not be opened (permission, vanished, swapped).
    pub unreadable: u64,
    /// `.gitignore` / `info/exclude` files skipped because of a limit ([`MAX_GITIGNORE_BYTES`],
    /// [`MAX_GITIGNORE_TOTAL_BYTES`], [`MAX_GITIGNORE_PATTERNS`],
    /// [`MAX_GITIGNORE_PATTERNS_TOTAL`]): their rules do not apply.
    pub ignore_files_skipped: u64,
    /// The rules the project would keep if only its own limits applied: the ones it keeps plus
    /// those of the files that only the walk's allowance kept out. The same whatever the
    /// allowance was (meaningful for a full walk).
    pub ignore_rules_wanted: usize,
}

struct Frame {
    parent: Option<(Rc<DirHandle>, OsString, Identity)>,
    path: PathBuf,
    depth: usize,
}

/// Walk `root` (canonical). Fails only if `root` itself cannot be opened.
pub fn walk(root: &Path, o: &TreeOptions) -> std::io::Result<Tree> {
    walk_from(root, root, &GitIgnore::default(), o)
}

/// Walk the part of `root`'s tree at and below `start` with the same rules as a full walk;
/// `base` holds the rules already known for the project (a `.gitignore` read again replaces its
/// layer). Used to poll the subtrees that have no watches and to watch directories created at
/// runtime. Fails only if `start` cannot be opened.
pub fn walk_from(
    root: &Path,
    start: &Path,
    base: &GitIgnore,
    o: &TreeOptions,
) -> std::io::Result<Tree> {
    let first = DirHandle::open_root(start).map_err(|e| match e {
        crate::discovery::dirfd::OpenError::Io(e) => e,
        crate::discovery::dirfd::OpenError::Replaced => {
            std::io::Error::other("the directory was replaced")
        }
    })?;
    let root_dev = first.identity().dev;
    let start_depth = start
        .strip_prefix(root)
        .map_or(0, |r| r.components().count());
    let mut tree = Tree {
        root: root.to_path_buf(),
        dirs: Vec::new(),
        git_dir: None,
        newest: None,
        ignore: Arc::new(GitIgnore::default()),
        truncated: false,
        unreadable: 0,
        ignore_files_skipped: 0,
        ignore_rules_wanted: 0,
    };
    let mut ignore = base.clone();
    let mut adm = Admission::new(o);
    if o.git_aware && start_depth == 0 {
        if let Some(repo) = o.repo_root.filter(|r| *r != root && root.starts_with(r)) {
            tree.ignore_files_skipped += add_repository_layers(&mut ignore, repo, root, &mut adm);
        }
    }
    let mut entries_seen = 0usize;
    let mut first = Some(first);
    let mut stack = vec![Frame {
        parent: None,
        path: start.to_path_buf(),
        depth: start_depth,
    }];
    while let Some(frame) = stack.pop() {
        let opened = match (&frame.parent, first.take()) {
            (None, Some(h)) => Ok(h),
            (Some((p, name, id)), _) => p.open_child(name, *id),
            (None, None) => continue,
        };
        let Ok(mut dir) = opened else {
            tree.unreadable += 1;
            continue;
        };
        tree.dirs.push(frame.path.clone());
        let (entries, _errors) = dir.entries();
        entries_seen += entries.len();
        if entries_seen > o.max_entries {
            tree.truncated = true;
            break;
        }
        if o.git_aware {
            if frame.depth == 0 && o.repo_root.is_none_or(|r| r == root) {
                tree.ignore_files_skipped +=
                    load_info_exclude(&mut ignore, &frame.path, &dir, &mut adm);
            }
            if entries.iter().any(|e| e.name == ".gitignore") {
                tree.ignore_files_skipped += u64::from(
                    ignore
                        .load(&frame.path, false, &dir, ".gitignore", &mut adm)
                        .is_some(),
                );
            }
        }
        let mut subdirs = Vec::new();
        for entry in entries {
            let Some(name) = entry.name.to_str() else {
                continue; // non-UTF-8 names are never reported
            };
            let path = frame.path.join(name);
            match entry.kind {
                Kind::Dir(id) => {
                    if frame.depth == 0 && name == ".git" {
                        tree.git_dir = Some(path);
                        continue;
                    }
                    let excluded = o.exclusions.exclude_dir(&path, &entry.name).is_some()
                        || o.other_projects.contains(&path)
                        || (o.same_file_system && id.dev != root_dev)
                        || frame.depth + 1 > o.max_depth
                        || (o.git_aware && ignore.is_ignored(&path, true));
                    if !excluded {
                        subdirs.push((entry.name, id, path));
                    }
                }
                Kind::File => {
                    if o.git_aware && ignore.is_ignored(&path, false) {
                        continue;
                    }
                    if let Some(mtime) = dir.mtime(&entry.name) {
                        let mtime = mtime.min(o.now);
                        if tree.newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
                            let rel = path
                                .strip_prefix(root)
                                .map(|r| r.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            tree.newest = Some((mtime, rel));
                        }
                    }
                }
                Kind::Symlink | Kind::Other => {}
            }
        }
        subdirs.sort_by(|a, b| a.0.cmp(&b.0));
        let dir = Rc::new(dir);
        for (name, id, path) in subdirs.into_iter().rev() {
            stack.push(Frame {
                parent: Some((Rc::clone(&dir), name, id)),
                path,
                depth: frame.depth + 1,
            });
        }
    }
    tree.ignore_rules_wanted = ignore.patterns() + adm.denied_rules;
    tree.ignore = Arc::new(ignore);
    Ok(tree)
}

/// Rules from a work tree's root above the project root: its `.git/info/exclude` and every
/// `.gitignore` from `repo` down to (not including) `root`. Each directory is opened by path and
/// read through its descriptor; one that cannot be read (e.g. outside the sandbox) is skipped.
/// Returns how many files a limit skipped.
fn add_repository_layers(
    ignore: &mut GitIgnore,
    repo: &Path,
    root: &Path,
    adm: &mut Admission,
) -> u64 {
    let Ok(rel) = root.strip_prefix(repo) else {
        return 0;
    };
    let mut dir = repo.to_path_buf();
    let mut dirs = vec![dir.clone()];
    for c in rel.components() {
        dir.push(c);
        if dir != root {
            dirs.push(dir.clone());
        }
    }
    let mut skipped = 0;
    for (i, d) in dirs.iter().enumerate() {
        let Ok(h) = DirHandle::open_root(d) else {
            continue;
        };
        if i == 0 {
            skipped += load_info_exclude(ignore, d, &h, adm);
        }
        skipped += u64::from(ignore.load(d, false, &h, ".gitignore", adm).is_some());
    }
    skipped
}

/// `.git/info/exclude` of a repository rooted at `path` (`dir` is its descriptor), only when
/// `.git` is a real directory. Returns 1 if a limit skipped the file, else 0.
fn load_info_exclude(
    ignore: &mut GitIgnore,
    path: &Path,
    dir: &DirHandle,
    adm: &mut Admission,
) -> u64 {
    let info = dir
        .open_child_dir(OsStr::new(".git"))
        .and_then(|git| git.open_child_dir(OsStr::new("info")));
    info.map_or(0, |info| {
        u64::from(ignore.load(path, true, &info, "exclude", adm).is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn opts<'a>(ex: &'a Exclusions, others: &'a HashSet<PathBuf>, git: bool) -> TreeOptions<'a> {
        TreeOptions {
            exclusions: ex,
            other_projects: others,
            max_depth: 10,
            same_file_system: true,
            git_aware: git,
            repo_root: None,
            now: i64::MAX,
            max_entries: MAX_ENTRIES,
            max_patterns: MAX_GITIGNORE_PATTERNS,
            reuse: None,
        }
    }

    fn set_mtime(p: &Path, secs: u64) {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    struct Fx {
        _t: tempfile::TempDir,
        root: PathBuf,
        ex: Exclusions,
    }

    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap().join("p");
        fs::create_dir(&root).unwrap();
        let ex = Exclusions::new(&root, Path::new("/nonexistent-home"), &[], &[], &[]).unwrap();
        Fx { _t: t, root, ex }
    }

    fn file(root: &Path, rel: &str, mtime: u64) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, rel).unwrap();
        set_mtime(&p, mtime);
    }

    #[test]
    fn prunes_excluded_gitignored_and_nested_directories() {
        let f = fx();
        let r = &f.root;
        file(r, "src/main.rs", 100);
        file(r, "docs/a.md", 300);
        file(r, "node_modules/x/i.js", 900); // default-excluded name
        file(r, ".cache/c", 900); // hidden directory
        file(r, "out/gen.txt", 900); // gitignored directory
        file(r, "app.log", 900); // gitignored file
        file(r, "keep.log", 200); // re-included
        file(r, "nested/CLAUDE.md", 950); // another project
        file(r, ".gitignore", 50);
        fs::write(r.join(".gitignore"), "out/\n*.log\n!keep.log\n").unwrap();
        set_mtime(&r.join(".gitignore"), 50);
        fs::create_dir_all(r.join(".git/info")).unwrap();
        fs::write(r.join(".git/info/exclude"), "secret.txt\n").unwrap();
        file(r, "secret.txt", 990);
        let others: HashSet<PathBuf> = [r.join("nested")].into();
        let t = walk(r, &opts(&f.ex, &others, true)).unwrap();
        let rel: Vec<String> = t
            .dirs
            .iter()
            .map(|d| d.strip_prefix(r).unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(rel, ["", "docs", "src"]);
        assert_eq!(t.git_dir, Some(r.join(".git")));
        assert_eq!(t.newest, Some((300, "docs/a.md".to_string())));
        assert!(t.ignore.is_ignored(&r.join("app.log"), false));
        assert!(!t.ignore.is_ignored(&r.join("keep.log"), false));
        assert!(
            t.ignore.is_ignored(&r.join("secret.txt"), false),
            "info/exclude"
        );
        assert!(
            t.ignore.is_ignored(&r.join("src/x.log"), false),
            "applies below"
        );
        assert!(!t.ignore.is_ignored(&r.join("src/main.rs"), false));
        assert!(!t.truncated);
    }

    #[test]
    fn deeper_gitignore_files_override_shallower_ones() {
        let f = fx();
        let r = &f.root;
        fs::create_dir_all(r.join("sub")).unwrap();
        fs::write(r.join(".gitignore"), "*.tmp\n").unwrap();
        fs::write(r.join("sub/.gitignore"), "!*.tmp\n").unwrap();
        let t = walk(r, &opts(&f.ex, &HashSet::new(), true)).unwrap();
        assert!(t.ignore.is_ignored(&r.join("a.tmp"), false));
        assert!(!t.ignore.is_ignored(&r.join("sub/b.tmp"), false));
    }

    #[test]
    fn without_git_gitignore_files_are_not_applied() {
        let f = fx();
        file(&f.root, "a.log", 700);
        fs::write(f.root.join(".gitignore"), "*.log\n").unwrap();
        set_mtime(&f.root.join(".gitignore"), 10);
        let t = walk(&f.root, &opts(&f.ex, &HashSet::new(), false)).unwrap();
        assert!(t.ignore.is_empty());
        assert_eq!(t.newest, Some((700, "a.log".to_string())));
    }

    #[test]
    fn future_times_are_clamped_symlinks_skipped_and_limits_apply() {
        let f = fx();
        file(&f.root, "future.txt", 4_000_000_000);
        std::os::unix::fs::symlink("/etc", f.root.join("etc-link")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", f.root.join("file-link")).unwrap();
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, false);
        o.now = 1_000;
        let t = walk(&f.root, &o).unwrap();
        assert_eq!(t.newest, Some((1_000, "future.txt".to_string())));
        assert_eq!(t.dirs.len(), 1, "symlinked directories are not followed");

        for i in 0..20 {
            file(&f.root, &format!("d{i}/f"), 5);
        }
        o.max_entries = 10;
        assert!(walk(&f.root, &o).unwrap().truncated);
        o.max_entries = MAX_ENTRIES;
        o.max_depth = 0;
        assert_eq!(walk(&f.root, &o).unwrap().dirs.len(), 1);
    }

    #[test]
    fn git_worktree_detection_stops_below_home() {
        let t = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(t.path()).unwrap();
        fs::create_dir_all(home.join("a/b/c")).unwrap();
        fs::create_dir(home.join(".git")).unwrap();
        let me = nix::unistd::geteuid().as_raw();
        let inside = |dir: &str| in_git_worktree(&home.join(dir), &home, &home, me);
        assert!(!inside("a/b/c"), "home repo ignored");
        fs::create_dir(home.join("a/.git")).unwrap();
        assert!(inside("a/b/c"));
        assert!(inside("a"));
        fs::write(home.join("a/b/c/.git"), "gitdir: x").unwrap();
        assert!(inside("a/b/c"), "a .git file counts");
    }

    /// v0.1.0 review L6: a `.git` above the project's discovery root is never looked at, and a
    /// `.git` of another user is not a work tree (Git itself refuses it).
    #[test]
    fn git_worktree_detection_stops_at_the_discovery_root_and_needs_our_own_git_dir() {
        let t = tempfile::tempdir().unwrap();
        let srv = fs::canonicalize(t.path()).unwrap();
        let home = Path::new("/nonexistent-home");
        let (code, project) = (srv.join("code"), srv.join("code/team/app"));
        fs::create_dir_all(&project).unwrap();
        let me = nix::unistd::geteuid().as_raw();
        // Another user's trap above the discovery root `code`: `<srv>/.git` + `.gitignore`.
        fs::create_dir(srv.join(".git")).unwrap();
        fs::write(srv.join(".gitignore"), "*\n").unwrap();
        assert_eq!(git_worktree_root(&project, &code, home, me), None);
        assert_eq!(
            git_worktree_root(&project, &srv, home, me),
            Some(srv.clone()),
            "control: with the boundary above it, that repository would be used"
        );
        // Walking with what the tracker derives from it: no rules, the file counts.
        file(&project, "src/main.rs", 100);
        let ex = Exclusions::new(&code, home, &[], &[], &[]).unwrap();
        let none = HashSet::new();
        let repo = git_worktree_root(&project, &code, home, me);
        let mut o = opts(&ex, &none, repo.is_some());
        o.repo_root = repo.as_deref();
        let tree = walk(&project, &o).unwrap();
        assert_eq!(tree.newest, Some((100, "src/main.rs".to_string())));
        assert!(tree.ignore.is_empty());

        // Inside the root: the nearest `.git` decides, and only if it is ours.
        fs::create_dir(code.join("team/.git")).unwrap();
        assert_eq!(
            git_worktree_root(&project, &code, home, me),
            Some(code.join("team"))
        );
        assert_eq!(
            git_worktree_root(&project, &code, home, me + 1),
            None,
            "a .git owned by another user is not a work tree"
        );
        // A foreign `.git` is not skipped in favour of one further up, either.
        fs::create_dir(code.join(".git")).unwrap();
        assert_eq!(git_worktree_root(&project, &code, home, me + 1), None);
    }

    #[test]
    fn rules_from_a_repository_root_above_the_project_apply() {
        let t = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(t.path()).unwrap().join("repo");
        let root = repo.join("pkgs/app");
        for d in ["src", "data/raw", "gen/x", "scratch", "keep"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::create_dir_all(repo.join(".git/info")).unwrap();
        fs::write(repo.join(".git/info/exclude"), "scratch/\n").unwrap();
        fs::write(repo.join(".gitignore"), "data/\n*.bin\n").unwrap();
        fs::write(repo.join("pkgs/.gitignore"), "gen/\n").unwrap();
        file(&root, "src/a.rs", 10);
        file(&root, "w.bin", 99);
        let ex = Exclusions::new(&root, Path::new("/nonexistent-home"), &[], &[], &[]).unwrap();
        let none = HashSet::new();
        let mut o = opts(&ex, &none, true);
        o.repo_root = Some(&repo);
        let t = walk(&root, &o).unwrap();
        let rel: Vec<String> = t
            .dirs
            .iter()
            .map(|d| {
                d.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            rel,
            ["", "keep", "src"],
            "data/, gen/ and scratch/ are ignored above"
        );
        assert_eq!(
            t.newest,
            Some((10, "src/a.rs".to_string())),
            "*.bin ignored"
        );
        assert!(t.ignore.is_ignored(&root.join("x.bin"), false));

        // Without the repository root, only the project's own rules apply (old behaviour).
        o.repo_root = None;
        assert_eq!(
            walk(&root, &o).unwrap().dirs.len(),
            8,
            "all eight directories"
        );
        assert_eq!(
            git_worktree_root(
                &root,
                &repo,
                Path::new("/nonexistent-home"),
                nix::unistd::geteuid().as_raw()
            ),
            Some(repo.clone())
        );
    }

    #[test]
    fn a_subtree_walk_keeps_the_project_rules_and_its_depth() {
        let f = fx();
        let r = &f.root;
        fs::write(r.join(".gitignore"), "cache/\n").unwrap();
        for d in ["a/b/cache", "a/b/c"] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        file(r, "a/b/c/new.txt", 500);
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        let full = walk(r, &o).unwrap();
        let sub = walk_from(r, &r.join("a/b"), &full.ignore, &o).unwrap();
        assert_eq!(sub.root, *r);
        assert_eq!(
            sub.dirs,
            [r.join("a/b"), r.join("a/b/c")],
            "cache/ from the root's rules"
        );
        assert_eq!(sub.newest, Some((500, "a/b/c/new.txt".to_string())));
        assert!(sub.git_dir.is_none());
        // Depth counts from the project root.
        o.max_depth = 2;
        let sub = walk_from(r, &r.join("a/b"), &full.ignore, &o).unwrap();
        assert_eq!(sub.dirs, [r.join("a/b")]);
    }

    #[test]
    fn layers_are_ranked_by_depth_and_replaced_not_duplicated() {
        let mut gi = GitIgnore::default();
        let deep = Path::new("/p/a/b");
        let shallow = Path::new("/p/a");
        gi.add(deep, false, b"!keep.tmp\n");
        gi.add(shallow, false, b"*.tmp\n"); // added later, but shallower: lower priority
        assert!(!gi.is_ignored(Path::new("/p/a/b/keep.tmp"), false));
        assert!(gi.is_ignored(Path::new("/p/a/b/other.tmp"), false));
        gi.add(shallow, false, b"*.log\n"); // replaces the old rules of /p/a
        assert!(!gi.is_ignored(Path::new("/p/a/x.tmp"), false));
        assert!(gi.is_ignored(Path::new("/p/a/x.log"), false));
        assert_eq!(gi.layers.len(), 2);
        gi.add(shallow, true, b"x.log\n!*.log\n"); // info/exclude ranks below .gitignore
        assert!(gi.is_ignored(Path::new("/p/a/x.log"), false));
        gi.add(deep, false, b"");
        assert_eq!(gi.layers.len(), 2, "an empty file removes its layer");
    }

    /// Bytes per line of [`rules`]: long enough that the byte limits are reached well before
    /// [`MAX_GITIGNORE_PATTERNS`].
    const RULE_LINE: usize = 512;

    /// `n` bytes of valid ignore rules, one per line: `f0000000`, `f0000001`, … each followed by
    /// `x` padding to [`RULE_LINE`] bytes, so `first_rule()` names what the first line ignores.
    fn rules(n: u64) -> Vec<u8> {
        let mut text = Vec::new();
        let mut i = 0u64;
        while (text.len() as u64) < n {
            let line = format!("f{i:07}{}\n", "x".repeat(RULE_LINE - 9));
            text.extend_from_slice(line.as_bytes());
            i += 1;
        }
        text.truncate(usize::try_from(n).unwrap());
        text
    }

    fn first_rule() -> String {
        format!("f0000000{}", "x".repeat(RULE_LINE - 9))
    }

    /// v0.1.0 review M2: a file over the per-file limit is skipped whole and counted; at the
    /// limit it is read.
    #[test]
    fn a_gitignore_over_the_per_file_limit_is_skipped_and_counted() {
        let f = fx();
        let r = &f.root;
        fs::create_dir_all(r.join(".git/info")).unwrap();
        for d in ["at-limit", "over-limit", "small"] {
            fs::create_dir(r.join(d)).unwrap();
        }
        fs::write(r.join("at-limit/.gitignore"), rules(MAX_GITIGNORE_BYTES)).unwrap();
        fs::write(
            r.join("over-limit/.gitignore"),
            rules(MAX_GITIGNORE_BYTES + 1),
        )
        .unwrap();
        fs::write(r.join("small/.gitignore"), "*.log\n").unwrap();
        fs::write(r.join(".git/info/exclude"), rules(MAX_GITIGNORE_BYTES + 1)).unwrap();
        let t = walk(r, &opts(&f.ex, &HashSet::new(), true)).unwrap();
        assert_eq!(
            t.ignore_files_skipped, 2,
            "over-limit/.gitignore and info/exclude"
        );
        let first = first_rule();
        assert!(t.ignore.is_ignored(&r.join("at-limit").join(&first), false));
        assert!(t.ignore.is_ignored(&r.join("small/x.log"), false));
        // Skipped means skipped: not even the first rule of the oversized file applies.
        assert!(!t
            .ignore
            .is_ignored(&r.join("over-limit").join(&first), false));
        assert!(!t.ignore.is_ignored(&r.join(&first), false), "info/exclude");
        assert_eq!(t.ignore.layers.len(), 2);
    }

    /// v0.1.0 review M2, the hostile repository: many directories, each with a large
    /// `.gitignore` (hard links, so tiny on disk). Only the project's total is read and kept;
    /// the rest is skipped and counted, in the walk's (sorted) order.
    #[test]
    fn a_project_keeps_at_most_the_total_of_ignore_bytes_however_many_files_it_has() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        let per_file = MAX_GITIGNORE_BYTES;
        let fit = MAX_GITIGNORE_TOTAL_BYTES / per_file;
        let dirs = 40u64;
        fs::write(r.join("big"), rules(per_file)).unwrap();
        for i in 0..dirs {
            let d = r.join(format!("d{i:02}"));
            fs::create_dir(&d).unwrap();
            fs::hard_link(r.join("big"), d.join(".gitignore")).unwrap();
        }
        let none = HashSet::new();
        let o = opts(&f.ex, &none, true);
        let t = walk(r, &o).unwrap();
        assert_eq!(t.ignore_files_skipped, dirs - fit);
        assert_eq!(t.ignore.layers.len() as u64, fit);
        let kept: u64 = t.ignore.layers.iter().map(|l| l.bytes).sum();
        assert_eq!(kept, MAX_GITIGNORE_TOTAL_BYTES);
        let first = first_rule();
        assert!(t.ignore.is_ignored(&r.join("d00").join(&first), false));
        assert!(!t.ignore.is_ignored(&r.join("d39").join(&first), false));
        assert_eq!(t.dirs.len() as u64, dirs + 1, "the walk itself is complete");

        // A subtree walk starts from the project's rules: the total still holds, and a file
        // that is read again replaces its own layer instead of counting twice.
        let again = walk_from(r, &r.join("d00"), &t.ignore, &o).unwrap();
        assert_eq!(
            again.ignore_files_skipped, 0,
            "d00/.gitignore replaces itself"
        );
        assert_eq!(again.ignore.layers.len() as u64, fit);
        let more = walk_from(r, &r.join("d39"), &t.ignore, &o).unwrap();
        assert_eq!(more.ignore_files_skipped, 1, "no room left for d39");
        assert_eq!(more.ignore.layers.len() as u64, fit);

        // A small file after the budget is used up is skipped too; an empty one is not.
        fs::write(r.join("d39/.gitignore"), "x\n").unwrap();
        let small = walk_from(r, &r.join("d39"), &t.ignore, &o).unwrap();
        assert_eq!(small.ignore_files_skipped, 1);
        fs::write(r.join("d39/.gitignore"), "").unwrap();
        let empty = walk_from(r, &r.join("d39"), &t.ignore, &o).unwrap();
        assert_eq!(empty.ignore_files_skipped, 0);
    }

    /// The limit that bounds memory: rules per project, counted before anything is compiled
    /// (comments and blank lines are free), whatever their size in bytes.
    #[test]
    fn a_project_keeps_at_most_the_total_of_ignore_rules() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        let per_file = MAX_GITIGNORE_PATTERNS / 4;
        let text: String = (0..per_file)
            .map(|i| format!("# a comment\n\n   \nrule{i}\n"))
            .collect();
        for d in ["d0", "d1", "d2", "d3", "d4", "d5"] {
            fs::create_dir(r.join(d)).unwrap();
            fs::write(r.join(d).join(".gitignore"), &text).unwrap();
        }
        let none = HashSet::new();
        let o = opts(&f.ex, &none, true);
        let t = walk(r, &o).unwrap();
        assert_eq!(t.ignore_files_skipped, 2, "four files fill the budget");
        assert_eq!(t.ignore.patterns(), MAX_GITIGNORE_PATTERNS);
        assert_eq!(t.ignore_rules_wanted, MAX_GITIGNORE_PATTERNS);
        assert!(t.ignore.is_ignored(&r.join("d3/rule7"), false));
        assert!(!t.ignore.is_ignored(&r.join("d4/rule7"), false));

        // One rule too many in a single file: skipped whole, nothing compiled.
        let over: String = (0..=MAX_GITIGNORE_PATTERNS)
            .map(|i| format!("r{i}\n"))
            .collect();
        let mut gi = GitIgnore::default();
        fs::write(r.join("d5/.gitignore"), &over).unwrap();
        let d5 = DirHandle::open_root(&r.join("d5")).unwrap();
        let mut adm = Admission::new(&o);
        let skipped = gi.load(&r.join("d5"), false, &d5, ".gitignore", &mut adm);
        assert_eq!(skipped, Some(Skipped::ByProject));
        assert!(gi.is_empty());
        let last_line = over.trim_end().rfind('\n').unwrap();
        fs::write(r.join("d5/.gitignore"), &over[..=last_line]).unwrap();
        let skipped = gi.load(&r.join("d5"), false, &d5, ".gitignore", &mut adm);
        assert_eq!(skipped, None);
        assert_eq!(gi.layers[0].rule_lines, MAX_GITIGNORE_PATTERNS);
    }

    /// The limit across projects reaches a walk as the number of rules the project may hold
    /// (`max_patterns`): a file that does not fit in it is skipped whole and counted, exactly
    /// like one over the project's own limit, and later files that do fit are still read.
    #[test]
    fn a_project_keeps_only_the_rules_the_limit_across_projects_leaves_it() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        for (dir, rules) in [("d0", 3), ("d1", 4), ("d2", 2), ("d3", 1)] {
            fs::create_dir(r.join(dir)).unwrap();
            let text: String = (0..rules).map(|i| format!("rule{i}\n")).collect();
            fs::write(r.join(dir).join(".gitignore"), text).unwrap();
        }
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        o.max_patterns = 6;
        let t = walk(r, &o).unwrap();
        // d0 (3) fits, d1 (4) would make 7, d2 (2) makes 5, d3 (1) makes 6.
        assert_eq!(t.ignore_files_skipped, 1);
        assert_eq!(t.ignore.patterns(), 6);
        assert!(t.ignore.is_ignored(&r.join("d0/rule0"), false));
        assert!(!t.ignore.is_ignored(&r.join("d1/rule0"), false), "skipped");
        assert!(t.ignore.is_ignored(&r.join("d2/rule0"), false));
        // No room at all: every file is skipped, the walk itself is complete.
        o.max_patterns = 0;
        let t = walk(r, &o).unwrap();
        assert_eq!((t.ignore_files_skipped, t.ignore.patterns()), (4, 0));
        assert_eq!(t.dirs.len(), 5);
        // A subtree walk starts from the project's rules: what they hold counts.
        o.max_patterns = 6;
        let full = walk(r, &o).unwrap();
        fs::write(r.join("d1/.gitignore"), "one\n").unwrap();
        let sub = walk_from(r, &r.join("d1"), &full.ignore, &o).unwrap();
        assert_eq!(
            sub.ignore_files_skipped, 1,
            "6 kept already: no room for one more"
        );
        o.max_patterns = 7;
        let sub = walk_from(r, &r.join("d1"), &full.ignore, &o).unwrap();
        assert_eq!((sub.ignore_files_skipped, sub.ignore.patterns()), (0, 7));
    }

    /// The number of rules a project wants (what the limit across projects is shared by) does
    /// not depend on what the walk was allowed, and neither do the project's own limits: files
    /// that only the allowance kept out still count towards them.
    #[test]
    fn what_a_project_wants_does_not_depend_on_what_it_was_allowed() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        let per_file = MAX_GITIGNORE_PATTERNS / 4;
        let text: String = (0..per_file).map(|i| format!("rule{i}\n")).collect();
        for d in ["d0", "d1", "d2", "d3", "d4", "d5"] {
            fs::create_dir(r.join(d)).unwrap();
            fs::write(r.join(d).join(".gitignore"), &text).unwrap();
        }
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        for (allowance, kept, skipped) in [
            (MAX_GITIGNORE_PATTERNS, 4 * per_file, 2),
            (2 * per_file + 1, 2 * per_file, 4),
            (per_file - 1, 0, 6),
            (0, 0, 6),
        ] {
            o.max_patterns = allowance;
            let t = walk(r, &o).unwrap();
            assert_eq!(t.ignore.patterns(), kept, "allowance {allowance}");
            assert_eq!(t.ignore_files_skipped, skipped, "allowance {allowance}");
            // Four files fill the project's own limit; d4 and d5 are over it in every case.
            assert_eq!(t.ignore_rules_wanted, 4 * per_file, "allowance {allowance}");
        }
    }

    /// Whether two sets of rules share the compiled rules of the ignore file in `dir`.
    fn same_layer(a: &GitIgnore, b: &GitIgnore, dir: &Path, exclude_file: bool) -> bool {
        let find = |g: &GitIgnore| {
            g.layers
                .iter()
                .find(|l| l.is(dir, rank(dir, exclude_file)))
                .cloned()
        };
        match (find(a), find(b)) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
            _ => false,
        }
    }

    /// The rule cache: a walk that is given the project's previous rules takes over the
    /// compiled rules of every ignore file whose device, inode, size, modification time and
    /// change time are unchanged, and compiles only what changed. Files that are gone lose their
    /// rules.
    #[test]
    fn a_later_walk_reuses_the_rules_of_unchanged_ignore_files_and_compiles_only_what_changed() {
        let f = fx();
        let r = &f.root;
        fs::create_dir_all(r.join(".git/info")).unwrap();
        fs::write(r.join(".git/info/exclude"), "excluded.txt\n").unwrap();
        fs::write(r.join(".gitignore"), "*.log\n").unwrap();
        for d in ["a", "b", "c"] {
            fs::create_dir(r.join(d)).unwrap();
            fs::write(r.join(d).join(".gitignore"), format!("{d}-first.tmp\n")).unwrap();
        }
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        let first = walk(r, &o).unwrap();
        assert_eq!(first.ignore.layers.len(), 5);

        // Without the previous rules everything is compiled again (the control).
        let again = walk(r, &o).unwrap();
        assert!(!same_layer(&first.ignore, &again.ignore, r, false));

        // With them, nothing is: every layer is the same object.
        o.reuse = Some(&first.ignore);
        let second = walk(r, &o).unwrap();
        assert_eq!(second.ignore.layers.len(), 5);
        assert!(
            same_layer(&first.ignore, &second.ignore, r, true),
            "info/exclude"
        );
        for dir in [r.clone(), r.join("a"), r.join("b"), r.join("c")] {
            assert!(
                same_layer(&first.ignore, &second.ignore, &dir, false),
                "{dir:?}"
            );
        }
        assert_eq!(second.ignore_rules_wanted, first.ignore_rules_wanted);

        // One file changes, one is deleted, one is new: only those differ.
        fs::write(r.join("a/.gitignore"), "a-second-version.tmp\n").unwrap();
        fs::remove_file(r.join("b/.gitignore")).unwrap();
        fs::create_dir(r.join("d")).unwrap();
        fs::write(r.join("d/.gitignore"), "d-first.tmp\n").unwrap();
        let third = walk(r, &o).unwrap();
        assert!(!same_layer(
            &first.ignore,
            &third.ignore,
            &r.join("a"),
            false
        ));
        assert!(third
            .ignore
            .is_ignored(&r.join("a/a-second-version.tmp"), false));
        assert!(!third.ignore.is_ignored(&r.join("a/a-first.tmp"), false));
        assert!(
            !third.ignore.is_ignored(&r.join("b/b-first.tmp"), false),
            "deleted"
        );
        assert!(
            third.ignore.is_ignored(&r.join("d/d-first.tmp"), false),
            "new"
        );
        assert!(same_layer(
            &first.ignore,
            &third.ignore,
            &r.join("c"),
            false
        ));
        assert!(same_layer(&first.ignore, &third.ignore, r, false));
        assert_eq!(third.ignore.layers.len(), 5);
    }

    /// What "unchanged" means: the same device, inode, size, modification time **and** change
    /// time. The first case is the one the change time is there for: a file rewritten in place
    /// to the same size, with its modification time put back, differs in nothing else, and is
    /// compiled again. (A rewrite inside the file system's timestamp resolution of the previous
    /// change would still be missed: the test waits that resolution out.)
    #[test]
    fn an_ignore_file_counts_as_changed_when_its_size_times_or_inode_change() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        let file = r.join(".gitignore");
        fs::write(&file, "aaa.tmp\n").unwrap();
        set_mtime(&file, 1_000);
        let id = |file: &Path| FileId::of(&fs::File::open(file).unwrap()).unwrap();
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        let first = walk(r, &o).unwrap();
        o.reuse = Some(&first.ignore);
        let ignores = |t: &Tree, name: &str| t.ignore.is_ignored(&r.join(name), false);
        // Control: nothing changed, the rules are reused.
        assert!(same_layer(
            &first.ignore,
            &walk(r, &o).unwrap().ignore,
            r,
            false
        ));

        // Rewritten in place: same inode, same size, and the modification time put back. Only
        // the change time tells (it moves once the file system's clock has ticked).
        let before = id(&file);
        let waited = std::time::Instant::now();
        loop {
            fs::write(&file, "bbb.tmp\n").unwrap();
            set_mtime(&file, 1_000);
            if id(&file).ctime != before.ctime {
                break;
            }
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(5),
                "the change time never moved: no test of it on this file system"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let after = id(&file);
        assert_eq!(
            (after.dev, after.ino, after.size, after.mtime),
            (before.dev, before.ino, before.size, before.mtime),
            "control: nothing but the change time differs"
        );
        let t = walk(r, &o).unwrap();
        assert!(!same_layer(&first.ignore, &t.ignore, r, false));
        assert!(ignores(&t, "bbb.tmp") && !ignores(&t, "aaa.tmp"));

        // The modification time (setting it moves the change time too).
        o.reuse = Some(&t.ignore);
        let before = Arc::clone(&t.ignore);
        set_mtime(&file, 2_000);
        let t = walk(r, &o).unwrap();
        assert!(!same_layer(&before, &t.ignore, r, false));
        assert!(ignores(&t, "bbb.tmp"));
        // The size.
        o.reuse = Some(&t.ignore);
        let before = Arc::clone(&t.ignore);
        fs::write(&file, "cccc.tmp\n").unwrap();
        set_mtime(&file, 2_000);
        let t = walk(r, &o).unwrap();
        assert!(!same_layer(&before, &t.ignore, r, false));
        assert!(ignores(&t, "cccc.tmp") && !ignores(&t, "bbb.tmp"));
        // The inode: another file of the same size and modification time takes its name.
        o.reuse = Some(&t.ignore);
        let before = Arc::clone(&t.ignore);
        let other = r.join("replacement");
        fs::write(&other, "dddd.tmp\n").unwrap();
        set_mtime(&other, 2_000);
        fs::rename(&other, &file).unwrap();
        let t = walk(r, &o).unwrap();
        assert!(!same_layer(&before, &t.ignore, r, false));
        assert!(ignores(&t, "dddd.tmp") && !ignores(&t, "cccc.tmp"));
    }

    /// One ignore file hard-linked into several directories is one inode with one size and
    /// time, but its rules are relative to each directory: every location has its own compiled
    /// rules, and each is reused for its own location only.
    #[test]
    fn hard_links_to_one_ignore_file_have_rules_of_their_own_per_directory() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        fs::write(r.join("shared"), "/only-here.tmp\n").unwrap();
        for d in ["a", "b"] {
            fs::create_dir(r.join(d)).unwrap();
            fs::hard_link(r.join("shared"), r.join(d).join(".gitignore")).unwrap();
        }
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        let first = walk(r, &o).unwrap();
        o.reuse = Some(&first.ignore);
        for t in [&first, &walk(r, &o).unwrap()] {
            assert_eq!(t.ignore.layers.len(), 2);
            assert!(t.ignore.is_ignored(&r.join("a/only-here.tmp"), false));
            assert!(t.ignore.is_ignored(&r.join("b/only-here.tmp"), false));
            assert!(!t.ignore.is_ignored(&r.join("a/sub/only-here.tmp"), false));
            assert!(same_layer(&first.ignore, &t.ignore, &r.join("a"), false));
            assert!(same_layer(&first.ignore, &t.ignore, &r.join("b"), false));
            assert!(!Arc::ptr_eq(&t.ignore.layers[0], &t.ignore.layers[1]));
        }
    }

    /// The limits decide the same way for a file whose rules are reused as for one that is
    /// read: nothing is kept that a fresh walk would skip.
    #[test]
    fn reused_rules_are_held_to_the_same_limits_as_fresh_ones() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        for (dir, rules) in [("d0", 3), ("d1", 4), ("d2", 2), ("d3", 1)] {
            fs::create_dir(r.join(dir)).unwrap();
            let text: String = (0..rules).map(|i| format!("rule{i}\n")).collect();
            fs::write(r.join(dir).join(".gitignore"), text).unwrap();
        }
        let none = HashSet::new();
        let mut o = opts(&f.ex, &none, true);
        let all = walk(r, &o).unwrap();
        assert_eq!((all.ignore.patterns(), all.ignore_files_skipped), (10, 0));
        o.reuse = Some(&all.ignore);
        for allowance in [10, 9, 6, 3, 2, 0] {
            o.max_patterns = allowance;
            let reused = walk(r, &o).unwrap();
            o.reuse = None;
            let fresh = walk(r, &o).unwrap();
            o.reuse = Some(&all.ignore);
            assert_eq!(
                (
                    reused.ignore.patterns(),
                    reused.ignore_files_skipped,
                    reused.ignore_rules_wanted
                ),
                (
                    fresh.ignore.patterns(),
                    fresh.ignore_files_skipped,
                    fresh.ignore_rules_wanted
                ),
                "allowance {allowance}"
            );
            assert!(reused.ignore.patterns() <= allowance);
            for dir in ["d0", "d1", "d2", "d3"] {
                assert_eq!(
                    reused.ignore.is_ignored(&r.join(dir).join("rule0"), false),
                    fresh.ignore.is_ignored(&r.join(dir).join("rule0"), false),
                    "{dir}, allowance {allowance}"
                );
            }
        }
    }

    /// The result of a full walk of `root` that kept `kept` rules and wanted `wanted`.
    fn walked(root: &Path, kept: usize, wanted: usize) -> Tree {
        let mut ignore = GitIgnore::default();
        let text: String = (0..kept).map(|i| format!("rule{i}\n")).collect();
        ignore.add(root, false, text.as_bytes());
        assert_eq!(ignore.patterns(), kept);
        Tree {
            root: root.to_path_buf(),
            dirs: Vec::new(),
            git_dir: None,
            newest: None,
            ignore: Arc::new(ignore),
            truncated: false,
            unreadable: 0,
            ignore_files_skipped: 0,
            ignore_rules_wanted: wanted,
        }
    }

    /// A full walk of `root` through the store: it keeps what it wants as far as it is allowed.
    fn walk_through(
        store: &RuleStore,
        root: &Path,
        recency: Option<i64>,
        wanted: usize,
        at_most: usize,
    ) -> usize {
        let grant = store.begin(root, recency, at_most);
        let kept = wanted.min(grant.max_patterns);
        store.settle(root, Some(&walked(root, kept, wanted)));
        kept
    }

    const NO_CAP: usize = MAX_GITIGNORE_PATTERNS;

    #[test]
    fn all_projects_together_never_hold_more_than_the_limit() {
        let (a, b, c) = (Path::new("/p/a"), Path::new("/p/b"), Path::new("/p/c"));
        let store = RuleStore::new(10);
        assert_eq!((store.room(a), store.total()), (10, 0));
        // A full walk of `a` is in progress: its whole allowance is taken until it settles.
        let grant = store.begin(a, None, NO_CAP);
        assert_eq!(grant.max_patterns, 10);
        assert!(grant.reuse.is_none(), "nothing to reuse yet");
        assert_eq!((store.room(b), store.total()), (0, 10));
        store.settle(a, Some(&walked(a, 4, 4)));
        assert_eq!((store.room(b), store.total(), store.kept(a)), (6, 4, 4));
        assert!(!store.contended());
        // `b` wants more than is left: it keeps what fits and stays wanting.
        assert_eq!(walk_through(&store, b, None, 9, NO_CAP), 6);
        assert_eq!((store.room(c), store.total()), (0, 10));
        assert!(store.contended());
        // A project's own rules do not count against it: a full walk replaces them.
        assert_eq!(store.room(a), 4);
        // No more than the caller allows, either.
        assert_eq!(store.begin(a, None, 3).max_patterns, 3);
        store.settle(a, Some(&walked(a, 1, 4)));
        assert_eq!((store.room(c), store.total()), (3, 7));
        // A walk that failed, and a project without rules, keep nothing and leave no entry.
        store.begin(c, None, NO_CAP);
        store.settle(c, None);
        store.begin(c, None, NO_CAP);
        store.settle(c, Some(&walked(c, 0, 0)));
        assert_eq!((store.total(), store.kept(c)), (7, 0));
        // A project that is no longer monitored frees its share.
        store.retain(|root| root != b);
        assert_eq!((store.room(c), store.total()), (9, 1));
    }

    #[test]
    fn a_full_walk_is_handed_the_rules_of_the_previous_one() {
        let store = RuleStore::new(100);
        let a = Path::new("/p/a");
        store.begin(a, None, NO_CAP);
        let first = walked(a, 3, 3);
        store.settle(a, Some(&first));
        let grant = store.begin(a, None, NO_CAP);
        assert!(Arc::ptr_eq(&grant.reuse.unwrap(), &first.ignore));
        store.settle(a, Some(&first));
        store.retain(|_| false);
        assert!(
            store.begin(a, None, NO_CAP).reuse.is_none(),
            "forgotten with the project"
        );
    }

    #[test]
    fn one_project_never_gets_more_than_the_project_limit() {
        let store = RuleStore::default();
        let fit = MAX_GITIGNORE_PATTERNS_TOTAL / MAX_GITIGNORE_PATTERNS;
        for i in 0..fit {
            let root = PathBuf::from(format!("/p/{i}"));
            assert_eq!(store.room(&root), MAX_GITIGNORE_PATTERNS);
            let grant = store.begin(&root, None, usize::MAX);
            assert_eq!(grant.max_patterns, MAX_GITIGNORE_PATTERNS);
        }
        let rest = MAX_GITIGNORE_PATTERNS_TOTAL - fit * MAX_GITIGNORE_PATTERNS;
        let last = store.begin(Path::new("/p/last"), None, usize::MAX);
        assert_eq!(last.max_patterns, rest);
        assert_eq!(store.total(), MAX_GITIGNORE_PATTERNS_TOTAL);
    }

    /// Two projects walked at the same time cannot both take the last room: what was handed out
    /// never exceeds the limit, whatever the interleaving.
    #[test]
    fn walks_at_the_same_time_cannot_take_more_than_the_limit_together() {
        const LIMIT: usize = 12_000;
        for _ in 0..50 {
            let store = Arc::new(RuleStore::new(LIMIT));
            let walkers: Vec<_> = (0..8)
                .map(|i| {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        let root = PathBuf::from(format!("/p/{i}"));
                        store.begin(&root, None, NO_CAP).max_patterns
                    })
                })
                .collect();
            let mut given: Vec<usize> = walkers.into_iter().map(|w| w.join().unwrap()).collect();
            given.sort_unstable();
            assert_eq!(given, [0, 0, 0, 0, 0, 2_000, 5_000, 5_000]);
            assert_eq!(store.total(), LIMIT);
        }
    }

    /// The limit across projects goes to the most recently active projects, not to whoever was
    /// walked first. `rebalance` names the walks that get there (give up first, then take), and
    /// has nothing to say once it is so.
    #[test]
    fn the_rules_go_to_the_most_recently_active_projects() {
        let (old, recent, unknown) = (
            Path::new("/p/a-old"),
            Path::new("/p/b-recent"),
            Path::new("/p/c-unknown"),
        );
        let store = RuleStore::new(10);
        // Walked in path order, first come, first served: the old project took the room.
        assert_eq!(walk_through(&store, old, Some(100), 6, NO_CAP), 6);
        assert_eq!(walk_through(&store, recent, Some(200), 6, NO_CAP), 4);
        assert_eq!(walk_through(&store, unknown, None, 3, NO_CAP), 0);
        // By recency: `recent` gets all it wants (6), `old` what is left (4), `unknown` nothing.
        let plan = store.rebalance();
        assert_eq!(plan, [(old.to_path_buf(), 4), (recent.to_path_buf(), 6)]);
        for (root, allowance) in &plan {
            let (recency, wanted) = if root == old {
                (Some(100), 6)
            } else {
                (Some(200), 6)
            };
            walk_through(&store, root, recency, wanted, *allowance);
            assert!(store.total() <= 10, "within the limit at every step");
        }
        assert_eq!(
            (store.kept(recent), store.kept(old), store.kept(unknown)),
            (6, 4, 0)
        );
        assert_eq!(store.rebalance(), [], "settled: nothing is walked again");
        assert!(
            store.contended(),
            "two projects still want more than they have"
        );

        // The project nobody knew anything about becomes the most recently active one.
        store.set_recency(unknown, Some(300));
        let plan = store.rebalance();
        assert_eq!(plan, [(old.to_path_buf(), 1), (unknown.to_path_buf(), 3)]);
        walk_through(&store, old, Some(100), 6, 1);
        walk_through(&store, unknown, Some(300), 3, 3);
        assert_eq!(
            (store.kept(unknown), store.kept(recent), store.kept(old)),
            (3, 6, 1)
        );
        assert_eq!(store.rebalance(), []);

        // A project leaves: the next in the order takes what it frees.
        store.retain(|root| root != recent);
        assert_eq!(store.rebalance(), [(old.to_path_buf(), 6)]);
        walk_through(&store, old, Some(100), 6, 6);
        assert_eq!(store.rebalance(), []);
        assert!(!store.contended());
    }

    /// The same projects give the same shares whatever order they were walked in, and equal
    /// recency is decided by the path: nothing depends on timing.
    #[test]
    fn the_shares_depend_on_the_projects_alone_not_on_the_order_of_their_walks() {
        let projects: [(&str, Option<i64>, usize); 5] = [
            ("/p/e", Some(500), 4),
            ("/p/d", Some(500), 4), // as recent as /p/e: the path decides (d before e)
            ("/p/c", Some(100), 4),
            ("/p/b", None, 4),
            ("/p/a", None, 4), // unknown comes last, whatever its path
        ];
        let expected = [
            ("/p/d", 4),
            ("/p/e", 4),
            ("/p/c", 2),
            ("/p/a", 0),
            ("/p/b", 0),
        ];
        let orders: [[usize; 5]; 4] = [
            [0, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 4, 0, 3, 1],
            [3, 0, 4, 1, 2],
        ];
        for order in orders {
            let store = RuleStore::new(10);
            for i in order {
                let (root, recency, wanted) = projects[i];
                walk_through(&store, Path::new(root), recency, wanted, NO_CAP);
            }
            // Until nothing is left to do (one round is enough; a second one must be empty).
            for (root, allowance) in store.rebalance() {
                let (_, recency, wanted) =
                    projects.iter().find(|p| Path::new(p.0) == root).unwrap();
                walk_through(&store, &root, *recency, *wanted, allowance);
                assert!(store.total() <= 10);
            }
            assert_eq!(store.rebalance(), [], "order {order:?}");
            for (root, kept) in expected {
                assert_eq!(store.kept(Path::new(root)), kept, "{root}, order {order:?}");
            }
        }
    }

    /// A project in the middle of a walk is left alone: its numbers are about to change.
    #[test]
    fn a_project_that_is_being_walked_is_not_planned_for() {
        let (a, b) = (Path::new("/p/a"), Path::new("/p/b"));
        let store = RuleStore::new(10);
        walk_through(&store, a, Some(100), 8, NO_CAP);
        walk_through(&store, b, Some(200), 8, NO_CAP);
        assert_eq!(
            store.rebalance(),
            [(a.to_path_buf(), 2), (b.to_path_buf(), 8)]
        );
        store.begin(a, Some(100), NO_CAP);
        assert_eq!(store.rebalance(), [(b.to_path_buf(), 8)]);
    }

    /// A file that grew past the limit loses the rules read earlier: they no longer describe it.
    #[test]
    fn a_gitignore_that_grows_past_the_limit_drops_its_old_rules() {
        let f = fx();
        let r = &f.root;
        fs::create_dir(r.join(".git")).unwrap();
        fs::write(r.join(".gitignore"), "*.log\n").unwrap();
        let none = HashSet::new();
        let o = opts(&f.ex, &none, true);
        let first = walk(r, &o).unwrap();
        assert!(first.ignore.is_ignored(&r.join("a.log"), false));
        fs::write(r.join(".gitignore"), rules(MAX_GITIGNORE_BYTES + 1)).unwrap();
        let second = walk_from(r, r, &first.ignore, &o).unwrap();
        assert_eq!(second.ignore_files_skipped, 1);
        assert!(!second.ignore.is_ignored(&r.join("a.log"), false));
        assert!(second.ignore.is_empty());
    }

    #[test]
    fn rules_above_the_project_root_count_against_the_same_limits() {
        let t = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(t.path()).unwrap().join("repo");
        let root = repo.join("pkgs/app");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(repo.join(".git/info")).unwrap();
        fs::write(repo.join(".git/info/exclude"), "*.tmp\n").unwrap();
        fs::write(repo.join(".gitignore"), rules(MAX_GITIGNORE_BYTES + 1)).unwrap();
        fs::write(repo.join("pkgs/.gitignore"), "*.bin\n").unwrap();
        let ex = Exclusions::new(&root, Path::new("/nonexistent-home"), &[], &[], &[]).unwrap();
        let none = HashSet::new();
        let mut o = opts(&ex, &none, true);
        o.repo_root = Some(&repo);
        let t = walk(&root, &o).unwrap();
        assert_eq!(t.ignore_files_skipped, 1, "the repository's own .gitignore");
        assert!(t.ignore.is_ignored(&root.join("x.tmp"), false));
        assert!(t.ignore.is_ignored(&root.join("x.bin"), false));
        assert!(!t.ignore.is_ignored(&root.join(first_rule()), false));
    }
}
