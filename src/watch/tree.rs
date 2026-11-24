//! The bounded walk of one project's tree (REQUIREMENTS.md §5): which directories may be watched,
//! the newest meaningful file (the *inferred* activity timestamp), and the in-process gitignore
//! matcher used to judge live events.
//!
//! Same safety rules as discovery: every directory is opened by descriptor relative to its parent
//! and verified by `(dev, ino)`; symlinks are never followed; excluded, gitignored and nested-project
//! directories are pruned before descending. File contents read: `.gitignore` files and
//! `.git/info/exclude` (bounded), nothing else.

use crate::discovery::dirfd::{DirHandle, Identity, Kind};
use crate::discovery::exclusions::Exclusions;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

/// Directory entries examined per project walk (larger trees are truncated and reported).
pub const MAX_ENTRIES: usize = 100_000;
const MAX_GITIGNORE_BYTES: u64 = 1024 * 1024;

/// Gitignore rules of one project: `.git/info/exclude` of its repository (lowest priority), then
/// `.gitignore` files from the repository's root down, deeper ones overriding shallower ones.
/// Approximates Git (documented differences: no `core.excludesFile`; rules above the
/// repository root never apply).
#[derive(Debug, Default, Clone)]
pub struct GitIgnore {
    /// Sorted by rank, lowest priority first. Only layers whose directory is an ancestor of a
    /// path apply to it, and those are ordered by depth, so one sorted list serves every path.
    layers: Vec<Layer>,
}

#[derive(Debug, Clone)]
struct Layer {
    dir: PathBuf,
    /// (depth of `dir`, 0 for `info/exclude` / 1 for `.gitignore`).
    rank: (usize, u8),
    rules: Gitignore,
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

    /// Add (or replace) the rules of `dir`'s `.gitignore` (or `info/exclude` when
    /// `exclude_file`).
    fn add(&mut self, dir: &Path, exclude_file: bool, text: &[u8]) {
        let rank = (dir.components().count(), u8::from(!exclude_file));
        self.layers.retain(|l| !(l.dir == dir && l.rank == rank));
        let mut b = GitignoreBuilder::new(dir);
        for line in String::from_utf8_lossy(text).lines() {
            let _ = b.add_line(None, line); // an invalid pattern is skipped, like Git does
        }
        if let Ok(rules) = b.build() {
            if rules.num_ignores() + rules.num_whitelists() > 0 {
                let at = self.layers.partition_point(|l| l.rank <= rank);
                self.layers.insert(
                    at,
                    Layer {
                        dir: dir.to_path_buf(),
                        rank,
                        rules,
                    },
                );
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

/// The root of the Git work tree containing `root`: `root` or the nearest ancestor below `home`
/// with a `.git` (a repository at `home` itself, e.g. dotfiles, does not count; same rule as the
/// Git module).
pub fn git_worktree_root(root: &Path, home: &Path) -> Option<PathBuf> {
    root.ancestors()
        .take_while(|a| *a != home && a.parent().is_some())
        .find(|a| std::fs::symlink_metadata(a.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

/// Whether `root` lies in a Git work tree ([`git_worktree_root`]).
pub fn in_git_worktree(root: &Path, home: &Path) -> bool {
    git_worktree_root(root, home).is_some()
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
    };
    let mut ignore = base.clone();
    if o.git_aware && start_depth == 0 {
        if let Some(repo) = o.repo_root.filter(|r| *r != root && root.starts_with(r)) {
            add_repository_layers(&mut ignore, repo, root);
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
                if let Some((text, _)) = read_info_exclude(&dir) {
                    ignore.add(&frame.path, true, &text);
                }
            }
            if entries.iter().any(|e| e.name == ".gitignore") {
                if let Some((text, _)) =
                    dir.read_regular(OsStr::new(".gitignore"), false, MAX_GITIGNORE_BYTES)
                {
                    ignore.add(&frame.path, false, &text);
                }
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
    tree.ignore = Arc::new(ignore);
    Ok(tree)
}

/// Rules from a work tree's root above the project root: its `.git/info/exclude` and every
/// `.gitignore` from `repo` down to (not including) `root`. Each directory is opened by path and
/// read through its descriptor; one that cannot be read (e.g. outside the sandbox) is skipped.
fn add_repository_layers(ignore: &mut GitIgnore, repo: &Path, root: &Path) {
    let Ok(rel) = root.strip_prefix(repo) else {
        return;
    };
    let mut dir = repo.to_path_buf();
    let mut dirs = vec![dir.clone()];
    for c in rel.components() {
        dir.push(c);
        if dir != root {
            dirs.push(dir.clone());
        }
    }
    for (i, d) in dirs.iter().enumerate() {
        let Ok(h) = DirHandle::open_root(d) else {
            continue;
        };
        if i == 0 {
            if let Some((text, _)) = read_info_exclude(&h) {
                ignore.add(d, true, &text);
            }
        }
        if let Some((text, _)) =
            h.read_regular(OsStr::new(".gitignore"), false, MAX_GITIGNORE_BYTES)
        {
            ignore.add(d, false, &text);
        }
    }
}

/// `.git/info/exclude` of a repository rooted here (only when `.git` is a real directory).
fn read_info_exclude(dir: &DirHandle) -> Option<(Vec<u8>, u64)> {
    let entries_git = dir.open_child_dir(OsStr::new(".git"))?;
    let info = entries_git.open_child_dir(OsStr::new("info"))?;
    info.read_regular(OsStr::new("exclude"), false, MAX_GITIGNORE_BYTES)
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
        assert!(
            !in_git_worktree(&home.join("a/b/c"), &home),
            "home repo ignored"
        );
        fs::create_dir(home.join("a/.git")).unwrap();
        assert!(in_git_worktree(&home.join("a/b/c"), &home));
        assert!(in_git_worktree(&home.join("a"), &home));
        fs::write(home.join("a/b/c/.git"), "gitdir: x").unwrap();
        assert!(
            in_git_worktree(&home.join("a/b/c"), &home),
            "a .git file counts"
        );
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
            git_worktree_root(&root, Path::new("/nonexistent-home")),
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
}
