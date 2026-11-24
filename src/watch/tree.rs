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

/// Gitignore rules of one project: `.git/info/exclude` (lowest priority), then `.gitignore`
/// files, deeper ones overriding shallower ones. Approximates Git (documented differences: no
/// `core.excludesFile`, no rules from above the project root).
#[derive(Debug, Default)]
pub struct GitIgnore {
    /// In priority order, lowest first.
    layers: Vec<(PathBuf, Gitignore)>,
}

impl GitIgnore {
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        for (dir, gi) in self.layers.iter().rev() {
            if !path.starts_with(dir) || path == dir {
                continue;
            }
            match gi.matched(path, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        false
    }

    fn add(&mut self, dir: &Path, text: &[u8]) {
        let mut b = GitignoreBuilder::new(dir);
        for line in String::from_utf8_lossy(text).lines() {
            let _ = b.add_line(None, line); // an invalid pattern is skipped, like Git does
        }
        if let Ok(gi) = b.build() {
            if gi.num_ignores() + gi.num_whitelists() > 0 {
                self.layers.push((dir.to_path_buf(), gi));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

/// Whether `root` lies in a Git work tree: `root` or an ancestor below `home` has `.git`
/// (a repository at `home` itself, e.g. dotfiles, does not count; same rule as the Git module).
pub fn in_git_worktree(root: &Path, home: &Path) -> bool {
    root.ancestors()
        .take_while(|a| *a != home && a.parent().is_some())
        .any(|a| std::fs::symlink_metadata(a.join(".git")).is_ok())
}

pub struct TreeOptions<'a> {
    pub exclusions: &'a Exclusions,
    /// Other projects' roots: their subtrees belong to them (§4.4), never to this project.
    pub other_projects: &'a HashSet<PathBuf>,
    pub max_depth: usize,
    pub same_file_system: bool,
    /// Apply `.gitignore` rules (the project is in a Git work tree).
    pub git_aware: bool,
    /// File times after this are clamped to it (a future mtime must not pin a project on top).
    pub now: i64,
    pub max_entries: usize,
}

#[derive(Debug)]
pub struct Tree {
    pub root: PathBuf,
    /// Eligible directories in preorder, the root first.
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
    let first = DirHandle::open_root(root).map_err(|e| match e {
        crate::discovery::dirfd::OpenError::Io(e) => e,
        crate::discovery::dirfd::OpenError::Replaced => {
            std::io::Error::other("the directory was replaced")
        }
    })?;
    let root_dev = first.identity().dev;
    let mut tree = Tree {
        root: root.to_path_buf(),
        dirs: Vec::new(),
        git_dir: None,
        newest: None,
        ignore: Arc::new(GitIgnore::default()),
        truncated: false,
        unreadable: 0,
    };
    let mut ignore = GitIgnore::default();
    let mut entries_seen = 0usize;
    let mut first = Some(first);
    let mut stack = vec![Frame {
        parent: None,
        path: root.to_path_buf(),
        depth: 0,
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
            if frame.depth == 0 {
                if let Some((text, _)) = read_info_exclude(&dir) {
                    ignore.add(&frame.path, &text);
                }
            }
            if entries.iter().any(|e| e.name == ".gitignore") {
                if let Some((text, _)) =
                    dir.read_regular(OsStr::new(".gitignore"), false, MAX_GITIGNORE_BYTES)
                {
                    ignore.add(&frame.path, &text);
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
}
