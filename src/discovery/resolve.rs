//! Session cwd → project root (REQUIREMENTS.md §4.3, §4.4). Sessions are the primary discovery
//! source: a recorded working directory becomes a project at the nearest enclosing directory that
//! is a Git work-tree root or holds a `CLAUDE.md` (never crossing the discovery root, never the
//! home directory); a marker directory without its own Git work tree inside another marker
//! directory or registered project belongs to that one (the nested rule, applied to what is on
//! disk, so the outcome does not depend on what is registered yet). Without any of these the cwd
//! itself is a *session-only* candidate: it never acts as the outer project of the nested rule,
//! and it is registered only if no marker, Git work tree or registered project lies below it;
//! otherwise the session is unassigned as a `container` (M3 security review, M4: a session in
//! `~/dev` must not swallow the projects below it). The home directory, temporary directories,
//! cwds that no longer exist and cwds outside the allowed roots are never projects either; they
//! are counted as *unassigned* sessions.
//!
//! Only metadata and directory entries are read (`canonicalize`, `lstat` of `.git` /
//! `CLAUDE.md`, a bounded descriptor-based listing below a session-only candidate). Never derived
//! from Claude Code's directory names.

use super::dirfd::{DirHandle, Identity, Kind};
use super::exclusions::Exclusions;
use super::walk::MARKER_NAME;
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Directories the container check lists below a session-only candidate at most; a tree larger
/// than this is treated as a container (it is no small, plain project folder).
pub const CONTAINER_SCAN_DIRS: usize = 2000;

/// Why a session's cwd does not name a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unassigned {
    /// The session recorded no usable cwd (absent, relative, not UTF-8).
    NoCwd,
    /// The cwd no longer exists (or is not a directory).
    Nonexistent,
    /// The home directory itself (or one of its ancestors).
    Home,
    /// A temporary directory outside the home directory (`/tmp`, `/var/tmp`, `/dev/shm`, `$TMPDIR`).
    Temporary,
    /// Not below any discovery root.
    OutsideRoots,
    /// Below an excluded directory or a hard boundary, on another file system than its root
    /// (with `same_file_system`), or deeper than `max_depth` below its root.
    Excluded,
    /// A session-only cwd (no Git work tree, no `CLAUDE.md` at or above it) with projects below
    /// it, such as `~/dev`: never a project of its own.
    Container,
}

impl Unassigned {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCwd => "no_cwd",
            Self::Nonexistent => "nonexistent",
            Self::Home => "home",
            Self::Temporary => "temporary",
            Self::OutsideRoots => "outside_roots",
            Self::Excluded => "excluded",
            Self::Container => "container",
        }
    }

    /// The reason depends only on the cwd and the configuration, so it holds while the daemon
    /// runs (a parse may stop early, [`crate::claude::parse`]). A missing cwd may appear and
    /// projects may appear below a container.
    pub fn is_static(self) -> bool {
        !matches!(self, Self::Nonexistent | Self::Container)
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::NoCwd,
            Self::Nonexistent,
            Self::Home,
            Self::Temporary,
            Self::OutsideRoots,
            Self::Excluded,
            Self::Container,
        ]
        .into_iter()
        .find(|u| u.as_str() == s)
    }
}

/// Temporary directories never hold projects (unless the home directory is inside one, as in the
/// synthetic test environment).
pub fn temp_dirs(tmpdir_env: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev/shm"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(t) = tmpdir_env.map(PathBuf::from).filter(|t| t.is_absolute()) {
        v.push(t);
    }
    let canonical: Vec<PathBuf> = v
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    for c in canonical {
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

pub struct Context {
    /// Canonical discovery roots with their exclusion rules.
    pub roots: Vec<(PathBuf, Exclusions)>,
    /// Canonical home directory.
    pub home: PathBuf,
    pub temp_dirs: Vec<PathBuf>,
    /// Canonical paths of the present registered projects.
    pub known: HashSet<PathBuf>,
    /// Discovery's `max_depth` (levels below the root).
    pub max_depth: usize,
    /// Discovery's `same_file_system`.
    pub same_file_system: bool,
}

fn has_entry(dir: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(dir.join(name)).is_ok()
}

fn is_marker(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(MARKER_NAME))
        .is_ok_and(|m| m.is_file() || m.file_type().is_symlink())
}

/// `dir` is a Git work-tree root (a `.git` entry of any kind) or holds a `CLAUDE.md`. A
/// registered project that is neither is *session-only*: it never makes the directories below
/// it nested (§4.4, M3 review M4).
pub fn is_anchored(dir: &Path) -> bool {
    has_entry(dir, ".git") || is_marker(dir)
}

/// A cwd that passed the checks that need no project knowledge.
struct Located<'a> {
    canonical: PathBuf,
    root: &'a Path,
    exclusions: &'a Exclusions,
    root_dev: u64,
}

impl Context {
    /// The project root for a session whose first recorded cwd is `cwd`.
    pub fn resolve(&self, cwd: Option<&str>) -> Result<PathBuf, Unassigned> {
        let at = self.locate(cwd)?;
        let within = |a: &&Path| a.starts_with(at.root) && *a != self.home.as_path();
        // Nearest Git work-tree root or marker directory at or above the cwd, within the root and
        // below the home directory (a dotfiles repository at home is not the project's).
        let Some(mut candidate) = at
            .canonical
            .ancestors()
            .take_while(within)
            .find(|a| is_anchored(a))
            .map(Path::to_path_buf)
        else {
            return self.session_only(&at);
        };
        // Nested rule (§4.4): a candidate without its own Git work tree that lies inside a marker
        // directory or a registered (anchored) project belongs to it; repeated, because that one
        // may be nested itself. A registered project stays what it is.
        while !self.known.contains(&candidate) && !has_entry(&candidate, ".git") {
            let outer = candidate
                .ancestors()
                .skip(1)
                .take_while(within)
                .find(|a| is_marker(a) || (self.known.contains(*a) && is_anchored(a)));
            match outer {
                Some(o) => candidate = o.to_path_buf(),
                None => break,
            }
        }
        Ok(candidate)
    }

    /// `cwd` can never belong to a project, whatever is registered: the checks of
    /// [`Self::resolve`] that depend only on the path and the configuration fail with a
    /// [`Unassigned::is_static`] reason.
    pub fn never_a_project(&self, cwd: &str) -> bool {
        matches!(self.locate(Some(cwd)), Err(u) if u.is_static())
    }

    /// The checks that need no project knowledge: a usable, existing, canonical cwd inside a
    /// discovery root, on a path discovery would walk.
    fn locate(&self, cwd: Option<&str>) -> Result<Located<'_>, Unassigned> {
        let cwd = cwd
            .map(Path::new)
            .filter(|p| p.is_absolute())
            .ok_or(Unassigned::NoCwd)?;
        let canonical = std::fs::canonicalize(cwd).map_err(|_| Unassigned::Nonexistent)?;
        if !canonical.is_dir() {
            return Err(Unassigned::Nonexistent);
        }
        if canonical.to_str().is_none() {
            return Err(Unassigned::NoCwd);
        }
        if self.home.starts_with(&canonical) {
            return Err(Unassigned::Home);
        }
        let in_home = canonical.starts_with(&self.home);
        if !in_home && self.temp_dirs.iter().any(|t| canonical.starts_with(t)) {
            return Err(Unassigned::Temporary);
        }
        let (root, ex) = self
            .roots
            .iter()
            .filter(|(r, _)| canonical.starts_with(r))
            .max_by_key(|(r, _)| r.as_os_str().len())
            .ok_or(Unassigned::OutsideRoots)?;
        // Every directory below the root, down to the cwd, must be one discovery would enter:
        // not excluded, not deeper than `max_depth`, on the root's file system (M3 review, L2).
        let rel = canonical.strip_prefix(root).unwrap_or(Path::new(""));
        if ex.is_under_boundary(root) || rel.components().count() > self.max_depth {
            return Err(Unassigned::Excluded);
        }
        let root_dev = std::fs::metadata(root)
            .map_err(|_| Unassigned::Nonexistent)?
            .dev();
        let mut p = root.clone();
        for c in rel.components() {
            p.push(c);
            if ex.exclude_dir(&p, c.as_os_str()).is_some() {
                return Err(Unassigned::Excluded);
            }
            if self.same_file_system
                && std::fs::symlink_metadata(&p).is_ok_and(|m| m.dev() != root_dev)
            {
                return Err(Unassigned::Excluded);
            }
        }
        Ok(Located {
            canonical,
            root,
            exclusions: ex,
            root_dev,
        })
    }

    /// No Git work tree or marker at or above the cwd: the cwd itself, unless projects lie
    /// below it.
    fn session_only(&self, at: &Located<'_>) -> Result<PathBuf, Unassigned> {
        let below = |k: &PathBuf| *k != at.canonical && k.starts_with(&at.canonical);
        if self.known.iter().any(below) || self.project_below(at) {
            return Err(Unassigned::Container);
        }
        Ok(at.canonical.clone())
    }

    /// Is there a Git work tree or a `CLAUDE.md` marker (a regular file, or a symlink resolving
    /// beneath its directory) strictly below `at`, on a path discovery would walk? A preorder
    /// walk by descriptor (open directories bounded by the depth), at most
    /// [`CONTAINER_SCAN_DIRS`] directories; a larger tree counts as "yes".
    fn project_below(&self, at: &Located<'_>) -> bool {
        enum Open {
            Root(DirHandle),
            Child(Rc<DirHandle>, OsString, Identity),
        }
        let base = at
            .canonical
            .strip_prefix(at.root)
            .map_or(0, |r| r.components().count());
        let Ok(first) = DirHandle::open_root(&at.canonical) else {
            return false;
        };
        let mut stack = vec![(Open::Root(first), at.canonical.clone(), base)];
        let mut listed = 0;
        while let Some((open, path, depth)) = stack.pop() {
            listed += 1;
            if listed > CONTAINER_SCAN_DIRS {
                return true;
            }
            let mut dir = match open {
                Open::Root(h) => h,
                Open::Child(parent, name, id) => match parent.open_child(&name, id) {
                    Ok(h) => h,
                    Err(_) => continue,
                },
            };
            let (entries, _) = dir.entries();
            let top = depth == base;
            let mut subdirs = Vec::new();
            for e in entries {
                if !top
                    && (e.name == ".git"
                        || (e.name == MARKER_NAME
                            && match e.kind {
                                Kind::File => true,
                                Kind::Symlink => dir.symlink_resolves_to_file_beneath(&e.name),
                                _ => false,
                            }))
                {
                    return true;
                }
                if let Kind::Dir(id) = e.kind {
                    subdirs.push((e.name, id));
                }
            }
            if depth >= self.max_depth {
                continue;
            }
            let dir = Rc::new(dir);
            for (name, id) in subdirs {
                if name.to_str().is_none() {
                    continue;
                }
                let child = path.join(&name);
                if at.exclusions.exclude_dir(&child, &name).is_some()
                    || (self.same_file_system && id.dev != at.root_dev)
                {
                    continue;
                }
                stack.push((Open::Child(Rc::clone(&dir), name, id), child, depth + 1));
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct T {
        _t: tempfile::TempDir,
        home: PathBuf,
        ctx: Context,
    }

    fn setup(known: &[&str]) -> T {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        let ex = Exclusions::new(
            &home,
            &home,
            &["/private".into()],
            &[home.join(".claude")],
            &[],
        )
        .unwrap();
        let ctx = Context {
            roots: vec![(home.clone(), ex)],
            home: home.clone(),
            temp_dirs: vec![base.join("tmp")],
            known: known.iter().map(|k| home.join(k)).collect(),
            max_depth: 10,
            same_file_system: true,
        };
        T { _t: t, home, ctx }
    }

    fn mk(home: &Path, rel: &str) -> PathBuf {
        let p = home.join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn cwd_resolves_to_the_nearest_git_root_or_marker() {
        let t = setup(&[]);
        let h = &t.home;
        let repo = mk(h, "dev/repo");
        fs::create_dir(repo.join(".git")).unwrap();
        mk(h, "dev/repo/src/deep");
        let pkg = mk(h, "dev/mono/packages/a");
        fs::write(pkg.join("CLAUDE.md"), "x").unwrap();
        fs::create_dir(h.join("dev/mono/.git")).unwrap();
        mk(h, "dev/mono/packages/a/src");
        let plain = mk(h, "scratch/notes");
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(r("dev/repo/src/deep"), Ok(repo.clone()));
        assert_eq!(r("dev/repo"), Ok(repo));
        assert_eq!(
            r("dev/mono/packages/a/src"),
            Ok(pkg),
            "the nearer marker wins"
        );
        assert_eq!(
            r("scratch/notes"),
            Ok(plain),
            "no Git, no marker: the cwd itself"
        );
    }

    #[test]
    fn inside_a_registered_project_only_an_own_git_root_is_separate() {
        let t = setup(&["dev/app"]);
        let h = &t.home;
        let app = mk(h, "dev/app");
        fs::write(app.join("CLAUDE.md"), "app").unwrap();
        let sub = mk(h, "dev/app/tools/gen");
        fs::write(sub.join("CLAUDE.md"), "nested instructions").unwrap();
        let vendored = mk(h, "dev/app/vendor-lib");
        fs::create_dir(vendored.join(".git")).unwrap();
        mk(h, "dev/app/plain/x");
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(
            r("dev/app/tools/gen"),
            Ok(app.clone()),
            "nested marker belongs to app"
        );
        assert_eq!(r("dev/app/plain/x"), Ok(app.clone()));
        assert_eq!(r("dev/app/vendor-lib"), Ok(vendored), "its own work tree");
        // A registered Git project without a marker nests the markers below it as well.
        fs::remove_file(app.join("CLAUDE.md")).unwrap();
        fs::create_dir(app.join(".git")).unwrap();
        assert_eq!(r("dev/app/tools/gen"), Ok(app.clone()));
        // A registered *session-only* project (no Git, no marker) nests nothing (M3 review M4).
        fs::remove_dir(app.join(".git")).unwrap();
        assert_eq!(r("dev/app/tools/gen"), Ok(sub), "app is session-only");
        assert_eq!(r("dev/app/plain/x"), Ok(h.join("dev/app/plain/x")));
    }

    #[test]
    fn home_temporary_missing_outside_and_excluded_cwds_are_unassigned() {
        let t = setup(&[]);
        let h = &t.home;
        fs::create_dir(h.join(".git")).unwrap(); // a dotfiles repository at home
        mk(h, "loose");
        mk(h, ".config/tool");
        mk(h, "private/x");
        mk(h, "proj/node_modules/pkg");
        let base = h.parent().unwrap();
        let tmp = mk(base, "tmp/work");
        let outside = mk(base, "srv/code");
        let r = |p: &Path| t.ctx.resolve(Some(p.to_str().unwrap()));
        assert_eq!(r(h), Err(Unassigned::Home));
        assert_eq!(r(base), Err(Unassigned::Home), "an ancestor of home");
        assert_eq!(
            r(&h.join("loose")),
            Ok(h.join("loose")),
            "home's .git is not its repo"
        );
        assert_eq!(r(&tmp), Err(Unassigned::Temporary));
        assert_eq!(r(&outside), Err(Unassigned::OutsideRoots));
        assert_eq!(r(&h.join("gone")), Err(Unassigned::Nonexistent));
        assert_eq!(r(&h.join(".config/tool")), Err(Unassigned::Excluded));
        assert_eq!(
            r(&h.join("private/x")),
            Err(Unassigned::Excluded),
            "user pattern"
        );
        assert_eq!(
            r(&h.join("proj/node_modules/pkg")),
            Err(Unassigned::Excluded)
        );
        assert_eq!(t.ctx.resolve(None), Err(Unassigned::NoCwd));
        assert_eq!(t.ctx.resolve(Some("relative/dir")), Err(Unassigned::NoCwd));
        let file = h.join("loose/f");
        fs::write(&file, "x").unwrap();
        assert_eq!(r(&file), Err(Unassigned::Nonexistent), "not a directory");
    }

    #[test]
    fn a_symlinked_cwd_resolves_to_its_canonical_project() {
        let t = setup(&[]);
        let h = &t.home;
        let real = mk(h, "dev/real");
        fs::create_dir(real.join(".git")).unwrap();
        std::os::unix::fs::symlink(&real, h.join("dev/alias")).unwrap();
        assert_eq!(
            t.ctx.resolve(Some(h.join("dev/alias").to_str().unwrap())),
            Ok(real)
        );
    }

    #[test]
    fn a_home_inside_a_temporary_directory_still_has_projects() {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let home = base.join("home");
        let p = mk(&home, "dev/p");
        let ctx = Context {
            roots: vec![(
                home.clone(),
                Exclusions::new(&home, &home, &[], &[], &[]).unwrap(),
            )],
            home: home.clone(),
            temp_dirs: vec![base.clone()],
            known: HashSet::new(),
            max_depth: 10,
            same_file_system: true,
        };
        assert_eq!(ctx.resolve(Some(p.to_str().unwrap())), Ok(p));
        for u in [
            Unassigned::Home,
            Unassigned::Excluded,
            Unassigned::NoCwd,
            Unassigned::Container,
        ] {
            assert_eq!(Unassigned::parse(u.as_str()), Some(u));
        }
        assert!(Unassigned::Excluded.is_static() && Unassigned::Home.is_static());
        assert!(!Unassigned::Nonexistent.is_static() && !Unassigned::Container.is_static());
    }

    /// The synthetic `dev/monorepo` layout: a Git work tree with a `CLAUDE.md`, and
    /// `services/api` with its own `CLAUDE.md` but no Git work tree. A session there belongs to
    /// the monorepo whether or not the monorepo is registered yet (first launch: sessions are
    /// resolved before the marker scan).
    #[test]
    fn a_session_in_a_nested_marker_folder_resolves_to_the_outer_marker_project() {
        for known in [&[][..], &["dev/monorepo"][..]] {
            let t = setup(known);
            let h = &t.home;
            let mono = mk(h, "dev/monorepo");
            fs::create_dir(mono.join(".git")).unwrap();
            fs::write(mono.join("CLAUDE.md"), "x").unwrap();
            let api = mk(h, "dev/monorepo/services/api");
            fs::write(api.join("CLAUDE.md"), "x").unwrap();
            mk(h, "dev/monorepo/services/api/src");
            let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
            assert_eq!(
                r("dev/monorepo/services/api"),
                Ok(mono.clone()),
                "{known:?}"
            );
            assert_eq!(r("dev/monorepo/services/api/src"), Ok(mono.clone()));
            assert_eq!(r("dev/monorepo/services"), Ok(mono));
        }
        // Chained: an outer marker, a nested marker without Git inside a nested Git project.
        let t = setup(&[]);
        let h = &t.home;
        fs::write(mk(h, "a").join("CLAUDE.md"), "x").unwrap();
        let c = mk(h, "a/b/c");
        fs::create_dir(c.join(".git")).unwrap();
        fs::write(c.join("CLAUDE.md"), "x").unwrap();
        fs::write(mk(h, "a/b/c/d").join("CLAUDE.md"), "x").unwrap();
        // A Git work tree without a marker inside a marker project is no project (as in the
        // marker scan), so its nested marker belongs to the outer one.
        fs::create_dir(mk(h, "a/g").join(".git")).unwrap();
        fs::write(mk(h, "a/g/h").join("CLAUDE.md"), "x").unwrap();
        fs::write(mk(h, "a/m").join("CLAUDE.md"), "x").unwrap();
        fs::write(mk(h, "a/m/n").join("CLAUDE.md"), "x").unwrap();
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(
            r("a/b/c/d"),
            Ok(c),
            "the nearest enclosing project with Git"
        );
        assert_eq!(
            r("a/m/n"),
            Ok(h.join("a")),
            "markers chain up to the outermost"
        );
        assert_eq!(r("a/g/h"), Ok(h.join("a")));
    }

    /// M3 review M4: a session in a parent folder without Git or marker (`~/dev`) never becomes
    /// an umbrella project, whichever is seen first.
    #[test]
    fn a_session_only_container_folder_is_unassigned_in_either_order() {
        let layout = |h: &Path| {
            fs::write(mk(h, "dev/app-a").join("CLAUDE.md"), "x").unwrap();
            fs::write(mk(h, "dev/app-b").join("CLAUDE.md"), "x").unwrap();
            mk(h, "dev/app-b/src");
            mk(h, "dev/app-c/src");
        };
        // Umbrella first: nothing registered yet, the markers are only on disk.
        let t = setup(&[]);
        let h = &t.home;
        layout(h);
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(r("dev"), Err(Unassigned::Container));
        assert_eq!(r("dev/app-b/src"), Ok(h.join("dev/app-b")));
        assert_eq!(
            r("dev/app-c/src"),
            Ok(h.join("dev/app-c/src")),
            "a plain folder with nothing below is a session-only project"
        );
        // Projects first: registered marker projects below.
        let t = setup(&["dev/app-a"]);
        layout(&t.home);
        assert_eq!(
            t.ctx.resolve(Some(t.home.join("dev").to_str().unwrap())),
            Err(Unassigned::Container)
        );
        // A session-only project registered by an older ccwm absorbs nothing.
        let t = setup(&["dev"]);
        let h = &t.home;
        layout(h);
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(r("dev/app-b/src"), Ok(h.join("dev/app-b")));
        assert_eq!(r("dev/app-c/src"), Ok(h.join("dev/app-c/src")));
        // A registered session-only project below makes a container too.
        let t = setup(&["notes/2026"]);
        mk(&t.home, "notes/2026");
        assert_eq!(
            t.ctx.resolve(Some(t.home.join("notes").to_str().unwrap())),
            Err(Unassigned::Container)
        );
    }

    #[test]
    fn the_container_check_sees_git_trees_but_not_excluded_folders_and_is_bounded() {
        let t = setup(&[]);
        let h = &t.home;
        mk(h, "work/node_modules/pkg");
        fs::write(h.join("work/node_modules/pkg/CLAUDE.md"), "x").unwrap();
        mk(h, "work/.hidden/.git");
        mk(h, "work/lib/repo/.git");
        let r = |rel: &str| t.ctx.resolve(Some(h.join(rel).to_str().unwrap()));
        assert_eq!(
            r("work"),
            Err(Unassigned::Container),
            "a Git work tree below"
        );
        fs::remove_dir(h.join("work/lib/repo/.git")).unwrap();
        assert_eq!(
            r("work"),
            Ok(h.join("work")),
            "excluded folders do not count"
        );
        let deep = mk(h, "plain");
        for i in 0..=CONTAINER_SCAN_DIRS {
            fs::create_dir(deep.join(format!("d{i}"))).unwrap();
        }
        assert_eq!(
            r("plain"),
            Err(Unassigned::Container),
            "a tree larger than the budget counts as a container"
        );
        assert!(!t.ctx.never_a_project(h.join("plain").to_str().unwrap()));
    }

    /// M3 review L2: a cwd discovery would not walk to (too deep, another file system).
    #[test]
    fn too_deep_and_other_file_system_cwds_are_excluded() {
        let mut t = setup(&[]);
        let h = t.home.clone();
        let deep = mk(&h, "a/b/c/d");
        t.ctx.max_depth = 3;
        assert_eq!(
            t.ctx.resolve(Some(deep.to_str().unwrap())),
            Err(Unassigned::Excluded)
        );
        assert!(t.ctx.never_a_project(deep.to_str().unwrap()));
        assert_eq!(
            t.ctx.resolve(Some(h.join("a/b/c").to_str().unwrap())),
            Ok(h.join("a/b/c"))
        );
        // Another file system below the root: `/dev/shm` (tmpfs) under a root of `/`.
        let shm = Path::new("/dev/shm");
        let (Ok(root_md), Ok(shm_md)) = (fs::metadata("/"), fs::metadata(shm)) else {
            eprintln!("NOTICE: /dev/shm unavailable; skipping the same_file_system check");
            return;
        };
        if root_md.dev() == shm_md.dev() {
            eprintln!("NOTICE: /dev/shm is on the root file system; skipping");
            return;
        }
        let Ok(dir) = tempfile::Builder::new().prefix("ccwm-").tempdir_in(shm) else {
            eprintln!("NOTICE: /dev/shm not writable; skipping");
            return;
        };
        let cwd = fs::canonicalize(dir.path()).unwrap();
        let mut ctx = Context {
            roots: vec![(
                PathBuf::from("/"),
                Exclusions::new(Path::new("/"), &h, &[], &[], &[]).unwrap(),
            )],
            home: h.clone(),
            temp_dirs: vec![],
            known: HashSet::new(),
            max_depth: 10,
            same_file_system: true,
        };
        assert_eq!(
            ctx.resolve(Some(cwd.to_str().unwrap())),
            Err(Unassigned::Excluded)
        );
        ctx.same_file_system = false;
        assert_eq!(ctx.resolve(Some(cwd.to_str().unwrap())), Ok(cwd));
    }
}
