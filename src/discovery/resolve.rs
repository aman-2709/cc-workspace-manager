//! Session cwd → project root (REQUIREMENTS.md §4.3, §4.4). Sessions are the primary discovery
//! source: a recorded working directory becomes a project at the nearest enclosing directory that
//! is a Git work-tree root or holds a `CLAUDE.md` (never crossing the discovery root, never the
//! home directory), or the cwd itself if there is none. The home directory, temporary
//! directories, cwds that no longer exist and cwds outside the allowed roots are never projects;
//! they are counted as *unassigned* sessions.
//!
//! Only metadata is read (`canonicalize`, `lstat` of `.git` / `CLAUDE.md`). Never derived from
//! Claude Code's directory names.

use super::exclusions::Exclusions;
use super::walk::MARKER_NAME;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

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
    /// Below an excluded directory or a hard boundary.
    Excluded,
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
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::NoCwd,
            Self::Nonexistent,
            Self::Home,
            Self::Temporary,
            Self::OutsideRoots,
            Self::Excluded,
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
}

fn has_entry(dir: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(dir.join(name)).is_ok()
}

fn is_marker(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(MARKER_NAME))
        .is_ok_and(|m| m.is_file() || m.file_type().is_symlink())
}

impl Context {
    /// The project root for a session whose first recorded cwd is `cwd`.
    pub fn resolve(&self, cwd: Option<&str>) -> Result<PathBuf, Unassigned> {
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
        // Every directory below the root, down to the cwd, must be one discovery would enter.
        let rel = canonical.strip_prefix(root).unwrap_or(Path::new(""));
        let mut p = root.clone();
        if ex.is_under_boundary(&p) {
            return Err(Unassigned::Excluded);
        }
        for c in rel.components() {
            p.push(c);
            if ex.exclude_dir(&p, c.as_os_str()).is_some() {
                return Err(Unassigned::Excluded);
            }
        }
        // Nearest Git work-tree root or marker directory at or above the cwd, within the root and
        // below the home directory (a dotfiles repository at home is not the project's).
        let candidate = canonical
            .ancestors()
            .take_while(|a| a.starts_with(root) && *a != self.home.as_path())
            .find(|a| self.known.contains(*a) || has_entry(a, ".git") || is_marker(a))
            .unwrap_or(&canonical)
            .to_path_buf();
        // Nested rule (§4.4): inside a registered project, a directory is a separate project only
        // with its own Git work tree.
        if !self.known.contains(&candidate) && !has_entry(&candidate, ".git") {
            if let Some(outer) = candidate
                .ancestors()
                .skip(1)
                .find(|a| self.known.contains(*a))
            {
                return Ok(outer.to_path_buf());
            }
        }
        Ok(candidate)
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
        assert_eq!(r("dev/app/plain/x"), Ok(app));
        assert_eq!(r("dev/app/vendor-lib"), Ok(vendored), "its own work tree");
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
        };
        assert_eq!(ctx.resolve(Some(p.to_str().unwrap())), Ok(p));
        for u in [Unassigned::Home, Unassigned::Excluded, Unassigned::NoCwd] {
            assert_eq!(Unassigned::parse(u.as_str()), Some(u));
        }
    }
}
