//! Which directories discovery refuses to enter (REQUIREMENTS.md §4.1/§4.2). Pure functions so the
//! rules are testable without a filesystem.

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Directory names skipped everywhere (in addition to hidden `.*` directories).
pub const DEFAULT_EXCLUDED_NAMES: [&str; 8] = [
    "node_modules",
    "target",
    "build",
    "_build",
    "dist",
    "venv",
    "__pycache__",
    "VirtualBox VMs",
];
/// Skipped only when directly under the home directory.
pub const HOME_ONLY_EXCLUDED: [&str; 1] = ["snap"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Hidden,
    DefaultName,
    UserPattern,
    FuseMount,
    HardBoundary,
}

/// Check user patterns once, at configuration time, so a typo is a startup error and not a silently
/// unusable root.
pub fn validate_patterns(patterns: &[String]) -> Result<(), String> {
    Exclusions::new(Path::new("/"), Path::new("/"), patterns, &[], &[]).map(|_| ())
}

#[derive(Clone)]
pub struct Exclusions {
    root: PathBuf,
    home: PathBuf,
    user: Gitignore,
    boundaries: Vec<PathBuf>,
    fuse_mounts: Vec<PathBuf>,
}

impl Exclusions {
    /// Invalid user patterns are returned as errors (strings) so the caller can report them.
    pub fn new(
        root: &Path,
        home: &Path,
        patterns: &[String],
        boundaries: &[PathBuf],
        fuse_mounts: &[PathBuf],
    ) -> Result<Self, String> {
        let mut builder = GitignoreBuilder::new(root);
        for p in patterns {
            builder
                .add_line(None, p)
                .map_err(|e| format!("invalid exclude pattern {p:?}: {e}"))?;
        }
        let user = builder
            .build()
            .map_err(|e| format!("invalid exclude patterns: {e}"))?;
        Ok(Self {
            root: root.to_path_buf(),
            home: home.to_path_buf(),
            user,
            boundaries: boundaries.to_vec(),
            fuse_mounts: fuse_mounts.to_vec(),
        })
    }

    pub fn is_under_boundary(&self, path: &Path) -> bool {
        self.boundaries
            .iter()
            .any(|b| path == b || path.starts_with(b))
    }

    /// Should the directory `path` (named `name`, a child of the walk) be pruned?
    pub fn exclude_dir(&self, path: &Path, name: &OsStr) -> Option<Reason> {
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            return Some(Reason::Hidden);
        }
        if self.is_under_boundary(path) {
            return Some(Reason::HardBoundary);
        }
        if DEFAULT_EXCLUDED_NAMES.contains(&name_str.as_ref())
            || (path.parent() == Some(self.home.as_path())
                && HOME_ONLY_EXCLUDED.contains(&name_str.as_ref()))
        {
            return Some(Reason::DefaultName);
        }
        if path != self.root && self.fuse_mounts.iter().any(|m| m == path) {
            return Some(Reason::FuseMount);
        }
        if self.user.matched(path, true).is_ignore() {
            return Some(Reason::UserPattern);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(patterns: &[&str]) -> Exclusions {
        let pats: Vec<String> = patterns.iter().map(ToString::to_string).collect();
        Exclusions::new(
            Path::new("/home/u"),
            Path::new("/home/u"),
            &pats,
            &[
                PathBuf::from("/proc"),
                PathBuf::from("/home/u/.local/share/ccwm"),
            ],
            &[PathBuf::from("/home/u/gdrive")],
        )
        .unwrap()
    }

    fn check(e: &Exclusions, p: &str) -> Option<Reason> {
        let path = Path::new(p);
        e.exclude_dir(path, path.file_name().unwrap())
    }

    #[test]
    fn hidden_and_default_names() {
        let e = ex(&[]);
        assert_eq!(check(&e, "/home/u/.cache"), Some(Reason::Hidden));
        assert_eq!(check(&e, "/home/u/p/.git"), Some(Reason::Hidden));
        for n in DEFAULT_EXCLUDED_NAMES {
            assert_eq!(
                check(&e, &format!("/home/u/p/{n}")),
                Some(Reason::DefaultName),
                "{n}"
            );
        }
        assert_eq!(check(&e, "/home/u/p/src"), None);
        assert_eq!(
            check(&e, "/home/u/p/Target"),
            None,
            "names are case-sensitive"
        );
    }

    #[test]
    fn snap_is_excluded_only_directly_under_home() {
        let e = ex(&[]);
        assert_eq!(check(&e, "/home/u/snap"), Some(Reason::DefaultName));
        assert_eq!(check(&e, "/home/u/p/snap"), None);
    }

    #[test]
    fn hard_boundaries_win() {
        let e = ex(&[]);
        assert_eq!(check(&e, "/proc"), Some(Reason::HardBoundary));
        assert_eq!(check(&e, "/proc/1/fd"), Some(Reason::HardBoundary));
        assert_eq!(
            check(&e, "/home/u/.local/share/ccwm/sub"),
            Some(Reason::HardBoundary)
        );
        assert!(e.is_under_boundary(Path::new("/proc")));
        assert!(!e.is_under_boundary(Path::new("/procfoo")));
    }

    #[test]
    fn fuse_mount_points_are_pruned_but_not_the_root() {
        let e = ex(&[]);
        assert_eq!(check(&e, "/home/u/gdrive"), Some(Reason::FuseMount));
        let as_root = Exclusions::new(
            Path::new("/home/u/gdrive"),
            Path::new("/home/u"),
            &[],
            &[],
            &[PathBuf::from("/home/u/gdrive")],
        )
        .unwrap();
        assert_eq!(
            as_root.exclude_dir(Path::new("/home/u/gdrive"), OsStr::new("gdrive")),
            None
        );
    }

    #[test]
    fn user_patterns_use_gitignore_syntax_relative_to_the_root() {
        let e = ex(&["vendor/", "/archive", "!keep", "tmp-*"]);
        assert_eq!(check(&e, "/home/u/p/vendor"), Some(Reason::UserPattern));
        assert_eq!(check(&e, "/home/u/archive"), Some(Reason::UserPattern));
        assert_eq!(check(&e, "/home/u/p/archive"), None, "anchored pattern");
        assert_eq!(check(&e, "/home/u/tmp-1"), Some(Reason::UserPattern));
        assert_eq!(check(&e, "/home/u/keep"), None);
    }

    #[test]
    fn invalid_pattern_is_reported() {
        let r = Exclusions::new(
            Path::new("/r"),
            Path::new("/h"),
            &["a\\".to_string()],
            &[],
            &[],
        );
        assert!(r.is_err());
    }
}
