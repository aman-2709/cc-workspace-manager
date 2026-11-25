//! Where the sessions are (REQUIREMENTS.md §7.1): only top-level
//! `<config dir>/projects/<encoded-dir>/<session-uuid>.jsonl` files are sessions. Subagent
//! transcripts (`<uuid>/subagents/…`), tool-result spills, memory files and everything else are
//! skipped and counted. Directories are opened by descriptor ([`DirHandle`]), files with
//! `O_NOFOLLOW`; nothing is ever written. Directory names are never decoded into paths.

use super::resume::is_uuid;
use crate::discovery::dirfd::{DirHandle, Kind};
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};

/// The sessions directory inside Claude Code's config directory.
pub const PROJECTS_DIR: &str = "projects";
/// Every listing stops after this many session files (far above the 819 seen on the
/// maintainer's machine); the rest is counted as skipped.
pub const MAX_FILES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFile {
    /// The file stem (a UUID, lower case).
    pub id: String,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Listing {
    pub files: Vec<SessionFile>,
    /// The `<encoded-dir>` directories that were listed completely (watch targets; files that
    /// disappeared from them are gone).
    pub dirs: Vec<PathBuf>,
    /// Entries that are not top-level session files (subagent directories, memory, aliases…).
    pub skipped: u64,
    /// Directories that could not be read.
    pub errors: u64,
}

/// `<name>.jsonl` with a UUID stem.
pub fn session_id_of(name: &OsStr) -> Option<String> {
    let stem = name.to_str()?.strip_suffix(".jsonl")?;
    is_uuid(stem).then(|| stem.to_ascii_lowercase())
}

/// List one `<encoded-dir>` (opened from `parent` by name, or as a root).
fn list_dir(dir: &mut DirHandle, path: &Path, out: &mut Listing) {
    let (entries, errors) = dir.entries();
    if !errors.is_empty() {
        out.errors += 1;
        return;
    }
    for e in entries {
        match (e.kind, session_id_of(&e.name)) {
            (Kind::File, Some(id)) if out.files.len() < MAX_FILES => out.files.push(SessionFile {
                id,
                path: path.join(&e.name),
            }),
            _ => out.skipped += 1,
        }
    }
    out.dirs.push(path.to_path_buf());
}

/// List every session under `projects` (`<config dir>/projects`, canonical). `None` if the
/// directory does not exist or cannot be opened.
pub fn list_all(projects: &Path) -> Option<Listing> {
    let mut root = DirHandle::open_root(projects).ok()?;
    let mut out = Listing::default();
    let (entries, errors) = root.entries();
    out.errors += u64::try_from(errors.len()).unwrap_or(u64::MAX);
    for e in entries {
        let Kind::Dir(id) = e.kind else {
            out.skipped += 1;
            continue;
        };
        let Some(name) = e.name.to_str().filter(|n| !n.starts_with('.')) else {
            out.skipped += 1;
            continue;
        };
        match root.open_child(&e.name, id) {
            Ok(mut dir) => list_dir(&mut dir, &projects.join(name), &mut out),
            Err(_) => out.errors += 1,
        }
    }
    Some(out)
}

/// List only the `<encoded-dir>` directories in `dirs` (each must be a direct child of
/// `projects`); directories that no longer exist are simply absent from `Listing::dirs`.
pub fn list_some(projects: &Path, dirs: &[PathBuf]) -> Listing {
    let mut out = Listing::default();
    for d in dirs {
        if d.parent() != Some(projects) {
            continue;
        }
        if let Ok(mut h) = DirHandle::open_root(d) {
            list_dir(&mut h, d, &mut out);
        }
    }
    out
}

/// Open a listed session file (never through a symlink).
pub fn open(file: &SessionFile) -> Option<File> {
    let parent = DirHandle::open_root(file.path.parent()?).ok()?;
    parent.open_regular(file.path.file_name()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const A: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const B: &str = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    #[test]
    fn only_top_level_uuid_jsonl_files_are_sessions() {
        let t = tempfile::tempdir().unwrap();
        let projects = fs::canonicalize(t.path()).unwrap().join(PROJECTS_DIR);
        let enc = projects.join("-home-u-dev-x");
        fs::create_dir_all(enc.join(format!("{A}/subagents"))).unwrap();
        fs::write(enc.join(format!("{A}.jsonl")), "{}\n").unwrap();
        fs::write(enc.join(format!("{A}/subagents/agent-abc.jsonl")), "{}\n").unwrap();
        fs::write(enc.join(".session-aliases"), "x").unwrap();
        fs::create_dir_all(enc.join("memory")).unwrap();
        fs::write(enc.join("notes.jsonl"), "{}\n").unwrap();
        std::os::unix::fs::symlink(
            enc.join(format!("{A}.jsonl")),
            enc.join(format!("{B}.jsonl")),
        )
        .unwrap();
        fs::create_dir_all(projects.join(".hidden")).unwrap();
        fs::write(projects.join("stray.jsonl"), "{}\n").unwrap();
        let l = list_all(&projects).unwrap();
        assert_eq!(
            l.files,
            [SessionFile {
                id: A.into(),
                path: enc.join(format!("{A}.jsonl"))
            }],
            "the symlinked {B}.jsonl is not a regular file"
        );
        assert_eq!(l.dirs, std::slice::from_ref(&enc));
        assert_eq!(
            l.skipped, 7,
            "subagent dir, aliases, memory, notes, symlink, hidden dir, stray file"
        );
        assert!(open(&l.files[0]).is_some());
        assert!(list_all(&projects.join("none")).is_none());
        let some = list_some(
            &projects,
            &[enc.clone(), projects.join("gone"), PathBuf::from("/etc")],
        );
        assert_eq!(some.files.len(), 1);
        assert_eq!(some.dirs, [enc]);
    }

    #[test]
    fn session_ids_come_only_from_uuid_stems() {
        assert_eq!(
            session_id_of(OsStr::new(&format!("{}.jsonl", A.to_uppercase()))).as_deref(),
            Some(A)
        );
        for bad in [
            "x.jsonl",
            "agent-123.jsonl",
            &format!("{A}.json"),
            &format!("{A}.jsonl.bak"),
        ] {
            assert!(session_id_of(OsStr::new(bad)).is_none(), "{bad}");
        }
    }
}
