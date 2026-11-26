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
/// maintainer's machine); the rest is counted as skipped and the directories it was in are
/// marked ([`Listing::cut`]).
pub const MAX_FILES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFile {
    /// The file stem (a lower-case UUID).
    pub id: String,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Listing {
    pub files: Vec<SessionFile>,
    /// The `<encoded-dir>` directories that were listed completely (watch targets; files that
    /// disappeared from them are gone).
    pub dirs: Vec<PathBuf>,
    /// Entries that are not top-level session files (subagent directories, memory, aliases…),
    /// and session files beyond [`MAX_FILES`].
    pub skipped: u64,
    /// Directories that could not be read.
    pub errors: u64,
    /// The directories of `dirs` in which the listing reached [`MAX_FILES`]: they hold session
    /// files that are not in `files`, so a file absent from them is **not** known to be gone
    /// (v0.1.0 review I8: the sessions the limit dropped used to be deleted from the index as
    /// gone). The other directories were listed completely, also in a listing that was cut
    /// off elsewhere (v0.1.1 review I2).
    pub cut: Vec<PathBuf>,
}

impl Listing {
    /// The listing stopped at [`MAX_FILES`]: session files exist that are not in `files`.
    pub fn truncated(&self) -> bool {
        !self.cut.is_empty()
    }
}

/// `<name>.jsonl` with a lower-case UUID stem. Claude Code writes lower case; other spellings are
/// not sessions (folding them would let two files share one id, M3 review L4).
pub fn session_id_of(name: &OsStr) -> Option<String> {
    let stem = name.to_str()?.strip_suffix(".jsonl")?;
    (is_uuid(stem) && !stem.bytes().any(|b| b.is_ascii_uppercase())).then(|| stem.to_string())
}

/// Keep one file per session id (the same `<uuid>.jsonl` copied into a second
/// `<encoded-dir>`, a common manual fix after moving a project): the file the index already
/// holds for that id (`indexed`) wins, otherwise the first by path. Returns how many files were
/// dropped (counted as duplicates).
pub fn dedupe(files: &mut Vec<SessionFile>, indexed: impl Fn(&str) -> Option<PathBuf>) -> u64 {
    files.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.path.cmp(&b.path)));
    let before = files.len();
    let mut keep: Vec<SessionFile> = Vec::with_capacity(before);
    let mut i = 0;
    while i < files.len() {
        let j = i + files[i..]
            .iter()
            .take_while(|f| f.id == files[i].id)
            .count();
        let group = &files[i..j];
        let chosen = indexed(&group[0].id)
            .and_then(|p| group.iter().find(|f| f.path == p))
            .unwrap_or(&group[0]);
        keep.push(chosen.clone());
        i = j;
    }
    *files = keep;
    (before - files.len()) as u64
}

/// List one `<encoded-dir>` (opened from `parent` by name, or as a root); at most `max_files`
/// session files in the whole listing.
fn list_dir(dir: &mut DirHandle, path: &Path, out: &mut Listing, max_files: usize) {
    let (entries, errors) = dir.entries();
    if !errors.is_empty() {
        out.errors += 1;
        return;
    }
    let mut cut = false;
    for e in entries {
        match (e.kind, session_id_of(&e.name)) {
            (Kind::File, Some(id)) if out.files.len() < max_files => out.files.push(SessionFile {
                id,
                path: path.join(&e.name),
            }),
            (Kind::File, Some(_)) => {
                cut = true;
                out.skipped += 1;
            }
            _ => out.skipped += 1,
        }
    }
    out.dirs.push(path.to_path_buf());
    if cut {
        out.cut.push(path.to_path_buf());
    }
}

/// List every session under `projects` (`<config dir>/projects`, canonical). `None` if the
/// directory does not exist or cannot be opened.
pub fn list_all(projects: &Path) -> Option<Listing> {
    list_all_capped(projects, MAX_FILES)
}

/// [`list_all`] with another limit than [`MAX_FILES`] (tests: the real limit is far out of reach).
pub fn list_all_capped(projects: &Path, max_files: usize) -> Option<Listing> {
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
            Ok(mut dir) => list_dir(&mut dir, &projects.join(name), &mut out, max_files),
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
            list_dir(&mut h, d, &mut out, MAX_FILES);
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

    /// v0.1.0 review I8: a listing that stopped at the file limit says so, and counts what it
    /// left out; one that fits does not.
    #[test]
    fn a_listing_cut_off_at_the_file_limit_is_marked_truncated() {
        let t = tempfile::tempdir().unwrap();
        let projects = fs::canonicalize(t.path()).unwrap().join(PROJECTS_DIR);
        for (dir, id) in [
            ("-a", A),
            ("-b", B),
            ("-b", "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        ] {
            fs::create_dir_all(projects.join(dir)).unwrap();
            fs::write(projects.join(dir).join(format!("{id}.jsonl")), "{}\n").unwrap();
        }
        fs::write(projects.join("-b/notes.txt"), "x").unwrap();
        let all = list_all_capped(&projects, 3).unwrap();
        assert_eq!(
            (all.files.len(), all.skipped, all.truncated()),
            (3, 1, false)
        );
        let cut = list_all_capped(&projects, 2).unwrap();
        assert_eq!(
            (cut.files.len(), cut.skipped, cut.truncated()),
            (2, 2, true)
        );
        assert_eq!(
            cut.dirs.len(),
            2,
            "both directories are still watch targets"
        );
        // v0.1.1 review I2: only the directory the limit was reached in is marked; the one
        // before it was listed completely.
        let order: Vec<&Path> = cut.dirs.iter().map(PathBuf::as_path).collect();
        assert_eq!(cut.cut.len(), 1, "{order:?}");
        assert_eq!(cut.cut[0], *order[1], "the second directory listed");
        let none = list_all_capped(&projects, 0).unwrap();
        assert_eq!(
            (none.files.len(), none.skipped, none.truncated()),
            (0, 4, true)
        );
        assert_eq!(none.cut.len(), 2, "every directory with a session file");
        assert!(!list_all(&projects).unwrap().truncated());

        // In a fixed order (a listing follows the order of the directory's entries): a
        // directory listed after the limit was reached is still complete when the limit left
        // nothing of it out.
        fs::create_dir_all(projects.join("-empty")).unwrap();
        let mut out = Listing::default();
        for d in ["-b", "-empty"] {
            let dir = projects.join(d);
            list_dir(&mut DirHandle::open_root(&dir).unwrap(), &dir, &mut out, 1);
        }
        assert_eq!(out.cut, [projects.join("-b")]);
        assert_eq!(out.dirs, [projects.join("-b"), projects.join("-empty")]);
    }

    #[test]
    fn session_ids_come_only_from_lower_case_uuid_stems() {
        assert_eq!(
            session_id_of(OsStr::new(&format!("{A}.jsonl"))).as_deref(),
            Some(A)
        );
        let mixed = format!("{}{}.jsonl", &A[..1].to_uppercase(), &A[1..]);
        for bad in [
            format!("{}.jsonl", A.to_uppercase()).as_str(),
            mixed.as_str(),
            "x.jsonl",
            "agent-123.jsonl",
            &format!("{A}.json"),
            &format!("{A}.jsonl.bak"),
        ] {
            assert!(session_id_of(OsStr::new(bad)).is_none(), "{bad}");
        }
    }

    #[test]
    fn one_file_per_session_id_the_indexed_one_first() {
        let f = |dir: &str, id: &str| SessionFile {
            id: id.into(),
            path: PathBuf::from(format!("/p/{dir}/{id}.jsonl")),
        };
        let all = vec![f("b", A), f("a", A), f("c", B), f("c", A)];
        let mut files = all.clone();
        assert_eq!(dedupe(&mut files, |_| None), 2);
        assert_eq!(files, [f("a", A), f("c", B)], "first by path");
        let mut files = all.clone();
        let indexed = f("c", A).path;
        assert_eq!(
            dedupe(&mut files, |id| (id == A).then(|| indexed.clone())),
            2
        );
        assert_eq!(files, [f("c", A), f("c", B)], "the indexed file wins");
        let mut files = all;
        assert_eq!(
            dedupe(&mut files, |_| Some(PathBuf::from("/gone.jsonl"))),
            2,
            "an indexed file that is gone: first by path"
        );
        assert_eq!(files[0], f("a", A));
    }
}
