//! Race-free directory access for the discovery walk (M1.1, finding M3).
//!
//! Path-based walking (`read_dir(path)` after classifying the entry) lets another user swap a
//! directory for a symlink between the two steps. Here every directory is opened **relative to its
//! parent's descriptor** with `O_DIRECTORY | O_NOFOLLOW` and accepted only if `fstat` shows the same
//! `(device, inode)` that the parent's listing showed; its entries are then read from that very
//! descriptor. A symlinked `CLAUDE.md` is resolved with `openat2(RESOLVE_BENEATH)` relative to the
//! directory's descriptor, so it can never point outside the directory, whatever is renamed
//! concurrently. Nothing here reads file contents or writes anything.

use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::{openat, openat2, readlinkat, OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode, SFlag};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

/// Which file a directory entry is: `(st_dev, st_ino)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
}

impl Identity {
    fn of(st: &FileStat) -> Self {
        Self {
            dev: st.st_dev,
            ino: st.st_ino,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir(Identity),
    File,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: OsString,
    pub kind: Kind,
}

#[derive(Debug)]
pub enum OpenError {
    /// The name no longer refers to the directory that was listed (a symlink or another
    /// directory was swapped in): skipped, never followed.
    Replaced,
    Io(io::Error),
}

impl From<Errno> for OpenError {
    fn from(e: Errno) -> Self {
        match e {
            // O_NOFOLLOW on a symlink, or O_DIRECTORY on something that is not a directory.
            Errno::ELOOP | Errno::ENOTDIR => Self::Replaced,
            other => Self::Io(io::Error::from(other)),
        }
    }
}

/// Bytes of a `CLAUDE.md` read for its content hash (§4.1: bounded marker reads).
pub const MAX_MARKER_BYTES: u64 = 256 * 1024;

fn is(st: &FileStat, kind: SFlag) -> bool {
    SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == kind
}

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// An open directory and its identity.
pub struct DirHandle {
    dir: Dir,
    id: Identity,
}

impl DirHandle {
    fn from_fd(fd: OwnedFd, expected: Identity) -> Result<Self, OpenError> {
        let st = fstat(&fd).map_err(OpenError::from)?;
        if !is(&st, SFlag::S_IFDIR) || Identity::of(&st) != expected {
            return Err(OpenError::Replaced);
        }
        Ok(Self {
            dir: Dir::from_fd(fd).map_err(OpenError::from)?,
            id: expected,
        })
    }

    /// Open a walk root. `path` must already be canonical (no symlink components); the final
    /// component is opened with `O_NOFOLLOW` and must be the directory `stat` saw just before.
    pub fn open_root(path: &Path) -> Result<Self, OpenError> {
        let expected = std::fs::metadata(path).map_err(OpenError::Io)?;
        use std::os::unix::fs::MetadataExt;
        let expected = Identity {
            dev: expected.dev(),
            ino: expected.ino(),
        };
        let fd = nix::fcntl::open(path, DIR_FLAGS, Mode::empty()).map_err(OpenError::from)?;
        Self::from_fd(fd, expected)
    }

    /// Open the sub-directory `name` relative to this directory; it must be `expected`.
    pub fn open_child(&self, name: &OsStr, expected: Identity) -> Result<Self, OpenError> {
        let fd =
            openat(self.dir.as_fd(), name, DIR_FLAGS, Mode::empty()).map_err(OpenError::from)?;
        Self::from_fd(fd, expected)
    }

    /// Open the real sub-directory `name` (never a symlink), whatever its identity.
    pub fn open_child_dir(&self, name: &OsStr) -> Option<Self> {
        let fd = openat(self.dir.as_fd(), name, DIR_FLAGS, Mode::empty()).ok()?;
        let st = fstat(&fd).ok()?;
        Self::from_fd(fd, Identity::of(&st)).ok()
    }

    pub fn identity(&self) -> Identity {
        self.id
    }

    /// List the entries (without `.` and `..`), classified without following symlinks.
    /// Entries that vanish between listing and classification come back as errors.
    pub fn entries(&mut self) -> (Vec<Entry>, Vec<io::Error>) {
        let mut raw: Vec<(OsString, Option<Type>)> = Vec::new();
        let mut errors = Vec::new();
        for item in self.dir.iter() {
            match item {
                Ok(e) => {
                    let name = OsStr::from_bytes(e.file_name().to_bytes());
                    if name != "." && name != ".." {
                        raw.push((name.to_os_string(), e.file_type()));
                    }
                }
                Err(e) => errors.push(io::Error::from(e)),
            }
        }
        let mut out = Vec::with_capacity(raw.len());
        for (name, d_type) in raw {
            let kind = match d_type {
                Some(Type::File) => Ok(Kind::File),
                Some(Type::Symlink) => Ok(Kind::Symlink),
                Some(Type::Directory) | None => self.classify(&name),
                Some(_) => Ok(Kind::Other),
            };
            match kind {
                Ok(kind) => out.push(Entry { name, kind }),
                Err(e) => errors.push(e),
            }
        }
        (out, errors)
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)`: directories need their identity, unknown types a kind.
    fn classify(&self, name: &OsStr) -> io::Result<Kind> {
        let st = fstatat(
            self.dir.as_fd(),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        Ok(if is(&st, SFlag::S_IFDIR) {
            Kind::Dir(Identity::of(&st))
        } else if is(&st, SFlag::S_IFREG) {
            Kind::File
        } else if is(&st, SFlag::S_IFLNK) {
            Kind::Symlink
        } else {
            Kind::Other
        })
    }

    /// A symlinked marker counts only if it resolves to a regular file **beneath** this directory.
    /// Opened with `O_PATH` (no content read, no blocking on FIFOs).
    pub fn symlink_resolves_to_file_beneath(&self, name: &OsStr) -> bool {
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        match openat2(self.dir.as_fd(), name, how) {
            Ok(fd) => fstat(&fd).is_ok_and(|st| is(&st, SFlag::S_IFREG)),
            // openat2 needs Linux 5.6; seccomp filters may also refuse it.
            Err(Errno::ENOSYS | Errno::EPERM) => self.symlink_beneath_fallback(name),
            Err(_) => false,
        }
    }

    /// Read at most `max` bytes of the regular file `name`; also returns its full size. With
    /// `beneath`, a symlink is followed only if it resolves inside this directory
    /// (`RESOLVE_BENEATH`; `None` without `openat2`); otherwise symlinks are never followed.
    /// FIFOs, devices and directories are never read.
    pub fn read_regular(&self, name: &OsStr, beneath: bool, max: u64) -> Option<(Vec<u8>, u64)> {
        use std::io::Read;
        let flags = OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let fd = if beneath {
            let how = OpenHow::new()
                .flags(flags)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);
            openat2(self.dir.as_fd(), name, how).ok()?
        } else {
            openat(
                self.dir.as_fd(),
                name,
                flags | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .ok()?
        };
        let st = fstat(&fd).ok()?;
        if !is(&st, SFlag::S_IFREG) {
            return None;
        }
        let mut buf = Vec::new();
        std::fs::File::from(fd)
            .take(max)
            .read_to_end(&mut buf)
            .ok()?;
        Some((buf, u64::try_from(st.st_size).unwrap_or(0)))
    }

    /// Open the regular file `name` in this directory for reading, never through a symlink
    /// (`O_NOFOLLOW`); FIFOs, devices and directories are refused.
    pub fn open_regular(&self, name: &OsStr) -> Option<std::fs::File> {
        let fd = openat(
            self.dir.as_fd(),
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .ok()?;
        let st = fstat(&fd).ok()?;
        is(&st, SFlag::S_IFREG).then(|| std::fs::File::from(fd))
    }

    /// SHA-256 of the marker file `name` (at most [`MAX_MARKER_BYTES`] are read; a larger file
    /// hashes its first bytes and its size). A symlinked marker must resolve beneath this
    /// directory (see [`Self::read_regular`]).
    pub fn marker_hash(&self, name: &OsStr, symlink: bool) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let (buf, size) = self.read_regular(name, symlink, MAX_MARKER_BYTES)?;
        let mut h = Sha256::new();
        h.update(&buf);
        if size > MAX_MARKER_BYTES {
            h.update(size.to_le_bytes());
        }
        Some(h.finalize().into())
    }

    /// Modification time (Unix seconds) of `name`, without following symlinks.
    pub fn mtime(&self, name: &OsStr) -> Option<i64> {
        fstatat(
            self.dir.as_fd(),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .ok()
        .map(|st| st.st_mtime)
    }

    /// Without `openat2`: read the link and follow it component by component with `O_NOFOLLOW`.
    /// Stricter than `RESOLVE_BENEATH`: absolute targets, `..` and nested symlinks are rejected.
    pub fn symlink_beneath_fallback(&self, name: &OsStr) -> bool {
        let Ok(target) = readlinkat(self.dir.as_fd(), name) else {
            return false;
        };
        let target = Path::new(&target);
        let mut parts: Vec<&OsStr> = Vec::new();
        for c in target.components() {
            match c {
                Component::Normal(p) => parts.push(p),
                Component::CurDir => {}
                Component::RootDir | Component::ParentDir | Component::Prefix(_) => return false,
            }
        }
        let Some((last, dirs)) = parts.split_last() else {
            return false;
        };
        let path_flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mut current: Option<OwnedFd> = None;
        for part in dirs {
            let base = current.as_ref().map_or(self.dir.as_fd(), AsFd::as_fd);
            match openat(base, *part, path_flags | OFlag::O_DIRECTORY, Mode::empty()) {
                Ok(fd) => current = Some(fd),
                Err(_) => return false,
            }
        }
        let base = current.as_ref().map_or(self.dir.as_fd(), AsFd::as_fd);
        openat(base, *last, path_flags, Mode::empty())
            .ok()
            .and_then(|fd| fstat(&fd).ok())
            .is_some_and(|st| is(&st, SFlag::S_IFREG))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn id_of(p: &Path) -> Identity {
        use std::os::unix::fs::MetadataExt;
        let md = fs::symlink_metadata(p).unwrap();
        Identity {
            dev: md.dev(),
            ino: md.ino(),
        }
    }

    #[test]
    fn lists_and_classifies_without_following_symlinks() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("d")).unwrap();
        fs::write(t.path().join("f"), "").unwrap();
        symlink("d", t.path().join("l")).unwrap();
        let mut h = DirHandle::open_root(t.path()).unwrap();
        let (mut entries, errors) = h.entries();
        assert!(errors.is_empty());
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            entries,
            vec![
                Entry {
                    name: "d".into(),
                    kind: Kind::Dir(id_of(&t.path().join("d")))
                },
                Entry {
                    name: "f".into(),
                    kind: Kind::File
                },
                Entry {
                    name: "l".into(),
                    kind: Kind::Symlink
                },
            ]
        );
    }

    #[test]
    fn a_child_swapped_for_a_symlink_or_another_directory_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let (sub, outside, other) = (
            t.path().join("root/sub"),
            t.path().join("outside"),
            t.path().join("root/other"),
        );
        for d in [&sub, &outside, &other] {
            fs::create_dir_all(d).unwrap();
        }
        let root = DirHandle::open_root(&t.path().join("root")).unwrap();
        let listed = id_of(&sub);
        root.open_child(OsStr::new("sub"), listed).unwrap();

        // Swap 1: the listed directory is replaced by a symlink to a directory outside.
        fs::rename(&sub, t.path().join("moved")).unwrap();
        symlink(&outside, &sub).unwrap();
        assert!(matches!(
            root.open_child(OsStr::new("sub"), listed),
            Err(OpenError::Replaced)
        ));
        // Swap 2: replaced by a different real directory.
        fs::remove_file(&sub).unwrap();
        fs::rename(&other, &sub).unwrap();
        assert!(matches!(
            root.open_child(OsStr::new("sub"), listed),
            Err(OpenError::Replaced)
        ));
        // Gone entirely.
        fs::remove_dir(&sub).unwrap();
        assert!(matches!(
            root.open_child(OsStr::new("sub"), listed),
            Err(OpenError::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn a_root_must_be_a_real_directory() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("f"), "").unwrap();
        assert!(DirHandle::open_root(&t.path().join("f")).is_err());
        symlink(t.path(), t.path().join("l")).unwrap();
        assert!(matches!(
            DirHandle::open_root(&t.path().join("l")),
            Err(OpenError::Replaced)
        ));
    }

    #[test]
    fn symlinked_markers_must_resolve_to_a_regular_file_beneath() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("p");
        fs::create_dir_all(d.join("docs")).unwrap();
        fs::write(d.join("AGENTS.md"), "").unwrap();
        fs::write(d.join("docs/inner.md"), "").unwrap();
        fs::write(t.path().join("secret.md"), "").unwrap();
        let cases = [
            ("ok-sibling", "AGENTS.md", true),
            ("ok-dot", "./AGENTS.md", true),
            ("ok-subdir", "docs/inner.md", true),
            ("escape-dotdot", "../secret.md", false),
            ("escape-abs", "/etc/hostname", false),
            ("dir", "docs", false),
            ("dangling", "missing.md", false),
            ("self-loop", "self-loop", false),
        ];
        for (name, target, _) in cases {
            symlink(target, d.join(name)).unwrap();
        }
        let h = DirHandle::open_root(&d).unwrap();
        for (name, target, want) in cases {
            assert_eq!(
                h.symlink_resolves_to_file_beneath(OsStr::new(name)),
                want,
                "{name} -> {target}"
            );
            assert_eq!(
                h.symlink_beneath_fallback(OsStr::new(name)),
                want,
                "fallback: {name} -> {target}"
            );
        }
        // The fallback is stricter: a chain of symlinks is rejected even when it stays inside.
        symlink("ok-sibling", d.join("chain")).unwrap();
        assert!(h.symlink_resolves_to_file_beneath(OsStr::new("chain")));
        assert!(!h.symlink_beneath_fallback(OsStr::new("chain")));
    }

    #[test]
    fn marker_hashes_are_bounded_and_never_leave_the_directory() {
        use sha2::{Digest, Sha256};
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("p");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("CLAUDE.md"), "hello").unwrap();
        fs::write(d.join("AGENTS.md"), "agents").unwrap();
        fs::write(t.path().join("secret.md"), "secret").unwrap();
        symlink("AGENTS.md", d.join("in")).unwrap();
        symlink("../secret.md", d.join("out")).unwrap();
        let big = vec![b'x'; usize::try_from(MAX_MARKER_BYTES).unwrap() + 10];
        fs::write(d.join("big"), &big).unwrap();
        let h = DirHandle::open_root(&d).unwrap();
        let want: [u8; 32] = Sha256::digest(b"hello").into();
        assert_eq!(h.marker_hash(OsStr::new("CLAUDE.md"), false), Some(want));
        let agents: [u8; 32] = Sha256::digest(b"agents").into();
        assert_eq!(h.marker_hash(OsStr::new("in"), true), Some(agents));
        assert_eq!(h.marker_hash(OsStr::new("out"), true), None, "escapes");
        assert_eq!(
            h.marker_hash(OsStr::new("in"), false),
            None,
            "not followed as a file"
        );
        let bounded = h.marker_hash(OsStr::new("big"), false).unwrap();
        let first: [u8; 32] = Sha256::digest(&big[..big.len() - 10]).into();
        assert_ne!(bounded, first, "the size is part of a truncated hash");
        nix::unistd::mkfifo(&d.join("fifo"), Mode::S_IRWXU).unwrap();
        assert_eq!(h.marker_hash(OsStr::new("fifo"), false), None);
    }

    #[test]
    fn a_fifo_target_is_not_a_marker_and_does_not_block() {
        let t = tempfile::tempdir().unwrap();
        nix::unistd::mkfifo(&t.path().join("pipe"), Mode::S_IRWXU).unwrap();
        symlink("pipe", t.path().join("CLAUDE.md")).unwrap();
        let h = DirHandle::open_root(t.path()).unwrap();
        assert!(!h.symlink_resolves_to_file_beneath(OsStr::new("CLAUDE.md")));
        assert!(!h.symlink_beneath_fallback(OsStr::new("CLAUDE.md")));
    }
}
