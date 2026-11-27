//! XDG directory resolution and private-directory verification.
//!
//! ccwm owns four directories (config, data, state, runtime). Every one must be a real directory
//! (not a symlink), owned by the daemon's user, with no group/world access. The runtime directory is
//! `$XDG_RUNTIME_DIR/ccwm`, falling back to `$XDG_STATE_HOME/ccwm/run` when that variable is unset.
//!
//! Every **ancestor** of those directories, and the config file, must also be trustworthy
//! ([`Owner::verify_trusted`]): owned by the user or root, and not writable by anyone else (a
//! root-owned sticky directory such as `/tmp` is fine; group-writable is fine only for the user's
//! private group). Otherwise another user could swap a component of the path.

use crate::error::{Error, Result};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

const APP: &str = "ccwm";
pub const SOCKET_NAME: &str = "ccwm.sock";
pub const LOCK_NAME: &str = "ccwm.lock";
pub const INSTANCE_NAME: &str = "instance.json";
pub const DB_NAME: &str = "ccwm.db";
pub const CONFIG_NAME: &str = "config.toml";
/// Where `PUT /settings` stages the new configuration before renaming it over [`CONFIG_NAME`]
/// (`Config::save` writes `<config file>.tmp`).
pub const CONFIG_TMP_NAME: &str = "config.toml.tmp";
/// Written next to `instance.json` and renamed over it (atomic replace).
pub const INSTANCE_TMP_NAME: &str = "instance.json.tmp";
/// SQLite's companion files next to the database.
pub const DB_WAL_NAME: &str = "ccwm.db-wal";
pub const DB_SHM_NAME: &str = "ccwm.db-shm";
/// Claude Code's config directory when `CLAUDE_CONFIG_DIR` is unset (relative to home).
pub const DEFAULT_CLAUDE_DIR: &str = ".claude";
/// `sun_path` is 108 bytes including the trailing NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;

/// The XDG-related environment variables, injectable for tests.
#[derive(Debug, Clone, Default)]
pub struct EnvVars {
    pub xdg_config_home: Option<OsString>,
    pub xdg_data_home: Option<OsString>,
    pub xdg_state_home: Option<OsString>,
    pub xdg_runtime_dir: Option<OsString>,
    pub claude_config_dir: Option<OsString>,
}

impl EnvVars {
    pub fn from_process() -> Self {
        let get = |k: &str| std::env::var_os(k);
        Self {
            xdg_config_home: get("XDG_CONFIG_HOME"),
            xdg_data_home: get("XDG_DATA_HOME"),
            xdg_state_home: get("XDG_STATE_HOME"),
            xdg_runtime_dir: get("XDG_RUNTIME_DIR"),
            claude_config_dir: get("CLAUDE_CONFIG_DIR"),
        }
    }
}

/// Claude Code's config directory (sessions live under it): `$CLAUDE_CONFIG_DIR` if absolute,
/// otherwise `~/.claude`.
pub fn session_dir(env: &EnvVars, home: &Path) -> PathBuf {
    xdg_absolute(&env.claude_config_dir).unwrap_or_else(|| home.join(DEFAULT_CLAUDE_DIR))
}

/// First executable regular file `name` on `path` (a `PATH` value; absolute entries only).
pub fn find_executable(name: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// Per the XDG spec, relative or empty values are invalid and ignored.
fn xdg_absolute(value: &Option<OsString>) -> Option<PathBuf> {
    let path = PathBuf::from(value.as_ref()?);
    path.is_absolute().then_some(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Dirs {
    pub fn resolve(env: &EnvVars, home: &Path) -> Self {
        let base = |var: &Option<OsString>, fallback: &str| {
            xdg_absolute(var)
                .unwrap_or_else(|| home.join(fallback))
                .join(APP)
        };
        let state = base(&env.xdg_state_home, ".local/state");
        let runtime = match xdg_absolute(&env.xdg_runtime_dir) {
            Some(dir) => dir.join(APP),
            None => state.join("run"),
        };
        Self {
            config: base(&env.xdg_config_home, ".config"),
            data: base(&env.xdg_data_home, ".local/share"),
            state,
            runtime,
        }
    }

    pub fn all(&self) -> [&Path; 4] {
        [&self.config, &self.data, &self.state, &self.runtime]
    }

    pub fn socket_path(&self) -> PathBuf {
        self.runtime.join(SOCKET_NAME)
    }
    pub fn lock_path(&self) -> PathBuf {
        self.runtime.join(LOCK_NAME)
    }
    pub fn instance_path(&self) -> PathBuf {
        self.runtime.join(INSTANCE_NAME)
    }
    pub fn instance_tmp_path(&self) -> PathBuf {
        self.runtime.join(INSTANCE_TMP_NAME)
    }
    pub fn db_path(&self) -> PathBuf {
        self.data.join(DB_NAME)
    }
    pub fn config_file(&self) -> PathBuf {
        self.config.join(CONFIG_NAME)
    }

    /// Paths discovery must never enter, whatever roots the user configures (§4.1): system
    /// pseudo-filesystems, ccwm's own directories and Claude Code's config directory (`session_dir`),
    /// whether or not it is hidden (§4.3: it is never a project; only the session integration reads it).
    pub fn hard_boundaries(&self, session_dir: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = ["/proc", "/sys", "/dev", "/run"]
            .iter()
            .map(PathBuf::from)
            .collect();
        out.extend(self.all().iter().map(|p| p.to_path_buf()));
        out.push(session_dir.to_path_buf());
        out
    }

    /// Fail with an actionable message if the socket path would not fit in `sockaddr_un`.
    pub fn check_socket_path(&self) -> Result<()> {
        let path = self.socket_path();
        let len = path.as_os_str().len();
        if len > MAX_SOCKET_PATH_BYTES {
            return Err(Error::new(format!(
                "the socket path is {len} bytes long (limit {MAX_SOCKET_PATH_BYTES}): {}. \
                 Use a shorter XDG_RUNTIME_DIR (or XDG_STATE_HOME when XDG_RUNTIME_DIR is unset)",
                path.display()
            )));
        }
        Ok(())
    }

    /// Verify the ancestors, then create (mode 0700) and verify all four directories, then check
    /// the socket path length.
    pub fn ensure(&self, owner: &Owner) -> Result<()> {
        for dir in self.all() {
            owner.verify_ancestors(dir)?;
            ensure_private_dir(dir, owner.uid)?;
        }
        self.check_socket_path()
    }

    /// [`Self::verify_runtime`] for user `uid`, looking up the private group (`lookup`, in
    /// production [`private_group`]) only when the strict check — no group write anywhere —
    /// fails for another reason than a missing directory. The lookup reads the user and group
    /// databases through NSS (files, but also sssd or LDAP), on every CLI command and every
    /// `ccwm hook` event: with a private runtime directory (`/run/user/<uid>/ccwm`) it is never
    /// needed (REQUIREMENTS.md §21.3; v0.2 review L5).
    pub fn verify_runtime_lazily(
        &self,
        uid: u32,
        lookup: impl FnOnce(u32) -> Option<u32>,
    ) -> Result<()> {
        let strict = Owner {
            uid,
            private_gid: None,
        };
        match self.verify_runtime(&strict) {
            Err(e) if !e.is_not_running() => self.verify_runtime(&Owner {
                uid,
                private_gid: lookup(uid),
            }),
            done => done,
        }
    }

    /// Verify (without creating anything) that the runtime directory is private and ours and that
    /// no other user can replace any of its ancestors. Used by the CLI before it talks to the daemon.
    pub fn verify_runtime(&self, owner: &Owner) -> Result<()> {
        owner.verify_ancestors(&self.runtime)?;
        let uid = owner.uid;
        match fs::symlink_metadata(&self.runtime) {
            Ok(md) => verify_private(&self.runtime, &md, uid),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::not_running(format!(
                "no ccwm runtime directory at {} (is the daemon running?)",
                self.runtime.display()
            ))),
            Err(e) => Err(Error::io(
                format!("cannot inspect {}", self.runtime.display()),
                &e,
            )),
        }
    }
}

fn verify_private(path: &Path, md: &fs::Metadata, uid: u32) -> Result<()> {
    if !md.file_type().is_dir() {
        return Err(Error::new(format!(
            "{} must be a real directory (not a symlink or file)",
            path.display()
        )));
    }
    if md.uid() != uid {
        return Err(Error::new(format!(
            "{} is not owned by the current user (uid {uid})",
            path.display()
        )));
    }
    if md.mode() & 0o077 != 0 {
        return Err(Error::new(format!(
            "{} has mode {:o}; it must not be accessible by group or others (run: chmod 700 {})",
            path.display(),
            md.mode() & 0o7777,
            path.display()
        )));
    }
    Ok(())
}

/// Who may own or write the paths ccwm trusts: the user, plus (for group write) the user's
/// private group when the account follows the user-private-group convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    /// A group that contains only this user (group name == user name, it is the user's primary
    /// group and it lists no other members). Group write by this group is not write by others.
    pub private_gid: Option<u32>,
}

impl Owner {
    /// The current user, looking up the private group in the user and group databases.
    pub fn current(uid: u32) -> Self {
        Self {
            uid,
            private_gid: private_group(uid),
        }
    }

    /// Fail unless no user other than `self` (or root) can modify `path` or replace any component
    /// of it. Checks the path as written (symlink components by owner) and its canonical form.
    /// Missing trailing components are skipped (they will be created privately).
    pub fn verify_trusted(&self, path: &Path) -> Result<()> {
        self.verify_chain(path)?;
        if let Ok(canonical) = fs::canonicalize(path) {
            if canonical != path {
                self.verify_chain(&canonical)?;
            }
        }
        Ok(())
    }

    /// Like [`Self::verify_trusted`] for every ancestor of `path`, not `path` itself.
    pub fn verify_ancestors(&self, path: &Path) -> Result<()> {
        match path.parent() {
            Some(parent) if parent != path => self.verify_trusted(parent),
            _ => Ok(()),
        }
    }

    fn verify_chain(&self, path: &Path) -> Result<()> {
        for prefix in path.ancestors() {
            if prefix.as_os_str().is_empty() {
                continue;
            }
            match fs::symlink_metadata(prefix) {
                Ok(md) => self.check_entry(prefix, &md)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::io(
                        format!("cannot inspect {}", prefix.display()),
                        &e,
                    ))
                }
            }
        }
        Ok(())
    }

    /// One path component: owned by us or root; if it is not a symlink, not writable by others.
    pub fn check_entry(&self, path: &Path, md: &fs::Metadata) -> Result<()> {
        if md.uid() != self.uid && md.uid() != 0 {
            return Err(Error::new(format!(
                "{} is owned by uid {}, not by you (uid {}) or root; refusing to trust it",
                path.display(),
                md.uid(),
                self.uid
            )));
        }
        if md.file_type().is_symlink() {
            return Ok(()); // a symlink's own mode is meaningless; replacing it needs the parent
        }
        let mode = md.mode();
        let sticky_root_dir = md.is_dir() && md.uid() == 0 && mode & 0o1000 != 0;
        let world_writable = mode & 0o002 != 0;
        let group_writable = mode & 0o020 != 0 && self.private_gid != Some(md.gid());
        if (world_writable || group_writable) && !sticky_root_dir {
            return Err(Error::new(format!(
                "{} has mode {:o} and can be modified by other users (run: chmod go-w {})",
                path.display(),
                mode & 0o7777,
                path.display()
            )));
        }
        Ok(())
    }
}

/// The user's private group: their primary group, named like the user, with no listed members
/// other than the user. `None` if the account does not follow that convention.
pub fn private_group(uid: u32) -> Option<u32> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    let group = nix::unistd::Group::from_gid(user.gid).ok()??;
    let only_user = group.mem.iter().all(|m| *m == user.name);
    (group.name == user.name && only_user).then_some(user.gid.as_raw())
}

/// Create `path` (and missing parents) with mode 0700 if absent; otherwise verify it. Never
/// changes the mode or owner of something that already exists.
pub fn ensure_private_dir(path: &Path, uid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) => verify_private(path, &md, uid),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|e| Error::io(format!("cannot create {}", path.display()), &e))?;
            let md = fs::symlink_metadata(path)
                .map_err(|e| Error::io(format!("cannot inspect {}", path.display()), &e))?;
            verify_private(path, &md, uid)
        }
        Err(e) => Err(Error::io(format!("cannot inspect {}", path.display()), &e)),
    }
}

/// Home directory of `uid`: `$HOME` if it is an absolute path to a directory owned by `uid` (this is
/// what systemd and login shells provide, and what the synthetic test environment overrides);
/// otherwise the passwd entry.
pub fn resolve_home(
    passwd_home: Option<PathBuf>,
    env_home: Option<PathBuf>,
    uid: u32,
) -> Result<PathBuf> {
    if let Some(home) = env_home.filter(|p| p.is_absolute()) {
        if fs::metadata(&home).is_ok_and(|md| md.is_dir() && md.uid() == uid) {
            return Ok(home);
        }
    }
    if let Some(home) = passwd_home.filter(|p| p.is_absolute()) {
        return Ok(home);
    }
    Err(Error::new("cannot determine the home directory ($HOME is unset or not owned by you, and there is no passwd entry)"))
}

/// A temporary directory with mode 0700, whatever the test process's umask: tempdirs inherit the
/// umask (0775 under umask 002), and a group-writable ancestor is correctly refused by [`Owner`].
#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    t
}

/// The real process's home directory. The passwd entry is looked up only when `$HOME` does not
/// qualify: the lookup can go through NSS (LDAP, sssd), too slow for `ccwm hook` (§21.3).
pub fn current_home(uid: u32) -> Result<PathBuf> {
    let env_home = std::env::var_os("HOME").map(PathBuf::from);
    if let Ok(home) = resolve_home(None, env_home.clone(), uid) {
        return Ok(home);
    }
    let passwd = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir);
    resolve_home(passwd, env_home, uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn owner() -> Owner {
        Owner {
            uid: uid(),
            private_gid: None,
        }
    }

    fn env(base: &Path) -> EnvVars {
        EnvVars {
            xdg_config_home: Some(base.join("c").into()),
            xdg_data_home: Some(base.join("d").into()),
            xdg_state_home: Some(base.join("s").into()),
            xdg_runtime_dir: Some(base.join("r").into()),
            claude_config_dir: None,
        }
    }

    #[test]
    fn resolves_from_xdg_vars() {
        let d = Dirs::resolve(&env(Path::new("/x")), Path::new("/home/u"));
        assert_eq!(d.config, Path::new("/x/c/ccwm"));
        assert_eq!(d.data, Path::new("/x/d/ccwm"));
        assert_eq!(d.state, Path::new("/x/s/ccwm"));
        assert_eq!(d.runtime, Path::new("/x/r/ccwm"));
        assert_eq!(d.socket_path(), Path::new("/x/r/ccwm/ccwm.sock"));
    }

    #[test]
    fn defaults_to_home_and_state_run_fallback() {
        let d = Dirs::resolve(&EnvVars::default(), Path::new("/home/u"));
        assert_eq!(d.config, Path::new("/home/u/.config/ccwm"));
        assert_eq!(d.data, Path::new("/home/u/.local/share/ccwm"));
        assert_eq!(d.state, Path::new("/home/u/.local/state/ccwm"));
        assert_eq!(d.runtime, Path::new("/home/u/.local/state/ccwm/run"));
    }

    #[test]
    fn relative_and_empty_xdg_values_are_ignored() {
        let env = EnvVars {
            xdg_config_home: Some("relative/dir".into()),
            xdg_runtime_dir: Some("".into()),
            ..EnvVars::default()
        };
        let d = Dirs::resolve(&env, Path::new("/home/u"));
        assert_eq!(d.config, Path::new("/home/u/.config/ccwm"));
        assert_eq!(d.runtime, Path::new("/home/u/.local/state/ccwm/run"));
    }

    #[test]
    fn hard_boundaries_include_runtime_and_system_dirs() {
        let d = Dirs::resolve(&EnvVars::default(), Path::new("/home/u"));
        let b = d.hard_boundaries(Path::new("/home/u/claude-cfg"));
        assert!(b.contains(&PathBuf::from("/home/u/claude-cfg")));
        for p in ["/proc", "/sys", "/dev", "/run"] {
            assert!(b.contains(&PathBuf::from(p)));
        }
        assert!(
            b.contains(&d.runtime)
                && b.contains(&d.data)
                && b.contains(&d.config)
                && b.contains(&d.state)
        );
    }

    #[test]
    fn ensure_creates_private_dirs() {
        let t = private_tempdir();
        let d = Dirs::resolve(&env(t.path()), t.path());
        d.ensure(&owner()).unwrap();
        for dir in d.all() {
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        d.ensure(&owner()).unwrap(); // idempotent
    }

    #[test]
    fn ensure_creates_fallback_runtime_under_state() {
        let t = private_tempdir();
        let mut e = env(t.path());
        e.xdg_runtime_dir = None;
        let d = Dirs::resolve(&e, t.path());
        d.ensure(&owner()).unwrap();
        assert!(d.runtime.ends_with("s/ccwm/run") && d.runtime.is_dir());
    }

    #[test]
    fn rejects_permissive_existing_dir_without_touching_it() {
        let t = private_tempdir();
        let dir = t.path().join("open");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_private_dir(&dir, uid()).unwrap_err().to_string();
        assert!(err.contains("chmod 700"), "{err}");
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn rejects_wrong_owner() {
        let t = private_tempdir();
        let err = ensure_private_dir(t.path(), uid() + 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not owned"), "{err}");
    }

    #[test]
    fn rejects_symlinked_dir() {
        let t = private_tempdir();
        let real = t.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_private_dir(&link, uid()).unwrap_err().to_string();
        assert!(err.contains("real directory"), "{err}");
    }

    #[test]
    fn rejects_overlong_socket_path() {
        let t = private_tempdir();
        let mut e = env(t.path());
        e.xdg_runtime_dir = Some(t.path().join("x".repeat(120)).into());
        let d = Dirs::resolve(&e, t.path());
        let err = d.check_socket_path().unwrap_err().to_string();
        assert!(err.contains("limit 107"), "{err}");
    }

    #[test]
    fn accepts_socket_path_at_the_limit() {
        let t = private_tempdir();
        let mut d = Dirs::resolve(&env(t.path()), t.path());
        // Pad the runtime dir so that runtime + "/ccwm.sock" is exactly 107 bytes.
        let pad = MAX_SOCKET_PATH_BYTES - d.socket_path().as_os_str().len();
        d.runtime = PathBuf::from(format!("{}{}", d.runtime.display(), "a".repeat(pad)));
        assert_eq!(d.socket_path().as_os_str().len(), MAX_SOCKET_PATH_BYTES);
        d.check_socket_path().unwrap();
    }

    #[test]
    fn verify_runtime_reports_missing_dir() {
        let t = private_tempdir();
        let d = Dirs::resolve(&env(t.path()), t.path());
        assert!(d
            .verify_runtime(&owner())
            .unwrap_err()
            .to_string()
            .contains("is the daemon running"));
    }

    #[test]
    fn session_dir_is_claude_config_dir_if_absolute_else_dot_claude() {
        let home = Path::new("/home/u");
        let mut e = EnvVars::default();
        assert_eq!(session_dir(&e, home), Path::new("/home/u/.claude"));
        e.claude_config_dir = Some("/srv/claude".into());
        assert_eq!(session_dir(&e, home), Path::new("/srv/claude"));
        for bad in ["relative", ""] {
            e.claude_config_dir = Some(bad.into());
            assert_eq!(
                session_dir(&e, home),
                Path::new("/home/u/.claude"),
                "{bad:?}"
            );
        }
    }

    fn dir_with_mode(parent: &Path, name: &str, mode: u32) -> PathBuf {
        let d = parent.join(name);
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(mode)).unwrap();
        d
    }

    #[test]
    fn trusted_paths_reject_group_and_world_writable_components() {
        let t = private_tempdir();
        let ok = dir_with_mode(t.path(), "ok", 0o755);
        owner().verify_trusted(&ok.join("missing/child")).unwrap();

        let ww = dir_with_mode(t.path(), "ww", 0o777);
        let err = owner()
            .verify_trusted(&ww.join("x"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("chmod go-w") && err.contains("777"), "{err}");

        let gw = dir_with_mode(t.path(), "gw", 0o775);
        let gid = fs::metadata(&gw).unwrap().gid();
        assert!(
            owner().verify_trusted(&gw).is_err(),
            "group-writable, not a private group"
        );
        let private = Owner {
            uid: uid(),
            private_gid: Some(gid),
        };
        private.verify_trusted(&gw).unwrap();
        let other_group = Owner {
            uid: uid(),
            private_gid: Some(gid + 1),
        };
        assert!(other_group.verify_trusted(&gw).is_err());
        assert!(
            private.verify_trusted(&ww).is_err(),
            "world-writable is never acceptable"
        );
    }

    #[test]
    fn trusted_paths_reject_foreign_owners_and_check_symlink_targets() {
        let t = private_tempdir();
        let foreign = Owner {
            uid: uid() + 1,
            private_gid: None,
        };
        let err = foreign.verify_trusted(t.path()).unwrap_err().to_string();
        assert!(err.contains("not by you"), "{err}");

        // A symlink whose target sits in a world-writable directory is caught via the canonical path.
        let ww = dir_with_mode(t.path(), "ww", 0o777);
        let target = ww.join("cfg.toml");
        fs::write(&target, "").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let safe = dir_with_mode(t.path(), "safe", 0o700);
        let link = safe.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(owner().verify_trusted(&link).is_err());

        let file = safe.join("plain.toml");
        fs::write(&file, "").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            owner().verify_trusted(&file).is_err(),
            "world-writable file"
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        owner().verify_trusted(&file).unwrap();
    }

    #[test]
    fn a_root_owned_sticky_directory_is_an_acceptable_ancestor() {
        let tmp = Path::new("/tmp");
        let md = fs::symlink_metadata(tmp).unwrap();
        if md.uid() != 0 || md.mode() & 0o1002 != 0o1002 {
            eprintln!(
                "NOTICE: /tmp is not a root-owned sticky world-writable directory here; skipping"
            );
            return;
        }
        owner().check_entry(tmp, &md).unwrap();
    }

    #[test]
    fn ensure_refuses_an_untrusted_ancestor_and_creates_nothing() {
        let t = private_tempdir();
        let ww = dir_with_mode(t.path(), "ww", 0o777);
        let d = Dirs::resolve(&env(&ww), &ww);
        let err = d.ensure(&owner()).unwrap_err().to_string();
        assert!(err.contains("other users"), "{err}");
        assert!(
            !ww.join("c").exists(),
            "nothing is created under an untrusted ancestor"
        );
        assert!(d.verify_runtime(&owner()).is_err());
    }

    /// v0.2 review L5: the private group is looked up only when a group-writable ancestor needs
    /// it, never for a private tree or a missing runtime directory.
    #[test]
    fn the_runtime_check_looks_up_the_private_group_only_when_needed() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let lookup = |gid: Option<u32>| {
            let calls = &calls;
            move |_uid: u32| {
                calls.set(calls.get() + 1);
                gid
            }
        };
        let t = private_tempdir();
        let d = Dirs::resolve(&env(t.path()), t.path());
        let err = d.verify_runtime_lazily(uid(), lookup(None)).unwrap_err();
        assert!(err.is_not_running(), "{err}");
        d.ensure(&owner()).unwrap();
        d.verify_runtime_lazily(uid(), lookup(None)).unwrap();
        assert_eq!(calls.get(), 0, "a private tree needs no lookup");
        // A group-writable ancestor: accepted only when its group is the user's private group.
        let gw = dir_with_mode(t.path(), "gw", 0o775);
        let gid = fs::metadata(&gw).unwrap().gid();
        let d = Dirs::resolve(&env(&gw), &gw);
        d.ensure(&Owner {
            uid: uid(),
            private_gid: Some(gid),
        })
        .unwrap();
        assert!(d.verify_runtime_lazily(uid(), lookup(None)).is_err());
        assert_eq!(calls.get(), 1);
        d.verify_runtime_lazily(uid(), lookup(Some(gid))).unwrap();
        assert_eq!(calls.get(), 2);
        assert!(d
            .verify_runtime_lazily(uid(), lookup(Some(gid + 1)))
            .is_err());
    }

    #[test]
    fn private_group_lookup_is_consistent_with_the_databases() {
        // Whatever the host's convention, the answer is either None or the user's primary gid.
        if let Some(gid) = private_group(uid()) {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid()))
                .unwrap()
                .unwrap();
            assert_eq!(gid, user.gid.as_raw());
        }
    }

    #[test]
    fn home_prefers_an_owned_env_home_then_passwd() {
        let t = private_tempdir();
        assert_eq!(
            resolve_home(Some("/home/p".into()), Some(t.path().into()), uid()).unwrap(),
            t.path()
        );
        // $HOME owned by someone else, relative, or missing: fall back to passwd
        assert_eq!(
            resolve_home(Some("/home/p".into()), Some(t.path().into()), uid() + 1).unwrap(),
            Path::new("/home/p")
        );
        assert_eq!(
            resolve_home(Some("/home/p".into()), Some("relative".into()), uid()).unwrap(),
            Path::new("/home/p")
        );
        assert_eq!(
            resolve_home(
                Some("/home/p".into()),
                Some(t.path().join("missing")),
                uid()
            )
            .unwrap(),
            Path::new("/home/p")
        );
        assert_eq!(
            resolve_home(Some("/home/p".into()), None, uid()).unwrap(),
            Path::new("/home/p")
        );
        assert!(resolve_home(Some("relative".into()), None, uid()).is_err());
        assert!(resolve_home(None, Some(t.path().into()), uid() + 1).is_err());
        assert!(resolve_home(None, None, uid()).is_err());
    }
}
