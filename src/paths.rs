//! XDG directory resolution and private-directory verification.
//!
//! ccwm owns four directories (config, data, state, runtime). Every one must be a real directory
//! (not a symlink), owned by the daemon's user, with no group/world access. The runtime directory is
//! `$XDG_RUNTIME_DIR/ccwm`, falling back to `$XDG_STATE_HOME/ccwm/run` when that variable is unset.

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
/// `sun_path` is 108 bytes including the trailing NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;

/// The XDG-related environment variables, injectable for tests.
#[derive(Debug, Clone, Default)]
pub struct EnvVars {
    pub xdg_config_home: Option<OsString>,
    pub xdg_data_home: Option<OsString>,
    pub xdg_state_home: Option<OsString>,
    pub xdg_runtime_dir: Option<OsString>,
}

impl EnvVars {
    pub fn from_process() -> Self {
        let get = |k: &str| std::env::var_os(k);
        Self {
            xdg_config_home: get("XDG_CONFIG_HOME"),
            xdg_data_home: get("XDG_DATA_HOME"),
            xdg_state_home: get("XDG_STATE_HOME"),
            xdg_runtime_dir: get("XDG_RUNTIME_DIR"),
        }
    }
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
    pub fn db_path(&self) -> PathBuf {
        self.data.join(DB_NAME)
    }
    pub fn config_file(&self) -> PathBuf {
        self.config.join(CONFIG_NAME)
    }

    /// Paths discovery must never enter, whatever roots the user configures (§4.1).
    pub fn hard_boundaries(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = ["/proc", "/sys", "/dev", "/run"]
            .iter()
            .map(PathBuf::from)
            .collect();
        out.extend(self.all().iter().map(|p| p.to_path_buf()));
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

    /// Create (mode 0700) and verify all four directories, then check the socket path length.
    pub fn ensure(&self, uid: u32) -> Result<()> {
        for dir in self.all() {
            ensure_private_dir(dir, uid)?;
        }
        self.check_socket_path()
    }

    /// Verify (without creating anything) that the runtime directory is private and ours.
    /// Used by the CLI before it talks to the daemon.
    pub fn verify_runtime(&self, uid: u32) -> Result<()> {
        match fs::symlink_metadata(&self.runtime) {
            Ok(md) => verify_private(&self.runtime, &md, uid),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::new(format!(
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

/// The real process's home directory.
pub fn current_home(uid: u32) -> Result<PathBuf> {
    let passwd = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir);
    resolve_home(passwd, std::env::var_os("HOME").map(PathBuf::from), uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn env(base: &Path) -> EnvVars {
        EnvVars {
            xdg_config_home: Some(base.join("c").into()),
            xdg_data_home: Some(base.join("d").into()),
            xdg_state_home: Some(base.join("s").into()),
            xdg_runtime_dir: Some(base.join("r").into()),
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
        let b = d.hard_boundaries();
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
        let t = tempfile::tempdir().unwrap();
        let d = Dirs::resolve(&env(t.path()), t.path());
        d.ensure(uid()).unwrap();
        for dir in d.all() {
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        d.ensure(uid()).unwrap(); // idempotent
    }

    #[test]
    fn ensure_creates_fallback_runtime_under_state() {
        let t = tempfile::tempdir().unwrap();
        let mut e = env(t.path());
        e.xdg_runtime_dir = None;
        let d = Dirs::resolve(&e, t.path());
        d.ensure(uid()).unwrap();
        assert!(d.runtime.ends_with("s/ccwm/run") && d.runtime.is_dir());
    }

    #[test]
    fn rejects_permissive_existing_dir_without_touching_it() {
        let t = tempfile::tempdir().unwrap();
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
        let t = tempfile::tempdir().unwrap();
        let err = ensure_private_dir(t.path(), uid() + 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not owned"), "{err}");
    }

    #[test]
    fn rejects_symlinked_dir() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ensure_private_dir(&link, uid()).unwrap_err().to_string();
        assert!(err.contains("real directory"), "{err}");
    }

    #[test]
    fn rejects_overlong_socket_path() {
        let t = tempfile::tempdir().unwrap();
        let mut e = env(t.path());
        e.xdg_runtime_dir = Some(t.path().join("x".repeat(120)).into());
        let d = Dirs::resolve(&e, t.path());
        let err = d.check_socket_path().unwrap_err().to_string();
        assert!(err.contains("limit 107"), "{err}");
    }

    #[test]
    fn accepts_socket_path_at_the_limit() {
        let t = tempfile::tempdir().unwrap();
        let mut d = Dirs::resolve(&env(t.path()), t.path());
        // Pad the runtime dir so that runtime + "/ccwm.sock" is exactly 107 bytes.
        let pad = MAX_SOCKET_PATH_BYTES - d.socket_path().as_os_str().len();
        d.runtime = PathBuf::from(format!("{}{}", d.runtime.display(), "a".repeat(pad)));
        assert_eq!(d.socket_path().as_os_str().len(), MAX_SOCKET_PATH_BYTES);
        d.check_socket_path().unwrap();
    }

    #[test]
    fn verify_runtime_reports_missing_dir() {
        let t = tempfile::tempdir().unwrap();
        let d = Dirs::resolve(&env(t.path()), t.path());
        assert!(d
            .verify_runtime(uid())
            .unwrap_err()
            .to_string()
            .contains("is the daemon running"));
    }

    #[test]
    fn home_prefers_an_owned_env_home_then_passwd() {
        let t = tempfile::tempdir().unwrap();
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
