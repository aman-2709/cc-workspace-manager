//! Single-instance guarantee: an exclusive `flock` on the lock file (released by the kernel when the
//! process dies, so a stale lock cannot exist) plus `instance.json` describing the live daemon.
//! `instance.json` is informational only: the CLI never trusts it for identity or for the port.

use crate::error::{Error, Result};
use crate::paths::Dirs;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceInfo {
    pub pid: u32,
    pub port: u16,
    pub version: String,
    pub started_at: i64,
}

/// Holds the lock for as long as it lives.
#[derive(Debug)]
pub struct InstanceLock {
    _lock: Flock<File>,
}

impl InstanceLock {
    pub fn acquire(dirs: &Dirs) -> Result<Self> {
        let path = dirs.lock_path();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::io(format!("cannot open lock file {}", path.display()), &e))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Self { _lock: lock }),
            Err((_, Errno::EWOULDBLOCK)) => Err(Error::new(format!(
                "another ccwm daemon is already running (lock held on {}). Use `ccwm open` to reach it",
                path.display()
            ))),
            Err((_, errno)) => Err(Error::new(format!("cannot lock {}: {errno}", path.display()))),
        }
    }
}

pub fn write_instance(dirs: &Dirs, info: &InstanceInfo) -> Result<()> {
    let path = dirs.instance_path();
    let tmp = dirs.instance_tmp_path();
    let json = serde_json::to_vec(info)
        .map_err(|e| Error::new(format!("cannot encode instance info: {e}")))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
    file.write_all(&json)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
    fs::rename(&tmp, &path).map_err(|e| Error::io(format!("cannot install {}", path.display()), &e))
}

pub fn remove_instance(dirs: &Dirs) {
    let _ = fs::remove_file(dirs.instance_path());
}

pub fn read_instance(path: &Path) -> Option<InstanceInfo> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::EnvVars;

    fn dirs(t: &Path) -> Dirs {
        let env = EnvVars {
            xdg_config_home: Some(t.join("c").into()),
            xdg_data_home: Some(t.join("d").into()),
            xdg_state_home: Some(t.join("s").into()),
            xdg_runtime_dir: Some(t.join("r").into()),
            claude_config_dir: None,
        };
        let d = Dirs::resolve(&env, t);
        d.ensure(&crate::paths::Owner {
            uid: nix::unistd::geteuid().as_raw(),
            private_gid: None,
        })
        .unwrap();
        d
    }

    #[test]
    fn second_acquire_fails_until_the_first_is_dropped() {
        let t = crate::paths::private_tempdir();
        let d = dirs(t.path());
        let first = InstanceLock::acquire(&d).unwrap();
        let err = InstanceLock::acquire(&d).unwrap_err().to_string();
        assert!(err.contains("already running"), "{err}");
        drop(first);
        InstanceLock::acquire(&d).unwrap();
    }

    #[test]
    fn instance_json_roundtrip_is_private_and_atomic() {
        use std::os::unix::fs::PermissionsExt;
        let t = crate::paths::private_tempdir();
        let d = dirs(t.path());
        let info = InstanceInfo {
            pid: 42,
            port: 8765,
            version: "0.1.0".into(),
            started_at: 7,
        };
        write_instance(&d, &info).unwrap();
        assert_eq!(read_instance(&d.instance_path()), Some(info));
        assert_eq!(
            fs::metadata(d.instance_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!d.instance_tmp_path().exists());
        remove_instance(&d);
        assert_eq!(read_instance(&d.instance_path()), None);
    }

    #[test]
    fn garbage_instance_file_reads_as_none() {
        let t = crate::paths::private_tempdir();
        let p = t.path().join("i.json");
        fs::write(&p, "{nope").unwrap();
        assert_eq!(read_instance(&p), None);
    }
}
