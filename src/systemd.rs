//! The systemd **user** unit and the `systemctl --user` calls behind `ccwm start|stop|restart`,
//! `ccwm service install|uninstall [--purge]` and the systemd line of `ccwm status`
//! (REQUIREMENTS.md §13). Nothing here needs root: everything talks to the user's own service
//! manager. Lingering (`loginctl enable-linger`, start at boot) is reported, never changed.
//!
//! `systemctl` is found on `PATH` (tests put a stand-in first on `PATH`). These are CLI-side
//! children, never children of the sandboxed daemon.

use crate::error::{Error, Result, EXIT_ALREADY_RUNNING, EXIT_PORT_IN_USE};
use crate::paths::{find_executable, Dirs, EnvVars, Owner};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const UNIT_NAME: &str = "ccwm.service";
/// Where the unit expects the binary (`%h/.local/bin/ccwm`), relative to the home directory.
pub const BINARY_IN_HOME: &str = ".local/bin/ccwm";

/// The unit file `ccwm service install` writes. Only directives verified to work in a **user**
/// unit with the real daemon are used (ARCHITECTURE.md §13); `ProtectSystem`/`ProtectHome` and
/// `PrivateTmp` need user namespaces in user units and are left out (Landlock confines the daemon
/// instead). `MemoryDenyWriteExecute` is left out because it is inherited by `claude --version`,
/// whose JavaScript runtime needs writable executable memory.
pub fn unit_text() -> String {
    format!(
        "# Written by `ccwm service install`; `ccwm service uninstall` removes it.\n\
         # Local changes belong in a drop-in (`systemctl --user edit ccwm`), which a reinstall keeps.\n\
         [Unit]\n\
         Description=CC Workspace Manager (ccwm, unofficial): discover, track and resume Claude Code projects\n\
         \n\
         [Service]\n\
         Type=exec\n\
         ExecStart=%h/{BINARY_IN_HOME} serve\n\
         # The `claude` CLI is verified at startup; its usual install location is ~/.local/bin.\n\
         Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # Port in use ({EXIT_PORT_IN_USE}) and another instance running ({EXIT_ALREADY_RUNNING}): restarting cannot help.\n\
         RestartPreventExitStatus={EXIT_PORT_IN_USE} {EXIT_ALREADY_RUNNING}\n\
         TimeoutStopSec=10\n\
         UMask=0077\n\
         Nice=10\n\
         IOSchedulingClass=idle\n\
         NoNewPrivileges=yes\n\
         LockPersonality=yes\n\
         RestrictRealtime=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictNamespaces=yes\n\
         SystemCallArchitectures=native\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// The user unit directory: `$XDG_CONFIG_HOME/systemd/user`, else `~/.config/systemd/user`.
pub fn unit_dir(env: &EnvVars, home: &Path) -> PathBuf {
    env.xdg_config_home
        .as_ref()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
        .join("systemd/user")
}

/// `true` if `loginctl enable-linger` is in effect for `user` (the user manager, and so the
/// service, starts at boot instead of at login); `None` if the user name is unknown.
pub fn linger_enabled(user: Option<&str>) -> Option<bool> {
    Some(Path::new("/var/lib/systemd/linger").join(user?).exists())
}

/// What `ccwm service install` says about starting at boot: a hint naming the command, unless
/// lingering is known to be enabled already (then there is nothing to suggest). ccwm never runs
/// the command itself.
pub fn linger_hint(linger: Option<bool>, user: Option<&str>) -> Option<String> {
    (linger != Some(true)).then(|| {
        format!(
            "It starts when you log in. To start it at boot, before you log in, enable lingering: `loginctl enable-linger {}` (may need administrator authorization).",
            user.unwrap_or("$USER")
        )
    })
}

/// The name of the user `uid` (for the linger check and the documentation hints).
pub fn user_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

/// `systemctl --user`, found on `PATH`.
pub struct Systemctl {
    program: PathBuf,
}

impl Systemctl {
    pub fn find(path: Option<&std::ffi::OsStr>) -> Result<Self> {
        find_executable("systemctl", path)
            .map(|program| Self { program })
            .ok_or_else(|| {
                Error::new(
                    "systemctl was not found: the service commands need systemd. Run the daemon in the foreground with `ccwm serve` instead",
                )
            })
    }

    fn output(&self, args: &[&str]) -> Result<Output> {
        Command::new(&self.program)
            .arg("--user")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::io(format!("cannot run {}", self.program.display()), &e))
    }

    /// Run `systemctl --user <args>`; fail with its own message if it fails.
    pub fn run(&self, args: &[&str]) -> Result<()> {
        let out = self.output(args)?;
        if out.status.success() {
            return Ok(());
        }
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(Error::new(format!(
            "`systemctl --user {}` failed{}",
            args.join(" "),
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {msg}")
            }
        )))
    }

    /// The first line `systemctl --user <args>` prints (its exit status is ignored: `is-active`
    /// and `is-enabled` exit non-zero for "inactive"/"disabled").
    fn line(&self, args: &[&str]) -> Result<String> {
        let out = self.output(args)?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string())
    }

    /// `loaded`, `not-found`, … (from `systemctl --user show -p LoadState`).
    pub fn load_state(&self) -> Result<String> {
        let state = self.line(&["show", "-p", "LoadState", "--value", UNIT_NAME])?;
        if state.is_empty() {
            return Err(Error::new(
                "cannot reach the systemd user manager (`systemctl --user` printed nothing): is this a login session?",
            ));
        }
        Ok(state)
    }

    pub fn installed(&self) -> Result<bool> {
        Ok(self.load_state()? != "not-found")
    }

    /// Fail with the install hint unless the unit is known to the user manager.
    pub fn require_installed(&self) -> Result<()> {
        if self.installed()? {
            Ok(())
        } else {
            Err(Error::new(format!(
                "the {UNIT_NAME} user unit is not installed. Install it with `ccwm service install` (or scripts/install.sh), or run `ccwm serve` in the foreground"
            )))
        }
    }

    /// `active`, `inactive`, `failed`, … and `enabled`, `disabled`, ….
    pub fn states(&self) -> Result<(String, String)> {
        Ok((
            self.line(&["is-active", UNIT_NAME])?,
            self.line(&["is-enabled", UNIT_NAME])?,
        ))
    }
}

/// One line for `ccwm status` / `ccwm doctor`: the unit's state, or why it is unknown.
pub fn status_line(systemctl: &Result<Systemctl>) -> String {
    let s = match systemctl {
        Ok(s) => s,
        Err(_) => return "systemd: systemctl not found (service commands unavailable)".into(),
    };
    match s.installed() {
        Ok(false) => "systemd: ccwm.service not installed (`ccwm service install`)".into(),
        Ok(true) => match s.states() {
            Ok((active, enabled)) => format!("systemd: ccwm.service {active} ({enabled})"),
            Err(e) => format!("systemd: unknown ({e})"),
        },
        Err(e) => format!("systemd: unknown ({e})"),
    }
}

/// What `install` did, for the CLI to print.
#[derive(Debug, PartialEq, Eq)]
pub enum UnitWrite {
    Created,
    Updated,
    Unchanged,
}

/// Write the unit file (atomically, mode 0644) after checking that nobody else can replace it or
/// its directory: systemd runs what it names with your rights.
pub fn write_unit(dir: &Path, owner: &Owner) -> Result<UnitWrite> {
    owner.verify_trusted(dir)?;
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::io(format!("cannot create {}", dir.display()), &e))?;
    owner.verify_trusted(dir)?;
    let path = dir.join(UNIT_NAME);
    let text = unit_text();
    let old = std::fs::read_to_string(&path).ok();
    if old.as_deref() == Some(text.as_str()) {
        return Ok(UnitWrite::Unchanged);
    }
    let tmp = dir.join(format!("{UNIT_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| Error::io(format!("cannot install {}", path.display()), &e))?;
    Ok(if old.is_some() {
        UnitWrite::Updated
    } else {
        UnitWrite::Created
    })
}

/// Remove ccwm's own directories (configuration, database, state, runtime files) for
/// `uninstall --purge`. Each must be a real directory owned by `uid` (a symlink is removed as a
/// link, its target is left alone). Returns the directories removed. Never touches anything else.
pub fn purge_dirs(dirs: &Dirs, uid: u32) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    // The runtime directory may live inside the state directory (fallback): remove it first.
    for dir in [&dirs.runtime, &dirs.state, &dirs.data, &dirs.config] {
        let md = match std::fs::symlink_metadata(dir) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io(format!("cannot inspect {}", dir.display()), &e)),
        };
        if md.uid() != uid {
            return Err(Error::new(format!(
                "{} is not owned by you; not removing it",
                dir.display()
            )));
        }
        let result = if md.file_type().is_dir() {
            std::fs::remove_dir_all(dir)
        } else {
            std::fs::remove_file(dir)
        };
        result.map_err(|e| Error::io(format!("cannot remove {}", dir.display()), &e))?;
        removed.push(dir.clone());
    }
    Ok(removed)
}

/// Ask on the terminal; only the answer `yes` confirms.
pub fn confirm(prompt: &str, input: &mut dyn std::io::BufRead) -> bool {
    crate::cli::err!("{prompt} Type 'yes' to continue: ");
    let mut answer = String::new();
    input.read_line(&mut answer).is_ok() && answer.trim() == "yes"
}

/// `PATH` of this process (the systemctl lookup).
pub fn path_var() -> Option<OsString> {
    std::env::var_os("PATH")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_runs_the_installed_binary_and_never_restarts_on_the_dedicated_codes() {
        let u = unit_text();
        for want in [
            "ExecStart=%h/.local/bin/ccwm serve\n",
            "Restart=on-failure\n",
            "RestartSec=5\n",
            "RestartPreventExitStatus=10 11\n",
            "TimeoutStopSec=10\n",
            "UMask=0077\n",
            "Nice=10\n",
            "IOSchedulingClass=idle\n",
            "NoNewPrivileges=yes\n",
            "WantedBy=default.target\n",
            "Type=exec\n",
        ] {
            assert!(u.contains(want), "{want:?} missing:\n{u}");
        }
        for never in [
            "PrivateDevices",
            "ProtectHome",
            "ProtectSystem",
            "MemoryDenyWriteExecute",
            "sudo",
        ] {
            assert!(!u.contains(never), "{never} in:\n{u}");
        }
        assert_eq!(EXIT_PORT_IN_USE, 10);
        assert_eq!(EXIT_ALREADY_RUNNING, 11);
    }

    #[test]
    fn unit_dir_follows_xdg_config_home_when_absolute() {
        let home = Path::new("/home/u");
        let mut env = EnvVars::default();
        assert_eq!(
            unit_dir(&env, home),
            Path::new("/home/u/.config/systemd/user")
        );
        env.xdg_config_home = Some("relative".into());
        assert_eq!(
            unit_dir(&env, home),
            Path::new("/home/u/.config/systemd/user")
        );
        env.xdg_config_home = Some("/x/cfg".into());
        assert_eq!(unit_dir(&env, home), Path::new("/x/cfg/systemd/user"));
    }

    #[test]
    fn writing_the_unit_is_atomic_idempotent_and_refuses_untrusted_directories() {
        let t = crate::paths::private_tempdir();
        let uid = nix::unistd::geteuid().as_raw();
        let owner = Owner::current(uid);
        let dir = t.path().join("systemd/user");
        assert_eq!(write_unit(&dir, &owner).unwrap(), UnitWrite::Created);
        let path = dir.join(UNIT_NAME);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), unit_text());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        assert_eq!(write_unit(&dir, &owner).unwrap(), UnitWrite::Unchanged);
        std::fs::write(&path, "old").unwrap();
        assert_eq!(write_unit(&dir, &owner).unwrap(), UnitWrite::Updated);
        assert!(!dir.join(format!("{UNIT_NAME}.tmp")).exists());

        use std::os::unix::fs::PermissionsExt;
        let open = t.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = write_unit(&open.join("systemd/user"), &owner).unwrap_err();
        assert!(err.to_string().contains("modified by other users"), "{err}");
        assert!(!open.join("systemd").exists());
    }

    #[test]
    fn purge_removes_only_ccwms_own_directories() {
        let t = crate::paths::private_tempdir();
        let uid = nix::unistd::geteuid().as_raw();
        let base = t.path();
        let dirs = Dirs {
            config: base.join("config/ccwm"),
            data: base.join("data/ccwm"),
            state: base.join("state/ccwm"),
            runtime: base.join("state/ccwm/run"),
        };
        for d in dirs.all() {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f"), "x").unwrap();
        }
        std::fs::write(base.join("data/keep"), "x").unwrap();
        let removed = purge_dirs(&dirs, uid).unwrap();
        assert_eq!(removed.len(), 4);
        for d in dirs.all() {
            assert!(!d.exists(), "{}", d.display());
        }
        assert!(base.join("data/keep").exists() && base.join("config").exists());
        assert!(purge_dirs(&dirs, uid).unwrap().is_empty(), "idempotent");

        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("precious"), "x").unwrap();
        std::os::unix::fs::symlink(&target, &dirs.data).unwrap();
        assert_eq!(purge_dirs(&dirs, uid).unwrap(), vec![dirs.data.clone()]);
        assert!(
            target.join("precious").exists(),
            "a symlink's target is never removed"
        );
        std::fs::create_dir_all(&dirs.config).unwrap();
        let err = purge_dirs(&dirs, uid + 1).unwrap_err();
        assert!(err.to_string().contains("not owned by you"), "{err}");
        assert!(
            dirs.config.exists(),
            "a directory of another owner is left alone"
        );
    }

    #[test]
    fn only_yes_confirms() {
        for (input, want) in [
            ("yes\n", true),
            ("yes", true),
            (" yes \n", true),
            ("y\n", false),
            ("YES\n", false),
            ("", false),
        ] {
            assert_eq!(confirm("Purge?", &mut input.as_bytes()), want, "{input:?}");
        }
    }

    /// The hint depends on the host's lingering state, so both states are checked here, where
    /// the state is an argument (the service test can only see the state of the machine it
    /// runs on: off on a developer machine, on for a CI runner's user).
    #[test]
    fn the_boot_hint_is_given_unless_lingering_is_already_enabled() {
        assert_eq!(linger_hint(Some(true), Some("alice")), None);
        for linger in [Some(false), None] {
            let hint = linger_hint(linger, Some("alice")).unwrap();
            assert!(
                hint.contains("`loginctl enable-linger alice`")
                    && hint.contains("administrator authorization"),
                "{hint}"
            );
        }
        let hint = linger_hint(Some(false), None).unwrap();
        assert!(hint.contains("`loginctl enable-linger $USER`"), "{hint}");
    }

    #[test]
    fn the_linger_check_reads_the_linger_directory() {
        assert_eq!(linger_enabled(None), None);
        assert_eq!(
            linger_enabled(Some("ccwm-surely-no-such-user")),
            Some(false)
        );
    }
}
