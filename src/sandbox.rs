//! Landlock self-sandbox (REQUIREMENTS.md §11.5).
//!
//! `apply` must run on the main thread **before any other thread exists**: `landlock_restrict_self`
//! confines only the calling thread and the threads/processes it creates afterwards. The ruleset is
//! inherited by child processes (git, `claude --version`). The returned [`SandboxReport`] states what
//! is actually enforced, never what was requested.

use crate::error::{Error, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// ABI we design against: filesystem rules (V1–V3) and TCP bind/connect (V4). Newer kernels are
/// used in best-effort mode but we do not request newer access rights (e.g. device ioctls).
const TARGET_ABI: ABI = ABI::V4;

/// System locations the daemon and its children (git, claude) need to read and execute.
pub const SYSTEM_READ_PATHS: [&str; 7] =
    ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin", "/proc"];

#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Readable and executable (discovery roots, session dir, system paths, config dir).
    pub read: Vec<PathBuf>,
    /// Readable and writable (ccwm's own config/data/state/runtime directories).
    pub read_write: Vec<PathBuf>,
    /// The only TCP port the process may bind (`None`/`0`: any bind is denied or, for 0, ephemeral).
    pub tcp_bind_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SandboxReport {
    /// Landlock ABI version the running kernel supports (as understood by this build); `None` if unavailable.
    pub abi: Option<u8>,
    /// `fully_enforced`, `partially_enforced` or `not_enforced`.
    pub status: &'static str,
    /// Filesystem access is confined (writes only under ccwm's directories; reads only under the allowed paths).
    pub filesystem: bool,
    /// All TCP `connect` is denied and TCP `bind` is limited to the configured port.
    pub network: bool,
    pub no_new_privs: bool,
    pub notes: Vec<String>,
}

impl SandboxReport {
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            abi: None,
            status: "not_enforced",
            filesystem: false,
            network: false,
            no_new_privs: false,
            notes: vec![reason.into()],
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "landlock {}: abi={} filesystem={} network={}{}",
            self.status,
            self.abi
                .map_or_else(|| "none".to_string(), |a| a.to_string()),
            self.filesystem,
            self.network,
            if self.notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", self.notes.join("; "))
            }
        )
    }
}

fn rw_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::MakeSock
        | AccessFs::Truncate
        | AccessFs::Refer
}

fn err<E: std::fmt::Display>(what: &str, e: E) -> Error {
    Error::new(format!("landlock: {what}: {e}"))
}

/// Build and enforce the ruleset on the calling thread. Paths that do not exist are skipped.
pub fn apply(policy: &Policy) -> Result<SandboxReport> {
    let abi = TARGET_ABI;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| err("handle fs access", e))?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|e| err("handle net access", e))?
        .create()
        .map_err(|e| err("create ruleset", e))?;

    for (paths, access) in [
        (&policy.read, AccessFs::from_read(abi)),
        (&policy.read_write, rw_access()),
    ] {
        for path in paths {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(|e| err(&format!("allow {}", path.display()), e))?;
            }
        }
    }
    if let Ok(fd) = PathFd::new("/dev/null") {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                fd,
                AccessFs::ReadFile | AccessFs::WriteFile,
            ))
            .map_err(|e| err("allow /dev/null", e))?;
    }
    if let Some(port) = policy.tcp_bind_port {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::BindTcp))
            .map_err(|e| err("allow tcp bind", e))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| err("restrict self", e))?;
    Ok(report_from(
        status.ruleset,
        status.landlock,
        status.no_new_privs,
    ))
}

fn report_from(
    ruleset: RulesetStatus,
    landlock: LandlockStatus,
    no_new_privs: bool,
) -> SandboxReport {
    let abi = match landlock {
        LandlockStatus::Available { effective_abi, .. } => Some(effective_abi as u8),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => None,
    };
    let enforced = !matches!(ruleset, RulesetStatus::NotEnforced);
    let status = match ruleset {
        RulesetStatus::FullyEnforced => "fully_enforced",
        RulesetStatus::PartiallyEnforced => "partially_enforced",
        RulesetStatus::NotEnforced => "not_enforced",
    };
    let network = enforced && abi.is_some_and(|a| a >= 4);
    let mut notes = Vec::new();
    if !enforced {
        notes.push("Landlock is unavailable or disabled on this kernel: no filesystem or network confinement".to_string());
    } else if !network {
        notes.push(
            "TCP confinement needs Landlock ABI 4 (Linux 6.7+): network access is not restricted"
                .to_string(),
        );
    }
    SandboxReport {
        abi,
        status,
        filesystem: enforced,
        network,
        no_new_privs,
        notes,
    }
}

/// Convenience: the allow-list for the daemon (§11.5).
pub fn daemon_policy(
    roots: &[PathBuf],
    session_dir: &Path,
    config_file_dir: Option<&Path>,
    dirs: &crate::paths::Dirs,
    tcp_port: u16,
) -> Policy {
    let mut read: Vec<PathBuf> = SYSTEM_READ_PATHS.iter().map(PathBuf::from).collect();
    read.extend(roots.iter().cloned());
    read.push(session_dir.to_path_buf());
    read.extend(config_file_dir.map(Path::to_path_buf));
    Policy {
        read,
        read_write: dirs.all().iter().map(|p| p.to_path_buf()).collect(),
        tcp_bind_port: Some(tcp_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_for_full_enforcement_on_abi4() {
        let r = report_from(
            RulesetStatus::FullyEnforced,
            LandlockStatus::Available {
                effective_abi: ABI::V4,
                kernel_abi: None,
            },
            true,
        );
        assert_eq!(
            (r.status, r.filesystem, r.network, r.abi),
            ("fully_enforced", true, true, Some(4))
        );
        assert!(r.notes.is_empty());
    }

    #[test]
    fn report_never_claims_network_on_old_abi() {
        let r = report_from(
            RulesetStatus::PartiallyEnforced,
            LandlockStatus::Available {
                effective_abi: ABI::V3,
                kernel_abi: None,
            },
            true,
        );
        assert!(r.filesystem && !r.network);
        assert!(r.notes[0].contains("ABI 4"));
    }

    #[test]
    fn report_for_unavailable_landlock_claims_nothing() {
        let r = report_from(
            RulesetStatus::NotEnforced,
            LandlockStatus::NotImplemented,
            false,
        );
        assert_eq!(
            (r.status, r.filesystem, r.network, r.abi),
            ("not_enforced", false, false, None)
        );
        assert!(r.summary().contains("unavailable"));
    }

    #[test]
    fn daemon_policy_contents() {
        let dirs =
            crate::paths::Dirs::resolve(&crate::paths::EnvVars::default(), Path::new("/home/u"));
        let p = daemon_policy(
            &[PathBuf::from("/home/u")],
            Path::new("/home/u/.claude"),
            Some(Path::new("/etc/x")),
            &dirs,
            8765,
        );
        assert!(
            p.read.contains(&PathBuf::from("/usr")) && p.read.contains(&PathBuf::from("/home/u"))
        );
        assert!(
            p.read.contains(&PathBuf::from("/home/u/.claude"))
                && p.read.contains(&PathBuf::from("/etc/x"))
        );
        assert_eq!(p.read_write.len(), 4);
        assert!(!p.read_write.contains(&PathBuf::from("/home/u")));
        assert_eq!(p.tcp_bind_port, Some(8765));
    }
}
