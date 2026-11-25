//! `config.toml` model. Read at startup only (§14); unknown keys are errors so typos fail loudly.

use crate::error::{Error, Result};
use crate::paths::Owner;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_PORT: u16 = 8765;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub discovery: DiscoveryConfig,
    pub watch: WatchConfig,
    pub activity: ActivityConfig,
    pub git: GitConfig,
    pub sessions: SessionsConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// 0 (ephemeral, for tests) or 1024..=65535.
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { port: DEFAULT_PORT }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfig {
    /// Absolute directories; empty means the user's home directory.
    pub roots: Vec<PathBuf>,
    /// Extra gitignore-syntax patterns, relative to each root.
    pub exclude: Vec<String>,
    pub max_depth: usize,
    pub same_file_system: bool,
    /// Seconds between background reconciliation scans (§4.5).
    pub scan_interval_secs: u64,
    /// Missing projects are purged after this many days (§4.5).
    pub missing_retention_days: u32,
    /// "Scan entire home": walk every root at every reconciliation. Off: the first
    /// reconciliation ever walks everything, later ones only the development roots (§4.5).
    pub full_scan: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude: Vec::new(),
            max_depth: 10,
            same_file_system: true,
            scan_interval_secs: 600,
            missing_retention_days: 30,
            full_scan: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct WatchConfig {
    /// Maximum inotify watches; 0 = automatic: 25 % of `max_user_watches` (§5.1).
    pub budget: u32,
    /// File events of one project are coalesced for this long (§5.1).
    pub debounce_ms: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            budget: 0,
            debounce_ms: 2000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ActivityConfig {
    /// Calendar days since the last modification from which a project is *inactive* (§5.3).
    pub inactive_after_days: u32,
    /// Calendar days from which a project is *dormant*.
    pub dormant_after_days: u32,
    /// Recent file events kept per project (§5.2).
    pub events_per_project: u32,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        Self {
            inactive_after_days: 7,
            dormant_after_days: 30,
            events_per_project: 200,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct GitConfig {
    /// Run worktree `git status` even when Git is too old (< 2.41.0) to pass `--attr-source`,
    /// i.e. without the filter-driver protection of §6. Off by default.
    pub allow_unhardened_status: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct SessionsConfig {
    /// Claude Code's config directory (sessions are under `projects/`). Unset:
    /// `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
    /// Cache the last prompt (redacted) in ccwm's database. Off by default: prompts are read
    /// from the session file each time the detail panel opens (§7.3).
    pub store_prompt_text: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    /// `cards` or `table` (a browser's own choice wins).
    pub default_view: String,
    /// `system`, `light` or `dark` (a browser's own choice wins).
    pub theme: String,
    /// Privacy mode for browsers that have not chosen yet.
    pub privacy: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            default_view: "cards".into(),
            theme: "system".into(),
            privacy: false,
        }
    }
}

pub fn validate_port(port: u16) -> Result<()> {
    if port != 0 && port < 1024 {
        return Err(Error::new(format!(
            "port {port} is not allowed: use 0 (ephemeral) or 1024-65535"
        )));
    }
    Ok(())
}

impl Config {
    /// The file as `PUT /settings` writes it: TOML with a header (comments are not preserved).
    pub fn to_toml(&self) -> Result<String> {
        let body =
            toml::to_string_pretty(self).map_err(|e| Error::new(format!("encode config: {e}")))?;
        Ok(format!(
            "# CC Workspace Manager configuration, written by the Settings page.\n# See config.example.toml for every key; comments are not preserved.\n\n{body}"
        ))
    }

    /// Write `path` atomically (`<path>.tmp`, mode 0600, fsync, rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let text = self.to_toml()?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| Error::io(format!("cannot write {}", tmp.display()), &e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| Error::io(format!("cannot replace {}", path.display()), &e))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config =
            toml::from_str(text).map_err(|e| Error::new(format!("invalid config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// A missing file means defaults; any other problem is an error. The file and every
    /// directory above it must be trusted by `owner` (no other user can modify or replace them):
    /// the config chooses the discovery roots and the port.
    pub fn load(path: &Path, owner: &Owner) -> Result<Self> {
        let md = match std::fs::metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(Error::io(
                    format!("cannot read config {}", path.display()),
                    &e,
                ))
            }
        };
        if !md.is_file() || md.len() > MAX_CONFIG_BYTES {
            return Err(Error::new(format!(
                "config {} must be a regular file smaller than {MAX_CONFIG_BYTES} bytes",
                path.display()
            )));
        }
        owner
            .verify_trusted(path)
            .map_err(|e| Error::new(format!("untrusted config file: {e}")))?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::io(format!("cannot read config {}", path.display()), &e))?;
        Self::parse(&text).map_err(|e| Error::new(format!("{} ({})", e, path.display())))
    }

    pub fn validate(&self) -> Result<()> {
        validate_port(self.server.port)?;
        let d = &self.discovery;
        if !(1..=64).contains(&d.max_depth) {
            return Err(Error::new("discovery.max_depth must be between 1 and 64"));
        }
        for root in &d.roots {
            if !root.is_absolute() {
                return Err(Error::new(format!(
                    "discovery.roots entry {} must be an absolute path",
                    root.display()
                )));
            }
        }
        for pattern in &d.exclude {
            if pattern.trim().is_empty() || pattern.len() > 256 || pattern.contains('\0') {
                return Err(Error::new(
                    "discovery.exclude entries must be 1-256 characters without NUL",
                ));
            }
        }
        crate::discovery::exclusions::validate_patterns(&d.exclude).map_err(Error::new)?;
        if !(60..=86_400).contains(&d.scan_interval_secs) {
            return Err(Error::new(
                "discovery.scan_interval_secs must be between 60 and 86400",
            ));
        }
        if !(1..=3650).contains(&d.missing_retention_days) {
            return Err(Error::new(
                "discovery.missing_retention_days must be between 1 and 3650",
            ));
        }
        let w = &self.watch;
        if w.budget > 1_048_576 {
            return Err(Error::new(
                "watch.budget must be 0 (automatic) or at most 1048576",
            ));
        }
        if !(100..=60_000).contains(&w.debounce_ms) {
            return Err(Error::new(
                "watch.debounce_ms must be between 100 and 60000",
            ));
        }
        let a = &self.activity;
        if !(1..a.dormant_after_days).contains(&a.inactive_after_days)
            || a.dormant_after_days > 3650
        {
            return Err(Error::new(
                "activity thresholds must satisfy 1 <= inactive_after_days < dormant_after_days <= 3650",
            ));
        }
        if !(1..=10_000).contains(&a.events_per_project) {
            return Err(Error::new(
                "activity.events_per_project must be between 1 and 10000",
            ));
        }
        if let Some(dir) = &self.sessions.dir {
            if !dir.is_absolute() {
                return Err(Error::new("sessions.dir must be an absolute path"));
            }
        }
        if !["cards", "table"].contains(&self.ui.default_view.as_str()) {
            return Err(Error::new("ui.default_view must be cards or table"));
        }
        if !["system", "light", "dark"].contains(&self.ui.theme.as_str()) {
            return Err(Error::new("ui.theme must be system, light or dark"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.server.port, 8765);
        assert!(c.discovery.roots.is_empty() && c.discovery.same_file_system);
        assert_eq!(c.discovery.max_depth, 10);
        assert_eq!(
            (
                c.discovery.scan_interval_secs,
                c.discovery.missing_retention_days
            ),
            (600, 30)
        );
        assert_eq!((c.watch.budget, c.watch.debounce_ms), (0, 2000));
        assert_eq!(
            (
                c.activity.inactive_after_days,
                c.activity.dormant_after_days,
                c.activity.events_per_project
            ),
            (7, 30, 200)
        );
        assert!(!c.git.allow_unhardened_status);
        assert!(!c.discovery.full_scan);
        assert_eq!(c.sessions, SessionsConfig::default());
        assert!(!c.sessions.store_prompt_text && c.sessions.dir.is_none());
        assert_eq!(
            (
                c.ui.default_view.as_str(),
                c.ui.theme.as_str(),
                c.ui.privacy
            ),
            ("cards", "system", false)
        );
    }

    #[test]
    fn saving_round_trips_and_is_private_and_atomic() {
        use std::os::unix::fs::PermissionsExt;
        let t = crate::paths::private_tempdir();
        let p = t.path().join("config.toml");
        let mut c = Config::default();
        c.discovery.roots = vec![
            PathBuf::from("/srv/code"),
            PathBuf::from("/home/u/it's here"),
        ];
        c.discovery.exclude = vec!["vendor/".into()];
        c.discovery.full_scan = true;
        c.sessions.store_prompt_text = true;
        c.sessions.dir = Some(PathBuf::from("/home/u/.claude-work"));
        c.ui.theme = "dark".into();
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p, &me()).unwrap(), c);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            format!("{}.tmp", crate::paths::CONFIG_NAME),
            crate::paths::CONFIG_TMP_NAME,
            "the staged name the hygiene test checks"
        );
        assert!(!t.path().join(crate::paths::CONFIG_TMP_NAME).exists());
        assert!(std::fs::read_to_string(&p)
            .unwrap()
            .starts_with("# CC Workspace Manager"));
        // The default config also round-trips (an absent sessions.dir stays absent).
        Config::default().save(&p).unwrap();
        assert_eq!(Config::load(&p, &me()).unwrap(), Config::default());
    }

    #[test]
    fn the_example_config_is_valid_and_matches_the_defaults() {
        let example = include_str!("../config.example.toml");
        assert_eq!(Config::parse(example).unwrap(), Config::default());
    }

    #[test]
    fn parses_m2_sections() {
        let c = Config::parse(
            "[discovery]\nscan_interval_secs = 120\nmissing_retention_days = 7\n[watch]\nbudget = 100\ndebounce_ms = 500\n[activity]\ninactive_after_days = 3\ndormant_after_days = 10\nevents_per_project = 50\n[git]\nallow_unhardened_status = true\n",
        )
        .unwrap();
        assert_eq!(c.discovery.scan_interval_secs, 120);
        assert_eq!(c.discovery.missing_retention_days, 7);
        assert_eq!((c.watch.budget, c.watch.debounce_ms), (100, 500));
        assert_eq!(
            (
                c.activity.inactive_after_days,
                c.activity.dormant_after_days
            ),
            (3, 10)
        );
        assert_eq!(c.activity.events_per_project, 50);
        assert!(c.git.allow_unhardened_status);
        assert!(Config::parse("[watch]\nrecursive = true").is_err());
        assert!(Config::parse("[git]\nallow = true").is_err());
    }

    #[test]
    fn parses_full_file() {
        let c = Config::parse(
            "[server]\nport = 9000\n[discovery]\nroots = [\"/srv/code\"]\nexclude = [\"vendor/\"]\nmax_depth = 4\nsame_file_system = false\n",
        )
        .unwrap();
        assert_eq!(c.server.port, 9000);
        assert_eq!(c.discovery.roots, vec![PathBuf::from("/srv/code")]);
        assert_eq!(c.discovery.exclude, vec!["vendor/".to_string()]);
        assert_eq!(
            (c.discovery.max_depth, c.discovery.same_file_system),
            (4, false)
        );
    }

    #[test]
    fn rejects_unknown_keys_at_every_level() {
        assert!(Config::parse("bogus = 1").is_err());
        assert!(Config::parse("[server]\nprot = 1").is_err());
        assert!(Config::parse("[discovery]\nfollow_symlinks = true").is_err());
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            "[server]\nport = 80",
            "[server]\nport = 70000",
            "[server]\nport = \"x\"",
            "[discovery]\nmax_depth = 0",
            "[discovery]\nmax_depth = 65",
            "[discovery]\nroots = [\"relative\"]",
            "[discovery]\nexclude = [\"\"]",
            "[discovery]\nexclude = [\"a\\u0000b\"]",
            "[discovery]\nexclude = [\"bad\\\\\"]",
            "[discovery]\nscan_interval_secs = 59",
            "[discovery]\nscan_interval_secs = 86401",
            "[discovery]\nmissing_retention_days = 0",
            "[watch]\nbudget = 2000000",
            "[watch]\ndebounce_ms = 99",
            "[activity]\ninactive_after_days = 0",
            "[activity]\ninactive_after_days = 30",
            "[activity]\ndormant_after_days = 5000",
            "[activity]\nevents_per_project = 0",
            "[sessions]\ndir = \"relative\"",
            "[sessions]\nstore = true",
            "[ui]\ndefault_view = \"grid\"",
            "[ui]\ntheme = \"blue\"",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn port_zero_is_allowed_for_ephemeral_binding() {
        assert!(Config::parse("[server]\nport = 0").is_ok());
        assert!(
            validate_port(0).is_ok() && validate_port(1023).is_err() && validate_port(1024).is_ok()
        );
    }

    /// Independent of the test process's umask (002 would make the file group-writable).
    fn private(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn me() -> Owner {
        Owner {
            uid: nix::unistd::geteuid().as_raw(),
            private_gid: None,
        }
    }

    #[test]
    fn load_rejects_a_config_file_other_users_can_modify() {
        use std::os::unix::fs::PermissionsExt;
        let t = crate::paths::private_tempdir();
        let p = t.path().join("c.toml");
        std::fs::write(&p, "[server]\nport = 9001\n").unwrap();
        for mode in [0o666, 0o646, 0o664] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = Config::load(&p, &me()).unwrap_err().to_string();
            assert!(err.contains("untrusted config"), "{mode:o}: {err}");
        }
        // Group write by the user's private group is not write by others.
        let gid = std::os::unix::fs::MetadataExt::gid(&std::fs::metadata(&p).unwrap());
        let private = Owner {
            private_gid: Some(gid),
            ..me()
        };
        assert_eq!(Config::load(&p, &private).unwrap().server.port, 9001);
        let foreign = Owner {
            uid: me().uid + 1,
            private_gid: None,
        };
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::load(&p, &foreign).is_err(), "owned by someone else");
    }

    #[test]
    fn load_missing_file_gives_defaults_and_bad_file_errors() {
        let t = crate::paths::private_tempdir();
        assert_eq!(
            Config::load(&t.path().join("none.toml"), &me()).unwrap(),
            Config::default()
        );
        let p = t.path().join("c.toml");
        std::fs::write(&p, "[server]\nport = 9001\n").unwrap();
        private(&p);
        assert_eq!(Config::load(&p, &me()).unwrap().server.port, 9001);
        std::fs::write(&p, "not toml [").unwrap();
        assert!(Config::load(&p, &me())
            .unwrap_err()
            .to_string()
            .contains("c.toml"));
        assert!(Config::load(t.path(), &me()).is_err()); // a directory is not a config file
    }
}
