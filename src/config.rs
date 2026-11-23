//! `config.toml` model. Read at startup only (§14); unknown keys are errors so typos fail loudly.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_PORT: u16 = 8765;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfig {
    /// Absolute directories; empty means the user's home directory.
    pub roots: Vec<PathBuf>,
    /// Extra gitignore-syntax patterns, relative to each root.
    pub exclude: Vec<String>,
    pub max_depth: usize,
    pub same_file_system: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude: Vec::new(),
            max_depth: 10,
            same_file_system: true,
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
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config =
            toml::from_str(text).map_err(|e| Error::new(format!("invalid config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// A missing file means defaults; any other problem is an error.
    pub fn load(path: &Path) -> Result<Self> {
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
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::io(format!("cannot read config {}", path.display()), &e))?;
        Self::parse(&text).map_err(|e| Error::new(format!("{} ({})", e, path.display())))
    }

    fn validate(&self) -> Result<()> {
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

    #[test]
    fn load_missing_file_gives_defaults_and_bad_file_errors() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::load(&t.path().join("none.toml")).unwrap(),
            Config::default()
        );
        let p = t.path().join("c.toml");
        std::fs::write(&p, "[server]\nport = 9001\n").unwrap();
        assert_eq!(Config::load(&p).unwrap().server.port, 9001);
        std::fs::write(&p, "not toml [").unwrap();
        assert!(Config::load(&p).unwrap_err().to_string().contains("c.toml"));
        assert!(Config::load(t.path()).is_err()); // a directory is not a config file
    }
}
