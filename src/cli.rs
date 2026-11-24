//! Command-line interface.

use crate::client;
use crate::daemon::{self, ServeArgs};
use crate::error::{Error, Result};
use crate::paths::{current_home, Dirs, EnvVars, Owner};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const NOTICE: &str = "CC Workspace Manager is an independent, unofficial open-source project. \
It is not affiliated with or endorsed by Anthropic.";

#[derive(Debug, Parser)]
#[command(
    name = "ccwm",
    version,
    about = "Discover, track, and resume your Claude Code projects.",
    after_help = NOTICE,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon in the foreground (this is what systemd runs).
    Serve {
        /// TCP port on 127.0.0.1 (default 8765, or [server] port in the config file).
        #[arg(long)]
        port: Option<u16>,
        /// Path to config.toml (default: $XDG_CONFIG_HOME/ccwm/config.toml).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Open the dashboard in your browser, signed in via a single-use link.
    Open {
        /// Print the URL instead of opening a browser.
        #[arg(long)]
        print: bool,
    },
    /// Show the running daemon's state (verified over the Unix socket).
    Status,
    /// Ask the daemon to rescan now and wait until the scan has finished.
    Scan,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { port, config } => {
            daemon::init_logging();
            daemon::serve(&ServeArgs { port, config })
        }
        Command::Open { print } => open(print),
        Command::Status => status(),
        Command::Scan => scan(),
    }
}

/// The daemon's socket after verifying the runtime directory (no TCP, ever).
fn daemon_socket() -> Result<(std::path::PathBuf, u32)> {
    let uid = nix::unistd::geteuid().as_raw();
    let home = current_home(uid)?;
    let dirs = Dirs::resolve(&EnvVars::from_process(), &home);
    dirs.verify_runtime(&Owner::current(uid))?;
    Ok((dirs.socket_path(), uid))
}

fn status() -> Result<()> {
    let (socket, uid) = daemon_socket()?;
    let st = client::call(&socket, uid, "service.status")?;
    print!("{}", format_status(&st));
    if let Some(warning) = commit_mismatch(st.get("commit").and_then(|v| v.as_str())) {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

/// A warning when the daemon was built from a different commit than this CLI.
pub fn commit_mismatch(daemon: Option<&str>) -> Option<String> {
    let ours = crate::service::COMMIT;
    match daemon {
        Some(theirs) if theirs == ours && ours != "unknown" => None,
        Some(theirs) => Some(format!(
            "the running daemon was built from commit {theirs}, this ccwm from {ours}; restart the daemon to run the same build"
        )),
        None => Some(format!(
            "the running daemon does not report its build commit (this ccwm is {ours}); restart it"
        )),
    }
}

fn s<'a>(v: &'a serde_json::Value, path: &str) -> std::borrow::Cow<'a, str> {
    match v.pointer(path) {
        Some(serde_json::Value::String(x)) => x.as_str().into(),
        Some(serde_json::Value::Null) | None => "unknown".into(),
        Some(other) => other.to_string().into(),
    }
}

/// A Unix time from the status as local date and time ("unknown" when absent).
fn when(v: &serde_json::Value, path: &str) -> String {
    v.pointer(path)
        .and_then(serde_json::Value::as_i64)
        .and_then(|t| jiff::Timestamp::from_second(t).ok())
        .map_or_else(
            || "unknown".to_string(),
            |t| {
                t.to_zoned_datetime(
                    jiff::tz::TimeZone::try_system().unwrap_or(jiff::tz::TimeZone::UTC),
                )
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string()
            },
        )
}

/// Human-readable summary of `service.status` (systemd state arrives with `ccwm start`, M4).
pub fn format_status(v: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "ccwm daemon {} (commit {}) running, port {}, up {}s\n",
        s(v, "/version"),
        s(v, "/commit"),
        s(v, "/port"),
        s(v, "/uptime_s")
    ));
    out.push_str(&format!(
        "  discovery: {}, last scan {}, next scan {}\n",
        s(v, "/discovery/phase"),
        when(v, "/discovery/last_success_at"),
        when(v, "/discovery/next_scan_at")
    ));
    out.push_str(&format!(
        "  monitoring: {}, {} watches (budget {}), {} watched / {} polled projects{}\n",
        s(v, "/monitoring/watcher"),
        s(v, "/monitoring/watches"),
        s(v, "/monitoring/budget"),
        s(v, "/monitoring/watched_projects"),
        s(v, "/monitoring/polled_projects"),
        if v.pointer("/monitoring/degraded") == Some(&serde_json::Value::Bool(true)) {
            " (DEGRADED)"
        } else {
            ""
        }
    ));
    if let Some(advice) = v.pointer("/monitoring/advice").and_then(|a| a.as_array()) {
        for a in advice.iter().filter_map(|a| a.as_str()) {
            out.push_str(&format!("    ! {a}\n"));
        }
    }
    out.push_str(&format!(
        "  git: {} {} (hardened status: {})\n",
        s(v, "/git/program"),
        s(v, "/git/version"),
        s(v, "/git/hardened_status")
    ));
    out.push_str(&format!(
        "  sandbox: {} (abi {}, filesystem {}, network {})\n",
        s(v, "/sandbox/status"),
        s(v, "/sandbox/abi"),
        s(v, "/sandbox/filesystem"),
        s(v, "/sandbox/network")
    ));
    out
}

/// How long `ccwm scan` waits for the scan to finish.
const SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

fn scan() -> Result<()> {
    let (socket, uid) = daemon_socket()?;
    let accepted = client::call(&socket, uid, "scan.refresh")?;
    let target = accepted
        .get("done_at_scans_finished")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::new("the daemon's response was incomplete"))?;
    println!("Scan requested.");
    let deadline = std::time::Instant::now() + SCAN_WAIT;
    let mut last_line = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let st = client::call(&socket, uid, "discovery.status")?;
        let phase = st.get("phase").and_then(|v| v.as_str()).unwrap_or("");
        let finished = st.get("scans_finished").and_then(serde_json::Value::as_u64);
        let line = format!(
            "{phase}: {} folders checked, {} projects found",
            s(&st, "/dirs_visited"),
            s(&st, "/projects_found")
        );
        if line != last_line {
            println!("{line}");
            last_line = line;
        }
        if finished.is_some_and(|n| n >= target) {
            println!("Scan finished.");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(
                "the scan did not finish within 10 minutes (it keeps running in the daemon)",
            ));
        }
    }
}

fn open(print_only: bool) -> Result<()> {
    let (socket, uid) = daemon_socket()?;
    let issued = client::call(&socket, uid, "auth.bootstrap")?;
    let token = issued.get("bootstrap_token").and_then(|v| v.as_str());
    let port = issued
        .get("port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok());
    let (Some(token), Some(port)) = (token, port) else {
        return Err(Error::new("the daemon's response was incomplete"));
    };
    let url = format!("http://127.0.0.1:{port}/#bt={token}");
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    if print_only || !has_display {
        println!("{url}");
        return Ok(());
    }
    // The single-use link stays out of the terminal when a browser could be launched.
    match std::process::Command::new("xdg-open")
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => {
            println!(
                "Opening the dashboard in your browser (the sign-in link is single-use and expires in {} seconds).",
                crate::auth::bootstrap::BOOTSTRAP_TTL_SECS
            );
            Ok(())
        }
        Err(_) => {
            println!("{url}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_carries_the_unofficial_notice() {
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("independent, unofficial")
                && help.contains("not affiliated with or endorsed by Anthropic")
        );
    }

    #[test]
    fn parses_serve_and_open() {
        let c = Cli::try_parse_from(["ccwm", "serve", "--port", "9000", "--config", "/x/c.toml"])
            .unwrap();
        assert!(matches!(
            c.command,
            Command::Serve {
                port: Some(9000),
                config: Some(_)
            }
        ));
        let c = Cli::try_parse_from(["ccwm", "open", "--print"]).unwrap();
        assert!(matches!(c.command, Command::Open { print: true }));
        assert!(matches!(
            Cli::try_parse_from(["ccwm", "status"]).unwrap().command,
            Command::Status
        ));
        assert!(matches!(
            Cli::try_parse_from(["ccwm", "scan"]).unwrap().command,
            Command::Scan
        ));
        assert!(Cli::try_parse_from(["ccwm", "serve", "--port", "99999"]).is_err());
        assert!(Cli::try_parse_from(["ccwm", "bogus"]).is_err());
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn commit_mismatch_warns_unless_both_builds_are_known_and_equal() {
        let ours = crate::service::COMMIT;
        if ours != "unknown" {
            assert_eq!(commit_mismatch(Some(ours)), None);
        }
        let w = commit_mismatch(Some("0000000000aa")).unwrap();
        assert!(w.contains("0000000000aa") && w.contains(ours) && w.contains("restart"));
        assert!(commit_mismatch(None).unwrap().contains("does not report"));
        assert!(commit_mismatch(Some("unknown")).is_some() || ours == "unknown");
    }

    #[test]
    fn status_text_shows_the_key_facts_and_unknowns_as_unknown() {
        let v = serde_json::json!({
            "version": "0.1.0", "commit": "abc", "port": 8765, "uptime_s": 5,
            "discovery": {"phase": "idle", "last_success_at": null, "next_scan_at": 10},
            "monitoring": {"watcher": "inotify", "watches": 3, "budget": 8192, "watched_projects": 2,
                           "polled_projects": 1, "degraded": true, "advice": ["raise it"]},
            "git": {"program": "/usr/bin/git", "version": "2.43.0", "hardened_status": true},
            "sandbox": {"status": "fully_enforced", "abi": 8, "filesystem": true, "network": "tcp_only"}
        });
        let t = format_status(&v);
        for want in [
            "commit abc",
            "port 8765",
            "last scan unknown",
            "(DEGRADED)",
            "! raise it",
            "2.43.0",
            "tcp_only",
        ] {
            assert!(t.contains(want), "{want} in {t}");
        }
    }
}
