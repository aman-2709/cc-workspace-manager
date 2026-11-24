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
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { port, config } => {
            daemon::init_logging();
            daemon::serve(&ServeArgs { port, config })
        }
        Command::Open { print } => open(print),
    }
}

fn open(print_only: bool) -> Result<()> {
    let uid = nix::unistd::geteuid().as_raw();
    let home = current_home(uid)?;
    let dirs = Dirs::resolve(&EnvVars::from_process(), &home);
    dirs.verify_runtime(&Owner::current(uid))?;
    let issued = client::call(&dirs.socket_path(), uid, "auth.bootstrap")?;
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
        assert!(Cli::try_parse_from(["ccwm", "serve", "--port", "99999"]).is_err());
        assert!(Cli::try_parse_from(["ccwm", "bogus"]).is_err());
    }
}
