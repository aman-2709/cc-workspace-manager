//! Startup / CLI errors and their process exit codes. HTTP and socket errors live in `api_error`.

use std::fmt;

/// Process exit codes. The two dedicated codes are listed in the systemd unit's
/// `RestartPreventExitStatus=`, so systemd does not restart-loop on them (REQUIREMENTS.md §13).
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
/// The configured TCP port is used by another process.
pub const EXIT_PORT_IN_USE: i32 = 10;
/// Another daemon holds the instance lock.
pub const EXIT_ALREADY_RUNNING: i32 = 11;

#[derive(Debug)]
pub struct Error {
    message: String,
    exit_code: i32,
    not_running: bool,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_ERROR,
            not_running: false,
        }
    }

    /// No daemon answers (yet): its runtime directory or socket is absent, or nothing listens.
    /// The CLI waits a little for a daemon that is still starting.
    pub fn not_running(message: impl Into<String>) -> Self {
        Self {
            not_running: true,
            ..Self::new(message)
        }
    }

    pub fn is_not_running(&self) -> bool {
        self.not_running
    }

    /// An error that maps to a specific process exit code ([`EXIT_PORT_IN_USE`], [`EXIT_ALREADY_RUNNING`]).
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = code;
        self
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// Wrap an I/O error with what we were trying to do (never include secrets here).
    pub fn io(context: impl fmt::Display, source: &std::io::Error) -> Self {
        Self::new(format!("{context}: {source}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
