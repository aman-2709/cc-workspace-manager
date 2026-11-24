//! Startup / CLI errors and their process exit codes. HTTP and socket errors live in `api_error`.

use std::fmt;

/// Process exit codes. M4 adds dedicated codes for "port in use" and "already running".
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;

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

    /// An error that maps to a specific process exit code (M4: port in use, already running).
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
