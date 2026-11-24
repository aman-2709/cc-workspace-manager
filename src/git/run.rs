//! Run one child process with a timeout and bounded output. The child gets its own process group,
//! so a timeout kills it **and** anything it started (e.g. a helper a malicious config managed to
//! launch). Blocking: call from a blocking thread.

use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How often the exit status is polled while waiting.
const POLL: Duration = Duration::from_millis(5);
/// stderr is only inspected for a few known messages.
const MAX_STDERR: usize = 64 * 1024;

#[derive(Debug)]
pub struct Output {
    /// `None` if the process was killed by a signal.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug)]
pub enum RunError {
    Spawn(io::Error),
    Timeout,
    /// stdout exceeded the limit; the process group was killed.
    TooLarge,
}

/// Read at most `cap` bytes; set `over` (and stop reading) if there is more.
fn capped_reader<R: Read + Send + 'static>(
    mut r: R,
    cap: usize,
    over: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() + n > cap {
                        over.store(true, Ordering::Relaxed);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
        buf
    })
}

/// Spawn `cmd` (stdin closed, stdout/stderr captured) in a new process group and wait at most
/// `timeout`. On timeout or oversized output the whole group gets `SIGKILL`.
pub fn run(mut cmd: Command, timeout: Duration, max_stdout: usize) -> Result<Output, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn().map_err(RunError::Spawn)?;
    let pgid = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| RunError::Spawn(io::Error::other("pid out of range")))?;
    let too_large = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .map(|s| capped_reader(s, max_stdout, Arc::clone(&too_large)));
    let stderr = child
        .stderr
        .take()
        .map(|s| capped_reader(s, MAX_STDERR, Arc::new(AtomicBool::new(false))));

    let deadline = Instant::now() + timeout;
    let mut failure = None;
    // Wait without reaping (WNOWAIT): while the exited child is a zombie its pid, and so the
    // process-group id, cannot be reused, so the killpg below can only reach our own leftovers.
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    while let Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) = waitid(Id::Pid(pgid), flags) {
        if too_large.load(Ordering::Relaxed) {
            failure = Some(RunError::TooLarge);
        } else if Instant::now() >= deadline {
            failure = Some(RunError::Timeout);
        }
        if failure.is_some() {
            break;
        }
        thread::sleep(POLL);
    }
    // Kill the group (on timeout: git and its children; otherwise: anything git left behind, which
    // could hold the pipes open), then reap.
    let _ = killpg(pgid, Signal::SIGKILL);
    let status = child.wait().ok();
    let stdout = stdout.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = stderr.and_then(|h| h.join().ok()).unwrap_or_default();
    if let Some(f) = failure {
        return Err(f);
    }
    if too_large.load(Ordering::Relaxed) {
        return Err(RunError::TooLarge);
    }
    Ok(Output {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn captures_output_and_exit_code() {
        let out = run(
            sh("printf out; printf err >&2; exit 3"),
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert_eq!(
            (out.code, out.stdout.as_slice(), out.stderr.as_slice()),
            (Some(3), &b"out"[..], &b"err"[..])
        );
        assert!(!out.success());
    }

    #[test]
    fn a_timeout_kills_the_whole_process_group() {
        let t = tempfile::tempdir().unwrap();
        let marker = t.path().join("survived");
        let started = Instant::now();
        // The background grandchild would create the marker after 1.5 s unless it is killed too.
        let script = format!("(sleep 1.5; touch '{}') & sleep 30", marker.display());
        let r = run(sh(&script), Duration::from_millis(300), 1024);
        assert!(matches!(r, Err(RunError::Timeout)), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1800));
        assert!(!marker.exists(), "a grandchild outlived the timeout kill");
    }

    #[test]
    fn oversized_output_is_refused() {
        let r = run(sh("yes x | head -c 100000"), Duration::from_secs(5), 1000);
        assert!(matches!(r, Err(RunError::TooLarge)), "{r:?}");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let r = run(
            Command::new("/nonexistent/ccwm-no-such-git"),
            Duration::from_secs(1),
            10,
        );
        assert!(matches!(r, Err(RunError::Spawn(_))));
    }
}
