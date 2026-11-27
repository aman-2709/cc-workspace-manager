//! The CLI side of the Unix-socket channel. It never speaks TCP: an impostor on the HTTP port gets
//! nothing. Before sending a byte it verifies, via `SO_PEERCRED`, that the daemon runs as the
//! same user.

use crate::error::{Error, Result};
use crate::ipc::protocol::decode_response;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);
/// The longest response the CLI reads.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

pub fn verify_peer(peer_uid: u32, expected_uid: u32) -> Result<()> {
    if peer_uid != expected_uid {
        return Err(Error::new(format!(
            "refusing to talk to the process on the ccwm socket: it runs as uid {peer_uid}, not as you (uid {expected_uid})"
        )));
    }
    Ok(())
}

/// Send `{"op": op}` and return the `ok` payload.
pub fn call(socket: &Path, expected_uid: u32, op: &str) -> Result<Value> {
    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            Error::not_running(format!(
                "ccwm is not running (cannot reach {}). Start it with `ccwm serve`",
                socket.display()
            ))
        }
        _ => Error::io(format!("cannot connect to {}", socket.display()), &e),
    })?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| Error::io("socket setup", &e))?;
    let cred = getsockopt(&stream, PeerCredentials)
        .map_err(|e| Error::new(format!("cannot verify the daemon's identity: {e}")))?;
    verify_peer(cred.uid(), expected_uid)?;

    let request = format!("{}\n", json!({ "op": op }));
    stream
        .write_all(request.as_bytes())
        .map_err(|e| Error::io("cannot send the request", &e))?;
    let mut line = String::new();
    BufReader::new(stream.take(MAX_RESPONSE_BYTES))
        .read_line(&mut line)
        .map_err(|e| Error::io("cannot read the response", &e))?;
    decode_response(&line).map_err(Error::new)
}

/// The socket exchange of `ccwm hook` — connect, send, the daemon's acknowledgement — gets at
/// most this long (REQUIREMENTS.md §21.3).
pub const HOOK_BUDGET: Duration = Duration::from_millis(100);
const MAX_HOOK_RESPONSE_BYTES: usize = 4096;

/// What became of a hook event [`send_hook`] sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookSent {
    Accepted,
    /// The daemon refused it (`malformed`, `no_claude_ancestor`, `pid_mismatch`, `limit`).
    Refused(String),
    NotRunning,
    /// The budget ran out (a busy or stuck daemon, a full listen queue).
    TimedOut,
    Failed(String),
}

impl std::fmt::Display for HookSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted => f.write_str("accepted"),
            Self::Refused(why) => write!(f, "the ccwm daemon refused the event ({why})"),
            Self::NotRunning => f.write_str("the ccwm daemon is not running; the event is dropped"),
            Self::TimedOut => write!(
                f,
                "no answer from the ccwm daemon within {} ms; the event may be lost",
                HOOK_BUDGET.as_millis()
            ),
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// A Unix-socket connection that gives up after `timeout`. A blocking `connect()` on a Unix
/// socket waits while the listener's queue is full; `SO_SNDTIMEO` bounds that wait (it then
/// fails with `EAGAIN`).
fn connect_within(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    use nix::sys::socket::{
        connect, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
    };
    use nix::sys::time::TimeVal;
    use std::os::fd::AsRawFd;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let micros = i64::try_from(timeout.as_micros())
        .unwrap_or(i64::MAX)
        .max(1);
    setsockopt(
        &fd,
        sockopt::SendTimeout,
        &TimeVal::new(micros / 1_000_000, micros % 1_000_000),
    )?;
    connect(fd.as_raw_fd(), &UnixAddr::new(path)?)?;
    Ok(UnixStream::from(fd))
}

/// Send one `hook.event` line and read the daemon's one-line answer, all within `budget`
/// (§21.3): connect, verify the daemon's UID (`SO_PEERCRED`), write, read. Whatever happens, it
/// returns by the deadline; it never retries and never waits for a starting daemon.
pub fn send_hook(socket: &Path, expected_uid: u32, line: &str, budget: Duration) -> HookSent {
    let deadline = std::time::Instant::now() + budget;
    let left = || {
        deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
    };
    let Some(t) = left() else {
        return HookSent::TimedOut;
    };
    let mut stream = match connect_within(socket, t) {
        Ok(s) => s,
        Err(e) => {
            return match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    HookSent::NotRunning
                }
                _ if is_timeout(&e) => HookSent::TimedOut,
                _ => HookSent::Failed(format!("cannot connect to {}: {e}", socket.display())),
            }
        }
    };
    match getsockopt(&stream, PeerCredentials) {
        Ok(cred) => {
            if let Err(e) = verify_peer(cred.uid(), expected_uid) {
                return HookSent::Failed(e.to_string());
            }
        }
        Err(e) => return HookSent::Failed(format!("cannot verify the daemon's identity: {e}")),
    }
    let Some(t) = left() else {
        return HookSent::TimedOut;
    };
    if let Err(e) = stream
        .set_write_timeout(Some(t))
        .and_then(|()| stream.write_all(line.as_bytes()))
    {
        return if is_timeout(&e) {
            HookSent::TimedOut
        } else {
            HookSent::Failed(format!("cannot send the event: {e}"))
        };
    }
    let mut answer = Vec::new();
    let mut buf = [0u8; 512];
    while !answer.contains(&b'\n') {
        let Some(t) = left() else {
            return HookSent::TimedOut;
        };
        match stream
            .set_read_timeout(Some(t))
            .and_then(|()| stream.read(&mut buf))
        {
            Ok(0) => {
                return HookSent::Failed(
                    "the ccwm daemon closed the connection without an answer".into(),
                )
            }
            Ok(n) => answer.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if is_timeout(&e) => return HookSent::TimedOut,
            Err(e) => return HookSent::Failed(format!("cannot read the answer: {e}")),
        }
        if answer.len() > MAX_HOOK_RESPONSE_BYTES {
            return HookSent::Failed("the ccwm daemon's answer is too long".into());
        }
    }
    match decode_response(&String::from_utf8_lossy(&answer)) {
        Ok(v) if v.get("accepted") == Some(&Value::Bool(true)) => HookSent::Accepted,
        Ok(_) => HookSent::Failed("the ccwm daemon sent an unexpected answer".into()),
        Err(why) => HookSent::Refused(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_uid_must_match() {
        assert!(verify_peer(1000, 1000).is_ok());
        assert!(verify_peer(0, 1000)
            .unwrap_err()
            .to_string()
            .contains("uid 0"));
    }

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    const LINE: &str = "{\"op\":\"hook.event\"}\n";

    /// A listener that runs `serve` on its first connection, in a thread.
    fn listener(
        serve: impl FnOnce(UnixStream) + Send + 'static,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                serve(s);
            }
        });
        (dir, path)
    }

    fn timed(socket: &Path) -> (HookSent, Duration) {
        let started = std::time::Instant::now();
        let sent = send_hook(socket, uid(), LINE, HOOK_BUDGET);
        (sent, started.elapsed())
    }

    /// Within the budget plus scheduling slack, and clearly below the 1 s watchdog.
    fn within_budget(d: Duration) -> bool {
        d < HOOK_BUDGET + Duration::from_millis(150)
    }

    #[test]
    fn a_hook_event_without_a_daemon_returns_at_once() {
        let t = tempfile::tempdir().unwrap();
        let (sent, took) = timed(&t.path().join("none.sock"));
        assert_eq!(sent, HookSent::NotRunning);
        assert!(took < Duration::from_millis(50), "{took:?}");
        // A socket file nobody listens on.
        let path = t.path().join("dead.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert_eq!(timed(&path).0, HookSent::NotRunning);
    }

    #[test]
    fn a_daemon_that_never_answers_costs_the_budget_and_no_more() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (_d, path) = listener(move |mut s| {
            let mut line = String::new();
            let _ = BufReader::new(&mut s).read_line(&mut line);
            tx.send(line).unwrap();
            std::thread::sleep(Duration::from_secs(3)); // holds the connection, never answers
        });
        let (sent, took) = timed(&path);
        assert_eq!(sent, HookSent::TimedOut);
        assert!(
            took >= HOOK_BUDGET - Duration::from_millis(5) && within_budget(took),
            "{took:?}"
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            LINE,
            "the event was sent"
        );
    }

    #[test]
    fn a_full_listen_queue_costs_the_budget_and_no_more() {
        use nix::sys::socket::{
            bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.sock");
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            &UnixAddr::new(&path).unwrap(),
        )
        .unwrap();
        listen(&fd, Backlog::new(0).unwrap()).unwrap();
        // Never accepted: with a backlog of 0 one connection fills the queue.
        let _queued = UnixStream::connect(&path).unwrap();
        let (sent, took) = timed(&path);
        assert_eq!(sent, HookSent::TimedOut);
        assert!(within_budget(took), "{took:?}");
    }

    #[test]
    fn the_answer_decides_and_odd_answers_fail() {
        let answer = |reply: &'static [u8]| {
            let (_d, path) = listener(move |mut s| {
                let mut line = String::new();
                let _ = BufReader::new(&mut s).read_line(&mut line);
                let _ = s.write_all(reply);
                std::thread::sleep(Duration::from_millis(300));
            });
            timed(&path)
        };
        assert_eq!(
            answer(b"{\"ok\":{\"accepted\":true}}\n").0,
            HookSent::Accepted
        );
        // Split over several reads.
        assert_eq!(
            answer(b"{\"ok\":{\"accep").0,
            HookSent::TimedOut,
            "no newline yet"
        );
        assert_eq!(
            answer(b"{\"error\":{\"code\":\"invalid_argument\",\"message\":\"pid_mismatch\"}}\n").0,
            HookSent::Refused("pid_mismatch".into())
        );
        assert!(matches!(answer(b"{\"ok\":{}}\n").0, HookSent::Failed(_)));
        assert!(matches!(
            answer(b"junk\n").0,
            HookSent::Refused(_) | HookSent::Failed(_)
        ));
        let long: &'static [u8] = Box::leak(vec![b'x'; 10_000].into_boxed_slice());
        let (sent, took) = answer(long);
        assert!(
            matches!(sent, HookSent::Failed(ref w) if w.contains("too long")),
            "{sent:?}"
        );
        assert!(within_budget(took));
        // Closed without an answer, after reading the event or before it (then the write may
        // fail first: either way nothing was accepted).
        let (_d, path) = listener(|mut s| {
            let mut line = String::new();
            let _ = BufReader::new(&mut s).read_line(&mut line);
        });
        assert!(
            matches!(timed(&path).0, HookSent::Failed(ref w) if w.contains("without an answer"))
        );
        let (_d, path) = listener(drop);
        assert!(matches!(timed(&path).0, HookSent::Failed(_)));
    }

    #[test]
    fn a_hook_event_goes_only_to_a_daemon_of_the_same_user() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (_d, path) = listener(move |mut s| {
            let mut got = Vec::new();
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let _ = s.read_to_end(&mut got);
            tx.send(got).unwrap();
        });
        let sent = send_hook(&path, uid() + 1, LINE, HOOK_BUDGET);
        assert!(
            matches!(sent, HookSent::Failed(ref w) if w.contains("refusing")),
            "{sent:?}"
        );
        assert!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap().is_empty(),
            "nothing sent"
        );
    }

    #[test]
    fn missing_socket_gives_a_helpful_message() {
        let t = tempfile::tempdir().unwrap();
        let err = call(&t.path().join("none.sock"), 1000, "ping")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not running") && err.contains("ccwm serve"),
            "{err}"
        );
        assert!(call(&t.path().join("none.sock"), 1000, "ping")
            .unwrap_err()
            .is_not_running());
    }
}
