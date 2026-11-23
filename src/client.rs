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
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

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
            Error::new(format!(
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
    }
}
