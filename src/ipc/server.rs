//! The daemon side of the Unix-socket channel. Every connection is authenticated with `SO_PEERCRED`
//! (the peer UID must equal the daemon's UID) before a single byte is read from it.

use super::protocol::{dispatch, encode_response, parse_request, MAX_REQUEST_BYTES};
use crate::api_error::ApiError;
use crate::error::{Error, Result};
use crate::service::Service;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Semaphore};

const READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONCURRENT: usize = 16;

pub fn peer_allowed(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

/// Bind the socket. The instance lock proves no live daemon owns it, so a stale socket file *that we
/// own* is removed; anything else at that path is an error.
pub fn bind(path: &Path, uid: u32) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() && md.uid() == uid => {
            fs::remove_file(path).map_err(|e| {
                Error::io(format!("cannot remove stale socket {}", path.display()), &e)
            })?;
        }
        Ok(_) => {
            return Err(Error::new(format!(
                "{} exists and is not a socket owned by you; refusing to replace it",
                path.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(format!("cannot inspect {}", path.display()), &e)),
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::io(format!("cannot bind socket {}", path.display()), &e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(format!("cannot chmod {}", path.display()), &e))?;
    Ok(listener)
}

/// Accept connections until `shutdown` flips to `true`.
pub async fn serve(
    listener: UnixListener,
    service: Arc<Service>,
    daemon_uid: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                    drop(stream); // too many concurrent clients: refuse
                    continue;
                };
                let service = Arc::clone(&service);
                tokio::spawn(async move {
                    handle(stream, &service, daemon_uid).await;
                    drop(permit);
                });
            }
        }
    }
}

async fn handle(stream: UnixStream, service: &Service, daemon_uid: u32) {
    match stream.peer_cred() {
        Ok(cred) if peer_allowed(cred.uid(), daemon_uid) => {}
        Ok(_) => {
            tracing::warn!("rejected a socket connection from a different user");
            return;
        }
        Err(_) => return,
    }
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES as u64 + 1));
    let mut line = Vec::new();
    let read = tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut line)).await;
    let result = match read {
        Ok(Ok(n)) if n > 0 && n <= MAX_REQUEST_BYTES && line.ends_with(b"\n") => {
            match std::str::from_utf8(&line) {
                Ok(text) => match parse_request(text) {
                    Ok(req) => {
                        tracing::trace!(op = ?req, "socket request");
                        dispatch(service, req).await
                    }
                    Err(e) => Err(e),
                },
                Err(_) => Err(ApiError::invalid("request is not valid UTF-8")),
            }
        }
        Ok(Ok(_)) => Err(ApiError::invalid("request too large or incomplete")),
        _ => return,
    };
    let mut out = encode_response(&result);
    out.push('\n');
    let _ = write_half.write_all(out.as_bytes()).await;
    let _ = write_half.shutdown().await;
}
