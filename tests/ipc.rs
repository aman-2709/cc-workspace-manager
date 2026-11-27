//! The Unix-socket CLI channel: peer-credential authentication in both directions, protocol
//! errors, socket hygiene. Part of security acceptance test 6 (peer-UID mismatch, simulated).

mod common;

use cc_workspace_manager::client;
use cc_workspace_manager::ipc::server;
use common::env;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener as StdListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

fn my_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

struct Running {
    socket: PathBuf,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ccwm-ipc")
        .tempdir_in("/tmp")
        .unwrap()
}

async fn start(service: Arc<cc_workspace_manager::service::Service>, daemon_uid: u32) -> Running {
    let dir = short_dir();
    let socket = dir.path().join("s.sock");
    let listener = server::bind(&socket, my_uid()).unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, service, daemon_uid, rx));
    Running {
        socket,
        stop,
        task,
        _dir: dir,
    }
}

impl Running {
    async fn call(&self, op: &'static str) -> Result<serde_json::Value, String> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            client::call(&socket, my_uid(), op).map_err(|e| e.to_string())
        })
        .await
        .unwrap()
    }
    async fn stop(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap();
    }
}

#[tokio::test]
async fn ping_bootstrap_status_and_revoke_all_work_over_the_socket() {
    let e = env().await;
    let srv = start(e.service.clone(), my_uid()).await;

    assert_eq!(
        srv.call("ping").await.unwrap()["version"],
        env!("CARGO_PKG_VERSION")
    );

    let issued = srv.call("auth.bootstrap").await.unwrap();
    assert_eq!(issued["port"], common::PORT);
    assert_eq!(
        issued["expires_in"],
        cc_workspace_manager::auth::bootstrap::BOOTSTRAP_TTL_SECS
    );
    let token = issued["bootstrap_token"].as_str().unwrap();
    let session = e.service.auth_exchange(token).await.unwrap(); // the token really works
    assert_eq!(
        e.get("/api/v1/stats", Some(&session.session_token))
            .await
            .status(),
        200
    );
    assert!(e.service.auth_exchange(token).await.is_err(), "single use");

    let status = srv.call("service.status").await.unwrap();
    assert_eq!(status["port"], common::PORT);
    assert_eq!(status["sandbox"]["status"], "not_enforced");

    assert_eq!(srv.call("auth.revoke_all").await.unwrap()["revoked"], 1);
    assert_eq!(
        e.get("/api/v1/stats", Some(&session.session_token))
            .await
            .status(),
        401
    );
    srv.stop().await;
}

#[tokio::test]
async fn a_connection_from_another_uid_is_dropped_without_a_response() {
    let e = env().await;
    // Pretend the daemon runs as a different user: our (real) uid is then "someone else".
    let srv = start(e.service.clone(), my_uid() + 1).await;
    const REQUEST: &[u8] = b"{\"op\":\"auth.bootstrap\"}\n";

    // The daemon drops the connection as soon as it has seen the peer's uid, which may be
    // before, while or after the client writes (on a busy machine: before, and the write then
    // fails with EPIPE). Whichever it is, not one byte comes back.
    let stream = tokio::net::UnixStream::connect(&srv.socket).await.unwrap();
    let received = common::response_to_a_dropped_connection(stream, REQUEST).await;
    assert!(received.is_empty(), "the rejected peer got {received:?}");

    // The order that made the write fail, forced: wait until the daemon has closed (EOF with
    // nothing received), then send. Still nothing comes back.
    let mut closed = tokio::net::UnixStream::connect(&srv.socket).await.unwrap();
    let mut before = Vec::new();
    let eof = tokio::io::AsyncReadExt::read_to_end(&mut closed, &mut before);
    tokio::time::timeout(Duration::from_secs(5), eof)
        .await
        .expect("the daemon closes a rejected connection on its own")
        .unwrap();
    assert!(before.is_empty(), "sent before any request: {before:?}");
    let received = common::response_to_a_dropped_connection(closed, REQUEST).await;
    assert!(received.is_empty(), "the rejected peer got {received:?}");

    // The CLI client reports a failure, however the drop shows up for it: the request cannot
    // be sent, the read is reset, or the "response" is empty.
    let err = srv.call("auth.bootstrap").await.unwrap_err();
    assert!(
        err.contains("cannot send the request")
            || err.contains("cannot read")
            || err.contains("invalid response"),
        "{err}"
    );
    assert_eq!(
        e.service.bootstrap.outstanding(),
        0,
        "nothing was issued to the rejected peer"
    );
    srv.stop().await;
}

#[tokio::test]
async fn the_client_refuses_a_peer_with_the_wrong_uid_before_sending_anything() {
    let dir = short_dir();
    let socket = dir.path().join("fake.sock");
    let listener = StdListener::bind(&socket).unwrap();
    let received = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut buf = Vec::new();
        let _ = conn.read_to_end(&mut buf);
        buf
    });
    let sock = socket.clone();
    // "expected uid" differs from the real peer (us), as if an impostor owned the socket.
    let err = tokio::task::spawn_blocking(move || {
        client::call(&sock, my_uid() + 1, "auth.bootstrap")
            .unwrap_err()
            .to_string()
    })
    .await
    .unwrap();
    assert!(err.contains("refusing to talk"), "{err}");
    assert!(
        received.join().unwrap().is_empty(),
        "the client must not send a byte to an unverified peer"
    );
}

#[tokio::test]
async fn protocol_errors_get_json_errors_and_never_crash_the_server() {
    let e = env().await;
    let srv = start(e.service.clone(), my_uid()).await;
    let raw = |payload: Vec<u8>| {
        let socket = srv.socket.clone();
        tokio::task::spawn_blocking(move || {
            let mut s = UnixStream::connect(socket).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = s.write_all(&payload);
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        })
    };
    for bad in [
        &b"{\"op\":\"nope\"}\n"[..],
        b"garbage\n",
        b"{}\n",
        b"{\"op\":\"ping\",\"extra\":1}\n",
        b"\xff\xfe\n",
    ] {
        let out = raw(bad.to_vec()).await.unwrap();
        assert!(
            out.contains("\"error\"") && out.contains("invalid_argument"),
            "{bad:?} -> {out:?}"
        );
    }
    // A request of exactly the limit (32 KiB with its newline, §21.4) is read; one byte more
    // is too large, and so is a line that never ends.
    let max = cc_workspace_manager::ipc::protocol::MAX_REQUEST_BYTES;
    let padded = |len: usize| {
        let mut r = b"{\"op\":\"ping\"}".to_vec();
        r.resize(len - 1, b' ');
        r.push(b'\n');
        r
    };
    let out = raw(padded(max)).await.unwrap();
    assert!(out.contains("\"ok\"") && out.contains("version"), "{out}");
    let out = raw(padded(max + 1)).await.unwrap();
    assert!(out.contains("too large"), "{out}");
    let out = raw(vec![b'a'; max + 10]).await.unwrap();
    assert!(out.contains("invalid_argument"), "{out}");
    // A malformed hook event is answered `malformed` and counted, never a protocol crash.
    let out = raw(b"{\"op\":\"hook.event\",\"event\":\"Stop\"}\n".to_vec())
        .await
        .unwrap();
    assert!(
        out.contains("invalid_argument") && out.contains("malformed"),
        "{out}"
    );
    let events = srv.call("hooks.events").await.unwrap();
    assert_eq!(events["refused"]["malformed"], 1);
    assert_eq!(events["events"][0]["event"], "Stop");
    assert_eq!(events["events"][0]["outcome"], "refused: malformed");
    // still alive afterwards
    assert!(srv.call("ping").await.is_ok());
    srv.stop().await;
}

#[tokio::test]
async fn a_silent_client_is_timed_out_and_does_not_block_others() {
    let e = env().await;
    let srv = start(e.service.clone(), my_uid()).await;
    let hang = UnixStream::connect(&srv.socket).unwrap(); // connects, never sends
    assert!(srv.call("ping").await.is_ok());
    drop(hang);
    srv.stop().await;
}

#[tokio::test]
async fn socket_is_private_stale_sockets_are_replaced_and_foreign_files_are_not() {
    let dir = short_dir();
    let socket = dir.path().join("s.sock");
    let first = server::bind(&socket, my_uid()).unwrap();
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(first); // the file stays behind, like after a crash
    let _second = server::bind(&socket, my_uid()).expect("a stale socket we own is replaced");

    let file = dir.path().join("not-a-socket");
    std::fs::write(&file, "precious").unwrap();
    let err = server::bind(&file, my_uid()).err().unwrap().to_string();
    assert!(err.contains("not a socket"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "precious");
    // a socket owned by "someone else" is not replaced either
    assert!(server::bind(&socket, my_uid() + 1).is_err());
}

#[test]
fn peer_allowed_is_exact() {
    assert!(server::peer_allowed(1000, 1000));
    assert!(!server::peer_allowed(0, 1000));
    assert!(!server::peer_allowed(1001, 1000));
}

#[test]
fn no_daemon_means_a_clear_error_and_no_network_attempt() {
    let t = tempfile::tempdir().unwrap();
    let err = client::call(&Path::new(t.path()).join("absent.sock"), my_uid(), "ping")
        .unwrap_err()
        .to_string();
    assert!(err.contains("not running"), "{err}");
}
