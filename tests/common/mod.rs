//! Shared test scaffolding: a real `Service` over a temp database with a fake clock.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, Response};
use axum::Router;
use cc_workspace_manager::activity::Classifier;
use cc_workspace_manager::clock::FakeClock;
use cc_workspace_manager::config::ActivityConfig;
use cc_workspace_manager::db::reader::Reader;
use cc_workspace_manager::db::writer::{ProjectUpsert, Source, Writer};
use cc_workspace_manager::discovery::status::SharedStatus;
use cc_workspace_manager::events::Notifier;
use cc_workspace_manager::http;
use cc_workspace_manager::sandbox::SandboxReport;
use cc_workspace_manager::service::{Deps, Service};
use cc_workspace_manager::watch::SharedMonitor;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt;

/// A temporary directory with mode 0700 regardless of the umask: ccwm refuses group-writable
/// ancestors that do not belong to the user's private group.
pub fn tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    t
}

/// The home directory the test service assumes (seeded projects live below it).
pub const HOME: &str = "/home/u";

/// A port that is only used for Host/Origin/CSP arithmetic in oneshot tests.
pub const PORT: u16 = 18765;
pub const START: i64 = 1_800_000_000;

pub struct Env {
    pub service: Arc<Service>,
    pub clock: Arc<FakeClock>,
    pub writer: Arc<Writer>,
    pub router: Router,
    _dir: tempfile::TempDir,
}

pub async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let clock = Arc::new(FakeClock::new(START));
    let writer = Arc::new(Writer::spawn(&db).unwrap());
    let reader = Reader::open(&db, 2).unwrap();
    let (notifier, _changes) = Notifier::channel();
    let service = Arc::new(Service::new(Deps {
        clock: clock.clone(),
        writer: writer.clone(),
        reader,
        discovery: SharedStatus::default(),
        sandbox: SandboxReport::disabled("test"),
        port: PORT,
        home: std::path::PathBuf::from(HOME),
        classifier: Classifier::new(jiff::tz::TimeZone::UTC, &ActivityConfig::default()),
        monitor: SharedMonitor::default(),
        notifier,
        tracker: None,
    }));
    let router = http::router(service.clone());
    Env {
        service,
        clock,
        writer,
        router,
        _dir: dir,
    }
}

impl Env {
    pub async fn seed(&self, names: &[&str]) {
        let batch = names
            .iter()
            .map(|n| ProjectUpsert {
                canonical_path: format!("{HOME}/{n}"),
                name: (*n).to_string(),
                source: Source::Marker,
                marker_hash: None,
            })
            .collect();
        self.writer.upsert_projects(batch, START).await.unwrap();
    }

    /// bootstrap -> exchange, the way the real flow does it.
    pub async fn login(&self) -> String {
        let b = self.service.auth_bootstrap().unwrap();
        self.service
            .auth_exchange(&b.bootstrap_token)
            .await
            .unwrap()
            .session_token
    }

    pub async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.unwrap()
    }

    /// GET with correct Host (no Origin), optional bearer token.
    pub async fn get(&self, path: &str, token: Option<&str>) -> Response<Body> {
        let mut b = Request::builder()
            .uri(path)
            .header("host", format!("127.0.0.1:{PORT}"));
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    /// POST with correct Host and Origin, JSON body, optional bearer token.
    pub async fn post(&self, path: &str, token: Option<&str>, body: &str) -> Response<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", format!("127.0.0.1:{PORT}"))
            .header("origin", format!("http://127.0.0.1:{PORT}"))
            .header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        self.send(b.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

pub async fn json(resp: Response<Body>) -> (u16, serde_json::Value) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
    });
    (status, v)
}

pub fn code(v: &serde_json::Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("<none>")
}

/// Every entry's mode, mtime, ctime, size, inode and (for files) content: for "nothing was modified" checks.
pub fn snapshot(root: &Path) -> Vec<String> {
    snapshot_excluding(root, &[])
}

/// Like [`snapshot`], skipping the subtrees in `skip` (ccwm's own directories, which it writes).
pub fn snapshot_excluding(root: &Path, skip: &[std::path::PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if skip.iter().any(|s| p.starts_with(s)) {
            continue;
        }
        let md = fs::symlink_metadata(&p).unwrap();
        out.push(format!(
            "{} mode={:o} mtime={}.{} ctime={} size={} ino={}",
            p.display(),
            md.mode(),
            md.mtime(),
            md.mtime_nsec(),
            md.ctime(),
            md.size(),
            md.ino()
        ));
        if md.is_dir() {
            stack.extend(fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
        } else if md.is_file() {
            out.push(format!("  content={:?}", fs::read(&p).unwrap()));
        }
    }
    out.sort();
    out
}

// ---- a minimal blocking WebSocket client (client crates are banned, even for tests) --------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Text(String),
    /// Close frame with its status code (`None` if it carried none).
    Close(Option<u16>),
    Other(u8),
}

pub struct WsClient {
    s: std::net::TcpStream,
}

impl WsClient {
    /// Upgrade `GET /api/v1/ws` on `addr` (Host is `127.0.0.1:<host_port>`). `Err((status, head))`
    /// if the server did not switch protocols.
    pub fn connect(
        addr: std::net::SocketAddr,
        host_port: u16,
        origin: Option<&str>,
    ) -> Result<Self, (u16, String)> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).map_err(|e| (0, e.to_string()))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        let mut req = format!(
            "GET /api/v1/ws HTTP/1.1\r\nHost: 127.0.0.1:{host_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        );
        if let Some(o) = origin {
            req.push_str(&format!("Origin: {o}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())
            .map_err(|e| (0, e.to_string()))?;
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => break,
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if status != 101 {
            return Err((status, head));
        }
        Ok(Self { s })
    }

    /// Send a masked text frame (clients must mask).
    pub fn send_text(&mut self, text: &str) {
        use std::io::Write;
        let payload = text.as_bytes();
        let mut f = vec![0x81u8];
        match payload.len() {
            n if n < 126 => f.push(0x80 | u8::try_from(n).unwrap()),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            }
        }
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let _ = self.s.write_all(&f);
    }

    /// The next frame, or `None` if the connection ended or nothing arrived within `timeout`.
    pub fn recv(&mut self, timeout: std::time::Duration) -> Option<Frame> {
        use std::io::Read;
        self.s.set_read_timeout(Some(timeout)).unwrap();
        let mut h = [0u8; 2];
        self.s.read_exact(&mut h).ok()?;
        let opcode = h[0] & 0x0f;
        let mut len = u64::from(h[1] & 0x7f);
        if len == 126 {
            let mut b = [0u8; 2];
            self.s.read_exact(&mut b).ok()?;
            len = u64::from(u16::from_be_bytes(b));
        } else if len == 127 {
            let mut b = [0u8; 8];
            self.s.read_exact(&mut b).ok()?;
            len = u64::from_be_bytes(b);
        }
        let mut payload = vec![0u8; usize::try_from(len).ok()?];
        self.s.read_exact(&mut payload).ok()?;
        Some(match opcode {
            1 => Frame::Text(String::from_utf8_lossy(&payload).into_owned()),
            8 => Frame::Close(
                (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]])),
            ),
            o => Frame::Other(o),
        })
    }

    /// Next text frame parsed as JSON, skipping nothing; panics on anything else.
    pub fn recv_json(&mut self, timeout: std::time::Duration) -> serde_json::Value {
        match self.recv(timeout) {
            Some(Frame::Text(t)) => serde_json::from_str(&t).unwrap(),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}
