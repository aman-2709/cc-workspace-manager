//! Shared test scaffolding: a real `Service` over a temp database with a fake clock.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, Response};
use axum::Router;
use cc_workspace_manager::clock::FakeClock;
use cc_workspace_manager::db::reader::Reader;
use cc_workspace_manager::db::writer::{ProjectUpsert, Source, Writer};
use cc_workspace_manager::discovery::status::SharedStatus;
use cc_workspace_manager::http;
use cc_workspace_manager::sandbox::SandboxReport;
use cc_workspace_manager::service::Service;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt;

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
    let service = Arc::new(Service::new(
        clock.clone(),
        writer.clone(),
        reader,
        SharedStatus::default(),
        SandboxReport::disabled("test"),
        PORT,
    ));
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
                canonical_path: format!("/home/u/{n}"),
                name: (*n).to_string(),
                source: Source::Marker,
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
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
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
