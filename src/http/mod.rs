//! The browser-facing HTTP server (loopback only).
//!
//! Connection handling (M1.1, findings H1/H2/L5): a connection slot is taken **before** `accept`
//! (at most [`MAX_CONNECTIONS`]; further clients wait in the kernel backlog and use none of our
//! file descriptors, so the Unix socket stays usable), then the client's UID is verified
//! ([`peer`]) before a single byte is read, then HTTP/1 is served with a header-read timeout.

mod assets;
mod error;
mod extract;
pub mod middleware;
pub mod peer;
mod routes;
pub mod ws;

use crate::api_error::{ApiError, Code};
use crate::service::Service;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post, put};
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use peer::{PeerUidLookup, Verdict};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// Concurrent TCP connections being served (each holds one file descriptor).
pub const MAX_CONNECTIONS: usize = 64;
/// A client must send a complete request head within this time (also bounds idle keep-alive).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// On shutdown, in-flight connections get this long to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Rejections of other users' connections are logged at most this often.
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(60);

pub struct AppState {
    pub service: Arc<Service>,
    pub(crate) hosts: [String; 3],
    pub(crate) origin: String,
    pub(crate) csp: String,
}

impl AppState {
    pub fn new(service: Arc<Service>) -> Arc<Self> {
        let port = service.port();
        Arc::new(Self {
            hosts: middleware::allowed_hosts(port),
            origin: middleware::allowed_origin(port),
            csp: middleware::csp(port),
            service,
        })
    }
}

async fn not_found() -> ApiError {
    ApiError::new(Code::NotFound, "not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(Code::MethodNotAllowed, "method not allowed")
}

pub fn router(service: Arc<Service>) -> Router {
    let state = AppState::new(service);
    let api = Router::new()
        .route("/health", get(routes::health))
        .route("/auth/exchange", post(routes::exchange))
        .route("/auth/rotate", post(routes::rotate))
        .route("/auth/logout", post(routes::logout))
        .route("/projects", get(routes::projects))
        .route(
            "/projects/{id}",
            get(routes::project).delete(routes::forget),
        )
        .route("/projects/{id}/sessions", get(routes::project_sessions))
        .route(
            "/projects/{id}/ignore",
            put(routes::ignore).delete(routes::unignore),
        )
        .route(
            "/settings",
            get(routes::settings).put(routes::update_settings),
        )
        .route("/session-index/clear", post(routes::clear_session_index))
        .route("/refresh", post(routes::refresh))
        .route("/ws", get(ws::upgrade))
        .route("/stats", get(routes::stats))
        .route("/discovery/status", get(routes::discovery_status))
        .route("/service/status", get(routes::service_status));
    Router::new()
        .route("/", get(assets::index))
        .route("/app.css", get(assets::css))
        .route("/app.js", get(assets::js))
        .nest("/api/v1", api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(extract::MAX_BODY_BYTES))
        // Layers run outermost-last: headers wrap host check wrap origin check.
        .layer(from_fn_with_state(
            Arc::clone(&state),
            middleware::origin_check,
        ))
        .layer(from_fn_with_state(
            Arc::clone(&state),
            middleware::host_check,
        ))
        .layer(from_fn_with_state(
            Arc::clone(&state),
            middleware::security_headers,
        ))
        .with_state(state)
}

#[derive(Clone)]
pub struct ServeOptions {
    /// Only connections whose client socket belongs to this UID are served.
    pub daemon_uid: u32,
    pub peer_uid: PeerUidLookup,
    pub max_connections: usize,
    pub header_read_timeout: Duration,
}

impl ServeOptions {
    /// Production settings: procfs peer lookup and the default limits.
    pub fn new(daemon_uid: u32) -> Self {
        Self {
            daemon_uid,
            peer_uid: peer::procfs_lookup(),
            max_connections: MAX_CONNECTIONS,
            header_read_timeout: HEADER_READ_TIMEOUT,
        }
    }
}

/// Counts rejected connections; logs at most once per [`REJECT_LOG_INTERVAL`] so another user
/// cannot flood the journal.
#[derive(Default)]
struct RejectLog {
    total: AtomicU64,
    last: Mutex<Option<Instant>>,
}

impl RejectLog {
    fn note(&self, verdict: &Verdict) {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let Ok(mut last) = self.last.lock() else {
            return;
        };
        if last.is_some_and(|t| t.elapsed() < REJECT_LOG_INTERVAL) {
            return;
        }
        *last = Some(Instant::now());
        tracing::warn!(
            total,
            reason = ?verdict,
            "rejected a TCP connection that does not belong to the daemon's user"
        );
    }
}

/// Serve until `shutdown` resolves, then let in-flight connections finish (bounded).
pub async fn serve(
    listener: TcpListener,
    service: Arc<Service>,
    opts: ServeOptions,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = router(service);
    let slots = Arc::new(Semaphore::new(opts.max_connections));
    let (stop_tx, stop_rx) = watch::channel(false);
    let rejects = Arc::new(RejectLog::default());
    let mut connections = JoinSet::new();
    let mut shutdown = pin!(shutdown);
    loop {
        let permit = tokio::select! {
            biased;
            () = &mut shutdown => break,
            p = Arc::clone(&slots).acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break, // the semaphore is never closed
            },
        };
        let accepted = tokio::select! {
            biased;
            () = &mut shutdown => break,
            r = listener.accept() => r,
        };
        let (stream, remote) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                accept_error(&e).await;
                continue;
            }
        };
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        connections.spawn(connection(
            Conn {
                stream,
                local,
                remote,
                _permit: permit,
            },
            app.clone(),
            opts.clone(),
            stop_rx.clone(),
            Arc::clone(&rejects),
        ));
        while connections.try_join_next().is_some() {}
    }
    drop(listener); // refuse new connections from now on
    let _ = stop_tx.send(true);
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        tracing::warn!(
            "closing HTTP connections that did not finish within the shutdown grace period"
        );
    }
    Ok(())
}

struct Conn {
    stream: TcpStream,
    local: SocketAddr,
    remote: SocketAddr,
    /// Released (slot freed) when the connection ends.
    _permit: OwnedSemaphorePermit,
}

async fn connection(
    conn: Conn,
    app: Router,
    opts: ServeOptions,
    mut stop: watch::Receiver<bool>,
    rejects: Arc<RejectLog>,
) {
    let (lookup, remote, local) = (Arc::clone(&opts.peer_uid), conn.remote, conn.local);
    let found = tokio::task::spawn_blocking(move || lookup(remote, local))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    let verdict = peer::decide(&found, opts.daemon_uid);
    tracing::debug!(verdict = ?verdict, "tcp peer check");
    if verdict != Verdict::Allowed {
        rejects.note(&verdict);
        return; // dropping the stream closes it; nothing was read or written
    }
    let served = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(opts.header_read_timeout)
        .serve_connection(TokioIo::new(conn.stream), TowerToHyperService::new(app))
        .with_upgrades();
    let mut served = pin!(served);
    let mut stopping = false;
    loop {
        tokio::select! {
            _ = served.as_mut() => break,
            () = crate::events::until_stopped(&mut stop), if !stopping => {
                stopping = true;
                served.as_mut().graceful_shutdown();
            }
        }
    }
}

/// Transient per-connection errors are ignored; resource exhaustion (EMFILE…) backs off.
async fn accept_error(e: &std::io::Error) {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
    if matches!(
        e.kind(),
        ConnectionAborted | ConnectionRefused | ConnectionReset
    ) {
        return;
    }
    tracing::warn!(error = %e, "accept failed; backing off");
    tokio::time::sleep(Duration::from_millis(250)).await;
}
