//! The browser-facing HTTP server (loopback only).

mod assets;
mod error;
mod extract;
pub mod middleware;
mod routes;

use crate::api_error::{ApiError, Code};
use crate::service::Service;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpListener;

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

/// Serve until `shutdown` resolves, then finish in-flight requests.
pub async fn serve(
    listener: TcpListener,
    service: Arc<Service>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router(service))
        .with_graceful_shutdown(shutdown)
        .await
}
