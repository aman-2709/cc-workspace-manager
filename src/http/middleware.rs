//! Host/Origin validation and security headers (REQUIREMENTS.md §11.3).

use super::AppState;
use crate::api_error::{ApiError, Code};
use axum::extract::{Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HOST, ORIGIN, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

pub const API_PREFIX: &str = "/api/";

/// The CSP from §11.3, parameterised by the bound port.
pub fn csp(port: u16) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self' ws://127.0.0.1:{port}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

pub fn allowed_hosts(port: u16) -> [String; 3] {
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
}

pub fn allowed_origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Outermost: attach the security headers to every response, including rejections.
pub async fn security_headers(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let is_api = req.uri().path().starts_with(API_PREFIX);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if let Ok(v) = HeaderValue::from_str(&state.csp) {
        h.insert(CONTENT_SECURITY_POLICY, v);
    }
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(if is_api { "no-store" } else { "no-cache" }),
    );
    resp
}

/// DNS-rebinding defence: only our own loopback authorities are served.
pub async fn host_check(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let mut hosts = req.headers().get_all(HOST).iter();
    let host_ok = match (hosts.next(), hosts.next()) {
        (Some(h), None) => h
            .to_str()
            .is_ok_and(|h| state.hosts.iter().any(|a| a.eq_ignore_ascii_case(h))),
        _ => false,
    };
    // An absolute-form request target carries its own authority; it must be ours too.
    let uri_ok = req.uri().authority().is_none_or(|a| {
        state
            .hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(a.as_str()))
    });
    if !(host_ok && uri_ok) {
        return ApiError::new(Code::HostNotAllowed, "host not allowed").into_response();
    }
    next.run(req).await
}

/// For `/api`: an `Origin`, if present, must be exactly ours; state-changing requests must have one.
pub async fn origin_check(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path().starts_with(API_PREFIX) {
        let mut origins = req.headers().get_all(ORIGIN).iter();
        let reject = match (origins.next(), origins.next()) {
            (None, _) => !matches!(*req.method(), Method::GET | Method::HEAD),
            (Some(o), None) => o.to_str().map_or(true, |o| o != state.origin),
            (Some(_), Some(_)) => true,
        };
        if reject {
            return ApiError::new(Code::OriginNotAllowed, "origin not allowed").into_response();
        }
    }
    next.run(req).await
}
