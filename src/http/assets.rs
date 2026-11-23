//! The embedded single-page UI. Three fixed files compiled into the binary; no filesystem access at
//! request time, so there is no path to traverse.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};

const INDEX_HTML: &str = include_str!("../../web/index.html");
const APP_CSS: &str = include_str!("../../web/app.css");
const APP_JS: &str = include_str!("../../web/app.js");

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut resp = body.into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}

pub async fn index() -> Response {
    asset("text/html; charset=utf-8", INDEX_HTML)
}
pub async fn css() -> Response {
    asset("text/css; charset=utf-8", APP_CSS)
}
pub async fn js() -> Response {
    asset("text/javascript; charset=utf-8", APP_JS)
}
