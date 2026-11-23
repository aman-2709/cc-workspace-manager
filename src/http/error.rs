//! `ApiError` as an HTTP response: status from the code, `{"error":{…}}` body.

use crate::api_error::ApiError;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = (status, self.to_json().to_string()).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    }
}
