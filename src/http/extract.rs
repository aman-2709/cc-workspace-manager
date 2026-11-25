//! Request extractors that fail with the JSON error envelope instead of axum's plain-text rejections.

use super::AppState;
use crate::api_error::{ApiError, Code};
use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// Request bodies are tiny JSON objects.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned> FromRequest<Arc<AppState>> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &Arc<AppState>) -> Result<Self, ApiError> {
        let is_json = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
            });
        if !is_json {
            return Err(ApiError::invalid("content-type must be application/json"));
        }
        // A body that never arrives must not hold its connection slot for ever (the head has
        // its own timeout in the server loop; v0.1.0 review L5). The connection is closed after
        // the 408, because the body was not read.
        let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES);
        let bytes = tokio::time::timeout(state.body_read_timeout, body)
            .await
            .map_err(|_| {
                ApiError::new(
                    Code::RequestTimeout,
                    "the request body did not arrive in time",
                )
            })?
            .map_err(|_| ApiError::new(Code::PayloadTooLarge, "request body too large"))?;
        serde_json::from_slice(&bytes)
            .map(ApiJson)
            .map_err(|_| ApiError::invalid("malformed JSON body"))
    }
}

pub struct ApiQuery<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Query::<T>::try_from_uri(&parts.uri)
            .map(|Query(q)| ApiQuery(q))
            .map_err(|_| ApiError::invalid("invalid query string"))
    }
}

/// The presented `Authorization: Bearer <token>`, **not** yet authenticated. Only `/auth/rotate`
/// uses it directly, because the service must also accept a token whose rotation is overdue there.
pub struct Bearer {
    pub token: String,
}

/// An authenticated browser session (`Authorization: Bearer <session token>`).
pub struct SessionAuth {
    pub token: String,
}

fn bearer(parts: &Parts) -> Option<&str> {
    let mut values = parts.headers.get_all(AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = first.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

impl<S: Send + Sync> FromRequestParts<S> for Bearer {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        let token = bearer(parts)
            .ok_or_else(ApiError::unauthorized)?
            .to_string();
        Ok(Self { token })
    }
}

impl FromRequestParts<Arc<AppState>> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, ApiError> {
        let Bearer { token } = Bearer::from_request_parts(parts, state).await?;
        state.service.authenticate(&token).await?;
        Ok(Self { token })
    }
}
