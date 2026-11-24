//! HTTP handlers. Each is a thin adapter over [`crate::service::Service`].

use super::extract::{ApiJson, ApiQuery, Bearer, SessionAuth};
use super::AppState;
use crate::api_error::ApiError;
use crate::auth::sessions::IssuedSession;
use crate::discovery::status::DiscoverySnapshot;
use crate::service::{Health, ProjectsPage, ProjectsQuery, ServiceStatus, Stats};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

type St = State<Arc<AppState>>;

pub async fn health(State(s): St) -> Json<Health> {
    Json(s.service.health())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeBody {
    bootstrap_token: String,
}

pub async fn exchange(
    State(s): St,
    ApiJson(body): ApiJson<ExchangeBody>,
) -> Result<Json<IssuedSession>, ApiError> {
    Ok(Json(s.service.auth_exchange(&body.bootstrap_token).await?))
}

/// The service authenticates here itself: an overdue token is accepted for rotation only.
pub async fn rotate(State(s): St, bearer: Bearer) -> Result<Json<IssuedSession>, ApiError> {
    Ok(Json(s.service.auth_rotate(&bearer.token).await?))
}

pub async fn logout(State(s): St, auth: SessionAuth) -> Result<StatusCode, ApiError> {
    s.service.auth_logout(&auth.token).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn projects(
    State(s): St,
    _auth: SessionAuth,
    ApiQuery(q): ApiQuery<ProjectsQuery>,
) -> Result<Json<ProjectsPage>, ApiError> {
    Ok(Json(s.service.list_projects(q).await?))
}

pub async fn stats(State(s): St, _auth: SessionAuth) -> Result<Json<Stats>, ApiError> {
    Ok(Json(s.service.stats().await?))
}

pub async fn discovery_status(State(s): St, _auth: SessionAuth) -> Json<DiscoverySnapshot> {
    Json(s.service.discovery_status())
}

pub async fn service_status(State(s): St, _auth: SessionAuth) -> Json<ServiceStatus> {
    Json(s.service.service_status())
}
