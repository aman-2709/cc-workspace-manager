//! HTTP handlers. Each is a thin adapter over [`crate::service::Service`].

use super::extract::{ApiJson, ApiQuery, Bearer, SessionAuth};
use super::AppState;
use crate::api_error::ApiError;
use crate::auth::sessions::IssuedSession;
use crate::service::{
    Accepted, Cleared, Health, PrivacyQuery, ProjectsPage, ProjectsQuery, SessionsQuery,
    SettingsView, Stats,
};
use crate::view::{ProjectDetail, ProjectView, SessionList};
use axum::extract::{Path, State};
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

/// Project ids come from the path; anything that is not a well-formed id is a 404 (the service
/// validates), and the extractor's own rejection is mapped to the JSON envelope.
type Id = Result<Path<String>, axum::extract::rejection::PathRejection>;

fn id(p: Id) -> Result<String, ApiError> {
    p.map(|Path(id)| id)
        .map_err(|_| ApiError::new(crate::api_error::Code::NotFound, "no such project"))
}

pub async fn project(
    State(s): St,
    _auth: SessionAuth,
    p: Id,
    ApiQuery(q): ApiQuery<PrivacyQuery>,
) -> Result<Json<ProjectDetail>, ApiError> {
    Ok(Json(s.service.project(&id(p)?, q.privacy()?).await?))
}

/// Reads the last prompt from the session file on demand (§7.3).
pub async fn project_sessions(
    State(s): St,
    _auth: SessionAuth,
    p: Id,
    ApiQuery(q): ApiQuery<SessionsQuery>,
) -> Result<Json<SessionList>, ApiError> {
    Ok(Json(s.service.project_sessions(&id(p)?, &q).await?))
}

pub async fn settings(
    State(s): St,
    _auth: SessionAuth,
    ApiQuery(q): ApiQuery<PrivacyQuery>,
) -> Result<Json<SettingsView>, ApiError> {
    Ok(Json(s.service.settings(q.privacy()?).await?))
}

pub async fn update_settings(
    State(s): St,
    _auth: SessionAuth,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> Result<Json<SettingsView>, ApiError> {
    Ok(Json(s.service.update_settings(body).await?))
}

pub async fn clear_session_index(
    State(s): St,
    _auth: SessionAuth,
) -> Result<Json<Cleared>, ApiError> {
    Ok(Json(s.service.clear_session_index().await?))
}

pub async fn ignore(
    State(s): St,
    _auth: SessionAuth,
    p: Id,
) -> Result<Json<ProjectView>, ApiError> {
    Ok(Json(s.service.set_ignored(&id(p)?, true).await?))
}

pub async fn unignore(
    State(s): St,
    _auth: SessionAuth,
    p: Id,
) -> Result<Json<ProjectView>, ApiError> {
    Ok(Json(s.service.set_ignored(&id(p)?, false).await?))
}

pub async fn refresh(
    State(s): St,
    _auth: SessionAuth,
) -> Result<(StatusCode, Json<Accepted>), ApiError> {
    Ok((StatusCode::ACCEPTED, Json(s.service.refresh()?)))
}

pub async fn stats(State(s): St, _auth: SessionAuth) -> Result<Json<Stats>, ApiError> {
    Ok(Json(s.service.stats().await?))
}

pub async fn discovery_status(
    State(s): St,
    _auth: SessionAuth,
    ApiQuery(q): ApiQuery<PrivacyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(s.service.discovery_json(q.privacy()?)))
}

pub async fn service_status(
    State(s): St,
    _auth: SessionAuth,
    ApiQuery(q): ApiQuery<PrivacyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(s.service.service_json(q.privacy()?)))
}
