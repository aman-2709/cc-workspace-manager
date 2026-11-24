//! `GET /api/v1/ws` (REQUIREMENTS.md §11.2 "WebSocket", §9 "Live updates").
//!
//! The upgrade requires the exact allowed `Origin`. The first client message must be
//! `{"type":"auth","token":"…"}` within [`AUTH_TIMEOUT`]; otherwise, or if the token is not valid,
//! the socket is closed with code 4401. Nothing is sent before authentication succeeds. The token
//! is revalidated when sessions are revoked (logout, revoke-all) and every [`REVALIDATE`], so a
//! token that expires or is rotated out (after its 60 s grace) closes the socket with 4401.

use super::AppState;
use crate::api_error::{ApiError, Code};
use crate::service::Service;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::ORIGIN;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

pub const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
pub const REVALIDATE: Duration = Duration::from_secs(10);
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// Client messages are tiny (the auth message only).
const MAX_MESSAGE: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Auth { token: String },
}

pub async fn upgrade(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let mut origins = headers.get_all(ORIGIN).iter();
    let origin_ok = matches!(
        (origins.next(), origins.next()),
        (Some(o), None) if o.to_str().is_ok_and(|o| o == s.origin)
    );
    if !origin_ok {
        return ApiError::new(Code::OriginNotAllowed, "origin not allowed").into_response();
    }
    let Ok(ws) = ws else {
        return ApiError::invalid("a WebSocket upgrade is required").into_response();
    };
    let service = Arc::clone(&s.service);
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| session(socket, service))
}

async fn close(mut socket: WebSocket, code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: Utf8Bytes::from_static(reason),
        })))
        .await;
}

/// Wait for the auth message; `Some(token)` if it was well-formed and valid.
async fn authenticate(socket: &mut WebSocket, service: &Service) -> Option<String> {
    let first = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            match socket.recv().await? {
                Ok(Message::Text(t)) => return Some(t),
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .ok()??;
    let ClientMsg::Auth { token } = serde_json::from_str(first.as_str()).ok()?;
    service.authenticate(&token).await.ok()?;
    Some(token)
}

async fn session(mut socket: WebSocket, service: Arc<Service>) {
    // Subscribe before authenticating so no change between "ready" and the first event is lost;
    // nothing is forwarded until authentication succeeded.
    let mut events = service.hub.subscribe();
    let mut revocations = service.auth_changes();
    let Some(token) = authenticate(&mut socket, &service).await else {
        close(socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let ready = Message::Text(Utf8Bytes::from_static(r#"{"type":"ready"}"#));
    if socket.send(ready).await.is_err() {
        return;
    }
    let mut tick = tokio::time::interval(REVALIDATE);
    tick.reset();
    loop {
        let revalidate = tokio::select! {
            ev = events.recv() => {
                let text = match ev {
                    Ok(text) => text,
                    Err(RecvError::Lagged(_)) => Arc::from(crate::events::resync().to_string()),
                    Err(RecvError::Closed) => break,
                };
                if socket.send(Message::Text(Utf8Bytes::from(text.as_ref()))).await.is_err() {
                    break;
                }
                false
            }
            _ = tick.tick() => true,
            changed = revocations.changed() => {
                if changed.is_err() {
                    break; // the service is shutting down
                }
                true
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => false,
                // The client has nothing more to say; anything else ends the session.
                _ => break,
            },
        };
        if revalidate && service.authenticate(&token).await.is_err() {
            close(socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
            return;
        }
    }
}
