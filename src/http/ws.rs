//! `GET /api/v1/ws` (REQUIREMENTS.md §11.2 "WebSocket", §9 "Live updates").
//!
//! The upgrade requires the exact allowed `Origin`. The first client message must be
//! `{"type":"auth","token":"…"}` within [`AUTH_TIMEOUT`]; otherwise, or if the token is not valid,
//! the socket is closed with code 4401. Nothing is sent before authentication succeeds. The token
//! is revalidated when sessions are revoked (logout, revoke-all) and every [`REVALIDATE`], so a
//! token that expires or is rotated out (after its 60 s grace) closes the socket with 4401.
//! Revalidation comes before everything else the session has to do, and no send waits longer than
//! [`SEND_TIMEOUT`]: a client that stops reading cannot keep its socket open past a revocation,
//! and no event is forwarded once a revocation is signalled (v0.1.0 review I3).
//!
//! Privacy mode (§10) is a subscription option: `{"type":"auth","token":…,"privacy":true}` or,
//! later, `{"type":"privacy","on":true|false}`; the client then receives the privacy variant of
//! every event (paths, titles and prompts already removed by the server).

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
/// A client that does not take a message within this time is disconnected (it reconnects and
/// fetches a fresh snapshot). Without a limit, a send to a client that stopped reading would
/// block the session, and with it the revalidation of its token.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(5);
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// Client messages are tiny (auth and the privacy option).
const MAX_MESSAGE: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Auth {
        token: String,
        #[serde(default)]
        privacy: bool,
    },
    Privacy {
        on: bool,
    },
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

/// Send one message; `false` if the client is gone or did not take it within [`SEND_TIMEOUT`].
async fn send(socket: &mut WebSocket, msg: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(msg)).await,
        Ok(Ok(()))
    )
}

async fn close(mut socket: WebSocket, code: u16, reason: &'static str) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::from_static(reason),
    };
    send(&mut socket, Message::Close(Some(frame))).await;
}

/// Wait for the auth message; `Some((token, privacy))` if it was well-formed and valid.
async fn authenticate(socket: &mut WebSocket, service: &Service) -> Option<(String, bool)> {
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
    let ClientMsg::Auth { token, privacy } = serde_json::from_str(first.as_str()).ok()? else {
        return None;
    };
    service.authenticate(&token).await.ok()?;
    Some((token, privacy))
}

async fn session(mut socket: WebSocket, service: Arc<Service>) {
    // Subscribe before authenticating so no change between "ready" and the first event is lost;
    // nothing is forwarded until authentication succeeded.
    let mut events = service.hub.subscribe();
    let mut revocations = service.auth_changes();
    let Some((token, mut private)) = authenticate(&mut socket, &service).await else {
        close(socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
        return;
    };
    let ready = Message::Text(Utf8Bytes::from_static(r#"{"type":"ready"}"#));
    if !send(&mut socket, ready).await {
        return;
    }
    let mut tick = tokio::time::interval(REVALIDATE);
    tick.reset();
    loop {
        // In this order when several are ready: a revocation (or the periodic check) is acted on
        // before an event is forwarded, and a client's privacy switch before the next event.
        let revalidate = tokio::select! {
            biased;
            changed = revocations.changed() => {
                if changed.is_err() {
                    break; // the service is shutting down
                }
                true
            }
            _ = tick.tick() => true,
            msg = socket.recv() => match msg {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => false,
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMsg>(t.as_str()) {
                    Ok(ClientMsg::Privacy { on }) => {
                        private = on;
                        false
                    }
                    // Anything else (a second auth, garbage) ends the session.
                    _ => break,
                },
                _ => break,
            },
            ev = events.recv() => {
                let text: Utf8Bytes = match ev {
                    Ok(msg) => Utf8Bytes::from(msg.for_client(private)),
                    Err(RecvError::Lagged(_)) => Utf8Bytes::from(crate::events::resync().to_string()),
                    Err(RecvError::Closed) => break,
                };
                if !send(&mut socket, Message::Text(text)).await {
                    break;
                }
                false
            }
        };
        if revalidate && service.authenticate(&token).await.is_err() {
            close(socket, CLOSE_UNAUTHORIZED, "unauthorized").await;
            return;
        }
    }
}
