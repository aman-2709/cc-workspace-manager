//! JSON-lines protocol between the `ccwm` CLI and the daemon. One request line, one response line:
//! `{"ok": …}` or `{"error":{"code","message"}}` (same codes as HTTP). Requests are dispatched into
//! the same [`Service`] the HTTP handlers use.

use crate::api_error::ApiError;
use crate::claude::hook::Report;
use crate::presence::HookRequest;
use crate::service::Service;
use serde_json::{json, Value};

/// Requests larger than this are refused: a `hook.event` with a cwd of 4,096 bytes, each byte
/// JSON-escaped (`\u00XX`), still fits (REQUIREMENTS.md §21.4).
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Ping,
    AuthBootstrap,
    AuthRevokeAll,
    ServiceStatus,
    /// Coalesced reconciliation (`ccwm scan`).
    ScanRefresh,
    DiscoveryStatus,
    /// A Claude Code hook event from `ccwm hook` (§21.4); a malformed one is answered (and
    /// counted) by the service.
    HookEvent(HookRequest),
    /// The activity indicator's counters and debug log (`ccwm hooks events`).
    HooksEvents,
}

impl Request {
    /// The op's name, for the trace log (never a field of a request: a hook's cwd stays out).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::AuthBootstrap => "auth.bootstrap",
            Self::AuthRevokeAll => "auth.revoke_all",
            Self::ServiceStatus => "service.status",
            Self::ScanRefresh => "scan.refresh",
            Self::DiscoveryStatus => "discovery.status",
            Self::HookEvent(_) => "hook.event",
            Self::HooksEvents => "hooks.events",
        }
    }
}

/// Exactly `{"op": "<name>"}` and nothing else (serde cannot reject extra fields on tagged unit
/// variants); `hook.event` has its fields, checked by hand ([`Report::from_request`]).
pub fn parse_request(line: &str) -> Result<Request, ApiError> {
    let bad = || ApiError::invalid("unknown or malformed request");
    let value: Value = serde_json::from_str(line.trim()).map_err(|_| bad())?;
    let obj = value.as_object().ok_or_else(bad)?;
    let op = obj.get("op").and_then(Value::as_str).ok_or_else(bad)?;
    if op == "hook.event" {
        return Ok(Request::HookEvent(Report::from_request(obj)));
    }
    if obj.len() != 1 {
        return Err(bad());
    }
    match op {
        "ping" => Ok(Request::Ping),
        "auth.bootstrap" => Ok(Request::AuthBootstrap),
        "auth.revoke_all" => Ok(Request::AuthRevokeAll),
        "service.status" => Ok(Request::ServiceStatus),
        "scan.refresh" => Ok(Request::ScanRefresh),
        "discovery.status" => Ok(Request::DiscoveryStatus),
        "hooks.events" => Ok(Request::HooksEvents),
        _ => Err(bad()),
    }
}

/// Run `req` for the peer whose pid `SO_PEERCRED` gave (`hook.event` is the only op that uses
/// it: the daemon finds the session's process from it, §21.5).
pub async fn dispatch(
    service: &Service,
    req: Request,
    peer_pid: Option<i32>,
) -> Result<Value, ApiError> {
    match req {
        Request::Ping => Ok(json!({
            "version": crate::service::VERSION,
            "commit": crate::service::COMMIT,
        })),
        Request::AuthBootstrap => {
            Ok(serde_json::to_value(service.auth_bootstrap()?).map_err(ApiError::internal)?)
        }
        Request::AuthRevokeAll => Ok(json!({ "revoked": service.auth_revoke_all().await? })),
        Request::ServiceStatus => {
            Ok(serde_json::to_value(service.service_status()).map_err(ApiError::internal)?)
        }
        Request::ScanRefresh => {
            Ok(serde_json::to_value(service.refresh()?).map_err(ApiError::internal)?)
        }
        Request::DiscoveryStatus => {
            Ok(serde_json::to_value(service.discovery_status()).map_err(ApiError::internal)?)
        }
        Request::HookEvent(request) => service.hook_event(peer_pid, request),
        Request::HooksEvents => {
            Ok(serde_json::to_value(service.hook_events()).map_err(ApiError::internal)?)
        }
    }
}

/// Encode a result as one response line (without the trailing newline).
pub fn encode_response(result: &Result<Value, ApiError>) -> String {
    match result {
        Ok(v) => json!({ "ok": v }).to_string(),
        Err(e) => e.to_json().to_string(),
    }
}

/// Decode a response line into `Ok(value)` or the daemon's error.
pub fn decode_response(line: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(line.trim())
        .map_err(|_| "the daemon sent an invalid response".to_string())?;
    if let Some(ok) = v.get("ok") {
        return Ok(ok.clone());
    }
    match v.pointer("/error/message").and_then(Value::as_str) {
        Some(msg) => Err(msg.to_string()),
        None => Err("the daemon sent an unrecognised response".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_ops() {
        assert_eq!(parse_request(r#"{"op":"ping"}"#).unwrap(), Request::Ping);
        assert_eq!(
            parse_request("{\"op\":\"auth.bootstrap\"}\n").unwrap(),
            Request::AuthBootstrap
        );
        assert_eq!(
            parse_request(r#"{"op":"auth.revoke_all"}"#).unwrap(),
            Request::AuthRevokeAll
        );
        assert_eq!(
            parse_request(r#"{"op":"service.status"}"#).unwrap(),
            Request::ServiceStatus
        );
        assert_eq!(
            parse_request(r#"{"op":"scan.refresh"}"#).unwrap(),
            Request::ScanRefresh
        );
        assert_eq!(
            parse_request(r#"{"op":"discovery.status"}"#).unwrap(),
            Request::DiscoveryStatus
        );
        assert_eq!(
            parse_request(r#"{"op":"hooks.events"}"#).unwrap(),
            Request::HooksEvents
        );
    }

    const SID: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";

    #[test]
    fn hook_events_are_parsed_by_hand_and_malformed_ones_kept_for_the_service() {
        let line =
            format!(r#"{{"op":"hook.event","event":"Stop","session_id":"{SID}","cwd":"/p"}}"#);
        let Request::HookEvent(Ok(r)) = parse_request(&line).unwrap() else {
            panic!("a valid hook event")
        };
        assert_eq!(
            (r.event, r.cwd.as_str()),
            (crate::claude::hook::Event::Stop, "/p")
        );
        // Malformed fields are not a protocol error: the service counts and answers them.
        let bad = format!(
            r#"{{"op":"hook.event","event":"Stop","session_id":"{SID}","cwd":"/p","x":1}}"#
        );
        assert!(matches!(
            parse_request(&bad).unwrap(),
            Request::HookEvent(Err(_))
        ));
        assert!(matches!(
            parse_request(r#"{"op":"hook.event"}"#).unwrap(),
            Request::HookEvent(Err(_))
        ));
        assert_eq!(parse_request(&line).unwrap().name(), "hook.event");
        // Another op with fields is still refused.
        assert!(parse_request(r#"{"op":"hooks.events","x":1}"#).is_err());
    }

    /// A cwd of 4,096 bytes, every one JSON-escaped, fits in a request.
    #[test]
    fn the_longest_hook_event_fits_in_the_request_limit() {
        let cwd = format!(
            "/{}",
            "\\u0001".repeat(crate::claude::hook::MAX_CWD_BYTES - 1)
        );
        let line = format!(
            r#"{{"op":"hook.event","event":"Notification","session_id":"{SID}","cwd":"{cwd}","notification_type":"permission_prompt","prompt_id":"{SID}","claude_pid":4194304}}"#
        );
        assert!(
            line.len() < MAX_REQUEST_BYTES,
            "{} bytes with the newline",
            line.len() + 1
        );
        assert!(matches!(
            parse_request(&line).unwrap(),
            Request::HookEvent(Ok(_))
        ));
    }

    #[test]
    fn rejects_unknown_ops_extra_fields_and_garbage() {
        for bad in [
            r#"{"op":"rm -rf"}"#,
            r#"{"op":"ping","x":1}"#,
            "{}",
            "[]",
            "garbage",
            "",
            r#"{"op":1}"#,
        ] {
            assert_eq!(
                parse_request(bad).unwrap_err().code,
                crate::api_error::Code::InvalidArgument,
                "{bad}"
            );
        }
    }

    #[test]
    fn response_encoding_roundtrips() {
        let ok = encode_response(&Ok(json!({"a":1})));
        assert_eq!(ok, r#"{"ok":{"a":1}}"#);
        assert_eq!(decode_response(&ok).unwrap(), json!({"a":1}));
        let err = encode_response(&Err(ApiError::invalid("nope")));
        assert_eq!(decode_response(&err).unwrap_err(), "nope");
        assert!(decode_response("junk").is_err());
        assert!(decode_response("{}").is_err());
    }
}
