//! JSON-lines protocol between the `ccwm` CLI and the daemon. One request line, one response line:
//! `{"ok": …}` or `{"error":{"code","message"}}` (same codes as HTTP). Requests are dispatched into
//! the same [`Service`] the HTTP handlers use.

use crate::api_error::ApiError;
use crate::service::Service;
use serde_json::{json, Value};

/// Requests larger than this are refused.
pub const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Ping,
    AuthBootstrap,
    AuthRevokeAll,
    ServiceStatus,
    /// Coalesced reconciliation (`ccwm scan`).
    ScanRefresh,
    DiscoveryStatus,
}

/// Exactly `{"op": "<name>"}` and nothing else (serde cannot reject extra fields on tagged unit variants).
pub fn parse_request(line: &str) -> Result<Request, ApiError> {
    let bad = || ApiError::invalid("unknown or malformed request");
    let value: Value = serde_json::from_str(line.trim()).map_err(|_| bad())?;
    let obj = value.as_object().filter(|o| o.len() == 1).ok_or_else(bad)?;
    match obj.get("op").and_then(Value::as_str).ok_or_else(bad)? {
        "ping" => Ok(Request::Ping),
        "auth.bootstrap" => Ok(Request::AuthBootstrap),
        "auth.revoke_all" => Ok(Request::AuthRevokeAll),
        "service.status" => Ok(Request::ServiceStatus),
        "scan.refresh" => Ok(Request::ScanRefresh),
        "discovery.status" => Ok(Request::DiscoveryStatus),
        _ => Err(bad()),
    }
}

pub async fn dispatch(service: &Service, req: Request) -> Result<Value, ApiError> {
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
