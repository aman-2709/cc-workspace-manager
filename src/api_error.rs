//! The error type shared by every transport (HTTP and the Unix socket) and the service layer.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    InvalidArgument,
    Unauthorized,
    OriginNotAllowed,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    HostNotAllowed,
    Internal,
}

impl Code {
    pub fn status(self) -> u16 {
        match self {
            Self::InvalidArgument => 400,
            Self::Unauthorized => 401,
            Self::OriginNotAllowed => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::HostNotAllowed => 421,
            Self::Internal => 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: Code,
    pub message: String,
}

impl ApiError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    /// One message for every authentication failure, so responses reveal nothing about why.
    pub fn unauthorized() -> Self {
        Self::new(
            Code::Unauthorized,
            "authentication required or token invalid",
        )
    }

    /// Log the cause, return a generic message (never content, tokens or paths).
    pub fn internal(cause: impl fmt::Display) -> Self {
        tracing::error!(error = %cause, "internal error");
        Self::new(Code::Internal, "internal error")
    }

    /// `{"error":{"code":"…","message":"…"}}`
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "error": { "code": self.code, "message": self.message } })
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<crate::error::Error> for ApiError {
    fn from(e: crate::error::Error) -> Self {
        Self::internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_and_status_codes() {
        let e = ApiError::invalid("bad limit");
        assert_eq!(
            e.to_json(),
            serde_json::json!({"error":{"code":"invalid_argument","message":"bad limit"}})
        );
        let table = [
            (Code::InvalidArgument, 400),
            (Code::Unauthorized, 401),
            (Code::OriginNotAllowed, 403),
            (Code::NotFound, 404),
            (Code::MethodNotAllowed, 405),
            (Code::PayloadTooLarge, 413),
            (Code::HostNotAllowed, 421),
            (Code::Internal, 500),
        ];
        for (c, s) in table {
            assert_eq!(c.status(), s);
        }
    }

    #[test]
    fn internal_errors_do_not_leak_the_cause() {
        let e = ApiError::internal("secret path /home/u/x");
        assert_eq!(e.message, "internal error");
        assert!(!e.to_json().to_string().contains("secret"));
    }
}
