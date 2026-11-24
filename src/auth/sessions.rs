//! Browser sessions: 32-byte bearer tokens stored only as SHA-256 digests, sliding 30-day expiry,
//! rotation (new token now, old token honoured for a 60 s grace window), logout and revoke-all.
//! Rotation is enforced: once a token is overdue (more than 24 h + 60 s since the session last
//! rotated), it is accepted **only** by `rotate` (M1.1, finding L1).

use super::tokens::{digests_equal, hash_token, is_well_formed, new_token};
use crate::api_error::ApiError;
use crate::clock::Clock;
use crate::db::queries;
use crate::db::reader::Reader;
use crate::db::writer::Writer;
use serde::Serialize;
use std::sync::Arc;

pub const SESSION_TTL_SECS: i64 = 30 * 24 * 3600;
pub const ROTATE_AFTER_SECS: i64 = 24 * 3600;
pub const ROTATION_GRACE_SECS: i64 = 60;
/// After `rotate_after`, a client gets this long (it checks just before sending) before the token
/// is restricted to `rotate`.
pub const ROTATION_OVERDUE_SLACK_SECS: i64 = 60;
/// The sliding expiry is persisted at most this often per session.
pub const TOUCH_INTERVAL_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IssuedSession {
    pub session_token: String,
    pub expires_at: i64,
    pub rotate_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthedSession {
    pub id: String,
    pub token_hash: [u8; 32],
    pub via_previous: bool,
}

#[derive(Clone)]
pub struct Sessions {
    writer: Arc<Writer>,
    reader: Reader,
    clock: Arc<dyn Clock>,
}

impl Sessions {
    pub fn new(writer: Arc<Writer>, reader: Reader, clock: Arc<dyn Clock>) -> Self {
        Self {
            writer,
            reader,
            clock,
        }
    }

    pub async fn create(&self) -> Result<IssuedSession, ApiError> {
        let token = new_token()?;
        let now = self.clock.now();
        let stored = self
            .writer
            .create_session(hash_token(&token), now, now + SESSION_TTL_SECS)
            .await?;
        Ok(IssuedSession {
            session_token: token,
            expires_at: stored.expires_at,
            rotate_after: stored.rotated_at + ROTATE_AFTER_SECS,
        })
    }

    /// Resolve a bearer token for ordinary use. Every failure is the same `Unauthorized`,
    /// including a token whose rotation is overdue.
    pub async fn authenticate(&self, token: &str) -> Result<AuthedSession, ApiError> {
        let (authed, overdue) = self.lookup(token).await?;
        if overdue {
            return Err(ApiError::unauthorized());
        }
        Ok(authed)
    }

    /// Resolve a token without the rotation check; also says whether rotation is overdue.
    async fn lookup(&self, token: &str) -> Result<(AuthedSession, bool), ApiError> {
        if !is_well_formed(token) {
            return Err(ApiError::unauthorized());
        }
        let hash = hash_token(token);
        let now = self.clock.now();
        let rec = self
            .reader
            .with(move |c| queries::find_session(c, &hash, now))
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        if !digests_equal(&rec.matched_hash, &hash) || rec.expires_at <= now {
            return Err(ApiError::unauthorized());
        }
        if now - rec.last_used_at >= TOUCH_INTERVAL_SECS {
            self.writer
                .touch_session(rec.id.clone(), now, now + SESSION_TTL_SECS);
        }
        let overdue = now >= rec.rotated_at + ROTATE_AFTER_SECS + ROTATION_OVERDUE_SLACK_SECS;
        Ok((
            AuthedSession {
                id: rec.id,
                token_hash: hash,
                via_previous: rec.via_previous,
            },
            overdue,
        ))
    }

    /// Issue a new token for the session; the presented (current) token stays valid for 60 s more.
    /// The only operation an overdue token may perform.
    pub async fn rotate(&self, token: &str) -> Result<IssuedSession, ApiError> {
        let (authed, _overdue) = self.lookup(token).await?;
        if authed.via_previous {
            return Err(ApiError::unauthorized()); // only the current token may rotate
        }
        let new = new_token()?;
        let now = self.clock.now();
        let stored = self
            .writer
            .rotate_session(
                authed.token_hash,
                hash_token(&new),
                now,
                now + ROTATION_GRACE_SECS,
                now + SESSION_TTL_SECS,
            )
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(IssuedSession {
            session_token: new,
            expires_at: stored.expires_at,
            rotate_after: now + ROTATE_AFTER_SECS,
        })
    }

    pub async fn logout(&self, token: &str) -> Result<(), ApiError> {
        let authed = self.authenticate(token).await?;
        self.writer.delete_session(authed.token_hash).await?;
        Ok(())
    }

    pub async fn revoke_all(&self) -> Result<u64, ApiError> {
        Ok(self.writer.revoke_all().await?)
    }
}
