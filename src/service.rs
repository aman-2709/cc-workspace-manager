//! The service layer: every operation exposed by the HTTP API and the Unix socket lives here, so the
//! transports contain no business logic.

use crate::api_error::ApiError;
use crate::auth::bootstrap::{BootstrapStore, BOOTSTRAP_TTL_SECS};
use crate::auth::sessions::{AuthedSession, IssuedSession, Sessions};
use crate::auth::tokens::{base64url_decode, base64url_encode};
use crate::clock::Clock;
use crate::db::queries::{self, ListParams, Order, ProjectRow};
use crate::db::reader::Reader;
use crate::db::writer::Writer;
use crate::discovery::status::{DiscoverySnapshot, SharedStatus};
use crate::sandbox::SandboxReport;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_LIMIT: u32 = 50;
pub const MAX_LIMIT: u32 = 200;
const MAX_QUERY_CHARS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BootstrapIssued {
    pub bootstrap_token: String,
    pub expires_in: i64,
    /// The TCP port the daemon actually bound (the CLI takes it from here, never from a probe).
    pub port: u16,
}

/// Raw, unvalidated `GET /projects` parameters.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectsQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub limit: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectsPage {
    pub items: Vec<ProjectRow>,
    pub next_cursor: Option<String>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Stats {
    pub total_projects: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiscoveryBrief {
    pub phase: crate::discovery::status::Phase,
    pub last_success_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub version: &'static str,
    pub uptime_s: i64,
    pub port: u16,
    pub sandbox: SandboxReport,
    pub discovery: DiscoveryBrief,
}

/// Keyset cursor; opaque to clients.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    s: String,
    o: String,
    k: String,
    i: String,
}

pub struct Service {
    pub clock: Arc<dyn Clock>,
    pub writer: Arc<Writer>,
    pub reader: Reader,
    pub bootstrap: BootstrapStore,
    pub sessions: Sessions,
    pub discovery: SharedStatus,
    pub sandbox: SandboxReport,
    port: u16,
    started_at: i64,
}

impl Service {
    pub fn new(
        clock: Arc<dyn Clock>,
        writer: Arc<Writer>,
        reader: Reader,
        discovery: SharedStatus,
        sandbox: SandboxReport,
        port: u16,
    ) -> Self {
        let started_at = clock.now();
        Self {
            bootstrap: BootstrapStore::new(Arc::clone(&clock)),
            sessions: Sessions::new(Arc::clone(&writer), reader.clone(), Arc::clone(&clock)),
            clock,
            writer,
            reader,
            discovery,
            sandbox,
            port,
            started_at,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn health(&self) -> Health {
        Health {
            status: "ok",
            version: VERSION,
        }
    }

    // ---- auth -------------------------------------------------------------------------------

    pub fn auth_bootstrap(&self) -> Result<BootstrapIssued, ApiError> {
        Ok(BootstrapIssued {
            bootstrap_token: self.bootstrap.issue()?,
            expires_in: BOOTSTRAP_TTL_SECS,
            port: self.port,
        })
    }

    pub async fn auth_exchange(&self, bootstrap_token: &str) -> Result<IssuedSession, ApiError> {
        if !self.bootstrap.redeem(bootstrap_token) {
            return Err(ApiError::unauthorized());
        }
        self.sessions.create().await
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthedSession, ApiError> {
        self.sessions.authenticate(token).await
    }

    pub async fn auth_rotate(&self, token: &str) -> Result<IssuedSession, ApiError> {
        self.sessions.rotate(token).await
    }

    pub async fn auth_logout(&self, token: &str) -> Result<(), ApiError> {
        self.sessions.logout(token).await
    }

    pub async fn auth_revoke_all(&self) -> Result<u64, ApiError> {
        self.sessions.revoke_all().await
    }

    // ---- data -------------------------------------------------------------------------------

    pub async fn list_projects(&self, q: ProjectsQuery) -> Result<ProjectsPage, ApiError> {
        let v = validate_projects_query(&q)?;
        let limit = v.limit;
        let params = ListParams {
            q: v.q,
            order: v.sql_order,
            limit: limit + 1,
            after: v.after,
        };
        let (mut rows, total) = self
            .reader
            .with(move |c| queries::list_projects(c, &params))
            .await?;
        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next_cursor = match (has_more, rows.last()) {
            (true, Some(last)) => Some(encode_cursor(
                &v.sort,
                &v.order,
                &last.name.to_lowercase(),
                &last.id,
            )),
            _ => None,
        };
        Ok(ProjectsPage {
            items: rows,
            next_cursor,
            total,
        })
    }

    pub async fn stats(&self) -> Result<Stats, ApiError> {
        Ok(Stats {
            total_projects: self.reader.with(queries::count_projects).await?,
        })
    }

    pub fn discovery_status(&self) -> DiscoverySnapshot {
        self.discovery.snapshot()
    }

    pub fn service_status(&self) -> ServiceStatus {
        let d = self.discovery.snapshot();
        ServiceStatus {
            version: VERSION,
            uptime_s: (self.clock.now() - self.started_at).max(0),
            port: self.port,
            sandbox: self.sandbox.clone(),
            discovery: DiscoveryBrief {
                phase: d.phase,
                last_success_at: d.last_success_at,
            },
        }
    }
}

struct ValidQuery {
    q: Option<String>,
    sort: String,
    order: String,
    sql_order: Order,
    limit: u32,
    after: Option<(String, String)>,
}

fn encode_cursor(sort: &str, order: &str, key: &str, id: &str) -> String {
    let c = Cursor {
        s: sort.into(),
        o: order.into(),
        k: key.into(),
        i: id.into(),
    };
    base64url_encode(serde_json::to_string(&c).unwrap_or_default().as_bytes())
}

fn decode_cursor(raw: &str, sort: &str, order: &str) -> Result<(String, String), ApiError> {
    let bad = || ApiError::invalid("invalid cursor");
    let bytes = base64url_decode(raw).ok_or_else(bad)?;
    let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    let id_ok = c.i.len() == 32 && c.i.bytes().all(|b| b.is_ascii_hexdigit());
    if c.s != sort || c.o != order || !id_ok || c.k.len() > 1024 {
        return Err(bad());
    }
    Ok((c.k, c.i))
}

fn validate_projects_query(q: &ProjectsQuery) -> Result<ValidQuery, ApiError> {
    let search = match q.q.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) if s.chars().count() > MAX_QUERY_CHARS => {
            return Err(ApiError::invalid("q is too long"))
        }
        Some(s) if s.chars().any(char::is_control) => {
            return Err(ApiError::invalid("q contains control characters"))
        }
        Some(s) => Some(s.to_string()),
    };
    let sort = q.sort.as_deref().unwrap_or("activity");
    if !matches!(sort, "activity" | "name") {
        return Err(ApiError::invalid("sort must be one of: activity, name"));
    }
    let order = match q.order.as_deref() {
        None => "asc",
        Some(o @ ("asc" | "desc")) => o,
        Some(_) => return Err(ApiError::invalid("order must be asc or desc")),
    };
    // Without activity timestamps (M1) "unknown sorts last, ties by name" is plain name order, and
    // `order` only flips an explicit name sort.
    let (order, sql_order) = if sort == "name" && order == "desc" {
        ("desc", Order::Desc)
    } else {
        ("asc", Order::Asc)
    };
    let limit = match q.limit.as_deref() {
        None => DEFAULT_LIMIT,
        Some(s) => match s.parse::<u32>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
            _ => {
                return Err(ApiError::invalid(format!(
                    "limit must be an integer between 1 and {MAX_LIMIT}"
                )))
            }
        },
    };
    let after = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c, sort, order))
        .transpose()?;
    Ok(ValidQuery {
        q: search,
        sort: sort.to_string(),
        order: order.to_string(),
        sql_order,
        limit,
        after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(f: impl FnOnce(&mut ProjectsQuery)) -> Result<ValidQuery, ApiError> {
        let mut query = ProjectsQuery::default();
        f(&mut query);
        validate_projects_query(&query)
    }

    #[test]
    fn defaults() {
        let v = q(|_| {}).unwrap();
        assert_eq!(
            (v.sort.as_str(), v.order.as_str(), v.limit, v.q),
            ("activity", "asc", 50, None)
        );
    }

    #[test]
    fn validation_errors() {
        assert!(q(|x| x.sort = Some("bogus".into())).is_err());
        assert!(q(|x| x.order = Some("sideways".into())).is_err());
        for bad in ["0", "201", "-1", "abc", "", "1.5", "99999999999"] {
            assert!(q(|x| x.limit = Some(bad.into())).is_err(), "{bad:?}");
        }
        assert!(q(|x| x.q = Some("a".repeat(201))).is_err());
        assert!(q(|x| x.q = Some("a\nb".into())).is_err());
        assert!(
            q(|x| x.limit = Some("200".into())).is_ok()
                && q(|x| x.limit = Some("1".into())).is_ok()
        );
    }

    #[test]
    fn blank_search_is_no_search_and_text_is_trimmed() {
        assert_eq!(q(|x| x.q = Some("   ".into())).unwrap().q, None);
        assert_eq!(
            q(|x| x.q = Some(" abc ".into())).unwrap().q.as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn cursor_roundtrip_and_forgery() {
        let id = "0123456789abcdef0123456789abcdef";
        let c = encode_cursor("name", "desc", "key", id);
        assert_eq!(
            decode_cursor(&c, "name", "desc").unwrap(),
            ("key".to_string(), id.to_string())
        );
        assert!(decode_cursor(&c, "name", "asc").is_err(), "order mismatch");
        assert!(
            decode_cursor(&c, "activity", "desc").is_err(),
            "sort mismatch"
        );
        assert!(decode_cursor("not base64 ***", "name", "asc").is_err());
        assert!(decode_cursor(&base64url_encode(b"{}"), "name", "asc").is_err());
        assert!(decode_cursor(
            &base64url_encode(br#"{"s":"name","o":"asc","k":"x","i":"short"}"#),
            "name",
            "asc"
        )
        .is_err());
        assert!(decode_cursor(
            &base64url_encode(
                br#"{"s":"name","o":"asc","k":"x","i":"0123456789abcdef0123456789abcdef","z":1}"#
            ),
            "name",
            "asc"
        )
        .is_err());
    }

    #[test]
    fn activity_sort_ignores_order_until_timestamps_exist() {
        let v = q(|x| {
            x.sort = Some("activity".into());
            x.order = Some("desc".into());
        })
        .unwrap();
        assert_eq!((v.order.as_str(), v.sql_order), ("asc", Order::Asc));
        let v = q(|x| {
            x.sort = Some("name".into());
            x.order = Some("desc".into());
        })
        .unwrap();
        assert_eq!(v.sql_order, Order::Desc);
    }
}
