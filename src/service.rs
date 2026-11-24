//! The service layer: every operation exposed by the HTTP API and the Unix socket lives here, so the
//! transports contain no business logic.

use crate::activity::{Classifier, Filter};
use crate::api_error::{ApiError, Code};
use crate::auth::bootstrap::{BootstrapStore, BOOTSTRAP_TTL_SECS};
use crate::auth::sessions::{AuthedSession, IssuedSession, Sessions};
use crate::auth::tokens::{base64url_decode, base64url_encode};
use crate::clock::Clock;
use crate::db::queries::{self, Filters, ListParams, Order, SortBy};
use crate::db::reader::Reader;
use crate::db::writer::Writer;
use crate::discovery::status::{DiscoverySnapshot, SharedStatus};
use crate::events::{next_batch, Batch, Change, Hub, Notifier};
use crate::git::GitSummary;
use crate::sandbox::SandboxReport;
use crate::tracker::{Control, Tracker};
use crate::view::{self, ProjectDetail, ProjectView};
use crate::watch::{MonitorStatus, SharedMonitor};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The Git commit this binary was built from (`build.rs`): `<12 hex>[-dirty]` or `unknown`.
pub const COMMIT: &str = env!("CCWM_GIT_COMMIT");
pub const DEFAULT_LIMIT: u32 = 50;
pub const MAX_LIMIT: u32 = 200;
const MAX_QUERY_CHARS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
    pub commit: &'static str,
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
    pub activity: Option<String>,
    pub dirty: Option<String>,
    pub include_missing: Option<String>,
    pub include_ignored: Option<String>,
    pub limit: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectsPage {
    pub items: Vec<ProjectView>,
    pub next_cursor: Option<String>,
    pub total: u64,
}

/// Summary statistics (§9). Counts cover present, non-ignored projects; `missing` counts
/// missing, non-ignored ones. "This week" = today + recent (§5.3).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Stats {
    pub total_projects: u64,
    pub modified_today: u64,
    pub modified_this_week: u64,
    pub inactive: u64,
    pub dormant: u64,
    pub unknown_activity: u64,
    pub uncommitted_changes: u64,
    pub missing: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiscoveryBrief {
    pub phase: crate::discovery::status::Phase,
    pub last_success_at: Option<i64>,
    pub next_scan_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Queues {
    pub git_in_flight: usize,
    pub websocket_clients: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub version: &'static str,
    pub commit: &'static str,
    pub uptime_s: i64,
    pub port: u16,
    pub sandbox: SandboxReport,
    pub discovery: DiscoveryBrief,
    pub monitoring: MonitorStatus,
    /// `null` when the tracker is not running (tests).
    pub git: Option<GitSummary>,
    pub queues: Queues,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Accepted {
    pub status: &'static str,
    /// The requested scan has finished once discovery's `scans_finished` reaches this value.
    pub done_at_scans_finished: u64,
}

/// Keyset cursor; opaque to clients.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    s: String,
    o: String,
    v: i64,
    k: String,
    i: String,
}

/// Everything the service needs. `tracker` is `None` in tests that exercise the transports only.
pub struct Deps {
    pub clock: Arc<dyn Clock>,
    pub writer: Arc<Writer>,
    pub reader: Reader,
    pub discovery: SharedStatus,
    pub sandbox: SandboxReport,
    pub port: u16,
    pub home: PathBuf,
    pub classifier: Classifier,
    pub monitor: SharedMonitor,
    pub notifier: Notifier,
    pub tracker: Option<Arc<Tracker>>,
}

pub struct Service {
    pub clock: Arc<dyn Clock>,
    pub writer: Arc<Writer>,
    pub reader: Reader,
    pub bootstrap: BootstrapStore,
    pub sessions: Sessions,
    pub discovery: SharedStatus,
    pub sandbox: SandboxReport,
    pub hub: Hub,
    pub notifier: Notifier,
    monitor: SharedMonitor,
    tracker: Option<Arc<Tracker>>,
    home: PathBuf,
    classifier: Classifier,
    /// Bumped whenever sessions are revoked; open WebSockets revalidate their token at once.
    auth_epoch: watch::Sender<u64>,
    port: u16,
    started_at: i64,
    /// Last monitoring message sent (to skip repeats).
    last_monitoring: Mutex<Option<String>>,
}

impl Service {
    pub fn new(d: Deps) -> Self {
        let started_at = d.clock.now();
        Self {
            bootstrap: BootstrapStore::new(Arc::clone(&d.clock)),
            sessions: Sessions::new(
                Arc::clone(&d.writer),
                d.reader.clone(),
                Arc::clone(&d.clock),
            ),
            clock: d.clock,
            writer: d.writer,
            reader: d.reader,
            discovery: d.discovery,
            sandbox: d.sandbox,
            hub: Hub::default(),
            notifier: d.notifier,
            monitor: d.monitor,
            tracker: d.tracker,
            home: d.home,
            classifier: d.classifier,
            auth_epoch: watch::channel(0).0,
            port: d.port,
            started_at,
            last_monitoring: Mutex::new(None),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn health(&self) -> Health {
        Health {
            status: "ok",
            version: VERSION,
            commit: COMMIT,
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
        self.sessions.logout(token).await?;
        self.revalidate_sockets();
        Ok(())
    }

    pub async fn auth_revoke_all(&self) -> Result<u64, ApiError> {
        let n = self.sessions.revoke_all().await?;
        self.revalidate_sockets();
        Ok(n)
    }

    /// Make every open WebSocket revalidate its token now (after purging expired sessions; the
    /// periodic check catches the rest within [`crate::http::ws::REVALIDATE`]).
    pub fn revalidate_sockets(&self) {
        self.auth_epoch.send_modify(|e| *e += 1);
    }

    /// Changes whenever sessions were revoked (WebSockets revalidate on change).
    pub fn auth_changes(&self) -> watch::Receiver<u64> {
        self.auth_epoch.subscribe()
    }

    // ---- projects ---------------------------------------------------------------------------

    fn view(&self, row: &queries::ProjectRow, now: i64) -> ProjectView {
        let monitoring = if row.ignored || row.missing_since.is_some() {
            None
        } else {
            self.monitor.of(&row.id)
        };
        view::project_view(row, &self.classifier, now, &self.home, monitoring)
    }

    pub async fn list_projects(&self, q: ProjectsQuery) -> Result<ProjectsPage, ApiError> {
        let now = self.clock.now();
        let v = validate_projects_query(&q, &self.classifier, now)?;
        let limit = v.params.limit;
        let mut params = v.params.clone();
        params.limit = limit + 1;
        let (mut rows, total) = self
            .reader
            .with(move |c| queries::list_projects(c, &params))
            .await?;
        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next_cursor = match (has_more, rows.last()) {
            (true, Some(last)) => Some(encode_cursor(&v.sort, &v.order, last)),
            _ => None,
        };
        Ok(ProjectsPage {
            items: rows.iter().map(|r| self.view(r, now)).collect(),
            next_cursor,
            total,
        })
    }

    async fn row(&self, id: &str) -> Result<queries::ProjectRow, ApiError> {
        if !is_project_id(id) {
            return Err(ApiError::new(Code::NotFound, "no such project"));
        }
        let id = id.to_string();
        self.reader
            .with(move |c| queries::get_project(c, &id))
            .await?
            .ok_or_else(|| ApiError::new(Code::NotFound, "no such project"))
    }

    pub async fn project(&self, id: &str) -> Result<ProjectDetail, ApiError> {
        let row = self.row(id).await?;
        Ok(ProjectDetail {
            project: self.view(&row, self.clock.now()),
            git_detail: row.git.as_ref().map(view::git_detail),
        })
    }

    /// Ignore (`true`) or un-ignore a project by its canonical path (§4.5). Idempotent.
    pub async fn set_ignored(&self, id: &str, ignored: bool) -> Result<ProjectView, ApiError> {
        let row = self.row(id).await?;
        let changed = self
            .writer
            .set_ignored(&row.path, ignored, self.clock.now())
            .await?;
        if changed {
            self.control(if ignored {
                Control::Ignored(row.id.clone())
            } else {
                Control::Unignored(row.id.clone())
            });
            self.notifier.project(&row.id);
        }
        let row = self.row(id).await?;
        Ok(self.view(&row, self.clock.now()))
    }

    fn control(&self, c: Control) {
        if let Some(t) = &self.tracker {
            let t = Arc::clone(t);
            tokio::spawn(async move {
                if let Err(e) = t.on_control(c).await {
                    tracing::warn!(error = %e, "tracker request failed");
                }
            });
        }
    }

    /// Trigger a coalesced reconciliation (§4.5).
    pub fn refresh(&self) -> Result<Accepted, ApiError> {
        match &self.tracker {
            Some(t) => Ok(Accepted {
                status: "accepted",
                done_at_scans_finished: t.request_refresh(),
            }),
            None => Err(ApiError::internal("refresh requested without a tracker")),
        }
    }

    pub async fn stats(&self) -> Result<Stats, ApiError> {
        let b = self
            .classifier
            .boundaries(self.clock.now())
            .ok_or_else(|| ApiError::internal("cannot compute day boundaries"))?;
        let c = self
            .reader
            .with(move |c| queries::stat_counts(c, &b))
            .await?;
        Ok(Stats {
            total_projects: c.total,
            modified_today: c.today,
            modified_this_week: c.week,
            inactive: c.inactive,
            dormant: c.dormant,
            unknown_activity: c.unknown,
            uncommitted_changes: c.dirty,
            missing: c.missing,
        })
    }

    pub fn discovery_status(&self) -> DiscoverySnapshot {
        self.discovery.snapshot()
    }

    pub fn service_status(&self) -> ServiceStatus {
        let d = self.discovery.snapshot();
        ServiceStatus {
            version: VERSION,
            commit: COMMIT,
            uptime_s: (self.clock.now() - self.started_at).max(0),
            port: self.port,
            sandbox: self.sandbox.clone(),
            discovery: DiscoveryBrief {
                phase: d.phase,
                last_success_at: d.last_success_at,
                next_scan_at: d.next_scan_at,
            },
            monitoring: self.monitor.snapshot(),
            git: self.tracker.as_ref().map(|t| t.git.summary()),
            queues: Queues {
                git_in_flight: self.tracker.as_ref().map_or(0, |t| t.git.in_flight()),
                websocket_clients: self.hub.clients(),
            },
        }
    }

    // ---- live updates -----------------------------------------------------------------------

    /// Turn coalesced changes into WebSocket messages until `stop` or every producer is gone.
    pub async fn run_publisher(
        self: Arc<Self>,
        mut changes: mpsc::Receiver<Change>,
        mut stop: watch::Receiver<bool>,
    ) {
        loop {
            let batch = tokio::select! {
                b = next_batch(&mut changes) => b,
                () = crate::events::until_stopped(&mut stop) => None,
            };
            let Some(batch) = batch else { break };
            if let Err(e) = self.publish(batch).await {
                tracing::warn!(error = %e, "publishing live updates failed");
            }
        }
    }

    pub async fn publish(&self, batch: Batch) -> Result<(), ApiError> {
        if self.hub.clients() == 0 {
            return Ok(());
        }
        if self.notifier.take_lost() {
            self.hub.send(&crate::events::resync());
            return Ok(());
        }
        let now = self.clock.now();
        for id in &batch.changed {
            let id2 = id.clone();
            match self
                .reader
                .with(move |c| queries::get_project(c, &id2))
                .await?
            {
                Some(row) => self.hub.send(&serde_json::json!({
                    "type": "project",
                    "project": self.view(&row, now),
                })),
                None => self
                    .hub
                    .send(&serde_json::json!({"type": "project_removed", "id": id})),
            }
        }
        for id in &batch.removed {
            self.hub
                .send(&serde_json::json!({"type": "project_removed", "id": id}));
        }
        if !batch.changed.is_empty() || !batch.removed.is_empty() || batch.status {
            self.hub
                .send(&serde_json::json!({"type": "stats", "stats": self.stats().await?}));
        }
        if batch.status {
            self.hub.send(&serde_json::json!({
                "type": "discovery",
                "status": self.discovery_status(),
            }));
            let monitoring = serde_json::json!({
                "type": "monitoring",
                "monitoring": self.monitor.snapshot(),
            });
            let text = monitoring.to_string();
            let mut last = self.last_monitoring.lock().map_err(ApiError::internal)?;
            if last.as_deref() != Some(text.as_str()) {
                self.hub.send(&monitoring);
                *last = Some(text);
            }
        }
        Ok(())
    }
}

/// Project ids are 32 lowercase hex characters (`db::writer::random_id`).
pub fn is_project_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone)]
struct ValidQuery {
    sort: String,
    order: String,
    params: ListParams,
}

fn encode_cursor(sort: &str, order: &str, last: &queries::ProjectRow) -> String {
    let c = Cursor {
        s: sort.into(),
        o: order.into(),
        v: last.k1,
        k: last.sort_key.clone(),
        i: last.id.clone(),
    };
    base64url_encode(serde_json::to_string(&c).unwrap_or_default().as_bytes())
}

fn decode_cursor(raw: &str, sort: &str, order: &str) -> Result<(i64, String, String), ApiError> {
    let bad = || ApiError::invalid("invalid cursor");
    let bytes = base64url_decode(raw).ok_or_else(bad)?;
    let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if c.s != sort || c.o != order || !is_project_id(&c.i) || c.k.len() > 1024 {
        return Err(bad());
    }
    Ok((c.v, c.k, c.i))
}

/// `1`/`true` or `0`/`false`; absent = false.
fn flag(v: Option<&str>, name: &str) -> Result<bool, ApiError> {
    match v {
        None | Some("0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        Some(_) => Err(ApiError::invalid(format!(
            "{name} must be 1, 0, true or false"
        ))),
    }
}

fn validate_projects_query(
    q: &ProjectsQuery,
    classifier: &Classifier,
    now: i64,
) -> Result<ValidQuery, ApiError> {
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
    let sort_name = q.sort.as_deref().unwrap_or("activity");
    let sort = match sort_name {
        "activity" => SortBy::Activity,
        "name" => SortBy::Name,
        "commit" => SortBy::Commit,
        _ => {
            return Err(ApiError::invalid(
                "sort must be one of: activity, name, commit",
            ))
        }
    };
    // Times default to newest first, names to A-Z.
    let default_order = if sort == SortBy::Name { "asc" } else { "desc" };
    let order_name = q.order.as_deref().unwrap_or(default_order);
    let order = match order_name {
        "asc" => Order::Asc,
        "desc" => Order::Desc,
        _ => return Err(ApiError::invalid("order must be asc or desc")),
    };
    let activity = match q.activity.as_deref() {
        None | Some("all") => None,
        Some(a) => {
            let f = Filter::parse(a).ok_or_else(|| {
                ApiError::invalid(
                    "activity must be one of: all, today, week, inactive, dormant, unknown",
                )
            })?;
            Some(
                classifier
                    .range(f, now)
                    .ok_or_else(|| ApiError::internal("cannot compute day boundaries"))?,
            )
        }
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
        .map(|c| decode_cursor(c, sort_name, order_name))
        .transpose()?;
    Ok(ValidQuery {
        sort: sort_name.to_string(),
        order: order_name.to_string(),
        params: ListParams {
            filters: Filters {
                q: search,
                include_missing: flag(q.include_missing.as_deref(), "include_missing")?,
                include_ignored: flag(q.include_ignored.as_deref(), "include_ignored")?,
                dirty: flag(q.dirty.as_deref(), "dirty")?,
                activity,
            },
            sort,
            order,
            limit,
            after,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ActivityConfig;

    fn q(f: impl FnOnce(&mut ProjectsQuery)) -> Result<ValidQuery, ApiError> {
        let mut query = ProjectsQuery::default();
        f(&mut query);
        let c = Classifier::new(jiff::tz::TimeZone::UTC, &ActivityConfig::default());
        validate_projects_query(&query, &c, 1_800_000_000)
    }

    #[test]
    fn defaults() {
        let v = q(|_| {}).unwrap();
        assert_eq!(
            (v.sort.as_str(), v.order.as_str(), v.params.limit),
            ("activity", "desc", 50)
        );
        assert_eq!(v.params.filters, Filters::default());
        assert_eq!(q(|x| x.sort = Some("name".into())).unwrap().order, "asc");
        assert_eq!(q(|x| x.sort = Some("commit".into())).unwrap().order, "desc");
    }

    #[test]
    fn validation_errors() {
        for bad_sort in ["bogus", "session", "Name"] {
            assert!(q(|x| x.sort = Some(bad_sort.into())).is_err(), "{bad_sort}");
        }
        assert!(q(|x| x.order = Some("sideways".into())).is_err());
        for bad in ["0", "201", "-1", "abc", "", "1.5", "99999999999"] {
            assert!(q(|x| x.limit = Some(bad.into())).is_err(), "{bad:?}");
        }
        assert!(q(|x| x.q = Some("a".repeat(201))).is_err());
        assert!(q(|x| x.q = Some("a\nb".into())).is_err());
        assert!(q(|x| x.activity = Some("yesterday".into())).is_err());
        for name in ["dirty", "include_missing", "include_ignored"] {
            let r = q(|x| {
                let v = Some("yes".to_string());
                match name {
                    "dirty" => x.dirty = v,
                    "include_missing" => x.include_missing = v,
                    _ => x.include_ignored = v,
                }
            });
            assert!(r.is_err(), "{name}");
        }
        assert!(
            q(|x| x.limit = Some("200".into())).is_ok()
                && q(|x| x.limit = Some("1".into())).is_ok()
        );
    }

    #[test]
    fn filters_are_parsed() {
        let v = q(|x| {
            x.activity = Some("week".into());
            x.dirty = Some("1".into());
            x.include_missing = Some("true".into());
            x.include_ignored = Some("0".into());
        })
        .unwrap();
        let f = v.params.filters;
        assert!(f.dirty && f.include_missing && !f.include_ignored);
        assert!(f.activity.unwrap().from.is_some());
        assert!(q(|x| x.activity = Some("all".into()))
            .unwrap()
            .params
            .filters
            .activity
            .is_none());
        assert!(
            q(|x| x.activity = Some("unknown".into()))
                .unwrap()
                .params
                .filters
                .activity
                .unwrap()
                .unknown
        );
    }

    #[test]
    fn blank_search_is_no_search_and_text_is_trimmed() {
        assert_eq!(
            q(|x| x.q = Some("   ".into())).unwrap().params.filters.q,
            None
        );
        assert_eq!(
            q(|x| x.q = Some(" abc ".into()))
                .unwrap()
                .params
                .filters
                .q
                .as_deref(),
            Some("abc")
        );
    }

    fn row(k1: i64) -> queries::ProjectRow {
        queries::ProjectRow {
            id: "0123456789abcdef0123456789abcdef".into(),
            sort_key: "key".into(),
            k1,
            name: "n".into(),
            path: "/p".into(),
            sources: vec![],
            first_seen_at: 0,
            activity_at: None,
            activity_kind: None,
            activity_path: None,
            missing_since: None,
            ignored: false,
            git: None,
        }
    }

    #[test]
    fn cursor_roundtrip_and_forgery() {
        let c = encode_cursor("name", "desc", &row(-5));
        assert_eq!(
            decode_cursor(&c, "name", "desc").unwrap(),
            (
                -5,
                "key".to_string(),
                "0123456789abcdef0123456789abcdef".to_string()
            )
        );
        assert!(decode_cursor(&c, "name", "asc").is_err(), "order mismatch");
        assert!(
            decode_cursor(&c, "activity", "desc").is_err(),
            "sort mismatch"
        );
        assert!(decode_cursor("not base64 ***", "name", "asc").is_err());
        assert!(decode_cursor(&base64url_encode(b"{}"), "name", "asc").is_err());
        assert!(decode_cursor(
            &base64url_encode(br#"{"s":"name","o":"asc","v":0,"k":"x","i":"short"}"#),
            "name",
            "asc"
        )
        .is_err());
        assert!(decode_cursor(
            &base64url_encode(
                br#"{"s":"name","o":"asc","v":0,"k":"x","i":"0123456789abcdef0123456789abcdef","z":1}"#
            ),
            "name",
            "asc"
        )
        .is_err());
        assert!(
            decode_cursor(
                &base64url_encode(
                    br#"{"s":"name","o":"asc","k":"x","i":"0123456789abcdef0123456789abcdef"}"#
                ),
                "name",
                "asc"
            )
            .is_err(),
            "an M1 cursor (no v) is rejected"
        );
    }

    #[test]
    fn project_ids_are_strict() {
        assert!(is_project_id("0123456789abcdef0123456789abcdef"));
        for bad in [
            "",
            "0123456789ABCDEF0123456789abcdef",
            "../../etc/passwd",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdefg",
        ] {
            assert!(!is_project_id(bad), "{bad}");
        }
    }
}
