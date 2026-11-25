//! Typed read queries. All SQL is parameterized; `LIKE` input is escaped.

use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OptionalExtension};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    /// Latest meaningful modification (§5.4 default).
    Activity,
    Name,
    /// Latest Git commit.
    Commit,
    /// Latest Claude Code session activity.
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filters {
    pub q: Option<String>,
    pub include_missing: bool,
    pub include_ignored: bool,
    /// Only projects with uncommitted changes (staged, modified or untracked).
    pub dirty: bool,
    pub activity: Option<crate::activity::Range>,
    /// Only projects with at least one indexed session.
    pub has_sessions: bool,
    /// Privacy mode: `q` matches the name and branch only, never the (hidden) path.
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListParams {
    pub filters: Filters,
    pub sort: SortBy,
    pub order: Order,
    pub limit: u32,
    /// Keyset position: `(k1, sort_key, id)` of the last row of the previous page.
    pub after: Option<(i64, String, String)>,
}

/// The Git cache of one project as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRow {
    pub fetched_at: i64,
    pub state: String,
    pub branch: Option<String>,
    pub detached: bool,
    pub upstream: Option<String>,
    pub ahead: Option<i64>,
    pub behind: Option<i64>,
    pub staged: Option<i64>,
    pub modified: Option<i64>,
    pub untracked: Option<i64>,
    pub head_commit: Option<String>,
    pub head_subject: Option<String>,
    pub head_author: Option<String>,
    pub head_time: Option<i64>,
    pub remote_url: Option<String>,
    /// JSON file lists; only read for the detail view.
    pub files: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRow {
    pub id: String,
    /// Stored normalized name ([`crate::db::sort_key`]); used for cursors.
    pub sort_key: String,
    /// The primary keyset value for the requested sort (see [`list_projects`]).
    pub k1: i64,
    pub name: String,
    pub path: String,
    pub sources: Vec<String>,
    pub first_seen_at: i64,
    pub activity_at: Option<i64>,
    pub activity_kind: Option<String>,
    pub activity_path: Option<String>,
    pub missing_since: Option<i64>,
    pub ignored: bool,
    pub git: Option<GitRow>,
    pub sessions: SessionSummary,
}

/// The per-project session summary shown on cards and in the table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSummary {
    pub count: u64,
    /// Last activity of the most recent session.
    pub latest_at: Option<i64>,
    /// The most recent session's recorded (redacted) title.
    pub latest_title: Option<String>,
}

/// Escape `%`, `_` and `\` so user text is matched literally.
pub fn like_pattern(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for ch in q.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('%');
    out
}

const PROJECT_COLUMNS: &str = "p.id, p.name, p.canonical_path, p.first_seen_at,
    (SELECT group_concat(source) FROM (SELECT source FROM project_sources s WHERE s.project_id = p.id ORDER BY source)),
    p.sort_key, p.activity_at, p.activity_kind, p.activity_path, p.missing_since,
    (i.canonical_path IS NOT NULL),
    g.fetched_at, g.state, g.branch, g.detached, g.upstream, g.ahead, g.behind, g.staged, g.modified,
    g.untracked, g.head_commit, g.head_subject, g.head_author, g.head_time, g.remote_url,
    p.session_count, p.session_at,
    (SELECT title FROM sessions s WHERE s.project_id = p.id
       ORDER BY coalesce(s.last_activity_at, -9223372036854775807) DESC, s.id LIMIT 1)";

/// Index of `k1` (and then `files`) after [`PROJECT_COLUMNS`].
const AFTER_COLUMNS: usize = 29;

const PROJECT_JOINS: &str = "FROM projects p
    LEFT JOIN git_cache g ON g.project_id = p.id
    LEFT JOIN ignored_paths i ON i.canonical_path = p.canonical_path";

/// Rows are read with [`PROJECT_COLUMNS`] at indexes 0..29, then `k1` and `files` if selected.
fn project_from_row(
    r: &rusqlite::Row<'_>,
    k1_at: Option<usize>,
    files_at: Option<usize>,
) -> rusqlite::Result<ProjectRow> {
    let sources: Option<String> = r.get(4)?;
    let git = match r.get::<_, Option<i64>>(11)? {
        None => None,
        Some(fetched_at) => Some(GitRow {
            fetched_at,
            state: r.get(12)?,
            branch: r.get(13)?,
            detached: r.get::<_, Option<bool>>(14)?.unwrap_or(false),
            upstream: r.get(15)?,
            ahead: r.get(16)?,
            behind: r.get(17)?,
            staged: r.get(18)?,
            modified: r.get(19)?,
            untracked: r.get(20)?,
            head_commit: r.get(21)?,
            head_subject: r.get(22)?,
            head_author: r.get(23)?,
            head_time: r.get(24)?,
            remote_url: r.get(25)?,
            files: files_at.map(|i| r.get(i)).transpose()?.flatten(),
        }),
    };
    Ok(ProjectRow {
        id: r.get(0)?,
        name: r.get(1)?,
        path: r.get(2)?,
        first_seen_at: r.get(3)?,
        sources: sources
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default(),
        sort_key: r.get(5)?,
        activity_at: r.get(6)?,
        activity_kind: r.get(7)?,
        activity_path: r.get(8)?,
        missing_since: r.get(9)?,
        ignored: r.get(10)?,
        git,
        sessions: SessionSummary {
            count: u64::try_from(r.get::<_, i64>(26)?).unwrap_or(0),
            latest_at: r.get(27)?,
            latest_title: r.get(28)?,
        },
        k1: k1_at.map(|i| r.get(i)).transpose()?.unwrap_or(0),
    })
}

/// The `WHERE` clause for [`Filters`], using parameters `?1`..`?9`.
const FILTER_SQL: &str =
    "(?1 IS NULL OR p.name LIKE ?1 ESCAPE '\\' OR (NOT ?9 AND p.canonical_path LIKE ?1 ESCAPE '\\')
                           OR g.branch LIKE ?1 ESCAPE '\\')
     AND (?2 OR p.missing_since IS NULL)
     AND (?3 OR i.canonical_path IS NULL)
     AND (NOT ?4 OR coalesce(g.staged, 0) + coalesce(g.modified, 0) + coalesce(g.untracked, 0) > 0)
     AND (?5 IS NULL OR p.activity_at >= ?5)
     AND (?6 IS NULL OR p.activity_at < ?6)
     AND (NOT ?7 OR p.activity_at IS NULL)
     AND (NOT ?8 OR p.session_count > 0)";

fn filter_values(f: &Filters) -> Vec<Value> {
    let range = f.activity.unwrap_or_default();
    let opt = |v: Option<i64>| v.map_or(Value::Null, Value::Integer);
    vec![
        f.q.as_deref()
            .map(like_pattern)
            .map_or(Value::Null, Value::Text),
        Value::Integer(i64::from(f.include_missing)),
        Value::Integer(i64::from(f.include_ignored)),
        Value::Integer(i64::from(f.dirty)),
        opt(range.from),
        opt(range.until),
        Value::Integer(i64::from(range.unknown)),
        Value::Integer(i64::from(f.has_sessions)),
        Value::Integer(i64::from(f.private)),
    ]
}

/// The primary sort key `k1`, ascending in every case: a time sort maps "newest first" to the
/// negated time, and unknown times to `i64::MAX`, so unknowns sort last in both orders and the
/// tie-break by name stays ascending. Name sorts use a constant and flip the whole order instead.
fn k1_expr(sort: SortBy, order: Order) -> &'static str {
    match (sort, order) {
        (SortBy::Activity, Order::Desc) => "coalesce(-p.activity_at, 9223372036854775807)",
        (SortBy::Activity, Order::Asc) => "coalesce(p.activity_at, 9223372036854775807)",
        (SortBy::Commit, Order::Desc) => "coalesce(-g.head_time, 9223372036854775807)",
        (SortBy::Commit, Order::Asc) => "coalesce(g.head_time, 9223372036854775807)",
        (SortBy::Session, Order::Desc) => "coalesce(-p.session_at, 9223372036854775807)",
        (SortBy::Session, Order::Asc) => "coalesce(p.session_at, 9223372036854775807)",
        (SortBy::Name, _) => "0",
    }
}

/// One page of projects plus the total number of matches (ignoring the cursor).
pub fn list_projects(
    conn: &Connection,
    p: &ListParams,
) -> rusqlite::Result<(Vec<ProjectRow>, u64)> {
    let mut values = filter_values(&p.filters);
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) {PROJECT_JOINS} WHERE {FILTER_SQL}"),
        params_from_iter(values.iter()),
        |r| r.get(0),
    )?;
    let (dir, cmp) = match (p.sort, p.order) {
        (SortBy::Name, Order::Desc) => ("DESC", "<"),
        _ => ("ASC", ">"),
    };
    let k1 = k1_expr(p.sort, p.order);
    let sql = format!(
        "SELECT {PROJECT_COLUMNS}, {k1} AS k1 {PROJECT_JOINS}
         WHERE {FILTER_SQL} AND (?10 IS NULL OR ({k1}, p.sort_key, p.id) {cmp} (?10, ?11, ?12))
         ORDER BY k1 {dir}, p.sort_key {dir}, p.id {dir}
         LIMIT ?13"
    );
    match &p.after {
        Some((k, key, id)) => values.extend([
            Value::Integer(*k),
            Value::Text(key.clone()),
            Value::Text(id.clone()),
        ]),
        None => values.extend([Value::Null, Value::Null, Value::Null]),
    }
    values.push(Value::Integer(i64::from(p.limit)));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(values.iter()), |r| {
            project_from_row(r, Some(AFTER_COLUMNS), None)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((rows, u64::try_from(total).unwrap_or(0)))
}

/// One project with its Git file lists, whatever its missing/ignored state.
pub fn get_project(conn: &Connection, id: &str) -> rusqlite::Result<Option<ProjectRow>> {
    conn.query_row(
        &format!("SELECT {PROJECT_COLUMNS}, 0, g.files {PROJECT_JOINS} WHERE p.id = ?1"),
        [id],
        |r| project_from_row(r, None, Some(AFTER_COLUMNS + 1)),
    )
    .optional()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatCounts {
    pub total: u64,
    pub today: u64,
    pub week: u64,
    pub inactive: u64,
    pub dormant: u64,
    pub unknown: u64,
    pub dirty: u64,
    pub missing: u64,
    /// Indexed sessions of the present, non-ignored projects.
    pub sessions: u64,
}

/// Counts over present, non-ignored projects (missing ones counted separately), bucketed with
/// the same boundaries as the activity filters.
pub fn stat_counts(
    conn: &Connection,
    b: &crate::activity::Boundaries,
) -> rusqlite::Result<StatCounts> {
    let n = |v: Option<i64>| u64::try_from(v.unwrap_or(0)).unwrap_or(0);
    conn.query_row(
        &format!(
            "SELECT count(*) FILTER (WHERE p.missing_since IS NULL),
                    count(*) FILTER (WHERE p.missing_since IS NULL AND p.activity_at >= ?1),
                    count(*) FILTER (WHERE p.missing_since IS NULL AND p.activity_at >= ?2),
                    count(*) FILTER (WHERE p.missing_since IS NULL AND p.activity_at >= ?3 AND p.activity_at < ?2),
                    count(*) FILTER (WHERE p.missing_since IS NULL AND p.activity_at < ?3),
                    count(*) FILTER (WHERE p.missing_since IS NULL AND p.activity_at IS NULL),
                    count(*) FILTER (WHERE p.missing_since IS NULL
                        AND coalesce(g.staged, 0) + coalesce(g.modified, 0) + coalesce(g.untracked, 0) > 0),
                    count(*) FILTER (WHERE p.missing_since IS NOT NULL),
                    sum(p.session_count) FILTER (WHERE p.missing_since IS NULL)
             {PROJECT_JOINS} WHERE i.canonical_path IS NULL"
        ),
        rusqlite::params![b.today, b.recent, b.inactive],
        |r| {
            Ok(StatCounts {
                total: n(r.get(0)?),
                today: n(r.get(1)?),
                week: n(r.get(2)?),
                inactive: n(r.get(3)?),
                dormant: n(r.get(4)?),
                unknown: n(r.get(5)?),
                dirty: n(r.get(6)?),
                missing: n(r.get(7)?),
                sessions: n(r.get(8)?),
            })
        },
    )
}

/// What the tracker needs to know about every registered project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    pub id: String,
    pub path: String,
    pub missing: bool,
    pub ignored: bool,
    pub activity_at: Option<i64>,
}

pub fn tracked_projects(conn: &Connection) -> rusqlite::Result<Vec<Tracked>> {
    conn.prepare(&format!(
        "SELECT p.id, p.canonical_path, p.missing_since IS NOT NULL, i.canonical_path IS NOT NULL, p.activity_at
         {PROJECT_JOINS} ORDER BY coalesce(-p.activity_at, 9223372036854775807), p.sort_key, p.id"
    ))?
    .query_map([], |r| {
        Ok(Tracked {
            id: r.get(0)?,
            path: r.get(1)?,
            missing: r.get(2)?,
            ignored: r.get(3)?,
            activity_at: r.get(4)?,
        })
    })?
    .collect()
}

/// Missing projects that a newly registered project `new_id` is a moved copy of (§4.5): the same
/// HEAD commit and remote for Git projects (`head` given), else the same marker hash without Git.
pub fn move_sources(
    conn: &Connection,
    new_id: &str,
    head: Option<&str>,
    remote: Option<&str>,
) -> rusqlite::Result<Vec<String>> {
    conn.prepare(
        "SELECT o.id FROM projects n
           JOIN projects o ON o.missing_since IS NOT NULL AND o.id <> n.id
           LEFT JOIN git_cache og ON og.project_id = o.id
         WHERE n.id = ?1 AND (
           (?2 IS NOT NULL AND og.head_commit = ?2 AND og.remote_url IS ?3)
           OR (?2 IS NULL AND n.marker_hash IS NOT NULL AND o.marker_hash = n.marker_hash
               AND og.head_commit IS NULL))",
    )?
    .query_map(rusqlite::params![new_id, head, remote], |r| r.get(0))?
    .collect()
}

pub fn project_path(conn: &Connection, id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT canonical_path FROM projects WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .optional()
}

/// Recent file events of a project, newest first (tests and diagnostics).
pub fn file_events(conn: &Connection, id: &str) -> rusqlite::Result<Vec<(i64, String, String)>> {
    conn.prepare("SELECT at, kind, path FROM file_events WHERE project_id = ?1 ORDER BY id DESC")?
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect()
}

pub fn count_projects(conn: &Connection) -> rusqlite::Result<u64> {
    conn.query_row("SELECT count(*) FROM projects", [], |r| r.get::<_, i64>(0))
        .map(|n| u64::try_from(n).unwrap_or(0))
}

pub fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

// ---- Claude Code sessions (M3) -------------------------------------------------------------

/// Everything the session ingest needs to continue parsing a file incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub id: String,
    pub file_path: String,
    pub project_id: Option<String>,
    pub unassigned: Option<String>,
    pub aggregate: crate::claude::parse::Aggregate,
    pub checkpoint: crate::claude::parse::Checkpoint,
}

pub fn session_states(conn: &Connection) -> rusqlite::Result<Vec<SessionState>> {
    use crate::claude::parse::{Aggregate, Checkpoint, Counts};
    let u = |v: i64| u64::try_from(v).unwrap_or(0);
    conn.prepare(
        "SELECT s.id, s.file_path, s.project_id, s.unassigned, s.first_cwd, s.last_cwd, s.started_at,
                s.last_activity_at, s.title, s.git_branch, s.version, s.entrypoint, s.continued_in,
                s.derived_from, s.is_sidechain,
                c.dev, c.ino, c.size, c.offset, c.mtime_ns, c.lines, c.malformed, c.oversized,
                c.unknown, c.foreign_id
         FROM sessions s JOIN session_file_checkpoints c ON c.session_id = s.id",
    )?
    .query_map([], |r| {
        let derived: Option<String> = r.get(13)?;
        Ok(SessionState {
            id: r.get(0)?,
            file_path: r.get(1)?,
            project_id: r.get(2)?,
            unassigned: r.get(3)?,
            aggregate: Aggregate {
                first_cwd: r.get(4)?,
                last_cwd: r.get(5)?,
                started_at: r.get(6)?,
                last_activity_at: r.get(7)?,
                title: r.get(8)?,
                git_branch: r.get(9)?,
                version: r.get(10)?,
                entrypoint: r.get(11)?,
                continued_in: r.get(12)?,
                derived_from: derived
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or_default(),
                is_sidechain: r.get(14)?,
                counts: Counts {
                    lines: u(r.get(20)?),
                    malformed: u(r.get(21)?),
                    oversized: u(r.get(22)?),
                    unknown: u(r.get(23)?),
                    foreign: u(r.get(24)?),
                },
            },
            checkpoint: Checkpoint {
                dev: u(r.get(15)?),
                ino: u(r.get(16)?),
                size: u(r.get(17)?),
                offset: u(r.get(18)?),
                mtime_ns: r.get(19)?,
            },
        })
    })?
    .collect()
}

/// One session as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub project_id: Option<String>,
    pub file_path: String,
    pub first_cwd: Option<String>,
    pub last_cwd: Option<String>,
    pub started_at: Option<i64>,
    pub last_activity_at: Option<i64>,
    pub title: Option<String>,
    pub git_branch: Option<String>,
    pub version: Option<String>,
    pub continued_in: Option<String>,
    pub prompt_text: Option<String>,
    pub prompt_at: Option<i64>,
}

const SESSION_COLUMNS: &str =
    "id, project_id, file_path, first_cwd, last_cwd, started_at, last_activity_at,
    title, git_branch, version, continued_in, prompt_text, prompt_at";

fn session_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: r.get(0)?,
        project_id: r.get(1)?,
        file_path: r.get(2)?,
        first_cwd: r.get(3)?,
        last_cwd: r.get(4)?,
        started_at: r.get(5)?,
        last_activity_at: r.get(6)?,
        title: r.get(7)?,
        git_branch: r.get(8)?,
        version: r.get(9)?,
        continued_in: r.get(10)?,
        prompt_text: r.get(11)?,
        prompt_at: r.get(12)?,
    })
}

/// A project's sessions, most recent activity first (unknown last).
pub fn project_sessions(
    conn: &Connection,
    project_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<SessionRow>> {
    conn.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM sessions WHERE project_id = ?1
         ORDER BY coalesce(last_activity_at, -9223372036854775807) DESC, id LIMIT ?2"
    ))?
    .query_map(
        rusqlite::params![project_id, i64::from(limit)],
        session_from_row,
    )?
    .collect()
}

pub fn session_by_id(conn: &Connection, id: &str) -> rusqlite::Result<Option<SessionRow>> {
    conn.query_row(
        &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?1"),
        [id],
        session_from_row,
    )
    .optional()
}

/// Session totals for the discovery status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCounts {
    pub indexed: u64,
    pub malformed: u64,
    pub oversized: u64,
    pub unknown: u64,
    /// `(reason, sessions)` of the unassigned sessions.
    pub unassigned: Vec<(String, u64)>,
}

pub fn session_counts(conn: &Connection) -> rusqlite::Result<SessionCounts> {
    let n = |v: Option<i64>| u64::try_from(v.unwrap_or(0)).unwrap_or(0);
    let (indexed, malformed, oversized, unknown) = conn.query_row(
        "SELECT (SELECT count(*) FROM sessions), sum(malformed), sum(oversized), sum(unknown)
         FROM session_file_checkpoints",
        [],
        |r| Ok((n(r.get(0)?), n(r.get(1)?), n(r.get(2)?), n(r.get(3)?))),
    )?;
    let unassigned = conn
        .prepare(
            "SELECT unassigned, count(*) FROM sessions WHERE unassigned IS NOT NULL
             GROUP BY unassigned ORDER BY unassigned",
        )?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, n(r.get(1)?))))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(SessionCounts {
        indexed,
        malformed,
        oversized,
        unknown,
        unassigned,
    })
}

/// Ignored projects `(id, name, canonical path)`, by name (Settings).
pub fn ignored_projects(conn: &Connection) -> rusqlite::Result<Vec<(String, String, String)>> {
    conn.prepare(
        "SELECT p.id, p.name, p.canonical_path FROM projects p
         JOIN ignored_paths i ON i.canonical_path = p.canonical_path ORDER BY p.sort_key, p.id",
    )?
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
    .collect()
}

/// Development roots (§4.5): the parent directories of present projects found from sessions.
pub fn session_project_parents(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let paths: Vec<String> = conn
        .prepare(
            "SELECT p.canonical_path FROM projects p
             JOIN project_sources s ON s.project_id = p.id AND s.source = 'session'
             WHERE p.missing_since IS NULL",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut parents: Vec<String> = paths
        .iter()
        .filter_map(|p| {
            std::path::Path::new(p)
                .parent()?
                .to_str()
                .map(str::to_string)
        })
        .collect();
    parents.sort();
    parents.dedup();
    Ok(parents)
}

/// What an incoming session token resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub expires_at: i64,
    pub last_used_at: i64,
    pub rotated_at: i64,
    /// The stored digest that matched (current or previous); callers re-verify it in constant time.
    pub matched_hash: [u8; 32],
    /// True if the token matched the *previous* token (inside its rotation grace window).
    pub via_previous: bool,
}

/// Look up a session by token hash: the current token, or the previous one while its grace
/// window is open. Expiry is checked by the caller against its own clock.
pub fn find_session(
    conn: &Connection,
    token_hash: &[u8; 32],
    now: i64,
) -> rusqlite::Result<Option<SessionRecord>> {
    conn.query_row(
        "SELECT id, expires_at, last_used_at, rotated_at, (token_hash <> ?1) AS via_prev,
                CASE WHEN token_hash = ?1 THEN token_hash ELSE prev_token_hash END
         FROM auth_sessions
         WHERE token_hash = ?1 OR (prev_token_hash = ?1 AND prev_valid_until > ?2)",
        rusqlite::params![token_hash.as_slice(), now],
        |r| {
            Ok(SessionRecord {
                id: r.get(0)?,
                expires_at: r.get(1)?,
                last_used_at: r.get(2)?,
                rotated_at: r.get(3)?,
                via_previous: r.get::<_, i64>(4)? != 0,
                matched_hash: r
                    .get::<_, Vec<u8>>(5)?
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            })
        },
    )
    .optional()
}

/// Live session ids, most recently used first (tests and diagnostics).
pub fn session_ids_by_use(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    conn.prepare("SELECT id FROM auth_sessions ORDER BY last_used_at DESC, created_at DESC")?
        .query_map([], |r| r.get(0))?
        .collect()
}

pub fn count_sessions(conn: &Connection) -> rusqlite::Result<u64> {
    conn.query_row("SELECT count(*) FROM auth_sessions", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|n| u64::try_from(n).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(like_pattern("a%b_c\\d"), "%a\\%b\\_c\\\\d%");
        assert_eq!(like_pattern(""), "%%");
    }
}
