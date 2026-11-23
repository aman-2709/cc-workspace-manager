//! Typed read queries. All SQL is parameterized; `LIKE` input is escaped.

use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListParams {
    pub q: Option<String>,
    pub order: Order,
    pub limit: u32,
    /// Keyset position: `(lower(name), id)` of the last row of the previous page.
    pub after: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectRow {
    pub id: String,
    pub name: String,
    pub path: String,
    pub sources: Vec<String>,
    pub first_seen_at: i64,
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

/// One page of projects plus the total number of matches (ignoring the cursor).
pub fn list_projects(
    conn: &Connection,
    p: &ListParams,
) -> rusqlite::Result<(Vec<ProjectRow>, u64)> {
    let pattern = p.q.as_deref().map(like_pattern);
    let (dir, cmp) = match p.order {
        Order::Asc => ("ASC", ">"),
        Order::Desc => ("DESC", "<"),
    };
    let filter = "(?1 IS NULL OR name LIKE ?1 ESCAPE '\\' OR canonical_path LIKE ?1 ESCAPE '\\')";
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM projects WHERE {filter}"),
        [&pattern],
        |r| r.get(0),
    )?;

    let sql = format!(
        "SELECT id, name, canonical_path, first_seen_at,
                (SELECT group_concat(source) FROM (SELECT source FROM project_sources s WHERE s.project_id = projects.id ORDER BY source))
         FROM projects
         WHERE {filter} AND (?2 IS NULL OR (lower(name), id) {cmp} (?2, ?3))
         ORDER BY lower(name) {dir}, id {dir}
         LIMIT ?4"
    );
    let (after_name, after_id) = match &p.after {
        Some((n, i)) => (Some(n.clone()), Some(i.clone())),
        None => (None, None),
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(
            params_from_iter([
                pattern
                    .map(rusqlite::types::Value::Text)
                    .unwrap_or(rusqlite::types::Value::Null),
                after_name
                    .map(rusqlite::types::Value::Text)
                    .unwrap_or(rusqlite::types::Value::Null),
                after_id
                    .map(rusqlite::types::Value::Text)
                    .unwrap_or(rusqlite::types::Value::Null),
                rusqlite::types::Value::Integer(i64::from(p.limit)),
            ]),
            |r| {
                let sources: Option<String> = r.get(4)?;
                Ok(ProjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    path: r.get(2)?,
                    first_seen_at: r.get(3)?,
                    sources: sources
                        .map(|s| s.split(',').map(str::to_string).collect())
                        .unwrap_or_default(),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((rows, u64::try_from(total).unwrap_or(0)))
}

pub fn count_projects(conn: &Connection) -> rusqlite::Result<u64> {
    conn.query_row("SELECT count(*) FROM projects", [], |r| r.get::<_, i64>(0))
        .map(|n| u64::try_from(n).unwrap_or(0))
}

pub fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
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
