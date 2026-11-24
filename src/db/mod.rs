//! SQLite access: embedded migrations, one writer thread, a small read-only connection pool.
//! No `rusqlite` call may run on a Tokio worker thread.

pub mod queries;
pub mod reader;
pub mod writer;

use crate::error::{Error, Result};
use rusqlite::Connection;
use std::path::Path;

/// One schema step: SQL, then (optionally) a Rust step in the same transaction for data the SQL
/// cannot compute (e.g. Unicode case folding).
struct Migration {
    sql: &'static str,
    backfill: Option<fn(&rusqlite::Transaction<'_>) -> Result<()>>,
}

/// Ordered migrations; index + 1 is the `PRAGMA user_version` after applying it.
const MIGRATIONS: [Migration; 3] = [
    Migration {
        sql: include_str!("migrations/001_init.sql"),
        backfill: None,
    },
    Migration {
        sql: include_str!("migrations/002_sort_key.sql"),
        backfill: Some(backfill_sort_keys),
    },
    Migration {
        sql: include_str!("migrations/003_activity.sql"),
        backfill: None,
    },
];

/// The normalized name used for sorting and keyset pagination. Computed only here, stored in
/// `projects.sort_key`, and read back for cursors, so Rust and SQL can never disagree (L8).
pub fn sort_key(name: &str) -> String {
    name.to_lowercase()
}

fn backfill_sort_keys(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let rows: Vec<(String, String)> = tx
        .prepare("SELECT id, name FROM projects")
        .and_then(|mut st| {
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()
        })
        .map_err(|e| db_err("read names", &e))?;
    for (id, name) in rows {
        tx.execute(
            "UPDATE projects SET sort_key = ?2 WHERE id = ?1",
            rusqlite::params![id, sort_key(&name)],
        )
        .map_err(|e| db_err("backfill sort key", &e))?;
    }
    Ok(())
}

pub(crate) fn db_err(context: &str, e: &rusqlite::Error) -> Error {
    Error::new(format!("database {context}: {e}"))
}

/// Open the read-write connection (creating the file with mode 0600 under umask 0077), set
/// pragmas and apply pending migrations.
pub fn open_writer_connection(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path).map_err(|e| db_err("open", &e))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000; PRAGMA temp_store = MEMORY;",
    )
    .map_err(|e| db_err("pragmas", &e))?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> Result<()> {
    let current: usize = conn
        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
        .map_err(|e| db_err("read version", &e))
        .and_then(|v| usize::try_from(v).map_err(|_| Error::new("negative schema version")))?;
    if current > MIGRATIONS.len() {
        return Err(Error::new(format!(
            "database schema version {current} is newer than this ccwm supports ({}); refusing to open it",
            MIGRATIONS.len()
        )));
    }
    for (idx, m) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn
            .transaction()
            .map_err(|e| db_err("begin migration", &e))?;
        tx.execute_batch(m.sql)
            .map_err(|e| db_err(&format!("migration {}", idx + 1), &e))?;
        if let Some(backfill) = m.backfill {
            backfill(&tx)?;
        }
        tx.pragma_update(
            None,
            "user_version",
            i64::try_from(idx + 1).unwrap_or(i64::MAX),
        )
        .map_err(|e| db_err("set version", &e))?;
        tx.commit().map_err(|e| db_err("commit migration", &e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_once_and_are_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("x.db");
        drop(open_writer_connection(&path).unwrap());
        let mut conn = open_writer_connection(&path).unwrap(); // second open: no-op
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            tables,
            [
                "auth_sessions",
                "file_events",
                "git_cache",
                "ignored_paths",
                "meta",
                "project_sources",
                "projects"
            ]
        );
        migrate(&mut conn).unwrap();
    }

    #[test]
    fn migration_2_backfills_unicode_sort_keys_for_existing_rows() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("x.db");
        {
            // A database left at schema version 1 by an M1 daemon.
            let mut conn = Connection::open(&path).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute_batch(MIGRATIONS[0].sql).unwrap();
            tx.pragma_update(None, "user_version", 1).unwrap();
            tx.execute(
                "INSERT INTO projects (id, canonical_path, name, first_seen_at, last_seen_at) VALUES (?1, '/p', 'ÉCOLE', 0, 0)",
                ["0123456789abcdef0123456789abcdef"],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let conn = open_writer_connection(&path).unwrap();
        let key: String = conn
            .query_row("SELECT sort_key FROM projects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(key, "école");
        assert_eq!(sort_key("ÉCOLE"), "école");
    }

    #[test]
    fn refuses_a_newer_schema() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("x.db");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        drop(conn);
        let err = open_writer_connection(&path).unwrap_err().to_string();
        assert!(err.contains("newer"), "{err}");
    }

    #[test]
    fn pragmas_are_set() {
        let t = tempfile::tempdir().unwrap();
        let conn = open_writer_connection(&t.path().join("x.db")).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!((mode.as_str(), fk), ("wal", 1));
    }

    #[test]
    fn db_wal_and_shm_files_are_private_under_umask_077() {
        use std::os::unix::fs::PermissionsExt;
        // SQLite honours the process umask; emulate the daemon's umask for this check.
        let old = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join(crate::paths::DB_NAME);
        let conn = open_writer_connection(&path).unwrap();
        // WAL and SHM exist while a connection is open and a write has happened.
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
            .unwrap();
        nix::sys::stat::umask(old);
        let mode = |name: &str| {
            std::fs::metadata(t.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(crate::paths::DB_NAME), 0o600);
        assert_eq!(mode(crate::paths::DB_WAL_NAME), 0o600);
        assert_eq!(mode(crate::paths::DB_SHM_NAME), 0o600);
    }
}
