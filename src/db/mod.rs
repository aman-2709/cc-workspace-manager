//! SQLite access: embedded migrations, one writer thread, a small read-only connection pool.
//! No `rusqlite` call may run on a Tokio worker thread.

pub mod queries;
pub mod reader;
pub mod writer;

use crate::error::{Error, Result};
use rusqlite::Connection;
use std::path::Path;

/// Ordered migrations; index + 1 is the `PRAGMA user_version` after applying it.
const MIGRATIONS: [&str; 1] = [include_str!("migrations/001_init.sql")];

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
    for (idx, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn
            .transaction()
            .map_err(|e| db_err("begin migration", &e))?;
        tx.execute_batch(sql)
            .map_err(|e| db_err(&format!("migration {}", idx + 1), &e))?;
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
            ["auth_sessions", "meta", "project_sources", "projects"]
        );
        migrate(&mut conn).unwrap();
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
    fn db_file_is_private_under_umask_077() {
        use std::os::unix::fs::PermissionsExt;
        // SQLite honours the process umask; emulate the daemon's umask for this check.
        let old = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("x.db");
        drop(open_writer_connection(&path).unwrap());
        nix::sys::stat::umask(old);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
