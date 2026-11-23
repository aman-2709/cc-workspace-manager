//! A small pool of read-only connections. Blocking SQLite work runs on `spawn_blocking`, never on
//! a Tokio worker.

use super::db_err;
use crate::error::{Error, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};

pub const POOL_SIZE: usize = 4;

struct Pool {
    conns: Mutex<Vec<Connection>>,
    available: Condvar,
}

#[derive(Clone)]
pub struct Reader {
    pool: Arc<Pool>,
}

impl Reader {
    /// The database must already exist (the writer creates and migrates it first).
    pub fn open(path: &Path, size: usize) -> Result<Self> {
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| db_err("open read-only", &e))?;
            conn.execute_batch(
                "PRAGMA query_only = ON; PRAGMA busy_timeout = 5000; PRAGMA temp_store = MEMORY;",
            )
            .map_err(|e| db_err("reader pragmas", &e))?;
            conns.push(conn);
        }
        Ok(Self {
            pool: Arc::new(Pool {
                conns: Mutex::new(conns),
                available: Condvar::new(),
            }),
        })
    }

    /// Run `f` with a pooled connection on a blocking thread.
    pub async fn with<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let pool = Arc::clone(&self.pool);
        tokio::task::spawn_blocking(move || {
            let conn = {
                let mut guard = pool
                    .conns
                    .lock()
                    .map_err(|_| Error::new("reader pool poisoned"))?;
                loop {
                    if let Some(c) = guard.pop() {
                        break c;
                    }
                    guard = pool
                        .available
                        .wait(guard)
                        .map_err(|_| Error::new("reader pool poisoned"))?;
                }
            };
            let result = f(&conn).map_err(|e| db_err("query", &e));
            if let Ok(mut guard) = pool.conns.lock() {
                guard.push(conn);
                pool.available.notify_one();
            }
            result
        })
        .await
        .map_err(|e| Error::new(format!("reader task failed: {e}")))?
    }
}
