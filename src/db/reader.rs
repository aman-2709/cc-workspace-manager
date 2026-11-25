//! A small pool of read-only connections. Blocking SQLite work runs on `spawn_blocking`, never on
//! a Tokio worker.
//!
//! A caller first takes one of [`POOL_SIZE`] async permits and only then moves to a blocking
//! thread, so at most one blocking thread per connection ever exists for reads. Without the permit,
//! a burst of reads (e.g. 500 Git refreshes looking up their project's path) would park one
//! blocking-pool thread per caller on the pool's condition variable: Tokio's blocking pool grows to
//! 512 threads on demand (found by the M4 benchmarks).

use super::db_err;
use crate::error::{Error, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::Semaphore;

pub const POOL_SIZE: usize = 4;

struct Pool {
    conns: Mutex<Vec<Connection>>,
    available: Condvar,
}

#[derive(Clone)]
pub struct Reader {
    pool: Arc<Pool>,
    /// One permit per connection, taken before a blocking thread is used.
    permits: Arc<Semaphore>,
    /// Tests: the most closures that were on blocking threads at the same time.
    #[cfg(test)]
    on_blocking: Arc<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>,
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
            permits: Arc::new(Semaphore::new(size)),
            #[cfg(test)]
            on_blocking: Arc::default(),
        })
    }

    /// Run `f` with a pooled connection on a blocking thread.
    pub async fn with<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| Error::new("reader pool closed"))?;
        let pool = Arc::clone(&self.pool);
        #[cfg(test)]
        let counter = Arc::clone(&self.on_blocking);
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _on = OnBlocking::enter(&counter);
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

#[cfg(test)]
struct OnBlocking<'a>(
    &'a (
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    ),
);

#[cfg(test)]
impl<'a> OnBlocking<'a> {
    fn enter(
        c: &'a (
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        ),
    ) -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let now = c.0.fetch_add(1, SeqCst) + 1;
        c.1.fetch_max(now, SeqCst);
        Self(c)
    }
}

#[cfg(test)]
impl Drop for OnBlocking<'_> {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_of_reads_never_parks_more_blocking_threads_than_connections() {
        let t = crate::paths::private_tempdir();
        let db = t.path().join("t.db");
        let _w = crate::db::writer::Writer::spawn(&db).unwrap();
        let r = Reader::open(&db, POOL_SIZE).unwrap();
        let calls: Vec<_> = (0..200)
            .map(|_| {
                let r = r.clone();
                tokio::spawn(async move {
                    r.with(|c| {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        c.query_row("SELECT 1", [], |x| x.get::<_, i64>(0))
                    })
                    .await
                })
            })
            .collect();
        for c in calls {
            assert_eq!(c.await.unwrap().unwrap(), 1);
        }
        let peak = r.on_blocking.1.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            (1..=POOL_SIZE).contains(&peak),
            "{peak} reads were on blocking threads at once (pool of {POOL_SIZE})"
        );
    }
}
