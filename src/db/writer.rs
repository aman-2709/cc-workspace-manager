//! The single database writer: one thread, one bounded channel, batched transactions.
//!
//! Callers send a command and (when they need the outcome) await a one-shot reply. Replies are
//! delivered only **after** the batch transaction has committed. Every command runs in its own
//! savepoint, so one failing command cannot poison the rest of its batch.

use super::{db_err, open_writer_connection};
use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::thread::JoinHandle;
use tokio::sync::{mpsc, oneshot};

const CHANNEL_CAPACITY: usize = 1024;
const MAX_BATCH: usize = 256;

pub type Reply<T> = oneshot::Sender<Result<T>>;
pub type TokenHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Marker,
    Session,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Marker => "marker",
            Self::Session => "session",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectUpsert {
    pub canonical_path: String,
    pub name: String,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpsertSummary {
    pub inserted: usize,
    pub updated: usize,
}

/// A freshly stored browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub id: String,
    pub expires_at: i64,
    pub rotated_at: i64,
}

enum Cmd {
    UpsertProjects {
        batch: Vec<ProjectUpsert>,
        now: i64,
        reply: Reply<UpsertSummary>,
    },
    CreateSession {
        token_hash: TokenHash,
        now: i64,
        expires_at: i64,
        reply: Reply<StoredSession>,
    },
    /// Replace the session's *current* token `old` with `new` and keep `old` valid until
    /// `grace_until`. `None` if `old` is not a live current token.
    RotateSession {
        old: TokenHash,
        new: TokenHash,
        now: i64,
        grace_until: i64,
        expires_at: i64,
        reply: Reply<Option<StoredSession>>,
    },
    DeleteSession {
        token_hash: TokenHash,
        reply: Reply<bool>,
    },
    TouchSession {
        id: String,
        now: i64,
        expires_at: i64,
    },
    RevokeAll {
        reply: Reply<u64>,
    },
    PurgeExpiredSessions {
        now: i64,
        reply: Reply<u64>,
    },
    SetMeta {
        key: String,
        value: String,
        reply: Reply<()>,
    },
    Flush {
        reply: Reply<()>,
    },
    /// Like `Flush`, then the writer thread exits.
    Shutdown {
        reply: Reply<()>,
    },
}

pub struct Writer {
    tx: mpsc::Sender<Cmd>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

fn random_id() -> Result<String> {
    crate::auth::tokens::random_hex(16)
}

impl Writer {
    /// Open (and migrate) the database, then start the writer thread.
    pub fn spawn(db_path: &Path) -> Result<Self> {
        let conn = open_writer_connection(db_path)?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let handle = std::thread::Builder::new()
            .name("ccwm-db-writer".into())
            .spawn(move || run(conn, rx))
            .map_err(|e| Error::io("cannot start the database writer thread", &e))?;
        Ok(Self {
            tx,
            handle: Mutex::new(Some(handle)),
        })
    }

    async fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Result<T> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(make(reply))
            .await
            .map_err(|_| Error::new("database writer is not running"))?;
        rx.await
            .map_err(|_| Error::new("database writer dropped the request"))?
    }

    fn call_blocking<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Result<T> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .blocking_send(make(reply))
            .map_err(|_| Error::new("database writer is not running"))?;
        rx.blocking_recv()
            .map_err(|_| Error::new("database writer dropped the request"))?
    }

    /// For discovery, which runs on a blocking thread.
    pub fn upsert_projects_blocking(
        &self,
        batch: Vec<ProjectUpsert>,
        now: i64,
    ) -> Result<UpsertSummary> {
        self.call_blocking(|reply| Cmd::UpsertProjects { batch, now, reply })
    }

    pub async fn upsert_projects(
        &self,
        batch: Vec<ProjectUpsert>,
        now: i64,
    ) -> Result<UpsertSummary> {
        self.call(|reply| Cmd::UpsertProjects { batch, now, reply })
            .await
    }

    pub async fn create_session(
        &self,
        token_hash: TokenHash,
        now: i64,
        expires_at: i64,
    ) -> Result<StoredSession> {
        self.call(|reply| Cmd::CreateSession {
            token_hash,
            now,
            expires_at,
            reply,
        })
        .await
    }

    pub async fn rotate_session(
        &self,
        old: TokenHash,
        new: TokenHash,
        now: i64,
        grace_until: i64,
        expires_at: i64,
    ) -> Result<Option<StoredSession>> {
        self.call(|reply| Cmd::RotateSession {
            old,
            new,
            now,
            grace_until,
            expires_at,
            reply,
        })
        .await
    }

    pub async fn delete_session(&self, token_hash: TokenHash) -> Result<bool> {
        self.call(|reply| Cmd::DeleteSession { token_hash, reply })
            .await
    }

    /// Best-effort sliding-expiry update: dropped silently if the queue is full.
    pub fn touch_session(&self, id: String, now: i64, expires_at: i64) {
        let _ = self.tx.try_send(Cmd::TouchSession {
            id,
            now,
            expires_at,
        });
    }

    pub async fn revoke_all(&self) -> Result<u64> {
        self.call(|reply| Cmd::RevokeAll { reply }).await
    }

    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64> {
        self.call(|reply| Cmd::PurgeExpiredSessions { now, reply })
            .await
    }

    pub async fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.call(|reply| Cmd::SetMeta {
            key: key.to_string(),
            value: value.to_string(),
            reply,
        })
        .await
    }

    pub fn set_meta_blocking(&self, key: &str, value: &str) -> Result<()> {
        self.call_blocking(|reply| Cmd::SetMeta {
            key: key.to_string(),
            value: value.to_string(),
            reply,
        })
    }

    /// Wait until everything queued before this call has been committed.
    pub async fn flush(&self) -> Result<()> {
        self.call(|reply| Cmd::Flush { reply }).await
    }

    /// Flush, stop the thread and wait for it (graceful shutdown).
    pub async fn shutdown(&self) -> Result<()> {
        let handle = self.handle.lock().ok().and_then(|mut h| h.take());
        let Some(handle) = handle else { return Ok(()) };
        let stopped = self.call(|reply| Cmd::Shutdown { reply }).await;
        let _ = tokio::task::spawn_blocking(move || handle.join()).await;
        stopped
    }
}

fn run(mut conn: Connection, mut rx: mpsc::Receiver<Cmd>) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }
        let stop = batch.iter().any(|c| matches!(c, Cmd::Shutdown { .. }));
        apply_batch(&mut conn, batch);
        if stop {
            break;
        }
    }
}

type Outcome = Box<dyn FnOnce(Option<&Error>) + Send>;

/// Run each command in a savepoint inside one transaction; send replies after the commit.
fn apply_batch(conn: &mut Connection, batch: Vec<Cmd>) {
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            let err = db_err("begin", &e);
            for cmd in batch {
                fail(cmd, &err);
            }
            return;
        }
    };
    let mut pending: Vec<Outcome> = Vec::with_capacity(batch.len());
    for cmd in batch {
        pending.push(execute(&tx, cmd));
    }
    let commit_err = tx.commit().err().map(|e| db_err("commit", &e));
    for outcome in pending {
        outcome(commit_err.as_ref());
    }
}

/// Deliver a failure to a command's reply channel without executing it.
fn fail(cmd: Cmd, err: &Error) {
    let e = || Error::new(err.to_string());
    match cmd {
        Cmd::UpsertProjects { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::CreateSession { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::RotateSession { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::DeleteSession { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::RevokeAll { reply } | Cmd::PurgeExpiredSessions { reply, .. } => {
            drop(reply.send(Err(e())))
        }
        Cmd::SetMeta { reply, .. } | Cmd::Flush { reply } | Cmd::Shutdown { reply } => {
            drop(reply.send(Err(e())))
        }
        Cmd::TouchSession { .. } => {}
    }
}

/// Execute one command in a savepoint. The returned closure sends the reply once the outer
/// transaction's commit outcome is known.
fn execute(tx: &rusqlite::Transaction<'_>, cmd: Cmd) -> Outcome {
    macro_rules! run {
        ($reply:expr, $body:expr) => {{
            let result = savepoint(tx, $body);
            let reply = $reply;
            Box::new(move |commit_err: Option<&Error>| {
                let msg = commit_err.map(ToString::to_string);
                let _ = reply.send(match (result, msg) {
                    (_, Some(m)) => Err(Error::new(m)),
                    (r, None) => r,
                });
            })
        }};
    }
    match cmd {
        Cmd::UpsertProjects { batch, now, reply } => {
            run!(reply, |c| upsert_projects(c, &batch, now))
        }
        Cmd::CreateSession {
            token_hash,
            now,
            expires_at,
            reply,
        } => {
            run!(reply, |c| create_session(c, token_hash, now, expires_at))
        }
        Cmd::RotateSession {
            old,
            new,
            now,
            grace_until,
            expires_at,
            reply,
        } => {
            run!(reply, |c| rotate_session(
                c,
                old,
                new,
                now,
                grace_until,
                expires_at
            ))
        }
        Cmd::DeleteSession { token_hash, reply } => run!(reply, |c| {
            c.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?1 OR prev_token_hash = ?1",
                params![token_hash.as_slice()],
            )
            .map(|n| n > 0)
            .map_err(|e| db_err("delete session", &e))
        }),
        Cmd::TouchSession {
            id,
            now,
            expires_at,
        } => {
            let _ = savepoint(tx, |c| {
                c.execute(
                    "UPDATE auth_sessions SET last_used_at = ?2, expires_at = max(expires_at, ?3) WHERE id = ?1",
                    params![id, now, expires_at],
                )
                .map(|_| ())
                .map_err(|e| db_err("touch session", &e))
            });
            Box::new(|_| {})
        }
        Cmd::RevokeAll { reply } => run!(reply, |c| {
            c.execute("DELETE FROM auth_sessions", [])
                .map(|n| n as u64)
                .map_err(|e| db_err("revoke all", &e))
        }),
        Cmd::PurgeExpiredSessions { now, reply } => run!(reply, |c| {
            c.execute(
                "DELETE FROM auth_sessions WHERE expires_at <= ?1",
                params![now],
            )
            .map(|n| n as u64)
            .map_err(|e| db_err("purge sessions", &e))
        }),
        Cmd::SetMeta { key, value, reply } => run!(reply, |c| {
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(|e| db_err("set meta", &e))
        }),
        Cmd::Flush { reply } | Cmd::Shutdown { reply } => run!(reply, |_c| Ok(())),
    }
}

fn savepoint<T>(
    tx: &rusqlite::Transaction<'_>,
    body: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    tx.execute_batch("SAVEPOINT cmd")
        .map_err(|e| db_err("savepoint", &e))?;
    match body(tx) {
        Ok(v) => {
            tx.execute_batch("RELEASE cmd")
                .map_err(|e| db_err("release", &e))?;
            Ok(v)
        }
        Err(e) => {
            let _ = tx.execute_batch("ROLLBACK TO cmd; RELEASE cmd");
            Err(e)
        }
    }
}

fn upsert_projects(c: &Connection, batch: &[ProjectUpsert], now: i64) -> Result<UpsertSummary> {
    let mut summary = UpsertSummary::default();
    for p in batch {
        let existing: Option<String> = c
            .query_row(
                "SELECT id FROM projects WHERE canonical_path = ?1",
                params![p.canonical_path],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| db_err("find project", &e))?;
        let id = match existing {
            Some(id) => {
                c.execute(
                    "UPDATE projects SET name = ?2, last_seen_at = ?3 WHERE id = ?1",
                    params![id, p.name, now],
                )
                .map_err(|e| db_err("update project", &e))?;
                summary.updated += 1;
                id
            }
            None => {
                let id = random_id()?;
                c.execute(
                    "INSERT INTO projects (id, canonical_path, name, first_seen_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?4)",
                    params![id, p.canonical_path, p.name, now],
                )
                .map_err(|e| db_err("insert project", &e))?;
                summary.inserted += 1;
                id
            }
        };
        c.execute(
            "INSERT OR IGNORE INTO project_sources (project_id, source, first_seen_at) VALUES (?1, ?2, ?3)",
            params![id, p.source.as_str(), now],
        )
        .map_err(|e| db_err("insert source", &e))?;
    }
    Ok(summary)
}

fn create_session(
    c: &Connection,
    token_hash: TokenHash,
    now: i64,
    expires_at: i64,
) -> Result<StoredSession> {
    let id = random_id()?;
    c.execute(
        "INSERT INTO auth_sessions (id, token_hash, created_at, last_used_at, rotated_at, expires_at) VALUES (?1, ?2, ?3, ?3, ?3, ?4)",
        params![id, token_hash.as_slice(), now, expires_at],
    )
    .map_err(|e| db_err("create session", &e))?;
    Ok(StoredSession {
        id,
        expires_at,
        rotated_at: now,
    })
}

fn rotate_session(
    c: &Connection,
    old: TokenHash,
    new: TokenHash,
    now: i64,
    grace_until: i64,
    expires_at: i64,
) -> Result<Option<StoredSession>> {
    let found: Option<String> = c
        .query_row(
            "SELECT id FROM auth_sessions
             WHERE token_hash = ?1 AND expires_at > ?2",
            params![old.as_slice(), now],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| db_err("find session", &e))?;
    let Some(id) = found else { return Ok(None) };
    c.execute(
        "UPDATE auth_sessions SET prev_token_hash = ?2, prev_valid_until = ?3, token_hash = ?4,
                rotated_at = ?5, last_used_at = ?5, expires_at = max(expires_at, ?6) WHERE id = ?1",
        params![
            id,
            old.as_slice(),
            grace_until,
            new.as_slice(),
            now,
            expires_at
        ],
    )
    .map_err(|e| db_err("rotate session", &e))?;
    Ok(Some(StoredSession {
        id,
        expires_at,
        rotated_at: now,
    }))
}
