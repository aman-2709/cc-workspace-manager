//! The single database writer: one thread, one bounded channel, batched transactions.
//!
//! Callers send a command and (when they need the outcome) await a one-shot reply. Replies are
//! delivered only **after** the batch transaction has committed. Every command runs in its own
//! savepoint, so one failing command cannot poison the rest of its batch.

use super::{db_err, open_writer_connection, sort_key};
use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tokio::sync::{mpsc, oneshot};

const CHANNEL_CAPACITY: usize = 1024;
const MAX_BATCH: usize = 256;
/// Live browser sessions kept; creating one more revokes the least recently used (L3).
pub const MAX_LIVE_SESSIONS: usize = 10;

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
    /// SHA-256 of the marker content, if it was read (kept otherwise).
    pub marker_hash: Option<[u8; 32]>,
}

/// What happened to one upserted project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upserted {
    pub id: String,
    pub canonical_path: String,
    pub inserted: bool,
    /// It was marked missing before and is present again.
    pub revived: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpsertSummary {
    pub inserted: usize,
    pub updated: usize,
    pub rows: Vec<Upserted>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityKind {
    /// From a walk of the tree (file modification times).
    Inferred,
    /// From a live filesystem event.
    Observed,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inferred => "inferred",
            Self::Observed => "observed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Create,
    Modify,
    Delete,
    Rename,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Rename => "rename",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub at: i64,
    pub kind: EventKind,
    /// Relative to the project root.
    pub path: String,
}

/// The latest meaningful modification of a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activity {
    pub at: i64,
    pub kind: ActivityKind,
    /// The latest modified file; `None` keeps the stored one (only directories changed).
    pub path: Option<String>,
}

/// One parsed session file to store (REQUIREMENTS.md §7.3: aggregates only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStore {
    pub id: String,
    pub file_path: String,
    /// The project the session belongs to; `None` with `unassigned` set when its cwd names none.
    pub project_id: Option<String>,
    pub unassigned: Option<&'static str>,
    pub aggregate: crate::claude::parse::Aggregate,
    pub checkpoint: crate::claude::parse::Checkpoint,
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
    /// Raise the project's activity to `activity` (never lowers it) and append `events`, keeping
    /// the newest `keep`. Replies whether the activity changed.
    RecordActivity {
        id: String,
        activity: Activity,
        events: Vec<FileEvent>,
        keep: u32,
        reply: Reply<bool>,
    },
    StoreGit {
        id: String,
        info: Box<crate::git::Info>,
        now: i64,
        reply: Reply<()>,
    },
    /// Mark present projects missing; replies with the ids that changed.
    MarkMissing {
        ids: Vec<String>,
        now: i64,
        reply: Reply<Vec<String>>,
    },
    /// Delete projects missing since `before` or earlier; replies with their ids.
    PurgeMissing {
        before: i64,
        reply: Reply<Vec<String>>,
    },
    /// Give project `id` a new canonical path (a move), keeping its id. A different project
    /// already registered at that path is deleted first (it was the same project, seen before the
    /// move was recognised); replies with its id.
    MoveProject {
        id: String,
        path: String,
        name: String,
        now: i64,
        reply: Reply<Option<String>>,
    },
    /// Ignore (or un-ignore) a canonical path; replies whether anything changed.
    SetIgnored {
        path: String,
        ignored: bool,
        now: i64,
        reply: Reply<bool>,
    },
    /// Insert or update parsed sessions (aggregates and checkpoints; a stale prompt cache is
    /// dropped); replies with the ids of the projects whose session summary changed.
    StoreSessions {
        sessions: Vec<SessionStore>,
        reply: Reply<Vec<String>>,
    },
    /// Re-assign sessions (`(session id, project id, unassigned reason)`) without re-parsing.
    AssignSessions {
        assignments: Vec<(String, Option<String>, Option<&'static str>)>,
        reply: Reply<Vec<String>>,
    },
    /// Forget sessions whose files are gone (by file path); replies with the affected projects.
    DeleteSessions {
        file_paths: Vec<String>,
        reply: Reply<Vec<String>>,
    },
    /// "Clear session index": every session and checkpoint (never the session files).
    ClearSessionIndex {
        reply: Reply<Vec<String>>,
    },
    /// Cache (or with `None`, drop) the last prompt of one session (opt-in setting). A no-op
    /// unless storing is enabled ([`Writer::set_store_prompts`]), checked inside the transaction.
    CachePrompt {
        session_id: String,
        prompt: Option<(String, Option<i64>)>,
    },
    /// Drop every cached prompt ("Store prompt text" turned off); replies with the count.
    ClearPromptCache {
        reply: Reply<u64>,
    },
    /// "Forget" a **missing** project: delete its row (sessions become unassigned, events and
    /// the Git cache go with it); never touches the disk. Replies whether a row was deleted.
    Forget {
        id: String,
        reply: Reply<bool>,
    },
    /// Clear `missing_since` of projects whose directory is back; replies with the changed ids.
    Revive {
        ids: Vec<String>,
        now: i64,
        reply: Reply<Vec<String>>,
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
    /// "Store prompt text" as the writer enforces it (M3 review, M2): the writer thread reads it
    /// while executing `CachePrompt`, so a prompt read that was in flight when the setting turned
    /// off can never be stored after the cache was cleared.
    store_prompts: Arc<AtomicBool>,
}

fn random_id() -> Result<String> {
    crate::auth::tokens::random_hex(16)
}

impl Writer {
    /// Open (and migrate) the database, then start the writer thread.
    pub fn spawn(db_path: &Path) -> Result<Self> {
        let mut conn = open_writer_connection(db_path)?;
        reindex_if_parser_changed(&mut conn, crate::claude::parse::PARSER_VERSION)?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let store_prompts = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&store_prompts);
        let handle = std::thread::Builder::new()
            .name("ccwm-db-writer".into())
            .spawn(move || run(conn, rx, &flag))
            .map_err(|e| Error::io("cannot start the database writer thread", &e))?;
        Ok(Self {
            tx,
            handle: Mutex::new(Some(handle)),
            store_prompts,
        })
    }

    /// Allow (or forbid) `CachePrompt`. Turning it off must happen **before** the cache is
    /// cleared ([`Self::clear_prompt_cache`]); off by default.
    pub fn set_store_prompts(&self, on: bool) {
        self.store_prompts.store(on, Ordering::SeqCst);
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

    pub async fn record_activity(
        &self,
        id: &str,
        activity: Activity,
        events: Vec<FileEvent>,
        keep: u32,
    ) -> Result<bool> {
        self.call(|reply| Cmd::RecordActivity {
            id: id.to_string(),
            activity,
            events,
            keep,
            reply,
        })
        .await
    }

    pub async fn store_git(&self, id: &str, info: crate::git::Info, now: i64) -> Result<()> {
        self.call(|reply| Cmd::StoreGit {
            id: id.to_string(),
            info: Box::new(info),
            now,
            reply,
        })
        .await
    }

    pub async fn mark_missing(&self, ids: Vec<String>, now: i64) -> Result<Vec<String>> {
        self.call(|reply| Cmd::MarkMissing { ids, now, reply })
            .await
    }

    pub async fn purge_missing(&self, before: i64) -> Result<Vec<String>> {
        self.call(|reply| Cmd::PurgeMissing { before, reply }).await
    }

    pub async fn move_project(
        &self,
        id: &str,
        path: &str,
        name: &str,
        now: i64,
    ) -> Result<Option<String>> {
        self.call(|reply| Cmd::MoveProject {
            id: id.to_string(),
            path: path.to_string(),
            name: name.to_string(),
            now,
            reply,
        })
        .await
    }

    pub async fn set_ignored(&self, path: &str, ignored: bool, now: i64) -> Result<bool> {
        self.call(|reply| Cmd::SetIgnored {
            path: path.to_string(),
            ignored,
            now,
            reply,
        })
        .await
    }

    pub async fn store_sessions(&self, sessions: Vec<SessionStore>) -> Result<Vec<String>> {
        self.call(|reply| Cmd::StoreSessions { sessions, reply })
            .await
    }

    pub async fn assign_sessions(
        &self,
        assignments: Vec<(String, Option<String>, Option<&'static str>)>,
    ) -> Result<Vec<String>> {
        self.call(|reply| Cmd::AssignSessions { assignments, reply })
            .await
    }

    pub async fn delete_sessions(&self, file_paths: Vec<String>) -> Result<Vec<String>> {
        self.call(|reply| Cmd::DeleteSessions { file_paths, reply })
            .await
    }

    pub async fn clear_session_index(&self) -> Result<Vec<String>> {
        self.call(|reply| Cmd::ClearSessionIndex { reply }).await
    }

    /// Best effort (dropped when the queue is full): the cache only speeds up the detail panel.
    pub fn cache_prompt(&self, session_id: &str, prompt: Option<(String, Option<i64>)>) {
        let _ = self.tx.try_send(Cmd::CachePrompt {
            session_id: session_id.to_string(),
            prompt,
        });
    }

    pub async fn clear_prompt_cache(&self) -> Result<u64> {
        self.call(|reply| Cmd::ClearPromptCache { reply }).await
    }

    pub async fn forget(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.call(|reply| Cmd::Forget { id, reply }).await
    }

    pub async fn revive(&self, ids: Vec<String>, now: i64) -> Result<Vec<String>> {
        self.call(|reply| Cmd::Revive { ids, now, reply }).await
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

fn run(mut conn: Connection, mut rx: mpsc::Receiver<Cmd>, store_prompts: &AtomicBool) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }
        let stop = batch.iter().any(|c| matches!(c, Cmd::Shutdown { .. }));
        apply_batch(&mut conn, batch, store_prompts);
        if stop {
            break;
        }
    }
}

/// Commands that delete session text: after their commit the WAL is checkpointed and truncated,
/// so the deleted bytes do not linger in old WAL frames (M3 review, L6).
fn deletes_session_text(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::ClearPromptCache { .. } | Cmd::ClearSessionIndex { .. }
    )
}

type Outcome = Box<dyn FnOnce(Option<&Error>) + Send>;

/// Run each command in a savepoint inside one transaction; send replies after the commit (and,
/// for a batch that deleted session text, after the WAL checkpoint).
fn apply_batch(conn: &mut Connection, batch: Vec<Cmd>, store_prompts: &AtomicBool) {
    let checkpoint = batch.iter().any(deletes_session_text);
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
        pending.push(execute(&tx, cmd, store_prompts));
    }
    let commit_err = tx.commit().err().map(|e| db_err("commit", &e));
    if checkpoint && commit_err.is_none() {
        // A reader holding an old snapshot can make this partial (busy_timeout waits for it);
        // the next clear or SQLite's own checkpoints finish the job.
        if let Err(e) = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
            tracing::warn!(error = %e, "WAL checkpoint after clearing session data failed");
        }
    }
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
        Cmd::SetMeta { reply, .. }
        | Cmd::StoreGit { reply, .. }
        | Cmd::Flush { reply }
        | Cmd::Shutdown { reply } => drop(reply.send(Err(e()))),
        Cmd::RecordActivity { reply, .. } | Cmd::SetIgnored { reply, .. } => {
            drop(reply.send(Err(e())))
        }
        Cmd::MarkMissing { reply, .. } | Cmd::PurgeMissing { reply, .. } => {
            drop(reply.send(Err(e())))
        }
        Cmd::MoveProject { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::StoreSessions { reply, .. }
        | Cmd::AssignSessions { reply, .. }
        | Cmd::DeleteSessions { reply, .. }
        | Cmd::ClearSessionIndex { reply }
        | Cmd::Revive { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::Forget { reply, .. } => drop(reply.send(Err(e()))),
        Cmd::ClearPromptCache { reply } => drop(reply.send(Err(e()))),
        Cmd::TouchSession { .. } | Cmd::CachePrompt { .. } => {}
    }
}

/// Execute one command in a savepoint. The returned closure sends the reply once the outer
/// transaction's commit outcome is known.
fn execute(tx: &rusqlite::Transaction<'_>, cmd: Cmd, store_prompts: &AtomicBool) -> Outcome {
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
        Cmd::PurgeExpiredSessions { now, reply } => run!(reply, |c| purge_expired(c, now)),
        Cmd::SetMeta { key, value, reply } => run!(reply, |c| {
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(|e| db_err("set meta", &e))
        }),
        Cmd::RecordActivity {
            id,
            activity,
            events,
            keep,
            reply,
        } => run!(reply, |c| record_activity(c, &id, &activity, &events, keep)),
        Cmd::StoreGit {
            id,
            info,
            now,
            reply,
        } => run!(reply, |c| store_git(c, &id, &info, now)),
        Cmd::MarkMissing { ids, now, reply } => run!(reply, |c| mark_missing(c, &ids, now)),
        Cmd::PurgeMissing { before, reply } => run!(reply, |c| purge_missing(c, before)),
        Cmd::MoveProject {
            id,
            path,
            name,
            now,
            reply,
        } => run!(reply, |c| move_project(c, &id, &path, &name, now)),
        Cmd::SetIgnored {
            path,
            ignored,
            now,
            reply,
        } => run!(reply, |c| set_ignored(c, &path, ignored, now)),
        Cmd::StoreSessions { sessions, reply } => run!(reply, |c| store_sessions(c, &sessions)),
        Cmd::AssignSessions { assignments, reply } => {
            run!(reply, |c| assign_sessions(c, &assignments))
        }
        Cmd::DeleteSessions { file_paths, reply } => {
            run!(reply, |c| delete_sessions(c, &file_paths))
        }
        Cmd::ClearSessionIndex { reply } => run!(reply, clear_session_index),
        Cmd::CachePrompt { session_id, prompt } => {
            if prompt.is_some() && !store_prompts.load(Ordering::SeqCst) {
                return Box::new(|_| {});
            }
            let _ = savepoint(tx, |c| {
                c.execute(
                    "UPDATE sessions SET prompt_text = ?2, prompt_at = ?3 WHERE id = ?1",
                    params![
                        session_id,
                        prompt.as_ref().map(|p| p.0.as_str()),
                        prompt.as_ref().and_then(|p| p.1)
                    ],
                )
                .map(|_| ())
                .map_err(|e| db_err("cache prompt", &e))
            });
            Box::new(|_| {})
        }
        Cmd::ClearPromptCache { reply } => run!(reply, |c| {
            c.execute(
                "UPDATE sessions SET prompt_text = NULL, prompt_at = NULL WHERE prompt_text IS NOT NULL OR prompt_at IS NOT NULL",
                [],
            )
            .map(|n| n as u64)
            .map_err(|e| db_err("clear prompt cache", &e))
        }),
        Cmd::Revive { ids, now, reply } => run!(reply, |c| revive(c, &ids, now)),
        Cmd::Forget { id, reply } => run!(reply, |c| forget(c, &id)),
        Cmd::Flush { reply } | Cmd::Shutdown { reply } => run!(reply, |_c| Ok(())),
    }
}

/// Recompute `session_count` / `session_at` of `ids` (deduplicated, `None`s skipped).
fn refresh_session_summary(c: &Connection, ids: &mut Vec<String>) -> Result<()> {
    ids.sort();
    ids.dedup();
    let mut st = c
        .prepare_cached(
            "UPDATE projects SET
               session_count = (SELECT count(*) FROM sessions WHERE project_id = ?1),
               session_at = (SELECT max(last_activity_at) FROM sessions WHERE project_id = ?1)
             WHERE id = ?1",
        )
        .map_err(|e| db_err("prepare session summary", &e))?;
    for id in ids.iter() {
        st.execute(params![id])
            .map_err(|e| db_err("session summary", &e))?;
    }
    Ok(())
}

fn project_of_session(c: &Connection, id: &str) -> Result<Option<String>> {
    c.query_row(
        "SELECT project_id FROM sessions WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<String>>(0),
    )
    .optional()
    .map(Option::flatten)
    .map_err(|e| db_err("find session", &e))
}

fn store_sessions(c: &Connection, sessions: &[SessionStore]) -> Result<Vec<String>> {
    let mut affected = Vec::new();
    for s in sessions {
        if let Some(old) = project_of_session(c, &s.id)? {
            affected.push(old);
        }
        let a = &s.aggregate;
        let derived = (!a.derived_from.is_empty())
            .then(|| serde_json::to_string(&a.derived_from))
            .transpose()
            .map_err(|e| Error::new(format!("encode derived-from: {e}")))?;
        // A project that no longer exists (purged meanwhile) leaves the session unassigned.
        c.execute(
            "INSERT INTO sessions (id, project_id, file_path, first_cwd, last_cwd, started_at,
                                   last_activity_at, title, git_branch, version, entrypoint,
                                   continued_in, derived_from, is_sidechain, unassigned)
             VALUES (?1, (SELECT id FROM projects WHERE id = ?2), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                     ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(id) DO UPDATE SET
               project_id = excluded.project_id, file_path = excluded.file_path,
               first_cwd = excluded.first_cwd, last_cwd = excluded.last_cwd,
               started_at = excluded.started_at, last_activity_at = excluded.last_activity_at,
               title = excluded.title, git_branch = excluded.git_branch, version = excluded.version,
               entrypoint = excluded.entrypoint, continued_in = excluded.continued_in,
               derived_from = excluded.derived_from, is_sidechain = excluded.is_sidechain,
               unassigned = excluded.unassigned, prompt_text = NULL, prompt_at = NULL",
            params![
                s.id,
                s.project_id,
                s.file_path,
                a.first_cwd,
                a.last_cwd,
                a.started_at,
                a.last_activity_at,
                a.title,
                a.git_branch,
                a.version,
                a.entrypoint,
                a.continued_in,
                derived,
                a.is_sidechain,
                s.unassigned,
            ],
        )
        .map_err(|e| db_err("store session", &e))?;
        let k = &s.checkpoint;
        let n = &a.counts;
        let int = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        c.execute(
            "INSERT INTO session_file_checkpoints
               (session_id, dev, ino, size, offset, mtime_ns, lines, malformed, oversized, unknown,
                foreign_id, partial)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(session_id) DO UPDATE SET dev = excluded.dev, ino = excluded.ino,
               size = excluded.size, offset = excluded.offset, mtime_ns = excluded.mtime_ns,
               lines = excluded.lines, malformed = excluded.malformed, oversized = excluded.oversized,
               unknown = excluded.unknown, foreign_id = excluded.foreign_id,
               partial = excluded.partial",
            params![
                s.id,
                int(k.dev),
                int(k.ino),
                int(k.size),
                int(k.offset),
                k.mtime_ns,
                int(n.lines),
                int(n.malformed),
                int(n.oversized),
                int(n.unknown),
                int(n.foreign),
                k.partial
            ],
        )
        .map_err(|e| db_err("store checkpoint", &e))?;
        if let Some(p) = project_of_session(c, &s.id)? {
            affected.push(p);
        }
    }
    refresh_session_summary(c, &mut affected)?;
    Ok(affected)
}

fn assign_sessions(
    c: &Connection,
    assignments: &[(String, Option<String>, Option<&'static str>)],
) -> Result<Vec<String>> {
    let mut affected = Vec::new();
    for (id, project, reason) in assignments {
        if let Some(old) = project_of_session(c, id)? {
            affected.push(old);
        }
        c.execute(
            "UPDATE sessions SET project_id = (SELECT id FROM projects WHERE id = ?2), unassigned = ?3
             WHERE id = ?1",
            params![id, project, reason],
        )
        .map_err(|e| db_err("assign session", &e))?;
        if let Some(p) = project_of_session(c, id)? {
            affected.push(p);
        }
    }
    refresh_session_summary(c, &mut affected)?;
    Ok(affected)
}

fn delete_sessions(c: &Connection, file_paths: &[String]) -> Result<Vec<String>> {
    let mut affected = Vec::new();
    for path in file_paths {
        let project: Option<Option<String>> = c
            .query_row(
                "SELECT project_id FROM sessions WHERE file_path = ?1",
                params![path],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| db_err("find session", &e))?;
        affected.extend(project.flatten());
        c.execute("DELETE FROM sessions WHERE file_path = ?1", params![path])
            .map_err(|e| db_err("delete session", &e))?;
    }
    refresh_session_summary(c, &mut affected)?;
    Ok(affected)
}

fn clear_session_index(c: &Connection) -> Result<Vec<String>> {
    let mut affected: Vec<String> = c
        .prepare("SELECT DISTINCT project_id FROM sessions WHERE project_id IS NOT NULL")
        .and_then(|mut st| {
            st.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()
        })
        .map_err(|e| db_err("list session projects", &e))?;
    c.execute_batch("DELETE FROM session_file_checkpoints; DELETE FROM sessions;")
        .map_err(|e| db_err("clear session index", &e))?;
    refresh_session_summary(c, &mut affected)?;
    Ok(affected)
}

/// `meta` key holding the [`crate::claude::parse::PARSER_VERSION`] the session index was built with.
pub const PARSER_VERSION_KEY: &str = "session_parser_version";

/// On an upgrade that changed the session parsing rules, clear the derived session index (in one
/// transaction with the new version), so the next ingest parses every file again from byte 0
/// and no row keeps a value computed by older rules. Projects stay; their session counts are
/// recomputed. Returns whether the index was cleared.
pub fn reindex_if_parser_changed(conn: &mut Connection, version: u32) -> Result<bool> {
    let want = version.to_string();
    let tx = conn.transaction().map_err(|e| db_err("begin", &e))?;
    let have: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![PARSER_VERSION_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| db_err("read parser version", &e))?;
    if have.as_deref() == Some(want.as_str()) {
        return Ok(false);
    }
    let sessions: i64 = tx
        .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
        .map_err(|e| db_err("count sessions", &e))?;
    clear_session_index(&tx)?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![PARSER_VERSION_KEY, want],
    )
    .map_err(|e| db_err("set parser version", &e))?;
    tx.commit().map_err(|e| db_err("commit", &e))?;
    if sessions > 0 {
        tracing::info!(
            from = have.as_deref().unwrap_or("1"),
            to = version,
            sessions,
            "session parsing rules changed: the session index is rebuilt from the session files"
        );
        if let Err(e) = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
            tracing::warn!(error = %e, "WAL checkpoint after clearing session data failed");
        }
    }
    Ok(sessions > 0)
}

fn forget(c: &Connection, id: &str) -> Result<bool> {
    // Its sessions lose the project (ON DELETE SET NULL) and are resolved again at the next
    // ingest; the reason stays empty until then.
    c.execute(
        "DELETE FROM projects WHERE id = ?1 AND missing_since IS NOT NULL",
        params![id],
    )
    .map(|n| n > 0)
    .map_err(|e| db_err("forget project", &e))
}

fn revive(c: &Connection, ids: &[String], now: i64) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    for id in ids {
        if c.execute(
            "UPDATE projects SET missing_since = NULL, last_seen_at = ?2 WHERE id = ?1 AND missing_since IS NOT NULL",
            params![id, now],
        )
        .map_err(|e| db_err("revive", &e))?
            > 0
        {
            changed.push(id.clone());
        }
    }
    Ok(changed)
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
        let existing: Option<(String, Option<i64>)> = c
            .query_row(
                "SELECT id, missing_since FROM projects WHERE canonical_path = ?1",
                params![p.canonical_path],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| db_err("find project", &e))?;
        let hash = p.marker_hash.as_ref().map(<[u8; 32]>::as_slice);
        let row = match existing {
            Some((id, missing_since)) => {
                c.execute(
                    "UPDATE projects SET name = ?2, sort_key = ?3, last_seen_at = ?4, missing_since = NULL,
                            marker_hash = coalesce(?5, marker_hash) WHERE id = ?1",
                    params![id, p.name, sort_key(&p.name), now, hash],
                )
                .map_err(|e| db_err("update project", &e))?;
                summary.updated += 1;
                Upserted {
                    id,
                    canonical_path: p.canonical_path.clone(),
                    inserted: false,
                    revived: missing_since.is_some(),
                }
            }
            None => {
                let id = random_id()?;
                c.execute(
                    "INSERT INTO projects (id, canonical_path, name, sort_key, first_seen_at, last_seen_at, marker_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                    params![id, p.canonical_path, p.name, sort_key(&p.name), now, hash],
                )
                .map_err(|e| db_err("insert project", &e))?;
                summary.inserted += 1;
                Upserted {
                    id,
                    canonical_path: p.canonical_path.clone(),
                    inserted: true,
                    revived: false,
                }
            }
        };
        c.execute(
            "INSERT OR IGNORE INTO project_sources (project_id, source, first_seen_at) VALUES (?1, ?2, ?3)",
            params![row.id, p.source.as_str(), now],
        )
        .map_err(|e| db_err("insert source", &e))?;
        summary.rows.push(row);
    }
    Ok(summary)
}

fn record_activity(
    c: &Connection,
    id: &str,
    a: &Activity,
    events: &[FileEvent],
    keep: u32,
) -> Result<bool> {
    let changed = c
        .execute(
            "UPDATE projects SET activity_at = ?2, activity_kind = ?3,
                    activity_path = coalesce(?4, activity_path)
             WHERE id = ?1 AND (activity_at IS NULL OR activity_at < ?2
                                -- same second: a newer observation may upgrade an inference or
                                -- name a newer file; an inference never replaces an observation
                                OR (activity_at = ?2 AND ?3 = 'observed'
                                    AND (activity_kind IS NOT 'observed'
                                         OR activity_path IS NOT coalesce(?4, activity_path))))",
            params![id, a.at, a.kind.as_str(), a.path],
        )
        .map_err(|e| db_err("record activity", &e))?
        > 0;
    if events.is_empty() {
        return Ok(changed);
    }
    let mut insert = c
        .prepare_cached("INSERT INTO file_events (project_id, at, kind, path) SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM projects WHERE id = ?1)")
        .map_err(|e| db_err("prepare event", &e))?;
    for e in events {
        insert
            .execute(params![id, e.at, e.kind.as_str(), e.path])
            .map_err(|e| db_err("insert event", &e))?;
    }
    c.execute(
        "DELETE FROM file_events WHERE project_id = ?1 AND id NOT IN (
           SELECT id FROM file_events WHERE project_id = ?1 ORDER BY id DESC LIMIT ?2)",
        params![id, i64::from(keep)],
    )
    .map_err(|e| db_err("trim events", &e))?;
    Ok(changed)
}

fn store_git(c: &Connection, id: &str, g: &crate::git::Info, now: i64) -> Result<()> {
    let wt = g.worktree.as_ref();
    let files = wt
        .map(|w| serde_json::to_string(&w.files))
        .transpose()
        .map_err(|e| Error::new(format!("encode git files: {e}")))?;
    let head = g.head.as_ref();
    c.execute(
        "INSERT INTO git_cache (project_id, fetched_at, state, branch, detached, upstream, ahead, behind,
                                staged, modified, untracked, files, head_commit, head_subject, head_author,
                                head_time, remote_url)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
         WHERE EXISTS (SELECT 1 FROM projects WHERE id = ?1)
         ON CONFLICT(project_id) DO UPDATE SET
           fetched_at = excluded.fetched_at, state = excluded.state, branch = excluded.branch,
           detached = excluded.detached, upstream = excluded.upstream, ahead = excluded.ahead,
           behind = excluded.behind, staged = excluded.staged, modified = excluded.modified,
           untracked = excluded.untracked, files = excluded.files, head_commit = excluded.head_commit,
           head_subject = excluded.head_subject, head_author = excluded.head_author,
           head_time = excluded.head_time, remote_url = excluded.remote_url",
        params![
            id,
            now,
            g.state.as_str(),
            g.branch,
            g.detached,
            g.upstream,
            g.ahead,
            g.behind,
            wt.map(|w| w.staged),
            wt.map(|w| w.modified),
            wt.map(|w| w.untracked),
            files,
            head.map(|h| h.hash.as_str()),
            head.map(|h| h.subject.as_str()),
            head.map(|h| h.author.as_str()),
            head.map(|h| h.time),
            g.remote_url,
        ],
    )
    .map_err(|e| db_err("store git", &e))?;
    Ok(())
}

fn mark_missing(c: &Connection, ids: &[String], now: i64) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    let mut st = c
        .prepare_cached(
            "UPDATE projects SET missing_since = ?2 WHERE id = ?1 AND missing_since IS NULL",
        )
        .map_err(|e| db_err("prepare missing", &e))?;
    for id in ids {
        if st
            .execute(params![id, now])
            .map_err(|e| db_err("mark missing", &e))?
            > 0
        {
            changed.push(id.clone());
        }
    }
    Ok(changed)
}

fn purge_missing(c: &Connection, before: i64) -> Result<Vec<String>> {
    let ids: Vec<String> = c
        .prepare("SELECT id FROM projects WHERE missing_since IS NOT NULL AND missing_since <= ?1")
        .and_then(|mut st| {
            st.query_map(params![before], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()
        })
        .map_err(|e| db_err("find purgeable", &e))?;
    c.execute(
        "DELETE FROM projects WHERE missing_since IS NOT NULL AND missing_since <= ?1",
        params![before],
    )
    .map_err(|e| db_err("purge missing", &e))?;
    Ok(ids)
}

fn move_project(
    c: &Connection,
    id: &str,
    path: &str,
    name: &str,
    now: i64,
) -> Result<Option<String>> {
    let occupant: Option<String> = c
        .query_row(
            "SELECT id FROM projects WHERE canonical_path = ?1 AND id <> ?2",
            params![path, id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| db_err("find occupant", &e))?;
    if let Some(other) = &occupant {
        // Keep the sources the newer row had (e.g. a session source seen at the new path).
        c.execute(
            "INSERT OR IGNORE INTO project_sources (project_id, source, first_seen_at)
             SELECT ?1, source, first_seen_at FROM project_sources WHERE project_id = ?2",
            params![id, other],
        )
        .map_err(|e| db_err("merge sources", &e))?;
        c.execute("DELETE FROM projects WHERE id = ?1", params![other])
            .map_err(|e| db_err("delete duplicate", &e))?;
    }
    // An ignored project stays ignored where it moved to (the ignore is keyed by path).
    c.execute(
        "UPDATE OR IGNORE ignored_paths SET canonical_path = ?2
         WHERE canonical_path = (SELECT canonical_path FROM projects WHERE id = ?1)",
        params![id, path],
    )
    .map_err(|e| db_err("move ignore", &e))?;
    c.execute(
        "DELETE FROM ignored_paths WHERE canonical_path = (SELECT canonical_path FROM projects WHERE id = ?1)
           AND canonical_path <> ?2",
        params![id, path],
    )
    .map_err(|e| db_err("drop old ignore", &e))?;
    c.execute(
        "UPDATE projects SET canonical_path = ?2, name = ?3, sort_key = ?4, missing_since = NULL, last_seen_at = ?5
         WHERE id = ?1",
        params![id, path, name, sort_key(name), now],
    )
    .map_err(|e| db_err("move project", &e))?;
    Ok(occupant)
}

fn set_ignored(c: &Connection, path: &str, ignored: bool, now: i64) -> Result<bool> {
    let n = if ignored {
        c.execute(
            "INSERT OR IGNORE INTO ignored_paths (canonical_path, ignored_at) VALUES (?1, ?2)",
            params![path, now],
        )
    } else {
        c.execute(
            "DELETE FROM ignored_paths WHERE canonical_path = ?1",
            params![path],
        )
    }
    .map_err(|e| db_err("set ignored", &e))?;
    Ok(n > 0)
}

/// Insert a session after dropping expired ones, then keep only the [`MAX_LIVE_SESSIONS`] most
/// recently used (the new one counts as just used). Existing sessions are otherwise left alone:
/// `ccwm open` does not sign out other browsers.
fn create_session(
    c: &Connection,
    token_hash: TokenHash,
    now: i64,
    expires_at: i64,
) -> Result<StoredSession> {
    purge_expired(c, now)?;
    let id = random_id()?;
    c.execute(
        "INSERT INTO auth_sessions (id, token_hash, created_at, last_used_at, rotated_at, expires_at) VALUES (?1, ?2, ?3, ?3, ?3, ?4)",
        params![id, token_hash.as_slice(), now, expires_at],
    )
    .map_err(|e| db_err("create session", &e))?;
    c.execute(
        "DELETE FROM auth_sessions WHERE id NOT IN (
           SELECT id FROM auth_sessions ORDER BY (id = ?1) DESC, last_used_at DESC, created_at DESC LIMIT ?2)",
        params![id, MAX_LIVE_SESSIONS as i64],
    )
    .map_err(|e| db_err("cap sessions", &e))?;
    Ok(StoredSession {
        id,
        expires_at,
        rotated_at: now,
    })
}

/// Delete expired sessions and forget previous tokens whose grace window has closed.
fn purge_expired(c: &Connection, now: i64) -> Result<u64> {
    let n = c
        .execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?1",
            params![now],
        )
        .map_err(|e| db_err("purge sessions", &e))?;
    c.execute(
        "UPDATE auth_sessions SET prev_token_hash = NULL, prev_valid_until = NULL
         WHERE prev_valid_until IS NOT NULL AND prev_valid_until <= ?1",
        params![now],
    )
    .map_err(|e| db_err("purge previous tokens", &e))?;
    Ok(n as u64)
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
