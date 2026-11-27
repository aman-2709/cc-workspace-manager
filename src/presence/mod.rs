//! The activity indicator's daemon side (REQUIREMENTS.md §21; ARCHITECTURE.md §15): hook events
//! from `ccwm hook`, which Claude Code process each came from ([`proc`]), the open sessions
//! ([`store`]), their persistence across restarts, and the liveness sweep.
//!
//! Hook events are **never activity** (§21.1): nothing here touches activity times, sort order,
//! watches or ignore rules, and nothing here registers a project.

pub mod proc;
pub mod store;

use crate::claude::hook::{Malformed, Report};
use crate::clock::Clock;
use crate::db::reader::Reader;
use crate::db::writer::Writer;
use proc::ProcFs;
use serde::Serialize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use store::{Counters, LogEntry, Outcome, Persist, Refusal, Store};
use tokio::sync::watch;

/// Open sessions are checked this often while any is tracked (§21.6, O13).
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// A `hook.event` request as the socket protocol parsed it.
pub type HookRequest = Result<Report, Malformed>;

/// `hooks.events` (`ccwm hooks events`): the counters and the debug log.
#[derive(Debug, Clone, Serialize)]
pub struct EventsView {
    /// When the daemon started (Unix seconds): a new value means the log started over.
    pub started_at: i64,
    #[serde(flatten)]
    pub counters: Counters,
    pub open: usize,
    pub open_noninteractive: usize,
    /// The debug log's size: older entries are dropped.
    pub kept: usize,
    pub events: Vec<LogEntry>,
}

pub struct Presence {
    store: Mutex<Store>,
    proc: ProcFs,
    uid: u32,
    daemon_pid: u32,
    /// Read once: it changes only with a reboot, which ends the daemon too. Empty when it could
    /// not be read (then no persisted session can be verified at start).
    boot_id: String,
    writer: Arc<Writer>,
    clock: Arc<dyn Clock>,
    started_at: i64,
}

impl Presence {
    pub fn new(
        proc: ProcFs,
        uid: u32,
        daemon_pid: u32,
        writer: Arc<Writer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let boot_id = proc.boot_id().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "cannot read the boot id: open sessions cannot be restored after a restart");
            String::new()
        });
        Self {
            store: Mutex::new(Store::default()),
            proc,
            uid,
            daemon_pid,
            boot_id,
            started_at: clock.now(),
            writer,
            clock,
        }
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, p: Persist) {
        match p {
            Persist::Put(id, open) => self.writer.put_open_session(&id, &open),
            Persist::Delete(ids) => self.writer.delete_open_sessions(ids),
        }
    }

    /// A `hook.event` from the socket peer `peer_pid` (§21.5, §21.6). Called by the socket
    /// handler while `ccwm hook` waits for its answer: validation, the process walk and the
    /// in-memory update only; the database write is queued, never awaited.
    pub fn report(&self, peer_pid: Option<i32>, request: HookRequest) -> Result<(), Refusal> {
        let now = self.clock.now();
        let at_ms = self.clock.now_ms();
        let report = match request {
            Ok(r) if r.claude_pid != Some(self.daemon_pid) => r,
            Ok(r) => {
                let session = Some(r.session_id.clone());
                return self.refuse(
                    now,
                    at_ms,
                    Some(r.event),
                    None,
                    session,
                    None,
                    Refusal::Malformed,
                );
            }
            Err(m) => {
                return self.refuse(
                    now,
                    at_ms,
                    None,
                    m.event,
                    m.session_id,
                    None,
                    Refusal::Malformed,
                );
            }
        };
        let sent = Some(report.claude_pid.is_some());
        let found = peer_pid
            .and_then(|p| u32::try_from(p).ok())
            .ok_or(Refusal::NoClaudeAncestor)
            .and_then(|peer| {
                self.proc
                    .find_claude(peer, report.claude_pid, self.uid, &self.boot_id)
            });
        let found = match found {
            Ok(f) => f,
            Err(r) => {
                let session = Some(report.session_id.clone());
                return self.refuse(now, at_ms, Some(report.event), None, session, sent, r);
            }
        };
        let mut store = self.store();
        store.received(now);
        let applied = store.apply(&report, &found, now, |id| self.proc.alive(id));
        let outcome = match &applied {
            Ok((Outcome::Opened, _)) if !found.interactive => {
                "opened (non-interactive)".to_string()
            }
            Ok((o, _)) => o.as_str().to_string(),
            Err(r) => format!("refused: {}", r.as_str()),
        };
        store.log(
            at_ms,
            Some(report.event),
            None,
            Some(report.session_id.clone()),
            sent,
            outcome,
        );
        match applied {
            Ok((_, persist)) => {
                drop(store);
                tracing::trace!(event = report.event.name(), "hook event");
                if let Some(p) = persist {
                    self.persist(p);
                }
                Ok(())
            }
            Err(r) => {
                store.refused(r);
                tracing::trace!(
                    event = report.event.name(),
                    refused = r.as_str(),
                    "hook event"
                );
                Err(r)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &self,
        now: i64,
        at_ms: i64,
        event: Option<crate::claude::hook::Event>,
        event_name: Option<&'static str>,
        session_id: Option<String>,
        sent: Option<bool>,
        r: Refusal,
    ) -> Result<(), Refusal> {
        let mut store = self.store();
        store.received(now);
        store.refused(r);
        store.log(
            at_ms,
            event,
            event_name,
            session_id,
            sent,
            format!("refused: {}", r.as_str()),
        );
        drop(store);
        tracing::trace!(
            event = event
                .map(crate::claude::hook::Event::name)
                .or(event_name)
                .unwrap_or("?"),
            refused = r.as_str(),
            "hook event"
        );
        Err(r)
    }

    /// Close every session whose process is gone (§21.6, O13). The `/proc` reads happen outside
    /// the lock; a session that moved to another process meanwhile stays.
    pub fn sweep(&self) -> Vec<String> {
        let tracked = self.store().identities();
        if tracked.is_empty() {
            return Vec::new();
        }
        let gone: Vec<_> = tracked
            .into_iter()
            .filter(|(_, id)| !self.proc.alive(id))
            .collect();
        if gone.is_empty() {
            return Vec::new();
        }
        let at_ms = self.clock.now_ms();
        let mut store = self.store();
        let mut closed = Vec::new();
        for (sid, identity) in gone {
            if store.close_if(&sid, &identity) {
                store.log(
                    at_ms,
                    None,
                    None,
                    Some(sid.clone()),
                    None,
                    "closed: process gone".into(),
                );
                closed.push(sid);
            }
        }
        drop(store);
        self.writer.delete_open_sessions(closed.clone());
        closed
    }

    /// At start (§21.7): put back the persisted sessions whose process is still the same Claude
    /// Code process (same pid, start time and boot id); delete the others. The interactive flag
    /// is read again. Returns (restored, dropped).
    pub async fn restore(&self, reader: &Reader) -> crate::error::Result<(usize, usize)> {
        let rows = reader.with(crate::db::queries::open_sessions).await?;
        let at_ms = self.clock.now_ms();
        let mut dropped = Vec::new();
        let mut restored = 0;
        let mut store = self.store();
        for (sid, mut open) in rows {
            let verdict = (!self.boot_id.is_empty())
                .then(|| {
                    self.proc
                        .still_claude(&open.identity, self.uid, &self.boot_id)
                })
                .flatten();
            let kept = match verdict {
                Some(interactive) => {
                    open.interactive = interactive;
                    store.restore(sid.clone(), open)
                }
                None => false,
            };
            let outcome = if kept {
                "restored"
            } else {
                "dropped at start: process gone"
            };
            store.log(at_ms, None, None, Some(sid.clone()), None, outcome.into());
            if kept {
                restored += 1;
            } else {
                dropped.push(sid);
            }
        }
        drop(store);
        let n = dropped.len();
        self.writer.delete_open_sessions(dropped);
        Ok((restored, n))
    }

    /// "Clear session index" (§21.7, O16): the database rows go with the index (the writer
    /// deletes them in the same command); this empties the memory.
    pub fn clear(&self) {
        let at_ms = self.clock.now_ms();
        let mut store = self.store();
        let n = store.clear();
        store.log(
            at_ms,
            None,
            None,
            None,
            None,
            format!("cleared: {n} open session(s) forgotten"),
        );
    }

    pub fn events(&self) -> EventsView {
        let store = self.store();
        let (open, open_noninteractive) = store.open_counts();
        EventsView {
            started_at: self.started_at,
            counters: store.counters().clone(),
            open,
            open_noninteractive,
            kept: store::LOG_SIZE,
            events: store.log_entries(),
        }
    }

    /// Run [`Self::sweep`] every [`SWEEP_INTERVAL`] until `stop`.
    pub async fn run_sweeper(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let closed = self.sweep();
                    if !closed.is_empty() {
                        tracing::debug!(closed = closed.len(), "open sessions whose process is gone were closed");
                    }
                }
                () = crate::events::until_stopped(&mut stop) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::proc::fake::{FakeProc, BOOT};
    use super::*;
    use crate::claude::hook::{Event, Notice, Source};
    use crate::clock::FakeClock;

    const UID: u32 = 1000;
    const DAEMON: u32 = 7;
    const A: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const B: &str = "1b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";

    struct Env {
        fake: FakeProc,
        presence: Presence,
        writer: Arc<Writer>,
        reader: Reader,
        db: std::path::PathBuf,
        clock: Arc<FakeClock>,
        _dir: tempfile::TempDir,
    }

    /// A claude (100) with a hook process (300) under `sh` (200), as the live run had it.
    fn env() -> Env {
        let fake = FakeProc::new();
        fake.process(50, UID, 1, 10, &["systemd", "--user"]);
        fake.process(100, UID, 50, 20, &["claude"]);
        fake.process(200, UID, 100, 30, &["sh", "-c", "x"]);
        fake.process(300, UID, 200, 31, &["ccwm", "hook", "Stop"]);
        open_env(fake)
    }

    fn open_env(fake: FakeProc) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let writer = Arc::new(Writer::spawn(&db).unwrap());
        let reader = Reader::open(&db, 1).unwrap();
        let clock = Arc::new(FakeClock::new(1_000));
        let presence = Presence::new(
            ProcFs::new(fake.root()),
            UID,
            DAEMON,
            Arc::clone(&writer),
            clock.clone(),
        );
        Env {
            fake,
            presence,
            writer,
            reader,
            db,
            clock,
            _dir: dir,
        }
    }

    fn report(event: Event, sid: &str, claude_pid: Option<u32>) -> HookRequest {
        Ok(Report {
            event,
            session_id: sid.into(),
            cwd: "/home/u/dev/SYNTHETIC-CWD-CANARY".into(),
            prompt_id: None,
            claude_pid,
        })
    }

    impl Env {
        async fn rows(&self) -> Vec<(String, u32)> {
            self.writer.flush().await.unwrap();
            self.reader
                .with(crate::db::queries::open_sessions)
                .await
                .unwrap()
                .into_iter()
                .map(|(id, o)| (id, o.identity.pid))
                .collect()
        }

        fn outcomes(&self) -> Vec<String> {
            self.presence
                .events()
                .events
                .into_iter()
                .map(|e| e.outcome)
                .collect()
        }
    }

    #[tokio::test]
    async fn events_open_and_close_sessions_and_the_database_follows() {
        let e = env();
        let p = &e.presence;
        p.report(
            Some(300),
            report(Event::SessionStart(Source::Startup), A, Some(100)),
        )
        .unwrap();
        p.report(Some(300), report(Event::UserPromptSubmit, A, None))
            .unwrap();
        assert_eq!(e.rows().await, [(A.to_string(), 100)]);
        let v = p.events();
        assert_eq!(
            (
                v.counters.received,
                v.open,
                v.open_noninteractive,
                v.counters.last_event_at
            ),
            (2, 1, 0, Some(1_000))
        );
        p.report(Some(300), report(Event::SessionEnd, A, Some(100)))
            .unwrap();
        p.report(Some(300), report(Event::SessionEnd, B, None))
            .unwrap();
        assert!(e.rows().await.is_empty());
        assert_eq!(
            e.outcomes(),
            ["opened", "accepted", "closed", "ignored (not open)"]
        );
        let log = p.events().events;
        assert_eq!(log[0].detail, Some("startup"));
        assert_eq!(
            log.iter().map(|l| l.claude_pid_sent).collect::<Vec<_>>(),
            [Some(true), Some(false), Some(true), Some(false)]
        );
        assert_eq!(log.iter().map(|l| l.seq).collect::<Vec<_>>(), [1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn refusals_are_counted_logged_and_change_nothing() {
        let e = env();
        let p = &e.presence;
        // CLAUDE_PID naming another process.
        assert_eq!(
            p.report(Some(300), report(Event::Stop, A, Some(200))),
            Err(Refusal::PidMismatch)
        );
        // No claude above the peer; no peer pid at all.
        e.fake.process(400, UID, 50, 40, &["ccwm", "hook", "Stop"]);
        assert_eq!(
            p.report(Some(400), report(Event::Stop, A, None)),
            Err(Refusal::NoClaudeAncestor)
        );
        assert_eq!(
            p.report(None, report(Event::Stop, A, None)),
            Err(Refusal::NoClaudeAncestor)
        );
        assert_eq!(
            p.report(Some(-1), report(Event::Stop, A, None)),
            Err(Refusal::NoClaudeAncestor)
        );
        // The daemon's own pid as CLAUDE_PID; a malformed request.
        assert_eq!(
            p.report(Some(300), report(Event::Stop, A, Some(DAEMON))),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            p.report(
                Some(300),
                Err(Malformed {
                    event: Some("Stop"),
                    session_id: None
                })
            ),
            Err(Refusal::Malformed)
        );
        let v = p.events();
        assert_eq!(v.open, 0);
        assert_eq!(v.counters.received, 6);
        assert_eq!(
            (
                v.counters.refused.malformed,
                v.counters.refused.no_claude_ancestor,
                v.counters.refused.pid_mismatch,
                v.counters.refused.limit
            ),
            (2, 3, 1, 0)
        );
        assert_eq!(
            e.outcomes(),
            [
                "refused: pid_mismatch",
                "refused: no_claude_ancestor",
                "refused: no_claude_ancestor",
                "refused: no_claude_ancestor",
                "refused: malformed",
                "refused: malformed"
            ]
        );
        assert_eq!(v.events[5].event, Some("Stop"));
        assert!(e.rows().await.is_empty());
    }

    #[tokio::test]
    async fn a_non_interactive_session_is_marked() {
        let e = env();
        e.fake
            .process(100, UID, 50, 20, &["claude", "-p", "SYNTHETIC-ARGV-PROMPT"]);
        e.presence
            .report(Some(300), report(Event::UserPromptSubmit, A, None))
            .unwrap();
        let v = e.presence.events();
        assert_eq!((v.open, v.open_noninteractive), (1, 1));
        assert_eq!(e.outcomes(), ["opened (non-interactive)"]);
        let shown = serde_json::to_string(&v).unwrap();
        assert!(
            !shown.contains("SYNTHETIC"),
            "no argv, cwd or prompt in the view: {shown}"
        );
    }

    #[tokio::test]
    async fn the_sweep_closes_sessions_whose_process_is_gone() {
        let e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        // A second claude with its own session.
        e.fake.process(500, UID, 50, 50, &["claude"]);
        e.fake.process(510, UID, 500, 51, &["ccwm", "hook", "Stop"]);
        e.presence
            .report(Some(510), report(Event::Stop, B, None))
            .unwrap();
        assert!(e.presence.sweep().is_empty(), "both alive");
        // The first claude exits; the second's pid is reused by another process.
        e.fake.remove(100);
        e.fake.process(500, UID, 50, 99, &["claude"]);
        let mut closed = e.presence.sweep();
        closed.sort();
        assert_eq!(closed, [A, B]);
        assert_eq!(e.presence.events().open, 0);
        assert!(e.rows().await.is_empty());
        assert!(e.outcomes().ends_with(&[
            "closed: process gone".to_string(),
            "closed: process gone".to_string()
        ]));
    }

    #[tokio::test]
    async fn a_zombie_is_gone_and_a_new_process_takes_the_session_over() {
        let e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        e.fake
            .process_full(100, "claude", UID, UID, 50, 20, 'Z', &[b"claude"]);
        // `claude --resume` in a new process: its first event (not SessionStart) moves the
        // session there, because the old process is gone.
        e.fake.process(600, UID, 50, 60, &["claude", "--resume", A]);
        e.fake.process(610, UID, 600, 61, &["ccwm", "hook", "Stop"]);
        e.presence
            .report(
                Some(610),
                report(Event::Notification(Notice::IdlePrompt), A, None),
            )
            .unwrap();
        assert_eq!(e.rows().await, [(A.to_string(), 600)]);
        assert!(e.presence.sweep().is_empty());
        assert_eq!(e.outcomes(), ["opened", "new process"]);
    }

    #[tokio::test]
    async fn a_restart_restores_live_sessions_and_drops_the_others() {
        let e = env();
        e.fake.process(500, UID, 50, 50, &["claude"]);
        e.fake.process(510, UID, 500, 51, &["ccwm", "hook", "Stop"]);
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        e.presence
            .report(Some(510), report(Event::Stop, B, None))
            .unwrap();
        e.writer.flush().await.unwrap();
        // Restart: the first claude now runs with --print; the second has exited.
        e.fake.process(100, UID, 50, 20, &["claude", "--print"]);
        e.fake.remove(500);
        let restarted = Presence::new(
            ProcFs::new(e.fake.root()),
            UID,
            DAEMON,
            Arc::clone(&e.writer),
            e.clock.clone(),
        );
        assert_eq!(restarted.restore(&e.reader).await.unwrap(), (1, 1));
        let v = restarted.events();
        assert_eq!(
            (v.open, v.open_noninteractive, v.counters.received),
            (1, 1, 0)
        );
        let mut outcomes: Vec<String> = v.events.iter().map(|l| l.outcome.clone()).collect();
        outcomes.sort();
        assert_eq!(outcomes, ["dropped at start: process gone", "restored"]);
        assert_eq!(e.rows().await, [(A.to_string(), 100)]);
        // A reboot (another boot id): nothing is restored, everything deleted.
        e.fake.set_boot_id("2d2c3b4a-0000-4000-8000-00000000b007");
        let rebooted = Presence::new(
            ProcFs::new(e.fake.root()),
            UID,
            DAEMON,
            Arc::clone(&e.writer),
            e.clock.clone(),
        );
        assert_eq!(rebooted.restore(&e.reader).await.unwrap(), (0, 1));
        assert!(e.rows().await.is_empty());
        // The boot id was BOOT for the first daemon.
        assert_eq!(BOOT.len(), 36);
    }

    #[tokio::test]
    async fn clear_session_index_empties_memory_and_database() {
        let e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        assert_eq!(e.rows().await.len(), 1);
        e.writer.clear_session_index().await.unwrap();
        e.presence.clear();
        assert!(e.rows().await.is_empty());
        assert_eq!(e.presence.events().open, 0);
        assert_eq!(
            e.outcomes().last().unwrap(),
            "cleared: 1 open session(s) forgotten"
        );
        // Back with its next event.
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        assert_eq!(e.presence.events().open, 1);
    }

    /// The cwd is persisted (by design, like a session row) but never in the view or a log.
    #[tokio::test]
    async fn the_cwd_reaches_only_the_open_sessions_table() {
        let e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        let view = serde_json::to_string(&e.presence.events()).unwrap();
        assert!(!view.contains("CANARY"), "{view}");
        e.writer.flush().await.unwrap();
        let cwd: String = rusqlite::Connection::open(&e.db)
            .unwrap()
            .query_row("SELECT first_cwd FROM open_sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cwd, "/home/u/dev/SYNTHETIC-CWD-CANARY");
    }

    /// The debug log, full and with the longest values, fits in a socket response.
    #[tokio::test]
    async fn a_full_debug_log_fits_in_one_socket_response() {
        let e = env();
        for i in 0..store::LOG_SIZE {
            e.presence
                .report(
                    Some(999_999),
                    report(
                        Event::Notification(Notice::PermissionPrompt),
                        A,
                        Some(4_194_304),
                    ),
                )
                .unwrap_err();
            assert!(i < store::LOG_SIZE);
        }
        e.clock.advance(1_000_000_000);
        let v = e.presence.events();
        assert_eq!(v.events.len(), store::LOG_SIZE);
        let line = crate::ipc::protocol::encode_response(&Ok(serde_json::to_value(&v).unwrap()));
        assert!(
            line.len() < crate::client::MAX_RESPONSE_BYTES as usize,
            "{} bytes",
            line.len()
        );
    }
}
