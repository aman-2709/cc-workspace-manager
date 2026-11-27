//! The activity indicator's daemon side (REQUIREMENTS.md §21; ARCHITECTURE.md §15): hook events
//! from `ccwm hook`, which Claude Code process each came from ([`proc`]), the open sessions and
//! their states ([`store`]), the ends of a turn recorded in session files (§21.2a), persistence
//! across restarts, the liveness sweep, and what the API and the UI show.
//!
//! Hook events are **never activity** (§21.1): nothing here touches activity times, the sort
//! orders of §5.4, watches or ignore rules, and nothing here registers a project. The listing's
//! "live sessions first" grouping (§21.8, [`Presence::live_ranks`]) is a separate leading key
//! that the UI shows and the toggle turns off.

pub mod proc;
pub mod store;

use crate::claude::hook::{Malformed, Report};
use crate::claude::parse::TurnFact;
use crate::clock::Clock;
use crate::db::reader::Reader;
use crate::db::writer::Writer;
use crate::events::Notifier;
use proc::ProcFs;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use store::{
    Counters, FactOutcome, LiveFilter, LiveView, LogEntry, OpenCounts, Outcome, Persist, Refusal,
    SessionLive, Store,
};
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
    /// Every tracked session, and the non-interactive ones among them (whatever the toggle).
    pub open: usize,
    pub open_noninteractive: usize,
    /// The debug log's size: older entries are dropped.
    pub kept: usize,
    pub events: Vec<LogEntry>,
}

/// `hooks` of `/service/status` and `ccwm status` (§21.10).
#[derive(Debug, Clone, Serialize)]
pub struct HooksStatus {
    #[serde(flatten)]
    pub counts: OpenCounts,
    #[serde(flatten)]
    pub counters: Counters,
}

/// What an accepted event asks of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reported {
    /// A session opened or moved to another process: its project is to be resolved.
    pub resolve: bool,
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
    notifier: Notifier,
    /// `indicator.show_noninteractive` (§21.8, O17), live.
    show_noninteractive: AtomicBool,
    /// `indicator.live_first` (§21.8): projects with an open session lead the listing. Live.
    live_first: AtomicBool,
    started_at: i64,
}

impl Presence {
    pub fn new(
        proc: ProcFs,
        uid: u32,
        daemon_pid: u32,
        writer: Arc<Writer>,
        clock: Arc<dyn Clock>,
        notifier: Notifier,
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
            notifier,
            show_noninteractive: AtomicBool::new(false),
            live_first: AtomicBool::new(true),
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

    fn publish(&self, projects: &[String]) {
        for id in projects {
            self.notifier.project(id);
        }
    }

    pub fn show_noninteractive(&self) -> bool {
        self.show_noninteractive.load(Ordering::Relaxed)
    }

    /// Turn the Settings toggle on or off (§21.8): the projects with a non-interactive session
    /// are published again.
    pub fn set_show_noninteractive(&self, on: bool) {
        if self.show_noninteractive.swap(on, Ordering::Relaxed) != on {
            let projects = self.store().noninteractive_projects();
            self.publish(&projects);
        }
    }

    /// Turn "Show live sessions first" on or off (§21.8): the projects with an open session are
    /// published again (their place in the listing changes).
    pub fn set_live_first(&self, on: bool) {
        if self.live_first.swap(on, Ordering::Relaxed) != on {
            let projects: Vec<String> = self
                .store()
                .live_ranks(self.show_noninteractive())
                .into_keys()
                .collect();
            self.publish(&projects);
        }
    }

    /// The listing's leading key when "Show live sessions first" is on: each project with a shown
    /// open session and its aggregate state (needs approval, working, waiting, unknown). `None`
    /// when the toggle is off.
    pub fn live_ranks(&self) -> Option<std::collections::BTreeMap<String, store::State>> {
        self.live_first
            .load(Ordering::Relaxed)
            .then(|| self.store().live_ranks(self.show_noninteractive()))
    }

    /// A `hook.event` from the socket peer `peer_pid` (§21.5, §21.6). Called by the socket
    /// handler while `ccwm hook` waits for its answer: validation, the process walk and the
    /// in-memory update only; the database write is queued, never awaited.
    pub fn report(&self, peer_pid: Option<i32>, request: HookRequest) -> Result<Reported, Refusal> {
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
        let applied = store.apply(&report, &found, at_ms, |id| self.proc.alive(id));
        let outcome = match &applied {
            Ok(a) => {
                let text = a.outcome.text();
                if !found.interactive && matches!(a.outcome, Outcome::Opened(_)) {
                    format!("{text} (non-interactive)")
                } else {
                    text
                }
            }
            Err(r) => format!("refused: {}", r.as_str()),
        };
        // The sessions a SessionStart closed went first (they no longer exist for the event).
        for sid in applied.iter().flat_map(|a| &a.replaced) {
            store.log(
                at_ms,
                None,
                None,
                Some(sid.clone()),
                None,
                "closed: its process started another session".into(),
            );
        }
        store.log(
            at_ms,
            Some(report.event),
            None,
            Some(report.session_id.clone()),
            sent,
            outcome,
        );
        match applied {
            Ok(a) => {
                drop(store);
                tracing::trace!(event = report.event.name(), "hook event");
                let resolve = matches!(a.outcome, Outcome::Opened(_) | Outcome::NewProcess(_));
                if !a.replaced.is_empty() {
                    self.persist(Persist::Delete(a.replaced));
                }
                if let Some(p) = a.persist {
                    self.persist(p);
                }
                self.publish(&a.projects);
                Ok(Reported { resolve })
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
    ) -> Result<Reported, Refusal> {
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

    /// The ends of a turn the session ingest read from session files (§21.2a): each moves its
    /// session to `waiting` when it belongs to the current turn. Logged unless there was nothing
    /// to change (a `turn_duration` after the `Stop` hook, a session that is not open).
    pub fn apply_facts(&self, facts: &[(String, TurnFact)]) {
        if facts.is_empty() {
            return;
        }
        let at_ms = self.clock.now_ms();
        let mut changed = Vec::new();
        let mut store = self.store();
        for (sid, fact) in facts {
            let (outcome, project) = store.apply_fact(sid, fact, at_ms);
            if outcome != FactOutcome::Nothing {
                store.log(
                    at_ms,
                    None,
                    None,
                    Some(sid.clone()),
                    None,
                    store::fact_text(fact, outcome),
                );
            }
            changed.extend(project);
        }
        drop(store);
        self.publish(&changed);
    }

    /// Start a project resolution: its sequence number and the open sessions to resolve, id and
    /// first cwd (never logged).
    pub fn cwds(&self) -> (u64, Vec<(String, String)>) {
        self.store().cwds()
    }

    /// The tracker's result of resolution `seq` ([`Self::cwds`]): a project id, or why there is
    /// none. A result older than one already applied is dropped (v0.2 review L8).
    pub fn assign(&self, seq: u64, results: Vec<(String, Result<String, &'static str>)>) {
        let changed = self.store().assign(seq, results);
        self.publish(&changed);
    }

    /// The aggregate shown for `project`, honouring the non-interactive toggle.
    pub fn live(&self, project: &str) -> Option<LiveView> {
        self.store().live(project, self.show_noninteractive())
    }

    /// One session's state for the detail panel.
    pub fn session_live(&self, session_id: &str) -> Option<SessionLive> {
        self.store()
            .session_live(session_id, self.show_noninteractive())
    }

    /// The projects a toolbar filter keeps.
    pub fn projects_matching(&self, filter: LiveFilter) -> Vec<String> {
        self.store()
            .projects_matching(filter, self.show_noninteractive())
    }

    pub fn status(&self) -> HooksStatus {
        let store = self.store();
        HooksStatus {
            counts: store.open_counts(self.show_noninteractive()),
            counters: store.counters().clone(),
        }
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
        let mut projects = Vec::new();
        for (sid, identity) in gone {
            if let Some(project) = store.close_if(&sid, &identity) {
                store.log(
                    at_ms,
                    None,
                    None,
                    Some(sid.clone()),
                    None,
                    "closed: process gone".into(),
                );
                projects.extend(project);
                closed.push(sid);
            }
        }
        drop(store);
        self.writer.delete_open_sessions(closed.clone());
        self.publish(&projects);
        closed
    }

    /// At start (§21.7): put back the persisted sessions whose process is still the same Claude
    /// Code process (same pid, start time and boot id), in the state `unknown`; delete the
    /// others. The interactive flag is read again. Returns (restored, dropped).
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
                    store.restore(sid.clone(), open, at_ms)
                }
                None => false,
            };
            let outcome = if kept {
                "restored: unknown"
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
        let (n, projects) = store.clear();
        store.log(
            at_ms,
            None,
            None,
            None,
            None,
            format!("cleared: {n} open session(s) forgotten"),
        );
        drop(store);
        self.publish(&projects);
    }

    pub fn events(&self) -> EventsView {
        let store = self.store();
        let (open, open_noninteractive) = store.totals();
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
    use super::store::State;
    use super::*;
    use crate::claude::hook::{Event, Notice, Source};
    use crate::claude::parse::TurnEnd;
    use crate::clock::FakeClock;

    /// Apply a resolution started now (the latest, so it is never dropped as older).
    fn assign_now(p: &Presence, results: Vec<(String, Result<String, &'static str>)>) {
        let (seq, _) = p.cwds();
        p.assign(seq, results);
    }

    const UID: u32 = 1000;
    const DAEMON: u32 = 7;
    const A: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const B: &str = "1b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const P1: &str = "9a8b7c6d-5e4f-4a3b-8c2d-000000000001";

    struct Env {
        fake: FakeProc,
        presence: Presence,
        writer: Arc<Writer>,
        reader: Reader,
        db: std::path::PathBuf,
        clock: Arc<FakeClock>,
        changes: tokio::sync::mpsc::Receiver<crate::events::Change>,
        notifier: Notifier,
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
        let (notifier, changes) = Notifier::channel();
        let presence = Presence::new(
            ProcFs::new(fake.root()),
            UID,
            DAEMON,
            Arc::clone(&writer),
            clock.clone(),
            notifier.clone(),
        );
        Env {
            fake,
            presence,
            writer,
            reader,
            db,
            clock,
            changes,
            notifier,
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

        fn restarted(&self) -> Presence {
            Presence::new(
                ProcFs::new(self.fake.root()),
                UID,
                DAEMON,
                Arc::clone(&self.writer),
                self.clock.clone(),
                self.notifier.clone(),
            )
        }

        /// The projects published since the last call.
        fn published(&mut self) -> Vec<String> {
            let mut out = Vec::new();
            while let Ok(c) = self.changes.try_recv() {
                if let crate::events::Change::Project(id) = c {
                    out.push(id);
                }
            }
            out.sort();
            out.dedup();
            out
        }
    }

    #[tokio::test]
    async fn events_open_change_and_close_sessions_and_the_database_follows() {
        let mut e = env();
        let p = &e.presence;
        assert_eq!(
            p.report(
                Some(300),
                report(Event::SessionStart(Source::Startup), A, Some(100))
            ),
            Ok(Reported { resolve: true })
        );
        // The tracker resolves the session's project; a state change then publishes it.
        let (seq, cwds) = p.cwds();
        assert_eq!(
            cwds,
            [(
                A.to_string(),
                "/home/u/dev/SYNTHETIC-CWD-CANARY".to_string()
            )]
        );
        p.assign(seq, vec![(A.into(), Ok("proj".into()))]);
        assert_eq!(e.published(), ["proj"]);
        let p = &e.presence;
        assert_eq!(p.live("proj").unwrap().state, State::Waiting);
        assert_eq!(
            p.report(Some(300), report(Event::UserPromptSubmit, A, None)),
            Ok(Reported { resolve: false })
        );
        assert_eq!(p.live("proj").unwrap().state, State::Working);
        assert_eq!(e.published(), ["proj"]);
        let p = &e.presence;
        p.report(Some(300), report(Event::PostToolUse, A, None))
            .unwrap();
        assert!(
            e.published().is_empty(),
            "no state change, nothing published"
        );
        assert_eq!(e.rows().await, [(A.to_string(), 100)]);
        let v = e.presence.events();
        assert_eq!(
            (
                v.counters.received,
                v.open,
                v.open_noninteractive,
                v.counters.last_event_at
            ),
            (3, 1, 0, Some(1_000))
        );
        let p = &e.presence;
        p.report(Some(300), report(Event::SessionEnd, A, Some(100)))
            .unwrap();
        p.report(Some(300), report(Event::SessionEnd, B, None))
            .unwrap();
        assert_eq!(p.live("proj"), None);
        assert!(e.rows().await.is_empty());
        assert_eq!(
            e.outcomes(),
            [
                "opened: waiting",
                "→ working",
                "unchanged: working",
                "closed",
                "ignored (not open)"
            ]
        );
        assert_eq!(e.published(), ["proj"]);
        let log = e.presence.events().events;
        assert_eq!(log[0].detail, Some("startup"));
        assert_eq!(
            log.iter().map(|l| l.claude_pid_sent).collect::<Vec<_>>(),
            [
                Some(true),
                Some(false),
                Some(false),
                Some(true),
                Some(false)
            ]
        );
    }

    /// v0.2 review L1 and L2 through the daemon side: a second process's `SessionEnd` is logged
    /// and ignored; `/clear` with a lost `SessionEnd` closes the old session, deletes its row and
    /// publishes its project.
    #[tokio::test]
    async fn one_process_one_session_and_only_the_owner_ends_it() {
        let mut e = env();
        // A second Claude Code (110) with its own hook process (310).
        e.fake.process(110, UID, 50, 21, &["claude", "--resume", A]);
        e.fake.process(210, UID, 110, 32, &["sh", "-c", "x"]);
        e.fake.process(310, UID, 210, 33, &["ccwm", "hook", "Stop"]);
        let p = &e.presence;
        p.report(Some(300), report(Event::Stop, A, None)).unwrap();
        assign_now(p, vec![(A.into(), Ok("proj".into()))]);
        p.report(
            Some(310),
            report(Event::SessionStart(Source::Resume), A, None),
        )
        .unwrap();
        // The first terminal leaves: A is the second one's now.
        p.report(Some(300), report(Event::SessionEnd, A, None))
            .unwrap();
        assert_eq!(p.live("proj").unwrap().state, State::Waiting);
        assert_eq!(e.rows().await, [(A.to_string(), 110)]);
        e.published();
        // In the second process, `/clear` ends A (its SessionEnd lost) and starts B.
        let p = &e.presence;
        p.report(
            Some(310),
            report(Event::SessionStart(Source::Clear), B, None),
        )
        .unwrap();
        assert_eq!(e.published(), ["proj"]);
        assert_eq!(e.rows().await, [(B.to_string(), 110)]);
        assert_eq!(e.presence.live("proj"), None, "B is not assigned yet");
        assert_eq!(
            e.outcomes(),
            [
                "opened: waiting",
                "new process: waiting",
                "ignored (another process)",
                "closed: its process started another session",
                "opened: waiting",
            ]
        );
        let log = e.presence.events().events;
        assert_eq!(
            (log[3].event, log[3].session_id.as_deref()),
            (None, Some(A))
        );
        assert_eq!(log[4].session_id.as_deref(), Some(B));
        assert_eq!(e.presence.events().open, 1);
    }

    /// v0.2 review L8: the result of a resolution that started earlier never overwrites a later
    /// one's.
    #[tokio::test]
    async fn an_older_resolution_result_is_dropped() {
        let mut e = env();
        let p = &e.presence;
        p.report(Some(300), report(Event::Stop, A, None)).unwrap();
        let (older, _) = p.cwds();
        let (newer, _) = p.cwds();
        assert!(newer > older);
        p.assign(newer, vec![(A.into(), Ok("proj".into()))]);
        p.assign(older, vec![(A.into(), Err(store::NOT_REGISTERED))]);
        assert_eq!(p.live("proj").unwrap().state, State::Waiting);
        assert_eq!(p.status().counts.unassigned.len(), 0);
        assert_eq!(e.published(), ["proj"]);
        // Started later than both: applied.
        let p = &e.presence;
        let (latest, _) = p.cwds();
        p.assign(latest, vec![(A.into(), Err(store::NOT_REGISTERED))]);
        assert_eq!(p.live("proj"), None);
    }

    /// "Show live sessions first" (§21.8): the ranks follow the shown sessions' aggregate, the
    /// toggle turns them off, and a change republishes the projects with an open session.
    #[tokio::test]
    async fn live_ranks_follow_the_aggregate_and_the_toggle() {
        let mut e = env();
        let p = &e.presence;
        assert_eq!(p.live_ranks(), Some(Default::default()));
        p.report(Some(300), report(Event::UserPromptSubmit, A, None))
            .unwrap();
        assign_now(p, vec![(A.into(), Ok("proj".into()))]);
        assert_eq!(
            p.live_ranks().unwrap().into_iter().collect::<Vec<_>>(),
            [("proj".to_string(), State::Working)]
        );
        e.published();
        let p = &e.presence;
        p.set_live_first(false);
        assert_eq!(p.live_ranks(), None);
        assert_eq!(e.published(), ["proj"]);
        let p = &e.presence;
        p.set_live_first(false);
        assert!(e.published().is_empty(), "no change, nothing published");
        let p = &e.presence;
        p.set_live_first(true);
        assert_eq!(e.published(), ["proj"]);
        // A hidden non-interactive session (another process) gives no rank until it is shown.
        e.fake.process(110, UID, 50, 21, &["claude", "-p", "x"]);
        e.fake.process(210, UID, 110, 32, &["sh", "-c", "x"]);
        e.fake.process(310, UID, 210, 33, &["ccwm", "hook", "Stop"]);
        let p = &e.presence;
        p.report(
            Some(310),
            report(Event::SessionStart(Source::Startup), B, None),
        )
        .unwrap();
        assign_now(
            p,
            vec![
                (A.into(), Ok("proj".into())),
                (B.into(), Ok("other".into())),
            ],
        );
        assert_eq!(
            p.live_ranks().unwrap().into_keys().collect::<Vec<_>>(),
            ["proj"],
            "B is hidden"
        );
        p.set_show_noninteractive(true);
        assert_eq!(
            p.live_ranks().unwrap().into_iter().collect::<Vec<_>>(),
            [
                ("other".to_string(), State::Waiting),
                ("proj".to_string(), State::Working)
            ]
        );
    }

    #[tokio::test]
    async fn refusals_are_counted_logged_and_change_nothing() {
        let e = env();
        let p = &e.presence;
        assert_eq!(
            p.report(Some(300), report(Event::Stop, A, Some(200))),
            Err(Refusal::PidMismatch)
        );
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
        // The hook process left before its event was handled (v0.2 review L7).
        assert_eq!(
            p.report(Some(999), report(Event::Stop, A, None)),
            Err(Refusal::ClientGone)
        );
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
        assert_eq!(v.counters.received, 7);
        let r = &v.counters.refused;
        assert_eq!(
            (
                r.malformed,
                r.no_claude_ancestor,
                r.pid_mismatch,
                r.limit,
                r.client_gone
            ),
            (2, 3, 1, 0, 1)
        );
        assert_eq!(v.events[4].outcome, "refused: client_gone");
        assert_eq!(v.events[6].event, Some("Stop"));
        assert!(e.rows().await.is_empty());
    }

    #[tokio::test]
    async fn a_non_interactive_session_is_hidden_until_the_toggle_is_on() {
        let mut e = env();
        e.fake
            .process(100, UID, 50, 20, &["claude", "-p", "SYNTHETIC-ARGV-PROMPT"]);
        e.presence
            .report(Some(300), report(Event::UserPromptSubmit, A, None))
            .unwrap();
        assign_now(&e.presence, vec![(A.into(), Ok("proj".into()))]);
        let v = e.presence.events();
        assert_eq!((v.open, v.open_noninteractive), (1, 1));
        assert_eq!(e.outcomes(), ["opened: working (non-interactive)"]);
        assert_eq!(e.presence.live("proj"), None);
        assert!(e.presence.projects_matching(LiveFilter::Open).is_empty());
        assert_eq!(e.presence.status().counts.hidden_noninteractive, 1);
        e.published();
        e.presence.set_show_noninteractive(true);
        assert_eq!(e.published(), ["proj"], "republished");
        assert_eq!(e.presence.live("proj").unwrap().state, State::Working);
        assert_eq!(e.presence.projects_matching(LiveFilter::Working), ["proj"]);
        e.presence.set_show_noninteractive(true);
        assert!(e.published().is_empty(), "no change, nothing published");
        let shown = serde_json::to_string(&e.presence.events()).unwrap()
            + &serde_json::to_string(&e.presence.status()).unwrap()
            + &serde_json::to_string(&e.presence.live("proj")).unwrap();
        assert!(
            !shown.contains("SYNTHETIC"),
            "no argv, cwd or prompt in the views: {shown}"
        );
    }

    #[tokio::test]
    async fn recorded_facts_end_the_current_turn_and_are_logged() {
        let mut e = env();
        let with_prompt = |event, p: &str| {
            let mut r = report(event, A, None).unwrap();
            r.prompt_id = Some(p.into());
            Ok(r)
        };
        e.presence
            .report(Some(300), with_prompt(Event::UserPromptSubmit, P1))
            .unwrap();
        assign_now(&e.presence, vec![(A.into(), Ok("proj".into()))]);
        e.presence
            .report(
                Some(300),
                with_prompt(Event::Notification(Notice::PermissionPrompt), P1),
            )
            .unwrap();
        e.published();
        // "No" in the dialog: only the session file says so.
        let older = TurnFact {
            end: TurnEnd::Interrupted,
            prompt_id: Some("9a8b7c6d-5e4f-4a3b-8c2d-000000000009".into()),
            at_ms: 2_000_000,
        };
        let current = TurnFact {
            end: TurnEnd::Interrupted,
            prompt_id: Some(P1.into()),
            at_ms: 1_000_500,
        };
        e.presence
            .apply_facts(&[(A.into(), older), (B.into(), current.clone())]);
        assert_eq!(
            e.presence.live("proj").unwrap().state,
            State::NeedsApproval,
            "an older turn, a session not open"
        );
        e.presence.apply_facts(&[(A.into(), current.clone())]);
        assert_eq!(e.presence.live("proj").unwrap().state, State::Waiting);
        assert_eq!(e.published(), ["proj"]);
        e.presence.apply_facts(&[(A.into(), current)]);
        let out = e.outcomes();
        assert_eq!(
            &out[out.len() - 2..],
            [
                "interrupted (session file): an older turn, ignored",
                "interrupted (session file): → waiting"
            ],
            "nothing logged when nothing changes"
        );
        assert_eq!(e.presence.status().counters.session_file_facts, 1);
    }

    #[tokio::test]
    async fn the_sweep_closes_sessions_whose_process_is_gone() {
        let mut e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        e.fake.process(500, UID, 50, 50, &["claude"]);
        e.fake.process(510, UID, 500, 51, &["ccwm", "hook", "Stop"]);
        e.presence
            .report(Some(510), report(Event::Stop, B, None))
            .unwrap();
        assign_now(
            &e.presence,
            vec![
                (A.into(), Ok("p".into())),
                (B.into(), Err(store::NOT_REGISTERED)),
            ],
        );
        assert!(e.presence.sweep().is_empty(), "both alive");
        e.published();
        e.fake.remove(100);
        e.fake.process(500, UID, 50, 99, &["claude"]);
        let mut closed = e.presence.sweep();
        closed.sort();
        assert_eq!(closed, [A, B]);
        assert_eq!(e.presence.events().open, 0);
        assert_eq!(e.published(), ["p"]);
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
        e.fake.process(600, UID, 50, 60, &["claude", "--resume", A]);
        e.fake.process(610, UID, 600, 61, &["ccwm", "hook", "Stop"]);
        let r = e
            .presence
            .report(
                Some(610),
                report(Event::Notification(Notice::IdlePrompt), A, None),
            )
            .unwrap();
        assert!(r.resolve, "a new process: resolved again");
        assert_eq!(e.rows().await, [(A.to_string(), 600)]);
        assert!(e.presence.sweep().is_empty());
        assert_eq!(e.outcomes(), ["opened: waiting", "new process: waiting"]);
    }

    #[tokio::test]
    async fn a_restart_restores_live_sessions_as_unknown_and_drops_the_others() {
        let e = env();
        e.fake.process(500, UID, 50, 50, &["claude"]);
        e.fake.process(510, UID, 500, 51, &["ccwm", "hook", "Stop"]);
        e.presence
            .report(Some(300), report(Event::UserPromptSubmit, A, None))
            .unwrap();
        e.presence
            .report(Some(510), report(Event::Stop, B, None))
            .unwrap();
        e.writer.flush().await.unwrap();
        e.fake.process(100, UID, 50, 20, &["claude", "--print"]);
        e.fake.remove(500);
        let restarted = e.restarted();
        assert_eq!(restarted.restore(&e.reader).await.unwrap(), (1, 1));
        assign_now(&restarted, vec![(A.into(), Ok("proj".into()))]);
        restarted.set_show_noninteractive(true);
        assert_eq!(
            restarted.live("proj").unwrap().state,
            State::Unknown,
            "never guessed"
        );
        let v = restarted.events();
        assert_eq!(
            (v.open, v.open_noninteractive, v.counters.received),
            (1, 1, 0)
        );
        let mut outcomes: Vec<String> = v.events.iter().map(|l| l.outcome.clone()).collect();
        outcomes.sort();
        assert_eq!(
            outcomes,
            ["dropped at start: process gone", "restored: unknown"]
        );
        assert_eq!(e.rows().await, [(A.to_string(), 100)]);
        e.fake.set_boot_id("2d2c3b4a-0000-4000-8000-00000000b007");
        assert_eq!(e.restarted().restore(&e.reader).await.unwrap(), (0, 1));
        assert!(e.rows().await.is_empty());
        assert_eq!(BOOT.len(), 36);
    }

    #[tokio::test]
    async fn clear_session_index_empties_memory_and_database() {
        let mut e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        assign_now(&e.presence, vec![(A.into(), Ok("proj".into()))]);
        assert_eq!(e.rows().await.len(), 1);
        e.published();
        e.writer.clear_session_index().await.unwrap();
        e.presence.clear();
        assert!(e.rows().await.is_empty());
        assert_eq!(e.presence.events().open, 0);
        assert_eq!(e.published(), ["proj"]);
        assert_eq!(
            e.outcomes().last().unwrap(),
            "cleared: 1 open session(s) forgotten"
        );
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        assert_eq!(e.presence.events().open, 1);
    }

    #[tokio::test]
    async fn the_cwd_reaches_only_the_open_sessions_table() {
        let e = env();
        e.presence
            .report(Some(300), report(Event::Stop, A, None))
            .unwrap();
        let view = serde_json::to_string(&e.presence.events()).unwrap()
            + &serde_json::to_string(&e.presence.status()).unwrap();
        assert!(!view.contains("CANARY"), "{view}");
        e.writer.flush().await.unwrap();
        let cwd: String = rusqlite::Connection::open(&e.db)
            .unwrap()
            .query_row("SELECT first_cwd FROM open_sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cwd, "/home/u/dev/SYNTHETIC-CWD-CANARY");
    }

    #[tokio::test]
    async fn a_full_debug_log_fits_in_one_socket_response() {
        let e = env();
        for _ in 0..store::LOG_SIZE {
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
        }
        e.clock.advance(1_000_000_000);
        let v = e.presence.events();
        assert_eq!(v.events.len(), store::LOG_SIZE);
        let line = crate::ipc::protocol::encode_response(&Ok(serde_json::to_value(&v).unwrap()));
        assert!(
            line.len() < crate::client::MAX_RESPONSE_BYTES as usize * 3 / 4,
            "{} bytes",
            line.len()
        );
    }
}
