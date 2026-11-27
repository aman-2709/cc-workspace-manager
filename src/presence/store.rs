//! The open sessions of the activity indicator, without I/O (REQUIREMENTS.md §21.6, §21.7): which
//! session ids are open and in which process, what each accepted event did, the counters and the
//! debug log of recent events (`ccwm hooks events`).
//!
//! Stop 1 of v0.2 tracks *open* and *closed* only; the activity states (working, waiting, needs
//! approval, unknown) come with the state machine of stop 2.

use super::proc::{Found, Identity};
use crate::claude::hook::{Event, Report};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

/// At most this many sessions are tracked; an event that would open one more is refused.
pub const MAX_SESSIONS: usize = 256;
/// The debug log keeps this many entries (the newest).
pub const LOG_SIZE: usize = 256;

/// Why an event was refused (§21.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NoClaudeAncestor,
    PidMismatch,
    Limit,
}

impl Refusal {
    pub const ALL: [Self; 4] = [
        Self::Malformed,
        Self::NoClaudeAncestor,
        Self::PidMismatch,
        Self::Limit,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NoClaudeAncestor => "no_claude_ancestor",
            Self::PidMismatch => "pid_mismatch",
            Self::Limit => "limit",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// An open session.
#[derive(Clone, PartialEq, Eq)]
pub struct Open {
    pub identity: Identity,
    pub interactive: bool,
    /// The cwd of the session's first event (untrusted; never logged).
    pub first_cwd: String,
    pub opened_at: i64,
}

impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Open")
            .field("identity", &self.identity)
            .field("interactive", &self.interactive)
            .field(
                "first_cwd",
                &format_args!("<{} bytes>", self.first_cwd.len()),
            )
            .field("opened_at", &self.opened_at)
            .finish()
    }
}

/// What an accepted event did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A session id that was not tracked is open now.
    Opened,
    /// A tracked session is in another process now (`SessionStart` from a new process, or an
    /// event from a new process after the old one ended).
    NewProcess,
    /// Tracked already, nothing to change.
    Accepted,
    /// `SessionEnd`: the session is closed.
    Closed,
    /// `SessionEnd` for a session that was not open.
    Ignored,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::NewProcess => "new process",
            Self::Accepted => "accepted",
            Self::Closed => "closed",
            Self::Ignored => "ignored (not open)",
        }
    }
}

/// What the database must do after a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Persist {
    Put(String, Open),
    Delete(Vec<String>),
}

/// One line of the debug log: names, times and ids only — never a cwd, a pid or any text from a
/// session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// The hook event; `None` for what the daemon did on its own (a session whose process was
    /// gone, a restore at start, "Clear session index").
    pub event: Option<&'static str>,
    /// `SessionStart`'s source or `Notification`'s type.
    pub detail: Option<&'static str>,
    pub session_id: Option<String>,
    /// Whether `ccwm hook` sent `CLAUDE_PID` (`None` when unknown or not an event).
    pub claude_pid_sent: Option<bool>,
    pub outcome: String,
}

/// The counters of §21.10 that stop 1 keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub received: u64,
    pub refused: Refused,
    pub last_event_at: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Refused {
    pub malformed: u64,
    pub no_claude_ancestor: u64,
    pub pid_mismatch: u64,
    pub limit: u64,
}

impl Refused {
    fn bump(&mut self, r: Refusal) {
        let n = match r {
            Refusal::Malformed => &mut self.malformed,
            Refusal::NoClaudeAncestor => &mut self.no_claude_ancestor,
            Refusal::PidMismatch => &mut self.pid_mismatch,
            Refusal::Limit => &mut self.limit,
        };
        *n += 1;
    }

    pub fn get(&self, r: Refusal) -> u64 {
        [
            self.malformed,
            self.no_claude_ancestor,
            self.pid_mismatch,
            self.limit,
        ][r.index()]
    }
}

#[derive(Debug, Default)]
pub struct Store {
    sessions: HashMap<String, Open>,
    log: VecDeque<LogEntry>,
    seq: u64,
    counters: Counters,
}

impl Store {
    /// An event that passed validation and the process walk. `alive` says whether the process a
    /// tracked session is in still runs; it is asked only when another process reports for it.
    pub fn apply(
        &mut self,
        report: &Report,
        found: &Found,
        now: i64,
        alive: impl Fn(&Identity) -> bool,
    ) -> Result<(Outcome, Option<Persist>), Refusal> {
        let id = &report.session_id;
        if report.event == Event::SessionEnd {
            return Ok(match self.sessions.remove(id) {
                Some(_) => (Outcome::Closed, Some(Persist::Delete(vec![id.clone()]))),
                None => (Outcome::Ignored, None),
            });
        }
        if let Some(open) = self.sessions.get_mut(id) {
            if open.identity == found.identity {
                return Ok((Outcome::Accepted, None));
            }
            // Only SessionStart moves a session to another process while its process runs
            // (§21.6); once that process is gone, the reporting one is the session's.
            if !matches!(report.event, Event::SessionStart(_)) && alive(&open.identity) {
                return Ok((Outcome::Accepted, None));
            }
            open.identity = found.identity.clone();
            open.interactive = found.interactive;
            return Ok((
                Outcome::NewProcess,
                Some(Persist::Put(id.clone(), open.clone())),
            ));
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Refusal::Limit);
        }
        let open = Open {
            identity: found.identity.clone(),
            interactive: found.interactive,
            first_cwd: report.cwd.clone(),
            opened_at: now,
        };
        self.sessions.insert(id.clone(), open.clone());
        Ok((Outcome::Opened, Some(Persist::Put(id.clone(), open))))
    }

    /// Count a received event (accepted or not).
    pub fn received(&mut self, now: i64) {
        self.counters.received += 1;
        self.counters.last_event_at = Some(now);
    }

    pub fn refused(&mut self, r: Refusal) {
        self.counters.refused.bump(r);
    }

    /// The tracked sessions and their processes (for the liveness sweep).
    pub fn identities(&self) -> Vec<(String, Identity)> {
        self.sessions
            .iter()
            .map(|(id, o)| (id.clone(), o.identity.clone()))
            .collect()
    }

    /// Close `id` if it is still in the process `identity` (it may have moved since the sweep
    /// looked). Returns whether it was closed.
    pub fn close_if(&mut self, id: &str, identity: &Identity) -> bool {
        if self
            .sessions
            .get(id)
            .is_some_and(|o| &o.identity == identity)
        {
            self.sessions.remove(id);
            return true;
        }
        false
    }

    /// Put back a persisted session at start (§21.7). Refused beyond the limit.
    pub fn restore(&mut self, id: String, open: Open) -> bool {
        if self.sessions.len() >= MAX_SESSIONS || self.sessions.contains_key(&id) {
            return false;
        }
        self.sessions.insert(id, open);
        true
    }

    /// "Clear session index" (§21.7, O16): no session is tracked any more.
    pub fn clear(&mut self) -> usize {
        let n = self.sessions.len();
        self.sessions.clear();
        n
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Open sessions, and how many of them are non-interactive.
    pub fn open_counts(&self) -> (usize, usize) {
        let hidden = self.sessions.values().filter(|o| !o.interactive).count();
        (self.sessions.len(), hidden)
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Append a debug-log entry (the oldest goes beyond [`LOG_SIZE`]).
    pub fn log(
        &mut self,
        at_ms: i64,
        event: Option<Event>,
        event_name: Option<&'static str>,
        session_id: Option<String>,
        claude_pid_sent: Option<bool>,
        outcome: String,
    ) {
        self.seq += 1;
        if self.log.len() == LOG_SIZE {
            self.log.pop_front();
        }
        self.log.push_back(LogEntry {
            seq: self.seq,
            at_ms,
            event: event.map(Event::name).or(event_name),
            detail: event.and_then(Event::detail),
            session_id,
            claude_pid_sent,
            outcome,
        });
    }

    pub fn log_entries(&self) -> Vec<LogEntry> {
        self.log.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude::hook::{Notice, Source};

    const A: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const B: &str = "1b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";

    fn report(event: Event, sid: &str) -> Report {
        Report {
            event,
            session_id: sid.into(),
            cwd: "/home/u/dev/p".into(),
            prompt_id: None,
            claude_pid: None,
        }
    }

    fn found(pid: u32, start: u64) -> Found {
        Found {
            identity: Identity {
                pid,
                start,
                boot_id: "b".into(),
            },
            interactive: true,
        }
    }

    const ALIVE: fn(&Identity) -> bool = |_| true;
    const GONE: fn(&Identity) -> bool = |_| false;

    #[test]
    fn any_event_opens_an_untracked_session_except_session_end() {
        for event in [
            Event::SessionStart(Source::Startup),
            Event::SessionStart(Source::Compact),
            Event::UserPromptSubmit,
            Event::Notification(Notice::PermissionPrompt),
            Event::Notification(Notice::IdlePrompt),
            Event::PostToolUse,
            Event::PostToolUseFailure,
            Event::PostToolBatch,
            Event::Stop,
            Event::StopFailure,
        ] {
            let mut s = Store::default();
            let (outcome, persist) = s.apply(&report(event, A), &found(10, 1), 5, ALIVE).unwrap();
            assert_eq!(outcome, Outcome::Opened, "{event:?}");
            let Some(Persist::Put(id, open)) = persist else {
                panic!("{event:?} persists the session")
            };
            assert_eq!(
                (id.as_str(), open.opened_at, open.first_cwd.as_str()),
                (A, 5, "/home/u/dev/p")
            );
            assert_eq!(s.open_counts(), (1, 0));
        }
        let mut s = Store::default();
        assert_eq!(
            s.apply(&report(Event::SessionEnd, A), &found(10, 1), 5, ALIVE)
                .unwrap(),
            (Outcome::Ignored, None)
        );
        assert!(s.is_empty());
    }

    #[test]
    fn session_end_closes_and_later_events_change_nothing_else() {
        let mut s = Store::default();
        s.apply(
            &report(Event::SessionStart(Source::Startup), A),
            &found(10, 1),
            5,
            ALIVE,
        )
        .unwrap();
        // Later events from the same process: accepted, nothing persisted, the first cwd kept.
        let mut later = report(Event::Stop, A);
        later.cwd = "/elsewhere".into();
        assert_eq!(
            s.apply(&later, &found(10, 1), 6, ALIVE).unwrap(),
            (Outcome::Accepted, None)
        );
        assert_eq!(
            s.apply(&report(Event::SessionEnd, A), &found(10, 1), 7, ALIVE)
                .unwrap(),
            (Outcome::Closed, Some(Persist::Delete(vec![A.into()])))
        );
        assert!(s.is_empty());
    }

    #[test]
    fn session_start_moves_a_session_to_its_new_process() {
        let mut s = Store::default();
        s.apply(&report(Event::Stop, A), &found(10, 1), 5, ALIVE)
            .unwrap();
        // Another live process reports for it without SessionStart: the session stays put.
        assert_eq!(
            s.apply(&report(Event::UserPromptSubmit, A), &found(20, 2), 6, ALIVE)
                .unwrap(),
            (Outcome::Accepted, None)
        );
        assert_eq!(s.identities()[0].1.pid, 10);
        // SessionStart (resume, a respawn) takes the new identity, the first cwd stays.
        let mut resumed = report(Event::SessionStart(Source::Resume), A);
        resumed.cwd = "/other".into();
        let mut f = found(20, 2);
        f.interactive = false;
        let (outcome, persist) = s.apply(&resumed, &f, 7, ALIVE).unwrap();
        assert_eq!(outcome, Outcome::NewProcess);
        let Some(Persist::Put(_, open)) = persist else {
            panic!()
        };
        assert_eq!(
            (
                open.identity.pid,
                open.interactive,
                open.first_cwd.as_str(),
                open.opened_at
            ),
            (20, false, "/home/u/dev/p", 5)
        );
        assert_eq!(s.open_counts(), (1, 1));
        // Once the session's process is gone, any event from the new one moves it.
        let (outcome, _) = s
            .apply(&report(Event::Stop, A), &found(30, 3), 8, GONE)
            .unwrap();
        assert_eq!(outcome, Outcome::NewProcess);
        assert_eq!(s.identities()[0].1.pid, 30);
    }

    #[test]
    fn one_process_may_hold_several_sessions_each_on_its_own() {
        let mut s = Store::default();
        s.apply(
            &report(Event::SessionStart(Source::Startup), A),
            &found(10, 1),
            5,
            ALIVE,
        )
        .unwrap();
        // `/clear` in the same process: SessionEnd(A), SessionStart(B).
        s.apply(&report(Event::SessionEnd, A), &found(10, 1), 6, ALIVE)
            .unwrap();
        s.apply(
            &report(Event::SessionStart(Source::Clear), B),
            &found(10, 1),
            6,
            ALIVE,
        )
        .unwrap();
        s.apply(
            &report(Event::SessionStart(Source::Startup), A),
            &found(10, 1),
            7,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.open_counts(), (2, 0));
        let id = found(10, 1).identity;
        assert!(s.close_if(A, &id));
        assert!(!s.close_if(A, &id), "already closed");
        assert!(
            !s.close_if(B, &found(10, 2).identity),
            "another process now"
        );
        assert_eq!(s.open_counts(), (1, 0));
    }

    #[test]
    fn the_limit_refuses_new_sessions_but_not_tracked_ones() {
        let mut s = Store::default();
        let sid = |i: usize| format!("{i:08x}-3d2a-4c5b-9e8f-1a2b3c4d5e6f");
        for i in 0..MAX_SESSIONS {
            s.apply(&report(Event::Stop, &sid(i)), &found(10, 1), 5, ALIVE)
                .unwrap();
        }
        assert_eq!(
            s.apply(
                &report(Event::Stop, &sid(MAX_SESSIONS)),
                &found(10, 1),
                5,
                ALIVE
            ),
            Err(Refusal::Limit)
        );
        assert_eq!(
            s.apply(&report(Event::Stop, &sid(0)), &found(10, 1), 5, ALIVE)
                .unwrap()
                .0,
            Outcome::Accepted
        );
        s.apply(&report(Event::SessionEnd, &sid(0)), &found(10, 1), 5, ALIVE)
            .unwrap();
        assert_eq!(
            s.apply(
                &report(Event::Stop, &sid(MAX_SESSIONS)),
                &found(10, 1),
                5,
                ALIVE
            )
            .unwrap()
            .0,
            Outcome::Opened
        );
        assert!(
            !s.restore(sid(999), s.sessions.values().next().unwrap().clone()),
            "full"
        );
        assert_eq!(s.clear(), MAX_SESSIONS);
        assert!(s.is_empty());
    }

    #[test]
    fn counters_and_the_log_keep_the_newest_entries() {
        let mut s = Store::default();
        s.received(10);
        s.received(12);
        s.refused(Refusal::PidMismatch);
        s.refused(Refusal::Malformed);
        s.refused(Refusal::Malformed);
        let c = s.counters();
        assert_eq!((c.received, c.last_event_at), (2, Some(12)));
        assert_eq!(Refusal::ALL.map(|r| c.refused.get(r)), [2, 0, 1, 0]);
        for i in 0..(LOG_SIZE + 3) {
            s.log(
                i as i64,
                Some(Event::Notification(Notice::IdlePrompt)),
                None,
                Some(A.into()),
                Some(true),
                "accepted".into(),
            );
        }
        s.log(1, None, None, None, None, "closed: process gone".into());
        let log = s.log_entries();
        assert_eq!(log.len(), LOG_SIZE);
        assert_eq!(log[0].seq, 5, "the oldest four dropped");
        assert_eq!(log.last().unwrap().seq, LOG_SIZE as u64 + 4);
        assert_eq!(
            (log[0].event, log[0].detail),
            (Some("Notification"), Some("idle_prompt"))
        );
        assert_eq!(log.last().unwrap().event, None);
        // A malformed request keeps only a known event name.
        s.log(
            2,
            None,
            Some("Stop"),
            None,
            None,
            "refused: malformed".into(),
        );
        assert_eq!(s.log_entries().last().unwrap().event, Some("Stop"));
    }

    #[test]
    fn debug_output_never_shows_the_cwd() {
        let open = Open {
            identity: found(10, 1).identity,
            interactive: true,
            first_cwd: "/home/u/SECRET-PROJECT".into(),
            opened_at: 1,
        };
        let shown = format!("{open:?} {:?}", Persist::Put(A.into(), open.clone()));
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("<22 bytes>"), "{shown}");
    }
}
