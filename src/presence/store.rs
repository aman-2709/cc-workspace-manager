//! The open sessions of the activity indicator, without I/O (REQUIREMENTS.md §21.2a, §21.6,
//! §21.7): which session ids are open, in which process, in which state and for which project;
//! the state machine over hook events and the facts recorded in session files; the per-project
//! aggregate and the three filters; the counters and the debug log of recent events
//! (`ccwm hooks events`).

use super::proc::{Found, Identity};
use crate::claude::hook::{Event, Notice, Report, Source};
use crate::claude::parse::{TurnEnd, TurnFact};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};

/// At most this many sessions are tracked; an event that would open one more is refused.
pub const MAX_SESSIONS: usize = 256;
/// The debug log keeps this many entries (the newest).
pub const LOG_SIZE: usize = 256;
/// The unassigned reason of a session whose project root is not registered (yet): the session
/// file registers it (§4.3); hook events never do.
pub const NOT_REGISTERED: &str = "not_registered";

/// Why an event was refused (§21.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NoClaudeAncestor,
    PidMismatch,
    Limit,
    /// The `ccwm hook` process that connected was gone (or its pid reused) when the daemon
    /// handled its event (v0.2 review L7): nothing can be said about its ancestry.
    ClientGone,
}

impl Refusal {
    pub const ALL: [Self; 5] = [
        Self::Malformed,
        Self::NoClaudeAncestor,
        Self::PidMismatch,
        Self::Limit,
        Self::ClientGone,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NoClaudeAncestor => "no_claude_ancestor",
            Self::PidMismatch => "pid_mismatch",
            Self::Limit => "limit",
            Self::ClientGone => "client_gone",
        }
    }
}

/// An open session's activity (§21.6), in the order of the project aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    NeedsApproval,
    Working,
    Waiting,
    Unknown,
}

impl State {
    pub const ALL: [Self; 4] = [
        Self::NeedsApproval,
        Self::Working,
        Self::Waiting,
        Self::Unknown,
    ];

    /// The project's place when live sessions come first (§21.8): 0 leads.
    pub fn rank(self) -> i64 {
        match self {
            Self::NeedsApproval => 0,
            Self::Working => 1,
            Self::Waiting => 2,
            Self::Unknown => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeedsApproval => "needs_approval",
            Self::Working => "working",
            Self::Waiting => "waiting",
            Self::Unknown => "unknown",
        }
    }
}

/// The state an event leads to from `current` (`None`: not tracked), ignoring staleness
/// (ARCHITECTURE.md §15, the state machine). `SessionEnd` is handled by the caller.
pub fn next_state(current: Option<State>, event: Event) -> State {
    match event {
        Event::SessionStart(Source::Compact) => current.unwrap_or(State::Unknown),
        Event::SessionStart(_) => State::Waiting,
        Event::UserPromptSubmit => State::Working,
        Event::Notification(Notice::PermissionPrompt) => State::NeedsApproval,
        Event::Notification(Notice::IdlePrompt) | Event::Stop | Event::StopFailure => {
            State::Waiting
        }
        // A turn that ended stays ended until the next prompt *(choice, for review)*.
        Event::PostToolUse | Event::PostToolUseFailure | Event::PostToolBatch => match current {
            Some(State::Waiting) => State::Waiting,
            _ => State::Working,
        },
        Event::SessionEnd => current.unwrap_or(State::Unknown),
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
    pub state: State,
    /// When `state` was entered: whole seconds (shown) and milliseconds (orders the recorded
    /// facts, §21.2a).
    pub since: i64,
    pub since_ms: i64,
    /// The current turn's prompt id (`UserPromptSubmit`), when known.
    pub prompt_id: Option<String>,
    /// The registered project the first cwd names, or why there is none (`unassigned`); both
    /// `None` until it was resolved.
    pub project: Option<String>,
    pub unassigned: Option<&'static str>,
}

impl Open {
    /// An open session in `state` since `now_ms`.
    pub fn new(
        identity: Identity,
        interactive: bool,
        first_cwd: String,
        now_ms: i64,
        state: State,
    ) -> Self {
        Self {
            identity,
            interactive,
            first_cwd,
            opened_at: now_ms.div_euclid(1000),
            state,
            since: now_ms.div_euclid(1000),
            since_ms: now_ms,
            prompt_id: None,
            project: None,
            unassigned: None,
        }
    }

    fn enter(&mut self, state: State, now_ms: i64) -> bool {
        if self.state == state {
            return false;
        }
        self.state = state;
        self.since = now_ms.div_euclid(1000);
        self.since_ms = now_ms;
        true
    }
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
            .field("state", &self.state)
            .field("since", &self.since)
            .field("prompt_id", &self.prompt_id)
            .field("project", &self.project)
            .field("unassigned", &self.unassigned)
            .finish()
    }
}

/// What an accepted event did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A session id that was not tracked is open now, in this state.
    Opened(State),
    /// A tracked session is in another process now (`SessionStart` from a new process, or an
    /// event from a new process after the old one ended).
    NewProcess(State),
    /// The session's state changed.
    Changed(State),
    /// Nothing changed (the session stays in this state).
    Unchanged(State),
    /// The event belongs to an older prompt than the session's current one: ignored, counted.
    Stale,
    /// `SessionEnd`: the session is closed.
    Closed,
    /// `SessionEnd` for a session that was not open.
    Ignored,
    /// `SessionEnd` from a process that does not hold the session while the one that does still
    /// runs (the same session resumed in a second terminal; v0.2 review L1): ignored.
    OtherProcess,
}

impl Outcome {
    pub fn text(self) -> String {
        match self {
            Self::Opened(s) => format!("opened: {}", s.as_str()),
            Self::NewProcess(s) => format!("new process: {}", s.as_str()),
            Self::Changed(s) => format!("→ {}", s.as_str()),
            Self::Unchanged(s) => format!("unchanged: {}", s.as_str()),
            Self::Stale => "stale (an older prompt)".into(),
            Self::Closed => "closed".into(),
            Self::Ignored => "ignored (not open)".into(),
            Self::OtherProcess => "ignored (another process)".into(),
        }
    }
}

/// What a recorded fact did (§21.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactOutcome {
    /// The session was in `working`, `needs_approval` or `unknown`: it waits now.
    Applied,
    /// The fact belongs to an older turn (another prompt id, or older than the state).
    OlderTurn,
    /// The session waits already, or is not open: nothing to do.
    Nothing,
}

/// What the database must do after a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Persist {
    Put(String, Open),
    Delete(Vec<String>),
}

/// An applied event: its outcome, the persistence it needs, the projects whose aggregate may
/// have changed (to publish), and the sessions it closed because their process started this one
/// (`SessionStart`: one process holds one session; v0.2 review L2). Their projects are in
/// `projects`; their rows are still to be deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub outcome: Outcome,
    pub persist: Option<Persist>,
    pub projects: Vec<String>,
    pub replaced: Vec<String>,
}

/// One line of the debug log: names, times and ids only — never a cwd, a pid or any text from a
/// session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// The hook event; `None` for what the daemon did on its own (a session whose process was
    /// gone, a restore at start, a fact from a session file, "Clear session index").
    pub event: Option<&'static str>,
    /// `SessionStart`'s source or `Notification`'s type.
    pub detail: Option<&'static str>,
    pub session_id: Option<String>,
    /// Whether `ccwm hook` sent `CLAUDE_PID` (`None` when unknown or not an event).
    pub claude_pid_sent: Option<bool>,
    pub outcome: String,
}

/// The counters of §21.10.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub received: u64,
    /// Events of an older prompt than their session's current one.
    pub stale: u64,
    /// Recorded facts from session files that ended a turn (§21.2a).
    pub session_file_facts: u64,
    pub refused: Refused,
    pub last_event_at: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Refused {
    pub malformed: u64,
    pub no_claude_ancestor: u64,
    pub pid_mismatch: u64,
    pub limit: u64,
    pub client_gone: u64,
}

impl Refused {
    fn slot(&mut self, r: Refusal) -> &mut u64 {
        match r {
            Refusal::Malformed => &mut self.malformed,
            Refusal::NoClaudeAncestor => &mut self.no_claude_ancestor,
            Refusal::PidMismatch => &mut self.pid_mismatch,
            Refusal::Limit => &mut self.limit,
            Refusal::ClientGone => &mut self.client_gone,
        }
    }
}

/// A project's open sessions as cards and rows show them (REQUIREMENTS.md §21.8): no path, pid,
/// id or text — states, counts and times only, so privacy mode shows it unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveView {
    /// `needs_approval` if any session needs it, else `working`, else `waiting`, else `unknown`.
    pub state: State,
    pub sessions: u32,
    pub needs_approval: u32,
    pub working: u32,
    pub waiting: u32,
    pub unknown: u32,
    /// When the one session entered its state (only with one session).
    pub since: Option<i64>,
    /// The earliest `permission_prompt` of the sessions that need approval ("· N min").
    pub needs_approval_since: Option<i64>,
}

/// One session's state for the detail panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionLive {
    pub state: State,
    pub since: i64,
}

/// The toolbar filters (§21.8): "Waiting for me" (waiting or needs approval), "Working",
/// "Open" (any state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveFilter {
    WaitingForMe,
    Working,
    Open,
}

impl LiveFilter {
    pub const ALL: [Self; 3] = [Self::WaitingForMe, Self::Working, Self::Open];

    /// The `live` query value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "waiting" => Some(Self::WaitingForMe),
            "working" => Some(Self::Working),
            "open" => Some(Self::Open),
            _ => None,
        }
    }

    pub fn matches(self, state: State) -> bool {
        match self {
            Self::WaitingForMe => matches!(state, State::Waiting | State::NeedsApproval),
            Self::Working => state == State::Working,
            Self::Open => true,
        }
    }
}

/// Open sessions by state for `ccwm status` (shown ones only), the hidden non-interactive ones,
/// and the unassigned ones by reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OpenCounts {
    pub open: u32,
    pub needs_approval: u32,
    pub working: u32,
    pub waiting: u32,
    pub unknown: u32,
    pub hidden_noninteractive: u32,
    pub unassigned: BTreeMap<&'static str, u32>,
}

#[derive(Debug, Default)]
pub struct Store {
    sessions: HashMap<String, Open>,
    log: VecDeque<LogEntry>,
    seq: u64,
    counters: Counters,
    /// The sequence number of the last project resolution started ([`Self::cwds`]) and of the
    /// newest one applied ([`Self::assign`]): an older result never overwrites a newer one
    /// (v0.2 review L8).
    resolutions_started: u64,
    resolution_applied: u64,
}

impl Store {
    /// An event that passed validation and the process walk, at `now_ms`. `alive` says whether
    /// the process a tracked session is in still runs; it is asked only when another process
    /// reports for it.
    ///
    /// A `SessionStart` first closes every other session its process holds: a process holds one
    /// session at a time (`/clear` and `/resume` end one and start the next in the same process),
    /// so they are what a lost `SessionEnd` left behind (v0.2 review L2).
    pub fn apply(
        &mut self,
        report: &Report,
        found: &Found,
        now_ms: i64,
        alive: impl Fn(&Identity) -> bool,
    ) -> Result<Applied, Refusal> {
        let replaced: Vec<String> = if matches!(report.event, Event::SessionStart(_)) {
            let mut ids: Vec<String> = self
                .sessions
                .iter()
                .filter(|(sid, o)| **sid != report.session_id && o.identity == found.identity)
                .map(|(sid, _)| sid.clone())
                .collect();
            ids.sort();
            ids
        } else {
            Vec::new()
        };
        let mut projects: Vec<String> = replaced
            .iter()
            .filter_map(|sid| self.sessions.remove(sid)?.project)
            .collect();
        // With a session closed above there is room for this one: the limit cannot refuse it.
        let mut applied = self.apply_event(report, found, now_ms, alive)?;
        projects.append(&mut applied.projects);
        projects.sort();
        projects.dedup();
        applied.projects = projects;
        applied.replaced = replaced;
        Ok(applied)
    }

    fn apply_event(
        &mut self,
        report: &Report,
        found: &Found,
        now_ms: i64,
        alive: impl Fn(&Identity) -> bool,
    ) -> Result<Applied, Refusal> {
        let id = &report.session_id;
        let applied = |outcome, persist, project: Option<&String>| Applied {
            outcome,
            persist,
            projects: project.into_iter().cloned().collect(),
            replaced: Vec::new(),
        };
        if report.event == Event::SessionEnd {
            // Only the session's own process ends it — or, once that one is gone, the process
            // that reports for it (the rule `moved` follows below). A second terminal that
            // resumed the same session and then left must not close it for the first (L1).
            let owner = self
                .sessions
                .get(id)
                .map(|o| o.identity == found.identity || !alive(&o.identity));
            return Ok(match owner {
                None => applied(Outcome::Ignored, None, None),
                Some(false) => applied(Outcome::OtherProcess, None, None),
                Some(true) => {
                    let project = self.sessions.remove(id).and_then(|o| o.project);
                    applied(
                        Outcome::Closed,
                        Some(Persist::Delete(vec![id.clone()])),
                        project.as_ref(),
                    )
                }
            });
        }
        let Some(open) = self.sessions.get_mut(id) else {
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(Refusal::Limit);
            }
            let state = next_state(None, report.event);
            let mut open = Open::new(
                found.identity.clone(),
                found.interactive,
                report.cwd.clone(),
                now_ms,
                state,
            );
            if !matches!(report.event, Event::SessionStart(_)) {
                open.prompt_id.clone_from(&report.prompt_id); // hooks added during a turn
            }
            self.sessions.insert(id.clone(), open.clone());
            return Ok(applied(
                Outcome::Opened(state),
                Some(Persist::Put(id.clone(), open)),
                None,
            ));
        };
        // Only SessionStart moves a session to another process while its process runs
        // (§21.6); once that process is gone, the reporting one is the session's.
        let mut persist = None;
        let moved = open.identity != found.identity
            && (matches!(report.event, Event::SessionStart(_)) || !alive(&open.identity));
        if moved {
            open.identity = found.identity.clone();
            open.interactive = found.interactive;
            persist = Some(Persist::Put(id.clone(), open.clone()));
        }
        let exempt = matches!(
            report.event,
            Event::SessionStart(_) | Event::UserPromptSubmit
        );
        let stale =
            !exempt && matches!((&report.prompt_id, &open.prompt_id), (Some(p), Some(c)) if p != c);
        if stale {
            self.counters.stale += 1;
            let outcome = if moved {
                Outcome::NewProcess(open.state)
            } else {
                Outcome::Stale
            };
            return Ok(applied(outcome, persist, None));
        }
        match report.event {
            Event::UserPromptSubmit => open.prompt_id.clone_from(&report.prompt_id),
            Event::SessionStart(Source::Compact) => {}
            Event::SessionStart(_) => open.prompt_id = None,
            // Not known (restored, hooks added during a turn): the event tells the turn.
            _ if open.prompt_id.is_none() => open.prompt_id.clone_from(&report.prompt_id),
            _ => {}
        }
        let changed = open.enter(next_state(Some(open.state), report.event), now_ms);
        let state = open.state;
        let outcome = match (moved, changed) {
            (true, _) => Outcome::NewProcess(state),
            (false, true) => Outcome::Changed(state),
            (false, false) => Outcome::Unchanged(state),
        };
        let projects = if changed || moved {
            open.project.iter().cloned().collect()
        } else {
            Vec::new()
        };
        Ok(Applied {
            outcome,
            persist,
            projects,
            replaced: Vec::new(),
        })
    }

    /// A recorded end of a turn from session `id`'s file (§21.2a): `working`, `needs_approval`
    /// or `unknown` → `waiting`, for the current turn only — the fact's prompt id equals the
    /// session's current one, or (without either) the record is not older than the state.
    /// Returns what it did and the session's project when the state changed.
    pub fn apply_fact(
        &mut self,
        id: &str,
        fact: &TurnFact,
        now_ms: i64,
    ) -> (FactOutcome, Option<String>) {
        let Some(open) = self.sessions.get_mut(id) else {
            return (FactOutcome::Nothing, None);
        };
        if open.state == State::Waiting {
            return (FactOutcome::Nothing, None);
        }
        let current_turn = match (&fact.prompt_id, &open.prompt_id) {
            (Some(p), Some(c)) => p == c,
            _ => fact.at_ms >= open.since_ms,
        };
        if !current_turn {
            return (FactOutcome::OlderTurn, None);
        }
        open.enter(State::Waiting, now_ms);
        self.counters.session_file_facts += 1;
        (FactOutcome::Applied, open.project.clone())
    }

    /// Count a received event (accepted or not).
    pub fn received(&mut self, now: i64) {
        self.counters.received += 1;
        self.counters.last_event_at = Some(now);
    }

    pub fn refused(&mut self, r: Refusal) {
        *self.counters.refused.slot(r) += 1;
    }

    /// The tracked sessions and their processes (for the liveness sweep).
    pub fn identities(&self) -> Vec<(String, Identity)> {
        self.sessions
            .iter()
            .map(|(id, o)| (id.clone(), o.identity.clone()))
            .collect()
    }

    /// Close `id` if it is still in the process `identity` (it may have moved since the sweep
    /// looked). Returns whether it was closed, and its project.
    pub fn close_if(&mut self, id: &str, identity: &Identity) -> Option<Option<String>> {
        if self
            .sessions
            .get(id)
            .is_some_and(|o| &o.identity == identity)
        {
            return self.sessions.remove(id).map(|o| o.project);
        }
        None
    }

    /// Put back a persisted session at start (§21.7), in the state `unknown` since `now_ms`.
    /// Refused beyond the limit.
    pub fn restore(&mut self, id: String, mut open: Open, now_ms: i64) -> bool {
        if self.sessions.len() >= MAX_SESSIONS || self.sessions.contains_key(&id) {
            return false;
        }
        open.state = State::Unknown;
        open.since = now_ms.div_euclid(1000);
        open.since_ms = now_ms;
        open.prompt_id = None;
        self.sessions.insert(id, open);
        true
    }

    /// "Clear session index" (§21.7, O16): no session is tracked any more. Returns how many
    /// were, and the projects they were in.
    pub fn clear(&mut self) -> (usize, Vec<String>) {
        let n = self.sessions.len();
        let projects = self
            .sessions
            .drain()
            .filter_map(|(_, o)| o.project)
            .collect();
        (n, projects)
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Start a project resolution: its sequence number, and the sessions to resolve (id and
    /// first cwd).
    pub fn cwds(&mut self) -> (u64, Vec<(String, String)>) {
        self.resolutions_started += 1;
        let cwds = self
            .sessions
            .iter()
            .map(|(id, o)| (id.clone(), o.first_cwd.clone()))
            .collect();
        (self.resolutions_started, cwds)
    }

    /// The result of resolution `seq`: set each listed session's project (`Ok`) or unassigned
    /// reason (`Err`). A resolution older than one already applied changes nothing — it may
    /// have looked at the projects before one was registered (v0.2 review L8). Returns the
    /// projects whose aggregate changed (a session joined or left them).
    pub fn assign(
        &mut self,
        seq: u64,
        results: Vec<(String, Result<String, &'static str>)>,
    ) -> Vec<String> {
        if seq < self.resolution_applied {
            return Vec::new();
        }
        self.resolution_applied = seq;
        let mut changed = Vec::new();
        for (id, r) in results {
            let Some(open) = self.sessions.get_mut(&id) else {
                continue; // closed meanwhile
            };
            let (project, unassigned) = match r {
                Ok(p) => (Some(p), None),
                Err(reason) => (None, Some(reason)),
            };
            if open.project != project {
                changed.extend(open.project.take());
                changed.extend(project.clone());
                open.project = project;
            }
            open.unassigned = unassigned;
        }
        changed.sort();
        changed.dedup();
        changed
    }

    fn shown(o: &Open, show_noninteractive: bool) -> bool {
        o.interactive || show_noninteractive
    }

    /// The aggregate of `project`'s shown sessions (§21.8), or `None` without any.
    pub fn live(&self, project: &str, show_noninteractive: bool) -> Option<LiveView> {
        let mut v = LiveView {
            state: State::Unknown,
            sessions: 0,
            needs_approval: 0,
            working: 0,
            waiting: 0,
            unknown: 0,
            since: None,
            needs_approval_since: None,
        };
        let mut only_since = None;
        for o in self.sessions.values().filter(|o| {
            o.project.as_deref() == Some(project) && Self::shown(o, show_noninteractive)
        }) {
            v.sessions += 1;
            v.state = v.state.min(o.state);
            only_since = Some(o.since);
            match o.state {
                State::NeedsApproval => {
                    v.needs_approval += 1;
                    v.needs_approval_since = Some(
                        v.needs_approval_since
                            .map_or(o.since, |s: i64| s.min(o.since)),
                    );
                }
                State::Working => v.working += 1,
                State::Waiting => v.waiting += 1,
                State::Unknown => v.unknown += 1,
            }
        }
        if v.sessions == 0 {
            return None;
        }
        v.since = if v.sessions == 1 { only_since } else { None };
        Some(v)
    }

    /// One session's state (the detail panel), unless hidden.
    pub fn session_live(&self, id: &str, show_noninteractive: bool) -> Option<SessionLive> {
        self.sessions
            .get(id)
            .filter(|o| Self::shown(o, show_noninteractive))
            .map(|o| SessionLive {
                state: o.state,
                since: o.since,
            })
    }

    /// The projects with at least one shown session that `filter` matches, sorted.
    pub fn projects_matching(&self, filter: LiveFilter, show_noninteractive: bool) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .values()
            .filter(|o| Self::shown(o, show_noninteractive) && filter.matches(o.state))
            .filter_map(|o| o.project.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Each project with a shown session, and its aggregate state (the order of [`Self::live`]).
    pub fn live_ranks(&self, show_noninteractive: bool) -> BTreeMap<String, State> {
        let mut out: BTreeMap<String, State> = BTreeMap::new();
        for o in self
            .sessions
            .values()
            .filter(|o| Self::shown(o, show_noninteractive))
        {
            if let Some(p) = &o.project {
                out.entry(p.clone())
                    .and_modify(|s| *s = (*s).min(o.state))
                    .or_insert(o.state);
            }
        }
        out
    }

    /// The projects of the non-interactive sessions (republished when the toggle changes).
    pub fn noninteractive_projects(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .values()
            .filter(|o| !o.interactive)
            .filter_map(|o| o.project.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn open_counts(&self, show_noninteractive: bool) -> OpenCounts {
        let mut c = OpenCounts::default();
        for o in self.sessions.values() {
            if !Self::shown(o, show_noninteractive) {
                c.hidden_noninteractive += 1;
                continue;
            }
            c.open += 1;
            *match o.state {
                State::NeedsApproval => &mut c.needs_approval,
                State::Working => &mut c.working,
                State::Waiting => &mut c.waiting,
                State::Unknown => &mut c.unknown,
            } += 1;
            if let Some(reason) = o.unassigned {
                *c.unassigned.entry(reason).or_default() += 1;
            }
        }
        c
    }

    /// All tracked sessions, and how many of them are non-interactive (whatever the toggle).
    pub fn totals(&self) -> (usize, usize) {
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

/// The debug-log text of a fact's outcome.
pub fn fact_text(fact: &TurnFact, outcome: FactOutcome) -> String {
    let what = match fact.end {
        TurnEnd::Interrupted => "interrupted (session file)",
        TurnEnd::Ended => "turn ended (session file)",
    };
    match outcome {
        FactOutcome::Applied => format!("{what}: → waiting"),
        FactOutcome::OlderTurn => format!("{what}: an older turn, ignored"),
        FactOutcome::Nothing => format!("{what}: nothing to change"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const B: &str = "1b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const P1: &str = "9a8b7c6d-5e4f-4a3b-8c2d-000000000001";
    const P2: &str = "9a8b7c6d-5e4f-4a3b-8c2d-000000000002";

    fn report(event: Event, sid: &str) -> Report {
        Report {
            event,
            session_id: sid.into(),
            cwd: "/home/u/dev/p".into(),
            prompt_id: None,
            claude_pid: None,
        }
    }

    fn with_prompt(event: Event, sid: &str, p: &str) -> Report {
        Report {
            prompt_id: Some(p.into()),
            ..report(event, sid)
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

    /// Apply a resolution started now (the latest, so it is never dropped as older).
    fn assign(s: &mut Store, results: Vec<(String, Result<String, &'static str>)>) -> Vec<String> {
        let (seq, _) = s.cwds();
        s.assign(seq, results)
    }

    const ALIVE: fn(&Identity) -> bool = |_| true;
    const GONE: fn(&Identity) -> bool = |_| false;

    const ALL_EVENTS: [Event; 11] = [
        Event::SessionStart(Source::Startup),
        Event::SessionStart(Source::Resume),
        Event::SessionStart(Source::Compact),
        Event::UserPromptSubmit,
        Event::Notification(Notice::PermissionPrompt),
        Event::Notification(Notice::IdlePrompt),
        Event::PostToolUse,
        Event::PostToolUseFailure,
        Event::PostToolBatch,
        Event::Stop,
        Event::StopFailure,
    ];

    /// A store with session A in `state` (and project `p`).
    fn store_in(state: State) -> Store {
        let mut s = Store::default();
        let open = Open::new(
            found(10, 1).identity,
            true,
            "/home/u/dev/p".into(),
            1_000,
            state,
        );
        s.sessions.insert(A.into(), open);
        assign(&mut s, vec![(A.into(), Ok("p".into()))]);
        s
    }

    /// The table of ARCHITECTURE.md §15: every event in every state, and from "not tracked".
    #[test]
    fn every_event_in_every_state() {
        use State::*;
        let expect = |event: Event, from: Option<State>| -> State {
            match (event, from) {
                (Event::SessionStart(Source::Compact), None) => Unknown,
                (Event::SessionStart(Source::Compact), Some(s)) => s,
                (Event::SessionStart(_), _) => Waiting,
                (Event::UserPromptSubmit, _) => Working,
                (Event::Notification(Notice::PermissionPrompt), _) => NeedsApproval,
                (
                    Event::PostToolUse | Event::PostToolUseFailure | Event::PostToolBatch,
                    Some(Waiting),
                ) => Waiting,
                (Event::PostToolUse | Event::PostToolUseFailure | Event::PostToolBatch, _) => {
                    Working
                }
                (_, _) => Waiting, // Stop, StopFailure, idle_prompt
            }
        };
        for event in ALL_EVENTS {
            let mut s = Store::default();
            let a = s
                .apply(&report(event, A), &found(10, 1), 5_000, ALIVE)
                .unwrap();
            assert_eq!(
                a.outcome,
                Outcome::Opened(expect(event, None)),
                "{event:?} opens"
            );
            for from in State::ALL {
                let mut s = store_in(from);
                let a = s
                    .apply(&report(event, A), &found(10, 1), 9_000, ALIVE)
                    .unwrap();
                let to = expect(event, Some(from));
                let want = if to == from {
                    Outcome::Unchanged(to)
                } else {
                    Outcome::Changed(to)
                };
                assert_eq!(a.outcome, want, "{event:?} in {from:?}");
                assert_eq!(
                    a.projects,
                    if to == from {
                        vec![]
                    } else {
                        vec!["p".to_string()]
                    },
                    "{event:?} in {from:?}"
                );
                let o = &s.sessions[A];
                assert_eq!(o.state, to);
                assert_eq!(
                    o.since,
                    if to == from { 1 } else { 9 },
                    "since moves only with the state"
                );
            }
        }
        // SessionEnd closes from every state.
        for from in State::ALL {
            let mut s = store_in(from);
            let a = s
                .apply(&report(Event::SessionEnd, A), &found(10, 1), 9_000, ALIVE)
                .unwrap();
            assert_eq!(
                (a.outcome, a.projects),
                (Outcome::Closed, vec!["p".to_string()])
            );
            assert!(s.is_empty());
        }
    }

    #[test]
    fn events_of_an_older_prompt_change_nothing_and_are_counted() {
        let mut s = Store::default();
        s.apply(
            &with_prompt(Event::UserPromptSubmit, A, P1),
            &found(10, 1),
            1_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.sessions[A].prompt_id.as_deref(), Some(P1));
        // A late idle notification of P1 after the prompt P2.
        s.apply(
            &with_prompt(Event::Stop, A, P1),
            &found(10, 1),
            2_000,
            ALIVE,
        )
        .unwrap();
        s.apply(
            &with_prompt(Event::UserPromptSubmit, A, P2),
            &found(10, 1),
            3_000,
            ALIVE,
        )
        .unwrap();
        let late = with_prompt(Event::Notification(Notice::IdlePrompt), A, P1);
        assert_eq!(
            s.apply(&late, &found(10, 1), 4_000, ALIVE).unwrap().outcome,
            Outcome::Stale
        );
        assert_eq!((s.sessions[A].state, s.counters.stale), (State::Working, 1));
        // An event without a prompt id, or of the current one, is not stale.
        assert_eq!(
            s.apply(&report(Event::PostToolUse, A), &found(10, 1), 5_000, ALIVE)
                .unwrap()
                .outcome,
            Outcome::Unchanged(State::Working)
        );
        assert_eq!(
            s.apply(
                &with_prompt(Event::Stop, A, P2),
                &found(10, 1),
                6_000,
                ALIVE
            )
            .unwrap()
            .outcome,
            Outcome::Changed(State::Waiting)
        );
        // SessionStart is never stale and forgets the prompt id; compact keeps it.
        s.apply(
            &with_prompt(Event::SessionStart(Source::Compact), A, P1),
            &found(10, 1),
            7_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.sessions[A].prompt_id.as_deref(), Some(P2));
        s.apply(
            &with_prompt(Event::SessionStart(Source::Resume), A, P1),
            &found(10, 1),
            8_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.sessions[A].prompt_id, None);
        // SessionEnd of an older prompt still closes.
        s.apply(
            &with_prompt(Event::UserPromptSubmit, A, P2),
            &found(10, 1),
            9_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(
            s.apply(
                &with_prompt(Event::SessionEnd, A, P1),
                &found(10, 1),
                9_500,
                ALIVE
            )
            .unwrap()
            .outcome,
            Outcome::Closed
        );
    }

    #[test]
    fn an_unknown_current_prompt_is_learned_from_the_next_event() {
        let mut s = Store::default();
        // Hooks added during a turn: the first event opens the session with its prompt id.
        s.apply(
            &with_prompt(Event::PostToolUse, A, P1),
            &found(10, 1),
            1_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.sessions[A].prompt_id.as_deref(), Some(P1));
        // Restored (no prompt id): a Stop of P2 is not stale and tells the turn.
        let mut s = Store::default();
        s.restore(
            A.into(),
            Open::new(found(10, 1).identity, true, "/c".into(), 0, State::Working),
            1_000,
        );
        s.apply(
            &with_prompt(Event::Stop, A, P2),
            &found(10, 1),
            2_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(
            (s.sessions[A].state, s.sessions[A].prompt_id.as_deref()),
            (State::Waiting, Some(P2))
        );
        assert_eq!(s.counters.stale, 0);
    }

    fn fact(end: TurnEnd, prompt: Option<&str>, at_ms: i64) -> TurnFact {
        TurnFact {
            end,
            prompt_id: prompt.map(str::to_string),
            at_ms,
        }
    }

    #[test]
    fn a_recorded_end_of_the_current_turn_makes_the_session_wait() {
        for from in [State::Working, State::NeedsApproval] {
            for end in [TurnEnd::Interrupted, TurnEnd::Ended] {
                let mut s = Store::default();
                s.apply(
                    &with_prompt(Event::UserPromptSubmit, A, P1),
                    &found(10, 1),
                    1_000,
                    ALIVE,
                )
                .unwrap();
                if from == State::NeedsApproval {
                    s.apply(
                        &with_prompt(Event::Notification(Notice::PermissionPrompt), A, P1),
                        &found(10, 1),
                        2_000,
                        ALIVE,
                    )
                    .unwrap();
                }
                assign(&mut s, vec![(A.into(), Ok("p".into()))]);
                // Of the current prompt: applied.
                assert_eq!(
                    s.apply_fact(A, &fact(end, Some(P1), 2_500), 3_000),
                    (FactOutcome::Applied, Some("p".into()))
                );
                assert_eq!(
                    (s.sessions[A].state, s.sessions[A].since),
                    (State::Waiting, 3)
                );
                assert_eq!(s.counters.session_file_facts, 1);
                // Waiting already: nothing.
                assert_eq!(
                    s.apply_fact(A, &fact(end, Some(P1), 2_600), 3_100).0,
                    FactOutcome::Nothing
                );
            }
        }
        // Not open: nothing.
        assert_eq!(
            Store::default()
                .apply_fact(A, &fact(TurnEnd::Ended, None, 1), 2)
                .0,
            FactOutcome::Nothing
        );
    }

    #[test]
    fn a_recorded_end_of_an_older_turn_changes_nothing() {
        let mut s = Store::default();
        s.apply(
            &with_prompt(Event::UserPromptSubmit, A, P2),
            &found(10, 1),
            10_000,
            ALIVE,
        )
        .unwrap();
        // Another prompt id: an older turn, however new the record.
        assert_eq!(
            s.apply_fact(A, &fact(TurnEnd::Interrupted, Some(P1), 20_000), 21_000)
                .0,
            FactOutcome::OlderTurn
        );
        // Without a prompt id (assistant, system records): older than the state, ignored ...
        assert_eq!(
            s.apply_fact(A, &fact(TurnEnd::Ended, None, 9_999), 21_000)
                .0,
            FactOutcome::OlderTurn
        );
        assert_eq!(s.sessions[A].state, State::Working);
        // ... not older: applied (a lost Stop, an Esc during a reply).
        assert_eq!(
            s.apply_fact(A, &fact(TurnEnd::Ended, None, 10_000), 21_000)
                .0,
            FactOutcome::Applied
        );
    }

    /// After a restart the current prompt id is not known: the timestamp decides, against the
    /// restore time (`unknown` since then).
    #[test]
    fn after_a_restart_the_record_time_decides() {
        let mut s = Store::default();
        let open = Open::new(
            found(10, 1).identity,
            true,
            "/c".into(),
            1_000,
            State::Working,
        );
        assert!(s.restore(A.into(), open, 50_000));
        assert_eq!(
            (s.sessions[A].state, s.sessions[A].since),
            (State::Unknown, 50)
        );
        assert_eq!(
            s.apply_fact(A, &fact(TurnEnd::Interrupted, Some(P1), 49_000), 51_000)
                .0,
            FactOutcome::OlderTurn
        );
        assert_eq!(s.sessions[A].state, State::Unknown, "unknown stays unknown");
        assert_eq!(
            s.apply_fact(A, &fact(TurnEnd::Interrupted, Some(P1), 50_500), 51_000)
                .0,
            FactOutcome::Applied
        );
        assert_eq!(s.sessions[A].state, State::Waiting);
    }

    #[test]
    fn any_event_opens_an_untracked_session_except_session_end() {
        for event in ALL_EVENTS {
            let mut s = Store::default();
            let a = s
                .apply(&report(event, A), &found(10, 1), 5_000, ALIVE)
                .unwrap();
            assert!(matches!(a.outcome, Outcome::Opened(_)), "{event:?}");
            let Some(Persist::Put(id, open)) = a.persist else {
                panic!("{event:?} persists the session")
            };
            assert_eq!(
                (id.as_str(), open.opened_at, open.first_cwd.as_str()),
                (A, 5, "/home/u/dev/p")
            );
            assert_eq!(s.open_counts(false).open, 1);
        }
        let mut s = Store::default();
        assert_eq!(
            s.apply(&report(Event::SessionEnd, A), &found(10, 1), 5_000, ALIVE)
                .unwrap()
                .outcome,
            Outcome::Ignored
        );
        assert!(s.is_empty());
    }

    #[test]
    fn session_start_moves_a_session_to_its_new_process() {
        let mut s = Store::default();
        s.apply(&report(Event::Stop, A), &found(10, 1), 5_000, ALIVE)
            .unwrap();
        // Another live process reports for it without SessionStart: the session stays put.
        let a = s
            .apply(
                &report(Event::UserPromptSubmit, A),
                &found(20, 2),
                6_000,
                ALIVE,
            )
            .unwrap();
        assert_eq!(
            (a.outcome, a.persist),
            (Outcome::Changed(State::Working), None)
        );
        assert_eq!(s.identities()[0].1.pid, 10);
        // SessionStart (resume, a respawn) takes the new identity; the first cwd stays.
        let mut resumed = report(Event::SessionStart(Source::Resume), A);
        resumed.cwd = "/other".into();
        let mut f = found(20, 2);
        f.interactive = false;
        let a = s.apply(&resumed, &f, 7_000, ALIVE).unwrap();
        assert_eq!(a.outcome, Outcome::NewProcess(State::Waiting));
        let Some(Persist::Put(_, open)) = a.persist else {
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
        assert_eq!(s.open_counts(false).hidden_noninteractive, 1);
        // Once the session's process is gone, any event from the new one moves it.
        let a = s
            .apply(&report(Event::Stop, A), &found(30, 3), 8_000, GONE)
            .unwrap();
        assert_eq!(a.outcome, Outcome::NewProcess(State::Waiting));
        assert_eq!(s.identities()[0].1.pid, 30);
    }

    /// v0.2 review L1 (E1): the same session resumed in a second terminal while the first still
    /// runs; the first one's `SessionEnd` must not close it for the second.
    #[test]
    fn session_end_closes_a_session_only_from_its_own_process() {
        let mut s = Store::default();
        s.apply(
            &report(Event::SessionStart(Source::Startup), A),
            &found(10, 1),
            5_000,
            ALIVE,
        )
        .unwrap();
        s.apply(
            &report(Event::SessionStart(Source::Resume), A),
            &found(20, 2),
            6_000,
            ALIVE,
        )
        .unwrap();
        s.apply(
            &with_prompt(Event::UserPromptSubmit, A, P1),
            &found(20, 2),
            7_000,
            ALIVE,
        )
        .unwrap();
        let a = s
            .apply(&report(Event::SessionEnd, A), &found(10, 1), 8_000, ALIVE)
            .unwrap();
        assert_eq!(
            a,
            Applied {
                outcome: Outcome::OtherProcess,
                persist: None,
                projects: vec![],
                replaced: vec![],
            }
        );
        assert_eq!(s.open_counts(false).working, 1, "still open, still working");
        assert_eq!(Outcome::OtherProcess.text(), "ignored (another process)");
        // A process that never held it, the same.
        let a = s
            .apply(&report(Event::SessionEnd, A), &found(30, 3), 8_000, ALIVE)
            .unwrap();
        assert_eq!(a.outcome, Outcome::OtherProcess);
        // Its own process ends it.
        let a = s
            .apply(&report(Event::SessionEnd, A), &found(20, 2), 9_000, ALIVE)
            .unwrap();
        assert_eq!(
            (a.outcome, a.persist),
            (Outcome::Closed, Some(Persist::Delete(vec![A.to_string()])))
        );
        assert!(s.is_empty());
        // Once its process is gone, the process that reports for it may end it (as any other
        // event moves it there).
        s.apply(&report(Event::Stop, A), &found(10, 1), 10_000, ALIVE)
            .unwrap();
        let a = s
            .apply(&report(Event::SessionEnd, A), &found(20, 2), 11_000, GONE)
            .unwrap();
        assert_eq!(a.outcome, Outcome::Closed);
        assert!(s.is_empty());
    }

    /// v0.2 review L2 (E2): `/clear` (or `/resume` inside a session) ends one session and starts
    /// the next in the same process; when the `SessionEnd` was lost, the `SessionStart` closes
    /// the old session — and only the sessions of that process.
    #[test]
    fn session_start_closes_the_other_sessions_of_its_process() {
        let mut s = Store::default();
        for (sid, pid) in [(A, 10), (B, 20)] {
            s.apply(&report(Event::Stop, sid), &found(pid, 1), 5_000, ALIVE)
                .unwrap();
        }
        assign(
            &mut s,
            vec![(A.into(), Ok("p".into())), (B.into(), Ok("q".into()))],
        );
        let x = "2b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
        let a = s
            .apply(
                &report(Event::SessionStart(Source::Clear), x),
                &found(10, 1),
                6_000,
                ALIVE,
            )
            .unwrap();
        assert_eq!(a.outcome, Outcome::Opened(State::Waiting));
        assert_eq!(a.replaced, [A]);
        assert_eq!(a.projects, ["p"], "A's project lost a session");
        let mut ids: Vec<String> = s.identities().into_iter().map(|(id, _)| id).collect();
        ids.sort();
        assert_eq!(ids, [B, x], "B is another process's");
        // A pid that was reused (another start time) is another process.
        let a = s
            .apply(
                &report(Event::SessionStart(Source::Startup), A),
                &found(20, 9),
                7_000,
                ALIVE,
            )
            .unwrap();
        assert!(a.replaced.is_empty());
        // compact, and a SessionStart for the session the process already holds, close nothing.
        for source in [Source::Compact, Source::Resume] {
            let a = s
                .apply(
                    &report(Event::SessionStart(source), x),
                    &found(10, 1),
                    8_000,
                    ALIVE,
                )
                .unwrap();
            assert!(a.replaced.is_empty(), "{source:?}");
        }
        // A session moved to the process by `/resume`: the session it held before goes.
        let a = s
            .apply(
                &report(Event::SessionStart(Source::Resume), B),
                &found(10, 1),
                9_000,
                ALIVE,
            )
            .unwrap();
        assert_eq!(
            (a.outcome, a.replaced),
            (Outcome::NewProcess(State::Waiting), vec![x.to_string()])
        );
        assert_eq!(a.projects, ["q"]);
        // Other events never close another session.
        let a = s
            .apply(&report(Event::Stop, x), &found(10, 1), 10_000, ALIVE)
            .unwrap();
        assert_eq!(
            (a.outcome, a.replaced.len()),
            (Outcome::Opened(State::Waiting), 0)
        );
        assert_eq!(s.totals().0, 3);
    }

    /// At the limit, a `SessionStart` that replaces its process's sessions has room.
    #[test]
    fn a_session_start_that_replaces_sessions_is_not_refused_at_the_limit() {
        let mut s = Store::default();
        let sid = |i: usize| format!("{i:08x}-3d2a-4c5b-9e8f-1a2b3c4d5e6f");
        for i in 0..MAX_SESSIONS {
            s.apply(&report(Event::Stop, &sid(i)), &found(10, 1), 5_000, ALIVE)
                .unwrap();
        }
        let new = report(Event::SessionStart(Source::Clear), &sid(MAX_SESSIONS));
        assert_eq!(
            s.apply(&new, &found(11, 1), 6_000, ALIVE),
            Err(Refusal::Limit),
            "another process: still refused"
        );
        let a = s.apply(&new, &found(10, 1), 6_000, ALIVE).unwrap();
        assert_eq!(a.outcome, Outcome::Opened(State::Waiting));
        assert_eq!(a.replaced.len(), MAX_SESSIONS);
        assert_eq!(s.totals().0, 1);
    }

    /// v0.2 review L8 at the store: results apply in the order their resolutions started.
    #[test]
    fn resolution_results_apply_only_when_not_older_than_the_last_applied() {
        let mut s = Store::default();
        s.apply(&report(Event::Stop, A), &found(10, 1), 1_000, ALIVE)
            .unwrap();
        let (first, _) = s.cwds();
        let (second, _) = s.cwds();
        assert_eq!(second, first + 1);
        assert_eq!(s.assign(second, vec![(A.into(), Ok("p".into()))]), ["p"]);
        assert!(
            s.assign(first, vec![(A.into(), Err(NOT_REGISTERED))])
                .is_empty(),
            "older: dropped"
        );
        assert_eq!(s.live_ranks(false).len(), 1);
        // The same resolution may not be applied twice out of order either way; a newer one is.
        let (third, _) = s.cwds();
        assert_eq!(
            s.assign(third, vec![(A.into(), Ok("q".into()))]),
            ["p", "q"]
        );
    }

    #[test]
    fn live_ranks_are_each_projects_aggregate_and_lead_in_the_aggregate_order() {
        assert_eq!(
            State::ALL.map(State::rank),
            [0, 1, 2, 3],
            "needs approval first"
        );
        assert!(State::ALL
            .iter()
            .all(|s| s.rank() < crate::db::queries::NOT_LIVE));
        let mut s = Store::default();
        let x = "2b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
        for (sid, pid, event) in [
            (A, 10, Event::Stop),
            (B, 11, Event::Notification(Notice::PermissionPrompt)),
            (x, 12, Event::UserPromptSubmit),
        ] {
            s.apply(&report(event, sid), &found(pid, 1), 1_000, ALIVE)
                .unwrap();
        }
        assign(
            &mut s,
            vec![
                (A.into(), Ok("p".into())),
                (B.into(), Ok("p".into())),
                (x.into(), Ok("q".into())),
            ],
        );
        assert_eq!(
            s.live_ranks(false).into_iter().collect::<Vec<_>>(),
            [
                ("p".to_string(), State::NeedsApproval),
                ("q".to_string(), State::Working)
            ]
        );
    }

    #[test]
    fn one_process_may_hold_several_sessions_each_on_its_own() {
        let mut s = Store::default();
        s.apply(
            &report(Event::SessionStart(Source::Startup), A),
            &found(10, 1),
            5_000,
            ALIVE,
        )
        .unwrap();
        s.apply(&report(Event::SessionEnd, A), &found(10, 1), 6_000, ALIVE)
            .unwrap();
        s.apply(
            &report(Event::SessionStart(Source::Clear), B),
            &found(10, 1),
            6_000,
            ALIVE,
        )
        .unwrap();
        s.apply(
            &report(Event::UserPromptSubmit, A),
            &found(10, 1),
            7_000,
            ALIVE,
        )
        .unwrap();
        assert_eq!(s.open_counts(false).open, 2);
        let id = found(10, 1).identity;
        assert!(s.close_if(A, &id).is_some());
        assert!(s.close_if(A, &id).is_none(), "already closed");
        assert!(
            s.close_if(B, &found(10, 2).identity).is_none(),
            "another process now"
        );
        assert_eq!(s.open_counts(false).open, 1);
    }

    #[test]
    fn the_limit_refuses_new_sessions_but_not_tracked_ones() {
        let mut s = Store::default();
        let sid = |i: usize| format!("{i:08x}-3d2a-4c5b-9e8f-1a2b3c4d5e6f");
        for i in 0..MAX_SESSIONS {
            s.apply(&report(Event::Stop, &sid(i)), &found(10, 1), 5_000, ALIVE)
                .unwrap();
        }
        assert_eq!(
            s.apply(
                &report(Event::Stop, &sid(MAX_SESSIONS)),
                &found(10, 1),
                5_000,
                ALIVE
            ),
            Err(Refusal::Limit)
        );
        assert_eq!(
            s.apply(&report(Event::Stop, &sid(0)), &found(10, 1), 5_000, ALIVE)
                .unwrap()
                .outcome,
            Outcome::Unchanged(State::Waiting)
        );
        s.apply(
            &report(Event::SessionEnd, &sid(0)),
            &found(10, 1),
            5_000,
            ALIVE,
        )
        .unwrap();
        assert!(matches!(
            s.apply(
                &report(Event::Stop, &sid(MAX_SESSIONS)),
                &found(10, 1),
                5_000,
                ALIVE
            )
            .unwrap()
            .outcome,
            Outcome::Opened(_)
        ));
        let any = s.sessions.values().next().unwrap().clone();
        assert!(!s.restore(sid(999), any, 1), "full");
        assert_eq!(s.clear().0, MAX_SESSIONS);
        assert!(s.is_empty());
    }

    /// Several sessions in one project; hidden non-interactive ones; the three filters.
    #[test]
    fn the_aggregate_counts_and_filters_shown_sessions() {
        let sid = |i: u32| format!("{i:08x}-3d2a-4c5b-9e8f-1a2b3c4d5e6f");
        let mut s = Store::default();
        let add = |s: &mut Store,
                   i: u32,
                   state: State,
                   since_ms: i64,
                   project: &str,
                   interactive: bool| {
            let mut f = found(i + 10, 1);
            f.interactive = interactive;
            s.sessions.insert(
                sid(i),
                Open::new(f.identity, interactive, "/c".into(), since_ms, state),
            );
            assign(s, vec![(sid(i), Ok(project.into()))]);
        };
        add(&mut s, 1, State::Working, 10_000, "p", true);
        add(&mut s, 2, State::NeedsApproval, 30_000, "p", true);
        add(&mut s, 3, State::NeedsApproval, 20_000, "p", true);
        add(&mut s, 4, State::Waiting, 40_000, "q", true);
        add(&mut s, 5, State::Unknown, 50_000, "r", true);
        add(&mut s, 6, State::Working, 60_000, "s", false); // `-p`: hidden
        add(&mut s, 7, State::Waiting, 70_000, "q", true);
        let p = s.live("p", false).unwrap();
        assert_eq!(
            (
                p.state,
                p.sessions,
                p.needs_approval,
                p.working,
                p.since,
                p.needs_approval_since
            ),
            (State::NeedsApproval, 3, 2, 1, None, Some(20))
        );
        let q = s.live("q", false).unwrap();
        assert_eq!((q.state, q.waiting, q.since), (State::Waiting, 2, None));
        let r = s.live("r", false).unwrap();
        assert_eq!(
            (r.state, r.unknown, r.since),
            (State::Unknown, 1, Some(50)),
            "one session: since"
        );
        assert_eq!(s.live("s", false), None, "hidden");
        assert_eq!(
            s.live("s", true).unwrap().state,
            State::Working,
            "shown with the toggle"
        );
        assert_eq!(s.live("nothing", true), None);
        assert_eq!(
            s.projects_matching(LiveFilter::WaitingForMe, false),
            ["p", "q"]
        );
        assert_eq!(s.projects_matching(LiveFilter::Working, false), ["p"]);
        assert_eq!(s.projects_matching(LiveFilter::Working, true), ["p", "s"]);
        assert_eq!(
            s.projects_matching(LiveFilter::Open, false),
            ["p", "q", "r"]
        );
        assert_eq!(s.noninteractive_projects(), ["s"]);
        let c = s.open_counts(false);
        assert_eq!(
            (
                c.open,
                c.needs_approval,
                c.working,
                c.waiting,
                c.unknown,
                c.hidden_noninteractive
            ),
            (6, 2, 1, 2, 1, 1)
        );
        assert_eq!(s.session_live(&sid(6), false), None);
        assert_eq!(
            s.session_live(&sid(2), false),
            Some(SessionLive {
                state: State::NeedsApproval,
                since: 30
            })
        );
        for f in LiveFilter::ALL {
            assert!(
                LiveFilter::parse(match f {
                    LiveFilter::WaitingForMe => "waiting",
                    LiveFilter::Working => "working",
                    LiveFilter::Open => "open",
                }) == Some(f)
            );
        }
        assert_eq!(LiveFilter::parse("needs_approval"), None);
    }

    #[test]
    fn assignment_moves_sessions_between_projects_and_counts_the_unassigned() {
        let mut s = Store::default();
        s.apply(&report(Event::Stop, A), &found(10, 1), 1_000, ALIVE)
            .unwrap();
        s.apply(&report(Event::Stop, B), &found(11, 1), 1_000, ALIVE)
            .unwrap();
        let (_, mut cwds) = s.cwds();
        cwds.sort();
        assert_eq!(cwds.len(), 2);
        assert_eq!(
            assign(
                &mut s,
                vec![(A.into(), Ok("p".into())), (B.into(), Err(NOT_REGISTERED))]
            ),
            ["p"]
        );
        assert_eq!(
            s.open_counts(false).unassigned.get(NOT_REGISTERED),
            Some(&1)
        );
        // B's project appears (the session file registered it); A's moved.
        assert_eq!(
            assign(
                &mut s,
                vec![(A.into(), Ok("q".into())), (B.into(), Ok("q".into()))]
            ),
            ["p", "q"]
        );
        assert!(s.open_counts(false).unassigned.is_empty());
        assert_eq!(
            assign(&mut s, vec![(A.into(), Ok("q".into()))]),
            Vec::<String>::new(),
            "no change"
        );
        assert_eq!(
            assign(
                &mut s,
                vec![(
                    "ffffffff-3d2a-4c5b-9e8f-1a2b3c4d5e6f".into(),
                    Ok("x".into())
                )]
            ),
            Vec::<String>::new(),
            "closed meanwhile"
        );
        // A state change publishes the project; closing does too.
        let a = s
            .apply(
                &report(Event::UserPromptSubmit, A),
                &found(10, 1),
                2_000,
                ALIVE,
            )
            .unwrap();
        assert_eq!(a.projects, ["q"]);
        let (n, projects) = s.clear();
        assert_eq!((n, projects.len()), (2, 2));
    }

    #[test]
    fn counters_and_the_log_keep_the_newest_entries() {
        let mut s = Store::default();
        s.received(10);
        s.received(12);
        s.refused(Refusal::PidMismatch);
        s.refused(Refusal::Malformed);
        s.refused(Refusal::Malformed);
        s.refused(Refusal::ClientGone);
        let c = s.counters();
        assert_eq!((c.received, c.last_event_at), (2, Some(12)));
        // Every reason is counted under its own name (what `ccwm status`, `ccwm hooks events`
        // and `ccwm doctor` read through `Refusal::ALL`).
        let json = serde_json::to_value(&c.refused).unwrap();
        assert_eq!(
            Refusal::ALL.map(|r| json[r.as_str()].as_u64()),
            [Some(2), Some(0), Some(1), Some(0), Some(1)]
        );
        assert_eq!(json.as_object().unwrap().len(), Refusal::ALL.len());
        for i in 0..(LOG_SIZE + 3) {
            s.log(
                i as i64,
                Some(Event::Notification(Notice::IdlePrompt)),
                None,
                Some(A.into()),
                Some(true),
                "x".into(),
            );
        }
        s.log(1, None, None, None, None, "closed: process gone".into());
        let log = s.log_entries();
        assert_eq!(log.len(), LOG_SIZE);
        assert_eq!(log[0].seq, 5, "the oldest four dropped");
        assert_eq!(
            (log[0].event, log[0].detail),
            (Some("Notification"), Some("idle_prompt"))
        );
        assert_eq!(log.last().unwrap().event, None);
    }

    #[test]
    fn outcome_and_fact_texts() {
        assert_eq!(Outcome::Opened(State::Waiting).text(), "opened: waiting");
        assert_eq!(
            Outcome::Changed(State::NeedsApproval).text(),
            "→ needs_approval"
        );
        assert_eq!(
            Outcome::Unchanged(State::Working).text(),
            "unchanged: working"
        );
        assert_eq!(
            fact_text(&fact(TurnEnd::Interrupted, None, 1), FactOutcome::Applied),
            "interrupted (session file): → waiting"
        );
        assert_eq!(
            fact_text(&fact(TurnEnd::Ended, None, 1), FactOutcome::OlderTurn),
            "turn ended (session file): an older turn, ignored"
        );
    }

    #[test]
    fn debug_output_never_shows_the_cwd() {
        let open = Open::new(
            found(10, 1).identity,
            true,
            "/home/u/SECRET-PROJECT".into(),
            1_000,
            State::Working,
        );
        let shown = format!("{open:?} {:?}", Persist::Put(A.into(), open.clone()));
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("<22 bytes>"), "{shown}");
    }
}
