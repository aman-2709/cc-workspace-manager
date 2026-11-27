//! Claude Code hooks (REQUIREMENTS.md §21.2–§21.4, §21.9; ARCHITECTURE.md §11a): the event JSON a
//! hook command reads on stdin, the report `ccwm hook` sends over the Unix socket and its
//! validation on both ends, and the settings snippet `ccwm hooks print` writes.
//!
//! Allowlist parsing, as in [`super::record`]: only `hook_event_name`, `session_id`, `cwd`,
//! `prompt_id`, `source`, `notification_type` and the presence of `agent_id` are declared. The
//! prompt (`prompt`), the assistant's last message (`last_assistant_message`), the tool fields
//! (`tool_name`, `tool_input`, `tool_response`, `tool_calls`, `error`), `background_tasks`,
//! `session_crons`, `session_title`, `transcript_path` and anything unknown are skipped by serde
//! without being materialized: they never become a value in ccwm's memory, let alone reach the
//! socket, a log or the database.

use super::record::lenient_string;
use super::resume::{is_lower_uuid, is_unsafe_char, shell_quote};
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::Path;

/// Stdin is read up to this many bytes; a longer input is malformed (§21.3).
pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
/// The longest cwd accepted, as for a cwd recorded in a session file (§7.3).
pub const MAX_CWD_BYTES: usize = 4096;
/// Linux's largest pid (`pid_max` cannot exceed 2^22).
pub const MAX_PID: u32 = 4_194_304;
/// The `timeout` (seconds) of every handler in the snippet: Claude Code's own bound, far above
/// what `ccwm hook` needs (its watchdog ends it after 1 s).
pub const SNIPPET_TIMEOUT_SECS: u32 = 5;

/// `SessionStart`'s `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Startup,
    Resume,
    Clear,
    Compact,
    Fork,
}

impl Source {
    pub const ALL: [Self; 5] = [
        Self::Startup,
        Self::Resume,
        Self::Clear,
        Self::Compact,
        Self::Fork,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Resume => "resume",
            Self::Clear => "clear",
            Self::Compact => "compact",
            Self::Fork => "fork",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The two `notification_type`s the indicator uses (the snippet's two `Notification` matchers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    PermissionPrompt,
    IdlePrompt,
}

impl Notice {
    pub const ALL: [Self; 2] = [Self::PermissionPrompt, Self::IdlePrompt];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PermissionPrompt => "permission_prompt",
            Self::IdlePrompt => "idle_prompt",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The nine events of §21.2, each with the one field its kind needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    SessionStart(Source),
    UserPromptSubmit,
    Notification(Notice),
    PostToolUse,
    PostToolUseFailure,
    PostToolBatch,
    Stop,
    StopFailure,
    SessionEnd,
}

/// The event names, in the order of §21.2 (the snippet's order).
pub const EVENT_NAMES: [&str; 9] = [
    "SessionStart",
    "UserPromptSubmit",
    "Notification",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Stop",
    "StopFailure",
    "SessionEnd",
];

/// `name` as one of [`EVENT_NAMES`] (with a `'static` lifetime), or `None`.
pub fn event_name(name: &str) -> Option<&'static str> {
    EVENT_NAMES.into_iter().find(|n| *n == name)
}

impl Event {
    pub fn name(self) -> &'static str {
        match self {
            Self::SessionStart(_) => "SessionStart",
            Self::UserPromptSubmit => "UserPromptSubmit",
            Self::Notification(_) => "Notification",
            Self::PostToolUse => "PostToolUse",
            Self::PostToolUseFailure => "PostToolUseFailure",
            Self::PostToolBatch => "PostToolBatch",
            Self::Stop => "Stop",
            Self::StopFailure => "StopFailure",
            Self::SessionEnd => "SessionEnd",
        }
    }

    /// `SessionStart`'s source or `Notification`'s type; `None` for the other events.
    pub fn detail(self) -> Option<&'static str> {
        match self {
            Self::SessionStart(s) => Some(s.as_str()),
            Self::Notification(n) => Some(n.as_str()),
            _ => None,
        }
    }

    /// `PostToolUse`, `PostToolUseFailure` or `PostToolBatch`.
    pub fn is_tool(self) -> bool {
        matches!(
            self,
            Self::PostToolUse | Self::PostToolUseFailure | Self::PostToolBatch
        )
    }

    /// The event named `name`, with `source` (required for `SessionStart`) or `notice`
    /// (required for `Notification`). `None` for another name, a missing or unknown value.
    fn from_parts(name: &str, source: Option<&str>, notice: Option<&str>) -> Option<Self> {
        Some(match name {
            "SessionStart" => Self::SessionStart(Source::parse(source?)?),
            "UserPromptSubmit" => Self::UserPromptSubmit,
            "Notification" => Self::Notification(Notice::parse(notice?)?),
            "PostToolUse" => Self::PostToolUse,
            "PostToolUseFailure" => Self::PostToolUseFailure,
            "PostToolBatch" => Self::PostToolBatch,
            "Stop" => Self::Stop,
            "StopFailure" => Self::StopFailure,
            "SessionEnd" => Self::SessionEnd,
            _ => return None,
        })
    }
}

/// An absolute path of at most [`MAX_CWD_BYTES`] without NUL: the shape a cwd must have before
/// it is resolved like a session cwd (§4.4, §21.4).
pub fn valid_cwd(cwd: &str) -> bool {
    cwd.starts_with('/') && cwd.len() <= MAX_CWD_BYTES && !cwd.contains('\0')
}

/// A pid another process can have: 2 to [`MAX_PID`] (1 is init, 0 is no process).
pub fn valid_pid(pid: u64) -> bool {
    (2..=u64::from(MAX_PID)).contains(&pid)
}

/// `CLAUDE_PID` as Claude Code sets it (`String(process.pid)`): decimal digits without a sign
/// or a leading zero, a valid pid. Anything else is not used (`None`): the walk decides alone.
pub fn parse_claude_pid(value: Option<&OsStr>) -> Option<u32> {
    let s = value?.to_str()?;
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pid: u64 = s.parse().ok()?;
    valid_pid(pid).then(|| u32::try_from(pid).ok()).flatten()
}

/// Why `ccwm hook` sends nothing (§21.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// An event the indicator does not use: a `Notification` of another type, or an event from
    /// inside a subagent (`agent_id`). Not a failure: nothing is written.
    NotUsed,
    /// The argument is not one of [`EVENT_NAMES`], or the input's `hook_event_name` differs.
    WrongEvent,
    /// The input is not one JSON object of at most [`MAX_INPUT_BYTES`], or a needed field is
    /// missing or invalid (the field's name; never its content).
    Malformed(&'static str),
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUsed => f.write_str("not an event the activity indicator uses"),
            Self::WrongEvent => f.write_str(
                "the event argument is not one of the nine hook events, or differs from the input's hook_event_name",
            ),
            Self::Malformed(what) => write!(f, "malformed hook input: {what}"),
        }
    }
}

/// The allowlisted fields of a hook's stdin. String fields of another JSON type are absent.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HookInput {
    #[serde(deserialize_with = "lenient_string")]
    hook_event_name: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    session_id: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    cwd: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    prompt_id: Option<String>,
    /// `SessionStart` only (`UserPromptSubmit` has a `source` of its own, unused).
    #[serde(deserialize_with = "lenient_string")]
    source: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    notification_type: Option<String>,
    /// Presence only (set inside a subagent); its value is skipped unread.
    agent_id: Option<IgnoredAny>,
}

/// A [`HookInput`] from a JSON **object** only: a derived struct would also accept an array
/// (positional fields).
struct ObjectOnly(HookInput);

impl<'de> Deserialize<'de> for ObjectOnly {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = HookInput;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<HookInput, A::Error> {
                HookInput::deserialize(de::value::MapAccessDeserializer::new(m))
            }
        }
        d.deserialize_map(V).map(ObjectOnly)
    }
}

/// Read the first JSON value of `input` (at most [`MAX_INPUT_BYTES`]). Parsing stops at the end
/// of that value: a stdin that stays open after it holds nothing up.
fn read_input(input: impl Read) -> Result<HookInput, Skip> {
    serde_json::Deserializer::from_reader(input.take(MAX_INPUT_BYTES))
        .into_iter::<ObjectOnly>()
        .next()
        .and_then(Result::ok)
        .map(|o| o.0)
        .ok_or(Skip::Malformed(
            "not one JSON object of at most 16 MiB with string fields",
        ))
}

/// What `ccwm hook` sends and the daemon accepts: the validated `hook.event` request (§21.4).
/// Its `Debug` output leaves the cwd out (it is never logged).
#[derive(Clone, PartialEq, Eq)]
pub struct Report {
    pub event: Event,
    /// A lower-case UUID.
    pub session_id: String,
    /// [`valid_cwd`]; untrusted, never logged.
    pub cwd: String,
    /// A lower-case UUID, when the input has one.
    pub prompt_id: Option<String>,
    /// `CLAUDE_PID`, when it was set and [`parse_claude_pid`] accepted it.
    pub claude_pid: Option<u32>,
}

impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("event", &self.event)
            .field("session_id", &self.session_id)
            .field("cwd", &format_args!("<{} bytes>", self.cwd.len()))
            .field("prompt_id", &self.prompt_id)
            .field("claude_pid", &self.claude_pid)
            .finish()
    }
}

/// A `hook.event` request the daemon refused as malformed, with what of it was valid (for the
/// debug log: a known event name and a valid session id; never anything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    pub event: Option<&'static str>,
    pub session_id: Option<String>,
}

impl Report {
    /// The report for the hook event `arg` read from `input` (the hook's stdin), with
    /// `claude_pid` from the `CLAUDE_PID` variable. Only the allowlisted fields are read.
    pub fn from_hook(
        arg: &str,
        input: impl Read,
        claude_pid: Option<&OsStr>,
    ) -> Result<Self, Skip> {
        let name = event_name(arg).ok_or(Skip::WrongEvent)?;
        let input = read_input(input)?;
        if input.hook_event_name.as_deref() != Some(name) {
            return Err(Skip::WrongEvent);
        }
        let event = if name == "Notification" {
            // Only the two types the snippet's matchers select; a Notification from inside a
            // subagent is still the session's (its permission dialog blocks the session).
            let kind = input
                .notification_type
                .as_deref()
                .ok_or(Skip::Malformed("notification_type"))?;
            Event::Notification(Notice::parse(kind).ok_or(Skip::NotUsed)?)
        } else {
            if input.agent_id.is_some() {
                return Err(Skip::NotUsed);
            }
            Event::from_parts(name, input.source.as_deref(), None)
                .ok_or(Skip::Malformed("source"))?
        };
        let session_id = input
            .session_id
            .filter(|s| is_lower_uuid(s))
            .ok_or(Skip::Malformed("session_id"))?;
        let cwd = input
            .cwd
            .filter(|c| valid_cwd(c))
            .ok_or(Skip::Malformed("cwd"))?;
        let prompt_id = match input.prompt_id {
            None => None,
            Some(p) if is_lower_uuid(&p) => Some(p),
            Some(_) => return Err(Skip::Malformed("prompt_id")),
        };
        Ok(Self {
            event,
            session_id,
            cwd,
            prompt_id,
            claude_pid: parse_claude_pid(claude_pid),
        })
    }

    /// The `hook.event` request as one line (with its newline): exactly the keys of §21.4.
    pub fn to_request_line(&self) -> String {
        let mut m = Map::new();
        m.insert("op".into(), "hook.event".into());
        m.insert("event".into(), self.event.name().into());
        m.insert("session_id".into(), self.session_id.clone().into());
        m.insert("cwd".into(), self.cwd.clone().into());
        match self.event {
            Event::SessionStart(s) => {
                m.insert("source".into(), s.as_str().into());
            }
            Event::Notification(n) => {
                m.insert("notification_type".into(), n.as_str().into());
            }
            _ => {}
        }
        if let Some(p) = &self.prompt_id {
            m.insert("prompt_id".into(), p.clone().into());
        }
        if let Some(pid) = self.claude_pid {
            m.insert("claude_pid".into(), pid.into());
        }
        format!("{}\n", Value::Object(m))
    }

    /// A `hook.event` request object (its `op` already checked), validated by hand: the exact
    /// key set of §21.4 for its event, and every value within its bounds.
    pub fn from_request(obj: &Map<String, Value>) -> Result<Self, Malformed> {
        let str_of = |k: &str| obj.get(k).and_then(Value::as_str);
        let name = str_of("event").and_then(event_name);
        let session_id = str_of("session_id").filter(|s| is_lower_uuid(s));
        let malformed = || Malformed {
            event: name,
            session_id: session_id.map(str::to_string),
        };
        let name = name.ok_or_else(malformed)?;
        let own_key = match name {
            "SessionStart" => Some("source"),
            "Notification" => Some("notification_type"),
            _ => None,
        };
        let allowed = |k: &str| {
            matches!(
                k,
                "op" | "event" | "session_id" | "cwd" | "prompt_id" | "claude_pid"
            ) || Some(k) == own_key
        };
        if !obj.keys().all(|k| allowed(k)) {
            return Err(malformed());
        }
        let event = Event::from_parts(name, str_of("source"), str_of("notification_type"))
            .ok_or_else(malformed)?;
        let session_id = session_id.ok_or_else(malformed)?.to_string();
        let cwd = str_of("cwd")
            .filter(|c| valid_cwd(c))
            .ok_or_else(malformed)?
            .to_string();
        let prompt_id = match obj.get("prompt_id") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|p| is_lower_uuid(p))
                    .ok_or_else(malformed)?
                    .to_string(),
            ),
        };
        let claude_pid = match obj.get("claude_pid") {
            None => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|p| valid_pid(*p))
                    .and_then(|p| u32::try_from(p).ok())
                    .ok_or_else(malformed)?,
            ),
        };
        Ok(Self {
            event,
            session_id,
            cwd,
            prompt_id,
            claude_pid,
        })
    }
}

/// The hook command for `event` (§21.9): `command -v '<ccwm>' >/dev/null 2>&1 && '<ccwm>' hook
/// <event>; exit 0`. A missing ccwm is not called, and the shell exits 0 with nothing on stdout
/// whatever ccwm did.
pub fn guarded_command(ccwm: &str, event: &str) -> String {
    let q = shell_quote(ccwm);
    format!("command -v {q} >/dev/null 2>&1 && {q} hook {event}; exit 0")
}

/// One handler entry of the snippet.
#[derive(Serialize)]
struct Handler {
    #[serde(rename = "type")]
    kind: &'static str,
    command: String,
    timeout: u32,
}

#[derive(Serialize)]
struct Matcher {
    #[serde(skip_serializing_if = "Option::is_none")]
    matcher: Option<&'static str>,
    hooks: [Handler; 1],
}

/// The events in the order of §21.2, each with its matcher entries.
struct Hooks(Vec<(&'static str, Vec<Matcher>)>);

impl Serialize for Hooks {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (event, entries) in &self.0 {
            m.serialize_entry(event, entries)?;
        }
        m.end()
    }
}

#[derive(Serialize)]
struct Snippet {
    hooks: Hooks,
}

/// The `{"hooks": …}` object `ccwm hooks print` writes (§21.9), for the ccwm binary at `ccwm`
/// (its canonical path). Refused for a path that is not UTF-8 or that holds a character §8
/// keeps out of a terminal: the command must carry the path byte for byte, and it is shown.
pub fn snippet(ccwm: &Path) -> Result<String, String> {
    let path = ccwm.to_str().ok_or_else(|| {
        format!(
            "the path of this ccwm ({}) is not valid UTF-8: it cannot be written into a settings file byte for byte",
            ccwm.display()
        )
    })?;
    if path.chars().any(is_unsafe_char) {
        return Err(format!(
            "the path of this ccwm ({}) contains a control or bidirectional-format character: move the binary (e.g. to ~/.local/bin/ccwm) and run `ccwm hooks print` from there",
            super::resume::escape(path)
        ));
    }
    let entry = |event: &'static str, matcher: Option<&'static str>| Matcher {
        matcher,
        hooks: [Handler {
            kind: "command",
            command: guarded_command(path, event),
            timeout: SNIPPET_TIMEOUT_SECS,
        }],
    };
    let hooks = EVENT_NAMES
        .into_iter()
        .map(|event| {
            let entries = if event == "Notification" {
                Notice::ALL
                    .into_iter()
                    .map(|n| entry(event, Some(n.as_str())))
                    .collect()
            } else {
                vec![entry(event, None)]
            };
            (event, entries)
        })
        .collect();
    serde_json::to_string_pretty(&Snippet {
        hooks: Hooks(hooks),
    })
    .map(|mut s| {
        s.push('\n');
        s
    })
    .map_err(|e| format!("cannot encode the snippet: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SID: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";
    const PID: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
    const CANARIES: [&str; 6] = [
        "SYNTHETIC-PROMPT-CANARY",
        "SYNTHETIC-ASSISTANT-CANARY",
        "SYNTHETIC-TOOL-CANARY",
        "SYNTHETIC-TRANSCRIPT-CANARY",
        "SYNTHETIC-TITLE-CANARY",
        "SYNTHETIC-CRON-CANARY",
    ];

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks/2.1.332")
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(fixture_dir().join(name)).unwrap()
    }

    fn report(arg: &str, input: &str) -> Result<Report, Skip> {
        Report::from_hook(arg, input.as_bytes(), None)
    }

    /// Every fixture (the 2.1.332 shapes with synthetic values) gives the expected event, and
    /// none of the canaries in the skipped fields reaches the request line.
    #[test]
    fn every_2_1_332_event_shape_gives_its_report_and_no_skipped_field() {
        let expected: [(&str, &str, Result<Event, Skip>); 13] = [
            (
                "SessionStart",
                "SessionStart.json",
                Ok(Event::SessionStart(Source::Startup)),
            ),
            (
                "SessionStart",
                "SessionStart-compact.json",
                Ok(Event::SessionStart(Source::Compact)),
            ),
            (
                "UserPromptSubmit",
                "UserPromptSubmit.json",
                Ok(Event::UserPromptSubmit),
            ),
            (
                "Notification",
                "Notification-permission_prompt.json",
                Ok(Event::Notification(Notice::PermissionPrompt)),
            ),
            (
                "Notification",
                "Notification-idle_prompt.json",
                Ok(Event::Notification(Notice::IdlePrompt)),
            ),
            (
                "Notification",
                "Notification-auth_success.json",
                Err(Skip::NotUsed),
            ),
            ("PostToolUse", "PostToolUse.json", Ok(Event::PostToolUse)),
            (
                "PostToolUse",
                "PostToolUse-subagent.json",
                Err(Skip::NotUsed),
            ),
            (
                "PostToolUseFailure",
                "PostToolUseFailure.json",
                Ok(Event::PostToolUseFailure),
            ),
            (
                "PostToolBatch",
                "PostToolBatch.json",
                Ok(Event::PostToolBatch),
            ),
            ("Stop", "Stop.json", Ok(Event::Stop)),
            ("StopFailure", "StopFailure.json", Ok(Event::StopFailure)),
            ("SessionEnd", "SessionEnd.json", Ok(Event::SessionEnd)),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (arg, file, want) in expected {
            seen.insert(file);
            let got = report(arg, &fixture(file));
            assert_eq!(
                got.as_ref().map(|r| r.event).map_err(|e| *e),
                want,
                "{file}"
            );
            if let Ok(r) = got {
                assert_eq!(r.session_id, SID, "{file}");
                assert!(r.cwd.starts_with("/home/synthetic/"), "{file}");
                let line = r.to_request_line();
                for c in CANARIES {
                    assert!(
                        !line.contains(c),
                        "{c} reached the request of {file}: {line}"
                    );
                }
                assert!(!line.contains("transcript"), "{line}");
                // What the daemon parses back is what was sent.
                let obj: Map<String, Value> = serde_json::from_str(&line).unwrap();
                assert_eq!(Report::from_request(&obj).unwrap(), r, "{file}");
            }
        }
        let on_disk: std::collections::BTreeSet<String> = std::fs::read_dir(fixture_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".json"))
            .collect();
        let tested: std::collections::BTreeSet<String> =
            seen.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(on_disk, tested, "every fixture is tested");
        // The fixtures really hold the canaries (otherwise the test proves nothing).
        let all: String = on_disk.iter().map(|f| fixture(f)).collect();
        for c in CANARIES {
            assert!(all.contains(c), "{c} is in a fixture");
        }
    }

    #[test]
    fn the_request_has_exactly_the_keys_of_its_event() {
        let keys = |arg: &str, file: &str| -> Vec<String> {
            let line = report(arg, &fixture(file)).unwrap().to_request_line();
            assert!(line.ends_with('\n') && !line[..line.len() - 1].contains('\n'));
            let obj: Map<String, Value> = serde_json::from_str(&line).unwrap();
            obj.keys().cloned().collect()
        };
        assert_eq!(
            keys("SessionStart", "SessionStart.json"),
            ["cwd", "event", "op", "session_id", "source"]
        );
        assert_eq!(
            keys("Notification", "Notification-idle_prompt.json"),
            [
                "cwd",
                "event",
                "notification_type",
                "op",
                "prompt_id",
                "session_id"
            ]
        );
        assert_eq!(
            keys("Stop", "Stop.json"),
            ["cwd", "event", "op", "prompt_id", "session_id"]
        );
        let with_pid = Report::from_hook(
            "Stop",
            fixture("Stop.json").as_bytes(),
            Some(OsStr::new("4242")),
        )
        .unwrap();
        assert_eq!(with_pid.claude_pid, Some(4242));
        assert!(with_pid.to_request_line().contains(r#""claude_pid":4242"#));
    }

    #[test]
    fn the_argument_must_name_one_of_the_nine_events_and_match_the_input() {
        let stop = fixture("Stop.json");
        assert_eq!(report("SessionEnd", &stop), Err(Skip::WrongEvent));
        assert_eq!(report("stop", &stop), Err(Skip::WrongEvent));
        assert_eq!(report("PreToolUse", &stop), Err(Skip::WrongEvent));
        assert_eq!(report("", &stop), Err(Skip::WrongEvent));
        let other = stop.replace(
            r#""hook_event_name": "Stop""#,
            r#""hook_event_name": "PreToolUse""#,
        );
        assert_ne!(other, stop);
        assert_eq!(report("Stop", &other), Err(Skip::WrongEvent));
        let missing = r#"{"session_id":"0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f","cwd":"/x"}"#;
        assert_eq!(report("Stop", missing), Err(Skip::WrongEvent));
    }

    fn minimal(extra: &str) -> String {
        format!(
            r#"{{"hook_event_name":"Stop","session_id":"{SID}","cwd":"/home/synthetic/p"{extra}}}"#
        )
    }

    #[test]
    fn hostile_and_malformed_inputs_send_nothing() {
        // Nesting in a declared field beyond serde_json's recursion limit (128) fails.
        let deep = format!(
            r#"{{"hook_event_name":"Stop","session_id":"{SID}","cwd":{}"/p"{}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "empty"),
            ("   ".into(), "whitespace"),
            ("garbage".into(), "not JSON"),
            ("[]".into(), "an array"),
            (format!(r#"["Stop","{SID}","/p"]"#), "positional fields"),
            ("\"Stop\"".into(), "a string"),
            ("null".into(), "null"),
            (minimal("").replace('}', ""), "unterminated"),
            (
                deep,
                "nesting beyond serde_json's limit in a declared field",
            ),
            (
                format!(
                    r#"{{"hook_event_name":"Stop","session_id":"{SID}","session_id":"{SID}","cwd":"/p"}}"#
                ),
                "duplicate key",
            ),
            (minimal("").replace("/home", "\u{0}"), "NUL in JSON source"),
            (
                minimal("").replace("/home/synthetic/p", "/x\\u0000y"),
                "NUL in the cwd",
            ),
            (
                minimal("").replace("/home/synthetic/p", "relative"),
                "relative cwd",
            ),
            (
                minimal("").replace(
                    "/home/synthetic/p",
                    &format!("/{}", "a".repeat(MAX_CWD_BYTES)),
                ),
                "cwd over 4,096 bytes",
            ),
            (
                minimal("").replace(SID, &SID.to_uppercase()),
                "upper-case session id",
            ),
            (
                minimal("").replace(SID, "not-a-uuid"),
                "session id not a UUID",
            ),
            (
                minimal("").replace(&format!(r#""{SID}""#), "7"),
                "session id a number",
            ),
            (minimal(r#","prompt_id":"x""#), "prompt id not a UUID"),
            (
                minimal(&format!(r#","prompt_id":"{}""#, PID.to_uppercase())),
                "upper-case prompt id",
            ),
            (
                minimal("").replace(r#","cwd":"/home/synthetic/p""#, ""),
                "no cwd",
            ),
        ];
        for (input, what) in cases {
            let got = report("Stop", &input);
            assert!(
                matches!(got, Err(Skip::Malformed(_)) | Err(Skip::WrongEvent)),
                "{what}: {got:?}"
            );
        }
        // Invalid UTF-8 in a declared field fails the parse; inside a skipped string it is
        // skipped unread like the rest of that string.
        let with_byte = |input: String, marker: u8| {
            let mut bytes = input.into_bytes();
            let at = bytes.iter().rposition(|b| *b == marker).unwrap();
            bytes[at] = 0xff;
            Report::from_hook("Stop", bytes.as_slice(), None)
        };
        assert!(matches!(
            with_byte(minimal("").replace("/home/synthetic/p", "/home/q"), b'q'),
            Err(Skip::Malformed(_))
        ));
        assert_eq!(
            with_byte(minimal(r#","prompt":"x""#), b'x').unwrap().event,
            Event::Stop
        );
        // A skipped field is skipped without recursion (serde_json ignores values iteratively):
        // a million levels of nesting cost no stack and no value.
        let skipped_deep = minimal(&format!(
            r#","prompt":{}{}"#,
            "[".repeat(1_000_000),
            "]".repeat(1_000_000)
        ));
        assert_eq!(report("Stop", &skipped_deep).unwrap().event, Event::Stop);
        // Fields of other types are absent, not errors.
        assert_eq!(
            report("Stop", &minimal(r#","prompt":{"a":[1,2]},"unknown":[{}]"#))
                .unwrap()
                .session_id,
            SID
        );
        // A SessionStart needs a known source; a Notification a type.
        let start = |source: &str| {
            format!(
                r#"{{"hook_event_name":"SessionStart","session_id":"{SID}","cwd":"/p"{source}}}"#
            )
        };
        assert_eq!(
            report("SessionStart", &start("")),
            Err(Skip::Malformed("source"))
        );
        assert_eq!(
            report("SessionStart", &start(r#","source":"reboot""#)),
            Err(Skip::Malformed("source"))
        );
        let note = |t: &str| {
            format!(r#"{{"hook_event_name":"Notification","session_id":"{SID}","cwd":"/p"{t}}}"#)
        };
        assert_eq!(
            report("Notification", &note("")),
            Err(Skip::Malformed("notification_type"))
        );
        assert_eq!(
            report(
                "Notification",
                &note(r#","notification_type":"elicitation_dialog""#)
            ),
            Err(Skip::NotUsed)
        );
        // A subagent's permission prompt is the session's; its other events are not used.
        assert_eq!(
            report(
                "Notification",
                &note(r#","notification_type":"permission_prompt","agent_id":"a1""#)
            )
            .unwrap()
            .event,
            Event::Notification(Notice::PermissionPrompt)
        );
        assert_eq!(
            report("Stop", &minimal(r#","agent_id":"a1""#)),
            Err(Skip::NotUsed)
        );
        assert_eq!(
            report("Stop", &minimal(r#","agent_id":null"#))
                .unwrap()
                .event,
            Event::Stop,
            "a null agent_id is no agent_id"
        );
    }

    /// A 16 MiB prompt is skipped (and the input still accepted while it fits); one byte more
    /// than the limit is malformed. The parse stops at the end of the first value.
    #[test]
    fn a_huge_prompt_is_skipped_and_the_input_bounded() {
        let head = format!(
            r#"{{"hook_event_name":"UserPromptSubmit","session_id":"{SID}","cwd":"/p","prompt":""#
        );
        let tail = "\"}";
        let fill = usize::try_from(MAX_INPUT_BYTES).unwrap() - head.len() - tail.len();
        let fits = format!(
            "{head}{}{tail}",
            "SYNTHETIC-PROMPT-CANARY ".repeat(fill / 24) + &"x".repeat(fill % 24)
        );
        assert_eq!(fits.len() as u64, MAX_INPUT_BYTES);
        let r = report("UserPromptSubmit", &fits).unwrap();
        assert!(!r.to_request_line().contains("CANARY"));
        let over = format!("{head}{}{tail}", "x".repeat(fill + 1));
        assert!(matches!(
            report("UserPromptSubmit", &over),
            Err(Skip::Malformed(_))
        ));
        // A value followed by more input (or a stdin that stays open) is read up to its end.
        let then_garbage = format!("{}garbage", minimal(""));
        assert_eq!(report("Stop", &then_garbage).unwrap().event, Event::Stop);
    }

    #[test]
    fn claude_pid_is_used_only_in_claude_codes_own_spelling() {
        let p = |s: &str| parse_claude_pid(Some(OsStr::new(s)));
        assert_eq!(p("4242"), Some(4242));
        assert_eq!(p("2"), Some(2));
        assert_eq!(p("4194304"), Some(MAX_PID));
        for bad in [
            "",
            "1",
            "0",
            "4194305",
            "99999999999999999999",
            "+42",
            "-42",
            " 42",
            "42 ",
            "0x2a",
            "042",
            "4.2",
        ] {
            assert_eq!(p(bad), None, "{bad:?}");
        }
        assert_eq!(parse_claude_pid(None), None);
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(parse_claude_pid(Some(OsStr::from_bytes(b"42\xff"))), None);
    }

    fn request(v: Value) -> Result<Report, Malformed> {
        Report::from_request(v.as_object().unwrap())
    }

    #[test]
    fn the_daemon_accepts_exactly_the_keys_and_bounds_of_section_21_4() {
        let base = serde_json::json!({"op": "hook.event", "event": "Stop", "session_id": SID, "cwd": "/p"});
        assert_eq!(request(base.clone()).unwrap().event, Event::Stop);
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            request(b)
        };
        let without = |k: &str| {
            let mut b = base.clone();
            b.as_object_mut().unwrap().remove(k);
            request(b)
        };
        // Optional keys at and past their bounds.
        assert_eq!(with("claude_pid", 2.into()).unwrap().claude_pid, Some(2));
        assert_eq!(
            with("claude_pid", MAX_PID.into()).unwrap().claude_pid,
            Some(MAX_PID)
        );
        for bad in [
            Value::from(1),
            Value::from(0),
            Value::from(-5),
            Value::from(u64::from(MAX_PID) + 1),
            Value::from(2.5),
            Value::from("42"),
            Value::Null,
        ] {
            assert!(with("claude_pid", bad.clone()).is_err(), "claude_pid {bad}");
        }
        assert_eq!(
            with("prompt_id", PID.into()).unwrap().prompt_id.as_deref(),
            Some(PID)
        );
        for bad in [
            Value::from(PID.to_uppercase()),
            Value::from("x"),
            Value::Null,
            Value::from(1),
        ] {
            assert!(with("prompt_id", bad.clone()).is_err(), "prompt_id {bad}");
        }
        // The cwd at and past its bounds.
        let at_limit = format!("/{}", "c".repeat(MAX_CWD_BYTES - 1));
        assert_eq!(with("cwd", at_limit.clone().into()).unwrap().cwd, at_limit);
        for bad in [
            Value::from(format!("/{}", "c".repeat(MAX_CWD_BYTES))),
            Value::from("relative/p"),
            Value::from(""),
            Value::from("/a\u{0}b"),
            Value::from(5),
            Value::Null,
        ] {
            assert!(with("cwd", bad.clone()).is_err(), "cwd {bad}");
        }
        // Missing, extra and wrongly typed keys, with what was valid kept for the log.
        let err = without("cwd").unwrap_err();
        assert_eq!(
            err,
            Malformed {
                event: Some("Stop"),
                session_id: Some(SID.into())
            }
        );
        assert!(without("session_id").is_err());
        assert_eq!(without("event").unwrap_err().event, None);
        assert!(with("extra", 1.into()).is_err());
        assert!(
            with("source", "startup".into()).is_err(),
            "source only on SessionStart"
        );
        assert!(with("notification_type", "idle_prompt".into()).is_err());
        let e = with("event", "PreToolUse".into()).unwrap_err();
        assert_eq!((e.event, e.session_id.as_deref()), (None, Some(SID)));
        assert_eq!(
            with("session_id", SID.to_uppercase().into())
                .unwrap_err()
                .session_id,
            None
        );
        // SessionStart needs its source, Notification its type, each from the allowed values.
        let start = serde_json::json!({"op": "hook.event", "event": "SessionStart", "session_id": SID, "cwd": "/p", "source": "resume"});
        assert_eq!(
            request(start.clone()).unwrap().event,
            Event::SessionStart(Source::Resume)
        );
        for s in Source::ALL {
            let mut v = start.clone();
            v["source"] = s.as_str().into();
            assert_eq!(request(v).unwrap().event, Event::SessionStart(s));
        }
        let mut v = start.clone();
        v["source"] = "Resume".into();
        assert!(request(v).is_err());
        let mut v = start.clone();
        v.as_object_mut().unwrap().remove("source");
        assert!(request(v).is_err());
        let note = serde_json::json!({"op": "hook.event", "event": "Notification", "session_id": SID, "cwd": "/p", "notification_type": "auth_success"});
        assert!(request(note.clone()).is_err());
        let mut v = note;
        v["notification_type"] = "permission_prompt".into();
        assert_eq!(
            request(v).unwrap().event,
            Event::Notification(Notice::PermissionPrompt)
        );
    }

    #[test]
    fn the_snippet_is_the_guarded_command_for_every_event_in_order() {
        let s = snippet(Path::new("/home/synthetic/.local/bin/ccwm")).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let hooks = v["hooks"].as_object().unwrap();
        assert_eq!(v.as_object().unwrap().len(), 1);
        assert_eq!(hooks.len(), 9);
        // Pretty-printed in the order of §21.2.
        let mut at = 0;
        for name in EVENT_NAMES {
            let found = s[at..]
                .find(&format!("\"{name}\": ["))
                .unwrap_or_else(|| panic!("{name} in order"));
            at += found + 1;
        }
        for (name, entries) in hooks {
            let entries = entries.as_array().unwrap();
            let matchers: Vec<Option<&str>> = entries
                .iter()
                .map(|e| e.get("matcher").and_then(Value::as_str))
                .collect();
            if name == "Notification" {
                assert_eq!(matchers, [Some("permission_prompt"), Some("idle_prompt")]);
            } else {
                assert_eq!(matchers, [None], "{name}");
            }
            for e in entries {
                let h = &e["hooks"];
                assert_eq!(h.as_array().unwrap().len(), 1);
                assert_eq!(h[0]["type"], "command");
                assert_eq!(h[0]["timeout"], 5);
                assert_eq!(
                    h[0]["command"],
                    format!("command -v '/home/synthetic/.local/bin/ccwm' >/dev/null 2>&1 && '/home/synthetic/.local/bin/ccwm' hook {name}; exit 0")
                );
            }
        }
        assert!(s.ends_with("}\n"));
    }

    #[test]
    fn the_snippet_quotes_odd_paths_and_refuses_unsafe_ones() {
        let s = snippet(Path::new("/home/syn thetic/it's \"x\"/ccwm")).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["hooks"]["Stop"][0]["hooks"][0]["command"],
            r#"command -v '/home/syn thetic/it'\''s "x"/ccwm' >/dev/null 2>&1 && '/home/syn thetic/it'\''s "x"/ccwm' hook Stop; exit 0"#
        );
        for bad in [
            "/a\nb/ccwm",
            "/a\u{1b}[31m/ccwm",
            "/a\u{202e}b/ccwm",
            "/a\tb/ccwm",
            "/a\u{85}b/ccwm",
        ] {
            let e = snippet(Path::new(bad)).unwrap_err();
            assert!(e.contains("control or bidirectional"), "{bad:?}: {e}");
        }
        use std::os::unix::ffi::OsStrExt;
        let e = snippet(Path::new(OsStr::from_bytes(b"/a\xffb/ccwm"))).unwrap_err();
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn debug_output_never_shows_the_cwd() {
        let r = report(
            "Stop",
            &minimal("").replace("/home/synthetic/p", "/home/u/SECRET"),
        )
        .unwrap();
        let shown = format!("{r:?}");
        assert!(
            !shown.contains("SECRET") && shown.contains("<14 bytes>"),
            "{shown}"
        );
    }

    #[test]
    fn event_names_details_and_tool_events() {
        for name in EVENT_NAMES {
            assert_eq!(event_name(name), Some(name));
        }
        assert_eq!(event_name("PreToolUse"), None);
        assert_eq!(Event::SessionStart(Source::Fork).detail(), Some("fork"));
        assert_eq!(
            Event::Notification(Notice::IdlePrompt).detail(),
            Some("idle_prompt")
        );
        assert_eq!(Event::Stop.detail(), None);
        let tools: Vec<&str> = [
            Event::SessionStart(Source::Startup),
            Event::UserPromptSubmit,
            Event::Notification(Notice::IdlePrompt),
            Event::PostToolUse,
            Event::PostToolUseFailure,
            Event::PostToolBatch,
            Event::Stop,
            Event::StopFailure,
            Event::SessionEnd,
        ]
        .into_iter()
        .filter(|e| e.is_tool())
        .map(Event::name)
        .collect();
        assert_eq!(
            tools,
            ["PostToolUse", "PostToolUseFailure", "PostToolBatch"]
        );
    }
}
