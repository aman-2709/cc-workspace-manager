//! Incremental parsing of one session file into idempotent per-session aggregates
//! (REQUIREMENTS.md §7.2, §7.3).
//!
//! A checkpoint remembers the file's identity, size, mtime and the byte offset just after the last
//! complete line. An append is parsed from that offset; a trailing line without its newline is
//! never consumed (Claude Code may still be writing it). A new inode, a shrunk file or a rewrite of
//! the same size resets the aggregate and parses from 0. Aggregates are minimum/maximum
//! timestamps, first/last cwd and last-wins values, so reading a line twice changes nothing.
//!
//! **Early stop.** The caller passes a predicate over the first recorded cwd. Once it says the
//! session can never belong to a project (an excluded folder, outside the roots, home, a
//! temporary directory), the rest of the file is not read: the checkpoint is marked `partial`
//! and later appends are not read either, until the predicate changes its mind (a restart with
//! other roots) — then the file is parsed again from byte 0.

use super::record::{
    parse_timestamp, parse_timestamp_ms, DerivedFrom, Head, CONVERSATIONAL, KNOWN_TYPES,
};
use super::redact::redact;
use super::resume::{is_lower_uuid, is_uuid};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

/// Version of the session parsing rules. **Bump it** whenever a change to the parser, to the
/// cleaning or capping of stored strings, or to which files count as sessions would store a
/// different aggregate for the same file. The database writer compares it with the version the
/// index was built with (`meta.session_parser_version`) when it opens the database and, if they
/// differ, clears the derived session index, so every file is parsed again from byte 0 and no
/// row keeps a value computed by older rules (REQUIREMENTS.md §7.2).
/// History: 1 = M3 (no `meta` entry), 2 = M3.1 (cleaned and capped strings, lower-case ids,
/// one file per id, early stop).
pub const PARSER_VERSION: u32 = 2;
/// Longer lines are skipped and counted (the longest real line seen was 1.9 MB).
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Stored titles are cut to this many characters (after redaction).
pub const MAX_TITLE_CHARS: usize = 300;
/// At most this many `derived-from` session ids are kept per session.
pub const MAX_DERIVED: usize = 16;
/// A longer recorded cwd (`PATH_MAX`) is ignored like an absent one (M3 review, L3).
pub const MAX_CWD_BYTES: usize = 4096;
/// The Git branch, version and entrypoint are stored without control characters and cut to
/// this many characters.
pub const MAX_META_CHARS: usize = 256;
const READ_BUFFER: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checkpoint {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    /// Just after the last complete line read.
    pub offset: u64,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_ns: i64,
    /// Reading stopped early because the first cwd names no project (see the module docs);
    /// `offset` is where it stopped.
    pub partial: bool,
}

/// Line counters of one file (cumulative since its last reset).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub lines: u64,
    pub malformed: u64,
    pub oversized: u64,
    /// Record types not in the verified schema, or records without a type.
    pub unknown: u64,
    /// Records whose `sessionId` is not the file's (none in the schema output; skipped).
    pub foreign: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aggregate {
    pub first_cwd: Option<String>,
    pub last_cwd: Option<String>,
    /// Minimum timestamp over conversational records.
    pub started_at: Option<i64>,
    /// Maximum timestamp over conversational records.
    pub last_activity_at: Option<i64>,
    /// Latest `ai-title` (file order), redacted and shortened.
    pub title: Option<String>,
    pub git_branch: Option<String>,
    pub version: Option<String>,
    pub entrypoint: Option<String>,
    /// The session this one was continued in (`continued-in`), a validated UUID.
    pub continued_in: Option<String>,
    /// Sessions this one derives from (`derived-from`), validated UUIDs.
    pub derived_from: Vec<String>,
    /// A subagent/sidechain session. Always `false` in v0.1: only top-level session files are
    /// ingested (§7.1); `isSidechain` records inside them do not make the session one.
    pub is_sidechain: bool,
    pub counts: Counts,
}

/// How a turn ended, as Claude Code recorded it (REQUIREMENTS.md §21.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnEnd {
    /// The user ended it: Esc during a reply or a running tool, "No" or Esc in a permission
    /// dialog.
    Interrupted,
    /// `system` `turn_duration`: the turn finished (written after the `Stop` hooks).
    Ended,
}

/// A recorded end of a turn: what the activity indicator may learn from a session file. Never
/// stored; only the latest of one read is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnFact {
    pub end: TurnEnd,
    /// The turn's prompt id when the record has one (`user` records), a lower-case UUID.
    pub prompt_id: Option<String>,
    /// The record's timestamp, milliseconds since the epoch.
    pub at_ms: i64,
}

/// The end of a turn `head` (a record of type `kind`) records, from structural fields only:
/// `interruptedMessageId` with `rowSource: "harness"` or `toolDenialKind: "user-rejected"` on a
/// `user` record, `isAbortedMidStream: true` on an `assistant` record, `subtype:
/// "turn_duration"` on a `system` record. Claude Code's interruption strings are never read.
pub fn turn_end(kind: &str, head: &Head) -> Option<TurnEnd> {
    match kind {
        "user" => {
            let marker = head.interrupted_message_id.is_some()
                && head.row_source.as_deref() == Some("harness");
            let rejected = head.tool_denial_kind.as_deref() == Some("user-rejected");
            (marker || rejected).then_some(TurnEnd::Interrupted)
        }
        "assistant" => (head.is_aborted_mid_stream == Some(true)).then_some(TurnEnd::Interrupted),
        "system" => (head.subtype.as_deref() == Some("turn_duration")).then_some(TurnEnd::Ended),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Same identity, size and mtime as the checkpoint: nothing read.
    Unchanged,
    Updated {
        checkpoint: Checkpoint,
        aggregate: Box<Aggregate>,
        /// The previous aggregate was discarded (rotation, truncation or rewrite).
        reset: bool,
        /// The latest recorded end of a turn among the records read now (§21.2a).
        fact: Option<TurnFact>,
    },
}

/// The checkpoint fields of an open file (its `fstat`).
pub fn identity(md: &std::fs::Metadata) -> Checkpoint {
    Checkpoint {
        dev: md.dev(),
        ino: md.ino(),
        size: md.len(),
        offset: 0,
        mtime_ns: md.mtime().saturating_mul(1_000_000_000) + md.mtime_nsec(),
        partial: false,
    }
}

/// Never stop early.
pub fn read_all(_first_cwd: &str) -> bool {
    false
}

/// Parse what is new in `file` (whose id is `session_id`) since `prev`. `stop(first_cwd)`:
/// the session names no project, so nothing after its first cwd needs reading.
pub fn parse(
    file: &mut File,
    session_id: &str,
    prev: Option<(&Checkpoint, &Aggregate)>,
    stop: &dyn Fn(&str) -> bool,
) -> io::Result<Outcome> {
    let now = identity(&file.metadata()?);
    let (start, mut agg, reset) = match prev {
        Some((c, a)) if c.dev == now.dev && c.ino == now.ino && now.size >= c.offset => {
            let stops = a.first_cwd.as_deref().is_some_and(stop);
            if c.partial && !stops {
                // Stopped early before, but the session may belong to a project now (other
                // roots after a restart): read it all, changed or not.
                (0, Aggregate::default(), true)
            } else if now.size == c.size && now.mtime_ns == c.mtime_ns {
                return Ok(Outcome::Unchanged);
            } else if stops {
                // Still nothing to learn from this file: note its new size, read nothing.
                return Ok(Outcome::Updated {
                    checkpoint: Checkpoint {
                        offset: c.offset,
                        partial: true,
                        ..now
                    },
                    aggregate: Box::new(a.clone()),
                    reset: false,
                    fact: None,
                });
            } else if now.size == c.size {
                (0, Aggregate::default(), true) // same size, new mtime: rewritten in place
            } else {
                (c.offset, a.clone(), false)
            }
        }
        Some(_) => (0, Aggregate::default(), true),
        None => (0, Aggregate::default(), false),
    };
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(READ_BUFFER, &mut *file);
    let mut pos = start;
    let mut offset = start;
    let mut line: Vec<u8> = Vec::new();
    let mut oversized = false;
    let mut partial = false;
    let mut fact = None;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break; // EOF: an unterminated line stays unread
        }
        let (take, complete) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        if !oversized {
            if line.len() + take > MAX_LINE_BYTES {
                oversized = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&buf[..take]);
            }
        }
        let consumed = take + usize::from(complete);
        reader.consume(consumed);
        pos += consumed as u64;
        if complete {
            if oversized {
                agg.counts.lines += 1;
                agg.counts.oversized += 1;
            } else if !line.iter().all(u8::is_ascii_whitespace) {
                let had_cwd = agg.first_cwd.is_some();
                apply_line(&mut agg, &mut fact, session_id, &line);
                if !had_cwd && agg.first_cwd.as_deref().is_some_and(stop) {
                    partial = true;
                }
            }
            line.clear();
            oversized = false;
            offset = pos;
            if partial {
                break;
            }
        }
    }
    Ok(Outcome::Updated {
        checkpoint: Checkpoint {
            offset,
            size: now.size.max(offset),
            partial,
            ..now
        },
        aggregate: Box::new(agg),
        reset,
        fact,
    })
}

/// Keep the latest non-empty value, without control characters and at most
/// [`MAX_META_CHARS`] long (it reaches terminals through `ccwm status`-style output).
fn set_last(slot: &mut Option<String>, v: Option<String>) {
    if let Some(v) = v.map(|v| crate::git::parse::clean(&v, MAX_META_CHARS)) {
        if !v.is_empty() {
            *slot = Some(v);
        }
    }
}

/// Fold one complete line into the aggregate; a recorded end of a turn replaces `fact`.
fn apply_line(agg: &mut Aggregate, fact: &mut Option<TurnFact>, session_id: &str, line: &[u8]) {
    agg.counts.lines += 1;
    let Ok(head) = serde_json::from_slice::<Head>(line) else {
        agg.counts.malformed += 1;
        return;
    };
    let Some(kind) = head.kind.as_deref() else {
        agg.counts.unknown += 1;
        return;
    };
    if head.session_id.as_deref().is_some_and(|s| s != session_id) {
        agg.counts.foreign += 1;
        return;
    }
    if !KNOWN_TYPES.contains(&kind) {
        agg.counts.unknown += 1;
        return;
    }
    if let Some(end) = turn_end(kind, &head) {
        if let Some(at_ms) = head.timestamp.as_deref().and_then(parse_timestamp_ms) {
            *fact = Some(TurnFact {
                end,
                prompt_id: head.prompt_id.clone().filter(|p| is_lower_uuid(p)),
                at_ms,
            });
        }
    }
    if CONVERSATIONAL.contains(&kind) {
        if let Some(t) = head.timestamp.as_deref().and_then(parse_timestamp) {
            agg.started_at = Some(agg.started_at.map_or(t, |s| s.min(t)));
            agg.last_activity_at = Some(agg.last_activity_at.map_or(t, |s| s.max(t)));
        }
        if let Some(cwd) = head
            .cwd
            .filter(|c| !c.is_empty() && c.len() <= MAX_CWD_BYTES)
        {
            if agg.first_cwd.is_none() {
                agg.first_cwd = Some(cwd.clone());
            }
            agg.last_cwd = Some(cwd);
        }
        set_last(&mut agg.git_branch, head.git_branch);
        set_last(&mut agg.version, head.version);
        set_last(&mut agg.entrypoint, head.entrypoint);
        return;
    }
    match kind {
        "ai-title" => {
            if let Some(t) = head.ai_title.filter(|t| !t.trim().is_empty()) {
                agg.title = Some(redact(t.trim()).chars().take(MAX_TITLE_CHARS).collect());
            }
        }
        "continued-in" => {
            if let Some(id) = head
                .continued_in
                .filter(|id| is_uuid(id) && id != session_id)
            {
                agg.continued_in = Some(id.to_ascii_lowercase());
            }
        }
        "derived-from" => {
            if let Ok(d) = serde_json::from_slice::<DerivedFrom>(line) {
                for id in d.sessions.into_iter().filter_map(|r| r.id) {
                    let id = id.to_ascii_lowercase();
                    if is_uuid(&id)
                        && id != session_id
                        && !agg.derived_from.contains(&id)
                        && agg.derived_from.len() < MAX_DERIVED
                    {
                        agg.derived_from.push(id);
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    fn line(ty: &str, ts: &str, cwd: &str) -> String {
        format!(
            r#"{{"type":"{ty}","sessionId":"{ID}","timestamp":"{ts}","cwd":"{cwd}","version":"2.1.331","gitBranch":"main"}}"#
        )
    }

    fn run(path: &std::path::Path, prev: Option<(Checkpoint, Aggregate)>) -> Outcome {
        let mut f = File::open(path).unwrap();
        parse(&mut f, ID, prev.as_ref().map(|(c, a)| (c, a)), &read_all).unwrap()
    }

    fn updated(o: Outcome) -> (Checkpoint, Aggregate, bool) {
        match o {
            Outcome::Updated {
                checkpoint,
                aggregate,
                reset,
                ..
            } => (checkpoint, *aggregate, reset),
            Outcome::Unchanged => panic!("expected an update"),
        }
    }

    fn fact_of(o: Outcome) -> Option<TurnFact> {
        match o {
            Outcome::Updated { fact, .. } => fact,
            Outcome::Unchanged => panic!("expected an update"),
        }
    }

    // ---- v0.2: the recorded ends of a turn (REQUIREMENTS.md §21.2a) ---------------------------

    const TURN_SID: &str = "5e55a0b1-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
    const TURN_P: &str = "6b38c910-1111-4aaa-8bbb-000000000001";
    const FIXED: [&str; 2] = [
        "[Request interrupted by user]",
        "[Request interrupted by user for tool use]",
    ];

    fn turn_fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/turns/2.1.332")
            .join(format!("{name}.jsonl"))
    }

    fn turn_fact(name: &str) -> Option<TurnFact> {
        let mut f = File::open(turn_fixture(name)).unwrap();
        fact_of(parse(&mut f, TURN_SID, None, &read_all).unwrap())
    }

    fn ms(ts: &str) -> i64 {
        parse_timestamp_ms(ts).unwrap()
    }

    #[test]
    fn every_recorded_end_of_a_turn_gives_its_fact() {
        let interrupted = |at: &str| {
            Some(TurnFact {
                end: TurnEnd::Interrupted,
                prompt_id: Some(TURN_P.into()),
                at_ms: ms(at),
            })
        };
        let ended = |at: &str| {
            Some(TurnFact {
                end: TurnEnd::Ended,
                prompt_id: None,
                at_ms: ms(at),
            })
        };
        // The latest fact of the read: for an interrupt, the user marker (it has the prompt id).
        assert_eq!(
            turn_fact("esc-during-reply"),
            interrupted("2026-11-27T01:06:00.607Z")
        );
        assert_eq!(
            turn_fact("deny-in-dialog"),
            interrupted("2026-11-27T01:09:31.063Z")
        );
        assert_eq!(
            turn_fact("esc-on-dialog"),
            interrupted("2026-11-27T01:12:42.284Z")
        );
        assert_eq!(
            turn_fact("esc-during-approved-tool"),
            interrupted("2026-11-27T01:11:30.247Z")
        );
        assert_eq!(turn_fact("normal-turn"), ended("2026-11-27T01:07:29.3Z"));
        assert_eq!(turn_fact("approved-tool"), ended("2026-11-27T01:08:50.3Z"));
        assert_eq!(
            turn_fact("clear-and-exit"),
            None,
            "rowSource harness alone is no interruption"
        );
        let next = turn_fact("esc-then-next-turn").unwrap();
        assert_eq!(
            (next.end, next.at_ms),
            (TurnEnd::Ended, ms("2026-11-27T01:20:12.3Z"))
        );
    }

    /// The structural rule and Claude Code's fixed strings agree: an interruption is found in
    /// exactly the fixtures whose records carry one of the strings, and for the same turn (the
    /// marker's `promptId`). The parser never reads the text; this test does, to corroborate.
    #[test]
    fn the_structural_rule_matches_the_fixed_interruption_strings() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/turns/2.1.332");
        let mut files = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let mut structural = Vec::new(); // prompt ids of the records the rule marks
            let mut strings = Vec::new(); // prompt ids of the records with a fixed string
            for line in text.lines() {
                let head: Head = serde_json::from_str(line).unwrap();
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let kind = head.kind.clone().unwrap();
                if turn_end(&kind, &head) == Some(TurnEnd::Interrupted) {
                    structural.push(head.prompt_id.clone());
                }
                let blocks = v
                    .pointer("/message/content")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default();
                if blocks.iter().any(|b| {
                    b.get("text")
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| FIXED.contains(&t))
                }) {
                    strings.push(head.prompt_id.clone());
                    assert_eq!(
                        head.row_source.as_deref(),
                        Some("harness"),
                        "{path:?}: the marker is Claude Code's"
                    );
                }
            }
            files += 1;
            assert_eq!(structural.is_empty(), strings.is_empty(), "{path:?}");
            for p in &strings {
                assert!(
                    structural.contains(p),
                    "{path:?}: the marker's turn is the one the rule finds"
                );
            }
        }
        assert_eq!(files, 8, "every fixture is checked");
    }

    #[test]
    fn a_turn_end_is_learned_from_an_append_and_again_from_a_read_from_byte_0() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(format!("{TURN_SID}.jsonl"));
        let text = std::fs::read_to_string(turn_fixture("deny-in-dialog")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        let (c, a, _) = updated(run_id(&p, None, TURN_SID));
        let mut f = File::open(&p).unwrap();
        assert_eq!(
            fact_of(parse(&mut f, TURN_SID, None, &read_all).unwrap()),
            None,
            "prompt and tool use only"
        );
        // The rejection is appended: only the new records are read, and they hold the fact.
        let mut w = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(w, "{}\n{}", lines[2], lines[3]).unwrap();
        let fact = fact_of(run_id(&p, Some((c, a)), TURN_SID)).unwrap();
        assert_eq!(
            (fact.end, fact.prompt_id.as_deref()),
            (TurnEnd::Interrupted, Some(TURN_P))
        );
        // A read from byte 0 (no checkpoint) finds the same, latest fact again: the indicator
        // tells it from a new one by its turn (§21.2a), not by how often it is read.
        assert_eq!(fact_of(run_id(&p, None, TURN_SID)), Some(fact));
    }

    #[test]
    fn turn_end_fields_of_other_types_or_values_are_ignored() {
        let head = |json: &str| serde_json::from_str::<Head>(json).unwrap();
        let end = |kind: &str, json: &str| turn_end(kind, &head(json));
        assert_eq!(
            end(
                "user",
                r#"{"interruptedMessageId":"m","rowSource":"harness"}"#
            ),
            Some(TurnEnd::Interrupted)
        );
        assert_eq!(
            end(
                "user",
                r#"{"interruptedMessageId":"m","rowSource":"local"}"#
            ),
            None,
            "only Claude Code's own marker"
        );
        assert_eq!(
            end(
                "user",
                r#"{"interruptedMessageId":null,"rowSource":"harness"}"#
            ),
            None
        );
        assert_eq!(end("user", r#"{"rowSource":"harness"}"#), None);
        assert_eq!(
            end("user", r#"{"toolDenialKind":"user-rejected"}"#),
            Some(TurnEnd::Interrupted)
        );
        assert_eq!(
            end("user", r#"{"toolDenialKind":"classifier-denied"}"#),
            None,
            "other kinds do not end a turn"
        );
        assert_eq!(end("user", r#"{"toolDenialKind":7}"#), None);
        assert_eq!(
            end("assistant", r#"{"isAbortedMidStream":true}"#),
            Some(TurnEnd::Interrupted)
        );
        assert_eq!(end("assistant", r#"{"isAbortedMidStream":false}"#), None);
        assert_eq!(end("assistant", r#"{"isAbortedMidStream":"true"}"#), None);
        assert_eq!(
            end("user", r#"{"isAbortedMidStream":true}"#),
            None,
            "an assistant field"
        );
        assert_eq!(
            end("system", r#"{"subtype":"turn_duration"}"#),
            Some(TurnEnd::Ended)
        );
        assert_eq!(end("system", r#"{"subtype":"stop_hook_summary"}"#), None);
        assert_eq!(end("assistant", r#"{"subtype":"turn_duration"}"#), None);
        assert_eq!(
            end("attachment", r#"{"toolDenialKind":"user-rejected"}"#),
            None
        );
        // A prompt id that is not a lower-case UUID is dropped; the fact keeps its time.
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("x.jsonl");
        std::fs::write(&p, format!("{{\"type\":\"user\",\"sessionId\":\"{TURN_SID}\",\"timestamp\":\"2026-01-01T00:00:00.250Z\",\"promptId\":\"NOT-A-UUID\",\"toolDenialKind\":\"user-rejected\"}}\n")).unwrap();
        let fact = fact_of(run_id(&p, None, TURN_SID)).unwrap();
        assert_eq!(
            (fact.prompt_id, fact.at_ms),
            (None, ms("2026-01-01T00:00:00.250Z"))
        );
        // Without a timestamp there is no fact (it could not be ordered).
        std::fs::write(&p, format!("{{\"type\":\"system\",\"sessionId\":\"{TURN_SID}\",\"subtype\":\"turn_duration\"}}\n")).unwrap();
        assert_eq!(fact_of(run_id(&p, None, TURN_SID)), None);
    }

    /// The parser reads none of the text of these records: the canaries in prompts, replies
    /// and tool output reach no fact or aggregate.
    #[test]
    fn turn_records_leave_their_text_unread() {
        for name in [
            "esc-during-reply",
            "deny-in-dialog",
            "approved-tool",
            "esc-then-next-turn",
        ] {
            let mut f = File::open(turn_fixture(name)).unwrap();
            let shown = format!("{:?}", parse(&mut f, TURN_SID, None, &read_all).unwrap());
            for c in ["CANARY", "doesn't want", "Request interrupted"] {
                assert!(!shown.contains(c), "{name}: {c} in {shown}");
            }
        }
    }

    /// v0.2 review L6: the guard behind "message text and `toolUseResult` stay unread". serde_json
    /// does not validate UTF-8 inside a string it skips, but a string it decodes must be valid:
    /// raw invalid bytes in every field the parser must not read leave every record parsed — a
    /// parser that started decoding one of them would count the record as malformed (or lose
    /// the fact). The output-canary test above cannot see a field decoded and then dropped.
    #[test]
    fn unread_fields_stay_undecoded_even_with_invalid_utf8() {
        const RAW: &[u8] = b"\xff\xfe\xc3(";
        let record = |kind: &str, ts: &str, fields: &[(&str, &[u8])]| -> Vec<u8> {
            let mut l = format!(
                r#"{{"type":"{kind}","sessionId":"{TURN_SID}","timestamp":"{ts}","cwd":"/w/a""#
            )
            .into_bytes();
            for (k, v) in fields {
                l.extend_from_slice(format!(",\"{k}\":").as_bytes());
                l.extend_from_slice(v);
            }
            l.extend_from_slice(b"}\n");
            l
        };
        let s = |inner: &[u8]| [b"\"".as_slice(), inner, b"\""].concat();
        let text = s(RAW);
        let content = [br#"[{"type":"text","text":""#.as_slice(), RAW, br#""}]"#].concat();
        let message = [br#"{"role":"user","content":""#.as_slice(), RAW, br#""}"#].concat();
        let assistant_message = [
            br#"{"role":"assistant","content":"#.as_slice(),
            &content,
            b"}",
        ]
        .concat();
        let prompt_id = s(TURN_P.as_bytes());
        let lines = [
            // "No" in a permission dialog: the denial's result record.
            record(
                "user",
                "2026-01-01T00:00:01.000Z",
                &[
                    ("promptId", &prompt_id),
                    ("toolDenialKind", br#""user-rejected""#),
                    ("toolUseResult", &text),
                    ("message", &message),
                ],
            ),
            // A tool result whose structured output is an object.
            record(
                "user",
                "2026-01-01T00:00:02.000Z",
                &[
                    (
                        "toolUseResult",
                        &[br#"{"stdout":"#.as_slice(), &text, b"}"].concat(),
                    ),
                    ("message", &message),
                ],
            ),
            record(
                "assistant",
                "2026-01-01T00:00:03.000Z",
                &[
                    ("isAbortedMidStream", b"true"),
                    ("message", &assistant_message),
                ],
            ),
            record(
                "system",
                "2026-01-01T00:00:04.000Z",
                &[("subtype", br#""turn_duration""#), ("content", &text)],
            ),
            record(
                "attachment",
                "2026-01-01T00:00:05.000Z",
                &[(
                    "attachment",
                    &[br#"{"content":"#.as_slice(), &text, b"}"].concat(),
                )],
            ),
            // `interruptedMessageId` is read for its presence only, never decoded.
            record(
                "user",
                "2026-01-01T00:00:06.000Z",
                &[
                    ("promptId", &prompt_id),
                    ("interruptedMessageId", &text),
                    ("rowSource", br#""harness""#),
                    ("message", &message),
                ],
            ),
        ];
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("raw.jsonl");
        std::fs::write(&p, lines.concat()).unwrap();
        let (_, aggregate, _) = updated(run_id(&p, None, TURN_SID));
        assert_eq!(
            (aggregate.counts.lines, aggregate.counts.malformed),
            (6, 0),
            "every record parsed: no unread field was decoded"
        );
        assert_eq!(aggregate.first_cwd.as_deref(), Some("/w/a"));
        assert_eq!(
            fact_of(run_id(&p, None, TURN_SID)),
            Some(TurnFact {
                end: TurnEnd::Interrupted,
                prompt_id: Some(TURN_P.into()),
                at_ms: ms("2026-01-01T00:00:06.000Z"),
            })
        );
        // The same bytes in a field the parser does read make the record malformed: the
        // technique detects decoding.
        std::fs::write(
            &p,
            record("user", "2026-01-01T00:00:07.000Z", &[("promptId", &text)]),
        )
        .unwrap();
        let (_, aggregate, _) = updated(run_id(&p, None, TURN_SID));
        assert_eq!(aggregate.counts.malformed, 1);
    }

    fn run_id(path: &std::path::Path, prev: Option<(Checkpoint, Aggregate)>, id: &str) -> Outcome {
        let mut f = File::open(path).unwrap();
        parse(&mut f, id, prev.as_ref().map(|(c, a)| (c, a)), &read_all).unwrap()
    }

    #[test]
    fn aggregates_use_min_and_max_timestamps_and_first_and_last_cwd() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(format!("{ID}.jsonl"));
        let body = [
            line("user", "2026-01-01T10:00:05.000Z", "/w/a"),
            line("assistant", "2026-01-01T09:59:00.000Z", "/w/a"),
            line("system", "2026-01-01T10:30:00.000Z", "/w/b"),
            // Not conversational: its timestamp never counts.
            r#"{"type":"queue-operation","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","timestamp":"2030-01-01T00:00:00.000Z","content":"SKIPPED"}"#.to_string(),
            line("attachment", "2026-01-01T10:10:00.000Z", "/w/b"),
            r#"{"type":"ai-title","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","aiTitle":"First"}"#.to_string(),
            r#"{"type":"ai-title","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","aiTitle":"Use ghp_abcdefghijklmnopqrstuvwxyz0123"}"#.to_string(),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&p, body).unwrap();
        let (c, a, reset) = updated(run(&p, None));
        assert!(!reset);
        assert_eq!(a.started_at, Some(1_767_261_540));
        assert_eq!(a.last_activity_at, Some(1_767_263_400));
        assert_eq!(
            (a.first_cwd.as_deref(), a.last_cwd.as_deref()),
            (Some("/w/a"), Some("/w/b"))
        );
        assert_eq!(
            a.title.as_deref(),
            Some("Use [REDACTED]"),
            "last wins, redacted"
        );
        assert_eq!(
            (a.version.as_deref(), a.git_branch.as_deref()),
            (Some("2.1.331"), Some("main"))
        );
        assert_eq!(a.counts.lines, 7);
        assert_eq!(c.offset, std::fs::metadata(&p).unwrap().len());
        assert_eq!(run(&p, Some((c, a))), Outcome::Unchanged);
    }

    #[test]
    fn appends_are_parsed_from_the_offset_and_a_partial_line_waits() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        std::fs::write(&p, line("user", "2026-01-01T10:00:00.000Z", "/w") + "\n").unwrap();
        let (c1, a1, _) = updated(run(&p, None));
        // Append one full line and half of another.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let next = line("assistant", "2026-01-01T11:00:00.000Z", "/w");
        write!(f, "{next}\n{}", &next[..20]).unwrap();
        let (c2, a2, reset) = updated(run(&p, Some((c1, a1.clone()))));
        assert!(!reset);
        assert_eq!(a2.counts.lines, 2, "the partial line is not counted");
        assert_eq!(a2.last_activity_at, Some(1_767_265_200));
        assert_eq!(c2.offset, c1.offset + next.len() as u64 + 1);
        // The rest of the partial line arrives.
        writeln!(f, "{}", &next[20..]).unwrap();
        let (c3, a3, _) = updated(run(&p, Some((c2, a2.clone()))));
        assert_eq!(a3.counts.lines, 3);
        assert_eq!(c3.offset, std::fs::metadata(&p).unwrap().len());
        // Re-reading the same lines (e.g. after a crash before the checkpoint was stored)
        // changes no aggregate except the counters.
        let (_, again, _) = updated(run(&p, Some((c2, a3.clone()))));
        assert_eq!(
            (
                again.started_at,
                again.last_activity_at,
                again.first_cwd.clone()
            ),
            (a3.started_at, a3.last_activity_at, a3.first_cwd.clone())
        );
    }

    #[test]
    fn truncation_rotation_and_rewrites_reparse_from_zero() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        let two = format!(
            "{}\n{}\n",
            line("user", "2026-01-01T10:00:00.000Z", "/old"),
            line("user", "2026-01-01T12:00:00.000Z", "/old")
        );
        std::fs::write(&p, &two).unwrap();
        let (c, a, _) = updated(run(&p, None));
        // Truncated (smaller than the offset).
        std::fs::write(&p, line("user", "2026-02-01T10:00:00.000Z", "/new") + "\n").unwrap();
        let (c2, a2, reset) = updated(run(&p, Some((c, a.clone()))));
        assert!(reset);
        assert_eq!(a2.first_cwd.as_deref(), Some("/new"));
        assert_eq!(a2.counts.lines, 1);
        // Rotated: a new inode at the same path.
        let q = t.path().join("tmp.jsonl");
        std::fs::write(&q, &two).unwrap();
        std::fs::rename(&q, &p).unwrap();
        let (c3, a3, reset) = updated(run(&p, Some((c2, a2))));
        assert!(reset);
        assert_eq!(a3.first_cwd.as_deref(), Some("/old"));
        // Rewritten in place with the same size and a new mtime.
        let same = two.replace("/old", "/odd");
        std::fs::write(&p, &same).unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        let (_, a4, reset) = updated(run(&p, Some((c3, a3))));
        assert!(reset);
        assert_eq!(a4.first_cwd.as_deref(), Some("/odd"));
    }

    #[test]
    fn malformed_unknown_foreign_and_oversized_lines_are_counted_and_skipped() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        let big = format!(
            r#"{{"type":"user","sessionId":"{ID}","timestamp":"2030-01-01T00:00:00.000Z","cwd":"/big","pad":"{}"}}"#,
            "x".repeat(MAX_LINE_BYTES)
        );
        let body = [
            "{not json".to_string(),
            r#"{"type":"brand-new-type","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}"#.to_string(),
            r#"{"no":"type"}"#.to_string(),
            r#"{"type":"user","sessionId":"ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee","timestamp":"2031-01-01T00:00:00.000Z","cwd":"/foreign"}"#.to_string(),
            big,
            String::new(),
            line("user", "2026-01-01T10:00:00.000Z", "/ok"),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&p, body).unwrap();
        let (c, a, _) = updated(run(&p, None));
        assert_eq!(
            a.counts,
            Counts {
                lines: 6,
                malformed: 1,
                oversized: 1,
                unknown: 2,
                foreign: 1
            }
        );
        assert_eq!(a.first_cwd.as_deref(), Some("/ok"));
        assert_eq!(
            a.last_activity_at,
            Some(1_767_261_600),
            "skipped lines never count"
        );
        assert_eq!(c.offset, std::fs::metadata(&p).unwrap().len());
    }

    #[test]
    fn continuation_links_are_validated() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        let other = "11111111-2222-4333-8444-555555555555";
        let body = [
            format!(r#"{{"type":"continued-in","sessionId":"{ID}","continuedInSessionId":"not-a-uuid","timestamp":"2026-01-01T00:00:00.000Z"}}"#),
            format!(r#"{{"type":"continued-in","sessionId":"{ID}","continuedInSessionId":"{other}","timestamp":"2026-01-01T00:00:00.000Z"}}"#),
            format!(r#"{{"type":"derived-from","sessionId":"{ID}","v":1,"sessions":[{{"id":"{other}","type":"x","via":"y"}},{{"id":"$(bad)"}},{{"id":"{ID}"}},{{"id":"{other}"}}]}}"#),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&p, body).unwrap();
        let (_, a, _) = updated(run(&p, None));
        assert_eq!(a.continued_in.as_deref(), Some(other));
        assert_eq!(a.derived_from, [other.to_string()]);
    }

    #[test]
    fn reading_stops_after_a_first_cwd_that_names_no_project() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        let body = [
            r#"{"type":"ai-title","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","aiTitle":"before"}"#.to_string(),
            line("user", "2026-01-01T10:00:00.000Z", "/excluded/x"),
            line("assistant", "2026-01-01T11:00:00.000Z", "/excluded/x"),
            r#"{"type":"ai-title","sessionId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","aiTitle":"never read"}"#.to_string(),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&p, &body).unwrap();
        let excluded = |c: &str| c.starts_with("/excluded");
        let open = || File::open(&p).unwrap();
        let (c, a, _) = updated(parse(&mut open(), ID, None, &excluded).unwrap());
        assert!(c.partial);
        assert_eq!(a.counts.lines, 2, "nothing after the first cwd was read");
        assert_eq!(a.title.as_deref(), Some("before"));
        assert_eq!(a.first_cwd.as_deref(), Some("/excluded/x"));
        let first_line = body.find('\n').unwrap() + 1;
        let second = first_line + body[first_line..].find('\n').unwrap() + 1;
        assert_eq!(c.offset, second as u64);
        assert_eq!(c.size, body.len() as u64);
        assert_eq!(
            parse(&mut open(), ID, Some((&c, &a)), &excluded).unwrap(),
            Outcome::Unchanged
        );
        // An append is noted (new size) but not read.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "{}", line("user", "2026-02-01T10:00:00.000Z", "/x")).unwrap();
        let (c2, a2, reset) = updated(parse(&mut open(), ID, Some((&c, &a)), &excluded).unwrap());
        assert!(!reset && c2.partial);
        assert_eq!((c2.offset, a2.clone()), (c.offset, a.clone()));
        assert_eq!(c2.size, std::fs::metadata(&p).unwrap().len());
        // The predicate changed (other roots after a restart): read everything from byte 0.
        let (c3, a3, reset) = updated(parse(&mut open(), ID, Some((&c2, &a2)), &read_all).unwrap());
        assert!(reset && !c3.partial);
        assert_eq!(a3.counts.lines, 5);
        assert_eq!(a3.title.as_deref(), Some("never read"));
        assert_eq!(a3.last_activity_at, Some(1_769_940_000));
        // A session fully read before (an older ccwm) stops being read once it is excluded.
        writeln!(f, "{}", line("user", "2026-03-01T10:00:00.000Z", "/x")).unwrap();
        let (c4, a4, _) = updated(parse(&mut open(), ID, Some((&c3, &a3)), &excluded).unwrap());
        assert!(c4.partial);
        assert_eq!((c4.offset, a4), (c3.offset, a3));
    }

    #[test]
    fn over_long_cwds_are_ignored_and_metadata_is_cleaned_and_capped() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.jsonl");
        let long = format!("/{}", "d".repeat(MAX_CWD_BYTES));
        let body = [
            line("user", "2026-01-01T10:00:00.000Z", &long),
            format!(
                r#"{{"type":"user","sessionId":"{ID}","timestamp":"2026-01-01T10:00:01.000Z","gitBranch":"b\u001b[31mred\u0007","version":"{}","entrypoint":"cli\n"}}"#,
                "9".repeat(1000)
            ),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&p, body).unwrap();
        let (_, a, _) = updated(run(&p, None));
        assert_eq!(a.first_cwd, None, "a cwd longer than PATH_MAX is no cwd");
        assert_eq!(a.git_branch.as_deref(), Some("b[31mred"));
        assert_eq!(a.version.map(|v| v.len()), Some(MAX_META_CHARS));
        assert_eq!(a.entrypoint.as_deref(), Some("cli"));
        let ok = format!("/{}", "d".repeat(MAX_CWD_BYTES - 1));
        std::fs::write(&p, line("user", "2026-01-01T10:00:00.000Z", &ok) + "\n").unwrap();
        assert_eq!(updated(run(&p, None)).1.first_cwd, Some(ok));
    }
}
