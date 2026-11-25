//! Incremental parsing of one session file into idempotent per-session aggregates
//! (REQUIREMENTS.md §7.2, §7.3).
//!
//! A checkpoint remembers the file's identity, size, mtime and the byte offset just after the last
//! complete line. An append is parsed from that offset; a trailing line without its newline is
//! never consumed (Claude Code may still be writing it). A new inode, a shrunk file or a rewrite of
//! the same size resets the aggregate and parses from 0. Aggregates are minimum/maximum
//! timestamps, first/last cwd and last-wins values, so reading a line twice changes nothing.

use super::record::{parse_timestamp, DerivedFrom, Head, CONVERSATIONAL, KNOWN_TYPES};
use super::redact::redact;
use super::resume::is_uuid;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

/// Longer lines are skipped and counted (the longest real line seen was 1.9 MB).
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Stored titles are cut to this many characters (after redaction).
pub const MAX_TITLE_CHARS: usize = 300;
/// At most this many `derived-from` session ids are kept per session.
pub const MAX_DERIVED: usize = 16;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Same identity, size and mtime as the checkpoint: nothing read.
    Unchanged,
    Updated {
        checkpoint: Checkpoint,
        aggregate: Box<Aggregate>,
        /// The previous aggregate was discarded (rotation, truncation or rewrite).
        reset: bool,
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
    }
}

/// Parse what is new in `file` (whose id is `session_id`) since `prev`.
pub fn parse(
    file: &mut File,
    session_id: &str,
    prev: Option<(&Checkpoint, &Aggregate)>,
) -> io::Result<Outcome> {
    let now = identity(&file.metadata()?);
    let (start, mut agg, reset) = match prev {
        Some((c, a)) if c.dev == now.dev && c.ino == now.ino && now.size >= c.offset => {
            if now.size == c.size && now.mtime_ns == c.mtime_ns {
                return Ok(Outcome::Unchanged);
            }
            if now.size == c.size {
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
                apply_line(&mut agg, session_id, &line);
            }
            line.clear();
            oversized = false;
            offset = pos;
        }
    }
    Ok(Outcome::Updated {
        checkpoint: Checkpoint {
            offset,
            size: now.size.max(offset),
            ..now
        },
        aggregate: Box::new(agg),
        reset,
    })
}

fn set_last(slot: &mut Option<String>, v: Option<String>) {
    if v.is_some() {
        *slot = v;
    }
}

/// Fold one complete line into the aggregate.
fn apply_line(agg: &mut Aggregate, session_id: &str, line: &[u8]) {
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
    if CONVERSATIONAL.contains(&kind) {
        if let Some(t) = head.timestamp.as_deref().and_then(parse_timestamp) {
            agg.started_at = Some(agg.started_at.map_or(t, |s| s.min(t)));
            agg.last_activity_at = Some(agg.last_activity_at.map_or(t, |s| s.max(t)));
        }
        if let Some(cwd) = head.cwd.filter(|c| !c.is_empty()) {
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
        parse(&mut f, ID, prev.as_ref().map(|(c, a)| (c, a))).unwrap()
    }

    fn updated(o: Outcome) -> (Checkpoint, Aggregate, bool) {
        match o {
            Outcome::Updated {
                checkpoint,
                aggregate,
                reset,
            } => (checkpoint, *aggregate, reset),
            Outcome::Unchanged => panic!("expected an update"),
        }
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
}
