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
                apply_line(&mut agg, session_id, &line);
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
