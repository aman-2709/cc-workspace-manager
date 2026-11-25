//! Genuine user prompts (REQUIREMENTS.md §7.3), read **on demand** from the original session file
//! with a bounded window, redacted and truncated. Nothing here stores anything.
//!
//! Claude Code writes tool results, meta records, slash-command echoes, task notifications and
//! SDK input as `user` records too. The rules (maintainer decision, from the §19 schema output):
//! a genuine prompt is a `user` record with `message.role = "user"`, not `isMeta`, not
//! `isSidechain`, not `isCompactSummary`, without `toolUseResult` and without `tool_result`
//! content, whose text does not start with a known synthetic tag, and whose `promptSource` is
//! `typed`, `queued` or `suggestion_accepted`. Records without `promptSource` (older versions)
//! are accepted by the same checks plus `turnOrigin ≠ task_notification`.

use super::record::{parse_timestamp, Content, Head, UserContent, UserRecord};
use super::redact::redact;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// At most this much of a session file is read per request (head or tail window).
pub const WINDOW_BYTES: u64 = 4 * 1024 * 1024;
/// Prompts are shown truncated to this many characters.
pub const MAX_CHARS: usize = 2000;

/// `promptSource` values that mark a human prompt.
pub const GENUINE_SOURCES: [&str; 3] = ["typed", "queued", "suggestion_accepted"];

/// Opening tags Claude Code writes into `user` records that the user did not type (the §19
/// script's table). `<pasted_content>` is **not** among them: the schema output shows it at the
/// start of a `queued`, human-origin prompt, i.e. text the user pasted.
pub const SYNTHETIC_TAGS: [&str; 13] = [
    "artifact-content-authored-by-others",
    "bash-input",
    "bash-stderr",
    "bash-stdout",
    "command-args",
    "command-message",
    "command-name",
    "local-command-caveat",
    "local-command-stderr",
    "local-command-stdout",
    "system-reminder",
    "task-notification",
    "user-prompt-submit-hook",
];

fn starts_with_synthetic_tag(text: &str) -> bool {
    let Some(rest) = text.trim_start().strip_prefix('<') else {
        return false;
    };
    SYNTHETIC_TAGS.iter().any(|t| {
        rest.strip_prefix(t)
            .is_some_and(|after| after.starts_with('>') || after.starts_with(' '))
    })
}

/// The flags of `r` allow a genuine prompt (everything but the text checks).
pub fn is_candidate(r: &UserRecord) -> bool {
    if r.kind.as_deref() != Some("user")
        || r.is_meta == Some(true)
        || r.is_sidechain == Some(true)
        || r.is_compact_summary == Some(true)
        || r.tool_use_result.is_some()
    {
        return false;
    }
    match r.prompt_source.as_deref() {
        Some(s) if !GENUINE_SOURCES.contains(&s) => return false,
        Some(_) => {}
        None if r.turn_origin.as_deref() == Some("task_notification") => return false,
        None => {}
    }
    r.message
        .as_ref()
        .is_some_and(|m| m.role.as_deref() == Some("user"))
}

/// The prompt text of a candidate's content, if it is genuine (no `tool_result` block, not
/// empty, no synthetic opening tag).
pub fn genuine_text(c: &UserContent) -> Option<String> {
    let text = match &c.message.as_ref()?.content {
        Content::Text(t) => t.clone(),
        Content::Blocks(blocks) => {
            if blocks
                .iter()
                .any(|b| b.kind.as_deref() == Some("tool_result"))
            {
                return None;
            }
            blocks
                .iter()
                .filter(|b| b.kind.as_deref() == Some("text"))
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join("\n")
        }
        Content::None => return None,
    };
    (!text.trim().is_empty() && !starts_with_synthetic_tag(&text)).then_some(text)
}

/// The genuine prompt of one JSONL line, with its timestamp. Three passes, each only when the
/// previous one passed: the record type, the flags, then the content.
pub fn genuine_in_line(line: &[u8]) -> Option<(String, Option<i64>)> {
    // Cheap first pass: most lines are not `user` records.
    let head: Head = serde_json::from_slice(line).ok()?;
    if head.kind.as_deref() != Some("user") {
        return None;
    }
    let flags: UserRecord = serde_json::from_slice(line).ok()?;
    if !is_candidate(&flags) {
        return None;
    }
    let content: UserContent = serde_json::from_slice(line).ok()?;
    let at = head.timestamp.as_deref().and_then(parse_timestamp);
    genuine_text(&content).map(|t| (t, at))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Prompt {
    /// Redacted, at most [`MAX_CHARS`] characters.
    pub text: String,
    pub truncated: bool,
    pub at: Option<i64>,
}

/// The outcome of an on-demand read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Prompt(Prompt),
    /// No genuine prompt in the window read; `whole_file`: the window covered the whole file.
    None {
        whole_file: bool,
    },
}

/// Redact first (a secret is never half-shown), then truncate by characters.
pub fn finish(text: &str, at: Option<i64>) -> Prompt {
    let red = redact(text);
    let truncated = red.chars().count() > MAX_CHARS;
    Prompt {
        text: if truncated {
            red.chars().take(MAX_CHARS).collect()
        } else {
            red
        },
        truncated,
        at,
    }
}

fn open(path: &Path) -> io::Result<(File, u64)> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok((f, md.len()))
}

/// Complete lines of `buf`; `skip_first`: the window starts inside a line, so drop it. A
/// trailing piece without a newline is never a line (it may still be being written).
fn complete_lines(buf: &[u8], skip_first: bool) -> impl Iterator<Item = &[u8]> {
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let start = if skip_first {
        buf[..end]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(end, |i| i + 1)
    } else {
        0
    };
    buf[start..end]
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
}

/// The last genuine prompt in the final [`WINDOW_BYTES`] of the file.
pub fn last_prompt(path: &Path) -> io::Result<Found> {
    let (mut f, size) = open(path)?;
    let from = size.saturating_sub(WINDOW_BYTES);
    f.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::with_capacity(usize::try_from(size - from).unwrap_or(0));
    f.take(WINDOW_BYTES).read_to_end(&mut buf)?;
    let last = complete_lines(&buf, from > 0)
        .filter_map(genuine_in_line)
        .last();
    Ok(match last {
        Some((t, at)) => Found::Prompt(finish(&t, at)),
        None => Found::None {
            whole_file: from == 0,
        },
    })
}

/// The first genuine prompt in the first [`WINDOW_BYTES`] of the file.
pub fn first_prompt(path: &Path) -> io::Result<Found> {
    let (f, size) = open(path)?;
    let mut buf = Vec::with_capacity(usize::try_from(size.min(WINDOW_BYTES)).unwrap_or(0));
    f.take(WINDOW_BYTES).read_to_end(&mut buf)?;
    let first = complete_lines(&buf, false).find_map(genuine_in_line);
    Ok(match first {
        Some((t, at)) => Found::Prompt(finish(&t, at)),
        None => Found::None {
            whole_file: size <= WINDOW_BYTES,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(json: &str) -> Option<String> {
        genuine_in_line(json.as_bytes()).map(|(t, _)| t)
    }

    /// `(isMeta, isSidechain, isCompactSummary, promptSource, turnOrigin, toolUseResult, content,
    /// genuine)`.
    type Case = (
        bool,
        bool,
        bool,
        Option<&'static str>,
        Option<&'static str>,
        bool,
        String,
        bool,
    );

    /// One record per `user` signature in the maintainer's §19 schema output (31 signatures):
    /// `(isMeta, isSidechain, isCompactSummary, promptSource, turnOrigin, toolUseResult, content)`
    /// → genuine?
    #[test]
    fn every_signature_of_the_schema_output_is_classified() {
        let text = |t: &str| format!("\"{t}\"");
        let blocks = |kinds: &[&str]| {
            let b: Vec<String> = kinds
                .iter()
                .map(|k| match *k {
                    "text" => r#"{"type":"text","text":"SYNTH text"}"#.to_string(),
                    "image" => {
                        r#"{"type":"image","source":{"type":"base64","data":"AAAA"}}"#.to_string()
                    }
                    "tool_result" => {
                        r#"{"type":"tool_result","tool_use_id":"t","content":"SYNTH out"}"#
                            .to_string()
                    }
                    _ => unreachable!(),
                })
                .collect();
            format!("[{}]", b.join(","))
        };
        let plain = text("SYNTH plain prompt");
        let tag = |t: &str| text(&format!("<{t}>SYNTH</{t}>"));
        #[rustfmt::skip]
        let cases: Vec<Case> = vec![
            (false, false, false, None, None, true, blocks(&["tool_result"]), false),
            (false, true, false, None, None, true, blocks(&["tool_result"]), false),
            (false, false, false, Some("sdk"), Some("sdk"), false, blocks(&["text"]), false),
            (false, false, false, Some("typed"), Some("human"), false, plain.clone(), true),
            (false, false, false, Some("system"), Some("task_notification"), false, tag("task-notification"), false),
            (false, true, false, None, None, false, plain.clone(), false),
            (false, false, false, Some("suggestion_accepted"), Some("human"), false, plain.clone(), true),
            (true, false, false, None, None, false, blocks(&["text"]), false),
            (true, false, false, None, None, false, tag("local-command-caveat"), false),
            (false, false, false, None, None, false, tag("command-name"), false),
            (true, true, false, None, None, false, blocks(&["text"]), false),
            (true, true, false, None, None, false, plain.clone(), false),
            (false, false, true, None, None, false, plain.clone(), false),
            (false, false, false, None, None, false, tag("local-command-stdout"), false),
            (true, false, false, None, None, false, plain.clone(), false),
            (false, false, false, Some("typed"), None, false, plain.clone(), true),
            (false, false, false, None, None, false, blocks(&["text"]), true),
            (false, false, false, Some("queued"), Some("human"), false, plain.clone(), true),
            (false, false, false, Some("typed"), Some("human"), false, blocks(&["image", "text"]), true),
            (false, false, false, Some("system"), None, false, tag("task-notification"), false),
            (false, false, false, Some("suggestion_accepted"), None, false, plain.clone(), true),
            (false, true, false, None, None, false, blocks(&["tool_result"]), false),
            (false, false, false, None, None, false, tag("bash-input"), false),
            (false, false, false, None, Some("human"), false, tag("bash-stdout"), false),
            (false, false, false, Some("queued"), None, false, plain.clone(), true),
            (true, false, false, None, None, false, tag("system-reminder"), false),
            (false, false, false, Some("queued"), Some("human"), false, tag("pasted_content"), true),
            (false, false, false, None, Some("human"), false, tag("command-message"), false),
            (false, true, false, None, None, false, blocks(&["text"]), false),
            (false, false, false, Some("queued"), Some("human"), false, blocks(&["image", "text"]), true),
            (false, true, true, None, None, false, plain.clone(), false),
        ];
        assert_eq!(cases.len(), 31);
        for (i, (meta, side, compact, src, origin, tool, content, want)) in cases.iter().enumerate()
        {
            let mut fields = vec![
                r#""type":"user""#.to_string(),
                format!(r#""isMeta":{meta}"#),
                format!(r#""isSidechain":{side}"#),
            ];
            if *compact {
                fields.push(r#""isCompactSummary":true"#.into());
            }
            if let Some(s) = src {
                fields.push(format!(r#""promptSource":"{s}""#));
            }
            if let Some(o) = origin {
                fields.push(format!(r#""turnOrigin":"{o}""#));
            }
            if *tool {
                fields.push(r#""toolUseResult":{"stdout":"SYNTH"}"#.into());
            }
            fields.push(format!(
                r#""message":{{"role":"user","content":{content}}}"#
            ));
            let json = format!("{{{}}}", fields.join(","));
            assert_eq!(rec(&json).is_some(), *want, "signature {i}: {json}");
        }
    }

    #[test]
    fn other_values_and_shapes_are_not_genuine() {
        assert!(rec(r#"{"type":"user","promptSource":"future_value","message":{"role":"user","content":"x"}}"#).is_none());
        assert!(rec(r#"{"type":"user","turnOrigin":"task_notification","message":{"role":"user","content":"x"}}"#).is_none());
        assert!(rec(r#"{"type":"user","message":{"role":"assistant","content":"x"}}"#).is_none());
        assert!(rec(r#"{"type":"assistant","message":{"role":"user","content":"x"}}"#).is_none());
        assert!(rec(r#"{"type":"user","message":{"role":"user","content":"   "}}"#).is_none());
        assert!(
            rec(r#"{"type":"user","message":{"role":"user","content":[{"type":"image"}]}}"#)
                .is_none()
        );
        assert!(rec(r#"{"type":"user","message":{"role":"user"}}"#).is_none());
        assert!(rec(r#"{"type":"user"}"#).is_none());
        // A tag-like start that is not a known synthetic tag is the user's own text.
        assert_eq!(
            rec(r#"{"type":"user","promptSource":"typed","message":{"role":"user","content":"<div> is broken"}}"#).as_deref(),
            Some("<div> is broken")
        );
        assert!(rec(r#"{"type":"user","message":{"role":"user","content":"  <command-name>/clear</command-name>"}}"#).is_none());
        assert_eq!(
            rec(r#"{"type":"user","message":{"role":"user","content":"<command-namex>"}}"#)
                .as_deref(),
            Some("<command-namex>")
        );
    }

    #[test]
    fn finish_redacts_then_truncates_by_characters() {
        let p = finish(&format!("token=abc123 {}", "é".repeat(3000)), Some(5));
        assert!(p.truncated);
        assert_eq!(p.text.chars().count(), MAX_CHARS);
        assert!(p.text.starts_with("token=[REDACTED] "));
        assert!(!p.text.contains("abc123"));
        assert_eq!(p.at, Some(5));
        let short = finish("hello", None);
        assert_eq!((short.text.as_str(), short.truncated), ("hello", false));
    }

    #[test]
    fn complete_lines_drop_partial_first_and_last_lines() {
        let b = b"tail of a line\n{\"a\":1}\n\n{\"b\":2}\n{\"partial";
        let v: Vec<&[u8]> = complete_lines(b, true).collect();
        assert_eq!(v, [&b"{\"a\":1}"[..], &b"{\"b\":2}"[..]]);
        let v: Vec<&[u8]> = complete_lines(b"{\"x\":1}", false).collect();
        assert!(v.is_empty(), "no newline: nothing complete");
    }
}
