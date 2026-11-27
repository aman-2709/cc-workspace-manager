//! Allowlisted deserialization of Claude Code session records (REQUIREMENTS.md §7.1, §7.3).
//!
//! Only the fields ccwm needs are declared. Everything else in a line — tool results
//! (`toolUseResult`), API payloads (`api-request-blob`), `wireToolInputs`, attachment bodies,
//! `serverClassifierContext`, queue contents, account and organization ids — is skipped by serde
//! without being materialized (`IgnoredAny`), so it never reaches ccwm's memory as a value, let
//! alone its database or logs. A declared field of an unexpected JSON type is treated as absent
//! instead of failing the record.

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;

/// Record types that carry `cwd` and the conversation's timestamps (ARCHITECTURE.md §11).
pub const CONVERSATIONAL: [&str; 4] = ["user", "assistant", "attachment", "system"];

/// Every record type seen in the maintainer's schema output (Claude Code 2.1.217–2.1.331). Other
/// types are skipped and counted as unknown; they never fail a file.
pub const KNOWN_TYPES: [&str; 29] = [
    "agent-color",
    "agent-name",
    "ai-title",
    "api-request",
    "api-request-blob",
    "api-request-shape",
    "artifact-autoreact-ledger",
    "artifact-comment-monitor",
    "assistant",
    "atis-latch",
    "attachment",
    "bridge-session",
    "continued-in",
    "cost-state",
    "data-flow-records",
    "derived-from",
    "file-history-delta",
    "file-history-snapshot",
    "fork-context-ref",
    "frame-link",
    "last-prompt",
    "mode",
    "permission-mode",
    "pr-link",
    "queue-operation",
    "session-owner",
    "system",
    "tools-used",
    "user",
];

// Visitor methods that accept a JSON value of an unexpected kind and return `$v` (draining
// arrays and objects without materializing them).
macro_rules! skip_scalars {
    ($v:expr) => {
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok($v)
        }
    };
}
macro_rules! skip_bool {
    ($v:expr) => {
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok($v)
        }
    };
}
macro_rules! skip_str {
    ($v:expr) => {
        fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
            Ok($v)
        }
    };
}
macro_rules! skip_seq {
    ($v:expr) => {
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
            while s.next_element::<IgnoredAny>()?.is_some() {}
            Ok($v)
        }
    };
}
macro_rules! skip_map {
    ($v:expr) => {
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok($v)
        }
    };
}

/// A string field, or `None` if it is absent, `null` or not a string.
pub(crate) fn lenient_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Option<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Some(v))
        }
        skip_scalars!(None);
        skip_bool!(None);
        skip_seq!(None);
        skip_map!(None);
    }
    d.deserialize_any(V)
}

/// A boolean field, or `None` if it is absent or not a boolean.
fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Option<bool>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v))
        }
        skip_scalars!(None);
        skip_str!(None);
        skip_seq!(None);
        skip_map!(None);
    }
    d.deserialize_any(V)
}

/// The fields every record is read for (the aggregate pass). Small: a 1.9 MB line costs a scan,
/// not an allocation.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Head {
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub kind: Option<String>,
    #[serde(rename = "sessionId", deserialize_with = "lenient_string")]
    pub session_id: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub timestamp: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub cwd: Option<String>,
    #[serde(rename = "gitBranch", deserialize_with = "lenient_string")]
    pub git_branch: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub version: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub entrypoint: Option<String>,
    /// `ai-title` records.
    #[serde(rename = "aiTitle", deserialize_with = "lenient_string")]
    pub ai_title: Option<String>,
    /// `continued-in` records: the session this one continues in.
    #[serde(rename = "continuedInSessionId", deserialize_with = "lenient_string")]
    pub continued_in: Option<String>,
    // v0.2, the recorded ends of a turn (REQUIREMENTS.md §21.2a): top-level fields only; no
    // message text, and `toolUseResult` stays unread.
    /// The turn's prompt id (`user` records); equals the hooks' `prompt_id`.
    #[serde(rename = "promptId", deserialize_with = "lenient_string")]
    pub prompt_id: Option<String>,
    /// Who wrote the record (`harness`: Claude Code itself, e.g. an interruption marker).
    #[serde(rename = "rowSource", deserialize_with = "lenient_string")]
    pub row_source: Option<String>,
    /// Presence only: the record marks the interruption of a message.
    #[serde(rename = "interruptedMessageId")]
    pub interrupted_message_id: Option<IgnoredAny>,
    /// A tool use the user rejected (`user-rejected`), on its result record.
    #[serde(rename = "toolDenialKind", deserialize_with = "lenient_string")]
    pub tool_denial_kind: Option<String>,
    /// An assistant message cut off by an interrupt.
    #[serde(rename = "isAbortedMidStream", deserialize_with = "lenient_bool")]
    pub is_aborted_mid_stream: Option<bool>,
    /// `system` records' kind (`turn_duration` ends a turn).
    #[serde(deserialize_with = "lenient_string")]
    pub subtype: Option<String>,
}

/// `derived-from` records: `{"sessions":[{"id":…,"type":…,"via":…}]}`. Parsed separately (only
/// for that record type), so no other record's `sessions` field is ever materialized.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DerivedFrom {
    pub sessions: Vec<DerivedRef>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DerivedRef {
    #[serde(deserialize_with = "lenient_string")]
    pub id: Option<String>,
}

/// The classification flags of a `user` record (on demand only). `message.content` is **not**
/// part of it: it is skipped unread here and deserialized ([`UserContent`]) only for records
/// whose flags pass (M3 security review, L8), so command output in synthetic records is never
/// materialized.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UserRecord {
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub kind: Option<String>,
    #[serde(rename = "isMeta", deserialize_with = "lenient_bool")]
    pub is_meta: Option<bool>,
    #[serde(rename = "isSidechain", deserialize_with = "lenient_bool")]
    pub is_sidechain: Option<bool>,
    #[serde(rename = "isCompactSummary", deserialize_with = "lenient_bool")]
    pub is_compact_summary: Option<bool>,
    #[serde(rename = "promptSource", deserialize_with = "lenient_string")]
    pub prompt_source: Option<String>,
    #[serde(rename = "turnOrigin", deserialize_with = "lenient_string")]
    pub turn_origin: Option<String>,
    /// Presence only: the tool result itself is skipped unread.
    #[serde(rename = "toolUseResult")]
    pub tool_use_result: Option<IgnoredAny>,
    pub message: Option<MessageRole>,
}

/// `message.role` only.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MessageRole {
    #[serde(deserialize_with = "lenient_string")]
    pub role: Option<String>,
}

/// The content of a candidate prompt: read only after its [`UserRecord`] flags passed.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UserContent {
    pub message: Option<Message>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Message {
    pub content: Content,
}

/// `message.content`: a string, or an array of blocks of which only `type` and `text` are read
/// (a `tool_result` block's own `content` is skipped).
#[derive(Debug, Default)]
pub enum Content {
    #[default]
    None,
    Text(String),
    Blocks(Vec<Block>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Block {
    #[serde(rename = "type", deserialize_with = "lenient_string")]
    pub kind: Option<String>,
    #[serde(deserialize_with = "lenient_string")]
    pub text: Option<String>,
}

impl<'de> Deserialize<'de> for Content {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Content;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or an array of content blocks")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Content, E> {
                Ok(Content::Text(v.to_string()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Content, E> {
                Ok(Content::Text(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Content, A::Error> {
                let mut blocks = Vec::new();
                while let Some(b) = s.next_element::<BlockOrOther>()? {
                    if let BlockOrOther::Block(b) = b {
                        blocks.push(b);
                    }
                }
                Ok(Content::Blocks(blocks))
            }
            skip_map!(Content::None);
            skip_scalars!(Content::None);
            skip_bool!(Content::None);
        }
        d.deserialize_any(V)
    }
}

/// An array element that is a block object, or anything else (skipped).
enum BlockOrOther {
    Block(Block),
    Other,
}

impl<'de> Deserialize<'de> for BlockOrOther {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BlockOrOther;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a content block")
            }
            fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<BlockOrOther, A::Error> {
                Block::deserialize(de::value::MapAccessDeserializer::new(m))
                    .map(BlockOrOther::Block)
            }
            skip_seq!(BlockOrOther::Other);
            skip_str!(BlockOrOther::Other);
            skip_scalars!(BlockOrOther::Other);
            skip_bool!(BlockOrOther::Other);
        }
        d.deserialize_any(V)
    }
}

/// ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`, the only shape in the schema output) to Unix
/// seconds. Anything unparseable is `None`, never a guess.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    s.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

/// [`parse_timestamp`] in milliseconds (the recorded ends of a turn are ordered against hook
/// events more finely than a second).
pub fn parse_timestamp_ms(s: &str) -> Option<i64> {
    s.parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_millisecond())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_reads_only_the_allowlisted_fields_and_tolerates_odd_types() {
        let h: Head = serde_json::from_str(
            r#"{"type":"user","sessionId":"s","timestamp":"2026-01-02T03:04:05.678Z","cwd":{"x":1},
               "gitBranch":7,"version":true,"toolUseResult":{"huge":[1,2,3]},"unknownField":[{}]}"#,
        )
        .unwrap();
        assert_eq!(h.kind.as_deref(), Some("user"));
        assert_eq!(h.cwd, None, "an object is not a cwd");
        assert_eq!(h.git_branch, None);
        assert_eq!(h.version, None);
        assert_eq!(
            parse_timestamp(h.timestamp.as_deref().unwrap()),
            Some(1_767_323_045)
        );
    }

    #[test]
    fn content_is_a_string_or_blocks_and_tool_result_bodies_are_skipped() {
        let u: UserContent = serde_json::from_str(
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"SKIPPED"}]},{"type":"text","text":"hello"},3,"x"]}}"#,
        )
        .unwrap();
        let Content::Blocks(b) = u.message.unwrap().content else {
            panic!("blocks expected")
        };
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].kind.as_deref(), Some("tool_result"));
        assert_eq!(
            b[0].text, None,
            "the tool result's nested content is not read"
        );
        assert_eq!(b[1].text.as_deref(), Some("hello"));
        let u: UserContent =
            serde_json::from_str(r#"{"message":{"content":"plain"},"toolUseResult":"x"}"#).unwrap();
        assert!(matches!(u.message.unwrap().content, Content::Text(ref t) if t == "plain"));
        let f: UserRecord = serde_json::from_str(
            r#"{"message":{"role":"user","content":"plain"},"toolUseResult":"x"}"#,
        )
        .unwrap();
        assert!(f.tool_use_result.is_some());
        assert_eq!(f.message.unwrap().role.as_deref(), Some("user"));
        let u: UserContent = serde_json::from_str(r#"{"message":{"content":{"a":1}}}"#).unwrap();
        assert!(matches!(u.message.unwrap().content, Content::None));
    }

    #[test]
    fn timestamps_parse_or_stay_unknown() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:01.000Z"), Some(1));
        assert_eq!(parse_timestamp("not a time"), None);
        assert_eq!(parse_timestamp(""), None);
    }
}
