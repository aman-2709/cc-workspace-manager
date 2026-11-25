//! Claude Code integration (REQUIREMENTS.md §7, §8). The **only** module that knows Claude Code's
//! file formats: where sessions live ([`locate`]), the allowlisted record fields ([`record`]),
//! incremental aggregates ([`parse`]), genuine prompts read on demand ([`prompt`]), redaction
//! ([`redact`]), resume commands ([`resume`]) and the `claude` CLI check ([`cli`]).
//!
//! The verified schema (ARCHITECTURE.md §11) comes from the maintainer-run, structure-only
//! inspection script (§19); the fixtures under `tests/fixtures/sessions/` are synthetic.

pub mod cli;
pub mod locate;
pub mod parse;
pub mod prompt;
pub mod record;
pub mod redact;
pub mod resume;
