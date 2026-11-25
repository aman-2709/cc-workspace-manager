# Synthetic Claude Code session fixtures

**Every value here is invented.** No real session record, redacted or not, may ever be committed
(REQUIREMENTS.md §7.1, §19). The record shapes follow the maintainer's structure-only output of
`scripts/inspect-session-schema.py` (key paths, value types, allowlisted discriminators; Claude Code
2.1.217–2.1.331, recorded in ARCHITECTURE.md §11).

Layout: `<claude-code-version>/projects/<encoded-dir>/<session-uuid>.jsonl`, i.e. each version
directory is a Claude config directory's `projects/` tree. `@HOME@` stands for the home directory and
is replaced when the corpus is installed (`synth::install_sessions`, used by `ccwm-synth` and the
tests through `synth::SESSION_FIXTURES`).

| File | Covers |
|---|---|
| `2.1.331/…-dev-alpha/1111…` | typical session: unordered timestamps, tool results, meta and command records, two `ai-title`s (last wins), `last-prompt` (never used), sensitive record types with canaries (`api-request-blob`, `session-owner`, `bridge-session`, `queue-operation`), `pr-link`, `continued-in` |
| `2.1.331/…-dev-alpha/1111…/subagents/…` | a subagent transcript (ignored in v0.1) |
| `2.1.331/…-dev-alpha/2222…` | the continuation: `derived-from`, cwd change (`…/src`) |
| `2.1.331/…-dev-alpha/memory/notes.md` | a non-session file |
| `2.1.331/…-dev-session-only-src/3333…` | a project without `CLAUDE.md`; secrets in a prompt (redaction); `suggestion_accepted`, task notification, SDK input |
| `2.1.331/…-home/4444…` | a session started in the home directory (unassigned) |
| `2.1.331/…-dev-deleted/5555…` | a cwd that no longer exists (unassigned) |
| `2.1.331/…-dev-gamma/6666…` | edge cases: malformed line, unknown types, record without type, foreign `sessionId`, sidechain and compact-summary records, `<pasted_content>` prompt, image + text, odd field types, a blank line, an unterminated last line |
| `2.1.220/…-inner-src/7777…` | an older version without `promptSource`/`turnOrigin` (the classifier path); cwd below a nested Git project |

The `.session-aliases` file Claude Code keeps there is created by `install_sessions` (the repository's
`.gitignore` excludes that name). The files were generated once by a throw-away script from these
shapes; edit them by hand, keep them synthetic, and update the assertions in `tests/tracker.rs`,
`tests/process.rs` and `src/synth.rs` that count them.
