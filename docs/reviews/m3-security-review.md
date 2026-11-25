# M3 security review (development continuity)

Independent, adversarial review of milestone M3. I did not write this code. Scope per the review brief:
the session parser as an untrusted-input boundary, prompt redaction and prompt persistence, resume command
construction, privacy mode across REST/WebSocket/status/settings, session-based discovery, the new settings
endpoints, whether acceptance tests 2, 8 and 10 test what they claim, and whether real session data is
committed.

Sources read: `REQUIREMENTS.md` §0, §4, §7, §8, §10, §11, §16, §19 (and Appendix A), `ARCHITECTURE.md` (in full,
esp. §6, §7b, §8, §11, §13e, §14), `docs/reviews/m1-security-review.md`, `docs/reviews/m2-security-review.md`, and
the M3 commit (`git show 8a0facb`): `src/claude/*`, `src/discovery/resolve.rs`, `src/tracker/sessions.rs`, the
session/settings/privacy paths of `src/service.rs`, `src/db/writer.rs`, `src/config.rs`, `src/http/{routes,ws}.rs`,
`src/events.rs`, the Settings/privacy/copy code of `web/app.js`, `tests/process.rs` (the M3 acceptance test),
`tests/sessions_api.rs` and the fixture corpus. **No code was modified and `~/.claude` was not opened.**

**Experiments (run, not just reasoned).** All of them ran in the session scratchpad. None touched the real home, a
real project or `~/.claude`:
- A throw-away crate that links `cc-workspace-manager` by path and calls its public functions (`redact`,
  `resume::command`, `locate::session_id_of`, `resolve::Context::resolve`, `parse::parse`, `prompt::last_prompt`) on
  synthetic inputs. Every "demonstrated" result below comes from the shipped code, not a re-implementation.
- A pty-driven interactive `bash` 5.2.21 (`env -i`, `--norc`), fed the exact bytes of a generated resume command.
  This simulates a paste.

**Summary.** No Critical and no High findings. There are four Medium findings:
- **M1.** A resume command can run an arbitrary command when it is pasted (demonstrated).
- **M2.** Prompt text can be stored while "Store prompt text" is off.
- **M3.** Redaction misses the most common secret spellings (demonstrated).
- **M4.** A session started in a parent folder (e.g. `~/dev`) absorbs the non-Git projects below it (demonstrated).

There are also eight Low findings, a few informational notes and some test gaps. Most of the untrusted-input
handling is sound. The parser survived 200,000-level JSON nesting and 7 MB values without failing. UUID
validation and POSIX quoting are correct, the continuation chain is cycle-safe, and the GET privacy paths are
complete. The fixtures are synthetic.

---

## Medium

### M1. Control characters in the recorded cwd survive quoting, so a pasted resume command can run anything

**Where:** `src/claude/resume.rs:16` (`shell_quote`), `src/claude/resume.rs:31` (`command`); the cwd comes
unfiltered from `src/claude/parse.rs:194`; the UI copies it verbatim (`web/app.js`, `navigator.clipboard.writeText`).

**What is right.** POSIX single quoting is correct. Nothing inside `'…'` is special to the *shell parser*. The unit
test proves this for `$()`, backticks, `'`, newlines and a leading `-` by running `/bin/sh`.

**The hole.** The command is not run by `sh -c`. It is **pasted into an interactive terminal**, and the line editor
(readline, zle) acts on control characters before the shell parser sees anything. Directory names may contain any
byte except `/` and NUL, so the first recorded cwd can carry `\x15` (Ctrl-U, kill line), `\n` (accept line), or the
bracketed-paste end marker `ESC[201~`. `command()` puts these bytes into the copied text unchanged.

**Demonstrated** with the shipped `resume::command` and a pty-driven `bash -i` (5.2.21):
- `resume::command("/home/u/x\u{15}touch /tmp/pwned\n", id)` returns
  `cd -- '/home/u/x\u{15}touch /tmp/pwned\n' && claude --resume …`.
- With bracketed paste **off**, feeding those bytes created the sentinel. Ctrl-U erased `cd -- '/home/u/x`, the
  newline accepted `touch <sentinel>`, and the leftover `' && claude …` was stuck in an unterminated quote.
- With bracketed paste **on**, a cwd that also contains `ESC[201~` (wrapped in `ESC[200~ … ESC[201~` as a terminal
  would send it) **also created the sentinel**. The embedded marker ends the paste early.
- The UI shows the command with `textContent`, so these characters are invisible to the user before copying.

**Preconditions and impact.** The user must have started `claude` in a directory with a hostile name. For example,
the directory came from a tarball or a cloned repository (Git paths may contain these bytes), and the user `cd`'d
into it and ran `claude` there. Later the user copies "Resume" from ccwm and pastes it. Whether the bracketed-paste
variant works depends on the terminal: some terminals (e.g. xterm with `allowPasteControls` off) strip control
characters from pastes, many do not. The result is arbitrary command execution as the user, through the one action
ccwm offers for session data. §11.1 puts session content and malicious project files in scope, and §8's
"adversarial path" requirement exists to prevent exactly this.

**Fix (needs a §8 amendment).** If the cwd contains any C0 control character (including `\t`, `\n` and `\r`), DEL,
a C1 control character, or a Unicode bidi/format character (`U+202A–U+202E`, `U+2066–U+2069`, `U+200E/F`), generate
**no command**. Add a warning `cwd_unsafe_characters` and show the path escaped (e.g. `\x15`). `$'…'` quoting is not
an alternative: it is not POSIX and does not help against the line editor. Change the adversarial-path unit test
(which currently *accepts* `\n`) to expect no command for newline, `\x15`, `\x1b[201~`, `\r` and `U+202E`. Add the
pty test as a regression test.

### M2. Prompt text can be cached while "Store prompt text" is off

**Where:** `src/service.rs:490` (setting read once per request), `src/service.rs:520` (`cache_prompt` after the
file read), `src/db/writer.rs:709` (`CachePrompt` updates without a guard), `src/service.rs:670`–`701`
(read-merge-write of the settings), `src/service.rs:722` (`clear_prompt_cache`), `web/app.js:1116` (the Settings
form sends **every** field).

There are three ways to end up with stored prompt text after the user turned the setting off. §7.3 says turning it
off deletes the cached text, and the review brief asks that no prompt text persists while it is off.

1. **Stale Settings form (the most likely).** `settingsPatch` sends every form value, including the
   `store_prompt_text` checkbox **as it was when the page was rendered**. Suppose the user turns the setting off in
   one tab, and a Settings tab opened earlier later saves an unrelated change (say, the theme). That save re-enables
   `store_prompt_text`. It also silently reverts roots, exclusions, budget and the other fields to the stale values.
   Nothing warns the user, and prompts are cached again from then on.
2. **Request/settings race.** `session_view` reads `store_prompts()` at the start, then reads the file on the blocking
   pool, then calls `try_send(CachePrompt)`. If the user's `PUT /settings` (off → `ClearPromptCache`) is processed in
   between, the `CachePrompt` arrives after the clear and stores the prompt anyway. The writer applies `CachePrompt`
   unconditionally. The text stays until that session's aggregate changes (an idle session: indefinitely).
3. **Lost update.** `update_settings` releases the settings mutex between merging and `st.saved = new`. Two
   concurrent PUTs both merge onto the same `old`, and the later one wins whole.

**Fix.**
- Give the writer the authority. Keep a shared `AtomicBool` (or a `meta` row) that `apply_live` sets **before**
  `ClearPromptCache`, and make `CachePrompt` a no-op unless it is set, checked inside the writer transaction.
- Make the settings save a compare-and-swap. Either the client sends only the fields the user changed, or the
  response carries a version that the next PUT must echo (409 otherwise), and the lock is held across
  merge/validate/save/apply.
- Test it: (a) a stale full-form PUT does not flip `store_prompt_text` back on (or is rejected); (b) a prompt read
  that is in flight while the setting turns off stores nothing (inject a delay into the read).

### M3. Redaction misses the most common secret spellings, including the `password=` form the spec requires

**Where:** `src/claude/redact.rs:46` (the assignment rule), `:26` (private keys), `:33` (`sk-`).

The key-assignment rule starts with `\b(password|…|api[_-]?key|access[_-]?key)`. `_` is a word character, so there
is **no `\b` inside `DB_PASSWORD` or `aws_secret_access_key`**. The rule also needs `=`/`:` right after the keyword,
so a JSON/YAML-quoted key (`"password": "…"`) never matches. **Demonstrated** with the shipped `redact()`; all of
these come back unchanged:

| Input (synthetic) | Why it is missed |
|---|---|
| `DB_PASSWORD=hunter2hunter2`, `MY_API_KEY=…`, `client_secret=…` | no word boundary after `_` |
| `export AWS_SECRET_ACCESS_KEY=wJalr…`, `aws_secret_access_key = …` | same; the AWS *secret* key has no prefix |
| `{"password": "hunter2hunter2"}`, `{"api_key": "…"}` | the quote between the key and `:` |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----…` | the rule needs `PRIVATE KEY-----`; PGP has ` BLOCK-----` |
| `sk_live_…` (Stripe), `glpat-…` (GitLab), `npm_…`, `AIza…` (Google), `Authorization: Basic …` | no rule |

These are exactly the shapes people paste into prompts: `.env` lines, JSON config, CI variables. §7.3 lists
`password=` as a required pattern and names AWS keys. Only the access key id (`AKIA…`) is caught; the secret that
matters is not. SECURITY.md does say "best effort", but it also lists "`password=`/`token:`/`api_key=`-style
assignments" as recognised, which overstates what the code does.

**Fix.**
- Match keywords as a suffix of an identifier: `(?i)\b[\w.-]*?(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[=:]\s*["']?[^\s"',;]+`.
  That covers `DB_PASSWORD=`, `aws_secret_access_key =`, `"password": "x"` and `client_secret: x`.
- Broaden the PEM rule to `-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`.
- Add `\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`, `\bglpat-[A-Za-z0-9_-]{20,}`, `\bnpm_[A-Za-z0-9]{36}`,
  `\bAIza[0-9A-Za-z_-]{35}` and `(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}`.
- Add every row above as a test case, and fix the stray-quote output (`TOKEN: [REDACTED]'`).

### M4. A session started in a parent folder becomes an "umbrella" project that absorbs the non-Git projects below it

**Where:** `src/discovery/resolve.rs:147` (no marker or Git root found ⇒ the cwd itself), `:151`–`158` (nested rule
against `known`); `src/tracker/sessions.rs:85`–`137` (one context per batch); the marker scan uses the same `known`
set.

Starting `claude` in `~/dev` to work across several repositories is common. `~/dev` has no `.git` and no
`CLAUDE.md`, so §4.4's fallback registers **`~/dev` itself** as a session project. After that, the nested rule
treats every non-Git candidate below it as part of `~/dev`. **Demonstrated** with the shipped `Context::resolve`
(`~/dev/app-a` and `~/dev/app-b` each hold a `CLAUDE.md`, no Git):
- Fresh index: a session in `~/dev` resolves to `dev`.
- With `~/dev` known: a session in `~/dev/app-b/src` resolves to **`dev`**. With `~/dev` unknown it resolves to
  `dev/app-b`.

The outcome depends on order. On a first launch, all sessions resolve against the same `known` set, so `app-b`
(whose session was in the same batch) is registered. The full marker scan that follows runs with `known` containing
`~/dev`, so `app-a`'s `CLAUDE.md` is classified as "a nested instruction file of `~/dev`" and `app-a` **never
becomes a project**. Every later session in `app-a` is attributed to `~/dev`. Enrolling `~/dev` then walks and
watches the whole dev tree (up to 100,000 entries), and files changed in `app-a` count as `~/dev` activity. The same
happens with `~/Documents` or any other container folder.

A crafted session (§11.1: session content is in scope) can do this on purpose. One `cwd` at a high-level folder
hides the marker projects below it and takes over their attribution. That is the "hijack an existing project" case
from the brief, by **absorption** rather than by taking over an id. Already-registered projects persist (missing =
directory gone), so the damage hits newly created or not-yet-discovered projects.

**Fix (needs a §4.4 decision).** A session-only candidate (cwd fallback, no marker or Git root) should not take part
in the nested rule as an outer project. Either do not register it when a registered or marker project lies below it
(count the session as unassigned, e.g. `container`), or register it but exclude session-only projects from `known`
in both the resolver and the marker scan. Add tests for both orders (umbrella first, projects first).

---

## Low

### L1. Privacy mode is not applied to the ignore and settings-save responses, and the settings privacy test passes vacuously

**Where:** `src/service.rs:759` (`set_ignored` returns `self.view(…, Privacy::Off)`, used by
`PUT`/`DELETE /projects/{id}/ignore`), `src/service.rs:701` (`update_settings` returns `settings(Privacy::Off)`);
`src/http/routes.rs:106`/`114` and `update_settings` accept no `privacy` query.

A privacy-mode client that ignores or un-ignores a project receives the absolute `path` and `display_path`. A
client that saves the settings receives the roots, exclusions, session directory and config path. `app.js` does not
render these responses, but §10 is a server guarantee ("the server omits these fields … for that client"), and the
data does reach the browser (network log, JS heap). **Test gap:** `tests/sessions_api.rs` checks
`/settings?privacy=1` with canaries (`/home/u`, …) that the test's settings never contain: no roots, no exclusions,
a session dir outside `/home/u`. The check would pass even if the settings stripping were deleted.
**Fix:** accept `privacy` on these three routes (or return 204/minimal bodies). Add them to the canary test, with
configured roots, exclusions and a session dir that contain canaries.

### L2. Session-discovered projects skip `same_file_system` and `max_depth`

**Where:** `src/discovery/resolve.rs:123`–`140`. The checks are hidden, hard boundary, default names, FUSE mount
points and user patterns. There is no device comparison with the root and no depth limit.

A session whose cwd is on an NFS/SMB/removable mount below home, or simply deeper than `max_depth`, is registered.
It is then walked, watched and Git-inspected, even though discovery would never have entered it (§4.1:
`same_file_system = true` by default). On a network filesystem that means Git and tree walks over the network
mount, and stalls up to the 5 s Git timeout. **Fix:** in `resolve`, reject (as `excluded`) a canonical cwd whose
`st_dev` differs from its root's when `same_file_system` is on, and one deeper than `max_depth`. Add tests.

### L3. Stored session strings are unbounded, unsanitized and not redacted

**Where:** `src/claude/parse.rs:194`–`202`. `first_cwd`, `last_cwd`, `git_branch`, `version` and `entrypoint` are
stored and returned as read.

**Demonstrated:** a 7,000,001-byte `cwd` and a `gitBranch` of `"b\x1b[31mred\x07"` were both accepted into the
aggregate. They are stored per session in SQLite and returned by `/projects/{id}/sessions` (and `version`/branch in
privacy mode too). The 8 MiB line cap bounds each value, but not the database (one large value per session file).
Control characters also reach `ccwm status`-style terminal output wherever these fields are printed. §7.3 says
redaction applies to "everything displayed or stored from sessions"; only titles and prompts are redacted.
**Fix:** cap these fields (e.g. cwd at 4,096 bytes, the length of `PATH_MAX`; branch/version/entrypoint at 256)
and treat an over-long cwd as `no_cwd`. Strip control characters from branch/version/entrypoint (the Git module's
`clean()` already does this for Git's own strings). Either redact them or document the exemption for paths in §7.3
(redacting a cwd would break resume).

### L4. Session ids are case-folded, so two files can share one id and get re-parsed forever

**Where:** `src/claude/locate.rs:41` (`stem.to_ascii_lowercase()`); `src/tracker/sessions.rs:276`–`279` (`prev`
only when `file_path` matches); `src/db/writer.rs` `store_sessions` (`ON CONFLICT(id)` replaces `file_path`).

**Demonstrated:** `0B7C…6F.jsonl` and `0b7c…6f.jsonl` map to the same id. Two files with one id (upper/lower case,
or the same file copied into a second `<encoded-dir>`) take turns owning the row. In each ingest, the file the row
does not currently point at has no checkpoint, so it is parsed from byte 0 (up to ~80 MB) and overwrites the
session's `first_cwd`, title and checkpoint. The resume command then alternates between the two cwds. Copying a
session file into the new encoded directory after moving a project is a common manual workaround for
`claude --resume`, so this can happen without an attacker. Impact: repeated full parses (CPU and I/O on every
reconciliation and session event) and a flapping resume target. **Fix:** key a session by `(id, file_path)`, or
keep the first file for an id and count later ones as `skipped.duplicate_id`. Do not case-fold the stem (Claude
Code writes lower case; treat others as non-sessions). Add a test.

### L5. `continued-in` is followed across projects and into unassigned sessions without a warning

**Where:** `src/service.rs:555`–`575`.

The chain follows any indexed session. That includes sessions of **another project** and **unassigned** sessions
(`temporary`, `outside_roots`, `excluded`, `home`). The command shown in project A's panel can then `cd` into
`/tmp/…`, an excluded folder or another project, and resume a different transcript. The only hint is
`via_continuation: true`. A planted session file (from a synced or shared `~/.claude`) can point a real session's
resume at an attacker-written transcript, which Claude Code then loads as conversation context. Cycles and the
16-hop cap are handled correctly (see "sound" below). **Fix:** follow a link only when the target is assigned to
the same project. Otherwise offer the session itself with a warning such as `continuation_other_project` or
`continuation_unassigned`, and show the target's cwd next to the command.

### L6. Deleted prompt text and a cleared index stay in SQLite free pages and the WAL

**Where:** `src/db/mod.rs:72` (no `secure_delete`), `src/db/writer.rs:724` (`ClearPromptCache`),
`clear_session_index` (`src/db/writer.rs:888`).

`UPDATE … SET prompt_text = NULL` and `DELETE FROM sessions` leave the old bytes in freed pages and WAL frames until
SQLite reuses them. `tests/sessions_api.rs:627` says so in a comment ("may linger in free pages"). SECURITY.md,
however, says turning the setting off "deletes the cache", and §7.3/§13 promise deletion. The data directory is
`0700` (same-user attackers are out of scope), but backups and disk images of `~/.local/share` keep the text.
**Fix:** `PRAGMA secure_delete = ON` (or `FAST`) on the writer connection, plus `PRAGMA wal_checkpoint(TRUNCATE)`
after `ClearPromptCache` and `ClearSessionIndex`. Then assert in the test that the canary is absent from the db,
WAL and SHM bytes after turning the setting off.

### L7. `PUT /settings` accepts security-relevant keys the Settings page does not offer

**Where:** `src/service.rs:663` (any `Config` key may be patched), `src/config.rs:148` (`validate_port` accepts
`0`), `src/config.rs:280` (`sessions.dir` only needs to be absolute).

Over the browser API, an authenticated client can set `git.allow_unhardened_status = true` (on an old Git this
re-enables unhardened status, which §6 shows runs filter drivers), `discovery.roots = ["/"]` and
`sessions.dir = "/"` (a Landlock read rule of `/` at the next start), and `server.port = 0`. ARCHITECTURE §6 says 0
is "for tests only", and the UI's `min=1024` is not enforced on the server. The documented XSS residual (§11.3: a
stolen `localStorage` token) therefore becomes a **persistent** downgrade of the hardening that survives restarts.
The sandbox report does flag broad read rules after a restart, so the downgrade is visible. **Fix:** the server
should allow only the §9 Settings keys in a PUT and reject the rest ("edit config.toml"). Reject port 0 there.
Optionally refuse `/` and ancestors of home as `sessions.dir`.

### L8. The on-demand prompt read materializes the text of non-genuine `user` records before classifying them

**Where:** `src/claude/prompt.rs:103`. `UserRecord` (including `message.content`) is deserialized for every `user`
line in the 4 MiB window; classification happens afterwards.

The string content of `<bash-stdout>`, `<local-command-stdout>`, task notifications and similar records (command
output, which can contain secrets) is allocated, then discarded as synthetic. It is never stored, logged or
returned, but §7.1 allows reading `message.content` "of genuine prompts (on demand only)". **Fix:** deserialize the
flags first (`isMeta`, `isSidechain`, `isCompactSummary`, `promptSource`, `turnOrigin`, `toolUseResult` presence,
`message.role`), and deserialize the content only when they pass. The synthetic-tag check still needs the text, so
the claim should then be "content of candidate prompts".

### Informational

- **Prompt reads reopen the file by its stored path** (`prompt::open`, `O_NOFOLLOW` on the last component only).
  The parent `<encoded-dir>` is resolved by path, unlike the descriptor-based ingest. Only a same-user writer could
  swap it, and the parser exposes only genuine-prompt text, so this is a consistency note, not a vulnerability.
- **The `claude --version/--help` check runs the user's real binary.** Under Landlock it cannot write anywhere. On
  a host without Landlock it is unconfined, and tests 2 and 5 use a fake `claude`, so neither would notice side
  effects of the real binary (e.g. on `~/.claude`). Worth a sentence in SECURITY.md.
- `tests/process.rs`'s privacy loop omits `/service/status?privacy=1` (it is covered in `tests/sessions_api.rs`).

---

## Acceptance tests 2, 8, 10 — do they test what they claim?

All three live in one process-level test, `tests/process.rs:1667`
(`m3_acceptance_sessions_resume_privacy_and_acceptance_2_8_10`).

### Test 2 (session files unchanged) — sound for what it runs; two gaps.
It snapshots the whole Claude directory before the daemon starts and compares it at the end. The snapshot covers
mode, mtime (ns), **ctime**, size, inode and full content (`tests/common/mod.rs:269`), so a chmod, touch, rewrite or
replacement would fail it. In between, the run parses the sessions, reads prompts on demand, runs the `claude`
check and clears the index. Gaps:
- No `service uninstall` step (M4, already documented).
- The session files are never appended to during the run, so the live-watch and incremental-checkpoint path is not
  part of the acceptance run (it is unit-tested in `tests/tracker.rs`).
- The `claude` binary is a fake, so its side effects are not covered (see the informational note).

### Test 8 (no sensitive data in logs) — sound.
It runs at `CCWM_LOG=trace` and confirms that trace events were actually emitted (`"socket request"`). The canaries
cover prompts, the in-prompt token and password, account and organization ids, the API blob, the remote
credential, a title, the session token and the bootstrap token. One addition would help: a canary in a
malformed/oversized line and in an unreadable session file, which exercises the error paths
(`tracker/sessions.rs:290` logs `error = %e`).

### "No prompt text persisted by default" (the DB canary scan) — weaker than it looks.
The DB, WAL and SHM bytes are scanned only **after** `POST /session-index/clear` has deleted every session row. The
scan still catches stored text only because SQLite usually leaves deleted bytes in free pages (L6), which is not
guaranteed. Scan **before** clearing, then again after. The test also never covers the setting turning off while a
read is in flight (M2).

### Test 10 (clear / delete DB / uninstall leave data byte-identical) — partly hollow.
Clearing the index is done while the daemon runs, and that part is meaningful. "Deleting the database" happens
**after the daemon has stopped**, followed immediately by the snapshot comparison. Deleting files in ccwm's own data
directory cannot change anything else, so that step proves nothing. The interesting case is a **restart on an empty
database** (a full re-ingest from byte 0 of every file), and the test does not do that. `uninstall --purge` is
missing (M4). **Fix:** delete the DB, start the daemon again, wait for a scan, stop it, then compare.

---

## Checked and found sound

- **Parser robustness** (`claude/record.rs`, `parse.rs`). Demonstrated: a line with 200,000 levels of array
  nesting, in an unknown field, in `cwd` and inside a prompt's content block, parsed without a stack overflow or a
  failure. serde_json's ignore path is iterative, and the lenient visitors drain without recursing per level. The
  memory use is bounded by the 8 MiB line cap: an oversized line is dropped as soon as it crosses the cap and is not
  kept while the scan looks for its newline. An unterminated trailing line is never consumed (the offset stays
  before it). Rotation (new inode), shrink below the offset and same-size rewrites reset the aggregate. Unknown
  types, foreign `sessionId`s, records without a type and malformed JSON are counted and skipped. Odd JSON types for
  allowlisted fields are treated as absent.
- **Allowlist.** Only the §7.1 fields are declared. `toolUseResult` is presence-only (`IgnoredAny`), and
  `tool_result` block bodies, `api-request-blob`, `session-owner`/`bridge-session` ids, `queue-operation` content
  and `wireToolInputs` are never declared. The M3 DB canary scan confirms none of them is stored. `derived-from` is
  parsed a second time only for that record type and capped at 16 validated UUIDs.
- **File access.** The session tree is listed by descriptor. Only `<uuid>.jsonl` regular files are sessions;
  subagent directories, `memory/`, aliases, symlinks and hidden directories are skipped. Files are opened with
  `openat(O_NOFOLLOW|O_NONBLOCK)` and `fstat`-checked as regular, so a FIFO swapped in cannot block the ingest
  thread. Prompt reads take a bounded 4 MiB head/tail window and drop a partial first line. Redaction runs before
  truncation, so a secret cannot be split at the 2,000-character boundary.
- **Resume.** `is_uuid` is strict (8-4-4-4-12 hex), and both the file stem and `continuedInSessionId` must pass it.
  Shell quoting is correct for the shell parser (M1 is about the line editor). The continuation chain is cycle-safe:
  a case-variant self-link is lower-cased at parse time and caught by `seen`, a longer cycle stops at the first
  repeat, the chain is capped at 16 hops, and a target that is not indexed gets `continuation_not_indexed`. The cwd
  used is the target's **first** cwd, as §8 requires.
- **Session discovery boundaries.** The cwd is canonicalized first, and every check runs on the canonical path, so
  a symlinked cwd cannot escape the roots. Each component below the root goes through `exclude_dir`: hidden,
  hard boundaries (incl. ccwm's dirs and the Claude config dir), default names, FUSE mount points and user
  patterns. Home and its ancestors are refused, temporary directories outside home are refused, relative and
  non-UTF-8 cwds are `no_cwd`, and the walk-up never reaches home. Assigned sessions keep their project. Upserts key
  on the canonical path, so a session cannot take over another project's **id**; M4 is the absorption variant. The
  marker-scan scope does not let a session reach outside the configured roots.
- **Privacy (GET + WebSocket).** List, detail, sessions, discovery, service status and settings omit the §10 fields
  on the server. Search ignores the path in privacy mode. Each WebSocket client gets the privacy variant of
  `project`/`discovery` events, built per event, and can switch with `{"type":"privacy"}` after auth (unknown
  messages close the socket). `stats`, `monitoring` and `project_removed` carry no hidden fields. The sandbox
  `notes` mention broad read rules, but those are only `/` or *strict* ancestors of home, never the home directory
  itself.
- **Settings.** `deny_unknown_fields` plus the full `validate()` run on the merged object. The service keeps the
  file's config, so `--port` is never written back (the process test asserts it). The write is atomic: a
  `0600` tmp file, fsync, rename. PUT needs the exact Origin. In privacy mode the UI sends `null` for the hidden
  roots/exclusions and leaves them out, so a save there does not wipe them.
- **Fixtures and repository.** Every tracked `*.jsonl` is under `tests/fixtures/sessions/`. All values are
  synthetic: `@HOME@`-templated cwds under `dev/{alpha,gamma,…}`, patterned UUIDs (`11111111-2222-4333-…`,
  `u0001-0000-…`), `SYNTHETIC …` text and canaries such as `ghp_SYNTHETICCANARY…`. A search over all tracked files
  found no real username, home path, e-mail address or real token. **No real session data is committed.**

---

## For the maintainer

1. **M1, M3 and M4 need spec decisions.**
   - M1: §8. Which characters make a cwd "unsafe" (no command plus a warning), and the change to the adversarial-path
     test, which currently accepts a newline.
   - M3: §7.3. Whether the redaction set grows, and SECURITY.md's wording.
   - M4: §4.4. How a session-only "container" cwd is treated.
2. **M2** can be fixed without a spec change: a writer-side guard, plus a compare-and-swap (or changed-fields-only)
   settings save. **L1** and **L6** are small, test-backed fixes. **L2–L5, L7 and L8** are hardening.
3. **Tests.** Scan the DB before clearing the index, restart on an empty database in test 10, and add the privacy
   canaries for settings and the ignore responses.

No code was modified and nothing was pushed.
