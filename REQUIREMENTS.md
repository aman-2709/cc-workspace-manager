# CC Workspace Manager — Requirements (v0.1)

Status: **Approved for implementation** · Single source of truth · Supersedes all earlier specifications and amendments (see Appendix A)

> **Install once. Automatically discover projects. Track development activity. Know where you left off. Resume work effortlessly.**

**Fundamental guarantee.** CC Workspace Manager reads your projects. It does not modify them, push them, or upload their data anywhere. It does not intentionally execute their contents: it neutralizes repository-defined Git helpers and sandboxes itself and its Git subprocesses where the kernel supports it. SECURITY.md lists the residual limits. Never claim a guarantee beyond what is enforced and tested.

---

## 0. How to use this document

- This file is the only specification. If code, other docs or earlier prompts disagree with it, this file wins.
- Sections marked **v0.1** are in scope. Section 18 lists roadmap items, which must **not** be implemented in v0.1.
- If a requirement turns out to be infeasible, contradictory or unsafe once you look at the real environment (for example, the actual Claude Code session schema), **stop and report it with a concrete alternative**. Do not silently change or drop it.
- Never claim a feature works, a platform is supported or a benchmark was achieved unless it was actually tested or measured.

## 1. Product identity

| Item | Value |
|---|---|
| Product name | CC Workspace Manager |
| Repository / Cargo package | `cc-workspace-manager` |
| Executable | `ccwm` |
| systemd user unit | `ccwm.service` |
| License | MIT (maintainer confirms the copyright holder before publishing) |
| Tagline | Discover, track, and resume your Claude Code projects. |
| Default URL | `http://127.0.0.1:8765` |

CC Workspace Manager is an **independent, unofficial** open-source project. It is not affiliated with or endorsed by Anthropic. README, `--help` and the UI footer must say so. Check for naming conflicts (crates.io, GitHub, common distro packages) before first publication.

It is a **project-centric workspace manager**, not a token/cost dashboard or a generic transcript viewer.

## 2. Principles and non-goals

Principles, in priority order: correctness → security → resource efficiency → maintainability → ease of installation → feature count.

Non-goals for v0.1:
- **Zero external network communication.** The only network traffic is loopback HTTP/WebSocket to the browser and the Unix-socket CLI channel. Prohibited: telemetry, analytics, crash reporting, external AI APIs, cloud sync, update checks, uploading any project, session or system information, external fonts/scripts/images/CDNs, and network access by Git subprocesses. External programs the user runs themselves (e.g. Claude Code via a copied resume command) are outside this guarantee; document that.
- **Strictly read-only monitoring.** ccwm never creates, modifies, deletes, renames or changes permissions of any monitored project file, Git repository (including `.git/index` and `.git/config`) or Claude Code session file. It never creates CLAUDE.md files or writes metadata into projects. During normal operation, only ccwm's own config/data/state/runtime directories are writable. `ccwm service install|uninstall` and the install scripts may modify only their documented installation locations.
- No automatic execution of anything extracted from projects or sessions.
- No remote or LAN access. Binding is loopback only, and non-loopback binding is not supported.
- No generic "AI assistant provider" abstraction. Keep the Claude Code integration in its own module and introduce an abstraction only when a second provider is actually built.
- No macOS/Windows support claims.

## 3. Platform and stack

- **Platform:** Linux x86_64. Ubuntu is the primary test target. Only report distributions and environments that were actually tested.
- **Language:** stable Rust. Declare an MSRV in `Cargo.toml`. Commit `Cargo.lock`.
- **Crates:** Axum (HTTP + WebSockets), Tokio, notify, rusqlite with `bundled` SQLite, serde / serde_json, clap, tracing (+ tracing-subscriber, journald-friendly output), a TOML crate for config, and `landlock` for sandboxing (§11.5). Choose walkdir or ignore for traversal (the `ignore` crate is preferred because it evaluates `.gitignore`). Before adding any other dependency, justify it in ARCHITECTURE.md.
- **Frontend:** HTML, CSS and vanilla JavaScript, embedded in the binary. No CDNs, external fonts, frameworks or build step that needs Node.
- **External runtime dependencies:** `git` (optional; Git features degrade gracefully without it) and `claude` (optional; used only to verify resume syntax). Document both.

## 4. Project discovery (v0.1)

### 4.1 Roots and scope
- The default discovery root is the home directory of the non-root user running the service, resolved by platform mechanisms (`$HOME` if it is an absolute path to a directory owned by that user, which is what systemd and login shells provide and what the synthetic test environment of §19 overrides; otherwise the passwd entry of the effective UID). Never hardcode `~/dev` or a username. Refuse to run as root.
- Users can add, remove and narrow roots (including roots outside home that they explicitly authorize) and add exclusion patterns. Changes apply without restart (watchers are reconfigured safely).
- Hard safety boundaries that explicit roots can never override: `/proc`, `/sys`, `/dev`, `/run`, the ccwm data, config, state and runtime directories, and any path not readable by the user.
- `same_file_system = true` by default. Symlinked directories are not followed by default. Max traversal depth defaults to 10 (configurable).
- Paths that are not valid UTF-8 are skipped and counted (`non_utf8` in the discovery status); they are never registered.
- Discovery reads **directory entries and metadata only**. File contents are read only for CLAUDE.md markers (bounded size) and Claude session files.

### 4.2 Default exclusions (configurable)
Skip hidden directories by default (`.*`, which covers `.git`, `.cache`, `.local`, `.config`, `.ssh`, `.npm`, `.cargo`, `.rustup`, `.claude`, `.venv`, browser profiles, trash). Also skip `node_modules`, `target`, `build`, `dist`, `venv`, `__pycache__`, `~/snap`, cloud-sync and FUSE mounts (detected via mount type where possible, e.g. `fuse.*`), VM and container image directories (e.g. `~/VirtualBox VMs`, `~/.local/share/containers` already hidden), and generated artifact and log directories. Prune excluded directories **before** descending. `~/.claude` is read only by the session integration (§7).

### 4.3 What qualifies as a project
A directory is a project candidate if **either** of these holds (both enabled by default):
1. **Marker:** it contains a file named exactly `CLAUDE.md` (case-sensitive). A `CLAUDE.md` that is a symlink counts as a marker (a common `AGENTS.md` pattern). Its target is read only if it resolves to a regular file inside the same project directory.
2. **Session:** a Claude Code session record's working directory (cwd) exists, lies within the allowed roots, and is not excluded.

Never a project: the home directory itself, `~/.claude`, anything under a hard safety boundary, and paths in the ignore list.

### 4.4 Resolving project roots
- **Session cwd → project root:** walk upward from the recorded cwd to the nearest directory that has a `CLAUDE.md` or is a Git work-tree root, without crossing the discovery-root boundary. If none is found, the cwd itself becomes the project root (session-only, non-Git). If the result is the home directory, don't register it; count it as "unassigned sessions" in discovery stats.
- **Store both** the resolved project root (for grouping) and the original session cwd (the **first** recorded cwd, for resume, §8).
- **Nested candidates:** if candidate B lies inside candidate A, B is a separate project only if B is a Git work-tree root different from A's. Otherwise B's `CLAUDE.md` is treated as a nested instruction file belonging to A. Ordinary Git subdirectories never become projects.
- File activity inside a nested project is attributed **only** to that nested project, never to its parent.
- Canonicalize all paths and deduplicate on the canonical path. Record every discovery source per project (`marker`, `session`, or both) and show it in the UI.

### 4.5 Lifecycle
- **First launch:** the server starts immediately. Discovery runs in the background and publishes projects progressively over WebSocket. **Later launches:** cached projects are shown immediately and reconciled in the background.
- **New projects:** a new `CLAUDE.md` in a watched directory (or a new session cwd) registers a project, enriches it and publishes it live, without a restart or page reload. In unwatched locations, the project appears at the next reconciliation.
- **Moves and renames:** use paired inotify rename events when available. Otherwise treat a missing project plus a new project with the same Git HEAD commit and remote (or the same CLAUDE.md content hash for non-Git projects) as a move, and keep the project's ID. If no match is found, mark the old project **missing** (shown in a "Missing" filter) and purge it after the retention period (default 30 days, configurable). Never silently delete projects.
- **Ignore:** users can permanently ignore a project. The ignore is stored by canonical path, and source files are untouched. Ignored projects are hidden and can be un-ignored in Settings.
- **Reconciliation:** a low-priority scan of the roots (default every 10 minutes, configurable). It must not overlap with a running scan, must use bounded concurrency, and must back off on errors. Manual refresh triggers a coalesced reconciliation.
- **Errors:** permission errors, vanished paths and inaccessible mounts are counted and skipped. Discovery never aborts because part of the tree fails. Error reports avoid leaking full sensitive paths unnecessarily.
- **Discovery status** exposes: phase, progress, projects found, skipped/error counts, last successful scan and next scheduled reconciliation.

## 5. Filesystem monitoring and activity (v0.1)

### 5.1 Watches
- **Never** use notify's recursive mode on Linux. Walk eligible trees explicitly, apply exclusions first, and register **non-recursive** watches on eligible directories only.
- Watch targets: project trees (excluding excluded and gitignored directories) and the parent directories of known projects (to detect new sibling projects). Never watch the whole home directory recursively.
- Add watches dynamically for newly created eligible directories, and remove obsolete ones.
- Use exactly **one** notify watcher (one inotify instance) for the whole daemon, because `max_user_instances` is a small shared pool. If the instance cannot be created, start with every project in polled mode and report it (banner, `ccwm doctor`).
- **Watch budget:** default `min(8192, 25% of /proc/sys/fs/inotify/max_user_watches)`, configurable. The inotify pool is shared with IDEs and other tools. Allocation priority: project root directories first, then the most recently active projects.
- **Degraded mode:** when the budget or the kernel limit is reached, or on queue overflow (`IN_Q_OVERFLOW`), mark the affected projects as *polled*, cover them in reconciliation (mtime checks), show a degraded-monitoring banner, and never change kernel limits automatically. Exposing `ccwm doctor` guidance is fine.
- Debounce and coalesce events per project (default 2 s). Bounded queues everywhere.
- Never generate activity from ccwm's own writes. The data, config and state directories are excluded unconditionally.

### 5.2 Meaningful activity
- A modification is *meaningful* if the file is not excluded (§4.2), not inside a nested project (§4.4), and, for Git projects, not gitignored and not under `.git/`. Gitignore evaluation is done in-process (the `ignore` crate's matcher), never by running `git check-ignore`; it approximates Git's own behavior and the differences are documented.
- Each project tracks: latest meaningful modification timestamp, latest modified file (relative path), and a bounded list of recent file events (default last 200 per project; create/modify/delete/rename; retention configurable).
- **Inferred vs observed:** the initial timestamp, computed by a bounded walk at first discovery, is labeled `inferred`. Timestamps from live events are labeled `observed`. The UI shows which it is. Unknown timestamps stay unknown and are never invented.

### 5.3 Activity classification
Based on local calendar days since the last meaningful modification (system time zone):

| Status | Calendar days ago |
|---|---|
| Today | 0 |
| Recent | 1–6 |
| Inactive | 7–29 |
| Dormant | ≥ 30 |
| Unknown | no reliable timestamp |

The thresholds are configurable. The **"Modified this week"** statistic = Today + Recent (days 0–6). This is intentional; keep it consistent with the buckets. Recent activity must never be presented as "a Claude session is running".

### 5.4 Sorting
- Default: latest meaningful file modification, newest first. Unknown sorts last. Ties are broken by name.
- Other sorts in v0.1: latest Claude session, latest Git commit, name.
- Git commit and session timestamps are shown separately and never drive the default sort.

## 6. Git integration (v0.1)

- A **single centralized module** runs all Git commands. Nothing else spawns `git`.
- **Allowlisted invocations only:** `rev-parse` (top-level, git-dir, HEAD), `status --porcelain=v2 --branch --ignore-submodules=all` (branch, upstream, ahead/behind against local remote-tracking refs, staged/modified/untracked), `log -1` with a fixed `--format`, and `config --get remote.origin.url` (or the equivalent for the upstream remote). Any `diff` that is ever added must use `--no-ext-diff --no-textconv`.
- **Always pass:** `--no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false -c core.hooksPath=/dev/null -c protocol.allow=never`.
- **Environment:** start from an empty environment. Set only `PATH`, `HOME`, `LC_ALL=C`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_OPTIONAL_LOCKS=0`. Pass arguments as an argument array with no shell. Never pass untrusted strings as options (use `--` where applicable).
- Timeout of 5 s per command (kill the process group on timeout). Global concurrency limit of 4. Results are cached per project and invalidated by relevant file events (`.git/HEAD`, refs, index) or by reconciliation.
- Handle: no Git installed, non-Git projects, detached HEAD, worktrees, nested repositories, and Git refusing the repo because of `safe.directory` / dubious ownership. Report this as a status and never override it.
- Sanitize remote URLs: strip userinfo and credentials before storing or displaying them.
- **Filter drivers and attributes:** `git status` runs clean/process filter drivers when it re-hashes stat-dirty files, and with `--no-optional-locks` that happens on every call. Reading config never executes anything. Every `status` invocation therefore (a) passes `--attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904` (the empty tree, a built-in object, so nothing is written) so `.gitattributes` in the worktree is not consulted, and (b) first enumerates drivers with `git config --get-regexp '^filter\..*\.(clean|smudge|process)$'` (includes and `includeIf` are resolved) and passes no-op `-c filter.<name>.clean= -c filter.<name>.smudge= -c filter.<name>.process= -c filter.<name>.required=false` for **every** driver in **every** scope (system, global, local, worktree, command line), because `.git/info/attributes` can select a driver even when (a) is in effect. Both are required: each alone leaves a verified bypass. Document the consequence: files whose status depends on attributes or filters (git-lfs, `text`/`eol` normalization) can be reported differently from the user's own `git status`.
- **Minimum Git version:** `--attr-source` was introduced in Git 2.41.0 (Git release notes). The hardened `status` has been verified only on Git 2.43.0 and ccwm reports the versions it was tested on. With an older Git, worktree `status` is **disabled by default** and the project shows the state "status disabled: git too old to harden"; a documented opt-in setting (`git.allow_unhardened_status`, default `false`) re-enables it. `rev-parse`, `log -1` and `config --get` stay available. `git status` runs no hooks; `core.hooksPath` is still overridden.
- Investigate every other repository-controlled configuration that can trigger command execution during the allowlisted commands (clean/process filters, fsmonitor, external diff/textconv, pager, credential and ssh helpers, includes), and document the findings in SECURITY.md. The flags are mitigations, **not a sandbox**; say so.
- Git subprocesses inherit the daemon's Landlock sandbox (§11.5): read-only filesystem and no outbound network where the kernel supports it.
- **Never** fetch, pull, push, commit, checkout, gc or write to monitored repositories.

## 7. Claude Code session integration (v0.1)

### 7.1 Source and schema
- Session root: the `CLAUDE_CONFIG_DIR` environment variable if set, else `~/.claude`. Configurable. Session files are typically `projects/<encoded-dir>/<session-id>.jsonl`. **Verify the actual layout and schema on this machine before implementing**, and record the findings in ARCHITECTURE.md.
- Never derive project paths by decoding directory names. Use the `cwd` recorded in the session records.
- Maintain a **versioned corpus of synthetic fixture files** (`tests/fixtures/sessions/<claude-code-version>/…`) that reproduce the verified schema: real record shapes, subagent/sidechain records, summaries, tool-result "user" records, malformed lines and truncated files. **Never commit real session records, even redacted ones.**
- Schema verification follows the development-time privacy rules (§19).
- Parse unknown record types and unknown fields without failing (skip them and count them).
- Only top-level `projects/<encoded-dir>/<session-id>.jsonl` files are sessions. Files under `<session-id>/subagents/` and everything else in the tree are ignored in v0.1 (counted as skipped) and the limitation is documented.

### 7.2 Incremental parsing
- Keep a checkpoint per file: device, inode, size, byte offset of the last complete line, and mtime.
- On append, parse from the offset. Never advance past an incomplete trailing line. If the inode changed or the size shrank, reparse from 0.
- Cap the maximum line size (default 8 MiB). Skip oversized lines and count them.
- Watch the session directories non-recursively for changes, with debouncing.
- There is no per-record deduplication. Sessions store idempotent per-session aggregates (minimum/maximum timestamps, last-wins title) and the byte-offset checkpoint prevents re-reading, so restarts never double-count.

### 7.3 Extracted data (only what v0.1 needs)
**Stored metadata** per session: session ID, file path, recorded cwd(s) (first and last seen), start time (the **minimum** timestamp over conversational records, i.e. `user`, `assistant`, `attachment` and `system` records), last activity time (the **maximum**; timestamps are not ordered within a file, so neither the first nor the last line is used), whether it is a subagent/sidechain session (when recorded; always false for ingested files in v0.1), and the recorded title or summary (when present, labeled *recorded*, redacted before storage).

**Prompt text is not stored by default.**
- The **last genuine user prompt** (and the first-prompt fallback) are read **on demand** when the detail panel is opened. Use a bounded tail read (or head read for the first prompt) of the original session file, at most 4 MiB, and truncate to 2,000 characters. Redact the result and don't persist it.
- *Genuine user prompt:* Claude Code also writes tool results and meta/command records as `user`-type records. A genuine prompt is a `user` record whose `promptSource` is `typed` or `queued`. `promptSource` values `sdk` and `system` are never genuine (the session itself still counts), and any other value is not genuine unless the maintainer's schema output (§19) shows otherwise. Records **without** `promptSource` go through a multi-field classifier built from the verified schema: not `isMeta`, not `isSidechain`, not `isCompactSummary`, no `toolUseResult` and no `tool_result` content, `turnOrigin` not `task_notification`, and text not beginning with a known synthetic tag. The last prompt is taken from `user` records, **never** from `last-prompt` records (which are truncated to about 200 characters).
- Cards show the recorded title, or "Untitled session". The truncated **first** genuine user prompt, explicitly labeled "first prompt", appears only in the detail panel, on demand.
- Setting: "Store prompt text" (**opt-in, default off**). When on, the last prompt is cached in SQLite (redacted) for faster display. Turning it off deletes the cached text.
- Never store full transcripts, assistant responses, or tool inputs or outputs in v0.1.
- Apply best-effort secret redaction to **everything displayed or stored** from sessions, titles included: private key blocks, common token formats such as `ghp_`, `github_pat_`, `sk-`, AWS access keys, `Bearer …`, `password=`. Document that redaction is not guaranteed to find every secret.
- "Clear session index" in Settings deletes ccwm's derived session data only. It never touches the original session files.
- Session duration is shown only when it can be computed reliably from recorded timestamps.
- Never fabricate titles, summaries, progress or pending tasks. Show explicit "not recorded" states.
- Session text is untrusted data. It is never interpreted as instructions and never rendered as HTML.

## 8. Resume commands (v0.1)

- Command form: `cd -- '<recorded-session-cwd>' && claude --resume <session-id>`
- The cwd is the session's **first recorded cwd** (a session can change directory later; the first cwd matches the directory Claude Code stores the session under), not the last cwd and not the resolved project root.
- Session IDs must pass strict UUID validation, or no command is generated.
- Paths are shell-escaped with POSIX single quotes (each `'` becomes `'\''`). Add a unit test with adversarial paths (spaces, quotes, `$()`, backticks, newlines, leading `-`).
- **CLI verification:** at startup and in `ccwm doctor`, locate `claude` on `PATH` and run `claude --version` and `claude --help` with a 5 s timeout. Confirm `--resume` is supported and cache the result keyed by binary path and mtime. Never run it per request.
- If `claude` is missing or unverified, still show the command with a warning. If the recorded cwd no longer exists, show a warning.
- The UI offers **copy only**. ccwm never executes resume commands or anything else taken from sessions or projects.

## 9. Dashboard UI (v0.1)

Clean, modern and responsive, inspired by GitHub and Linear without copying their branding. Dark, light and system themes. Semantic HTML, full keyboard navigation, visible focus, WCAG AA contrast, `prefers-reduced-motion` respected. Restrained animation. **Never use `innerHTML` (or equivalents) with data.** Build the DOM with `textContent` and DOM APIs.

- **Header:** product name, service and discovery status, last sync time, privacy toggle, theme toggle, settings.
- **Summary stats:** total projects, modified today, modified this week (0–6), inactive, dormant, projects with uncommitted changes, total sessions.
- **Toolbar:** search (name, path, branch), card/table toggle, sort (§5.4), activity filter (all/today/this week/inactive/dormant/unknown), "uncommitted changes" filter, "has sessions" filter, "show missing" toggle, manual refresh, discovery progress indicator.
- **Card view (default):** name, path, last meaningful modification (relative time; exact timestamp on hover and focus; inferred/observed marker), last modified file, Git branch and status, latest commit subject, latest session title/first prompt and time, session count, activity status, discovery source badge.
- **Table view:** compact, sortable columns for the same core fields, plus actions (open details, copy resume command, ignore). Paginate when there are more than 100 rows.
- Both views share the same data, search, sort and filters. View and theme persist in `localStorage`, and the default view comes from Settings.
- **Project detail panel** (opened from a card or row): canonical path, discovery sources, Git branch / upstream / ahead-behind, latest commit (short hash, subject, author, date), staged / modified / untracked files (capped at 200, with a count beyond that), latest session (title or first prompt, start and last activity, session count), **last user prompt**, and the **resume command** with a copy button and any warnings. Missing projects show a missing state.
- **Settings page:** roots, exclusions, ignored projects (un-ignore), scan interval, watch budget, activity thresholds, default view, theme, port (marked "requires restart"), store prompt text, clear session index, missing-project retention. Show the current discovery scope and exclusions in plain language. Validate input and explain which changes need a restart.
- **States:** loading, empty (explains the roots and qualification rules), error, partial discovery progress, degraded-monitoring banner, disconnected/reconnecting banner, unauthenticated page ("Run `ccwm open` in a terminal").
- **Live updates:** WebSocket events for project added/updated/removed, stats and discovery status. Reconnect with exponential backoff and fetch a fresh snapshot after reconnecting.

## 10. Privacy mode (v0.1)

A one-click toggle in the header (persisted in `localStorage`, with a default in Settings). When it's on, the **server omits** these fields from REST and WebSocket payloads for that client, so they never reach the DOM:
- absolute paths (show the project name only)
- usernames (including Git author names)
- Git remote URLs
- session titles, first and last user prompts, and excerpts
- resume commands

Applied consistently in cards, table, detail panel, search results and tooltips. Search must not match hidden fields while privacy mode is on. Project-name anonymization is deferred (§18).

## 11. Authentication and security (v0.1)

### 11.1 Threat model (also documented in SECURITY.md)
- **In scope:** other local Linux users; malicious websites (CSRF, cross-origin reads, DNS rebinding); other localhost services, including ones listening on other ports; malicious project files, CLAUDE.md content, session content and Git configuration.
- In scope also: another local user binding the ccwm port while the daemon is down, to impersonate it.
- **Out of scope:** malicious processes running as the same Linux user (they can read the data directly), a compromised OS or kernel, and root or privileged attackers.
- Claim no protection beyond this model.

### 11.2 Credentials
- **CLI ↔ daemon channel:** a **Unix domain socket** at `$XDG_RUNTIME_DIR/ccwm/ccwm.sock` (directory `0700`, socket `0600`). The daemon authenticates every connection with `SO_PEERCRED`: the peer UID must equal the daemon's UID. The CLI verifies the daemon the same way (peer UID equals its own) before sending anything. The protocol is newline-delimited JSON (one request object and one response object per connection) dispatched into the **same service layer** the HTTP handlers use; no HTTP client or server is involved, and HTTP client crates are banned (§11.5). If `XDG_RUNTIME_DIR` is unset, the runtime directory falls back to `$XDG_STATE_HOME/ccwm/run/`. In either case the directory must be owned by the user with mode `0700` (verified by the daemon and by the CLI) and the socket path must fit the 108-byte `sun_path` limit, otherwise startup fails with a clear message. **The CLI never sends credentials over TCP**, so an impostor on the TCP port receives nothing. There is no CLI token file.
- **Bootstrap token:** `ccwm open` asks the daemon over the Unix socket for a random single-use bootstrap token valid for 60 s, along with the TCP port the daemon actually bound. Only then does it open `http://127.0.0.1:<port>/#bt=<token>` (or print the URL with `--print` or when no display is available). The single canonical browser origin is `http://127.0.0.1:<port>`; `localhost` is a different origin and would split `localStorage`.
- The page reads the fragment, **removes it immediately** with `history.replaceState`, and exchanges it (`POST /api/v1/auth/exchange`, which requires a valid, unexpired, unused bootstrap token) for a **session token**. The session token is 32 random bytes, stored in `localStorage`, valid for 30 days on a sliding basis, and rotated at least every 24 h via `POST /api/v1/auth/rotate`, which issues a new token and keeps the previous one valid for 60 s (so concurrent tabs don't race).
- REST requests use `Authorization: Bearer <session token>`. Browsers never send this automatically, which handles CSRF. State-changing requests additionally require an allowed `Origin`.
- **WebSocket:** the `Origin` is validated on upgrade. The client must send `{"type":"auth","token":…}` as its first message within 5 s, or the connection is closed with code 4401. No data is sent before authentication succeeds. **Existing connections are revalidated:** when a session token expires, is rotated out or is revoked, the daemon closes every WebSocket bound to it with code 4401.
- **Revocation:** a "Sign out" button in the UI (revokes the current session) and `ccwm auth revoke-all` over the Unix socket (revokes every browser session).
- The server stores tokens **hashed** (SHA-256) and compares them in constant time. Tokens never appear in logs, error messages, URLs (apart from the single-use fragment) or the database in plaintext.
- Unauthenticated TCP endpoints: `GET /api/v1/health` (status and version only), the static assets, and `POST /api/v1/auth/exchange`. A health response on TCP is **never** treated as proof of daemon identity; identity is established only over the Unix socket.

### 11.3 HTTP hardening
- Bind to `127.0.0.1` only. Non-loopback binding is not supported in v0.1.
- **Host validation:** accept only `127.0.0.1:<port>`, `localhost:<port>` and `[::1]:<port>` (DNS rebinding defense). Reject all others with 421/403.
- **Origin validation** for state-changing requests and WebSocket upgrades: it must equal `http://127.0.0.1:<port>`. TCP requests without an Origin are rejected for state-changing endpoints; the CLI uses the Unix socket instead. Any request to `/api/v1` that carries an Origin other than the allowed one is rejected, including GET.
- **CSP:** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:<port>; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. No inline scripts or styles, no `eval`.
- Also send `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses, and `Cross-Origin-Opener-Policy: same-origin`.
- Validate and canonicalize every path input. Project IDs are opaque and validated. Prevent path traversal and symlink escapes. Use parameterized SQL only.
- **Residual risks, documented in SECURITY.md:** an XSS bug could steal the `localStorage` token (mitigated by the no-`innerHTML` rule and the CSP); a same-user process can read everything; the bootstrap fragment briefly exists in the browser history (it is single-use and expires in 60 s).

### 11.4 Data protection
- Data directory `0700`, files `0600`, process umask `0077`.
- Never log session content, prompts, tokens or credentials. Redact remote URLs in logs.

### 11.5 OS-level enforcement (best effort, reported)
- At startup, before discovery begins, the daemon applies a **Landlock** ruleset to itself. The ruleset is inherited by all child processes (`git`, `claude --version/--help`):
  - Read and execute allowed under the discovery roots, the Claude session directory, and the system paths needed to run `git`/`claude` (e.g. `/usr`, `/etc`, `/lib*`).
  - Write allowed **only** under ccwm's config, data, state and runtime directories.
  - Landlock ABI ≥ 4 (Linux 6.7+): deny all TCP `connect`, and allow TCP `bind` only on the configured port.
- Use the highest ABI the kernel supports. If Landlock is unavailable or only partly supported, run anyway and report exactly which protections are active in `ccwm doctor`, `/service/status` and the startup log. Never claim a protection that isn't active.
- Apply systemd user-unit hardening only where verified to work in user units. Don't depend on `ProtectHome`/`ReadOnlyPaths`, which need user namespaces in user units and fail on some systems.
- **Dependency-level enforcement:** `cargo-deny` bans HTTP/network client crates (e.g. `reqwest`, `ureq`, `curl`, `hyper` client features, `hyper-util` client, `isahc`, `attohttpc`) and DNS resolver crates. CI fails if any appear in the dependency tree.
- Tests catch regressions; they cannot prove the absence of network activity. Document the guarantee in those terms.

## 12. REST and WebSocket API (v0.1)

Browser endpoints are served on TCP under `/api/v1`. CLI operations (bootstrap token, refresh, status, revoke-all) are served on the Unix socket with the same handlers and JSON contracts, authenticated by peer credentials, as JSON lines (for example `{"op":"auth.bootstrap"}` answered by `{"ok":{…}}` or `{"error":{"code":…,"message":…}}`) through the same service layer. The CLI endpoints are not reachable over TCP.

All endpoints live under `/api/v1`. They return JSON and use structured errors `{"error":{"code":"…","message":"…"}}` with correct status codes. All input is validated. Lists use opaque keyset cursor pagination (`limit` ≤ 200; the cursor encodes the sort key and the id). Contracts are documented in ARCHITECTURE.md.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness and version (unauthenticated; useful during initial discovery) |
| POST | `/auth/bootstrap` | **Unix socket only**: issue a single-use bootstrap token |
| POST | `/auth/exchange` | Bootstrap → session token |
| POST | `/auth/rotate` | Issue a new session token; the old one stays valid for 60 s |
| POST | `/auth/logout` | Revoke the current session |
| POST | `/auth/revoke-all` | **Unix socket only**: revoke all browser sessions |
| GET | `/projects` | List; `q`, `sort`, `order`, `activity`, `dirty`, `has_sessions`, `include_missing`, `limit`, `cursor` |
| GET | `/projects/{id}` | Project detail incl. Git status and latest session |
| GET | `/projects/{id}/sessions` | Latest sessions (default 1, max 10) with resume command |
| PUT | `/projects/{id}/ignore` | Ignore |
| DELETE | `/projects/{id}/ignore` | Un-ignore |
| GET | `/stats` | Summary statistics |
| GET | `/discovery/status` | Discovery progress and health |
| GET | `/service/status` | Version, uptime, watch count/budget, degraded projects, queue depths, last scan, CLI verification result |
| GET / PUT | `/settings` | Read and update; the response lists changes that require a restart |
| POST | `/refresh` | Trigger a coalesced reconciliation (202) |
| POST | `/session-index/clear` | Clear derived session data |
| GET | `/ws` | WebSocket (auth per §11.2) |

Privacy mode is a per-request flag (`privacy=1`) and a per-WebSocket subscription option.

## 13. CLI and service management (v0.1)

| Command | Behavior |
|---|---|
| `ccwm serve [--port N] [--config PATH]` | Run the daemon in the foreground. This is what systemd runs. |
| `ccwm start` / `stop` / `restart` | Wrap `systemctl --user … ccwm.service`. Clear error if the unit isn't installed. |
| `ccwm status` | systemd state plus a `/service/status` summary |
| `ccwm open [--print]` | Get a bootstrap token and open or print the URL |
| `ccwm scan` | Trigger a refresh through the daemon over the Unix socket and report progress. **Never opens SQLite itself.** Errors clearly if no daemon is running. |
| `ccwm doctor` | Checks: daemon running (verified over the Unix socket), port, inotify limits and usage, Git version, `claude` CLI and resume support, session directory found and readable, data directory permissions, active Landlock protections (filesystem/network, ABI level), lingering status. Suggests fixes and never applies them. |
| `ccwm service install` / `uninstall [--purge]` | Write or remove the user unit, then `daemon-reload` and `enable --now` / `disable --now`. Uninstall preserves data unless `--purge` is given (with a confirmation prompt). No sudo. |
| `ccwm auth revoke-all` | Revoke all browser sessions |
| `ccwm --help` / `--version` | Help text includes the unofficial-project notice |

- **Single instance:** use an `flock` on `$XDG_RUNTIME_DIR/ccwm/ccwm.lock` (released automatically when the process dies, so stale locks can't happen), plus `instance.json` (pid, port, version, start time). The CLI validates the instance only over the Unix socket, using peer credentials, never by a TCP health check. Only the daemon writes to the database.
- **Port collision:** fail fast with a clear message naming the port and suggesting `--port` or the Settings change. Use a dedicated exit code, listed in `RestartPreventExitStatus=`, so systemd doesn't restart-loop; "another instance holds the lock" gets its own dedicated code in the same list. Never auto-pick another port. Port is set by default 8765, `--port`, or the config file.
- **systemd user unit** (`~/.config/systemd/user/ccwm.service`): `ExecStart=%h/.local/bin/ccwm serve`, `Restart=on-failure`, `RestartSec=5`, `TimeoutStopSec=10`, `UMask=0077`, `Nice=10`, `IOSchedulingClass=idle`, `NoNewPrivileges=yes`, plus any other hardening directives verified to work in **user** units. `ProtectSystem=strict` and `ProtectHome=read-only` with `ReadWritePaths=` for ccwm's directories may be added as defense in depth only after the real daemon has been tested under them (M4); Landlock (§11.5) remains the primary enforcement. `PrivateDevices` is not used (it is rejected in user units). Logs go to journald. Graceful shutdown on SIGTERM flushes the database writer and closes watchers.
- **Scripts:** `scripts/install.sh` (copies the binary to `~/.local/bin`, runs `ccwm service install`, prints next steps) and `scripts/uninstall.sh`. Both are idempotent, run no privileged commands and preserve data by default.
- **Documentation:** start/stop/restart/enable/disable/status/logs (`journalctl --user -u ccwm -f`), manual foreground mode, and the difference between starting at login and starting at boot. For boot-before-login, document `loginctl enable-linger $USER`, which may require administrator authorization depending on polkit policy. Never run it automatically.

## 14. Storage and configuration (v0.1)

- **Locations (XDG):** config `$XDG_CONFIG_HOME/ccwm/config.toml`; database `$XDG_DATA_HOME/ccwm/ccwm.db`; state `$XDG_STATE_HOME/ccwm/`; lock, `instance.json` and the Unix socket in `$XDG_RUNTIME_DIR/ccwm/`. All are outside the monitored trees and always excluded.
- **Settings** live in `config.toml` (human-readable, written atomically, `0600`). The port must be readable before the database opens. The file is read at startup only; `PUT /settings` rewrites it atomically (comments are not preserved) and hand edits made while the daemon runs are overwritten. Runtime and derived data live in SQLite.
- **SQLite:** rusqlite with bundled SQLite, WAL mode, `foreign_keys=ON`, `busy_timeout`, embedded versioned migrations (`PRAGMA user_version`), and indexes on the sort and filter columns. **One dedicated writer thread** fed by a bounded channel with batched transactions. Reads run on a small pool of read-only connections via `spawn_blocking`. Synchronous SQLite calls never run on Tokio worker threads.
- **Tables (minimum):** projects, project_sources, file_events (bounded), git_cache, sessions, session_file_checkpoints, ignored_paths, auth_sessions (hashed), meta.
- Constraints prevent duplicate projects (unique canonical path) and repeated session ingestion (unique session ID; per-session aggregates are idempotent).

## 15. Performance (v0.1)

- Target an always-on daemon: no continuous full scans, no unbounded watchers, queues or memory, no repeated full session parsing, no Git polling loops.
- **Targets** (to be measured, not assumed): idle CPU under 1% averaged over 10 minutes, and RSS under 50 MB with 200 projects.
- **Measure and document actual results** on synthetic fixtures (and on the dev machine if permitted): idle CPU, RSS, initial discovery duration, watch count, behavior with 500 synthetic projects, an event burst (10k file changes), and watch exhaustion and recovery. Publish the numbers with hardware and method. Never invent results.

## 16. Testing (v0.1)

Rust unit and integration tests using temporary directories, temporary Git repositories and synthetic session fixtures. Never touch real user projects or `~/.claude` in tests. Use injectable roots and clocks.

Coverage must include:
- Discovery: arbitrary home layouts, exact marker matching, symlinked markers, home and `~/.claude` exclusion, nested projects (Git and non-Git), session-cwd resolution (subdirectory cwd → project root), unassigned home sessions, deduplication, exclusions, symlink loops, `same_file_system`, inaccessible paths, explicit roots, ignore and un-ignore.
- Lifecycle: create, delete, rename and move (paired events and the fallback matcher), missing state, retention purge, a live marker creation appearing over WebSocket, creation outside watched areas found by reconciliation.
- Monitoring: non-recursive watch registration, watch budget enforcement, degraded mode, overflow recovery, debouncing, nested activity attribution, gitignored files ignored, no self-generated activity.
- Activity: bucket boundaries (0/1/6/7/29/30 days, across midnight and DST changes), the "this week" statistic, sort order including unknowns.
- Git: dirty/clean/untracked/staged, detached HEAD, worktrees, missing Git, `safe.directory` refusal, timeouts, remote URL sanitization, and **malicious configurations** (`core.fsmonitor` command, `core.hooksPath`, `diff.external`, textconv, a `core.pager`/`sshCommand` that would execute) asserting no execution, for example with a sentinel-file test.
- Sessions: incremental appends, partial trailing lines, truncation and rotation, malformed JSON, unknown types and fields, oversized lines, subagent records, tool-result "user" records excluded from the last prompt, deduplication across restarts, redaction, on-demand prompt reads bounded in size, no prompt text persisted while "Store prompt text" is off.
- Resume: UUID validation, adversarial path escaping, use of the recorded cwd, warning states.
- Security: auth flow (bootstrap single-use and expiry, exchange, rotation, logout, revoke-all), WebSocket auth timeout and no data before auth, WebSocket closed on token expiry and revocation, Host and Origin rejection, the CSP header present, path traversal attempts, privacy-mode field omission, Unix-socket peer-credential rejection (simulated mismatch), the CLI refusing to talk to an impostor (a TCP listener on the port with no valid socket).
- **Security acceptance tests** (required; each must exist and pass):
  1. Monitored project files are unchanged after discovery, watching and reconciliation (hash the full fixture tree, including mtimes and modes, before and after).
  2. Claude session files are unchanged (hash before and after parsing, clearing the index and uninstalling).
  3. `.git/index`, `.git/config` and refs are unchanged after every Git operation.
  4. Malicious Git configurations cannot execute commands: local-scope `core.fsmonitor`, clean/smudge/process filters activated by `.gitattributes`, `diff.external`, textconv, `core.pager`, `core.sshCommand`, `include`/`includeIf` pulling in any of these. Each is asserted with a sentinel file that must not appear.
  5. No external network connections: the daemon and its Git subprocesses run in a network namespace (`unshare -rn`, skipped with a notice where unavailable) through a full discovery, Git and session cycle, asserting that no non-loopback connect is attempted. `cargo-deny` network-crate bans pass.
  6. Unauthorized access is rejected: no token, an expired token, a revoked token, a wrong Origin, a wrong Host, and a peer-UID mismatch on the Unix socket. A real cross-user check is documented as a manual procedure.
  7. Path traversal and symlink escapes are rejected in all path inputs and in marker reads.
  8. Logs contain no sensitive data: run with canary secrets planted in fixture prompts, tokens and remote URLs, and assert none appear in the captured logs at any level.
  9. Runtime data and credentials are excluded from Git: a CI check that `git check-ignore` matches the database, WAL/SHM, the socket, config, state and `*.jsonl` outside the fixtures.
  10. Clearing the session index, deleting the ccwm database and `ccwm service uninstall --purge` leave project and Claude data byte-identical.
  11. Landlock: on kernels that support it, a write outside ccwm's directories and an outbound connect from the daemon and from a Git subprocess are both denied.
- API: validation errors, pagination, settings round-trip, restart persistence.
- CLI and service: single-instance lock, port collision exit code, `scan` going through the API, graceful shutdown.
- UI: view toggle preserving search, sort and filters; theme and view persistence; privacy toggle. Use lightweight DOM tests where practical, or documented manual verification steps.

Required to pass before each milestone is complete: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`.

## 17. Release engineering and documentation (v0.1)

- **Repository hygiene:** create a comprehensive `.gitignore` **before any code**. Ignore: `target/`; `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `*-journal`; token, credential, key and `.env*` files; local config and runtime state; `*.jsonl` **except** `tests/fixtures/**`; `.claude/settings.local.json`; logs; local benchmark results and test artifacts; IDE and OS files. Commit `Cargo.lock`, authored docs, sanitized `config.example.toml` and reviewed synthetic fixtures.
- **CI (GitHub Actions):** fmt, clippy, test, `cargo-deny` (licenses, advisories, and the network-crate bans from §11.5), gitleaks secret scanning (action pinned to a SHA) and the hygiene check from §16, on push and PR.
- **Before first publication:** audit all tracked files and the full Git history for sensitive data (gitleaks over history plus a manual review), and record the audit in the release notes. Release workflow on tag: build `x86_64-unknown-linux-musl` with bundled SQLite and embedded assets, strip, produce a `.tar.gz` and `SHA256SUMS`. Pin third-party actions to commit SHAs. Use least-privilege `permissions:`.
- Validate the release binary on the build host. Report only the environments actually tested.
- Do not create a GitHub repository, push, tag or publish without explicit authorization.
- **Documentation:**
  - `README.md`: what it is, the unofficial notice, quick start, privacy summary, screenshots once a real UI exists.
  - `CLAUDE.md`: architecture map, conventions, how to test, current milestone status. Keep it current.
  - `REQUIREMENTS.md`: this file.
  - `ARCHITECTURE.md`: modules, data flow diagram (Mermaid), schema, API contracts, verified session schema findings, Git hardening rationale.
  - `ROADMAP.md`: milestone checklist and the §18 backlog.
  - `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` (threat model, residual risks, reporting), `LICENSE`.
  - The docs must also cover a configuration reference, discovery semantics, inotify limits and troubleshooting, data retention and deletion, and service management.

## 18. Roadmap — v0.2 and later (do NOT implement in v0.1)

- Full session history, expandable conversations, and resume for older sessions
- CLAUDE.md rendering (pulldown-cmark + ammonia, server-side sanitization)
- Project notes, pending tasks, next steps, tags, custom descriptions
- Git commit history view, file activity timeline
- Pinning, pins-first mode, advanced filters, sort by discovery date
- Full-text session search (FTS5)
- Manual project split/merge overrides
- Project-name anonymization in privacy mode
- Data export
- Local usage statistics (local only, no telemetry)
- ARM64 (aarch64-musl) release binaries on native runners
- Additional AI coding assistants, with the provider abstraction introduced then
- macOS and Windows support

## 19. Development-time privacy (applies to the coding agent)

- Do not load the maintainer's real Claude Code conversations, proprietary project files, credentials or customer data into the coding agent's context.
- **Schema inspection:** the agent writes a bounded inspection script (e.g. `scripts/inspect-session-schema.sh` or `.py`) that prints only:
  - JSON key paths and value types
  - values of an allowlisted set of low-cardinality discriminator fields (e.g. `type`, `subtype`, `message.role`, `message.content[].type`, `isMeta`, `isSidechain`, `version`)
  - per-type record counts and file counts
  
  It prints no other string values and no paths beyond the directory structure pattern. **The maintainer reviews and runs the script and pastes the output back.** The agent does not run it, and does not read, `cat`, `head`, `grep` or otherwise open real session files.
- All agent-run execution and validation (`ccwm serve`, `curl`, benchmarks, screenshots) uses a **synthetic environment**: `HOME`, `XDG_*` and `CLAUDE_CONFIG_DIR` point to a generated directory under `/tmp` populated with synthetic projects and fixture sessions. Validation against the maintainer's real home directory is done by the maintainer in a browser.
- Documentation, screenshots and benchmarks use only synthetic data.

## 20. v0.1 milestones

Each milestone must be runnable end to end, have passing tests and meet its acceptance criteria before the next one starts. Update ROADMAP.md and CLAUDE.md at the end of each milestone.

**M1 — Foundation**
`.gitignore` first, then: Cargo scaffold, config, XDG paths and permissions, SQLite and migrations with the writer thread, single-instance lock, the Unix-socket CLI channel with peer-credential auth, the Landlock sandbox with active-protection reporting, `serve`/`open`/`--version`/`--help`, the full browser auth flow and HTTP hardening, CLAUDE.md marker discovery over the home directory (progressive, cached), core API (`/health`, `/projects`, `/stats`, `/discovery/status`), a basic card list UI (browser progress by polling; WebSocket arrives in M2), `POST /auth/rotate`, the synthetic test environment generator (§19), and the schema inspection script (handed to the maintainer to run).
*Accept (in the synthetic environment):* `ccwm serve` + `ccwm open` show marker-discovered projects. Unauthenticated, wrong-Host and wrong-Origin requests are rejected. The CLI refuses an impostor TCP listener. A restart shows the cached projects immediately. Security acceptance tests 1, 6, 7, 9 and 11 pass.

**M2 — Activity tracking**
The non-recursive watch engine with budget and degraded mode, reconciliation, meaningful-activity rules, buckets and sorting, the hardened Git module with malicious-config tests, card and table views with search, sort and filters, WebSocket live updates with reconnect, ignore, and the missing state.
*Accept:* editing a file moves its project to the top live. Creating a `CLAUDE.md` in a watched area registers a project without a reload. Git status is correct. Security acceptance tests 3, 4 and 5 pass.

**M3 — Development continuity**
Session schema verification and the fixture corpus, incremental parser, session-based discovery and cwd resolution, latest session and last-prompt extraction with redaction, resume commands and CLI verification, the detail panel, privacy mode, and the Settings page.
Built from the maintainer's pasted schema output (§19), using synthetic fixtures only.
*Accept:* a project with sessions but no CLAUDE.md appears. The detail panel shows the last prompt (read on demand), Git status, files and a correct resume command (recorded cwd, escaped). No prompt text is persisted by default. Privacy mode removes the listed fields from the payloads. Security acceptance tests 2, 8 and 10 pass.

**M4 — Release readiness**
`start/stop/restart/status/scan/doctor/service/auth` commands, the systemd unit and scripts, the port-collision exit code, the security and performance test pass with measured results, the full documentation set, CI and the release workflow, and the musl build.
*Accept:* a fresh user account can install from the release archive, the service starts at login (and at boot when lingering is enabled), the projects appear, all tests including the full security acceptance suite pass, CI (including gitleaks and the cargo-deny bans) is green, and the benchmarks are documented.

---

## Appendix A — Superseded, removed and deferred requirements

| Earlier requirement | Disposition |
|---|---|
| Python / FastAPI / Uvicorn stack | Superseded → Rust (§3) |
| SQLx | Superseded → rusqlite with bundled SQLite and a dedicated writer (§14) |
| Names "Claude Dashboard", "Claude Code Workspace Manager", `claude-workspace` | Superseded → CC Workspace Manager / `ccwm` (§1) |
| Hardcoded `~/dev` root | Superseded → user's home directory, configurable roots (§4.1) |
| Home from the passwd entry only | Superseded → `$HOME` (owned by the user) first, then passwd, so the §19 synthetic environment cannot silently fall through to the real home (§4.1) |
| CLAUDE.md as the only qualifying marker | Superseded → CLAUDE.md **or** session cwd (§4.3) |
| Session-only candidates "optionally surfaced" | Superseded → enabled by default (§4.3) |
| Cookie-based browser sessions (HttpOnly, SameSite) | Superseded → origin-scoped bearer tokens (§11.2) |
| "WebSockets or SSE" | Decided → WebSockets (§12) |
| notify recursive watches | Superseded → explicit non-recursive watches (§5.1) |
| Unversioned `/api/*` | Superseded → `/api/v1/*` (§12) |
| `/commits`, `/activity`, `/notes`, `/pin` endpoints | Deferred → v0.2 (§18) |
| Overlapping activity thresholds | Superseded → calendar-day buckets (§5.3) |
| Resume from the project root | Superseded → resume from the recorded session cwd (§8) |
| Generic AI-provider interface | Removed from v0.1 (§2) |
| Full session history, conversation view, searchable transcripts | Deferred (§18) |
| Storing assistant responses / tool activity | Removed from v0.1 (§7.3) |
| CLAUDE.md content on the detail page | Deferred → requires sanitized Markdown (§18) |
| Notes, TODOs, tags, next steps, custom description | Deferred (§18) |
| Pinning, pins-first mode, discovery-date sort | Deferred (§18) |
| FTS5 session search | Deferred (§18) |
| Project-name anonymization | Deferred (§18) |
| Data export | Deferred (§18); delete controls kept (§7.3, §13) |
| "Usage analytics" | Renamed to local usage statistics, deferred (§18) |
| ARM64 release, macOS, Windows | Deferred (§18) |
| "Validate on supported distributions" | Superseded → report only tested environments (§17) |
| Response-latency benchmarking | Removed (§15) |
| Discovery cancellation | Removed; discovery runs in the background without blocking (§4.5) |
| Non-loopback / LAN binding | Removed from v0.1 (§11.3) |
| CLI token file sent as a bearer over TCP | Superseded → Unix socket with `SO_PEERCRED` (§11.2) |
| Validating the daemon via a TCP `/health` check | Superseded → identity only via the Unix socket (§11.2, §13) |
| "Store prompt text", default on | Superseded → opt-in; on-demand bounded reads by default (§7.3) |
| Redacted real session samples as fixtures | Superseded → synthetic fixtures only (§7.1, §19) |
| Agent reads real session files to learn the schema | Superseded → maintainer-run structural inspection script (§19) |
| Agent validates against the real home directory | Superseded → synthetic environment (§19) |
| "Does not execute their contents" (unconditional) | Reworded → fundamental guarantee with documented limits (§0, §6) |
| Mandatory systemd `ProtectHome`/`ReadOnlyPaths` | Superseded → Landlock, best effort and reported (§11.5) |
| Neutralize only local/worktree-scope filter drivers | Superseded → every scope, plus `--attr-source=<empty tree>` (§6); verified bypasses otherwise |
| Git hardening flags alone prevent execution | Superseded → filter drivers run during `status` without the §6 filter rules (found by sentinel test) |
| Git without `--attr-source` assumed fine | Superseded → minimum Git 2.41.0 for worktree status, else disabled with an opt-in (§6) |
| Session start time = first record timestamp | Superseded → minimum timestamp over conversational records (§7.3) |
| Last activity = last record | Superseded → maximum timestamp (§7.3) |
| Resume from the last recorded cwd | Superseded → first recorded cwd (§8) |
| Last prompt from `last-prompt` records | Superseded → `user` records via `promptSource`/classifier; `last-prompt` records are truncated (§7.3) |
| Per-record deduplication key | Superseded → idempotent per-session aggregates + offset checkpoints (§7.2, §14) |
| Subagent/sidechain files ingested as sessions | Superseded → ignored in v0.1 (§7.1) |
| HTTP client crate (`ureq`) for the CLI | Rejected → JSON lines over the Unix socket (§11.2, §11.5) |
| No session-token rotation mechanism | Added `POST /auth/rotate`, 60 s grace (§11.2, §12) |
| Runtime directory outside the hard boundaries | Added to the hard boundaries (§4.1) |
| `XDG_RUNTIME_DIR` assumed set | Fallback `$XDG_STATE_HOME/ccwm/run/`, owner and mode verified, 108-byte limit (§11.2) |
| Several inotify instances | Exactly one watcher, polled fallback (§5.1) |
| Non-UTF-8 paths unspecified | Skipped and counted (§4.1) |

## Appendix B — Assumptions and verdicts

Verdicts were recorded on 2026-11-23 on the development host (Ubuntu 24.04.4, Linux 7.0.0-34, git 2.43.0, Claude Code 2.1.331). Session-schema facts come from a structural inspection of the maintainer's session directory (key paths, value types and low-cardinality discriminators only; accepted by the maintainer). Further session-schema inspection follows §19.

| # | Assumption | Verdict |
|---|---|---|
| 1 | Claude Code session files are JSONL under `<config dir>/projects/*/`, and records carry `sessionId`, `cwd`, `timestamp` and `type` fields, plus some way to tell genuine user prompts from tool results and meta records. | **Partly true.** Layout, `sessionId` (equals the file stem) and ISO-8601 `timestamp` are confirmed. `cwd` exists only on `user`, `assistant`, `attachment` and `system` records. Timestamps are not ordered within a file. No single flag identifies genuine prompts: `promptSource`/`turnOrigin`/`isMeta`/`isCompactSummary`/`toolUseResult` combine, and some records lack `promptSource` (§7.3). Subagent files sit deeper, in `<session-id>/subagents/`. |
| 2 | `claude --resume <session-id>` is the resume syntax and must be run from the session's original cwd. | **Syntax confirmed** in `claude --help` (2.1.331). The cwd requirement is **untested** (running it starts an interactive session) and inferred from the directory naming. |
| 3 | `CLAUDE_CONFIG_DIR` overrides the default `~/.claude` location. | **Not verifiable on this host** (the variable is unset); the string occurs in the `claude` binary. Treated as true; tests inject the root. |
| 4 | `--no-optional-locks` and the listed `-c` overrides are honored by the installed Git version. | **True on 2.43.0 but insufficient:** `filter.*.clean` still executed (§6). The §6 filter rules were verified on 2.43.0. |
| 5 | The systemd hardening directives chosen in §13 are accepted in user units on Ubuntu. | **True for `NoNewPrivileges`, `Nice`, `IOSchedulingClass`, `UMask`**, and for `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernelTunables`, `RestrictNamespaces`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute`, `LockPersonality`, `SystemCallArchitectures`. **`PrivateDevices=yes` is rejected.** The real daemon has not yet been tested under them (M4). |
| 6 | Landlock ABI level (`/sys/kernel/security/lsm` contains `landlock`; ABI ≥ 4 for network rules), and a Landlock-restricted process can still bind its TCP port and serve its Unix socket. | **Kernel side confirmed:** `landlock` is in the LSM list and the ABI is 8 (queried with `landlock_create_ruleset`). The bind/serve claim is verified by the M1 tests. |
| 7 | No-op `-c` overrides for filter drivers are honored by `git status` and prevent the driver from executing. | **True on 2.43.0** (sentinel test), but only together with `--attr-source` (§6). |
| 8 | `unshare -rn` is available on the test host. | **False on this host:** `unshare -rn` fails (`apparmor_restrict_unprivileged_userns=1`). Test 5 is skipped with a notice here; it needs a host or CI runner that allows unprivileged user namespaces. |
