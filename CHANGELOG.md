# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] — unreleased

The session activity indicator. Tested on the same environment as 0.1.1 (Linux x86_64, Ubuntu 24.04, kernel
7.0, systemd 255, Git 2.43.0) with Claude Code 2.1.332; the interactive behaviour of Claude Code it relies on was
checked on the maintainer's machine (REQUIREMENTS.md §21.12, O11).

### Added
- **Which projects have an open Claude Code session, and what it is doing** — opt-in, from Claude Code hooks
  you add to your Claude Code settings ([docs/session-hooks.md](docs/session-hooks.md)). Cards and table rows
  show a dot and a label: **Needs approval** (from the first minute "Needs approval · N min"), **Working** (the
  dot pulses, except with reduced motion), **Waiting for input**, **Session open** (state unknown, after a ccwm
  restart). Several sessions in one project: the most urgent state, with the counts in the tooltip. The table
  has a "Claude" column, the detail panel lists the open sessions and the latest session's state. Three
  toolbar filters with counts: **Waiting for me**, **Working**, **Open**. Changes appear live. Privacy mode
  keeps the indicator (states, counts and times only).
- **`ccwm hooks print`** prints the hooks to add: one per event, each a guarded command
  (`command -v '<ccwm>' >/dev/null 2>&1 && '<ccwm>' hook <Event>; exit 0`) that does nothing when ccwm is
  missing and never fails a Claude Code hook. ccwm never reads or edits Claude Code's settings.
- **`ccwm hook <Event>`**, run by those hooks: reads the event's JSON (at most 16 MiB; the prompt, Claude's reply
  and the tool fields are skipped unread), sends the event name, session id, working folder and prompt id over
  ccwm's Unix socket within 100 ms, never prints on stdout, always exits 0, and ends after 1 s whatever it waits
  for.
- **`ccwm hooks events [--follow]`**: the last 256 hook events the daemon received — time, event, session id,
  what the daemon did with it — for checking the hooks (in memory only).
- **Turn ends Claude Code reports to no hook** — Esc during a reply, "No" or Esc in a permission dialog, Esc
  while an approved tool runs — are taken from the session file: the session shows "Waiting for input" about
  2 seconds later. Only structural fields of those records are read, never their text.
- **Settings → "Show non-interactive sessions"** (`[indicator] show_noninteractive`, off by default, applies at
  once): `claude -p` runs and SDK hosts that start Claude Code non-interactively are tracked but hidden unless
  it is on.
- **`ccwm status`** has a "hooks" line (open sessions by state, hidden ones, those in no project, events
  received, stale and refused events, facts from session files); **`ccwm doctor`** an informational line;
  `/api/v1/service/status` a `hooks` object; `/api/v1/stats` the filter counts; `GET /api/v1/projects` a `live`
  field and a `live=waiting|working|open` filter; session items a `live` field.

### Changed
- The daemon decides which Claude Code process an event comes from itself (the nearest Claude Code process
  above the hook, at most 8 levels, of your user; `CLAUDE_PID` must name the same one) and closes a session when
  that process exits (checked every 5 s). Open sessions survive a ccwm restart as "Session open" while their
  process runs (database migration 6); a reboot or "Clear session index" forgets them.
- Unix-socket requests may be up to 32 KiB (was 4 KiB), and the CLI reads responses up to 256 KiB (was 64 KiB).
- The socket's trace log names the request type only (it printed the whole request).
- `ccwm` looks up the passwd entry only when `$HOME` does not qualify.

### Not run
- A release build of 0.2.0, CI, the release workflow, and the fresh-account install (the maintainer's steps,
  docs/release-checklist.md). The real `claude` was run only in the maintainer-approved O11 checks; the tests
  use a fake one.

## [0.1.1] — 2026-11-26

A maintenance release: no new features. Tested on the same environment as 0.1.0 (Linux x86_64, Ubuntu
24.04, kernel 7.0, systemd 255, Git 2.43.0).

### Changed
- **Session titles are shown as quotations.** On cards and in table rows the latest session's title is
  now in quotation marks and italics, and its tooltip (and the text for screen readers) says "Session
  title". The title is text Claude Code recorded: one worded like a status ("Resuming the session…") could
  be read as the state of the project.
- **The systemd unit has a memory limit**: `MemoryMax=2G` with `MemorySwapMax=0`, for the daemon and its
  `git` and `claude` children together. ccwm normally needs 20–30 MiB; at the limit the kernel kills the
  largest process. A `git` or `claude` child killed that way fails like any failed command and the daemon
  goes on (`OOMPolicy=continue`); a killed daemon is started again, and after 10 starts in 10 minutes the
  service stays `failed` (`StartLimitIntervalSec=10min`, `StartLimitBurst=10`) instead of restarting for
  ever. `MemorySwapMax=0` is part of it because, with swap, `MemoryMax=` alone only moves the excess to
  swap. Run `scripts/install.sh` (or `ccwm service install`) to get the new unit; change the limit with a
  drop-in (`systemctl --user edit ccwm`, see docs/service.md).
- **Ignore rules are limited across projects too**: 20,000 rules for all projects together, next to the
  limits per file and per project. Beyond it ignore files are skipped and counted, as before
  (`ccwm status`). The limit goes to the **most recently active projects**: when the rules do not fit
  all, the least recently active projects are the ones without, whatever order they were found in, and
  a project that becomes active again gets its rules back soon after (when the next project is walked,
  added or removed, or a session file changes; at the latest at the next scan). A project that is
  without its rules for that reason is still **scanned with all of them**, compiled for that scan alone
  and dropped, one project at a time: its "last change" is a real one, also for a project without
  watches. Changes ccwm sees live in it are judged with the rules it keeps. `ccwm status` names such
  projects ("ignore rules limited").
- **Compiled ignore rules are kept and reused.** The rules of a `.gitignore` are compiled again only
  when the file changed (its device, inode, size, modification time or change time), or when it had
  changed less than 2 s before it was read. Before, every scan of a project without watches compiled all
  its rules again.
- **A `.gitignore` in a new directory applies at once.** When a directory with ignore files appears in a
  watched project (a checkout, a move), the project is walked again and the new rules apply to what
  happens in it; before, only after the project's next full walk.
- **The Settings page refuses more.** A discovery root that is `/` or a folder containing your home
  folder, and your home folder itself as the session directory, can no longer be saved from the browser
  (symlinks are resolved first). Edit `config.toml` if you really want such a root.

### Fixed
- A WebSocket client that stopped reading could keep its session, and the check of its token, blocked
  for as long as it liked; and one event could still be sent after a sign-out was signalled. A
  revocation now comes first, and a client that does not take a message within 5 s is disconnected.
- The truncation of the write-ahead log after session data is deleted could fail silently when a reader
  was using the log. The result is now checked, logged, and the truncation repeated after the next
  write until it succeeds.
- With more than 100,000 session files, the sessions beyond that number were removed from the index as
  if their files were gone. A listing that was cut off no longer removes anything from the folders it
  cut off; folders it listed completely still lose the sessions whose files are gone. The state is
  logged once (not at every session change) and shown in `ccwm status`.
- Directories created in or moved into a watched project could take the daemon's memory past 2 GiB:
  each was walked on a thread of its own with room to compile a project's worth of ignore rules (24
  directories of 4,900 expensive rules: 2.1–2.5 GiB). Such walks now compile no rules (peak 99–108 MiB
  in the same case).
- Two full walks of one project at once could let all projects together hold more ignore rules than the
  limit, and a project enrolled during a walk could be forgotten while its rules were still in use. One
  walk per project at a time now, and projects are forgotten only when a list read after the walk says
  they left.
- While another program held a read transaction on ccwm's database, every write waited 5 s for the WAL
  truncation it still owed. Retries no longer wait, the warning is logged once, and a truncation owed when
  ccwm stopped is done at the next start.
- A shutdown could start one more reconciliation, which re-indexed the sessions right after "Clear
  session index" (and made an acceptance test fail now and then).
- The settings error for a path no longer claims that `.` is refused (it is accepted: `/a/./b` is `/a/b`).

### Tests
- Purge with ccwm's directories inside the home folder next to other applications' data; purge refused
  while a daemon holds the lock; canaries for privacy fields that no test could fail on; every directive
  of the unit pinned; `same_file_system` in both walks; the symlink-swap race now requires that a swap
  raced; redaction before truncation; the release archive (`package-release.sh`, `sha256sum -c`, install
  from the extracted archive).
- In CI, the pseudo-terminal paste test, the JavaScript tests and the `systemd-analyze` check fail instead
  of skipping when their tool is missing, and the Landlock assertions that depend on the kernel's ABI are
  required (`CCWM_REQUIRE_LANDLOCK_ABI`).
- Every test that writes a script and runs it at once lets a child shell write it (no more "text file
  busy").

### Known limitations
- Ignore rules that need a regular expression cost 17–20 KiB each. With 20,000 of them, the most the
  limits allow, and two more projects that lack their rules, ccwm holds 434 MiB (a glibc build) or
  381–392 MiB with a 480–492 MiB peak (the release binary), flat over repeated scans; each scan that
  walks the two projects compiles their rules again (1.3–1.8 s each). An ignore file that changes is
  compiled again next to the rules it replaces (docs/benchmarks.md). The unit's memory limit (2G) is far
  above that and will be lowered.
- The limit across projects goes to the most recently active projects, so a tree of projects with huge
  ignore files and recent file times can take it from older projects until those are active again. In a
  project without its rules, a change to a file they would ignore counts as activity when ccwm sees it
  live.
- The limits count rule lines, whatever a rule costs; the rules of a repository above several projects are
  counted (and compiled) once per project.
- The rule cache trusts a file's device, inode, size, modification time and change time. On a file system
  without a change time of its own (FAT), a `.gitignore` rewritten to the same size with its modification
  time restored keeps its old rules until it changes again or ccwm restarts.
- The memory limit needs the cgroup memory controller for your user manager (present on Ubuntu 24.04).
- Not run: CI on this version, the release workflow, a fresh-account install from the archive.
- Everything listed under 0.1.0 still applies, except "the ignore-file limits apply per project, not
  across projects".

## [0.1.0] — 2026-11-25

The first release. CC Workspace Manager (`ccwm`) is an independent, unofficial project, not affiliated
with or endorsed by Anthropic. Tested on Linux x86_64 only: Ubuntu 24.04, kernel 7.0, systemd 255,
Git 2.43.0.

### Discovery and tracking
- Finds projects from Claude Code sessions (the first recorded working directory, resolved to its Git
  work tree or `CLAUDE.md`) and from `CLAUDE.md` markers. A full marker walk runs on the first launch,
  then only the development roots ("Scan entire home" restores full walks). Nested projects follow the
  Git-root rule. Session-only "containers" never swallow the projects below them.
- Live activity from one inotify instance with non-recursive watches and a watch budget (25 % of
  `max_user_watches`, breadth first). Unwatched folders are checked at each reconciliation. Gitignored
  files and `.git/` never count as activity. Calendar-day buckets. Ignore files are read within limits
  (256 KiB per file; 1 MiB and 5,000 rules per project); a file over a limit is skipped and reported.
- Projects persist while their folder exists. Missing projects are kept for 30 days, can be forgotten, and
  are revived with their id when the folder returns. Moves keep the id.
- Hardened, allowlisted Git: branch, upstream, ahead/behind, staged/modified/untracked, latest commit.
  Repository-defined helpers are neutralised, every transport is blocked (including the lazy fetch of
  partial clones), and filter drivers are disabled. A filter driver whose name cannot be passed back to
  Git exactly (not valid UTF-8, `=`, control characters) turns worktree status off for that repository.
- Incremental, allowlist-only session parsing: titles, times, cwds, continuations. The last prompt is
  read on demand, redacted and never stored unless you opt in. Resume commands
  (`cd -- '<cwd>' && claude --resume <id>`) are offered for copying only, and none is generated for
  terminal-unsafe paths.

### Dashboard
- Card and table views, search, sort, filters (activity, missing only, uncommitted changes, has
  sessions), a detail panel, live WebSocket updates, dark/light/system themes, a privacy mode enforced by
  the server, and a Settings page.

### Security
- Loopback only. Host/Origin checks, strict CSP (no inline code, no workers). Single-use 30 s sign-in
  links over a peer-verified Unix socket, then hashed, rotating browser session tokens. Request heads and
  bodies have 10 s each to arrive.
- **TCP peer-UID check** on every connection, before a byte is read: one exact `sock_diag` netlink
  lookup, with a `/proc/net/tcp` fallback, chosen by a self-test at startup.
- **Landlock** self-sandbox: read-only on your projects, writes only in ccwm's directories, TCP connect
  denied, bind limited to the port, abstract sockets and signals scoped.
- **Seccomp socket filter** after the listeners are bound: no new socket and no socket pair of any
  kind, and no `io_uring`, on every thread and in children. The peer check's netlink socket is opened
  before the filter and reused. This closes UDP and path-based Unix sockets (stream and datagram), which
  Landlock leaves open.
- The daemon probes its own confinement (thread reads, a write outside its directories, an outbound
  connect, socket creation) and reports only what is verified (`ccwm status`, `ccwm doctor`,
  `/api/v1/service/status`). A probe that is not denied withdraws the claim; a probe that fails for an
  unexpected reason marks the protection `unverified`, neither claimed nor withdrawn.
- `cargo-deny` bans HTTP/TLS/DNS client crates. gitleaks runs in CI.

### CLI and service
- `ccwm serve | open | status | scan | start | stop | restart | doctor | service install | service
  uninstall [--purge] | auth revoke-all`.
- A systemd user unit with dedicated exit codes (10: port in use, 11: already running) that systemd does
  not restart on. `scripts/install.sh` and `scripts/uninstall.sh` are idempotent, need no root, and keep
  your data unless you pass `--purge`.
- A session-index rebuild on upgrade when the parsing rules change (parser version).
- Commands end quietly when their output pipe is closed (`ccwm status | head`).

### Release engineering
- GitHub Actions CI (fmt, clippy, tests with the runner's sandbox capabilities reported, cargo-deny,
  gitleaks over the full history; actions pinned to commit SHAs). A tag-triggered release workflow
  builds a static `x86_64-unknown-linux-musl` binary with bundled SQLite and embedded assets, plus
  `THIRD_PARTY_LICENSES` (cargo-about) and `SHA256SUMS`, as a draft release.

### Fixed before the release (pre-release security review, docs/reviews/v0.1.0-security-review.md)
These never shipped; they are listed because the review is part of the repository.
- **High:** a Git filter driver with a name that is not valid UTF-8 escaped the neutralisation and ran
  during `git status`. Such names now disable worktree status (fail closed).
- **Medium:** a datagram socket pair got around the seccomp filter (`socketpair()` is now denied, and
  `socket()` has no exception left); many large `.gitignore` files could exhaust memory (now limited per
  file and per project); the "impostor on the port" residual risk was understated (rewritten in
  SECURITY.md; `worker-src 'none'` added; `Clear-Site-Data` evaluated and not used).
- **Low:** credentials left in scp-like remote URLs and with a `/` in the password; a symlinked XDG
  directory inside a project made ccwm watch its own database; privacy mode showed read-rule paths in the
  sandbox notes; no timeout for request bodies; `.gitignore` rules taken from a `.git` above the discovery
  root. POSIX ACLs in the directory trust check are documented as a limitation, not checked.
- Also: the table view uses the full window width, the "too large to walk" note says "partly watched",
  and security test 5 lost its network-namespace variant (it cannot start the daemon without weakening
  the ownership checks; `strace` tracing and the seccomp filter cover it).

### Known limitations
- Linux x86_64 only, and only the environments above were tested. Not yet run: the release workflow, a
  fresh-account install from the archive, and the two-user check. The tests use a stand-in for
  `claude`; under the seccomp filter the real binary was checked by hand with Claude Code 2.1.332 only
  (`ccwm doctor` reports its check ok). If another version needs a socket for `--version`, `ccwm doctor`
  reports the check as failed.
- The ignore-file limits apply per project, not across projects. The directory trust check does not read
  POSIX ACLs. State that another local user's process leaves in the browser for the dashboard's origin
  while ccwm is not running persists until you clear that site data (see SECURITY.md).
- Roots, exclusions, depth, file-system, budget, port and session-directory changes need a restart.
- Subagent session files are not read. Gitignore evaluation approximates Git (no global
  `core.excludesFile`). Redaction is best effort.
- See [SECURITY.md](SECURITY.md) for the residual risks.
