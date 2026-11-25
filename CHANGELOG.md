# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

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
  fresh-account install from the archive, and the two-user check. The real `claude` binary
  has not been run under the seccomp filter (the tests use a stand-in): if its `--version` needs a
  socket, `ccwm doctor` reports the check as failed.
- The ignore-file limits apply per project, not across projects. The directory trust check does not read
  POSIX ACLs. State that another local user's process leaves in the browser for the dashboard's origin
  while ccwm is not running persists until you clear that site data (see SECURITY.md).
- Roots, exclusions, depth, file-system, budget, port and session-directory changes need a restart.
- Subagent session files are not read. Gitignore evaluation approximates Git (no global
  `core.excludesFile`). Redaction is best effort.
- See [SECURITY.md](SECURITY.md) for the residual risks.
