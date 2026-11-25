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
  files and `.git/` never count as activity. Calendar-day buckets.
- Projects persist while their folder exists. Missing projects are kept for 30 days, can be forgotten, and
  are revived with their id when the folder returns. Moves keep the id.
- Hardened, allowlisted Git: branch, upstream, ahead/behind, staged/modified/untracked, latest commit.
  Repository-defined helpers are neutralised, every transport is blocked (including the lazy fetch of
  partial clones), and filter drivers are disabled.
- Incremental, allowlist-only session parsing: titles, times, cwds, continuations. The last prompt is
  read on demand, redacted and never stored unless you opt in. Resume commands
  (`cd -- '<cwd>' && claude --resume <id>`) are offered for copying only, and none is generated for
  terminal-unsafe paths.

### Dashboard
- Card and table views, search, sort, filters (activity, missing only, uncommitted changes, has
  sessions), a detail panel, live WebSocket updates, dark/light/system themes, a privacy mode enforced by
  the server, and a Settings page.

### Security
- Loopback only. Host/Origin checks, strict CSP. Single-use 30 s sign-in links over a peer-verified Unix
  socket, then hashed, rotating browser session tokens.
- **TCP peer-UID check** on every connection, before a byte is read: one exact `sock_diag` netlink
  lookup, with a `/proc/net/tcp` fallback, chosen by a self-test at startup.
- **Landlock** self-sandbox: read-only on your projects, writes only in ccwm's directories, TCP connect
  denied, bind limited to the port, abstract sockets and signals scoped.
- **Seccomp socket filter** after the listeners are bound: no new sockets (except the peer check's
  netlink socket) and no `io_uring`, on every thread and in children. This closes UDP and path-based Unix
  sockets, which Landlock leaves open.
- The daemon probes its own confinement (thread reads, a write outside its directories, an outbound
  connect, socket creation) and reports only what is verified (`ccwm status`, `ccwm doctor`,
  `/api/v1/service/status`).
- `cargo-deny` bans HTTP/TLS/DNS client crates. gitleaks runs in CI.

### CLI and service
- `ccwm serve | open | status | scan | start | stop | restart | doctor | service install | service
  uninstall [--purge] | auth revoke-all`.
- A systemd user unit with dedicated exit codes (10: port in use, 11: already running) that systemd does
  not restart on. `scripts/install.sh` and `scripts/uninstall.sh` are idempotent, need no root, and keep
  your data unless you pass `--purge`.
- A session-index rebuild on upgrade when the parsing rules change (parser version).

### Release engineering
- GitHub Actions CI (fmt, clippy, tests with the runner's sandbox capabilities reported, cargo-deny,
  gitleaks over the full history; actions pinned to commit SHAs). A tag-triggered release workflow
  builds a static `x86_64-unknown-linux-musl` binary with bundled SQLite and embedded assets, plus
  `THIRD_PARTY_LICENSES` (cargo-about) and `SHA256SUMS`, as a draft release.

### Known limitations
- Linux x86_64 only, and only the environments above were tested. Not yet run: CI on GitHub, the
  network-namespace variant of security test 5, the release workflow, a fresh-account install from the
  archive, and the two-user check.
- Roots, exclusions, depth, file-system, budget, port and session-directory changes need a restart.
- Subagent session files are not read. Gitignore evaluation approximates Git (no global
  `core.excludesFile`). Redaction is best effort.
- See [SECURITY.md](SECURITY.md) for the residual risks.
