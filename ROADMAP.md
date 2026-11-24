# ROADMAP

Source: `REQUIREMENTS.md` §16–§20. A box is ticked only when the item was built **and run**. Each milestone
ends with `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` green;
ROADMAP.md + CLAUDE.md updated; one local commit; a report; then **wait for go-ahead** (M1 was pre-approved to
start immediately; later milestones are not).

Current position: **M1.1 (security hardening) complete — waiting for the maintainer's go-ahead for M2.**

---

## M1 — Foundation
Accept (synthetic environment): `ccwm serve` + `ccwm open` show marker-discovered projects; unauthenticated,
wrong-Host and wrong-Origin requests are rejected; the CLI refuses an impostor TCP listener; a restart shows
cached projects immediately; security acceptance tests **1, 6, 7, 9, 11** pass.

- [x] Spec revision applied; ARCHITECTURE.md / ROADMAP.md / CLAUDE.md rewritten
- [x] Full `.gitignore` before any code; local `git init`
- [x] Cargo scaffold (`cc-workspace-manager` / `ccwm`, `rust-version=1.94`, `Cargo.lock`), `LICENSE` (MIT, holder TBD), `config.example.toml`
- [x] `paths` (XDG + fallback, 0700, owner/mode verification, 108-byte socket limit, passwd home, refuse root, umask 0077) · `config` · `clock`
- [x] `sandbox`: Landlock policy applied before any thread, `SandboxReport` in log + `service.status`
- [x] `instance`: flock + `instance.json`
- [x] SQLite: pragmas, migration 1, writer thread, read pool
- [x] Discovery: exclusions, hard boundaries, mountinfo FUSE detection, DFS walk, marker rules, nested rule, non-UTF-8 skip, progressive batches, status counters
- [x] Auth: bootstrap (in-memory, single-use, 60 s), exchange, sessions (hashed, sliding 30 d), rotate (+60 s grace), logout, revoke-all
- [x] Service layer + Unix-socket server (SO_PEERCRED) + client (verifies peer) — ops `ping`, `auth.bootstrap`, `auth.revoke_all`, `service.status`
- [x] HTTP: security headers, Host/Origin/auth middleware, error envelope, body limit, routes `/health /auth/* /projects /stats /discovery/status /service/status`
- [x] CLI: `serve [--port --config]`, `open [--print]`, `--version`, `--help` (unofficial notice)
- [x] UI: embedded `index.html`/`app.css`/`app.js`; fragment → `replaceState` → exchange; polling; card list; loading/empty/error/unauthenticated/partial-progress states; unofficial footer; no `innerHTML`
- [x] Synthetic environment generator (`ccwm-synth`, shared with tests)
- [x] `scripts/inspect-session-schema.py` (tested on synthetic data only; handed to the maintainer, never run by the agent on real data)
- [x] `deny.toml` network-crate bans written (first run in M1.1, see below)
- [x] Tests: unit + HTTP + process-level + acceptance **1, 6, 7, 9, 11**
- [x] Manual acceptance run in a synthetic env (see CLAUDE.md "How to run"); the UI was exercised with a Node DOM stub, **not in a real browser** (the Chrome extension was not connected)
- [x] fmt / clippy / test green; docs + roadmap updated; local commit

## M1.1 — Security hardening (review of M1, `docs/reviews/m1-security-review.md`)
No new features. Spec changes approved by the maintainer and applied to REQUIREMENTS.md §11 and SECURITY.md.

- [x] L6 (first): schema script masks every key of a data-keyed object (> 12 distinct keys over the corpus, 64 at the record top level), independent of record order; tag labels only from the script's own table; timestamp shapes keep only digits→9 and `-:.TZ+`; canary tests
- [x] H1/H2: TCP peer-UID check on every accepted connection (`/proc/net/tcp{,6}`, fail closed, per connection); bootstrap TTL 30 s; `hidepid=invisible` documented as optional; impostor fake UI documented as residual risk
- [x] M1: Landlock scopes `AbstractUnixSocket | Signal` (ABI 6, best effort, reported); `sandbox::child_command` drops `DBUS_*`/`XDG_RUNTIME_DIR`/agent/display/systemd IPC variables; network reported as `tcp_only`; UDP and path-based Unix connect listed in `unconfined`
- [x] M2: no read grant for the `--config` directory; read rules that are `/` or an ancestor of home are flagged in the report
- [x] M3: descriptor-based walk (`openat(O_DIRECTORY|O_NOFOLLOW)` + `(dev, ino)` check; entries read from the fd; markers via `openat2(RESOLVE_BENEATH)` with a strict fallback); `skipped.changed` counter
- [x] M4: `apply` requires `/proc/self/task` = 1 entry, else `not_enforced`; worker and blocking-pool thread probes recorded in the report
- [x] L1 overdue token accepted only on `/auth/rotate` · L2 UI follows `storage` events, a 401 clears storage only if the stored token was the rejected one · L3 hourly purge + cap of 10 live sessions (LRU revoked), `ccwm open` revokes nothing · L4 ownership/mode checks of the config file and every ancestor of the XDG dirs (private-group rule) · L5 64-connection cap before `accept` + 10 s header-read timeout (hyper http1), Unix socket usable under load · L7 `CLAUDE_CONFIG_DIR` always a hard boundary · L8 stored `sort_key` (migration 2) for ORDER BY and cursors
- [x] Tests: 11 (harness-less, real `daemon_policy()`, exact errnos, threads and grandchildren, scopes, Unix-connect residual, `CCWM_REQUIRE_LANDLOCK=1`; real daemon's report and probes), 7 (`--config`, XDG vars, `CLAUDE_CONFIG_DIR`, symlink-swap race with mutation check), 9 (names from `paths.rs`, `instance.json.tmp`, in-repo synthetic env, fail in CI without git), 6 (concurrent rotation, logout/revoke-all in grace, simulated TCP peer-UID mismatch, overdue rotation), 1 (XDG dirs inside the walked home), log check at `CCWM_LOG=trace`, WAL/SHM modes
- [x] `cargo deny check` run and clean (cargo-deny 0.21.0 in `target/tools/`): unused license allowances removed, known `syn` 2/3 duplicate skipped with a reason
- [x] fmt / clippy / test / cargo deny green; docs updated; local commit

## M2 — Activity tracking
Accept: editing a file moves its project to the top live; creating `CLAUDE.md` in a watched area registers a
project without reload; Git status is correct; security acceptance tests **3, 4, 5** pass (5 needs a host with
unprivileged user namespaces — skipped with notice on the development host).

- [ ] One notify watcher / one inotify instance (polled fallback if creation fails); non-recursive watches; dynamic add/remove; budget `min(8192, 25 %)`; priority roots → recent
- [ ] Degraded/polled mode (budget, kernel limit, `IN_Q_OVERFLOW`) + banner + doctor text
- [ ] Reconciliation (10 min, non-overlapping, bounded, back-off, coalesced refresh) + `POST /refresh` + socket op
- [ ] Meaningful-activity rules (in-process gitignore matcher), inferred vs observed, bounded `file_events`; buckets (0/1/6/7/29/30, DST), "this week", sorting incl. unknown-last
- [ ] `git/`: allowlist; hardened env/flags; `--attr-source` + all-scope filter nulling; min-version gate (2.41.0) with disabled state + `git.allow_unhardened_status`; 5 s timeout + process-group kill; concurrency 4; cache/invalidation; URL sanitization; no-git/detached/worktree/nested/`safe.directory`
- [ ] Sentinel tests for every §16-test-4 vector; Git subprocess variant of Landlock test 11
- [ ] Move/rename (paired events + fallback matcher), missing state, retention purge, ignore/un-ignore
- [ ] WebSocket: auth message/5 s timeout/4401, nothing before auth, close on token expiry/rotation-out/revocation, events, reconnect with backoff + fresh snapshot
- [ ] UI: card + table, search/sort/filters, ignore, missing filter, banners
- [ ] `/projects/{id}`, ignore endpoints; fmt/clippy/test; docs; commit

## M3 — Development continuity
Accept: a project with sessions but no `CLAUDE.md` appears; detail panel shows last prompt (read on demand), Git
status, files, correct resume command (first recorded cwd, escaped); no prompt text persisted by default;
privacy mode removes the listed fields; security acceptance tests **2, 8, 10** pass. Built from the
maintainer's pasted §19 script output + synthetic fixtures only.

- [ ] Synthetic versioned fixture corpus; session locator (`CLAUDE_CONFIG_DIR`); top-level files only; non-recursive watches
- [ ] Incremental parser (checkpoints, partial line, truncation/rotation, 8 MiB cap, counters); min/max timestamps; first/last cwd; `ai-title`
- [ ] Prompt classifier (`typed`/`queued`; `sdk`/`system` excluded; classifier otherwise); on-demand bounded (4 MiB) read, 2,000-char cap, redaction; opt-in "Store prompt text"
- [ ] Session-based discovery + cwd → root, unassigned-home counter
- [ ] Resume command (UUID validation, POSIX quoting + adversarial tests), `claude` CLI verification (5 s, cached by path+mtime)
- [ ] Privacy mode (server-side omission, search ignores hidden fields); Settings page + `GET/PUT /settings`; clear session index
- [ ] fmt/clippy/test; docs; commit

## M4 — Release readiness
Accept: a fresh user account installs from the release archive; service starts at login (and at boot with
lingering); projects appear; all tests including the full security acceptance suite pass; CI (gitleaks +
cargo-deny bans) green; benchmarks documented.

- [ ] CLI `start/stop/restart/status/scan/doctor/service/auth`; dedicated exit codes (port in use, lock held) in `RestartPreventExitStatus=`
- [ ] systemd unit (+ optional `ProtectSystem`/`ProtectHome` only after testing the real daemon); `scripts/install.sh`/`uninstall.sh`
- [ ] Seccomp filter denying `socket()` after the TCP and Unix listeners are bound (deferred from M1.1; needs a dependency justified in ARCHITECTURE §4 first) — closes UDP and path-based Unix-socket connect
- [ ] Security acceptance test 5 fallback where `unshare -rn` is unavailable: strace `connect` of the daemon and children, assert no non-loopback connect
- [ ] Security + performance pass with measured numbers; docs (README, SECURITY, CONTRIBUTING, CHANGELOG, LICENSE, config reference, discovery semantics, inotify troubleshooting, retention, service mgmt)
- [ ] CI (fmt, clippy, test, cargo-deny, gitleaks, hygiene; SHA-pinned; least privilege) + release workflow (musl)
- [ ] History/secret audit before first publication; naming-conflict check (needs maintainer OK)
- [ ] Validate release binary on build host; report tested environments only

---

## Backlog — v0.2 and later (REQUIREMENTS.md §18; **do not implement in v0.1**)

- [ ] Full session history, expandable conversations, resume for older sessions
- [ ] CLAUDE.md rendering (pulldown-cmark + ammonia, server-side sanitization)
- [ ] Project notes, pending tasks, next steps, tags, custom descriptions
- [ ] Git commit history view, file activity timeline
- [ ] Pinning, pins-first mode, advanced filters, sort by discovery date
- [ ] Full-text session search (FTS5)
- [ ] Manual project split/merge overrides
- [ ] Project-name anonymization in privacy mode
- [ ] Data export
- [ ] Local usage statistics (local only, no telemetry)
- [ ] ARM64 (aarch64-musl) release binaries on native runners
- [ ] Additional AI coding assistants (introduce the provider abstraction then)
- [ ] macOS and Windows support
