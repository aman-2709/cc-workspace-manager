# ROADMAP

Source: `REQUIREMENTS.md` §16–§20. A box is ticked only when the item was built **and run**. Each milestone
ends with `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` green;
ROADMAP.md + CLAUDE.md updated; one local commit; a report; then **wait for go-ahead** (M1 was pre-approved to
start immediately; later milestones are not).

Current position: **v0.1.0 is released (tag `v0.1.0` at `975bf10`); next is v0.1.1 (below; not started).** The session activity indicator is the v0.2 headline (ARCHITECTURE §14).

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
- [x] Spec additions L1, L3, L4, L5 (§11) approved by the maintainer (2026-11-24)

## Pre-M2 (maintainer requests, 2026-11-24)
- [x] Test 5: strace fallback (`strace -f -e trace=connect,execve`, every `connect()` of the daemon and its Git children must be loopback or a Unix socket; Git execs must appear in the trace); network-namespace variant (`unshare --user --map-current-user --net`, probed with the exact wrapper) used where it works. **Ran here: the strace variant** (unshare blocked by AppArmor)
- [x] UI: home-relative paths (`display_path`, `~/…`), single line, left-ellipsized, full path in the tooltip; uniform card heights. Nested `CLAUDE.md` with/without its own Git root covered by `tests/discovery.rs::nested_projects_follow_the_git_root_rule` (`e/f`, `g/h` vs `c/d`, `a/b`); synthetic `dev/beta/packages/inner` is the **with its own Git root** case
- [x] Licensing: LICENSE holder, `license = "MIT"`, README with the trademark line, CONTRIBUTING (MIT inbound = outbound, DCO, no CLA); §17 `THIRD_PARTY_LICENSES` via `cargo-about` (M4)
- [x] SECURITY.md: same-user forwarders bypass the peer-UID check; test: a valid token over a peer-UID-rejected connection is still rejected (every endpoint, incl. the WebSocket upgrade)
- [x] Build commit in `/health`, `service.status` and `ccwm status`; `ccwm status` warns on a mismatch (pulled `ccwm status` and `ccwm scan` forward from M4; systemd state stays M4)

## M2 — Activity tracking
Accept: editing a file moves its project to the top live; creating `CLAUDE.md` in a watched area registers a
project without reload; Git status is correct; security acceptance tests **3, 4, 5** pass (5 needs a host with
unprivileged user namespaces — skipped with notice on the development host).

- [x] One notify watcher / one inotify instance (polled fallback if creation fails); non-recursive watches (`IN_DONT_FOLLOW`, `IN_ONLYDIR`); dynamic add/remove; budget `min(8192, 25 %)`; priority roots → parents → rest of each tree by recency
- [x] Degraded/polled mode (budget, kernel limit, no instance, truncated tree, `IN_Q_OVERFLOW` or our queue full → full rescan) + UI banner + advice text in `service.status` (for `ccwm doctor`, M4)
- [x] Reconciliation (10 min, non-overlapping, back-off, coalesced refresh, `scans_finished` counter) + `POST /refresh` + socket op `scan.refresh` + `ccwm scan`
- [x] Meaningful-activity rules (in-process gitignore matcher), inferred vs observed, bounded `file_events`; buckets (0/1/6/7/29/30, midnight, DST), "this week", sorting incl. unknown-last in both orders
- [x] `git/`: allowlist; hardened env/flags; `--attr-source` + all-scope filter nulling; unsafe driver names fail closed; `--no-show-signature`; min-version gate (2.41.0) with disabled state + `git.allow_unhardened_status`; 5 s timeout + process-group kill; concurrency 4; cache/invalidation by `.git` events, file activity and reconciliation; URL sanitization; no-git/detached/unborn/worktree/nested/home-repo/`safe.directory`
- [x] Sentinel tests for every §16-test-4 vector (with control runs); acceptance test 3; Git subprocess variant of Landlock test 11
- [x] Move/rename (paired events keep the id; fallback matcher: same HEAD + remote, or same marker hash, unique match only), missing state, retention purge, ignore/un-ignore (ignore follows a moved project)
- [x] WebSocket: Origin, auth message/5 s timeout/4401, nothing before auth, close on revocation/expiry/rotation-out/overdue, events (project, project_removed, stats, discovery, monitoring, resync), reconnect with back-off + fresh snapshot
- [x] UI: card + table (sortable columns, 100-row pages), search/sort/filters, stats, ignore/un-ignore, missing and ignored filters, degraded and reconnecting banners, theme (system/light/dark), view and theme persisted
- [x] `/projects/{id}`, ignore endpoints; acceptance (synthetic env, real browser): an edit moves its project to the top live, a new `CLAUDE.md` registers a project without reload, Git status correct; tests 3, 4, 5 pass
- [x] fmt / clippy / test / cargo deny green; docs; local commit

## M2.1 — Git transport hardening and real-home defects (review `docs/reviews/m2-security-review.md` + maintainer's real-home test)
No new features. Spec changes approved by the maintainer and applied to REQUIREMENTS.md §0/§5.1/§5.3/§6/§9/§16 and SECURITY.md.

- [x] H1: `GIT_ALLOW_PROTOCOL=` (empty) and `GIT_NO_LAZY_FETCH=1` in the Git environment; `-c protocol.{ext,ssh,file,git,http,https}.allow=never`; `GIT_NO_LAZY_FETCH` verified on the host's Ubuntu 2.43.0 build (CVE-2024-32465 backport), upstream 2.45.0; partial clones degrade to `partial_clone` ("Git status unavailable (partial clone)") instead of being refused
- [x] Test 4: promisor vectors (`ext::`, `file://` + `uploadpack`, `ssh://` + `core.sshCommand`), `HEAD` object removed, control = plain `git status`/`log`; each transport block alone tested; the `ls-remote` `sshCommand` control removed
- [x] Test 5: `execve` allowlist (daemon + `git --version|rev-parse|status|log|config`), zero fetch children for three promisor projects (L3), `strace -s 256`
- [x] L1, L4: SECURITY.md notes. L2: notify drops `IN_ONLYDIR` on `ENOTDIR` ⇒ directory check after every watch + real-inotify test; SECURITY.md note
- [x] Watches breadth first (roots → parents → `.git` + top level → deeper by recency); *partly watched* projects poll only their unwatched subtrees (`Cmd::Retry`); ancestor `.gitignore`/`info/exclude` of the work tree applied; new directories walked with the project's rules; `ccwm status` shows watched / partly watched / polled; test: one huge project + 20 small ones
- [x] Default budget 25 % of `max_user_watches` (no 8192 ceiling)
- [x] Activity: `activity.days_ago` from the classifier; the UI's relative time uses it (6/7-day boundary tested at a non-midnight time, Rust and JS)
- [x] UI: paths shortened at a `/` boundary; non-Git cards one Git line; "1 folder" plural + unreadable paths (discovery status `unreadable[]`, `ccwm status`, tooltip); degraded banner one line + `<details>`
- [x] `ccwm open` / `status` / `scan` wait up to ~5 s for a starting daemon (only "not running" errors are retried)
- [x] fmt / clippy / test (`CCWM_REQUIRE_LANDLOCK=1 CCWM_REQUIRE_INOTIFY=1`) / cargo deny green; synthetic daemon + real browser check; docs; local commit

## M3 — Development continuity
Accept: a project with sessions but no `CLAUDE.md` appears; detail panel shows last prompt (read on demand), Git
status, files, correct resume command (first recorded cwd, escaped); no prompt text persisted by default;
privacy mode removes the listed fields; security acceptance tests **2, 8, 10** pass. Built from the
maintainer's pasted §19 script output + synthetic fixtures only.

Pre-M3 maintainer decisions (2026-11-24): O5 and the `notify` license exceptions approved (now per crate in
`deny.toml`); schema output pasted (ARCHITECTURE.md §11); parser, title, prompt, resume and discovery-redesign
decisions recorded in REQUIREMENTS.md §4, §7, §8; `_build` excluded; DEGRADED only for real failures; privacy also
hides unreadable-folder paths; the CLI waits only while the instance lock is held.

- [x] Synthetic versioned fixture corpus (`tests/fixtures/sessions/{2.1.331,2.1.220}`, embedded by `synth`); session locator (`CLAUDE_CONFIG_DIR` / `sessions.dir`, fd-based, top-level files only, others counted); non-recursive, debounced session-directory watches (first in the budget)
- [x] Allowlist parser (lenient fields; skipped payloads never materialized); incremental checkpoints (partial line, truncation, rotation, same-size rewrite, 8 MiB cap, counters); min/max timestamps; first/last cwd; latest `ai-title` (redacted); `continued-in` / `derived-from`
- [x] Prompt classifier (`typed`/`queued`/`suggestion_accepted`; `sdk`/`system` excluded; older records via the classifier; all 31 schema signatures tested); on-demand bounded (4 MiB) reads, 2,000-char cap, redaction; opt-in "Store prompt text" (off deletes the cache)
- [x] Session-based discovery: cwd → nearest Git root / marker (never home), nested rule, unassigned reasons counted; full marker scan on first launch, then development roots; "Scan entire home"; projects persist (missing = directory gone)
- [x] Resume command (UUID validation, POSIX quoting + adversarial shell test, first cwd, latest continuation, warnings); `claude` CLI verification (5 s, cached by path+size+mtime, in `ccwm status` and `/service/status`)
- [x] Detail panel (Git, files, latest session, last/first prompt, resume + copy); table "Copy resume"; card/table session info; `sort=session`, `has_sessions`
- [x] Privacy mode (server-side omission in REST and WebSocket, search ignores hidden fields, also status/settings paths); Settings page + `GET/PUT /settings` (atomic 0600 write, live vs restart); clear session index
- [x] `_build` exclusion; DEGRADED/banner only for real failures; CLI waits only while the instance lock is held
- [x] Security acceptance tests 2, 8, 10 (process level; `service uninstall --purge` part in M4); test 5 with the session cycle and the `claude` check
- [x] fmt / clippy / test (`CCWM_REQUIRE_LANDLOCK=1 CCWM_REQUIRE_INOTIFY=1`) / cargo deny green; synthetic daemon + real browser check; docs; local commit

## M3.1 — M3 review fixes and real-home defects (review `docs/reviews/m3-security-review.md` + maintainer's real-home test)
Spec changes approved by the maintainer and recorded in REQUIREMENTS.md (§4.4, §4.5, §7.1–§7.3, §8, §9, §10, §12,
§13, §16, §18, Appendix A).

- [x] M1: no resume command for a cwd with C0/C1 controls, DEL or bidi/format characters; `cwd_unsafe_characters`; escaped display; adversarial test expects no command for `\n`, `\r`, `\x15`, `ESC[201~`, `U+202E`; pty paste regression test (bash, bracketed paste on and off, control runs)
- [x] M2: writer-side prompt-cache guard (flag cleared before `ClearPromptCache`); one settings lock from merge to apply; the page sends only changed fields; tests: stale form, concurrent saves, in-flight read during turn-off
- [x] M3: identifier-suffix keyword rule (incl. quoted JSON/YAML keys), PGP/generic PEM keys, `sk_`/`rk_` live/test, `glpat-`, `npm_`, `AIza`, Basic credentials; every review table row tested; no stray quote; SECURITY.md wording
- [x] M4: session-only candidates never nest others, `container` when projects lie below (both orders tested, unit and ingest); nested rule also against marker directories on disk (`monorepo/services/api` → `monorepo` on the first launch)
- [x] L1 privacy on ignore and settings-save responses + real canaries; L2 `same_file_system`/`max_depth`; L3 caps/stripping, cwd not redacted (documented); L4 lower-case ids, first file wins, duplicates counted; L5 same-project continuations; L6 `secure_delete` + WAL checkpoint; L7 settings allowlist, port 0 and broad session dirs rejected; L8 flags before content
- [x] SECURITY.md: unconfined `claude --version/--help` without Landlock
- [x] Tests: DB scanned before and after clearing the index; test 10 restarts on an empty DB and waits for a full re-ingest
- [x] Test isolation: the hygiene test runs in a throwaway repository under `/tmp`; the full run leaves the working tree unchanged
- [x] Forget (missing projects, database only; `DELETE /projects/{id}`) and "Missing only" (`missing_only`)
- [x] `ccwm status`: unassigned sessions by reason and folder; duplicates
- [x] Early stop for sessions whose first cwd can never name a project (migration 5, partial checkpoints)
- [x] UI: fixed-width actions column, inferred marker with tooltip, "—" for no commit, "sessions in projects", restart wording
- [x] Test confirms `monorepo/services/api` (CLAUDE.md, no own Git) resolves to the monorepo (resolver unit test and ingest test)
- [ ] ~~"Claude running" indicator~~ — deferred to v0.2 (maintainer decision; see the backlog and ARCHITECTURE §14)
- [x] fmt / clippy / test (`CCWM_REQUIRE_LANDLOCK=1 CCWM_REQUIRE_INOTIFY=1`) / cargo deny green; synthetic daemon + real browser check; docs; local commit

## M4 — Release readiness
Accept: a fresh user account installs from the release archive; service starts at login (and at boot with
lingering); projects appear; all tests including the full security acceptance suite pass; CI (gitleaks +
cargo-deny bans) green; benchmarks documented.

Pre-M4 maintainer decisions (2026-11-24): O1 and O7 approved (O1 permanent: no in-process reconfiguration, Landlock
cannot widen its rules); the M3.1 narrowed Basic-auth redaction rule approved.

- [x] CLI `start/stop/restart` (`systemctl --user`, wait for the socket / the lock), `doctor` (Landlock/seccomp from
  the daemon, inotify limits and usage of all the user's processes, Git, `claude` from the daemon's sandboxed check,
  session dir, permissions, port, systemd, lingering; suggests, never applies), `service install|uninstall [--purge]`,
  `auth revoke-all`; `status` gains the systemd line; exit codes 10 (port in use) / 11 (lock held) in
  `RestartPreventExitStatus=`
- [x] systemd user unit (directives verified with the real daemon in transient user units; `ProtectSystem`/
  `ProtectHome`/`PrivateTmp` tested and rejected: their user namespace breaks the ownership checks);
  `scripts/install.sh` / `uninstall.sh` (idempotent, no root, data kept unless `--purge`); lingering documented, never run
- [x] TCP peer lookup via `sock_diag` (exact 4-tuple request), procfs fallback chosen by a startup self-test,
  `peer_lookup` reported; fail-closed reply tests + a real-connection comparison with procfs
- [x] Seccomp filter after the listeners are bound (TSYNC; `socket()` denied except `NETLINK_SOCK_DIAG`, `io_uring` and
  x32 entry points denied; `seccompiler`, justified in ARCHITECTURE §4) — closes UDP and path-based Unix connect
- [x] Daemon-level probes: write outside (`O_TMPFILE`), outbound connect, socket creation on a worker and a blocking
  thread; claims withdrawn on a non-denial; asserted in the process tests and the harness-less sandbox test
- [x] Parser version: `PARSER_VERSION` vs `meta.session_parser_version`, the session index cleared at database open
  when they differ (M3 databases included)
- [x] Tests: test 8 canaries in malformed, oversized (9 MiB), appended-malformed lines and an unreadable session file
  (counters prove the paths ran); `/service/status?privacy=1` in the process privacy loop (+ a control); tests 2 and
  10 with `uninstall --purge` (`tests/service.rs`); `CCWM_REQUIRE_NETNS` for test 5; process tests use a stub
  `systemctl` (never the real user manager); a racy Git assertion in the M3 acceptance test now waits for the Git queue
- [x] Benchmarks (`scripts/bench.py`, synthetic, release build): idle CPU, RSS, discovery time, watches, 500
  projects, 10k-file burst, watch exhaustion/recovery, ~500 MiB of sessions — [docs/benchmarks.md](docs/benchmarks.md).
  Found and fixed: the reader parked one blocking thread per waiting caller (517 threads at 500 projects → 25)
- [x] CI (`.github/workflows/ci.yml`: fmt, clippy, test with runner capability report + `CCWM_REQUIRE_*` gating +
  NOTICE summary, cargo-deny, gitleaks over the full history; SHA-pinned; `contents: read`) and release workflow
  (`release.yml`: musl, strip, static check, cargo-about, `package-release.sh`, draft release) — **prepared, not run**
- [x] `about.toml` + `about.hbs` (cargo-about 0.9.3, pinned licenses = deny.toml); `.gitleaksignore` + `.gitleaks.toml`
- [x] Docs: README (install from release, screenshots from the synthetic env, privacy summary, notices), SECURITY
  (seccomp, probes, sock_diag, unit, residual risks, manual verification), docs/{configuration, discovery, service,
  troubleshooting, data-retention, benchmarks, two-user-verification, release-checklist}.md, CHANGELOG (0.1.0)
- [x] musl release binary built, stripped, static, smoke-tested in a synthetic env; package + `sha256sum -c` locally
- ~~Test 5 network-namespace variant~~ — removed in the v0.1.0 fix pass (it cannot start the daemon without
  weakening the ownership checks); test 5 uses strace
- [x] CI on GitHub: green as of `2b97ea0` (pushed by the maintainer). The first runs found two tests that
  depended on the runner: a rejected connection closing before the client wrote (`7323ef9`), and the lingering
  state of the runner's user (`2b97ea0`)
- [ ] The release workflow on GitHub (runs on a tag: owner action)
- [ ] Fresh-account install from the archive, start at login / at boot with lingering (owner, release checklist)
- [ ] Manual two-user check (owner; procedure in docs/two-user-verification.md)
- [ ] History/secret audit sign-off, repository recreation, naming-conflict check (O3), tag + release (owner;
  docs/release-checklist.md)
- [x] Spec changes "M4, needs approval" (REQUIREMENTS.md Appendix A): all approved by the maintainer on 2026-11-26,
  the seccomp and probe rows as amended by the fix pass

### v0.1.0 fix pass (pre-release security review; local commit, not pushed)

- [x] **H1** filter-driver names: exact or refused (non-UTF-8 names disable status); fuzz-style sentinel test with
  control runs; the rule recorded in REQUIREMENTS.md §6
- [x] **M1** seccomp denies `socketpair()` too; the peer check's netlink socket is opened before the filter and
  reused, so `socket()` has no exception; SIGTERM shutdown and Git under the filter tested (also the musl binary)
- [x] **M2** ignore files capped: 256 KiB per file, 1 MiB and 5,000 rules per project; skipped files counted and
  reported; hostile-repository tests (unit and real daemon); worst-case memory measured
- [x] **M3** residual-risk text rewritten; `worker-src 'none'`; `Clear-Site-Data` evaluated and **not** sent
  (reasons in SECURITY.md)
- [x] **L1** remote URL credentials (scp-like form, `/` in a password); **L2** canonical home and boundaries;
  **L3** privacy mode hides sandbox notes and the path of a failed save; **L5** request-body timeout (`408`);
  **L6** work-tree search bounded by the discovery root, `.git` must be the user's
- [x] **L4** POSIX ACLs: documented as a limitation (not checked)
- [x] Probes that fail for an unexpected reason report `unverified` (status, doctor, log)
- [x] `ccwm … | head` ends quietly on a closed pipe; "too large to walk" says "partly watched"; table view uses
  the window width, Activity column has a fixed width
- [x] CI: test 5's network-namespace variant and `CCWM_REQUIRE_NETNS` removed; workflows linted (actionlint)
- [x] Info: I1, I2, I4, I5, I6 (documentation), I9 (message)
- [ ] Not done: I3 (WebSocket send timeout / `biased` select), I7 (`wal_checkpoint` result), I8 (session-file cap),
  the stricter `PUT /settings` checks of I6, the review's remaining test-coverage gaps (4–8), a limit on ignore
  rules across projects, `MemoryMax=` in the unit
- [x] Maintainer's review of the choices made during the pass: approved on 2026-11-26 — the 5,000-rule ignore
  limit, `notes_hidden`, `408` for a late body, exit status 0 on a closed pipe (ARCHITECTURE.md §14). Also verified
  by the maintainer on the real home: the real `claude` (2.1.332) passes its check under the `socket`/`socketpair`
  denial
- ~~Live reconfiguration of roots/exclusions/budget~~ — dropped (O1 approved as permanent)

---

## v0.1.1 — planned (not started; needs a go-ahead)

- [ ] Session titles on cards and table rows are rendered so that they cannot be mistaken for a status: quoted
  and in italics, with a tooltip that says it is the session's title. Seen in real use: an AI title worded like
  a status message (it said that a session was being resumed) read as the state of the project. UI only;
  REQUIREMENTS.md §9 gets the wording when it is built

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
- [ ] Git `core.excludesFile` (the user's global ignore file) in the activity rules (maintainer request, post-v0.1)
- [ ] Display of `pr-link` records (the session's pull request) in the detail panel (maintainer request, post-v0.1)
- [ ] **Session activity indicator — the v0.2 headline** (extends the "Claude running" indicator deferred from M3.1; maintainer, 2026-11-25): opt-in Claude Code hooks `SessionStart`/`SessionEnd` and `UserPromptSubmit`/`Stop` call a `ccwm` subcommand that reports `session_id`, `cwd`, `pid` over the Unix socket. States: dim steady dot = session open, waiting for input; bright, gently pulsing dot = Claude working on a turn; no dot = no open session. Liveness from `/proc/<pid>/status` (+ `cmdline`); never inferred from file or session activity; a text label is always present; the pulse is off under `prefers-reduced-motion`; filters "Waiting for me" and "Working". ccwm documents the hook config and never edits `~/.claude`. First: verify the event names and input fields against the installed Claude Code version (ARCHITECTURE §14)
