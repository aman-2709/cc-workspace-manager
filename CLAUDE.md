# CLAUDE.md — CC Workspace Manager (`ccwm`)

Independent, unofficial tool to discover, track and resume Claude Code projects. Not affiliated with Anthropic.

## Source of truth
1. `REQUIREMENTS.md` is the **only** spec; it wins over everything. If a requirement is infeasible, contradictory or unsafe: **stop and report with a concrete alternative; never silently change it.**
2. `ARCHITECTURE.md` (modules, data flow, schema, contracts, verified findings), `ROADMAP.md` (checklists + §18 backlog). Keep all three current. §18 items are **not** v0.1.

## Current status
**v0.1.0 is released** (tag `v0.1.0` at `975bf10`). **v0.1.1 is built and committed locally** (a maintenance release, ROADMAP.md "v0.1.1"): not pushed, not tagged, CI not run on it. Its spec changes (REQUIREMENTS.md Appendix A, rows marked "v0.1.1, needs approval") and the choices made on the way (ARCHITECTURE.md §14) **wait for the maintainer's approval**. The v0.2 headline (the session activity indicator, ARCHITECTURE.md §14) and the other §18 items need their own go-ahead. Implement only what is approved; after it, stop, report, and wait.

## Session handoff (2026-11-26, after the v0.1.1 work)
- **State:** v0.1.0 is tagged at `975bf10`. On top of it: docs commits, then **one local commit for v0.1.1** (version 0.1.1 in `Cargo.toml`). Nothing of v0.1.1 is pushed. What was run is in ARCHITECTURE.md §13i.
- **v0.1.1 contains:** session titles as quotations on cards and table rows (`sessionParts` / `sessionLine` in `web/app.js`); `MemoryMax=2G` + `MemorySwapMax=0` in the unit; a limit of 20,000 ignore rules across projects (`watch::tree::IgnoreBudget`, shared by the tracker and the monitor); review items I3 (`http/ws.rs`: biased select, `SEND_TIMEOUT` 5 s), I7 (`db/writer.rs`: `truncate_wal`, owed until it succeeds), I8 (`claude/locate.rs`: `Listing::truncated`; `tracker/sessions.rs`: `gone_files`), I6 (`service.rs`: `check_patch_values`, `settable_path`); the review's test-coverage gaps 4–8; `synth::write_executable` for every script a test runs at once; an `ignore` scenario in `scripts/bench.py`.
- **Waiting for the maintainer:** approval of the Appendix A rows "v0.1.1, needs approval" and of the choices in ARCHITECTURE.md §14: 20,000 rules; `MemoryMax=2G`; **`MemorySwapMax=0` (not in the request; without it the limit only moves memory to swap, verified)**; the 5 s WebSocket send timeout; `CCWM_REQUIRE_LANDLOCK_ABI` in CI. The README item of the request was an unfilled placeholder: nothing was changed for it.
- **Found, not fixed (outside the v0.1.1 list; ARCHITECTURE.md §13i, §14):** polled projects are walked again at every scan and their ignore rules compiled again. The static musl binary gives the memory back (peak 775 MiB at the limit, then 395 MiB); **a glibc build does not** (1.66 GiB after four scans at the limit; ten times the kept size with a small set). Proposal: reuse the compiled rules of an ignore file whose content did not change. Not started: needs a go-ahead.
- **CI:** green on GitHub as of `2b97ea0` (v0.1.0), as reported by the maintainer. **Not run on v0.1.1.** New in the workflow: `CCWM_REQUIRE_LANDLOCK_ABI`; three skips (pty paste test, node, `systemd-analyze`) now fail in CI when their tool is missing — the runner is expected to have python3, bash, node and `systemd-analyze`; if the first CI run fails there, that expectation is wrong, not the code. No session has read the test job's summary.
- **Next step:** the maintainer's review of v0.1.1; then pushing, CI, tagging and the release workflow, which stay with the maintainer (Hard rules).
- **Decided not to do, documented instead (v0.1.0 fix pass):** `Clear-Site-Data` (not reliable in Chrome and Firefox per MDN's compatibility data, and it acts after a poisoned page already ran; not tested in a browser); POSIX ACLs in the trust check (L4: needs an xattr read, i.e. a new dependency).
- **From the v0.1.0 review:** everything the previous handoff listed as not fixed (I3, I7, I8, the settings checks of I6, test-coverage gaps 4–8, a limit on ignore rules across projects, `MemoryMax=`) is done in v0.1.1.
- **Approved by the maintainer (2026-11-26):** every REQUIREMENTS.md Appendix A row that was marked "M4, needs approval" (= ARCHITECTURE §14 O8), the seccomp row as amended by the fix pass and the probe row as amended; and these choices of the fix pass: the 5,000-rule ignore limit, `notes_hidden` in privacy mode, `408 request_timeout` for a late body, exit status 0 on a closed output pipe.
- **Verified by the maintainer on the real home (after `b03829a`):** `ccwm doctor` reports the `claude` check ok (Claude Code 2.1.332, `--resume` supported, checked by the daemon in its sandbox) with the seccomp `socket` and `socketpair` denial active. The tests still use a fake `claude`.
- **Owner actions, never run in a session:** the release workflow on GitHub (tag-triggered; linted with actionlint only), the fresh-account install from the archive + start at boot with lingering, the two-user check (docs/two-user-verification.md), the naming-conflict check (O3). Whether and how they went for v0.1.0 is not recorded in this file (docs/release-checklist.md is the list).
- **Open items:**
  - `GIT_NO_LAZY_FETCH` is honored by this host's Ubuntu git (CVE-2024-32465 backport); older upstream ignores it (the other two blocks still apply).
  - Watches are still added by path (L2 residual of the M2 review); only a swap to a non-directory is caught.
  - Prompt reads still reopen the file by path (informational, M3 review).
  - `cargo-deny` (0.21.0) and `cargo-about` (0.9.3, `--features cli`) live in `target/tools/` (reinstall after `cargo clean`; commands in `deny.toml` / `about.toml`). gitleaks 8.30.1 and actionlint 1.7.12 are in `/tmp/ccwm-ci/bin-gitleaks/` and `/tmp/ccwm-ci/bin-actionlint/` (gone after a reboot).
- **Build / test / run (synthetic environment only):** see **Commands** below. For a verified `claude` in a manual run, put a fake `claude` script in `<synth>/home/.local/bin` and start the daemon with `PATH=<that dir>:/usr/bin:/bin` (never let it find the real `claude`). Service commands in tests use a stand-in `systemctl` first on `PATH` (never the real user manager). Unit directives are verified with `systemd-run --user` transient units under their own names (the maintainer's real `ccwm.service` runs under the same user manager: never touch it). Stop a manually started daemon by the pid in its `instance.json`.

## Hard rules
- **Never** push, add remotes, tag, publish, run `sudo`, or run `loginctl enable-linger`. Never write outside this repo except cargo's normal `~/.cargo` cache and `/tmp` synthetic environments. Never modify `~/.claude` or monitored projects.
- **Development-time privacy (§19): do not open, read, `cat`, `head`, `grep`, `jq`, or otherwise touch any file under `~/.claude` or `$CLAUDE_CONFIG_DIR` — not even structurally.** Schema questions go through `scripts/inspect-session-schema.py`, which the **maintainer** runs and pastes back. Never copy real session content, real project content or credentials into the repo or the context.
- Run `ccwm` only in a synthetic environment (`ccwm-synth`), never against the real home; the maintainer validates against the real home in a browser. **Never run cargo with the synthetic `HOME`/`XDG_*`** — apply the synthetic env only to the spawned `ccwm` process.
- Do not claim anything works unless it was run. Report only tested environments.
- Per milestone: acceptance criteria met; `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` green; update ROADMAP.md + this file; one local commit (use the `code_commit_writer` skill); report (built / test results / how to run / known limitations).

## Commands
```bash
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
target/tools/bin/cargo-deny check        # install: cargo install --locked --root target/tools cargo-deny --version 0.21.0
target/tools/bin/cargo-about generate --frozen --fail about.hbs > /tmp/THIRD_PARTY_LICENSES   # install: see about.toml
cargo build --release --bins && scripts/bench.py --bin target/release    # benchmarks (synthetic, ~15 min; --idle 0 to skip the 10-min window; --only ignore: the ignore-rule limits, <1 min)
CARGO_TARGET_DIR=/tmp/ccwm-musl cargo build --locked --release --target x86_64-unknown-linux-musl --bin ccwm   # release binary (musl-gcc installed)
CCWM_REQUIRE_LANDLOCK=1 cargo test --test sandbox --test process   # fail (not skip) if Landlock is unavailable
CCWM_REQUIRE_LANDLOCK=1 CCWM_REQUIRE_LANDLOCK_ABI=8 CCWM_REQUIRE_INOTIFY=1 cargo test   # this host: everything required (ABI 8)
cargo build
target/debug/ccwm-synth /tmp/ccwm-synth-demo --projects 30      # synthetic HOME/XDG/CLAUDE_CONFIG_DIR (+ real Git repos if git exists); writes <dir>/env
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm serve --port 8766 &   # the synthetic env goes to ccwm only, never to cargo
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm open --print          # single-use sign-in link (open it in a browser)
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm status               # daemon state + build-commit check
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm scan                 # reconcile now, wait for it
```
Tests: `cargo test` (unit + `tests/*.rs`; `tests/watch.rs` uses a fake watch backend, `tests/tracker.rs`/`process.rs` need real inotify instances (skip with notice unless `CCWM_REQUIRE_INOTIFY=1`) and Git; test 5 needs `strace`; `tests/process.rs` spawns the real binary in a synthetic env; `tests/sandbox.rs` has its own `main` (`harness = false`) so Landlock is applied single-threaded; `tests/ui.rs` runs `node --test` if node exists; `tests/service.rs` drives install/uninstall scripts and service commands through a stand-in `systemctl`; `tests/sandbox.rs` makes raw system calls through a `python3`/ctypes child; with `CI` set, a missing python3/bash (pty paste test), node or `systemd-analyze` is a failure, not a skip: `common::skipped_coverage`; `CCWM_REQUIRE_LANDLOCK_ABI=<n>` makes the ABI 4 and ABI 6 assertions mandatory). Tests that check paths ccwm trusts use 0700 temp dirs (`common::tempdir`, `paths::private_tempdir`): tempdirs follow the umask (0775 here).

## Conventions
- Rust stable, `rust-version = "1.94"` (only tested toolchain). `Cargo.lock` committed. New dependency ⇒ justify in ARCHITECTURE.md §4 first; HTTP/DNS client crates are **banned** (`deny.toml`).
- Module boundaries: only `git/` spawns git (via `Git::command`: empty env + the eight §6 vars, `BASE_ARGS`); `claude/cli.rs` spawns only `claude --version|--help` (via `child_command` and `git::run::run`); only `watch/` touches notify; only `tracker` combines discovery, tree walk, Git and watches; only `claude/` knows Claude formats; only `db/writer.rs` writes SQLite; no `rusqlite` on Tokio workers; bounded queues; transports (HTTP, Unix socket) call `service.rs` only.
- **Landlock is applied in `main` before any other thread exists.** Report what is active, never what was requested.
- Security: bind `127.0.0.1` only; every TCP connection's peer UID verified (`http/peer.rs`) before anything is read; Host + Origin checks; tokens hashed (SHA-256), constant-time compared, never logged; parameterized SQL; clients never pass paths (opaque ids); session text never logged or rendered as HTML; CLI ↔ daemon only over the Unix socket with `SO_PEERCRED` verified on both sides; a TCP `/health` is never identity.
- After the listeners are bound the daemon may create **no socket and no socket pair**, of any family (seccomp, no exception): anything that needs one must exist before `deny_new_sockets` in `daemon::run` (the peer check's `SockDiag`, the signal handlers). Children must stay startable by `posix_spawn`: an absolute program path, no `pre_exec`, no uid/gid change (std's fork/exec fallback needs a `socketpair`).
- Commands print with `cli::out!/outln!/err!/errln!`, never `println!`/`eprintln!` (a closed pipe would panic; `tests/hygiene.rs` checks). A probe that fails for an unexpected reason makes its protection `unverified`, never claimed and never withdrawn.
- Git: a driver name, ref or key that cannot be passed back to Git byte for byte is refused, never approximated (no lossy decoding on anything that becomes an argument).
- Every child process of the daemon is built with `sandbox::child_command` (drops session-IPC env vars). Directories are walked by descriptor (`discovery/dirfd.rs`), never re-opened by path. Paths ccwm trusts (config file, ancestors of its dirs) go through `paths::Owner::verify_trusted`.
- Frontend: vanilla, embedded; no CDN/framework; **no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`** (grep test); no inline script/style (CSP) — style via classes/CSSOM.
- Unknown stays unknown; never fabricate titles/summaries/timestamps; `inferred` vs `observed`.
- Inject clocks, roots, uid and dirs so tests never read the real environment. A script that a test runs right after writing it is written with `synth::write_executable` (`common::write_executable` in `tests/`), never `fs::write`.
- Ignore rules: every walk gets its rule allowance from the shared `tree::IgnoreBudget` (`reserve` + `settle` for a full walk, `room` for a subtree walk); never build a `TreeOptions` in production code with a constant.
- User style: DRY (flag repetition); many tests > few; explicit over clever; "engineered enough"; handle edge cases; explain trade-offs. Invoke `andrej-karpathy-skills:karpathy-guidelines` before non-trivial code. When corrected or reviewed, ask whether to record the learning here.

## Environment facts (2026-11-25)
Ubuntu 24.04, rustc/cargo 1.94.0, git 2.43.0 (needs ≥2.41.0 for `--attr-source`), claude 2.1.331, systemd 255, Landlock ABI 8, strace 6.8, node 22, musl-gcc, shellcheck 0.9, Python 3 (bench.py, raw system calls in `tests/sandbox.rs`); unprivileged user namespaces are unavailable (AppArmor); inotify `max_user_instances` 128 with ~109 used by other processes (tests serialize their watchers).

## Gotchas learned
- notify 9 reports a rename as `From`, `To` **and** a paired `Both` (same cookie) and drops watches of a moved directory itself; act on `Both`, expire unpaired halves (200 ms).
- `Path::join("")` appends a trailing slash: the root of a moved tree moves to `to`, not `to.join("")`.
- Timestamps are whole seconds: never detect "a new scan finished" by comparing times (use `scans_finished`); tests that need "newer" must cross a second boundary.
- `log.showSignature=true` + `gpg.program` in repo config runs a program during `git log` ⇒ always `--no-show-signature`.
- Git splits `-c` at the first `=`: a filter driver named `x=y` cannot be nulled ⇒ disable status (fail closed).
- `watch::Ref` (from `wait_for`) is not `Send`: use `events::until_stopped` in spawned `select!`s.
- `pkill -f <pattern>` matches the invoking shell's own command line when the pattern appears in it: use a `[x]yz` bracket pattern.
- A test script used as a fake `ssh` must not read stdin (Git waits for it ⇒ deadlock).
- `git status` runs `filter.*.clean` even with the basic hardening flags; needs `--attr-source=<empty tree>` **and** nulling every filter driver in every scope (ARCHITECTURE.md §12).
- Landlock confines only the calling thread and its future children: apply it before spawning threads.
- SQLite under Landlock: `temp_store=MEMORY` (no `/tmp` writes).
- Session timestamps are unordered within a file; `cwd` only on `user|assistant|attachment|system`; no single genuine-prompt flag (ARCHITECTURE.md §11).
- `PrivateDevices=yes` is rejected in user units.
- Home is `$HOME` (if owned by you) before the passwd entry; otherwise the synthetic environment would silently fall through to the real home.
- serde `deny_unknown_fields` does not reject extra fields on internally tagged unit variants: the socket protocol parser checks the object shape by hand.
- `ignore::gitignore` accepts most odd patterns (`[`); only a few (`a\\`, `{a`) error — patterns are validated at config load.
- Landlock: `NetPort(0, BindTcp)` makes `--port 0` (ephemeral) work; without a rule for 0 an ephemeral bind is denied.
- libtest runs every test on a spawned thread, so a Landlock test inside the normal harness can never be single-threaded: `tests/sandbox.rs` is `harness = false`.
- Ubuntu's umask is 0002 with user private groups: files/dirs are group-writable by default. The L4 trust rule accepts group write only by the user's private group.
- Landlock ABI 8 does not confine `connect()` on path-based Unix sockets (`ResolveUnix` is ABI 9); abstract sockets and signals are scoped from ABI 6 (`connect` ⇒ `EPERM`).
- Nothing in ccwm logged below `info` before M1.1, so a trace-level log test proved nothing; the TCP peer check (debug) and socket requests (trace, op name only) now log there.
- `axum::serve` exposes no header-read timeout; the server loop uses hyper's http1 builder directly (`http/mod.rs`).
- A gitignore pattern with an inner slash is anchored to the `.gitignore` directory: use `**/ccwm/config.toml`.
- A repository's per-protocol `protocol.<name>.allow` beats a command-line `protocol.allow=never`; a promisor partial clone makes `status`/`log` lazily fetch (and run the transport). Block with `GIT_ALLOW_PROTOCOL=` + per-protocol `-c` + `GIT_NO_LAZY_FETCH=1`.
- notify 9 requests `IN_ONLYDIR` but retries **without** it on `ENOTDIR`: check `is_dir` after adding a watch.
- strace abbreviates arrays/strings at 32 by default (`...`): use `-s 256` when parsing `execve` argv.
- Changing a CSS grid template does not resize its container: a `ResizeObserver` on the container does not fire (test path fitting with a real width change).
- `pkill -f '[x]yz…'` still kills the invoking shell if the plain text `xyz…` appears **elsewhere** in the same command line (e.g. a restart after the kill): stop a daemon by the pid in `instance.json` instead.
- A browser navigation that changes only the URL fragment does not reload the page: `location.reload()` after navigating to a new `#bt=` link.
- The daemon's `Config` includes command-line overrides (`--port`): Settings must keep the **file's** config, or a save writes the override into `config.toml`.
- `ai-title` records carry no timestamp: "latest" title = last in file order.
- The synthetic home lives under `/tmp`: the "temporary directory" rule for session cwds exempts cwds inside home.
- `.session-aliases` is gitignored: fixtures that need it are created by `synth::install_sessions`.
- Privacy is a server concern: never strip fields in `app.js`; add the field to `view::Privacy` / the status/settings strippers in `service.rs` and to the canary test in `tests/sessions_api.rs`.
- Landlock scopes ptrace-class access: inside the daemon, `/proc/<pid>/cwd`, `/exe` (and `environ`, `fd`) of processes outside its domain are `EACCES`; `cmdline` and `status` stay readable. No rule relaxes it.
- No test may create files in the working tree (a real ccwm watching the maintainer's home registers them; they become missing projects). `git check-ignore --no-index` on a path that does not exist ignores the nested `.gitignore` files it would contain: test such cases in a throwaway repository under `/tmp`.
- A `partial` session checkpoint (early stop) must be re-read from 0 when its cwd stops qualifying **even if the file is unchanged** — check `partial` before the unchanged shortcut.
- The settings PUT body is a diff against the saved config (`changedSettings` in `app.js`); diff against `st.config` after `Object.assign(st, response)`, not a captured copy.
- `Reader::with` must take its permit before `spawn_blocking`: blocking on the pool's condvar inside a blocking task let 500 Git refreshes grow Tokio's blocking pool to 517 threads (M4 benchmark).
- Tests that need to wait for Git must poll: the Git queue runs after enrollment (`git: null` = not stored yet); asserting right after `wait_scan_done` is racy.
- systemd `ProtectSystem`/`ProtectHome`/`PrivateTmp` in a **user** unit put the service in a user namespace where root-owned paths show uid 65534: ccwm's trust checks refuse to start. Don't add them.
- seccomp TSYNC needs every thread to share the same filter ancestry: fine under systemd's own filters (verified); never install a per-thread filter before `deny_new_sockets`.
- Landlock denies `O_TMPFILE` outside the write set (`EACCES`): the write probe relies on it.
- A `sock_diag` exact lookup returns `ENOENT` both for "no such socket" and "no diag handler": the startup self-test (own loopback connection) decides whether `sock_diag` is usable at all.
- cargo-about 0.9 installs its binary only with `--features cli`.
- `gitleaks git` fingerprints contain the commit SHA: new synthetic canaries must contain `SYNTHETIC` (allowlisted in `.gitleaks.toml`) rather than be added to `.gitleaksignore`.
- The pty paste test drives `bash -i` through python3's `pty`; batch all pastes into one bash per mode (one bash per paste took ~40 s) and end with a liveness paste so a stuck quote cannot pass vacuously.
- `String::from_utf8_lossy` on a Git config key turns a non-UTF-8 driver name into another name: the `-c` override then neutralizes nothing (review H1). Decode strictly and refuse.
- A datagram `socketpair()` needs no `socket()` and can `sendto()` a path-based socket: a seccomp socket filter must deny `socketpair` too.
- Rust's `Command::spawn` uses `posix_spawn` only for an absolute (or `/`-containing) program without `pre_exec`/uid/gid; otherwise it forks and creates a `socketpair(AF_UNIX, SOCK_SEQPACKET)`, which the filter denies. musl takes the `posix_spawn` path too (checked with the static binary).
- Tokio creates its signal socket pair when the runtime is built; `signal()` itself needs no socket, but register the handlers before the filter anyway.
- `unsafe` is forbidden crate-wide, tests included: raw system calls in a test go through a `python3 -c` child with ctypes (it inherits the filter).
- The `ignore` crate costs about 15 KiB of memory and 0.25 ms per rule that needs a regular expression (1 MiB of such rules: 920 MiB, 15 s); literal rules are nearly free. Bytes are a poor limit: count rules, before compiling.
- A test that writes a script with `fs::write` and runs it at once can fail with `ETXTBSY` when another test thread forks in between (the child holds the write descriptor until it execs): let a child shell write it (`common::write_executable`).
- An unprivileged network namespace needs a user namespace, where root-owned paths show uid 65534: the daemon refuses to start there (same as the systemd directives). No namespace variant for test 5.
- `table-layout: fixed` ignores `min-width` on cells: give a column a width in `rem` on its header cell instead. `main:has(.table-wrap)` widens the page only while the table is shown.
- The browser automation window may not resize (maximized): emulate narrow layouts by setting a width on `main`.
- A server that rejects a connection may close it **before the client has written**: the client's write then fails with `EPIPE`/`ECONNRESET` instead of its read ending. A test of "dropped without a response" accepts the drop at any point, still reads the connection to EOF, and asserts on the **bytes received** (none), never on which call failed (`common::response_to_a_dropped_connection`). The first CI run failed `tests/ipc.rs` on this; locally it shows only under load (14 of 1,200 runs).
- Tests must not assume host state: lingering (`/var/lib/systemd/linger/<user>` is on for GitHub's `runner` user, off here), a systemd user session, `PATH`, the runner's user. The synthetic environment replaces `HOME`/`XDG_*`/`CLAUDE_CONFIG_DIR` only. Derive the expectation from the machine's actual state or inject the state, and cover each branch with a unit test of a pure function (`systemd::linger_hint` and the hint check in `tests/service.rs`).

- `MemoryMax=` in a user unit is enforced on Ubuntu 24.04 (the user manager has the memory controller), but with swap it only moves the excess to swap: a 300 MiB allocation under `MemoryMax=64M` survived with 246 MiB swapped. `MemorySwapMax=0` makes it a limit (`oom-kill`). With `Restart=on-failure` an over-limit daemon is restarted every few seconds.
- glibc malloc keeps memory freed on other threads (per-thread arenas): rules compiled on blocking-pool threads at every scan of polled projects made RSS several times the live size (5× after four scans, 10× after thirty with a small set). musl's allocator returns it. Measure memory with **both** builds; the release binary is musl.
- `Path::components()` drops `.` components: a check for "no `.` or `..`" by components only ever rejects `..`.
- A fresh synthetic environment is needed to see new markers: after the first full scan only development roots are scanned, so projects added to an environment that already has a database are not found.
- Tokio `select!` picks a ready arm at random unless `biased;`: to test an ordering, make both arms ready in one synchronous stretch of a current-thread test (no `.await` between the two triggers).
- `PRAGMA wal_checkpoint` reports a blocked checkpoint as a row (`busy = 1`), not as an error: read the row.
- `/dev` → `/dev/shm` is a file-system boundary every Linux has (devtmpfs → tmpfs): usable for `same_file_system` tests without mounting anything. `tempfile` names start with `.tmp` (hidden, never walked): give test directories a visible prefix.
- `gzip -9` of the 140 MB debug binary takes 15 s: tests of the release archive package a small stand-in script that execs the real binary.
- A single-use sign-in link lives 30 s: print it and open it in the same step.

## Module status
M1: `paths config clock error api_error sandbox instance db/{mod,writer,reader,queries} discovery/{walk,dirfd,exclusions,mounts,status} auth/{tokens,bootstrap,sessions} service ipc/{protocol,server} client http/{mod,peer,middleware,extract,routes,assets,error} daemon cli synth bin/ccwm-synth` + `web/*` + `scripts/inspect-session-schema.py` + `deny.toml` + `SECURITY.md`. M2: `activity git/{mod,run,parse} watch/{mod,tree} tracker events view http/ws build.rs` + migration 3 + README/CONTRIBUTING. M2.1: no new modules. M3: `claude/{locate,record,parse,prompt,redact,resume,cli}` `discovery/resolve` `tracker/{mod,sessions}` (was `tracker.rs`) + migration 4 + `tests/fixtures/sessions/` + `tests/sessions_api.rs`. M3.1: no new modules; migration 5 (`partial` checkpoints). M4: `systemd doctor` + `scripts/{install,uninstall,package-release}.sh` `scripts/bench.py` + `.github/workflows/{ci,release}.yml` `about.toml` `about.hbs` `.gitleaks.toml` `.gitleaksignore` + `tests/service.rs` + `docs/*.md`; no migration (parser version in `meta`). v0.1.0 fix pass: no new modules, no migration, no new dependency. v0.1.1: no new modules, no migration, no new dependency (new types: `watch::tree::IgnoreBudget`; `synth::write_executable`).

## Open items
See ARCHITECTURE.md §14 (O2, O3, O4).
