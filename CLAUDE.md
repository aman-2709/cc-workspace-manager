# CLAUDE.md — CC Workspace Manager (`ccwm`)

Independent, unofficial tool to discover, track and resume Claude Code projects. Not affiliated with Anthropic.

## Source of truth
1. `REQUIREMENTS.md` is the **only** spec; it wins over everything. If a requirement is infeasible, contradictory or unsafe: **stop and report with a concrete alternative; never silently change it.**
2. `ARCHITECTURE.md` (modules, data flow, schema, contracts, verified findings), `ROADMAP.md` (checklists + §18 backlog). Keep all three current. §18 items are **not** v0.1.

## Current status
**M1, M1.1, M2, M2.1, M3, M3.1, M4 (release readiness): complete (local commits, not pushed).** Waiting for the maintainer's review of M4, the "M4, needs approval" spec changes, and the owner actions (push/CI, fresh-account install, two-user check, release). v0.1 has no further milestone; v0.2 items need a new go-ahead. Implement only what is approved; after it, stop, report, and wait.

## Session handoff (2026-11-24, after M4)
- **State:** M4 in one local commit on top of M3.1: `ccwm start|stop|restart|doctor|service install|uninstall [--purge]|auth revoke-all`, systemd user unit (`src/systemd.rs`), `scripts/install.sh`/`uninstall.sh`, exit codes 10/11, `sock_diag` peer lookup (procfs fallback by self-test), seccomp socket filter (`seccompiler`), daemon-level write/connect/socket probes, parser version re-index, reader permits (thread fix), test 8 error-path canaries, tests 2/10 with `--purge` (`tests/service.rs`), `scripts/bench.py` + docs/benchmarks.md, CI + release workflows, cargo-about, gitleaks config, full docs set.
- **Approved before M4:** O1 (permanent: restart-only roots etc.), O7, the narrowed Basic-auth rule.
- **Needs approval:** REQUIREMENTS.md Appendix A rows marked "M4, needs approval" (= ARCHITECTURE §14 O8): sock_diag-first, the seccomp details (netlink allowance, io_uring, x32), probe semantics, parser re-index at DB open, unit directives/`Environment=PATH`/no `ProtectSystem`, service-command behaviour, gitleaks as a pinned binary + allowlists + draft releases.
- **Not run anywhere (needs a push / owner):** CI and release workflows on GitHub; test 5's network-namespace variant (CI sets `CCWM_REQUIRE_NETNS=1` when its probe works); fresh-account install from the archive + start at boot with lingering; the two-user check (docs/two-user-verification.md); naming-conflict check (O3). All in docs/release-checklist.md.
- **Open items:**
  - `GIT_NO_LAZY_FETCH` is honored by this host's Ubuntu git (CVE-2024-32465 backport); older upstream ignores it (the other two blocks still apply).
  - Watches are still added by path (L2 residual); only a swap to a non-directory is caught.
  - The real `claude` under the seccomp filter is untested (tests use a fake; if it needs a socket for `--version` the check reports `failed` and resume shows a warning): the maintainer's real-home run will show it in `ccwm doctor`.
  - `ccwm status | head` panics on the broken pipe (Rust `println!`; pre-existing, cosmetic).
  - Prompt reads still reopen the file by path (informational, M3 review).
  - `cargo-deny` (0.21.0) and `cargo-about` (0.9.3, `--features cli`) live in `target/tools/` (reinstall after `cargo clean`; commands in `deny.toml` / `about.toml`).
- **Build / test / run (synthetic environment only):** see **Commands** below. For a verified `claude` in a manual run, put a fake `claude` script in `<synth>/home/.local/bin` and start the daemon with `PATH=<that dir>:/usr/bin:/bin` (never let it find the real `claude`). Service commands in tests use a stand-in `systemctl` first on `PATH` (never the real user manager).

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
cargo build --release --bins && scripts/bench.py --bin target/release    # benchmarks (synthetic, ~15 min; --idle 0 to skip the 10-min window)
CARGO_TARGET_DIR=/tmp/ccwm-musl cargo build --locked --release --target x86_64-unknown-linux-musl --bin ccwm   # release binary (musl-gcc installed)
CCWM_REQUIRE_LANDLOCK=1 cargo test --test sandbox --test process   # fail (not skip) if Landlock is unavailable
cargo build
target/debug/ccwm-synth /tmp/ccwm-synth-demo --projects 30      # synthetic HOME/XDG/CLAUDE_CONFIG_DIR (+ real Git repos if git exists); writes <dir>/env
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm serve --port 8766 &   # the synthetic env goes to ccwm only, never to cargo
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm open --print          # single-use sign-in link (open it in a browser)
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm status               # daemon state + build-commit check
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm scan                 # reconcile now, wait for it
```
Tests: `cargo test` (unit + `tests/*.rs`; `tests/watch.rs` uses a fake watch backend, `tests/tracker.rs`/`process.rs` need real inotify instances (skip with notice unless `CCWM_REQUIRE_INOTIFY=1`) and Git; test 5 needs `strace` or user namespaces; `tests/process.rs` spawns the real binary in a synthetic env; `tests/sandbox.rs` has its own `main` (`harness = false`) so Landlock is applied single-threaded; `tests/ui.rs` runs `node --test` if node exists; `tests/service.rs` drives install/uninstall scripts and service commands through a stand-in `systemctl`; set `CCWM_REQUIRE_NETNS=1` to make test 5 fail unless its network-namespace variant ran). Tests that check paths ccwm trusts use 0700 temp dirs (`common::tempdir`, `paths::private_tempdir`): tempdirs follow the umask (0775 here).

## Conventions
- Rust stable, `rust-version = "1.94"` (only tested toolchain). `Cargo.lock` committed. New dependency ⇒ justify in ARCHITECTURE.md §4 first; HTTP/DNS client crates are **banned** (`deny.toml`).
- Module boundaries: only `git/` spawns git (via `Git::command`: empty env + the eight §6 vars, `BASE_ARGS`); `claude/cli.rs` spawns only `claude --version|--help` (via `child_command` and `git::run::run`); only `watch/` touches notify; only `tracker` combines discovery, tree walk, Git and watches; only `claude/` knows Claude formats; only `db/writer.rs` writes SQLite; no `rusqlite` on Tokio workers; bounded queues; transports (HTTP, Unix socket) call `service.rs` only.
- **Landlock is applied in `main` before any other thread exists.** Report what is active, never what was requested.
- Security: bind `127.0.0.1` only; every TCP connection's peer UID verified (`http/peer.rs`) before anything is read; Host + Origin checks; tokens hashed (SHA-256), constant-time compared, never logged; parameterized SQL; clients never pass paths (opaque ids); session text never logged or rendered as HTML; CLI ↔ daemon only over the Unix socket with `SO_PEERCRED` verified on both sides; a TCP `/health` is never identity.
- After the listeners are bound the daemon may create **no socket** (seccomp): anything new that needs one must be set up before `deny_new_sockets` in `daemon::run`, or use the allowed `NETLINK_SOCK_DIAG`.
- Every child process of the daemon is built with `sandbox::child_command` (drops session-IPC env vars). Directories are walked by descriptor (`discovery/dirfd.rs`), never re-opened by path. Paths ccwm trusts (config file, ancestors of its dirs) go through `paths::Owner::verify_trusted`.
- Frontend: vanilla, embedded; no CDN/framework; **no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`** (grep test); no inline script/style (CSP) — style via classes/CSSOM.
- Unknown stays unknown; never fabricate titles/summaries/timestamps; `inferred` vs `observed`.
- Inject clocks, roots, uid and dirs so tests never read the real environment.
- User style: DRY (flag repetition); many tests > few; explicit over clever; "engineered enough"; handle edge cases; explain trade-offs. Invoke `andrej-karpathy-skills:karpathy-guidelines` before non-trivial code. When corrected or reviewed, ask whether to record the learning here.

## Environment facts (2026-11-24)
Ubuntu 24.04, rustc/cargo 1.94.0, git 2.43.0 (needs ≥2.41.0 for `--attr-source`), claude 2.1.331, systemd 255, Landlock ABI 8, strace 6.8, node 22, musl-gcc, shellcheck 0.9, Python 3 (bench.py); `unshare -rn` and `--map-current-user` unavailable (AppArmor) ⇒ test 5 runs the strace variant; inotify `max_user_instances` 128 with ~109 used by other processes (tests serialize their watchers).

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

## Module status
M1: `paths config clock error api_error sandbox instance db/{mod,writer,reader,queries} discovery/{walk,dirfd,exclusions,mounts,status} auth/{tokens,bootstrap,sessions} service ipc/{protocol,server} client http/{mod,peer,middleware,extract,routes,assets,error} daemon cli synth bin/ccwm-synth` + `web/*` + `scripts/inspect-session-schema.py` + `deny.toml` + `SECURITY.md`. M2: `activity git/{mod,run,parse} watch/{mod,tree} tracker events view http/ws build.rs` + migration 3 + README/CONTRIBUTING. M2.1: no new modules. M3: `claude/{locate,record,parse,prompt,redact,resume,cli}` `discovery/resolve` `tracker/{mod,sessions}` (was `tracker.rs`) + migration 4 + `tests/fixtures/sessions/` + `tests/sessions_api.rs`. M3.1: no new modules; migration 5 (`partial` checkpoints). M4: `systemd doctor` + `scripts/{install,uninstall,package-release}.sh` `scripts/bench.py` + `.github/workflows/{ci,release}.yml` `about.toml` `about.hbs` `.gitleaks.toml` `.gitleaksignore` + `tests/service.rs` + `docs/*.md`; no migration (parser version in `meta`).

## Open items
See ARCHITECTURE.md §14 (O2, O3, O4, O8).
