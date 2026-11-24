# CLAUDE.md — CC Workspace Manager (`ccwm`)

Independent, unofficial tool to discover, track and resume Claude Code projects. Not affiliated with Anthropic.

## Source of truth
1. `REQUIREMENTS.md` is the **only** spec; it wins over everything. If a requirement is infeasible, contradictory or unsafe: **stop and report with a concrete alternative; never silently change it.**
2. `ARCHITECTURE.md` (modules, data flow, schema, contracts, verified findings), `ROADMAP.md` (checklists + §18 backlog). Keep all three current. §18 items are **not** v0.1.

## Current status
**M1 — Foundation: complete (pushed by the maintainer). M1.1 — security hardening: complete (local commit, not pushed).** Waiting for the maintainer's go-ahead before M2. Implement only the approved milestone; after it, stop, report, and wait.

## Session handoff (2026-11-23, after M1.1)
- **State:** M1.1 fixed every finding of `docs/reviews/m1-security-review.md` (H1–H2, M1–M4, L1–L8, weak tests 1/6/7/9/11) in one local commit `fix: M1.1 security hardening` (not pushed). Spec changes are in REQUIREMENTS.md §11 + Appendix A and in SECURITY.md (new).
- **Next:** M2, only after the maintainer approves.
- **Open items:**
  - The maintainer has not run `scripts/inspect-session-schema.py` yet (they run it and paste the output; the agent never runs it). Its `--policy` output was shown in the M1.1 report.
  - Security acceptance test 5: `unshare -rn` is unavailable here (AppArmor); the strace fallback is an M4 item.
  - Seccomp `socket()` deny (closes UDP and path-based Unix connect) is deferred to M4.
  - `cargo-deny` is not installed system-wide; it is installed into the ignored `target/tools/` (0.21.0; 0.22 needs rustc 1.95). `target/` is disposable, so reinstall after `cargo clean` (command in `deny.toml`).
- **Build / test / run (synthetic environment only):** See **Commands** below.

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
CCWM_REQUIRE_LANDLOCK=1 cargo test --test sandbox --test process   # fail (not skip) if Landlock is unavailable
cargo build
target/debug/ccwm-synth /tmp/ccwm-synth-demo --projects 30      # synthetic HOME/XDG/CLAUDE_CONFIG_DIR; writes <dir>/env
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm serve --port 8766 &   # the synthetic env goes to ccwm only, never to cargo
env $(cat /tmp/ccwm-synth-demo/env) target/debug/ccwm open --print          # single-use sign-in link (open it in a browser)
```
Tests: `cargo test` (unit + `tests/*.rs`; `tests/process.rs` spawns the real binary in a synthetic env; `tests/sandbox.rs` has its own `main` (`harness = false`) so Landlock is applied single-threaded; `tests/ui.rs` runs `node --test` if node exists). Tests that check paths ccwm trusts use 0700 temp dirs (`common::tempdir`, `paths::private_tempdir`): tempdirs follow the umask (0775 here).

## Conventions
- Rust stable, `rust-version = "1.94"` (only tested toolchain). `Cargo.lock` committed. New dependency ⇒ justify in ARCHITECTURE.md §4 first; HTTP/DNS client crates are **banned** (`deny.toml`).
- Module boundaries: only `git/` spawns git; only `claude/` knows Claude formats; only `db/writer.rs` writes SQLite; no `rusqlite` on Tokio workers; bounded queues; transports (HTTP, Unix socket) call `service.rs` only.
- **Landlock is applied in `main` before any other thread exists.** Report what is active, never what was requested.
- Security: bind `127.0.0.1` only; every TCP connection's peer UID verified (`http/peer.rs`) before anything is read; Host + Origin checks; tokens hashed (SHA-256), constant-time compared, never logged; parameterized SQL; clients never pass paths (opaque ids); session text never logged or rendered as HTML; CLI ↔ daemon only over the Unix socket with `SO_PEERCRED` verified on both sides; a TCP `/health` is never identity.
- Every child process of the daemon is built with `sandbox::child_command` (drops session-IPC env vars). Directories are walked by descriptor (`discovery/dirfd.rs`), never re-opened by path. Paths ccwm trusts (config file, ancestors of its dirs) go through `paths::Owner::verify_trusted`.
- Frontend: vanilla, embedded; no CDN/framework; **no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`** (grep test); no inline script/style (CSP) — style via classes/CSSOM.
- Unknown stays unknown; never fabricate titles/summaries/timestamps; `inferred` vs `observed`.
- Inject clocks, roots, uid and dirs so tests never read the real environment.
- User style: DRY (flag repetition); many tests > few; explicit over clever; "engineered enough"; handle edge cases; explain trade-offs. Invoke `andrej-karpathy-skills:karpathy-guidelines` before non-trivial code. When corrected or reviewed, ask whether to record the learning here.

## Environment facts (2026-11-23)
Ubuntu 24.04, rustc/cargo 1.94.0, git 2.43.0 (needs ≥2.41.0 for `--attr-source`), claude 2.1.331, systemd 255, Landlock ABI 8, `unshare -rn` unavailable (AppArmor) ⇒ acceptance test 5 skipped here, `max_user_instances` nearly exhausted (one inotify instance only).

## Gotchas learned
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

## Module status (M1)
`paths config clock error api_error sandbox instance db/{mod,writer,reader,queries} discovery/{walk,dirfd,exclusions,mounts,status} auth/{tokens,bootstrap,sessions} service ipc/{protocol,server} client http/{mod,peer,middleware,extract,routes,assets,error} daemon cli synth bin/ccwm-synth` + `web/*` + `scripts/inspect-session-schema.py` + `deny.toml` + `SECURITY.md`. Not built yet: `watch activity git claude privacy` (M2/M3).

## Open items
See ARCHITECTURE.md §14 (O1–O4).
