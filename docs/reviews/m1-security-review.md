I didn't change any code or open `~/.claude`. Everything below comes from reading the M1 commit (`0b4d9ff`) against REQUIREMENTS §0/§2/§6/§11/§16/§19 and ARCHITECTURE. I ran only three read-only commands: `cargo tree --offline`, `git check-ignore` on a few paths, and `findmnt /proc`. I wrote no exploit and ran none, so each scenario below is reasoned from the code, not demonstrated.

There are no critical findings: two high, four medium and eight low, plus weak tests 1, 6, 7, 9 and 11. Both highs need a spec change (§11.2/§11.3), so they need your approval before anyone fixes them.

## High

**H1. Another local user can steal the sign-in link from the browser's command line and take a 30-day session** (`src/cli.rs:79`, `src/cli.rs:87-92`)
- **Scenario:** with a display, `ccwm open` passes `http://127.0.0.1:<port>/#bt=<token>` as an argument to `xdg-open`, and from there to the browser. Process command lines are readable by every user here: `/proc` is mounted without `hidepid`.
  - User B loops over `/proc/*/cmdline` looking for `bt=`, then posts the token to `/auth/exchange` with curl, setting `Origin: http://127.0.0.1:8765` by hand.
  - curl wins easily against a browser that still has to start, load `/` and `app.js`, and run the exchange.
  - B gets a 30-day sliding session. In M1 that exposes every project path; from M3 on, prompts.
  - Host and Origin checks don't help: they stop browsers, not curl. The spec's residual-risk list covers browser history, not argv.
- **Fix (needs a spec amendment):** check the TCP peer's UID on loopback.
  - On accept, find the client's socket in `/proc/net/tcp` (or via `NETLINK_SOCK_DIAG`) and reject it unless its UID equals the daemon's euid.
  - In axum 0.8 this can be a wrapper around the `Listener` the server accepts on. `/proc` is already in the Landlock read set.
  - This works across the whole TCP API, so any leaked token is useless from another UID.
  - Interim: document the risk and recommend mounting `/proc` with `hidepid=invisible`.

**H2. A port impostor can read the browser's stored session token** (`web/app.js:64`, `web/app.js:72-75`; threat named in §11.1)
- **Scenario:** user B binds 8765 while the daemon is down (for example at boot, before your user service starts). Your browser restores its `http://127.0.0.1:8765` tab and loads B's page, which is the same origin.
  - B's script reads `localStorage["ccwm.session"]` and gets a valid 30-day token, which B can use once the real daemon is back.
  - M1 defends only the CLI against this impostor, not the browser.
- **Fix:** the peer-UID check from H1 makes a stolen token unusable from another UID. The impostor can still show a fake UI; document that as a residual risk.

## Medium

**M1. The sandbox doesn't block local IPC or UDP** (`src/sandbox.rs:18`, `src/sandbox.rs:97-103`)
- The ruleset asks only for ABI V4 rights. It never requests the ABI 6 scopes for abstract Unix sockets and signals, although landlock 0.4.8 and this kernel (ABI 8) support them.
- V4 filesystem rights don't cover `connect()` on a path-based Unix socket. Verify that on this kernel; it is the documented upstream limitation.
- **Scenario:** in M2, code running in a `git` child (or in the daemon) connects to the session D-Bus at `$XDG_RUNTIME_DIR/bus` and asks `systemd --user` to start a transient unit. That unit runs outside Landlock, with full write access and network.
  - UDP (DNS, for example) isn't restricted either, yet the report still says `network: true`.
- **Fix:**
  - Add `.scope(Scope::AbstractUnixSocket | Scope::Signal)` in best-effort mode and report it.
  - Bind the TCP and Unix listeners before applying the sandbox. After that, a seccomp filter can deny `socket()` entirely; that needs a dependency justified in ARCHITECTURE §4.
  - Remove `DBUS_SESSION_BUS_ADDRESS` and similar variables from children's environments.
  - List UDP and Unix-socket connect as not confined in the report notes.
  - Add a probe to `tests/sandbox.rs` that tries a Unix socket connect outside the allowed directories.

**M2. `--config` silently widens what the daemon may read** (`src/daemon.rs:229`, `src/sandbox.rs:187`)
- The config file's parent directory is granted read and execute. `--config /c.toml` therefore grants all of `/`, which voids read confinement while the report still says `fully_enforced`. `/tmp/c.toml` grants `/tmp`.
- The config is read before the sandbox is applied, so the grant isn't needed.
- **Fix:** drop the rule. More generally, note in the report whenever a read path is `/` or an ancestor of the home directory.

**M3. Discovery can be tricked into following a symlink** (`src/discovery/walk.rs:246`, `264-283`, `321`)
- Subdirectories are classified with `entry.file_type()`, but later opened by path with `fs::read_dir(&frame.path)`, which follows symlinks.
- **Scenario:** another user who can write somewhere under a root (a shared or group-writable directory) swaps a subdirectory for a symlink between those two steps.
  - The walk then enters any directory the daemon can read and registers that path as `canonical_path`, although it was never canonicalized.
  - In M1 this only adds a fake project. In M2, git and the file watcher would act on a directory the attacker chose.
- **Fix:** walk by file descriptor. Open each child with `openat(parent_fd, name, O_DIRECTORY|O_NOFOLLOW)` (or `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`), read entries from that descriptor, and register only after `fstat` matches the device/inode seen earlier. Check markers the same way.

**M4. Nothing guards "Landlock before any thread"** (`src/sandbox.rs:95`, `src/daemon.rs:238-241`)
- The ordering is correct today: nothing spawns a thread before `apply`. But no check enforces it, and no test would notice a regression (see test 11 below).
- If `apply` ran after the Tokio runtime is built, the worker and blocking threads (where discovery and SQLite run) would be unconfined while the report still said `fully_enforced`.
- **Fix:**
  - In `apply`, check that `/proc/self/task` has exactly one entry, and report `not_enforced` otherwise.
  - After the runtime starts, run a read-only probe on a worker thread and on a blocking-pool thread (for example, reading a directory outside the read set and expecting permission denied). Put the result in `SandboxReport`.

## Low

- **L1. 24-hour rotation isn't enforced** (`src/auth/sessions.rs:300-323`): `rotate_after` is only a hint to the client. A copied token that is never rotated stays valid indefinitely on the sliding 30-day window. Possible fix: once rotation is overdue, accept the token only on `/auth/rotate`.
- **L2. Multiple tabs sign each other out** (`web/app.js:64`, `77-79`, `104-124`): each tab reads `localStorage` once at startup and never listens for `storage` events.
  - After the 60-second grace period, a stale tab gets a 401, and `clearSession()` deletes the shared key, which signs out every tab.
  - A second rotation within the grace period also ends the first old token's grace early.
  - This is availability, not a vulnerability.
- **L3. Sessions pile up** (`src/db/writer.rs:222`, `src/service.rs:140-145`): `purge_expired_sessions` has no caller, and every `ccwm open` creates a new 30-day session without revoking the previous one. The rows are hashes, but more tokens stay live than necessary.
- **L4. Ownership checks stop at the final directory** (`src/paths.rs` `verify_private`; `src/config.rs` `load`): parent directories of the XDG paths aren't checked, and the config file's owner and mode aren't checked. A group-writable `--config` file lets another user choose the discovery roots and port.
- **L5. No limits on TCP connections** (`src/http/mod.rs:87`): there is no connection cap and no header timeout. Another local user can use up the daemon's file descriptors, which also blocks the Unix socket, so the CLI can't even run `revoke_all`.
- **L6. The schema script can print data as key names** (`scripts/inspect-session-schema.py:32`, `104-111`, `129-131`): keys that look like identifiers are printed even when the object is keyed by data, such as server or project names. The leading tag name of a prompt that starts with `<word` is also printed. Possible fix: show keys as `<key>` when a parent has many distinct keys.
- **L7. The Claude config directory isn't excluded if it isn't hidden** (`src/paths.rs` `hard_boundaries`): a non-hidden `CLAUDE_CONFIG_DIR` inside a root isn't a hard boundary. Discovery walks it, and its own `CLAUDE.md` registers it as a project. §4 requires excluding `~/.claude`.
- **L8. Pagination breaks on non-ASCII names** (`src/service.rs:184` vs `src/db/queries.rs:65`): this is a correctness bug, not a security one. The cursor uses Rust's Unicode `to_lowercase()`, while SQLite's `lower()` only handles ASCII, so non-ASCII names can be skipped or repeated across pages.

## Weak or missing tests

- **Test 11 is weak.**
  - It never runs the daemon and builds its own `Policy` instead of using `daemon_policy()`, so M2 isn't caught.
  - It applies Landlock on libtest's per-test thread, so "before any thread" isn't tested, and M4 isn't caught.
  - The process-level evidence is `NoNewPrivs: 1` (`tests/process.rs:392`), which doesn't prove Landlock is active.
  - Child probes count any non-zero exit as "denied"; they should check for `EACCES`.
  - It passes silently when Landlock is unavailable. It should fail when, say, `CCWM_REQUIRE_LANDLOCK=1` is set.
  - The Git-subprocess half is deferred to M2, yet M1's acceptance says test 11 passes.
- **Test 7 is mostly empty.** The HTTP traversal test (`tests/http.rs:542`) can't fail, because no route reads the filesystem. The path inputs that do exist aren't covered: `--config` (M2), the XDG variables, `CLAUDE_CONFIG_DIR`, and the symlink-swap race (M3).
- **Test 9 is narrow.**
  - `instance.json.tmp` at the repo root isn't ignored; `write_instance` creates exactly that file.
  - The list of names is maintained by hand instead of being built from the constants in `paths.rs`.
  - It skips silently when git is absent.
  - A `ccwm-synth` directory created inside the repo leaves its `env` file and `CLAUDE.md` unignored.
- **Test 6 is solid but has gaps.** It covers both the in-process router and real sockets. Missing:
  - two concurrent rotations with the same token
  - logging out with an old token during its grace period
  - `revoke_all` during a grace period
  - a client from another UID over TCP (that can only be tested once H1/H2 are fixed)
- **Test 1 is good.** It records mode, mtime, ctime, inode and content. But the synthetic environment puts the XDG directories outside the home it walks. The real default (`~/.local/share/ccwm`) is inside the walked root, and that layout isn't exercised.
- **Log check (test "8-lite") runs only at `info` level.** It should also run with `CCWM_LOG=trace`.

## Checked and found sound

- **Headers:** security headers, the CSP, Host and Origin checks apply to every response class, including 404, 405, 421 and static assets. Only HTTP/1 is enabled, so there is no HTTP/2 `:authority` bypass.
- **Unix socket:** `SO_PEERCRED` is checked on both sides before any byte is read or sent. The CLI verifies the runtime directory, and a stale socket is removed only if it is a socket you own.
- **Tokens:**
  - Generated from 32 bytes from `getrandom` and stored as SHA-256 hashes, compared in constant time.
  - Bootstrap tokens are single-use. Rotation is atomic because there is a single database writer.
  - No token is logged.
- **Writes:** the code writes only to ccwm's own directories. Permissions are 0700/0600 with umask 077; the WAL/SHM file modes aren't asserted.
- **Dependencies:** `cargo tree` shows no HTTP or DNS client crates, and `hyper`/`hyper-util` have only server features. `cargo-deny` has still never been run.

Do you want this recorded in CLAUDE.md or ARCHITECTURE §14 as open items? Separately, H1 and H2 need your decision on adding the TCP peer-UID check to the spec. I can also turn this into a shareable page.
