# Security

CC Workspace Manager (`ccwm`) is an independent, unofficial project, not affiliated with Anthropic.
This file describes what ccwm defends against, how, and what it does **not** protect. It follows
`REQUIREMENTS.md` §11; where they differ, the requirements win. Nothing here is claimed beyond what
is enforced and tested (see `ROADMAP.md` for what has been run).

## Threat model

**In scope**
- Other local Linux users (reading or using ccwm's data, sign-in links or session tokens).
- Malicious websites: CSRF, cross-origin reads, DNS rebinding.
- Other localhost services, including ones on other ports.
- Another local user binding the ccwm port while the daemon is down, to impersonate it.
- Malicious project files, `CLAUDE.md` content, session content and Git configuration.

**Out of scope**
- Malicious processes running as the **same** Linux user (they can read ccwm's data directly).
- A compromised OS or kernel; root or other privileged attackers.

## Protections

**CLI ↔ daemon.** A Unix socket in a `0700` runtime directory; both sides verify the peer UID with
`SO_PEERCRED` before sending anything. The CLI never sends credentials over TCP and never trusts a
TCP `/health` answer as identity.

**Browser sign-in.** `ccwm open` obtains a random, single-use bootstrap token (valid **30 s**) over the
Unix socket and opens `http://127.0.0.1:<port>/#bt=<token>`. The page removes the fragment
immediately and exchanges it for a 32-byte session token (stored hashed with SHA-256, compared in
constant time, sliding 30-day expiry). Rotation is **enforced**: after 24 h (+60 s slack) a token is
accepted only by `POST /api/v1/auth/rotate`; the previous token stays valid for 60 s. At most 10
browser sessions are live; an 11th revokes the least recently used. Expired sessions are purged
hourly. "Sign out" and `ccwm auth revoke-all` revoke sessions.

**TCP peer-UID check.** For every accepted loopback connection the daemon finds the client's end of
the connection in `/proc/net/tcp` / `/proc/net/tcp6` and serves it only if the socket belongs to the
daemon's effective UID. The check happens before a byte is read, applies to every endpoint (including
`/health` and static files), is cached per connection and fails closed. Consequence: a sign-in link
or session token that leaks to another local user (for example through a browser's command line in
`/proc/<pid>/cmdline`) is useless to them.

**HTTP hardening.** Bound to `127.0.0.1` only; `Host` must be `127.0.0.1`, `localhost` or `[::1]` with
the port; any `/api` request with a foreign `Origin` is rejected, and state-changing requests need
the exact `http://127.0.0.1:<port>` origin; strict CSP, `nosniff`, `no-referrer`, COOP,
`Cache-Control: no-store`. At most 64 concurrent connections (excess clients wait in the kernel
backlog), 10 s header-read timeout; the Unix socket stays usable under TCP load.

**Files.** ccwm's directories are `0700`, files `0600`, umask `0077`. ccwm refuses to start if any
ancestor of its directories, or the config file, could be modified by another user (allowed: owned
by you or root; root-owned sticky directories such as `/tmp`; group write only by your private
group). Discovery opens every directory by descriptor relative to its parent and checks its
`(device, inode)`, so a directory swapped for a symlink mid-walk is skipped, never followed; a
symlinked `CLAUDE.md` must resolve beneath its directory (`openat2(RESOLVE_BENEATH)`). ccwm's own
directories and Claude Code's config directory are never walked.

**Landlock (best effort, reported).** Applied on the main thread while the process is single-threaded
(verified via `/proc/self/task`, else reported `not_enforced`), then verified from a runtime worker
thread and a blocking-pool thread. Reads only under the discovery roots, the Claude config directory
and system paths; writes only under ccwm's directories; TCP `connect` denied and `bind` limited to the
configured port (ABI ≥ 4); abstract Unix sockets and signals scoped (ABI ≥ 6). The active set is in
the startup log and `GET /api/v1/service/status` (`sandbox`), including read rules that are `/` or an
ancestor of your home directory. Child processes (`git`, `claude`) inherit the ruleset and get an
environment without `DBUS_*`, `XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK` and similar IPC variables.

**WebSocket.** `GET /api/v1/ws` requires the exact `Origin`; the first message must authenticate
(`{"type":"auth","token":…}`) within 5 s, otherwise the socket is closed with code 4401 and nothing
is sent. The token is checked again whenever sessions are revoked (sign-out, `ccwm auth revoke-all`,
the hourly purge) and every 10 s, so a socket whose token expired, was rotated out (after its 60 s
grace) or is overdue for rotation is closed with 4401.

**Git (REQUIREMENTS.md §6).** Only allowlisted read commands run: `--version`, `rev-parse`,
`config --get-regexp` (filter drivers) / `config --get`, `status --porcelain=v2`, `log -1`. Each runs
without a shell, with an empty environment plus `PATH`, `HOME`, `LC_ALL=C`, `GIT_TERMINAL_PROMPT=0`,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_OPTIONAL_LOCKS=0`, a 5 s timeout that kills the whole process group,
at most 4 at a time, and the flags `--no-pager --no-optional-locks -c core.fsmonitor=false
-c core.untrackedCache=false -c core.hooksPath=/dev/null -c protocol.allow=never`. These flags are
mitigations, **not a sandbox**; the Landlock ruleset (no writes, no TCP connect) also applies to
every Git process. What was investigated, with a sentinel test for each vector Git can reach
(`tests/git.rs`, each with a control run proving the vector executes without the mitigation):

| Repository-controlled configuration | Reached by our commands? | Mitigation |
|---|---|---|
| `core.fsmonitor` | yes (`status`) | `-c core.fsmonitor=false` |
| clean/smudge/process filters via `.gitattributes`, `.git/info/attributes`, global attributes | yes (`status` re-hashing stat-dirty files) | `--attr-source=<empty tree>` **and** nulling every filter driver of every scope (`-c filter.<name>.clean= …`) |
| a filter driver whose name contains `=` (cannot be expressed with `-c`) | yes | worktree status is **not run** for that repository (`status_disabled_unsafe_config`, fail closed) |
| `include.path` / `includeIf` pulling in any of these | yes | the same overrides (`-c` wins over included files; drivers are enumerated with includes resolved) |
| `log.showSignature` + `gpg.program` (signature verification runs a program) | yes (`log -1`) | `--no-show-signature` |
| `core.pager`, `pager.<cmd>` | no (no terminal) | `--no-pager` anyway |
| `diff.external`, textconv drivers | no (no diff is produced) | — (asserted not executed) |
| `core.sshCommand`, credential helpers, `core.askPass` | no (no network command) | `protocol.allow=never`; Landlock denies TCP connect |
| hooks | no (`status` runs none) | `core.hooksPath=/dev/null` |
| `trace2.*Target` | not from repository config (Git reads trace2 settings only from system/global config and the environment) | the environment is empty; system config is not read |
| `core.worktree` pointing elsewhere | reads only; Landlock limits what can be read | — |

With Git older than 2.41.0 (no `--attr-source`), worktree status is disabled unless you opt in with
`git.allow_unhardened_status = true`. A repository Git refuses (`safe.directory`, dubious ownership)
is reported, never overridden. Remote URLs are stored and shown without credentials (userinfo,
query and fragment removed). Consequence of the filter rules: repositories whose status depends on
filters or attributes (git-lfs, `text`/`eol` normalisation) can show a different status than your
own `git status`.

**Monitoring.** One inotify instance with non-recursive watches on eligible directories only;
symlinks are never followed (`IN_DONT_FOLLOW`, `IN_ONLYDIR`). File contents read by monitoring:
`.gitignore` files and `.git/info/exclude` (bounded, through the parent directory's descriptor), to
evaluate ignore rules in-process; ccwm never runs `git check-ignore`. ccwm's own directories are
never watched, so its writes never count as activity.

**Dependencies.** `cargo-deny` bans HTTP/TLS client and DNS resolver crates (`deny.toml`). Note:
axum's WebSocket support enables the `connect` feature of `tokio-tungstenite` (a WebSocket *client*
entry point). ccwm never calls it, it adds no crate to the tree, and Landlock denies TCP connect.

## Residual risks

- **Impostor UI.** Another user who binds the port while ccwm is down can serve a fake page on the same
  origin. It can read what the page stored (the session token) but cannot use it (peer-UID check),
  and `ccwm open` never talks to it. It can still show you false information. Prefer starting ccwm
  at login (systemd user unit, M4).
- **Same-user forwarders and proxies.** Any forwarder or proxy running as you (`ssh -L`, `socat`,
  an IDE's port forwarding) bypasses the peer-UID check: the check sees the forwarder, which is
  you, not the client behind it, so another local user who can reach the forwarder's port can use
  a leaked sign-in link or session token through it. **Never forward the ccwm port.**
- **Not confined by the sandbox:** UDP and other non-TCP socket families, and `connect()` to
  path-based Unix sockets (no Landlock right for it before ABI 9; ccwm does not request it in v0.1).
  A seccomp `socket()` filter is planned for M4.
- **XSS** could read the `localStorage` token; mitigated by the strict CSP and the rule that no data
  ever reaches HTML-parsing DOM APIs.
- **Same-user processes** can read everything ccwm can.
- The single-use **bootstrap fragment** briefly exists in browser history (it expires in 30 s).
- **Watch registration by path.** Directories are listed through descriptors, but inotify watches
  are added by path (the `notify` crate has no descriptor interface). A directory swapped for
  another between the walk and the watch can make ccwm watch the wrong directory: events only,
  nothing is read or written, and symlinks are never followed.
- Tests catch regressions; they cannot prove the absence of network activity. Security acceptance
  test 5 traces every `connect()` of the daemon and its Git processes with `strace` (and runs them
  in a network namespace where unprivileged user namespaces are allowed).

## Optional defense in depth

- Mount `/proc` with `hidepid=invisible` (e.g. `proc /proc proc defaults,hidepid=invisible 0 0` in
  `/etc/fstab`, needs root) so other users cannot see process command lines. ccwm does not depend on
  it; it only removes the place where a sign-in link would be visible.

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately (the contact will be published
with the first release; until then, use the repository's private security advisory feature once the
repository is public).
