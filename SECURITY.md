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

**Dependencies.** `cargo-deny` bans HTTP/TLS client and DNS resolver crates (`deny.toml`).

## Residual risks

- **Impostor UI.** Another user who binds the port while ccwm is down can serve a fake page on the same
  origin. It can read what the page stored (the session token) but cannot use it (peer-UID check),
  and `ccwm open` never talks to it. It can still show you false information. Prefer starting ccwm
  at login (systemd user unit, M4).
- **Not confined by the sandbox:** UDP and other non-TCP socket families, and `connect()` to
  path-based Unix sockets (no Landlock right for it before ABI 9; ccwm does not request it in v0.1).
  A seccomp `socket()` filter is planned for M4.
- **XSS** could read the `localStorage` token; mitigated by the strict CSP and the rule that no data
  ever reaches HTML-parsing DOM APIs.
- **Same-user processes** can read everything ccwm can.
- The single-use **bootstrap fragment** briefly exists in browser history (it expires in 30 s).
- Tests catch regressions; they cannot prove the absence of network activity.

## Optional defense in depth

- Mount `/proc` with `hidepid=invisible` (e.g. `proc /proc proc defaults,hidepid=invisible 0 0` in
  `/etc/fstab`, needs root) so other users cannot see process command lines. ccwm does not depend on
  it; it only removes the place where a sign-in link would be visible.

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately (the contact will be published
with the first release; until then, use the repository's private security advisory feature once the
repository is public).
