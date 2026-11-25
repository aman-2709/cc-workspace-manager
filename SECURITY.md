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
grace) or is overdue for rotation is closed with 4401. Revalidation is a normal authenticated use of
the session, so an open tab slides the session's 30-day expiry forward (intended); it cannot keep a
token alive past the 24 h rotation rule, because an overdue token fails revalidation.

**Git (REQUIREMENTS.md §6).** Only allowlisted read commands run: `--version`, `rev-parse`,
`config --get-regexp` (filter drivers; promisor remotes after a failed `status`) / `config --get`,
`status --porcelain=v2`, `log -1`. Each runs without a shell, with an empty environment plus `PATH`,
`HOME`, `LC_ALL=C`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_OPTIONAL_LOCKS=0`,
`GIT_ALLOW_PROTOCOL=` (empty) and `GIT_NO_LAZY_FETCH=1`, a 5 s timeout that kills the whole process
group, at most 4 at a time, and the flags `--no-pager --no-optional-locks -c core.fsmonitor=false
-c core.untrackedCache=false -c core.hooksPath=/dev/null -c protocol.allow=never` plus
`-c protocol.<name>.allow=never` for `ext`, `ssh`, `file`, `git`, `http` and `https`. These flags
are mitigations, **not a sandbox**, and not the only line of defense: the Landlock ruleset (no
writes, no TCP connect) also applies to every Git process, but the Git hardening must hold on its
own where Landlock is absent or partial. What was investigated, with a sentinel test for each vector
Git can reach (`tests/git.rs`, each with a control run, using a command ccwm runs, proving the
vector executes without the mitigation):

| Repository-controlled configuration | Reached by our commands? | Mitigation |
|---|---|---|
| `core.fsmonitor` | yes (`status`) | `-c core.fsmonitor=false` |
| clean/smudge/process filters via `.gitattributes`, `.git/info/attributes`, global attributes | yes (`status` re-hashing stat-dirty files) | `--attr-source=<empty tree>` **and** nulling every filter driver of every scope (`-c filter.<name>.clean= …`) |
| a filter driver whose name contains `=` (cannot be expressed with `-c`) | yes | worktree status is **not run** for that repository (`status_disabled_unsafe_config`, fail closed) |
| `include.path` / `includeIf` pulling in any of these | yes | the same overrides (`-c` wins over included files; drivers are enumerated with includes resolved) |
| `log.showSignature` + `gpg.program` (signature verification runs a program) | yes (`log -1`) | `--no-show-signature` |
| `core.pager`, `pager.<cmd>` | no (no terminal) | `--no-pager` anyway |
| `diff.external`, textconv drivers | no (no diff is produced) | — (asserted not executed) |
| **Promisor partial clone, lazy fetch** (M2 review H1): with an object missing, `status` and `log -1` start `git fetch` on their own, which runs the repository's transport: an `ext::` command, `remote.<name>.uploadpack` (`file://`) or `core.sshCommand` (`ssh://`). A per-protocol `protocol.<name>.allow=always` in the repository's config overrides a generic `protocol.allow=never` | yes (`status`, `log -1`) | three blocks, each sufficient alone (tested): `GIT_ALLOW_PROTOCOL=` (empty: no transport, remote helpers included; overrides all config), `-c protocol.<name>.allow=never` (outranks the repository's per-protocol value), and `GIT_NO_LAZY_FETCH=1` (no fetch child at all; Git 2.45.0+ and builds with the CVE-2024-32465 fix such as Ubuntu `1:2.43.0-1ubuntu7.1`+, ignored by older Git). The repository shows "Git status unavailable (partial clone)" |
| `core.sshCommand`, credential helpers, `core.askPass` | only through a transport, i.e. the lazy fetch above (blocked there) | transport blocks above; Landlock denies TCP connect |
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
symlinks are never followed (`IN_DONT_FOLLOW`). The `notify` crate asks for `IN_ONLYDIR` but, on
`ENOTDIR`, silently retries without it; ccwm therefore checks after every watch that the path is
still a real directory and drops the watch otherwise (tested with a regular file and a symlink). File contents read by monitoring:
`.gitignore` files and `.git/info/exclude` (bounded, through the parent directory's descriptor), to
evaluate ignore rules in-process; ccwm never runs `git check-ignore`. ccwm's own directories are
never watched, so its writes never count as activity.

**Claude Code sessions (M3).** ccwm only reads Claude Code's session directory (`$CLAUDE_CONFIG_DIR` or
`~/.claude`, `projects/*/<uuid>.jsonl`), never writes it; directories are listed by descriptor and files opened
with `O_NOFOLLOW`. The parser declares only the fields it needs (REQUIREMENTS.md §7.1): tool results, API
payloads, tool inputs, attachment bodies, queue contents and account/organization ids are skipped by the JSON
parser without being materialized. ccwm stores aggregates only (times, first/last cwd, title, branch, version,
continuation links); prompt text is read from the session file when you open a project's details (a bounded
4 MiB window), redacted, cut to 2,000 characters and not stored — unless you turn on "Store prompt text", which
caches the redacted last prompt in ccwm's database. Turning it off first forbids caching inside the database
writer (so a prompt read still in flight cannot be stored afterwards), then deletes the cache. Deletions of
session data (turning the setting off, "Clear session index") overwrite the deleted content (`secure_delete`) and
checkpoint and truncate the write-ahead log, so the text does not linger in free pages or old WAL frames. Backups
or snapshots of the data directory taken earlier are outside ccwm's control. Session text is never logged and
never rendered as HTML. The branch, Claude Code version and entrypoint are stored without control characters and
cut to 256 characters; a cwd longer than 4,096 bytes is ignored. A session whose cwd can never name a project
(excluded, outside the roots, home, a temporary directory) is read only up to that cwd.

**Redaction is best effort.** Titles and prompts are scanned for PEM and PGP private key blocks, GitHub tokens
(`ghp_`, `gho_`, `github_pat_`…), GitLab (`glpat-`) and npm (`npm_`) tokens, Google API keys (`AIza…`), `sk-…` API
keys, Stripe-style `sk_live_`/`sk_test_`/`rk_…` keys, AWS access key ids, Slack tokens, JSON Web Tokens,
`Bearer …`, HTTP Basic credentials (after `Authorization:`, or a bare `Basic <base64>` that contains a digit,
`+`, `/` or `=`), credentials in URLs, and assignments whose key **ends** in `password`, `passwd`, `pwd`, `secret`,
`token`, `api_key`/`apikey`, `access_key` or `private_key` — `DB_PASSWORD=…`, `aws_secret_access_key = …`,
`client_secret: …` and JSON/YAML-quoted keys such as `"password": "…"`. An AWS *secret* key is recognised only
through such an assignment (it has no prefix of its own). Other formats — a bare high-entropy string, a secret
under an unusual key name, a secret split across lines — are **not** recognised; treat what ccwm shows as
sensitive. **Session cwds are not redacted** (a redacted path would break the resume command); privacy mode hides
them.

**Privacy mode** is enforced by the server: the browser never receives the hidden fields (paths, user names,
remote URLs, session titles, prompts, cwds, resume commands, and the paths in the status and Settings payloads,
including the responses to ignore/un-ignore and to saving the settings), for REST and WebSocket alike. It hides information from people looking at your screen; it is not access control.

**Resume commands** are built from the session's first recorded cwd (POSIX single-quoted) and a strictly
validated UUID, and are only shown for copying; ccwm never runs them. Running one starts Claude Code, which is
outside ccwm's guarantees. Quoting protects against the shell *parser* only; a pasted command reaches the
terminal's line editor first, which acts on control characters (Ctrl-U, newline, the bracketed-paste end marker
`ESC[201~`). A cwd containing any C0/C1 control character, DEL or a Unicode bidi/format character therefore gets
**no command** (warning `cwd_unsafe_characters`; the path is shown escaped). A pty test pastes every command ccwm
generates into an interactive `bash` and checks that nothing runs. A `continued-in` link is followed only to a
session of the same project, so a planted session file cannot redirect the resume into another project or an
unassigned folder. **The `claude` CLI check** runs `claude --version` and `claude --help` (5 s each, once
per binary version) as children of the sandboxed daemon: no TCP connect, no writes outside ccwm's directories;
UDP and path-based Unix sockets are not confined (see below). ccwm sets `DISABLE_AUTOUPDATER`,
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and `DISABLE_TELEMETRY` for these two calls as a best-effort request;
their effect is Claude Code's, not verified by ccwm. Security acceptance test 5 allows exactly these two `claude`
invocations. **Without Landlock** (an older kernel, or a report that is not `fully_enforced`) these two calls run
the real `claude` binary **unconfined**, with your rights; the tests use a fake `claude`, so side effects of the
real binary (for example on `~/.claude`) are not covered by them.

**Settings.** `PUT /settings` (session token + allowed Origin) rewrites the configuration file atomically with
mode 0600; it can change discovery roots, so it is as sensitive as the file itself. Roots added there are read only
after a restart (the sandbox's read set is fixed at startup). It accepts **only the keys of the Settings page**
(REQUIREMENTS.md §9); everything else — `git.allow_unhardened_status`, `watch.debounce_ms`,
`activity.events_per_project` — changes only by editing `config.toml`, so a stolen browser token cannot weaken the
hardening persistently. It also refuses port 0 and a session directory that is `/` or contains your home folder.
Saves are serialized from merge to apply, and the page sends only the fields you changed, so a stale Settings tab
cannot revert a change made elsewhere.

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
- **Watch registration by path** (M2 review L2). Directories are listed through descriptors, but
  inotify watches are added by path (the `notify` crate has no descriptor interface). A directory
  swapped for another real directory between the walk and the watch can make ccwm watch the wrong
  directory and attribute its events to the project: events only, nothing is read or written,
  symlinks are never followed, and a swap to a regular file is caught by the directory check.
- **Move matching is not identity** (M2 review L1). A new project is taken as a moved missing
  project when its Git HEAD and remote (or its `CLAUDE.md` hash) match; all of these are content
  anyone who can write in a discovery root controls, so in a shared or group-writable root another
  user could make a directory inherit a missing project's id, history and ignore state.
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
