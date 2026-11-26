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

**TCP peer-UID check.** For every accepted loopback connection the daemon finds the socket of the
client's end of the connection and serves it only if that socket belongs to the daemon's effective UID.
It asks the kernel with one exact `sock_diag` netlink request for the client's 4-tuple (M4). The reply
must name exactly that 4-tuple, in a state other than `LISTEN` or `TIME_WAIT`. Where `sock_diag` does not
work, a self-test at startup falls back to the `/proc/net/tcp` / `/proc/net/tcp6` row. The method in use
is reported as `peer_lookup` in `ccwm status` / `ccwm doctor`. The check happens before a byte is read,
applies to every endpoint (including `/health` and static files), is cached per connection and fails
closed: not found, ambiguous, or an error all mean "reject". Consequence: a sign-in link
or session token that leaks to another local user (for example through a browser's command line in
`/proc/<pid>/cmdline`) is useless to them.

**HTTP hardening.** Bound to `127.0.0.1` only; `Host` must be `127.0.0.1`, `localhost` or `[::1]` with
the port; any `/api` request with a foreign `Origin` is rejected, and state-changing requests need
the exact `http://127.0.0.1:<port>` origin; strict CSP (no inline script or style, no `eval`,
`worker-src 'none'`), `nosniff`, `no-referrer`, COOP, `Cache-Control: no-store`. These headers are on
every response the router produces; the bare `400` that the HTTP library itself sends for an unparsable
request line has no body and no headers. At most 64 concurrent connections (excess clients wait in the
kernel backlog); a client has 10 s to send a request head and 10 s more to send the body (`408`
otherwise, and the connection is closed); the Unix socket stays usable under TCP load.

**Files.** ccwm's directories are `0700`, files `0600`, umask `0077`. ccwm refuses to start if any
ancestor of its directories, or the config file, could be modified by another user (allowed: owned
by you or root; root-owned sticky directories such as `/tmp`; group write only by your private
group). This check reads owner and mode bits only: see "POSIX ACLs" under the residual risks.
Discovery opens every directory by descriptor relative to its parent and checks its
`(device, inode)`, so a directory swapped for a symlink mid-walk is skipped, never followed; a
symlinked `CLAUDE.md` must resolve beneath its directory (`openat2(RESOLVE_BENEATH)`). ccwm's own
directories and Claude Code's config directory are never walked or watched, under their configured
and their canonical paths (so not through a symlinked XDG directory that resolves into a project
either); the home directory is used in its canonical form everywhere.

**Landlock (best effort, reported).** Applied on the main thread while the process is single-threaded
(verified via `/proc/self/task`, else reported `not_enforced`), then verified from a runtime worker
thread and a blocking-pool thread. Reads only under the discovery roots, the Claude config directory
and system paths; writes only under ccwm's directories; TCP `connect` denied and `bind` limited to the
configured port (ABI ≥ 4); abstract Unix sockets and signals scoped (ABI ≥ 6). The active set is in
the startup log and `GET /api/v1/service/status` (`sandbox`), including read rules that are `/` or an
ancestor of your home directory. Child processes (`git`, `claude`) inherit the ruleset and get an
environment without `DBUS_*`, `XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK` and similar IPC variables.

**Seccomp socket filter (M4).** Once the TCP and Unix listeners are bound, the daemon installs a seccomp
filter on **every** thread (TSYNC). Threads and child processes created later inherit it. From then on
`socket()` and `socketpair()` fail with `EPERM` for **every** address family, with no exception: the one
`NETLINK_SOCK_DIAG` socket the peer check needs is opened before the filter and reused, and so is the
runtime's signal pipe. `io_uring` is denied too, because it can create sockets without `socket()`, and
so are the x32 entry points of `socket`, `socketpair` and `io_uring_setup`. The daemon and its Git and
`claude` children therefore cannot open UDP sockets, nor connect or send to path-based Unix sockets
(D-Bus, agents, the syslog socket): the two gaps Landlock ABI ≤ 8 leaves. A datagram socket pair, which
needs no `socket()`, was such a way out until it was closed (v0.1.0 review M1; tested with a control
run). Accepting connections on the existing listeners is unaffected. The filter uses `seccompiler`
(rust-vmm), and works without Landlock.

**Self-verification (M4).** The daemon checks its own confinement and claims only what it verified:

- Landlock: a read outside the read set, from a runtime worker thread and a blocking-pool thread.
- A write outside ccwm's directories: an anonymous `O_TMPFILE` in your home directory, so an
  unconfined probe leaves nothing behind.
- An outbound TCP connect to `127.0.0.1:1`.
- After the filter: creating a UDP socket, a Unix socket and a Unix socket pair, from a worker thread
  and a blocking-pool thread.

A read or write probe that is not denied withdraws every Landlock claim. A connect that is not denied
withdraws the TCP claim. A socket probe that is not denied withdraws the seccomp claim. A probe that
fails for an **unexpected** reason (e.g. a home directory on a file system without `O_TMPFILE`) proves
nothing either way: that protection is reported as **`unverified`**, neither claimed nor withdrawn. It
is listed under `unverified` (not under `unconfined`) in the report, shown as `unverified` by
`ccwm status` and `ccwm doctor` (which then warns), and logged as a warning at startup.
Everything is in the `sandbox` section of `/api/v1/service/status` and in `ccwm doctor`.

**systemd unit.** The user unit adds `NoNewPrivileges`, `UMask=0077`, `LockPersonality`,
`RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces` and `SystemCallArchitectures=native`, and a
memory limit for the daemon and its children together: `MemoryMax=2G` with `MemorySwapMax=0` (v0.1.1; see
"Ignore rules cost memory" under the residual risks for what it is sized for). These directives were
verified with the real daemon in a user unit. `ProtectSystem`, `ProtectHome` and
`PrivateTmp` are not used: in a user unit they need a user namespace, in which root-owned paths appear to
be owned by `nobody`, and ccwm's ownership checks then (correctly) refuse to start. See
[docs/service.md](docs/service.md).

**WebSocket.** `GET /api/v1/ws` requires the exact `Origin`; the first message must authenticate
(`{"type":"auth","token":…}`) within 5 s, otherwise the socket is closed with code 4401 and nothing
is sent. The token is checked again whenever sessions are revoked (sign-out, `ccwm auth revoke-all`,
the hourly purge) and every 10 s, so a socket whose token expired, was rotated out (after its 60 s
grace) or is overdue for rotation is closed with 4401. Revalidation is a normal authenticated use of
the session, so an open tab slides the session's 30-day expiry forward (intended); it cannot keep a
token alive past the 24 h rotation rule, because an overdue token fails revalidation. A revocation is
acted on before any event that is waiting at the same moment, and a client that does not take a message
within 5 s is disconnected: a client that stops reading cannot hold its socket open past a revocation
(v0.1.0 review I3).

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
| a filter driver whose name `-c` cannot carry back **byte for byte**: not valid UTF-8 (v0.1.0 review H1: a lossy conversion built the override for another name and the real driver ran), containing `=` (Git splits `-c` at the first `=`) or a control character, or empty | yes | worktree status is **not run** for that repository (`status_disabled_unsafe_config`, fail closed). The rule: when a name cannot be represented exactly, refuse; never approximate. Tested with driver names of arbitrary bytes, each with a control run |
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
is reported, never overridden. Remote URLs are stored and shown without credentials: userinfo is
removed, also in the scp-like form (`user:password@host:path`) and when a password holds an unescaped
`/`; a `scheme://` URL also loses its query and fragment. When it is unclear whether the text before an
`@` is a password, it is dropped. Consequence of the filter rules: repositories whose status depends on
filters or attributes (git-lfs, `text`/`eol` normalisation) can show a different status than your
own `git status`.

**Monitoring.** One inotify instance with non-recursive watches on eligible directories only;
symlinks are never followed (`IN_DONT_FOLLOW`). The `notify` crate asks for `IN_ONLYDIR` but, on
`ENOTDIR`, silently retries without it; ccwm therefore checks after every watch that the path is
still a real directory and drops the watch otherwise (tested with a regular file and a symlink). File contents read by monitoring:
`.gitignore` files and `.git/info/exclude` (through the parent directory's descriptor), to
evaluate ignore rules in-process; ccwm never runs `git check-ignore`. These reads are bounded per file
per project and across projects: at most 256 KiB per file, 1 MiB and 5,000 rules for all ignore files of
one project, and 20,000 rules for all projects together (v0.1.1). A file over a limit is skipped whole
(never read in part), counted, and reported in the monitoring status and `ccwm status`; its rules then do
not apply. The limits exist because compiled rules stay in memory: a hostile repository with many large
`.gitignore` files took the daemon to hundreds of megabytes (v0.1.0 review M2), and a directory tree also
chooses how many projects it holds. The limit across projects goes to the most recently active
projects; the least recently active ones are the ones that lose their rules, whatever order the
projects were found in. The compiled rules of a file are kept and reused until the file changes (its
device, inode, size, modification time or change time), so a scan compiles nothing for files that are as they were. The repository whose rules apply is searched no higher than the project's
discovery root, and its `.git` must be owned by you, as Git itself requires. ccwm's own directories are
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
checkpoint and truncate the write-ahead log, so the text does not linger in free pages or old WAL frames. If a
reader is still using the log at that moment the truncation cannot happen: that is logged, and it is tried again
after every later write until it succeeds (v0.1.0 review I7; before, the result was not looked at). Backups
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
including the responses to ignore/un-ignore and to saving the settings), for REST and WebSocket alike. The
sandbox notes of the service status can name paths too (the broad read rules, a rule that could not be added):
in privacy mode only their number is sent, and a settings save that fails does not name the configuration file.
It hides information from people looking at your screen; it is not access control.

**Resume commands** are built from the session's first recorded cwd (POSIX single-quoted) and a strictly
validated UUID, and are only shown for copying; ccwm never runs them. Running one starts Claude Code, which is
outside ccwm's guarantees. Quoting protects against the shell *parser* only; a pasted command reaches the
terminal's line editor first, which acts on control characters (Ctrl-U, newline, the bracketed-paste end marker
`ESC[201~`). A cwd containing any C0/C1 control character, DEL or a Unicode bidi/format character therefore gets
**no command** (warning `cwd_unsafe_characters`; the path is shown escaped). A pty test pastes every command ccwm
generates into an interactive `bash` and checks that nothing runs. A `continued-in` link is followed only to a
session of the same project, so a planted session file cannot redirect the resume into another project or an
unassigned folder. **The `claude` CLI check** runs `claude --version` and `claude --help` (5 s each, once
per binary version) as children of the sandboxed daemon: no TCP connect, no writes outside ccwm's directories,
and, under the seccomp filter, no new socket or socket pair of any kind (so no UDP and no path-based Unix
socket). Unlike Git, which gets an empty environment, these two calls inherit the daemon's environment without
the session-IPC variables (they need `PATH` and `HOME`). ccwm sets `DISABLE_AUTOUPDATER`,
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and `DISABLE_TELEMETRY` for these two calls as a best-effort request;
their effect is Claude Code's, not verified by ccwm. Security acceptance test 5 allows exactly these two `claude`
invocations. **Without Landlock** (an older kernel, or a report that is not `fully_enforced`) these two calls run
the real `claude` binary without the filesystem and TCP confinement, with your rights; the tests use a fake
`claude`, so side effects of the real binary (for example on `~/.claude`) are not covered by them, and neither is
the real binary's behaviour under the seccomp filter: if it needs a socket or a socket pair to print its version,
the check reports `failed` and the resume command shows a warning.

**Settings.** `PUT /settings` (session token + allowed Origin) rewrites the configuration file atomically with
mode 0600; it can change discovery roots, so it is as sensitive as the file itself. Roots added there are read only
after a restart (the sandbox's read set is fixed at startup). It accepts **only the keys of the Settings page**
(REQUIREMENTS.md §9); everything else — `git.allow_unhardened_status`, `watch.debounce_ms`,
`activity.events_per_project` — changes only by editing `config.toml`, so a stolen browser token cannot weaken the
hardening persistently. It also refuses port 0; a session directory that is `/`, your home folder, or a folder
that contains it; and a discovery root that is `/` or a folder that contains your home folder (v0.1.0 review I6;
symlinks are resolved before the check). Your home folder itself stays a valid root. A broader root can still be
written into `config.toml` by hand; the sandbox report then lists it as a broad read rule.
Saves are serialized from merge to apply, and the page sends only the fields you changed, so a stale Settings tab
cannot revert a change made elsewhere.

**Dependencies.** `cargo-deny` bans HTTP/TLS client and DNS resolver crates (`deny.toml`). Note:
axum's WebSocket support enables the `connect` feature of `tokio-tungstenite` (a WebSocket *client*
entry point). ccwm never calls it, it adds no crate to the tree, and Landlock denies TCP connect.

## Residual risks

- **Impostor on the port: a persistent script in the dashboard's origin** (v0.1.0 review M3). Another
  local user who binds the port while ccwm is not running — before the service starts, between a stop
  and a start, after a crash, or for as long as they like (the daemon then exits with code 10 and systemd
  does not retry) — serves whatever they want on the origin `http://127.0.0.1:<port>`. The peer-UID check
  makes a token they obtain useless **to their own connections**, and `ccwm open` never talks to them.
  But what they store in your browser for that origin outlives them: HTTP-cache entries with a lifetime
  they choose (a poisoned `/` or `/app.js`), a service-worker registration, `localStorage`. Once the real
  daemon is back, such a script runs in **your** browser, whose connections pass the peer-UID check, next
  to your session or your next sign-in link. That is the XSS residual below — read what the dashboard
  shows, call the state-changing API, and send it elsewhere, since the impostor's page is not bound by
  ccwm's CSP — reached without any bug in ccwm's page, and it lasts until the site data of that origin is
  cleared. It is more than "false information". What ccwm does: its own page can never register a worker
  (`worker-src 'none'`), and the daemon's exit code 10 ("port … is already in use") tells you that
  another process holds the port. What you should do:
  run ccwm as the systemd user service ([docs/service.md](docs/service.md)) so that it holds the port
  from login on (before login, only lingering closes the window); and if the port was ever held by a
  process that is not yours, **clear the site data of `http://127.0.0.1:<port>` in your browser before
  you sign in again**, or move ccwm to another port (another port is another origin).
  **`Clear-Site-Data` was evaluated and is not sent.** `Clear-Site-Data: "cache", "storage"` on the
  sign-in exchange would have to work in the browsers people use, in exactly the hostile case. According
  to MDN's browser-compat data (read on 2026-11-25), Chrome's `"cache"` directive is only partial —
  entries can still be served from the cache until the tab is reloaded, and the header can stall the
  response for seconds — and Firefox had no `"cache"` directive from version 94 to 137. The header would
  also arrive with the answer to a request the page itself makes: a poisoned page or service worker has
  already run with the sign-in link by then, so the header could shorten the persistence at best, and
  whether both browsers honour it on a response fetched by a service worker was not verified (no test
  with real browsers was run). `"storage"` would in addition erase the dashboard's own preferences at
  every sign-in.
- **Same-user forwarders and proxies.** Any forwarder or proxy running as you (`ssh -L`, `socat`,
  an IDE's port forwarding) bypasses the peer-UID check: the check sees the forwarder, which is
  you, not the client behind it, so another local user who can reach the forwarder's port can use
  a leaked sign-in link or session token through it. **Never forward the ccwm port.**
- **Sockets when the seccomp filter is not active.** Landlock does not confine UDP or other non-TCP
  socket families, nor `connect()`/`sendto()` to path-based Unix sockets (no Landlock right for it before
  ABI 9). The seccomp filter closes both (no `socket()`, no `socketpair()`), and the report lists them as
  `unconfined` whenever it is `not_applied`, or as `unverified` when its probes were inconclusive. With
  the filter, the daemon can still use the sockets it already has: its listeners, the connections it
  accepted, the journald stream systemd gave it as stdout/stderr, the runtime's signal pipe, and the one
  `NETLINK_SOCK_DIAG` socket of the peer check, which tells it what `/proc/net/tcp` already does. It
  cannot create another.
- **Kernels without Landlock** (or ABI < 4 / < 6): no filesystem, TCP or scope confinement. ccwm runs
  anyway and says so. The Git hardening and the seccomp filter still apply.
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
- **Ignore rules cost memory.** The limits above bound the rules ccwm keeps: 5,000 per project and
  20,000 for all projects together. Only rules that need a regular expression are expensive (17–20 KiB
  each; ordinary ones cost almost nothing), so the worst case — every rule of that kind, as a hostile tree
  would have it — is about 75 MiB for one project and 345–395 MiB for all (measured with release builds,
  [docs/benchmarks.md](docs/benchmarks.md)). The rules of a file are compiled once and reused until the
  file changes, so scanning the same projects again and again leaves memory where it is (measured over
  ten scans with every project polled: 344 MiB in a glibc build, 381 MiB with the release binary; before
  the rules were cached, a glibc build grew to 1.66 GiB in four such scans). What still costs extra, for a
  moment: an ignore file that changed is compiled next to the rules it replaces (at most one project's
  worth at a time), and when the rules move from one project to another (the limit across projects, by
  recency) the project that gives up goes first. **Who can take the rules:** a tree of projects with huge
  ignore files and recent file times can take the whole limit across projects, because the limit goes to
  the most recently active projects; older projects then lose their ignore rules until they are active
  again (files their rules would ignore count as activity meanwhile; `ccwm status` reports the skipped
  files). The process as a whole is bounded by the systemd unit: `MemoryMax=2G` with `MemorySwapMax=0` (on
  a host with swap, `MemoryMax=` alone only moves the excess to swap). At the limit the kernel stops the
  service and systemd starts it again after 5 s, for as long as the cause is there
  ([docs/troubleshooting.md](docs/troubleshooting.md)). The limit needs the cgroup memory controller for
  your user manager (present on Ubuntu 24.04); **without systemd (`ccwm serve` in a terminal) there is no
  such limit**. Not measured: a pattern built to make the matcher itself use as much memory as it can;
  the measurements used one pattern shape (`*1?b[c-d]*.x`). The cache trusts a file's device, inode, size,
  modification time and change time. The change time cannot be set back, so a file rewritten in place
  with its old size and modification time is still noticed; a rewrite to the same size within the file
  system's timestamp resolution of the previous change (milliseconds on ext4) is not, until the file
  changes again or the daemon restarts (that affects what counts as activity, nothing else).
- **POSIX ACLs** (v0.1.0 review L4). The check that refuses to start when an ancestor of ccwm's
  directories, or the config file, "could be modified by another user" reads the owner and the mode bits.
  It does not read access control lists: with an extended ACL the group bits show the ACL mask, so a
  directory on which you granted another user write access with `setfacl` passes when its group is your
  private group. The private-group rule looks at the group's listed members only, not at another account
  whose primary group it is (which only an administrator can create). Do not grant ACL write access on
  the ancestors of ccwm's directories.
- Tests catch regressions; they cannot prove the absence of network activity. Security acceptance
  test 5 traces every `connect()` and `execve()` of the daemon and its children with `strace`. It has
  no network-namespace variant: an unprivileged network namespace needs a user namespace, in which
  root-owned paths appear to belong to `nobody` and ccwm's ownership checks (correctly) refuse to start.
  What `connect()` tracing cannot see — datagrams sent without a connect — is covered by the seccomp
  filter, which lets the daemon and its children create no socket at all after startup and is tested on
  its own (`tests/sandbox.rs`).

## Optional defense in depth

- Mount `/proc` with `hidepid=invisible` (e.g. `proc /proc proc defaults,hidepid=invisible 0 0` in
  `/etc/fstab`, needs root) so other users cannot see process command lines. ccwm does not depend on
  it; it only removes the place where a sign-in link would be visible.

## Manual verification

The cross-user checks (another local user cannot use a leaked sign-in link or session token, cannot reach
the Unix socket or the data, and an impostor on the port receives nothing from `ccwm open`) are simulated
in the tests. They are also written up as a manual procedure with a real second account in
[docs/two-user-verification.md](docs/two-user-verification.md).

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately (the contact will be published
with the first release; until then, use the repository's private security advisory feature once the
repository is public).
