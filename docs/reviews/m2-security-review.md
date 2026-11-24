# M2 security review (activity tracking)

Independent, adversarial review of milestone M2 — I did not write this code. Scope per the review
brief: the Git module (every invocation, flag, env var and config vector that can execute a program
or touch the network), the watcher (symlink races, budget/overflow, self-events), WebSocket auth,
reconciliation/move logic, the new endpoints and query params, and whether acceptance tests 3, 4 and
5 genuinely test what they claim.

Sources read: `REQUIREMENTS.md` §0/§2/§5/§6/§11/§16, `ARCHITECTURE.md` (esp. §6, §7a, §8, §9, §12),
`docs/reviews/m1-security-review.md`, and the M2 commit `git show be95a61`. I read but did not modify
code, and did not open `~/.claude`.

Unlike the M1 review, I **ran** experiments. Everything was confined to the session scratchpad and a
short-lived synthetic environment built by `ccwm-synth`; no real home, project or `~/.claude` was
touched, and nothing was pushed. Where a scenario is demonstrated I say so; where it is reasoned I say
that too. The key experiments:
- Throw-away repos driven with ccwm's **exact** Git flags, environment (`env -i` + the six §6
  variables) and command sequence, with sentinel files for execution.
- The **real daemon** (`target/debug/ccwm serve`) in a synthetic env, with `strace -f -e
  trace=execve,socket` on the daemon and its Git children, and the SQLite WAL inspected for the
  recorded Git state.

One finding is **High**: a repository-controlled configuration makes ccwm's own `git status` / `git
log -1` execute an attacker-chosen program (a Git *transport/remote helper*) via a promisor
partial-clone lazy fetch. The §6 hardening flags do **not** stop it; on the development host only the
full Landlock sandbox does, by a mechanism I could not fully attribute and which the spec itself says
may be absent. Acceptance test 4 does not cover this vector and its `core.sshCommand` control is
misleading. The rest are four Low findings and test gaps. No Critical.

Both the fix for H1 and the test change it implies touch the §6 contract and the §16 acceptance
tests, so they need the maintainer's sign-off before anyone implements them.

---

## High

### H1. A malicious repo runs an arbitrary program during `git status` / `git log -1` via a promisor lazy fetch

**Where:** `src/git/mod.rs:31` (`BASE_ARGS`), `src/git/mod.rs:212` (`command`, the environment),
`src/git/mod.rs:324` (`status`), `src/git/mod.rs:284` (`log -1`). The vector is absent from
`BASE_ARGS` and from the environment in `command`.

**What the spec promises.** The fundamental guarantee (REQUIREMENTS.md §0) says ccwm "neutralizes
repository-defined Git helpers"; §6 requires investigating "every … repository-controlled
configuration that can trigger command execution … credential and ssh helpers, includes". §11.1 puts
"malicious … Git configuration" **in scope**. So a malicious repo achieving code execution during
routine inspection is squarely in the threat model.

**The hole.** `BASE_ARGS` passes `-c protocol.allow=never`. That is the *generic* protocol gate. Git
lets a **per-protocol** setting override the generic one, and a per-protocol setting in the
**repository's own config** overrides the generic one passed on our command line. So a repo that sets
`protocol.ext.allow = always` (or `protocol.ssh.allow`, `protocol.file.allow`) re-enables that
transport despite `protocol.allow=never`.

ccwm never runs `fetch`/`clone`/`ls-remote`, so normally no transport is reached. But a **promisor
partial clone** makes `git status` and `git log -1` perform a *lazy fetch* on their own the moment
they need an object that is absent from the local store. The attacker ships a repo with:
`extensions.partialClone=origin`, `remote.origin.promisor=true`, `protocol.ext.allow=always`,
`remote.origin.url = ext::sh <attacker script>`, and the commit object that `HEAD` points at removed
from `.git/objects`. When ccwm inspects it, `status` and `log` each spawn
`git fetch … --filter=blob:none`, which spawns `git remote-ext origin "sh <script>"`, which executes
the script. The same works with `core.sshCommand` behind an `ssh://` promisor and with
`remote.<name>.uploadpack` behind a `file://` promisor.

**Demonstrated (git-command layer, ccwm's exact flags + `env -i` + the six §6 vars).** Running, in a
crafted repo, exactly:

```
git --no-pager --no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false \
    -c core.hooksPath=/dev/null -c protocol.allow=never \
    --attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904 \
    status --porcelain=v2 --branch --ignore-submodules=all -z -- .
# and the ccwm `log -1 …` line
```
→ the sentinel file was created by both commands (`status` and `log`). `strace` of the by-hand run
shows the chain `git status → /usr/lib/git-core/git fetch … --filter=blob:none → git remote-ext
origin "sh …/helper.sh" → sh`. No `socket()` is involved: `ext::` is pure pipes, so this is code
execution, independent of any network rule.

**Live daemon (Ubuntu 24.04, Landlock ABI 8, `fully_enforced`).** Discovery registered the crafted
project and `strace` confirmed the daemon ran `rev-parse`, `status` **and** `log -1` against it, and
that `status`/`log` spawned the lazy `git fetch`. But the fetch child **did not** go on to spawn
`git remote-ext`, so the helper never ran and no sentinel appeared — on this host the attack is
contained.

**Why the containment is not the §6 hardening, and is fragile.** I could not fully attribute which
Landlock facet stops the fetch before it execs the helper. It is **not** the read-only-filesystem
rule: making the whole repo tree read-only (`chmod -R a-w`) *without* Landlock still let the helper
run (Git spawns `remote-ext` before it tries to write fetched objects). So the containment is a
non-obvious side effect of *full* Landlock confinement (ABI ≥ 4 network + ABI ≥ 6 scopes on this
kernel), not of the §6 Git flags. REQUIREMENTS.md §11.5 states Landlock is **best effort** and that on
kernels without it (ABI < 4, or Landlock unavailable) ccwm "runs anyway and reports". On those
configurations — which the spec explicitly supports — the §6 flags are the *only* defense, and they
are proven insufficient: this is unmitigated arbitrary command execution during routine inspection of
a malicious repo. The fundamental guarantee and §6 are therefore not met.

**Impact.** Arbitrary program execution as the daemon's user, triggered by ccwm merely discovering and
inspecting a repository the user never opened. On a host where full Landlock is active it is confined
(read-only filesystem, no TCP, scoped IPC) but the two residual channels ccwm already documents (UDP,
path-based Unix-socket `connect`) remain open to it; on a host without full Landlock it is unconfined.

**Fix (needs a §6 amendment).** Neutralize transports in a way repo config cannot override. ccwm never
needs any remote transport for its read-only commands, so:
- Set `GIT_ALLOW_PROTOCOL` in the child environment (`src/git/mod.rs:212`) to an empty/minimal
  allowlist (e.g. unset-all, or `file` only if a local-path remote URL must still be *read* by
  `config --get` — note that `config --get` does not itself invoke a transport, so even an empty value
  is safe). An environment variable cannot be overridden by repository config. **Verified:**
  `GIT_ALLOW_PROTOCOL=` (empty) and `GIT_ALLOW_PROTOCOL=file` both stopped the sentinel.
- Belt-and-braces, also pass explicit per-protocol denies on the command line, which outrank the
  repo's per-protocol allow: `-c protocol.ext.allow=never -c protocol.ssh.allow=never -c
  protocol.file.allow=never` (… and any other transport). **Verified:** `-c protocol.ext.allow=never`
  stopped the sentinel on its own.
- Consider additionally refusing to run worktree status/log on a repo that advertises
  `extensions.partialClone` (a promisor repo is the only way these read-only commands fetch), or
  disabling lazy fetch (there is no single clean flag; `GIT_ALLOW_PROTOCOL` is the robust lever).
- Extend acceptance test 4 (below) to cover this vector with a control run.

Do not rely on Landlock for this: §6 explicitly calls the flags "mitigations, not a sandbox", and the
guarantee must hold on the degraded-Landlock configurations the spec supports.

---

## Low

### L1. Move-matching trusts attacker-forgeable identity

**Where:** `src/tracker.rs:462` (`match_move`), `src/db/queries.rs:321` (`move_sources`),
`src/tracker.rs:431`–`440` (apply the move, which also moves the ignore entry via
`writer.move_project`).

A newly inserted project is treated as a moved copy of a unique missing project when their
`head_commit` **and** sanitized `remote_url` match, or (no commit) their `marker_hash` matches with no
Git head. All three are fully controlled by whoever creates the new repo/directory: a commit hash is
reproducible, a remote URL is a config string, and a `CLAUDE.md` content hash is trivially matched.

A local user who can write into a **shared or group-writable discovery root** can therefore craft a
directory that hijacks a missing project's stable id, its recorded history and its **ignore** state
(e.g. un-ignoring a project the user had ignored, or binding the old id to a repo the attacker
controls). The `[one]` uniqueness guard (`src/tracker.rs:472`) only prevents ambiguity, not forgery.
Severity is Low: §11.1 puts same-user processes out of scope, and cross-user requires an unusual
group-writable root; impact is limited to dashboard identity/ignore state, not code or data. Worth a
one-line note in SECURITY.md that move-matching keys on attacker-influenceable content and is not an
authentication of project identity. (Spec-conformant behaviour otherwise — this is §4.5 as written.)

### L2. Watch target is re-opened by path after the fd-based walk (symlink/rename swap)

**Where:** `src/watch/tree.rs:108` (fd-based, identity-checked walk produces `tree.dirs`) →
`src/watch/mod.rs:204` (`notify` adds each watch **by path**).

The tree walk is descriptor-based and `(dev,ino)`-verified, but the resulting directory paths are
handed to `notify`, which re-opens them by path to call `inotify_add_watch`. Between the two steps a
writer in the same tree can swap a directory. `with_dereference_symlinks(false)` (⇒ `IN_DONT_FOLLOW`)
is set, so a swap *to a symlink* is not followed; but a `RENAME_EXCHANGE` to a *different real
directory* would register a watch on the attacker's directory, whose events are then attributed by
longest-path-prefix to the victim project (`src/watch/mod.rs:286` "innermost registered project").
Impact is confined to spurious/fabricated activity entries and watch-budget consumption (inotify is
read-only); and cross-user needs a writable shared tree (§11.1). I could confirm `IN_DONT_FOLLOW` is
requested but not that `IN_ONLYDIR` is (the M2 notes claim it); a dir swapped to a regular file would
then be watched as a file. Low. If tightened later, add the watch by the descriptor the walk already
validated (or re-verify `(dev,ino)` after the add) rather than by path.

### L3. A malicious promisor repo multiplies failing `git fetch` subprocesses per inspection

**Where:** consequence of H1 at `src/git/mod.rs:246` (`inspect_inner` runs `status` then `log`, each
of which lazy-fetches) and `src/git/run.rs:74` (5 s timeout, process-group kill).

Even where Landlock contains H1, every inspection of a promisor repo spawns an extra `git fetch` child
from both `status` and `log` (observed: two `git fetch` execs per inspect). If the attacker points the
promisor transport at a hanging helper, each fetch runs until ccwm's 5 s timeout kills the process
group — so one inspection can cost ~10 s of a Git-queue slot, and a handful of such repos can occupy
all four slots (`MAX_CONCURRENT`, `src/git/mod.rs:23`) on every reconciliation (every 10 min) and on
every activity event, delaying legitimate Git refreshes. The process-group kill (verified working in
`run.rs` tests) bounds each call, so this is availability only. Low. The H1 fix (blocking the
transport) removes it as a side effect: with the transport denied, the fetch fails immediately.

### L4. A held WebSocket slides session expiry indefinitely

**Where:** `src/http/ws.rs:124` (revalidate every 10 s calls `service.authenticate`) →
`src/auth/sessions.rs:94` (`lookup` schedules `touch_session`, bumping `expires_at` to
`now + SESSION_TTL_SECS`).

An open WebSocket re-authenticates every 10 s, and each lookup (past the 5-minute touch interval)
slides the 30-day expiry forward. A session therefore never expires while any tab holds a socket open.
This is within the sliding-session design and is still bounded by the 24 h overdue-rotation rule
(`authenticate` rejects an overdue token, closing the socket within 10 s — verified by reading the
code path), so a stolen token cannot be kept alive past the rotation deadline without the rotate
secret. Informational/Low; note only if "sliding on passive WS traffic" is not intended.

---

## Acceptance tests 3, 4, 5 — do they test what they claim?

### Test 3 (`tests/git.rs:349`) — sound.
Snapshots `.git/index`, `.git/config`, refs and objects before/after three inspections of a
stat-dirty repo, plus a detached worktree, and re-reads `index`/`config` bytes at the end. It has a
real control proving plain `git status` *does* rewrite the index, so the assertion can fail. Good
coverage of the read-only-metadata guarantee.

### Test 4 (`tests/git.rs:416`–end) — real but has the H1 gap, and one misleading control.
It covers, each with a control that fires without the mitigation: `core.fsmonitor`; clean/smudge/
process filters via `.gitattributes`, `.git/info/attributes`, `include.path` and `includeIf`;
`diff.external`; `textconv`; `core.pager`/`pager.status`; `log.showSignature`+`gpg.program`; and a
filter name containing `=` (fail-closed). That is thorough for the vectors ccwm's commands reach on a
**healthy** repo.

Two problems:
- **Missing vector (H1):** no case sets up a promisor/partial-clone repo, so the test never exercises
  the one path by which `status`/`log` *do* contact a transport. The suite's green result is the false
  assurance behind H1.
- **Misleading control:** `acceptance_4_diff_external_textconv_pager_and_ssh_command_are_not_reached`
  (`tests/git.rs:568`) proves `core.sshCommand` is reached by `git ls-remote` — a command ccwm never
  runs — and concludes ccwm is safe because its commands "do not reach" it. The honest conclusion is
  only "not reached *on a repo with intact objects*"; a promisor repo reaches `sshCommand` through the
  lazy fetch. The control should be a command ccwm actually issues.

Fix: add a promisor-repo case (`ext::`, `remote.<n>.uploadpack` via `file://`, and `core.sshCommand`
via `ssh://`, each with the `HEAD` object removed) asserting no sentinel, with a control run; and
reword the `sshCommand` claim.

### Test 5 (`tests/process.rs:1289`) — sound for what it checks, but narrow, and one variant unrun.
The strace variant traces `connect`/`execve` on the daemon and children and flags any non-loopback
connect; the `connect_is_local` classifier is itself unit-tested (`tests/process.rs:1199`) and
correctly treats `AF_NETLINK` and unpardsed families as violations. Limits:
- It only inspects `connect()`. It adds `ssh://`/`https://` remotes to "tempt" Git but, because ccwm
  never fetches a healthy repo, no transport ever runs — so the test does **not** exercise the
  lazy-fetch path either, and would only catch H1 if the spawned helper happened to make a
  non-loopback `connect` (it need not: UDP, a path-based Unix socket, or local-only execution all pass).
- It does not assert the *absence* of unexpected `execve`s (a remote/transport helper, `ssh`, `sh`),
  only that ≥ 3 `git` execs occurred.
- The network-namespace variant (`unshare --user --map-current-user --keep-caps --net`) has **never
  run anywhere** (AppArmor blocks unprivileged userns on the dev host); only the strace variant has
  executed. This is already documented, but it means isolation is verified by tracing only.

---

## Checked and found sound

- **WebSocket auth** (`src/http/ws.rs`): exact `Origin` on upgrade, and multiple `Origin` headers are
  rejected (`ws.rs:39`). First message must be `{"type":"auth",…}` within 5 s (`deny_unknown_fields`),
  else close 4401; the subscription is created before auth but nothing is sent until auth succeeds
  (`ws.rs:84`–`95`). Message/frame size capped at 4 KiB. Revalidation every 10 s **and** on the
  revocation broadcast (logout, revoke-all, hourly purge), each calling `service.authenticate`, which
  rejects expired *and* overdue tokens (`src/auth/sessions.rs:70`) — so an overdue token cannot hold a
  socket open, and a revoked/expired one is dropped within 10 s (immediately on explicit revocation).
  The TCP peer-UID check (`http/mod.rs` serve loop) runs before any byte on the WS connection too.
- **Endpoints / query params:** `list_projects` validates through `validate_projects_query`; ids are
  checked by `is_project_id` before use (`src/service.rs:287`); ignore is keyed by the stored
  canonical path, never a client string (`src/service.rs:307`); cursors are validated against the
  request's sort/order. All SQL seen is parameterized (`rusqlite::params!` / `query_map`); no string
  interpolation into SQL. `has_sessions`/`sort=session`/`privacy` are rejected until M3.
- **Git metadata safety:** empty environment + the six §6 vars (unit-asserted, `git/mod.rs:471`);
  `--no-optional-locks` + `GIT_OPTIONAL_LOCKS=0` keep `status` from writing the index (test 3);
  `--no-show-signature` neutralizes `gpg.program` (found during M2, control-tested);
  `--attr-source=<empty tree>` + all-scope filter nulling (test 4); a filter name containing `=`
  fails closed (`StatusDisabledUnsafeConfig`); remote URLs are sanitized and control chars stripped
  (`parse::sanitize_remote_url`, unit-tested); subjects/authors/branches are `clean()`ed.
- **Watcher activity rules:** `.git/…` changes invalidate the Git cache instead of counting as
  activity, and `*.lock` is ignored (`src/watch/mod.rs:757`–`763`); gitignored/excluded paths produce
  nothing; the fd-based tree walk never follows symlinks and verifies `(dev,ino)` (`watch/tree.rs`);
  future mtimes are clamped to now; ccwm's own data/state/runtime dirs sit under hidden `.*`/XDG
  dot-directories and are excluded from walks, so ccwm does not watch itself.
- **Reconciliation:** projects are marked missing only when their root scanned `ok`
  (`src/tracker.rs:187`), so an unmounted disk does not mark its projects missing; purge is by
  retention; ids are preserved across paired renames and content-matched moves.

---

## For the maintainer

1. **H1 is the one to decide.** It needs a §6 amendment (add `GIT_ALLOW_PROTOCOL` to the child
   environment and/or explicit per-protocol `-c …=never`, and stop treating the §6 flags as covering
   transport/remote helpers) and an acceptance-test-4 addition (promisor vector + control). Both
   verified fixes are above. Should I open these as spec changes for M2, or hold them for M3?
2. The misleading `core.sshCommand` control in test 4 and the narrow scope of test 5 are worth fixing
   alongside H1 so the suite stops giving false assurance.
3. L1 (move-matching trusts forgeable identity) and L2 (watch re-open by path) are within the
   documented threat model's out-of-scope/shared-root caveats; I recommend a one-line SECURITY.md note
   for each rather than code changes in v0.1.

No code was modified and nothing was pushed. Want this recorded as open items in ARCHITECTURE §14, or
turned into a shareable page?
