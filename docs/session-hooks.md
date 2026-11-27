# Session activity indicator (Claude Code hooks)

ccwm can show, per project, whether a Claude Code session is open there and what it is doing:

| Dot | Label | Meaning |
|---|---|---|
| magenta, steady | **Needs approval** (from the first minute: **Needs approval · N min**) | Claude waits for you to approve a tool use or a network request |
| purple, pulsing | **Working** | Claude is working on a turn |
| teal, steady | **Waiting for input** | the session is open; Claude waits for your next prompt |
| hollow gray ring | **Session open** | the session is open (its process runs), what it is doing is not known — after a ccwm restart, until its next event |

The label is text; the dot only repeats it (its colour and pulse carry no extra meaning, and the pulse stops
when your system asks for reduced motion). Every colour has at least 4.5:1 contrast in both themes, and
"Needs approval" is kept well apart from the orange of uncommitted changes. On cards the state has a line of
its own under the project name. With several sessions in one project the most urgent state is shown, and the
tooltip counts them ("2 open sessions: 1 needs approval, 1 working"). The toolbar has three filters, each with
its count: **Waiting for me** (a session waits or needs approval), **Working**, **Open** (any state). The
table has a "Claude" column; the detail panel lists the open sessions.

**Live sessions first** (on by default): projects with an open session come first — needs approval, then
working, then waiting, then open — and within each group, and after them, your chosen sort applies. Settings →
"Show live sessions first" (`[indicator] live_first`) turns it off; it applies at once.

It is **opt-in**: nothing appears until you add ccwm's hooks to your Claude Code settings. ccwm never reads
or edits a Claude Code settings file.

## Turn it on

```bash
ccwm hooks print
```

prints a `{"hooks": {…}}` object. Merge it into one of:

- `~/.claude/settings.json` — every project;
- a project's `.claude/settings.local.json` — that project only (not committed).

If the file has no `hooks` yet, add the object's `hooks` key as it is; otherwise add each event's entry to the
event's list. Claude Code merges hooks across settings files, and an identical handler defined twice runs once.
In an interactive session the hooks start after you accept the folder's trust dialog.

Each hook runs this command (one per event, `<ccwm>` being the binary's absolute path):

```sh
command -v '<ccwm>' >/dev/null 2>&1 && '<ccwm>' hook <Event> >/dev/null; exit 0
```

It is safe when ccwm is missing or broken: a missing ccwm is not called, `>/dev/null` discards whatever an
older or foreign binary at that path might print, and `exit 0` ends the hook with status 0 whatever happened.
(Claude Code adds a `SessionStart` or `UserPromptSubmit` hook's stdout to the conversation and reads status 2
as "block": `ccwm hook` never prints on stdout and always exits 0.) Its stderr stays visible in
`claude --debug hooks`. If `ccwm` is on Claude Code's `PATH` you can use
`command -v ccwm >/dev/null 2>&1 && ccwm hook <Event> >/dev/null; exit 0` instead. `ccwm hooks print` warns
when the running binary is not `~/.local/bin/ccwm`, and when `~/.local/bin/ccwm` is a symbolic link: the hooks
then name the link's target, and after an upgrade that moves the link, run `ccwm hooks print` again (a hook
whose path no longer exists does nothing, silently). `scripts/install.sh` copies the binary, so this does not
arise with it.

## What `ccwm hook` does

Claude Code runs it with the event's JSON on stdin. It reads at most 16 MiB, keeps only the event name, the
session id, the working folder, the prompt id, `SessionStart`'s source and `Notification`'s type — the
prompt, Claude's reply and every tool field are skipped without being read into memory — and sends one
message over ccwm's Unix socket, waiting at most **100 ms** for the answer. A 1 s watchdog ends it whatever it
waits for. It never retries, opens no file, and does nothing when the daemon is not running. Cost: one process
start and one socket round trip per event (about 3–4 ms measured), including after every tool call
(`PostToolUse`, `PostToolBatch`). It looks up nothing in the user and group databases (no NSS, no LDAP or
sssd round trip) as long as `$HOME` is yours and the runtime directory has no group-writable parent.

The daemon checks where the message comes from: it walks up from the sending process to the nearest process of
your user that is Claude Code (`claude`, Claude Code's own process titles, or its versioned binary), at most 8
levels, and the `CLAUDE_PID` Claude Code sets must name the same process. Events from elsewhere are refused.
A session is closed when its process exits (checked every 5 s).

One Claude Code process holds one session. Only that process ends it: if you resume a session in a second
terminal while the first still runs, leaving the first does not close it for the second. When `/clear` or
`/resume` starts the next session in the same process, the previous one closes even if its end event was lost.

## When Claude Code reports nothing: the session file

Claude Code runs **no hook** when you interrupt a turn — Esc during a reply, "No" or Esc in a permission
dialog, Esc while an approved tool runs. It writes each of these into the session file, and ccwm (which
already reads the session files for its session index) takes them from there: the session then shows
"Waiting for input", about 2 seconds later. ccwm reads only a few structural fields of those records, never
their text, and uses a record only for the turn it belongs to.

## Know about

- **An approval is not reported.** After you approve a tool, the state stays "Needs approval" until the tool
  finishes — the minutes keep counting. A long build you approved shows as "Needs approval · 12 min".
- **An approval inside a subagent** shows "Needs approval" until the **whole subagent** finishes, not just the
  approved tool: ccwm ignores tool events from inside subagents (otherwise one subagent's tool would end
  another one's wait), so the next event it uses is the subagent's own end in the main conversation.
- **A Stop hook of your own that keeps Claude working** (one that exits 2 or answers `{"decision":"block"}`,
  as "keep going until the tests pass" hooks and some plugins do) leaves the session "Waiting for input" while
  Claude carries on: ccwm's own `Stop` hook has already reported the end of the turn, and tool events of a turn
  that ended do not move it back. It shows "Waiting for input" correctly again when the continued turn ends, and
  "Working" at your next prompt. (Reasoned from Claude Code's documented hook behaviour; not run.)
- **Non-interactive sessions** (`claude -p`, and SDK hosts such as editor extensions that start Claude Code with
  `--output-format`/`--input-format`) are tracked but hidden. Settings → "Show non-interactive sessions"
  (`[indicator] show_noninteractive`) shows them; it applies at once. Background sessions (`claude --bg`) are
  shown. Hidden sessions still count toward the limit of 256 open sessions: a large parallel fan-out of
  `claude -p` runs can fill it, and events of a new session are then refused (`limit`) until some close.
- **Never activity:** hook events do not change a project's "last change", the activity, name, commit or
  session sort, or its watches, and they never register a project (the session file does). Only the "live
  sessions first" grouping above follows them, and it can be turned off. A session in a folder that is no project is counted
  in `ccwm status` but shows nowhere.
- **A lost event** (the 100 ms ran out) leaves the last known state until the session's next event.
- **After a ccwm restart** an open session shows "Session open" until its next event; a reboot forgets them.
  "Clear session index" forgets them too.
- **No hooks run** under `claude --bare`, `--safe-mode`, `--restricted`, with `disableAllHooks` or a managed
  `allowManagedHooksOnly`, or before the trust dialog is accepted. A Claude Code in a container (another PID
  namespace), or started under another name, is not found. A shell whose runtime directory differs from the
  daemon's reaches no daemon. With ccwm uninstalled the hooks do nothing until you remove them.
- **Privacy mode** keeps the indicator: it holds states, counts and times only — no path, process id or text.

## Check it

```bash
ccwm status                  # "hooks: 2 open session(s) (1 needs approval, 1 working, …)"
ccwm hooks events --follow   # every event as it arrives: time, event, session id, what the daemon did
```

`ccwm hooks events` keeps the last 256 events in the daemon's memory (not on disk). A refused event says why:
`no_claude_ancestor` (not run by Claude Code, or Claude Code under another name), `pid_mismatch` (`CLAUDE_PID`
names another process), `malformed`, `limit` (256 open sessions), `client_gone` (the `ccwm hook` process had
already exited when the daemon handled its event, so its ancestry could not be checked). `--follow` waits for
the daemon through a restart and says so. `claude --debug hooks` shows the line
`ccwm hook` writes to stderr when something fails.

## Turn it off

Remove the entries from the settings file. Nothing else to do: ccwm stores no more than the open sessions'
ids, processes and working folders (deleted when they close).
