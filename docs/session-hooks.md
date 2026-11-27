# Session activity indicator (Claude Code hooks)

ccwm can show, per project, whether a Claude Code session is open there and what it is doing:

| Dot | Label | Meaning |
|---|---|---|
| bright, steady, warning colour | **Needs approval** (from the first minute: **Needs approval · N min**) | Claude waits for you to approve a tool use or a network request |
| bright, pulsing | **Working** | Claude is working on a turn |
| dim, steady | **Waiting for input** | the session is open; Claude waits for your next prompt |
| hollow ring | **Session open** | the session is open (its process runs), what it is doing is not known — after a ccwm restart, until its next event |

The label is text; the dot only repeats it (its colour and pulse carry no extra meaning, and the pulse stops
when your system asks for reduced motion). With several sessions in one project the most urgent state is
shown, and the tooltip counts them ("2 open sessions: 1 needs approval, 1 working"). The toolbar has three
filters, each with its count: **Waiting for me** (a session waits or needs approval), **Working**, **Open**
(any state). The table has a "Claude" column; the detail panel lists the open sessions.

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
command -v '<ccwm>' >/dev/null 2>&1 && '<ccwm>' hook <Event>; exit 0
```

It is safe when ccwm is missing or broken: a missing ccwm is not called, and `exit 0` ends the hook with
status 0 and nothing on stdout whatever happened. (Claude Code adds a `SessionStart` or `UserPromptSubmit`
hook's stdout to the conversation and reads status 2 as "block": `ccwm hook` never prints on stdout and always
exits 0.) If `ccwm` is on Claude Code's `PATH` you can use `command -v ccwm >/dev/null 2>&1 && ccwm hook <Event>;
exit 0` instead. `ccwm hooks print` warns when the running binary is not `~/.local/bin/ccwm`.

## What `ccwm hook` does

Claude Code runs it with the event's JSON on stdin. It reads at most 16 MiB, keeps only the event name, the
session id, the working folder, the prompt id, `SessionStart`'s source and `Notification`'s type — the
prompt, Claude's reply and every tool field are skipped without being read into memory — and sends one
message over ccwm's Unix socket, waiting at most **100 ms** for the answer. A 1 s watchdog ends it whatever it
waits for. It never retries, opens no file, and does nothing when the daemon is not running. Cost: one process
start and one socket round trip per event (about 3–4 ms measured), including after every tool call
(`PostToolUse`, `PostToolBatch`).

The daemon checks where the message comes from: it walks up from the sending process to the nearest process of
your user that is Claude Code (`claude`, Claude Code's own process titles, or its versioned binary), at most 8
levels, and the `CLAUDE_PID` Claude Code sets must name the same process. Events from elsewhere are refused.
A session is closed when its process exits (checked every 5 s).

## When Claude Code reports nothing: the session file

Claude Code runs **no hook** when you interrupt a turn — Esc during a reply, "No" or Esc in a permission
dialog, Esc while an approved tool runs. It writes each of these into the session file, and ccwm (which
already reads the session files for its session index) takes them from there: the session then shows
"Waiting for input", about 2 seconds later. ccwm reads only a few structural fields of those records, never
their text, and uses a record only for the turn it belongs to.

## Know about

- **An approval is not reported.** After you approve a tool, the state stays "Needs approval" until the tool
  finishes — the minutes keep counting. A long build you approved shows as "Needs approval · 12 min".
- **Non-interactive sessions** (`claude -p`, and SDK hosts such as editor extensions that start Claude Code with
  `--output-format`/`--input-format`) are tracked but hidden. Settings → "Show non-interactive sessions"
  (`[indicator] show_noninteractive`) shows them; it applies at once. Background sessions (`claude --bg`) are
  shown.
- **Never activity:** hook events do not change a project's "last change", its sort order or its watches, and
  they never register a project (the session file does). A session in a folder that is no project is counted
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
names another process), `malformed`, `limit` (256 open sessions). `claude --debug hooks` shows the line
`ccwm hook` writes to stderr when something fails.

## Turn it off

Remove the entries from the settings file. Nothing else to do: ccwm stores no more than the open sessions'
ids, processes and working folders (deleted when they close).
