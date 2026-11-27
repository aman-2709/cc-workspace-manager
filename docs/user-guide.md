# User guide

This guide takes you from download to everyday use. Each step has commands to copy and the output to expect.
For the details behind a step, follow the links to the reference docs. For what happens under the hood,
see [How it works](how-it-works.md).

CC Workspace Manager (`ccwm`) is an independent, unofficial project, not affiliated with or endorsed by
Anthropic.

1. [Requirements](#1-requirements)
2. [Install](#2-install)
3. [Try it once without a service](#3-try-it-once-without-a-service)
4. [Run it as a user service](#4-run-it-as-a-user-service)
5. [Open the dashboard and sign in](#5-open-the-dashboard-and-sign-in)
6. [Turn on the live session indicator](#6-turn-on-the-live-session-indicator)
7. [Everyday use](#7-everyday-use)
8. [Update to a new version](#8-update-to-a-new-version)
9. [Uninstall](#9-uninstall)
10. [Troubleshooting](#10-troubleshooting)

## 1. Requirements

| | Needed for | Without it |
|---|---|---|
| **Linux x86_64** | everything | the release binary does not run (macOS, Windows and ARM are not supported yet) |
| **Claude Code** | the sessions ccwm reads (`~/.claude/projects`), the resume command, the live indicator | projects come only from `CLAUDE.md` files; resume commands carry a "`claude` not found" warning |
| **Git 2.41 or newer** | Git status on each project | projects show without Git state |
| **systemd user session** | running ccwm as a service | run it in the foreground (`ccwm serve`) |
| **jq** | the copy-paste commands of [step 6](#6-turn-on-the-live-session-indicator) (adding the hooks to your Claude Code settings) | edit the settings file by hand ([session-hooks.md](session-hooks.md#turn-it-on)) |
| **Landlock** (Linux 5.13+; 6.7+ for TCP rules, 6.12+ for scoping) | the filesystem and network sandbox | ccwm runs anyway and reports exactly what is active |

Tested on Ubuntu 24.04 (kernel 7.0, systemd 255, Git 2.43) with Claude Code 2.1.332. Nothing else has been
tested yet.

`ccwm doctor` checks all of this once ccwm is installed: the daemon, systemd, lingering, the port, inotify
limits, Git, `claude`, Claude Code's session folder, the hooks, file permissions, and the sandbox. It only
suggests fixes; it never changes anything.

## 2. Install

### From a release (recommended)

The release is one static binary (no runtime libraries) plus two scripts.

1. Download the archive and its checksum file into an empty folder:

   ```bash
   mkdir ccwm-download && cd ccwm-download
   curl -fLO https://github.com/aman-2709/cc-workspace-manager/releases/download/v0.2.0/ccwm-0.2.0-x86_64-unknown-linux-musl.tar.gz
   curl -fLO https://github.com/aman-2709/cc-workspace-manager/releases/download/v0.2.0/SHA256SUMS
   ```

2. Check the download:

   ```bash
   sha256sum -c SHA256SUMS
   ```

   Expected:

   ```
   ccwm-0.2.0-x86_64-unknown-linux-musl.tar.gz: OK
   ```

   Anything other than `OK` means the file is damaged or not the one released: delete it and download again.
   The checksum shows that the file is intact. It is not a signature: both files come from the same
   release page.

3. Unpack and install:

   ```bash
   tar -xzf ccwm-0.2.0-x86_64-unknown-linux-musl.tar.gz
   cd ccwm-0.2.0-x86_64-unknown-linux-musl
   scripts/install.sh
   ```

   Expected (with your own home directory):

   ```
   Installed /home/you/.local/bin/ccwm (ccwm 0.2.0)
   Installed /home/you/.config/systemd/user/ccwm.service
   ccwm 0.2.0 (running). Open the dashboard with `ccwm open`.
   It starts when you log in. To start it at boot, before you log in, enable lingering: `loginctl enable-linger you` (may need administrator authorization).
   Next: ccwm open
   ```

   `install.sh` copies the binary to `~/.local/bin/ccwm` and installs and starts a systemd **user** service.
   It needs no root and runs no privileged command. If the last line says `~/.local/bin` is not on your
   `PATH`, add it (for bash: `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`, then open a new
   terminal), or call `~/.local/bin/ccwm` by its full path.

   If you want to try ccwm before installing a service, skip `install.sh` and go to
   [step 3](#3-try-it-once-without-a-service) with `./ccwm` from the unpacked folder.

### From source

You need Rust 1.94 (the only tested toolchain) and a C compiler.

```bash
git clone https://github.com/aman-2709/cc-workspace-manager.git
cd cc-workspace-manager
cargo build --release --locked
scripts/install.sh target/release/ccwm
```

The output is the same as above. The source build links against glibc; the release binary is a static musl
build.

## 3. Try it once without a service

`ccwm serve` runs the daemon in your terminal. It is exactly what the service runs.

1. Start it (from the unpacked release folder, or use `ccwm` if it is installed):

   ```bash
   ./ccwm serve
   ```

   Among the first log lines:

   ```
   INFO cc_workspace_manager::daemon: landlock fully_enforced: abi=8 filesystem=true network=tcp_only …
   INFO cc_workspace_manager::daemon: listening on http://127.0.0.1:8765 (run `ccwm open` to sign in) port=8765
   INFO cc_workspace_manager::tracker: reconciliation finished dirs=… projects=… full=true
   ```

2. In a second terminal, open the dashboard ([step 5](#5-open-the-dashboard-and-sign-in) has the details):

   ```bash
   ./ccwm open
   ```

3. Stop it with **Ctrl-C** in the first terminal. It shuts down cleanly (`shutting down` in the log).

Only one ccwm daemon runs per user. If the service is already running, `ccwm serve` exits with
"another ccwm daemon is already running" (exit code 11): use the running one, or `ccwm stop` first.

A foreground run creates the same index as the service (in `~/.local/share/ccwm`, see
[data retention](data-retention.md)). If you decide not to keep ccwm, [step 9](#9-uninstall) removes it.

## 4. Run it as a user service

`scripts/install.sh` already did this. To do it by hand, or again after `ccwm service uninstall`:

```bash
ccwm service install
```

It writes `~/.config/systemd/user/ccwm.service`, then runs `systemctl --user daemon-reload` and
`systemctl --user enable --now ccwm.service`.

Check it:

```bash
ccwm status
```

Expected, roughly:

```
systemd: ccwm.service active (enabled)
ccwm daemon 0.2.0 (commit …) running, port 8765, up 2m
  discovery: idle, last scan 2026-11-27 09:00:11, next scan 2026-11-27 09:10:11
  monitoring: inotify, 46 watches (budget 16384), projects: 25 watched, 0 partly watched, 0 polled
  git: /usr/bin/git 2.43.0 (hardened status: true)
  claude: verified 2.1.332 (Claude Code) (resume supported: true)
  hooks: no hook event since the daemon started (opt-in: `ccwm hooks print`)
  sandbox: fully_enforced (abi 8, filesystem true, network tcp_only, seccomp socket_denied)
  sessions: ok (120 files, 120 indexed; 4 not in a project)
```

Everyday service commands:

| Command | What it does |
|---|---|
| `ccwm start` / `ccwm stop` / `ccwm restart` | start, stop or restart the service, and wait until it answers |
| `ccwm status` | the service's and the daemon's state |
| `ccwm doctor` | check the installation and suggest fixes |
| `journalctl --user -u ccwm -f` | follow the logs |

### Start at login or at boot

A user service runs while you are logged in: systemd starts it when you log in and stops it after your last
session ends. That is usually what you want, since the dashboard is for you, in your browser.

To start ccwm at **boot** and keep it running after you log out, enable **lingering** for your user:

```bash
loginctl enable-linger "$USER"
loginctl show-user "$USER" --property=Linger      # expected: Linger=yes
```

Depending on your system's policy, `enable-linger` may need administrator authorization. **ccwm never runs
it for you.** `loginctl disable-linger "$USER"` turns it off. More in [service.md](service.md#start-at-login-vs-at-boot).

## 5. Open the dashboard and sign in

```bash
ccwm open
```

Expected:

```
Opening the dashboard in your browser (the sign-in link is single-use and expires in 30 seconds).
```

Your browser opens `http://127.0.0.1:8765/`, already signed in. The link inside is **single-use and valid
for 30 seconds**: if the page says "Run `ccwm open`", run it again.

If no browser opens (no desktop session, or you want another browser on the same machine), print the link
instead and open it yourself within 30 seconds:

```bash
ccwm open --print
```

```
http://127.0.0.1:8765/#bt=…
```

Keep `127.0.0.1` as it is: `localhost` is a different origin, and the sign-in does not carry over.

**Remote machines.** ccwm serves the browser on the same machine only. Do not forward its port (`ssh -L`,
`socat`, an editor's port forwarding): a forwarder that runs as you passes ccwm's "same Linux user" check,
so anyone who can reach the forwarded port could use a leaked sign-in link or token through it
([SECURITY.md](../SECURITY.md#residual-risks)).

To sign out a browser, use **Sign out** in the dashboard. `ccwm auth revoke-all` signs out every browser.

## 6. Turn on the live session indicator

The indicator shows, per project, whether a Claude Code session is open there and what it is doing:
**Needs approval**, **Working**, **Waiting for input**. It is **opt-in**: it needs hooks in your Claude Code
settings, and **ccwm never reads or edits Claude Code's settings files**. You add the hooks yourself.

The steps below merge ccwm's hooks into your user settings file (every project) without touching your
existing hooks or any other setting. They need `jq`. To use the hooks in one project only, use the same
steps with that project's `.claude/settings.local.json`. How the hooks work, and what they cannot see:
[session-hooks.md](session-hooks.md).

1. Name the settings file (Claude Code reads `$CLAUDE_CONFIG_DIR` instead of `~/.claude` when it is set):

   ```bash
   SETTINGS="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"
   [ -f "$SETTINGS" ] || (umask 077 && echo '{}' > "$SETTINGS")
   ```

2. Back it up (the date in the name keeps an earlier backup if you run these steps again):

   ```bash
   BACKUP="$SETTINGS.before-ccwm-$(date +%Y%m%d-%H%M%S)"
   cp -p "$SETTINGS" "$BACKUP" && echo "backup: $BACKUP"
   ```

3. Look at the hooks you already have:

   ```bash
   jq '.hooks // "no hooks yet"' "$SETTINGS"
   ```

   If `jq` reports a parse error, stop here: the file is not plain JSON, and the merge below would fail. Edit
   it by hand instead ([session-hooks.md](session-hooks.md#turn-it-on) says how).

4. Save ccwm's hooks to a file:

   ```bash
   ccwm hooks print > ccwm-hooks.json
   ```

   Each hook calls ccwm by its full path, guarded so it does nothing when ccwm is missing and never fails or
   blocks Claude Code:

   ```sh
   command -v '/home/you/.local/bin/ccwm' >/dev/null 2>&1 && '/home/you/.local/bin/ccwm' hook Stop >/dev/null; exit 0
   ```

   If `ccwm hooks print` prints a warning, read it: it means the binary you ran is not
   `~/.local/bin/ccwm`, and the hooks will call that other path.

5. Merge them. This **appends** ccwm's entries to each event's list, keeps every existing hook and setting,
   and adds nothing that is already there (running it twice changes nothing):

   ```bash
   jq -s '.[0] as $cur | .[1].hooks as $new
     | $cur | .hooks = (reduce ($new | keys_unsorted[]) as $e ($cur.hooks // {};
         .[$e] = ((.[$e] // []) + ($new[$e] - (.[$e] // []))) ))' \
     "$SETTINGS" ccwm-hooks.json > settings.merged.json
   ```

6. Check the result before you use it. Your own hooks must still be there, and each event must have one
   ccwm entry:

   ```bash
   jq '.hooks | map_values([.[].hooks[]?.command | if test("ccwm.* hook ") then "ccwm" else . end])' settings.merged.json
   ```

   Expected (with one hook of your own on `Stop`):

   ```json
   {
     "Stop": ["notify-send done", "ccwm"],
     "SessionStart": ["ccwm"],
     "UserPromptSubmit": ["ccwm"],
     "Notification": ["ccwm", "ccwm"],
     …
   }
   ```

   (`Notification` has two ccwm entries on purpose: one for permission prompts, one for idle prompts.)

7. Put it in place. `cp` keeps the settings file's permissions:

   ```bash
   cp settings.merged.json "$SETTINGS" && rm settings.merged.json
   ```

8. Verify. Start a **new** Claude Code session (hooks load at session start; in a new folder, accept the
   trust dialog first), send a prompt, then:

   ```bash
   ccwm status | grep hooks
   ```

   ```
     hooks: 1 open session(s) (0 needs approval, 1 working, 0 waiting, 0 unknown), last event …
   ```

   The project's card shows **Working**. `ccwm hooks events --follow` shows every event as it arrives, and
   why one was refused, if any.

### Turn it off

Remove exactly the entries you added (it uses the `ccwm-hooks.json` from step 4; if you no longer have it,
run `ccwm hooks print > ccwm-hooks.json` again with the same ccwm):

```bash
jq -s '.[1].hooks as $new | .[0]
  | if .hooks then
      .hooks = (reduce ($new | keys_unsorted[]) as $e (.hooks; if .[$e] then .[$e] -= $new[$e] else . end)
                | with_entries(select(.value | length > 0)))
      | if .hooks == {} then del(.hooks) else . end
    else . end' \
  "$SETTINGS" ccwm-hooks.json > settings.cleaned.json
jq '.hooks // "no hooks"' settings.cleaned.json        # check: none of ccwm's left, yours still there
cp settings.cleaned.json "$SETTINGS" && rm settings.cleaned.json
```

Or restore the backup from step 2, which also undoes any other change made to the file since:
`ls "$SETTINGS".before-ccwm-*` lists the backups, then `cp -p "<backup>" "$SETTINGS"`.

## 7. Everyday use

**Find a project.** Type in the search box (name, path or branch). Sort by last change, latest commit,
latest session or name. "All activity" narrows the list to projects changed today or this week, inactive,
dormant or missing ones. The checkboxes show only projects with uncommitted changes or with sessions, and
bring back missing or ignored ones.

**See what needs you.** With the indicator on, projects with an open session come first: needs approval,
then working, then waiting. The toolbar filters **Waiting for me**, **Working** and **Open** show only
those. Settings → "Show live sessions first" turns the ordering off.

**Cards or table.** Switch with **Cards** / **Table**. The table is denser and has a "Claude" column.

**Resume a session.** Open **Details** on a project: it shows the latest session's title, its last prompt
(read from the session file when you open the panel, redacted, not stored), and the resume command:

```
cd -- '/home/you/dev/my-project' && claude --resume <session-id>
```

**Copy** it (or **Copy resume** in the table) and paste it into a terminal. ccwm never runs it.

**Privacy mode.** **Privacy: off/on** in the header hides paths, user names, remote URLs, session titles,
prompts and resume commands. The server removes them before they reach the browser, so they are not just
hidden on screen. Use it when you share your screen. The default for new browsers is in Settings.

**Ignore a project.** **Ignore** (on its card or table row) hides it and stops tracking it. Nothing on disk
changes. "Show ignored" brings ignored projects back into the list with **Un-ignore**; Settings lists them
too.

**Forget a missing project.** A project whose folder is gone is marked *missing* and forgotten after 30 days.
**Forget** (in place of Ignore on its card or row, and in its details; click it twice to confirm) removes it
from ccwm's index now. Nothing on disk changes.

**Settings.** Roots, exclusions, scan interval, theme, privacy default, the indicator's options, and more.
Some apply at once, the rest after `ccwm restart` (the page says which). All keys:
[configuration.md](configuration.md).

**Rescan now.** **Scan now** in the dashboard, or `ccwm scan` in a terminal.

## 8. Update to a new version

Download, check and unpack the new release as in [step 2](#from-a-release-recommended), then run **its**
`install.sh`:

```bash
cd ccwm-<new version>-x86_64-unknown-linux-musl
scripts/install.sh
ccwm status          # the first daemon line shows the new version
```

`install.sh` replaces the binary atomically and restarts the running service. Your settings, index and
sign-ins are kept. The hooks call `~/.local/bin/ccwm` by path, so they keep working without changes.

## 9. Uninstall

From the unpacked release folder (or the repository):

| Command | Removes | Keeps |
|---|---|---|
| `scripts/uninstall.sh` | the service and `~/.local/bin/ccwm` | your ccwm settings and index |
| `scripts/uninstall.sh --purge` | the above, then, after you type `yes`: `~/.config/ccwm`, `~/.local/share/ccwm`, `~/.local/state/ccwm`, `$XDG_RUNTIME_DIR/ccwm` | nothing of ccwm's |

Expected for the plain uninstall (ccwm's own lines):

```
Removed /home/you/.config/systemd/user/ccwm.service
Your ccwm data is kept (/home/you/.config/ccwm, /home/you/.local/share/ccwm, /home/you/.local/state/ccwm). `ccwm service uninstall --purge` deletes it.
Removed /home/you/.local/bin/ccwm
```

The middle line names `ccwm service uninstall --purge`, but the plain `scripts/uninstall.sh` has just
removed `~/.local/bin/ccwm`, so that command is gone. To delete the kept data later, use the `ccwm` from the
unpacked release folder:

```bash
./ccwm service uninstall --purge     # asks before deleting; the service is already gone
```

or delete the four folders listed in the table yourself.

Your projects and Claude Code's sessions are never touched either way. If you added the hooks, remove them
too ([step 6](#turn-it-off)); until then they do nothing, silently.

## 10. Troubleshooting

Start with `ccwm doctor`: it checks everything below and suggests a fix for each problem. The five most
common:

| Symptom | Fix |
|---|---|
| `port 8765 is already in use` (exit code 10) | another program uses the port: pick another in Settings or `config.toml` (`[server] port`), then `ccwm restart`. [Port already in use](troubleshooting.md#port-already-in-use) |
| No projects, or fewer than expected | projects come from Claude Code sessions and `CLAUDE.md` files; `ccwm status` lists sessions that belong to no project, and why. [No projects appear](troubleshooting.md#no-projects-appear) |
| The page says "Run `ccwm open`" | the sign-in link is single-use and lives 30 s: run `ccwm open` again, and use `127.0.0.1`, not `localhost`. [Details](troubleshooting.md#the-browser-says-run-ccwm-open) |
| No dots for open sessions | the indicator is opt-in: add the hooks ([step 6](#6-turn-on-the-live-session-indicator)), start a **new** session, then watch `ccwm hooks events --follow`. [The session activity indicator shows nothing](troubleshooting.md#the-session-activity-indicator-shows-nothing) |
| Projects "polled" or a DEGRADED banner | inotify limits reached (shared with editors and IDEs); raising them needs an administrator. [inotify limits](troubleshooting.md#inotify-limits) |

Everything else: [troubleshooting.md](troubleshooting.md).
