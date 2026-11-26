# Troubleshooting

Start with `ccwm doctor`. It checks everything below and prints a suggested fix for each problem. It
never applies one. `ccwm status` and `journalctl --user -u ccwm` show the daemon's own view.

## Port already in use

```
ccwm: port 8765 is already in use. Choose another with `ccwm serve --port N` or set [server] port in the config file
```

The daemon exits with code **10**, and systemd does not restart it (`RestartPreventExitStatus`). ccwm never
moves to another port on its own, because the browser origin (`http://127.0.0.1:<port>`) and your sign-in
belong to that port.

- Find out who listens: `ss -ltnp 'sport = :8765'`. Another program is using the port, or a second ccwm runs
  in the foreground under a different configuration.
- Pick another port: set `[server] port = 8777` in `~/.config/ccwm/config.toml` (or on the Settings page),
  then `ccwm restart`.
- **Another user** can bind the port while your ccwm is down, and then show a fake page. Your ccwm's
  sign-in links never go to it (`ccwm open` talks to the daemon over its Unix socket only), and a token it
  captures is useless to it (TCP peer check). It can still show you false information. Run ccwm as a
  service that starts at login so the port is yours. See [SECURITY.md](../SECURITY.md).

"another ccwm daemon is already running" (exit code **11**) means a daemon of yours holds the instance lock:
use it (`ccwm open`), or stop it (`ccwm stop`, or Ctrl-C in the terminal that runs `ccwm serve`).

## inotify limits

ccwm uses one inotify **instance** and, by default, up to 25 % of `fs.inotify.max_user_watches` **watches**.
Both pools are shared by every program of your user: editors, IDEs, file managers, sync tools.

| Symptom | Cause |
|---|---|
| `monitoring: none` in `ccwm status`, the DEGRADED banner, every project "polled" | no inotify instance left (`fs.inotify.max_user_instances` reached) |
| projects "partly watched" (normal) or "polled" (DEGRADED) | the watch budget or the kernel limit is reached |
| "recovering overflow" | the kernel's event queue overflowed (a huge burst of changes); the next reconciliation rescans |

Projects without a watch still work: their changes are found at the next reconciliation, 10 minutes by
default or `ccwm scan`. They are not live.

Check the limits and what your processes use:

```bash
cat /proc/sys/fs/inotify/max_user_watches /proc/sys/fs/inotify/max_user_instances
ccwm doctor        # counts the instances and watches your processes hold
```

Raising them needs an administrator. ccwm never changes kernel settings:

```bash
printf 'fs.inotify.max_user_watches=524288\nfs.inotify.max_user_instances=512\n' | sudo tee /etc/sysctl.d/90-inotify.conf
sudo sysctl --system
ccwm restart
```

Without root, you can lower ccwm's own use instead: exclude large trees (`discovery.exclude`), set a smaller
`watch.budget`, or close other watchers.

## The service keeps restarting: out of memory

```
$ systemctl --user status ccwm
… Failed with result 'oom-kill'.
… Scheduled restart job, restart counter is at 3.
```

The unit limits the daemon and its `git` and `claude` children to 2 GiB together, with no swap
(`MemoryMax=2G`, `MemorySwapMax=0`; [service.md](service.md#the-unit)). ccwm normally needs 20–30 MiB, so
reaching the limit means something unusual is on disk. The kernel then stops the service, and systemd starts
it again after 5 s, for as long as the cause is there.

- Look for it: `journalctl --user -u ccwm -n 50`, and, while the daemon is up, `ccwm status`. A line about
  **skipped `.gitignore` files** points at a tree with a very large number of ignore rules (the limits are
  256 KiB per file, 5,000 rules per project, 20,000 for all projects). Exclude that tree (`discovery.exclude`
  in `config.toml`, or Ignore the project), then `ccwm restart`.
- A very large Git repository can need hundreds of megabytes for one `git status`, and ccwm runs up to four
  at a time. If that is your case, raise the limit with a drop-in
  ([service.md](service.md#the-unit)): `systemctl --user edit ccwm`, `MemoryMax=4G`.
- To stop the restarts while you look: `ccwm stop`.

## Landlock unavailable or partial

`ccwm status` shows `sandbox: fully_enforced (abi 8, filesystem true, network tcp_only, seccomp socket_denied)` on a kernel
with Landlock. Other results:

| Report | Meaning |
|---|---|
| `not_enforced`, "Landlock is unavailable or disabled on this kernel" | the kernel lacks Landlock (before Linux 5.13), or it is not in the active LSM list |
| `partially_enforced`, `network none` | Landlock ABI < 4 (before Linux 6.7): no TCP confinement |
| `abstract_unix_socket false`, `signal false` | ABI < 6 (before Linux 6.12): no scoping |
| `not_enforced` with a note about threads or probes | a check showed that the sandbox does not hold; ccwm claims nothing |
| `unverified` (as the status, or for `filesystem`, `network`, `seccomp`), plus a `! unverified …` line | a self-check failed for an unexpected reason, so that protection is neither confirmed nor disproved. Example: a home directory on a file system without `O_TMPFILE` (some network file systems) makes the write check inconclusive. The reason is in `sandbox.notes` of `GET /api/v1/service/status` and in the daemon's log; `ccwm doctor` warns |

ccwm runs anyway and reports exactly what is active. To get it:

- Check `cat /sys/kernel/security/lsm`. `landlock` must be in the list. Distributions that build it but do
  not enable it need `lsm=landlock,…` on the kernel command line, keeping the existing modules in their
  order. Ask your administrator.
- Use a newer kernel for TCP rules (6.7+) and scoping (6.12+).

Without Landlock, the Git hardening (REQUIREMENTS.md §6) and the seccomp socket filter still apply. The
`claude --version`/`--help` check then runs **unconfined**, with your rights.

The seccomp filter (`seccomp: socket_denied`) needs a kernel with `CONFIG_SECCOMP_FILTER`, which every
mainstream distribution kernel has. With it, the daemon and its `git` and `claude` children can create no
socket and no socket pair after startup. If it is reported as `not_applied`, UDP and path-based Unix sockets
are listed as unconfined.

## `claude` not found or unverified

Resume commands are still shown, with a warning (`claude_not_found`, `claude_unverified`).

- Under systemd, the daemon's `PATH` is `~/.local/bin:/usr/local/bin:/usr/bin:/bin` (see
  [service.md](service.md#the-unit)). If `claude` is elsewhere, add a drop-in with `systemctl --user edit
  ccwm`, then `ccwm restart`. `ccwm doctor` tells you when your shell finds a `claude` that the daemon
  cannot.
- `failed`: the daemon runs `claude --version` inside its sandbox, which can only execute programs under
  your discovery roots, the session directory and the system paths (`/usr`, `/bin`, …). A `claude`
  installed elsewhere (e.g. `/opt`) cannot run there. The command is still shown.

## No projects appear

- Projects come from Claude Code sessions and from folders containing `CLAUDE.md`. See
  [discovery.md](discovery.md). `ccwm status` lists sessions that belong to no project, by reason and
  folder (e.g. `12 outside roots (/srv/work)`).
- A session in `/tmp`, in your home directory itself or in a parent folder of several projects (a
  "container") is never a project.
- Roots outside your home must be added in Settings or `config.toml`, and need a restart: the sandbox's
  read set is fixed at startup.
- `sessions: missing` means Claude Code's directory is not where ccwm looks. Set `sessions.dir`, or
  `CLAUDE_CONFIG_DIR` in the service environment.

## The browser says "Run `ccwm open`"

Sign-in links are single-use and valid for 30 s. Run `ccwm open` again. Use the address it opens
(`http://127.0.0.1:<port>`). `localhost` is a different origin, and the sign-in does not carry over.

## A refused start: "… can be modified by other users" / "is not owned by you"

ccwm refuses to use a configuration file or directory that another user could change, because they could
redirect it. Run the `chmod` the message suggests. Group write is acceptable only by your own private group.
