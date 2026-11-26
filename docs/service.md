# Running ccwm as a service

ccwm runs as a **systemd user service**. It belongs to your user, needs no root, and starts when you log
in. Everything below uses `systemctl --user`. ccwm never runs `sudo` or `loginctl`.

## Install, upgrade, uninstall

From a release archive (`ccwm-<version>-x86_64-unknown-linux-musl.tar.gz`):

```bash
sha256sum -c SHA256SUMS            # both files from the release page, in the same folder
tar -xzf ccwm-0.1.1-x86_64-unknown-linux-musl.tar.gz
cd ccwm-0.1.1-x86_64-unknown-linux-musl
scripts/install.sh                 # copies ./ccwm to ~/.local/bin, installs and starts the unit
ccwm open                          # sign in in your browser
```

`scripts/install.sh [PATH/TO/ccwm]` does this:

1. It copies the binary to `~/.local/bin/ccwm`, atomically, so a running daemon is not disturbed.
2. It runs `ccwm service install`. That writes `~/.config/systemd/user/ccwm.service`, then runs
   `systemctl --user daemon-reload` and `systemctl --user enable --now ccwm.service`.
3. It restarts the service if it was already running (an upgrade).

Running it again is safe. To upgrade, run the new archive's `install.sh`.

`scripts/uninstall.sh` runs `ccwm service uninstall` (`disable --now`, remove the unit, `daemon-reload`), then
removes `~/.local/bin/ccwm`. **Your data is kept.** `scripts/uninstall.sh --purge` also deletes ccwm's
configuration, database and state, after you type `yes`. It deletes `~/.config/ccwm`, `~/.local/share/ccwm`,
`~/.local/state/ccwm` and `$XDG_RUNTIME_DIR/ccwm`, or their `$XDG_*` equivalents. Your projects and Claude
Code sessions are never touched.

The same steps without the scripts:

```bash
install -D -m 0755 ./ccwm ~/.local/bin/ccwm
ccwm service install
ccwm service uninstall            # keeps your data
ccwm service uninstall --purge    # removes the service, then asks before deleting ccwm's data
```

## Everyday commands

| Command | What it does |
|---|---|
| `ccwm start` / `ccwm stop` / `ccwm restart` | `systemctl --user start|stop|restart ccwm.service`, then waits until the daemon answers on its socket (or has released its lock). Fails with a hint if the unit is not installed. |
| `ccwm status` | The unit's state (`active (enabled)`, …) and the daemon's state: port, discovery, monitoring, Git, `claude`, sandbox, sessions. Warns if the daemon runs a different build than the CLI. |
| `ccwm doctor` | Checks the installation and suggests fixes (inotify limits, Landlock, Git, `claude`, the session directory, permissions, the port, lingering). It changes nothing. |
| `ccwm open` | A single-use sign-in link (30 s) for the dashboard. `--print` prints it instead of opening a browser. |
| `ccwm scan` | Rescan now and wait for it. |
| `ccwm auth revoke-all` | Sign out every browser. |
| `systemctl --user enable ccwm` / `disable ccwm` | Start (or stop starting) at login. |
| `journalctl --user -u ccwm -f` | Follow the logs (journald). |

## Foreground mode

`ccwm serve` runs the daemon in your terminal. That is what the unit runs, too. Stop it with Ctrl-C:
SIGTERM and SIGINT shut it down gracefully, flushing the database and closing the watchers. Options:
`--port N`, `--config PATH`. Only one daemon runs per user: a second one exits with code 11.

## Exit codes

| Code | Meaning | systemd |
|---|---|---|
| 0 | clean shutdown | — |
| 1 | any other error (the message says which) | restarted after 5 s (`Restart=on-failure`) |
| 10 | the port is used by another process | **not** restarted (`RestartPreventExitStatus=10 11`) |
| 11 | another ccwm daemon holds the instance lock | **not** restarted |

ccwm never picks another port on its own. See [troubleshooting.md](troubleshooting.md#port-already-in-use).

## Start at login vs. at boot

A user service starts with your **user manager**, which systemd starts when you log in and stops after
your last session ends. So by default ccwm runs while you are logged in. That is usually what you want:
the dashboard is for you, in your browser.

To start it at **boot**, before you log in, and keep it running after you log out, enable
**lingering** for your user:

```bash
loginctl enable-linger "$USER"     # may require administrator authorization, depending on polkit policy
loginctl show-user "$USER" --property=Linger
```

ccwm never runs this for you. `ccwm doctor` reports whether lingering is enabled, and `loginctl
disable-linger "$USER"` turns it off.

## The unit

`ccwm service install` writes this unit. Run `systemctl --user cat ccwm` to see what is installed.

```ini
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=10

[Service]
Type=exec
ExecStart=%h/.local/bin/ccwm serve
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=10 11
TimeoutStopSec=10
MemoryMax=2G
MemorySwapMax=0
OOMPolicy=continue
UMask=0077
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
SystemCallArchitectures=native

[Install]
WantedBy=default.target
```

Notes:

- **`Environment=PATH`**: the user manager's default `PATH` usually lacks `~/.local/bin`, where Claude
  Code's installer puts `claude`. ccwm checks `claude --resume` support at startup. If your `claude` lives
  elsewhere (an npm prefix, nvm), add a drop-in with `systemctl --user edit ccwm`:
  ```ini
  [Service]
  Environment=PATH=%h/.npm-global/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin
  ```
  Drop-ins survive a reinstall. `ccwm doctor` tells you when the daemon cannot find `claude` but your
  shell can.
- **`MemoryMax=2G` and `MemorySwapMax=0`** (since 0.1.1): the most memory the daemon and its `git` and
  `claude` children may use together, with no swap on top. It is a backstop, not a working size: ccwm
  normally needs 20–30 MiB, and the worst case its own limits allow was measured at about 490 MiB at the
  peak with the release binary (392 MiB of kept rules, plus one project's worth while a project without
  its rules is scanned with them; [benchmarks.md](benchmarks.md#ignore-rules-at-their-limits)). If the
  limit is ever reached, the kernel kills the largest process of the unit: a `git` or `claude` child then
  fails like any failed command and the daemon goes on (`OOMPolicy=continue`); a killed daemon is started
  again after 5 s ([troubleshooting.md](troubleshooting.md#the-service-keeps-restarting-out-of-memory)). `MemorySwapMax=0`
  belongs to it: on a machine with swap, `MemoryMax=` alone does not stop anything, it only moves the excess
  to swap. To use another limit, add a drop-in with `systemctl --user edit ccwm`:
  ```ini
  [Service]
  MemoryMax=512M
  ```
  (`MemoryMax=infinity` removes the limit.) Then `ccwm restart`. Check what applies with
  `systemctl --user show ccwm -p MemoryMax -p MemorySwapMax`. The limit needs the cgroup **memory
  controller** for your user manager: `cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers`
  must list `memory` (it does on Ubuntu 24.04). Without it, systemd accepts the directives and they do
  nothing. A daemon started by hand (`ccwm serve`) has no such limit.
- **`OOMPolicy=continue`** (since 0.1.1): systemd's default for a process of the unit that the kernel
  kills at the limit is to stop the whole unit. ccwm treats a `git` or `claude` that fails as a status,
  so only the process that was killed ends. Verified with the real daemon in a transient user unit under
  `MemoryMax=64M`: a `claude --version` that allocated 300 MiB was killed, the daemon kept running with
  the same process id; with the default policy the unit failed with `oom-kill` and was restarted.
- **`StartLimitIntervalSec=10min` and `StartLimitBurst=10`** (since 0.1.1, in `[Unit]`): a daemon that
  fails ten times in ten minutes stays stopped (`failed`, shown by `ccwm status`) instead of being
  restarted for ever; with `RestartSec=5`, systemd's own default (5 starts in 10 s) can never be reached.
  Starts by hand (`ccwm start`, `ccwm restart`) count too. After fixing the cause:
  `systemctl --user reset-failed ccwm`, then `ccwm start`.
- **What is not used, and why.** `ProtectSystem=`, `ProtectHome=` and `PrivateTmp=` make systemd run a
  *user* service inside a user namespace. There, root-owned paths such as `/` and `/home` appear to be
  owned by `nobody` (uid 65534). ccwm refuses to trust directories other users could own, so it would not
  start (verified with systemd 255). `MemoryDenyWriteExecute=` is inherited by `claude --version`, whose
  JavaScript runtime needs it off. `PrivateDevices=` is rejected in user units.
- The daemon confines itself with **Landlock** and a **seccomp** socket filter (see
  [SECURITY.md](../SECURITY.md)). These apply whether or not systemd runs it.

## Tested

The unit's directives were run with the real daemon, in a synthetic environment, as a transient user unit
on Ubuntu 24.04 with systemd 255. `systemd-analyze --user verify` accepts the generated unit. For the memory
limit (0.1.1), with the static release binary: the unit's cgroup shows `memory.max = 2147483648` and
`memory.swap.max = 0`; the daemon runs fully sandboxed under them and stops cleanly; with the limit lowered
to 200M and content that needs about 390 MiB, the unit ends with `oom-kill` and is restarted every few
seconds, and with 2G the same content runs at 384 MiB with no swap in use. The scripts and
the service commands are tested end to end with a stand-in `systemctl` (`tests/service.rs`). Installing
from the release archive on a fresh account, and starting at boot with lingering, are manual steps in
[release-checklist.md](release-checklist.md). They have not been run yet.
