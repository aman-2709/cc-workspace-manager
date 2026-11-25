# Manual two-user verification

Security acceptance test 6 covers rejection of other users with **simulated** peer-UID mismatches
(`tests/http.rs`, `tests/ipc.rs`). This procedure checks the same rejections with a **real second local
account**. It needs an administrator to create the account. **Status: not run yet.** Record the date,
host and result in the release notes when you run it.

Use a synthetic environment for ccwm (no real projects or sessions are needed for these checks), or
your normal installation.

## Setup

1. As an administrator, create a throw-away account: `sudo adduser ccwm-other` (or `useradd -m`).
2. As **you** (user A), start ccwm and note the port: `ccwm start` (or `ccwm serve`), then `ccwm status`.
   The examples assume port 8765.
3. Get a sign-in link without using it: `ccwm open --print`. Copy the `#bt=` token. It is valid for
   30 s: use it in check 2 within that time, or get a new link.
4. In your browser, sign in with a second `ccwm open`. Copy the session token: devtools →
   Application → Local Storage → `http://127.0.0.1:8765` → `ccwm.session` (the `token` field).

## Checks (as user B: `sudo -iu ccwm-other`)

| # | Command (as B) | Expected |
|---|---|---|
| 1 | `curl -sv http://127.0.0.1:8765/api/v1/health` | connection closed without an HTTP response (`Empty reply from server`). The TCP peer check runs before a byte is read, on every endpoint, `/health` included. |
| 2 | `curl -sv -H 'Origin: http://127.0.0.1:8765' -H 'Content-Type: application/json' -d '{"bootstrap_token":"<token from step 3>"}' http://127.0.0.1:8765/api/v1/auth/exchange` | connection closed, no response: a leaked sign-in link is useless to another user |
| 3 | `curl -sv -H 'Authorization: Bearer <session token from step 4>' http://127.0.0.1:8765/api/v1/projects` | connection closed, no response: a leaked session token is useless too |
| 4 | `ls -ld /run/user/$(id -u A)/ccwm` (A's uid) | permission denied, or mode `drwx------` owned by A: B cannot reach A's socket directory |
| 5 | `python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/user/<A uid>/ccwm/ccwm.sock')"` | `PermissionError` (the runtime directory is 0700). If an administrator relaxed the directory, the daemon still closes the connection silently (SO_PEERCRED check) |
| 6 | `ls -l ~A/.local/share/ccwm/` | permission denied (0700 directory, 0600 files) |
| 7 | as B: `XDG_RUNTIME_DIR=/run/user/<A uid> ccwm status` | refused before connecting: "cannot inspect …: Permission denied" or "… is not owned by the current user" (the CLI verifies the runtime directory) |

Then, as **A**, check that nothing was served to B:

- `journalctl --user -u ccwm | grep 'rejected a TCP connection'` shows the rejected connections (logged
  at most once a minute, with counts and no content).
- The dashboard still works for A (the rejections did not lock A out).

## Impostor check (port taken while A's ccwm is down)

1. As A: `ccwm stop`.
2. As B: `python3 -m http.server 8765 --bind 127.0.0.1` (a stand-in impostor).
3. As A: `ccwm open`. Expected: it refuses ("not running" / cannot reach the socket) and never sends
   anything to B's listener (B's server log shows no request). `ccwm serve` fails with exit code 10
   ("port 8765 is already in use").
4. Stop B's server. As A: `ccwm start`.

## Clean up

`sudo deluser --remove-home ccwm-other`. Write down the result of each row in the release notes.
