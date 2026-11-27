# Configuration reference

ccwm reads one file, `$XDG_CONFIG_HOME/ccwm/config.toml` (default `~/.config/ccwm/config.toml`), **when the
daemon starts**. A missing file means "all defaults". Unknown keys and out-of-range values are errors: the
daemon refuses to start and names the key. `config.example.toml` in the repository lists every key with its
default.

- The Settings page (`PUT /api/v1/settings`) rewrites the file atomically (mode 0600). It does not keep
  comments, and it overwrites edits you make by hand while the daemon runs. Stop ccwm first
  (`ccwm stop`) if you edit the file yourself.
- The file and every directory above it must be owned by you (or root) and not writable by other users.
  Group write is acceptable only for your private group. Otherwise ccwm refuses to read it.
- `ccwm serve --port N` and `ccwm serve --config PATH` override the port and the file location for one
  run. Settings never writes an override back.

**Live / restart.** Settings applies some keys while the daemon runs. The others are saved and marked
"takes effect after ccwm restart" (`ccwm restart`). Roots, exclusions, depth, file-system and session-directory
changes always need a restart: the Landlock sandbox's read set is fixed when the daemon starts and cannot
be widened afterwards.

| Key | Default | Range / values | Settings page | Applies |
|---|---|---|---|---|
| `server.port` | `8765` | 1024–65535 (`--port 0` = ephemeral, tests only) | yes | restart |
| `discovery.roots` | `[]` = your home directory | absolute paths | yes | restart |
| `discovery.exclude` | `[]` | gitignore patterns, 1–256 characters each, relative to each root | yes | restart |
| `discovery.max_depth` | `10` | 1–64 | yes | restart |
| `discovery.same_file_system` | `true` | bool | yes | restart |
| `discovery.scan_interval_secs` | `600` | 60–86400 | yes | live |
| `discovery.missing_retention_days` | `30` | 1–3650 | yes | live |
| `discovery.full_scan` ("Scan entire home") | `false` | bool | yes | live |
| `watch.budget` | `0` = 25 % of `fs.inotify.max_user_watches` (8192 if unreadable) | 0–1048576 | yes | restart |
| `watch.debounce_ms` | `2000` | 100–60000 | no (file only) | restart |
| `activity.inactive_after_days` | `7` | 1 ≤ inactive < dormant ≤ 3650 | yes | live |
| `activity.dormant_after_days` | `30` | see above | yes | live |
| `activity.events_per_project` | `200` | 1–10000 | no (file only) | restart |
| `git.allow_unhardened_status` | `false` | bool; see [SECURITY.md](../SECURITY.md) | no (file only) | restart |
| `sessions.dir` | unset = `$CLAUDE_CONFIG_DIR`, else `~/.claude` | absolute; not `/`, not an ancestor of home | yes | restart |
| `sessions.store_prompt_text` | `false` | bool; off deletes the cached prompts | yes | live |
| `ui.default_view` | `cards` | `cards`, `table` | yes | live |
| `ui.theme` | `system` | `system`, `light`, `dark` | yes | live |
| `ui.privacy` | `false` | bool (privacy-mode default for new browsers) | yes | live |
| `indicator.show_noninteractive` | `false` | bool: show `claude -p` and SDK sessions in the [session activity indicator](session-hooks.md) | yes | live |
| `indicator.live_first` | `true` | bool: projects with an open Claude Code session come first in the listing (needs approval, working, waiting, open), then the chosen sort | yes | live |

The Settings page accepts only the keys marked "yes". The others (`watch.debounce_ms`,
`activity.events_per_project` and especially `git.allow_unhardened_status`) can be changed only by editing
the file, so a stolen browser token cannot weaken the Git hardening permanently.

## Environment variables

| Variable | Effect |
|---|---|
| `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` | Where ccwm keeps its configuration (`…/ccwm/config.toml`), database (`…/ccwm/ccwm.db`) and state. Relative values are ignored, as the XDG specification requires. |
| `XDG_RUNTIME_DIR` | Lock, `instance.json` and the CLI's Unix socket (`…/ccwm/`). Without it, `$XDG_STATE_HOME/ccwm/run/` is used. The directory must be yours with mode 0700, and the socket path must be at most 107 bytes. |
| `CLAUDE_CONFIG_DIR` | Claude Code's config directory (sessions under `projects/`), unless `sessions.dir` is set. |
| `HOME` | Your home directory, if it is an absolute path to a directory you own; otherwise the passwd entry is used. |
| `CCWM_LOG` (or `RUST_LOG`) | Log filter, e.g. `info` (default), `debug`, `trace`. Session text, prompts, tokens and credentials are never logged at any level. |
| `NO_COLOR` | Plain log output. Under systemd (journald) logs are plain anyway. |

## Files ccwm writes

Only these, all private (directories 0700, files 0600):

| Path | Content |
|---|---|
| `~/.config/ccwm/config.toml` | Settings (only when you save them) |
| `~/.local/share/ccwm/ccwm.db` (+ `-wal`, `-shm`) | The index: projects, Git summaries, session aggregates, hashed browser-session tokens |
| `~/.local/state/ccwm/` | State directory (the runtime fallback lives here) |
| `$XDG_RUNTIME_DIR/ccwm/` | `ccwm.lock`, `instance.json`, `ccwm.sock` |

The installer also writes two files: `~/.local/bin/ccwm` and `~/.config/systemd/user/ccwm.service` (see
[service.md](service.md)). ccwm never writes into your projects or into Claude Code's directory. See
[data-retention.md](data-retention.md) for what the database holds and how to delete it.
