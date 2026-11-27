# Data retention and deletion

ccwm stores an **index**, never copies of your work. Everything is in `~/.local/share/ccwm/ccwm.db`
(SQLite; plus `-wal`/`-shm` while it runs), mode 0600, in a 0700 directory. Nothing leaves your machine.

## What is stored

| Data | Kept until |
|---|---|
| Projects: canonical path, name, discovery sources, first/last seen, the SHA-256 of `CLAUDE.md` (to recognise moves), latest meaningful change (time, relative file path) | the project is missing for `missing_retention_days` (default 30), or you **Forget** it |
| Recent file events per project: time, kind, relative path | the newest `activity.events_per_project` (200) are kept |
| Git summary per project: branch, upstream, counts, up to 200 file paths per list, latest commit (hash, subject, author, time), remote URL **without credentials** | the next refresh replaces it; deleted with the project |
| Session aggregates: id, file path, first/last cwd, start/last activity, AI title (redacted, ≤ 300 characters), branch, version, entrypoint, continuation links, unassigned reason, parse checkpoint | the session file disappears, **Clear session index**, or a parser upgrade (rebuilt from the files) |
| Last prompt text (redacted, ≤ 2,000 characters) | **only if "Store prompt text" is on**; turning it off deletes it |
| Open sessions of the activity indicator (v0.2, only with its hooks added): session id, the Claude Code process (pid, start time, boot id), the session's first working folder, when it opened — **no** prompt, state or text | the session closes (its `SessionEnd`, or its process exits), **Clear session index**, or a reboot (dropped at the next start) |
| The last 256 hook events (`ccwm hooks events`): time, event name, session id, outcome | in the daemon's memory only; gone at a restart |
| Ignored paths | you un-ignore them |
| Browser sessions: SHA-256 of the token, timestamps | 30 days after last use, sign-out, `ccwm auth revoke-all`, or LRU beyond 10 |

**Never stored:** full transcripts, assistant responses, tool inputs or outputs, API payloads, account or
organization ids, and prompts (unless you opt in). Tokens are never stored in plain text. Logs (journald)
never contain session text, prompts, tokens or credentials, and remote URLs are logged redacted.

## Deleting

| Action | Effect | Touches your files? |
|---|---|---|
| Settings → **Store prompt text** off | deletes every cached prompt | no |
| Settings → **Clear session index** | deletes every session aggregate and the open sessions of the activity indicator; projects stay; the next scan re-reads the session files from byte 0 | no |
| **Forget** (missing projects only) | removes the project from the index; its sessions are resolved again | no |
| **Ignore** | hides a project and stops tracking it | no |
| `ccwm auth revoke-all` / Sign out | revokes browser sessions | no |
| `ccwm service uninstall --purge` (`scripts/uninstall.sh --purge`) | after you type `yes`: deletes `~/.config/ccwm`, `~/.local/share/ccwm`, `~/.local/state/ccwm` and `$XDG_RUNTIME_DIR/ccwm` | no |
| delete `ccwm.db` while ccwm is stopped | a full re-index on the next start | no |

Deleted session data does not linger: SQLite overwrites deleted content (`secure_delete`), and after
clearing prompts or the session index, the write-ahead log is checkpointed and truncated. Copies made
earlier by backups or snapshots of your home directory are outside ccwm's control.

Security acceptance tests 2 and 10 check that clearing the index, deleting the database (with a full
re-ingest), and `service uninstall --purge` leave your projects and Claude Code's session files
byte-identical (content, mode, mtime, ctime, inode).
