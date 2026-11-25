# CC Workspace Manager (`ccwm`)

Discover, track, and resume your Claude Code projects.

CC Workspace Manager is an **independent, unofficial** open-source project. Claude and Claude Code are trademarks of Anthropic, PBC. This project is independent and not affiliated with or endorsed by Anthropic.

`ccwm` is a small local daemon with a browser dashboard. It finds the folders on your machine that are Claude Code projects (from your Claude Code sessions, and folders that contain a `CLAUDE.md`), shows which ones you worked on recently, what their Git state is and where you left off, and gives you the command to resume the last session. It is a project-centric workspace manager, not a token or cost dashboard.

> **Status: pre-release (milestone M3 of 4).** Discovery from sessions and `CLAUDE.md` files, live activity tracking, Git status, session titles, the last prompt and resume commands, privacy mode and Settings work. Packaging, the systemd unit and release binaries arrive in M4. Only Linux x86_64 (Ubuntu 24.04) has been tested.

## What it does today

- Finds projects from your Claude Code sessions (the folder each session started in, resolved to its Git repository) and from `CLAUDE.md` files under your home directory (configurable roots), skipping hidden, generated and dependency folders.
- Shows each project's latest session (its AI title as recorded by Claude Code), the last prompt (read from the session file when you open the details, redacted, not stored) and a resume command to copy (`cd -- '<folder>' && claude --resume <id>`); ccwm never runs it.
- Privacy mode hides paths, user names, remote URLs, titles, prompts and commands (enforced by the server); a Settings page edits the configuration.
- Tracks the latest meaningful file change per project, live (inotify, non-recursive watches, a watch budget) with a fallback to periodic checks; `.gitignore`d files and `.git/` do not count.
- Shows branch, ahead/behind, staged/modified/untracked counts and the latest commit, read with hardened, allowlisted Git commands.
- Card and table views with search, sort and filters; projects that disappear are marked missing, never silently deleted; projects can be ignored.

## Privacy and security in one paragraph

ccwm reads your projects; it never modifies them, pushes them, or sends anything anywhere. The only network traffic is loopback HTTP/WebSocket to your browser. The daemon confines itself with Landlock (read-only on your projects, no outbound TCP), runs Git with repository-defined helpers neutralised, and serves only connections that belong to your own user. See [SECURITY.md](SECURITY.md) for the threat model and the residual risks.

## Quick start (from source)

Requires Rust 1.94 and Linux. `git` is optional.

```bash
cargo build --release
target/release/ccwm serve            # the daemon, in the foreground (port 8765)
target/release/ccwm open             # in another terminal: opens the dashboard, signed in
target/release/ccwm status           # daemon state, build commit, monitoring, sandbox
target/release/ccwm scan             # rescan now and wait for it
```

To try it without touching your real home directory, use the synthetic environment:

```bash
cargo build
target/debug/ccwm-synth /tmp/ccwm-demo --projects 30
env $(cat /tmp/ccwm-demo/env) target/debug/ccwm serve --port 8766 &
env $(cat /tmp/ccwm-demo/env) target/debug/ccwm open --print
```

Configuration: `config.example.toml`. Documentation: [REQUIREMENTS.md](REQUIREMENTS.md) (the specification), [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). Release archives (M4) will include the licenses of all bundled dependencies (`THIRD_PARTY_LICENSES`).
