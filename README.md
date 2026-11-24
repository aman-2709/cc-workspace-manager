# CC Workspace Manager (`ccwm`)

Discover, track, and resume your Claude Code projects.

CC Workspace Manager is an **independent, unofficial** open-source project. Claude and Claude Code are trademarks of Anthropic, PBC. This project is independent and not affiliated with or endorsed by Anthropic.

`ccwm` is a small local daemon with a browser dashboard. It finds the folders on your machine that are Claude Code projects (they contain a `CLAUDE.md`), shows which ones you worked on recently and what their Git state is, and keeps that list current as you work. It is a project-centric workspace manager, not a token or cost dashboard.

> **Status: pre-release (milestone M2 of 4).** Discovery, live activity tracking, Git status, the card and table views and live updates work. Session integration, resume commands, privacy mode and Settings arrive in M3; packaging, the systemd unit and release binaries in M4. Only Linux x86_64 (Ubuntu 24.04) has been tested.

## What it does today

- Finds every directory with a `CLAUDE.md` under your home directory (configurable roots), skipping hidden, generated and dependency folders.
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
