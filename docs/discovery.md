# How ccwm finds and tracks projects

This summarizes REQUIREMENTS.md §4–§7 (the specification wins where they differ).

## What is a project

A folder is a project if **either**:

1. **A Claude Code session started in it.** ccwm reads the first working directory (`cwd`) recorded in
   each session file (`<Claude config dir>/projects/*/<session-id>.jsonl`). It walks up from there to the
   nearest folder that is a Git work-tree root (has `.git`) or has a `CLAUDE.md`. It never goes up to your
   home directory. A cwd with neither above it is a *session-only* project, unless projects, markers or
   Git repositories lie below it (then it is a "container", e.g. a session started in `~/dev`, and the
   session stays unassigned).
2. **It contains a file named exactly `CLAUDE.md`** (case-sensitive; a symlink counts if it resolves to a
   regular file inside the same folder).

Sessions are the primary source. The `CLAUDE.md` walk covers every root once (the first launch), then
only the *development roots*: the parent folders of session-discovered projects, 3 levels deep. Turn on
"Scan entire home" (`discovery.full_scan`) to walk every root at every scan.

**Nested folders.** A `CLAUDE.md` inside another project is that project's nested instruction file. It
becomes a separate project only if it has its own Git work tree. File activity inside a nested project
counts only for the nested project.

**Never a project:** your home directory itself, `~/.claude` (Claude Code's config directory), anything
under `/proc`, `/sys`, `/dev`, `/run` or ccwm's own directories, and folders you ignore.

**Unassigned sessions** are counted by reason in `ccwm status` and the discovery status: `no_cwd`,
`nonexistent`, `home`, `temporary` (`/tmp`, `/var/tmp`, `/dev/shm`, `$TMPDIR` outside home),
`outside_roots`, `excluded`, `container`. They are checked again at every scan. A session whose first cwd can
never name a project while the daemon runs (excluded, outside the roots, home, temporary) is read only up
to that cwd.

## Roots and exclusions

The default root is your home directory. ccwm skips, **before** descending:

- hidden folders (`.*`: `.git`, `.cache`, `.local`, `.config`, `.venv`, browser profiles, …);
- `node_modules`, `target`, `build`, `_build`, `dist`, `venv`, `__pycache__`, `VirtualBox VMs`, and
  `~/snap` in your home;
- FUSE mounts (cloud-sync and other user-space file systems), other file systems (with
  `same_file_system = true`), folders deeper than `max_depth`;
- your own `discovery.exclude` patterns (gitignore syntax, relative to each root);
- paths that are not valid UTF-8 (counted as `non_utf8`).

Symlinked folders are never followed. Folders that cannot be read are counted and listed ("1 folder could
not be read"). Discovery never stops because part of the tree fails.

## Lifecycle

- **First launch:** the dashboard starts at once. Projects appear progressively: sessions first, then the
  full `CLAUDE.md` walk. **Later launches** show the cached projects immediately and reconcile in the
  background.
- **Reconciliation** runs every `scan_interval_secs` (default 10 minutes), never overlapping. `ccwm scan`
  or the refresh button starts one now.
- **New projects** appear live: a new `CLAUDE.md` in a watched folder, or a new session (the session
  folders are watched). Elsewhere they appear at the next reconciliation.
- **Missing:** a project whose folder is gone is marked *missing* (the "Missing only" filter). It is
  forgotten from ccwm's index after `missing_retention_days` (default 30), or right away with **Forget**.
  Your files are never touched. A folder that comes back revives the project with its id.
- **Moves:** paired rename events keep the project's id. Without them, a new project with the same Git HEAD
  and remote (or the same `CLAUDE.md` content, for non-Git projects) as exactly one missing project takes
  over that project's id.
- **Ignore** hides a project permanently (stored by path; un-ignore it in Settings).

## Activity

The *latest meaningful change* is the newest change to a file that is not excluded, not in a nested
project, not under `.git/` and (for Git projects) not gitignored. It is computed in-process with the
`ignore` crate's matcher, which approximates Git (the user's global `core.excludesFile` is not applied in
v0.1). Hidden files count; creating or removing a folder counts as activity. The first value comes from a
walk at discovery and is marked *inferred* (`≈`). Values seen live are *observed*.

Buckets use local calendar days: **Today** (0), **Recent** (1–6), **Inactive** (7–29), **Dormant** (30+),
**Unknown**. "Modified this week" is Today + Recent. The thresholds are configurable.

## Watching (inotify)

ccwm uses **one** inotify instance and **non-recursive** watches on eligible folders only. Its budget is
25 % of `fs.inotify.max_user_watches` by default, because IDEs and other tools share that pool. The budget
is spent breadth first: every project root, the parents of project roots (to notice new sibling
projects), each project's `.git` and top-level folders, then deeper folders of the most recently active
projects. Folders without a watch are checked by modification time at each reconciliation:

- *partly watched*: the root is watched, some subfolders are not (normal operation, not degraded);
- *polled*: no watch at all (no inotify instance, or the budget ran out before the root);
- **DEGRADED** means a real failure: no inotify instance, a queue overflow being recovered, or polled
  projects. See [troubleshooting.md](troubleshooting.md#inotify-limits) for raising the limits.

A project tree with more than 100,000 entries is not walked completely: it is partly watched (what was
walked is watched live) and the whole tree is checked at each scan.

**Limits on ignore files.** ccwm reads `.gitignore` files and `.git/info/exclude` to decide what counts as
activity. A file larger than 256 KiB is skipped, and so is every further file once a project's ignore files
reach 1 MiB or 5,000 rules together, or once all projects together hold 20,000 rules (since 0.1.1). That
last limit goes to the most recently active projects: when the rules do not fit all, the least recently
active projects are the ones without, and a project that becomes active again gets its rules back at the
next scan (a project that is ignored or gone frees its share). A skipped
file's rules do not apply, so files it would ignore count as activity; `ccwm status` says how many files were
skipped. Ordinary projects have a few dozen rules each, so the limit across projects is far away for a few
hundred of them. The rules of an ignore file are compiled once and used again until the file changes
(another size, modification time or change time, or another file under that name). While a project is
without its rules because of the limit across projects, scans do not move its "last change" (they could
not tell ignored files from the others); changes seen live are recorded as always. The rules of a repository apply only if its `.git`
is yours and lies inside the project's discovery root.

## Git

Branch, upstream, ahead/behind, staged/modified/untracked counts and the latest commit are read with an
allowlist of hardened read-only Git commands (REQUIREMENTS.md §6, SECURITY.md). Git status is refreshed
when `.git` changes, on activity and at reconciliation, at most 4 commands at a time with a 5 s timeout
each.

## Sessions

Session files are parsed incrementally (a checkpoint per file: device, inode, size, offset, mtime), with an
8 MiB line cap. Only allowlisted fields are read (REQUIREMENTS.md §7.1). Stored: times, first and last
cwd, the latest AI title (redacted), branch, Claude Code version, continuation links. Prompts are read
from the file on demand and never stored unless you enable "Store prompt text". When a ccwm upgrade
changes the parsing rules, the session index is rebuilt from the files on the next start.
