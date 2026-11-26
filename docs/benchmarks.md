# Benchmarks

Measured on 2026-11-24 with `scripts/bench.py` against a release build of the M4 tree (`ccwm 0.1.0`, built
from `93f6d2f` plus the uncommitted M4 changes). Synthetic data only (REQUIREMENTS.md §19): no real home, projects
or sessions were involved. The targets (§15) are idle CPU under 1 % averaged over 10 minutes, and RSS under
50 MB with 200 projects. Every number below was measured once on this host. Treat them as one data point,
not a guarantee for other machines.

## Host

| | |
|---|---|
| CPU | Intel Core i7-8700K @ 3.70 GHz (6 cores / 12 threads) |
| Memory | 62.6 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS, Linux 7.0.0-34-generic |
| Storage | NVMe, ext4 (`/tmp` is on it, not tmpfs) |
| inotify | `max_user_watches` 65536 (so ccwm's default budget is 16384) |
| Load | a normal desktop session; other programs held ~109 of 128 inotify instances |

## Method

`scripts/bench.py --bin target/release --projects 500 --idle 600 --budget 1000 --sessions-mb 500`, plus a
separate `--only projects --projects 200 --idle 600` run. Both ran at the same time, in separate synthetic
environments. Each scenario:

1. generates a synthetic environment with `ccwm-synth` under `/tmp`;
2. gives every bulk project a small tree (7 folders, 16 files, `.gitignore`), and makes every fifth one a real
   Git repository with one commit;
3. starts the real `ccwm serve --port 0`, measuring from the moment of the process spawn.

CPU is the daemon's `utime + stime`, plus its reaped children (Git), from `/proc/<pid>/stat`. Memory is
`VmRSS` / `VmHWM` from `/proc/<pid>/status`. Watch counts and scan progress come from the daemon itself over its
Unix socket, and the burst check uses the HTTP API, signed in like a browser. "Quiet" means the daemon and its
children used no CPU for 5 s. The quiet window itself is not counted in the times below. The page cache was
warm: files were read right after they were written, and dropping caches needs root.

## Results

### Projects: discovery, memory, watches, idle

| | 200 projects | 500 projects |
|---|---|---|
| projects found (incl. the 8 fixture projects) | 208 | 508 |
| folders visited by the first scan | 1,828 | 4,528 |
| first scan finished after start | 0.18 s | 0.36 s |
| CPU quiet after start (Git status of every repository done) | 0.68 s | 1.87 s |
| CPU used until quiet (daemon / Git children) | 0.31 s / 0.39 s | 0.77 s / 1.03 s |
| inotify watches (budget 16,384) | 1,870 | 4,630 |
| projects watched / partly watched / polled | 209 / 0 / 0 | 509 / 0 / 0 |
| RSS after start (peak) | **17.6 MiB** (17.6 MiB) | 21.4 MiB (21.4 MiB) |
| threads | 25 | 25 |
| **idle CPU over 600 s** | **0.02 s = 0.003 % of one core** | **0.06 s = 0.01 % of one core** |
| RSS after the idle window | 16.4 MiB | 20.4 MiB |
| SIGTERM to exit | 0.02 s, exit 0 | 0.03 s, exit 0 |

Both targets are met with a wide margin: RSS 17.6 MiB against < 50 MB at 200 projects, and idle CPU
0.003–0.01 % against < 1 %. The 600 s window can include the one scheduled reconciliation
(`scan_interval_secs = 600`).

**Found and fixed by this benchmark.** The first run peaked at **517 threads** and 30.7 MiB at 500 projects,
because every Git refresh parked a blocking-pool thread while it waited for a database read connection. The
reader now takes an async permit per connection first (ARCHITECTURE.md §5). That run gave 25 threads and
21.4 MiB.

### Burst: 10,000 files created at once (500 projects, 20 each)

| | |
|---|---|
| time to write the files | 0.41 s |
| daemon quiet again after the burst started | 2.91 s (including the 2 s debounce) |
| CPU used by the daemon for the burst | 1.52 s |
| inotify queue overflows | 0 |
| projects showing the new *observed* activity | 500 of 500 |
| peak RSS during/after the burst | 25.0 MiB |

### Watch exhaustion and recovery (500 projects, `watch.budget = 1000`)

| | |
|---|---|
| watches in use | 1,000 (the budget) |
| projects watched / partly watched / polled | 3 / 506 / 0 — every project root is watched first (breadth first), so nothing is fully polled |
| DEGRADED | no (partly watched is normal operation) |
| reconciliation (`scan.refresh`, polls the unwatched subtrees) | 0.2 s |
| then: 400 projects deleted, two reconciliations (0.1 s each) | 931 watches; 109 watched / 0 partly watched / 0 polled — the refused subtrees were re-watched as budget freed up |

The kernel limit itself (`max_user_watches`) was not exhausted: raising or lowering it needs root. The
budget path is the same code (`ENOSPC` is handled like a full budget; see `tests/watch.rs`).

### Sessions: ~500 MiB of synthetic session files

The files use the verified record shapes (ARCHITECTURE.md §11): typed prompts, assistant text and thinking,
`tool_use`, tool results with `toolUseResult` (most of the bytes), system and `file-history-snapshot`
records, and an `ai-title` at the end. There were 93 files: one of 60 MiB (the largest real file seen was
76 MB) and 92 of 2–8 MiB, 506 MiB in total, plus the 7 fixture sessions.

| | |
|---|---|
| all 100 sessions indexed after start, from an empty database | 0.46 s |
| CPU (daemon + Git children, including discovery and Git of the 58 projects) | 0.40 s |
| peak RSS | 14.2 MiB |
| restart (checkpoints: nothing re-parsed): first scan finished | 0.14 s, CPU 0.32 s |
| 8 MiB appended to the largest file: refresh | 0.1 s, CPU 0.03 s |

The parse is cheap because the allowlist parser skips the large strings (tool results, assistant text)
without materializing them. Most of the CPU above is the daemon's normal startup work, which a restart that
parses nothing also costs. A separate check (`--sessions-mb 120 --keep`, then reading the index) confirmed
that every file was parsed to its last byte: the checkpoint offset equals the file size, the checkpoint is
not partial, and the end-of-file title was stored. With a cold page cache, reading 500 MiB from disk would
add the storage's read time. That was not measured.

### Ignore rules at their limits

Measured on 2026-11-26 with `ccwm 0.1.1` (`scripts/bench.py --only ignore`), on the same host. This is not
normal use: it is the most that ccwm's limits on ignore files allow (256 KiB per file, 5,000 rules per
project, 20,000 rules for all projects), with rules that all need a regular expression — the expensive
kind; ordinary rules such as `target/` or `*.log` cost almost nothing. Six projects, each with a `.git`
and a `.gitignore` of 5,000 rules of the shape `*1x7?b[c-d]*.x`, so four projects fill the limit across
projects and the files of two are skipped. Two builds: `target/release` (glibc) and the static
`x86_64-unknown-linux-musl` binary that releases ship.

| | glibc build | musl binary (release) |
|---|---|---|
| ignore files skipped / rules kept | 2 / 20,000 | 2 / 20,000 |
| first scan finished after start (the rules are compiled in it) | 5.3 s | 5.7 s |
| RSS with every project watched (peak) | **343.7 MiB** (343.7 MiB) | **391.4 MiB** (394.8 MiB) |
| every project polled (`watch.budget = 1`): ten more scans, each | 0.1 s | 0.1 s |
| RSS after the first and after the tenth of those scans | **343.8 MiB → 344.7 MiB** | **380.6 MiB → 380.7 MiB** |
| peak RSS in that run | 344.7 MiB | 384.3 MiB |

That is 17–20 KiB per rule kept, and it stays there: the compiled rules of an ignore file are kept and
used again until the file changes (its device, inode, size, modification time or change time), so a scan of projects
whose ignore files are as they were compiles nothing. Polled projects are the case that shows it: they
are walked again at every scan.

**Before the rules were cached** (the first 0.1.1 build, same fixture) every such scan compiled all 20,000
rules again, 5–6 s each, next to the ones they replaced. The musl binary gave the memory back (peak 775 MiB,
395–399 MiB after each scan). The glibc build did not: 672, 1,002, 1,332 and 1,661 MiB after scans 1 to 4.
With a smaller set (6 projects of 500 such rules, about 60 MiB kept) the glibc build reached 633 MiB after
30 scans. That measurement is why the cache exists.

The same check is a test (`tests/process.rs`, four polled projects of 400 such rules, twelve scans, memory
must not grow by more than 4 MiB): it passes for the glibc and for the musl target, and fails with reuse
switched off (99 MiB → 244 MiB in ten scans, glibc). Not measured: a pattern built to make the matcher
itself use as much memory as it can; ignore files that change at every scan (each change compiles that
file again, next to the rules it replaces, one project at a time).

The systemd unit carries a hard limit all the same, `MemoryMax=2G` with `MemorySwapMax=0`
([service.md](service.md#the-unit)): far above normal use (17–26 MiB in the tables above) and above this
worst case. With the cache it can be lower; that is planned (ROADMAP.md). A short re-run of the
500-project scenario with 0.1.1 gave 21.6 MiB after start and a 25.8 MiB peak in the 10,000-file burst
(0.1.0: 21.4 and 25.0).

## Reproducing

```bash
cargo build --release --bins
scripts/bench.py --bin target/release                        # ~15 minutes (10 of them idle)
scripts/bench.py --bin target/release --idle 0 --only burst,exhaustion
scripts/bench.py --bin target/release --only ignore          # the ignore-rule limits, under a minute
```

The script prints one JSON document (host, method, every measurement). Keep raw results out of the
repository (`/bench-results/` is gitignored).
