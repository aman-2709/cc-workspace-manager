//! `/proc` reads of the activity indicator (REQUIREMENTS.md §21.5–§21.7): which process is a
//! hook event's Claude Code session, and whether a session's process still runs.
//!
//! Only `status`, `stat` and `cmdline` of other processes are read (inside ccwm's Landlock
//! domain `exe`, `cwd` and `environ` of processes outside it fail with `EACCES`; ARCHITECTURE.md
//! §13k), plus the boot id. Every read is bounded. A `cmdline` can hold a prompt (`claude -p
//! "…"`): it is read to find `argv[0]` and a few options, then dropped — never stored, logged or
//! returned. The root is injectable so tests build fake `/proc` trees.

use super::store::Refusal;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The walk looks at most this many parents above the hook process (§21.5).
pub const MAX_STEPS: usize = 8;
const MAX_STATUS_BYTES: u64 = 16 * 1024;
const MAX_STAT_BYTES: u64 = 4096;
/// One argument may be 128 KiB (`MAX_ARG_STRLEN`); options normally come first.
pub const MAX_CMDLINE_BYTES: u64 = 256 * 1024;
const BOOT_ID: &str = "sys/kernel/random/boot_id";

/// Which process is a session's: pid, start time (`/proc/<pid>/stat` field 22, clock ticks after
/// boot) and the boot id. Together they survive pid reuse and a reboot.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub pid: u32,
    pub start: u64,
    pub boot_id: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pid {} (start {})", self.pid, self.start)
    }
}

/// The Claude Code process a hook event came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub identity: Identity,
    /// `false` for `-p`/`--print` and the options that need it (§21.5, O17).
    pub interactive: bool,
}

/// The fields of `/proc/<pid>/status` the walk needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub ruid: u32,
    pub euid: u32,
    pub ppid: u32,
}

/// The fields of `/proc/<pid>/stat` the walk and the liveness check need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub state: u8,
    pub start: u64,
}

impl Stat {
    /// A zombie (`Z`) or dead (`X`, `x`) process: gone for the indicator.
    pub fn is_dead(&self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

/// `/proc` (or a fake tree in tests).
#[derive(Debug, Clone)]
pub struct ProcFs {
    root: PathBuf,
}

impl Default for ProcFs {
    fn default() -> Self {
        Self::new("/proc")
    }
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// The value of the `key:` line of a `status` file, split on whitespace.
fn status_field<'a>(text: &'a str, key: &str) -> Option<std::str::SplitAsciiWhitespace<'a>> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .map(str::split_ascii_whitespace)
}

/// Parse a `status` file: `Uid:` (real, effective, …) and `PPid:`.
pub fn parse_status(text: &str) -> Option<Status> {
    let mut uid = status_field(text, "Uid")?;
    let ruid = uid.next()?.parse().ok()?;
    let euid = uid.next()?.parse().ok()?;
    let ppid = status_field(text, "PPid")?.next()?.parse().ok()?;
    Some(Status { ruid, euid, ppid })
}

/// Parse a `stat` line after the **last** `)`: the command name in parentheses may hold spaces
/// and parentheses of its own. Field 3 is the state, field 22 the start time.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let rest = &text[text.rfind(')')? + 1..];
    let mut fields = rest.split_ascii_whitespace();
    let state = fields.next()?.as_bytes();
    if state.len() != 1 {
        return None;
    }
    // Fields 4 to 21 lie between the state (3) and the start time (22).
    let start = fields.nth(18)?.parse().ok()?;
    Some(Stat {
        state: state[0],
        start,
    })
}

/// Split a `cmdline` read into arguments. When the read hit `limit`, the last argument may be
/// cut off and is dropped.
pub fn parse_cmdline(bytes: &[u8], truncated: bool) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut args: Vec<Vec<u8>> = bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect();
    if bytes.last() == Some(&0) || truncated {
        args.pop();
    }
    args
}

/// Claude Code's process, by `argv[0]` (REQUIREMENTS.md §21.5, decided after O11):
/// 1. its last path component is exactly `claude` (a session started as `claude`);
/// 2. it starts with `claude ` — a process title Claude Code writes over its arguments
///    (`claude bg-pty-host`, `claude bg-spare`: a background session's processes);
/// 3. it is Claude Code's versioned binary: a path ending in `/claude/versions/<version>`, the
///    version digits and dots (a background session resumed under 2.1.321).
pub fn is_claude(argv: &[Vec<u8>]) -> bool {
    let Some(a0) = argv.first() else {
        return false;
    };
    let mut parts = a0.rsplit(|b| *b == b'/');
    let last = parts.next().unwrap_or_default();
    if last == b"claude" || a0.starts_with(b"claude ") {
        return true;
    }
    let version = !last.is_empty()
        && last[0].is_ascii_digit()
        && last.iter().all(|b| b.is_ascii_digit() || *b == b'.');
    version && parts.next() == Some(b"versions") && parts.next() == Some(b"claude")
}

/// A non-interactive session (§21.5, O17): `-p` or `--print`, or `--output-format` /
/// `--input-format` (which work only with `--print`), with or without `=value`, before any `--`.
/// Combined short options (`-cp`) are not recognized.
pub fn noninteractive(argv: &[Vec<u8>]) -> bool {
    argv.iter()
        .skip(1)
        .take_while(|a| a.as_slice() != b"--")
        .any(|a| {
            matches!(
                a.as_slice(),
                b"-p" | b"--print" | b"--output-format" | b"--input-format"
            ) || a.starts_with(b"--output-format=")
                || a.starts_with(b"--input-format=")
        })
}

impl ProcFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn file(&self, pid: u32, name: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(name)
    }

    pub fn status(&self, pid: u32) -> io::Result<Status> {
        let bytes = read_bounded(&self.file(pid, "status"), MAX_STATUS_BYTES)?;
        parse_status(&String::from_utf8_lossy(&bytes)).ok_or_else(|| invalid("status"))
    }

    pub fn stat(&self, pid: u32) -> io::Result<Stat> {
        let bytes = read_bounded(&self.file(pid, "stat"), MAX_STAT_BYTES)?;
        parse_stat(&String::from_utf8_lossy(&bytes)).ok_or_else(|| invalid("stat"))
    }

    pub fn cmdline(&self, pid: u32) -> io::Result<Vec<Vec<u8>>> {
        let bytes = read_bounded(&self.file(pid, "cmdline"), MAX_CMDLINE_BYTES)?;
        let truncated = bytes.len() as u64 == MAX_CMDLINE_BYTES;
        Ok(parse_cmdline(&bytes, truncated))
    }

    /// `/proc/sys/kernel/random/boot_id`: 36 characters, a new value at every boot.
    pub fn boot_id(&self) -> io::Result<String> {
        let bytes = read_bounded(&self.root.join(BOOT_ID), 64)?;
        let id = String::from_utf8_lossy(&bytes).trim().to_string();
        crate::claude::resume::is_uuid(&id)
            .then_some(id)
            .ok_or_else(|| invalid("boot_id"))
    }

    /// The process a hook event came from (§21.5). From the socket peer `peer` (the `ccwm hook`
    /// process) up the `PPid` chain, at most [`MAX_STEPS`] parents, only through processes whose
    /// real and effective UID are `uid` and that started no later than their child (a parent
    /// that started later is a reused pid): the **nearest** one that [`is_claude`]. The walk stops
    /// at pid 1, at any unreadable process, and at the first of another user.
    ///
    /// `claimed` (`CLAUDE_PID`) must equal it: otherwise `PidMismatch`. Without it the walk's
    /// result is used.
    pub fn find_claude(
        &self,
        peer: u32,
        claimed: Option<u32>,
        uid: u32,
        boot_id: &str,
    ) -> Result<Found, Refusal> {
        let none = |_| Refusal::NoClaudeAncestor;
        let mut child_start = self.stat(peer).map_err(none)?.start;
        let mut parent = self.status(peer).map_err(none)?.ppid;
        for _ in 0..MAX_STEPS {
            if parent <= 1 {
                break;
            }
            let status = self.status(parent).map_err(none)?;
            if status.ruid != uid || status.euid != uid {
                break;
            }
            let stat = self.stat(parent).map_err(none)?;
            if stat.start > child_start || stat.is_dead() {
                break;
            }
            let argv = self.cmdline(parent).map_err(none)?;
            if is_claude(&argv) {
                if claimed.is_some_and(|c| c != parent) {
                    return Err(Refusal::PidMismatch);
                }
                return Ok(Found {
                    identity: Identity {
                        pid: parent,
                        start: stat.start,
                        boot_id: boot_id.to_string(),
                    },
                    interactive: !noninteractive(&argv),
                });
            }
            child_start = stat.start;
            parent = status.ppid;
        }
        Err(Refusal::NoClaudeAncestor)
    }

    /// The session's process still runs: same pid and start time, not a zombie. (The boot id is
    /// the daemon's own for every session it opened; [`Self::still_claude`] checks it at start.)
    pub fn alive(&self, id: &Identity) -> bool {
        self.stat(id.pid)
            .is_ok_and(|s| s.start == id.start && !s.is_dead())
    }

    /// At start (§21.7): a persisted session's process is the same, still the user's and still
    /// Claude Code under the current boot id. `Some(interactive)` (read again), else `None`.
    pub fn still_claude(&self, id: &Identity, uid: u32, boot_id: &str) -> Option<bool> {
        if id.boot_id != boot_id || !self.alive(id) {
            return None;
        }
        let status = self.status(id.pid).ok()?;
        if status.ruid != uid || status.euid != uid {
            return None;
        }
        let argv = self.cmdline(id.pid).ok()?;
        is_claude(&argv).then(|| !noninteractive(&argv))
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Fake `/proc` trees for tests.
    use std::path::{Path, PathBuf};

    pub const BOOT: &str = "1d2c3b4a-0000-4000-8000-00000000b007";

    pub struct FakeProc {
        pub dir: tempfile::TempDir,
    }

    impl FakeProc {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let fake = Self { dir };
            fake.set_boot_id(BOOT);
            fake
        }

        pub fn root(&self) -> &Path {
            self.dir.path()
        }

        pub fn set_boot_id(&self, id: &str) {
            let p = self.root().join(super::BOOT_ID);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, format!("{id}\n")).unwrap();
        }

        fn pid_dir(&self, pid: u32) -> PathBuf {
            let d = self.root().join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        /// A process: `comm` in `stat` (any text), real and effective UID, parent, start time,
        /// state and NUL-separated `argv`.
        #[allow(clippy::too_many_arguments)]
        pub fn process_full(
            &self,
            pid: u32,
            comm: &str,
            ruid: u32,
            euid: u32,
            ppid: u32,
            start: u64,
            state: char,
            argv: &[&[u8]],
        ) {
            let d = self.pid_dir(pid);
            std::fs::write(
                d.join("status"),
                format!("Name:\t{comm}\nUmask:\t0022\nState:\t{state} (x)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0\nUid:\t{ruid}\t{euid}\t{euid}\t{euid}\nGid:\t100\t100\t100\t100\n"),
            )
            .unwrap();
            // Fields 4–21 (ppid … itrealvalue), then 22 (starttime) and a few more.
            let middle: Vec<String> = (4..=21)
                .map(|f| if f == 4 { ppid.to_string() } else { "0".into() })
                .collect();
            std::fs::write(
                d.join("stat"),
                format!(
                    "{pid} ({comm}) {state} {} {start} 0 0 0\n",
                    middle.join(" ")
                ),
            )
            .unwrap();
            let mut cmdline = Vec::new();
            for a in argv {
                cmdline.extend_from_slice(a);
                cmdline.push(0);
            }
            std::fs::write(d.join("cmdline"), cmdline).unwrap();
        }

        /// A running process of `uid` started at `start`.
        pub fn process(&self, pid: u32, uid: u32, ppid: u32, start: u64, argv: &[&str]) {
            let argv: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
            let comm = argv
                .first()
                .map(|a| {
                    String::from_utf8_lossy(a)
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string()
                })
                .unwrap_or_default();
            self.process_full(pid, &comm, uid, uid, ppid, start, 'S', &argv);
        }

        pub fn remove(&self, pid: u32) {
            std::fs::remove_dir_all(self.root().join(pid.to_string())).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeProc, BOOT};
    use super::*;

    const UID: u32 = 1000;

    /// The live chain: `claude` (100) → `sh` (200) → `ccwm hook` (300); systemd above.
    fn chain(fake: &FakeProc, claude_argv: &[&str]) -> ProcFs {
        fake.process(1, 0, 0, 1, &["/sbin/init"]);
        fake.process(50, UID, 1, 10, &["/usr/lib/systemd/systemd", "--user"]);
        fake.process(100, UID, 50, 20, claude_argv);
        fake.process(200, UID, 100, 30, &["sh", "-c", "ccwm hook Stop"]);
        fake.process(
            300,
            UID,
            200,
            31,
            &["/home/u/.local/bin/ccwm", "hook", "Stop"],
        );
        ProcFs::new(fake.root())
    }

    fn found(pid: u32, start: u64, interactive: bool) -> Result<Found, Refusal> {
        Ok(Found {
            identity: Identity {
                pid,
                start,
                boot_id: BOOT.into(),
            },
            interactive,
        })
    }

    #[test]
    fn the_walk_finds_the_nearest_claude_with_and_without_claude_pid() {
        let fake = FakeProc::new();
        let p = chain(&fake, &["claude"]);
        // Without CLAUDE_PID the walk's result is used.
        assert_eq!(p.find_claude(300, None, UID, BOOT), found(100, 20, true));
        // With CLAUDE_PID equal to it: the same.
        assert_eq!(
            p.find_claude(300, Some(100), UID, BOOT),
            found(100, 20, true)
        );
        // With another pid (even a real process of the chain): refused.
        assert_eq!(
            p.find_claude(300, Some(200), UID, BOOT),
            Err(Refusal::PidMismatch)
        );
        assert_eq!(
            p.find_claude(300, Some(4242), UID, BOOT),
            Err(Refusal::PidMismatch)
        );
    }

    #[test]
    fn the_nearest_claude_wins_and_a_hook_outside_any_claude_tree_is_refused() {
        let fake = FakeProc::new();
        // An outer claude (100) runs a shell that runs another claude (400) whose hook reports.
        chain(&fake, &["claude"]);
        fake.process(400, UID, 200, 40, &["claude", "-p", "x"]);
        fake.process(410, UID, 400, 41, &["sh", "-c", "ccwm hook Stop"]);
        fake.process(420, UID, 410, 42, &["ccwm", "hook", "Stop"]);
        let p = ProcFs::new(fake.root());
        assert_eq!(p.find_claude(420, None, UID, BOOT), found(400, 40, false));
        assert_eq!(
            p.find_claude(420, Some(100), UID, BOOT),
            Err(Refusal::PidMismatch)
        );
        // A hook run by a plain shell of the user.
        fake.process(500, UID, 50, 50, &["bash"]);
        fake.process(510, UID, 500, 51, &["ccwm", "hook", "Stop"]);
        assert_eq!(
            p.find_claude(510, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        assert_eq!(
            p.find_claude(510, Some(100), UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        // An unknown peer.
        assert_eq!(
            p.find_claude(999, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
    }

    /// O11: a background session. Supervisor → `claude bg-pty-host` → the session (`claude
    /// bg-spare`, `CLAUDE_PID`) → `sh` → hook. The session itself is the nearest.
    #[test]
    fn a_background_session_is_its_own_process_not_the_supervisors() {
        let fake = FakeProc::new();
        fake.process(50, UID, 1, 10, &["/usr/lib/systemd/systemd", "--user"]);
        fake.process(
            60,
            UID,
            50,
            11,
            &[
                "/home/u/.local/bin/claude",
                "--json-path",
                "x",
                "--spawned-by",
                "y",
            ],
        );
        fake.process(
            70,
            UID,
            60,
            12,
            &["claude bg-pty-host", "--bg-pty-host", "--", "--bg-spare"],
        );
        fake.process(80, UID, 70, 13, &["claude bg-spare", "--bg-spare"]);
        fake.process(90, UID, 80, 20, &["sh", "-c", "x"]);
        fake.process(95, UID, 90, 21, &["ccwm", "hook", "Stop"]);
        let p = ProcFs::new(fake.root());
        assert_eq!(p.find_claude(95, Some(80), UID, BOOT), found(80, 13, true));
        assert_eq!(p.find_claude(95, None, UID, BOOT), found(80, 13, true));
        assert_eq!(
            p.find_claude(95, Some(60), UID, BOOT),
            Err(Refusal::PidMismatch),
            "not the supervisor"
        );
        // The older layout: the versioned binary under a pty host under systemd.
        fake.process(
            80,
            UID,
            70,
            13,
            &[
                "/home/u/.local/share/claude/versions/2.1.321",
                "--session-id",
                "s",
                "--resume",
                "r",
            ],
        );
        fake.process(70, UID, 50, 12, &["claude bg-pty-host", "--bg-pty-host"]);
        assert_eq!(p.find_claude(95, Some(80), UID, BOOT), found(80, 13, true));
    }

    #[test]
    fn the_walk_looks_at_most_eight_parents_and_stops_at_pid_1() {
        let fake = FakeProc::new();
        fake.process(1, UID, 0, 1, &["claude"]); // pid 1 is never the session
        fake.process(10, UID, 1, 10, &["claude"]);
        // claude (10) → p11 … p18 (8 shells) → hook (19): claude is the 9th parent.
        for pid in 11..=18 {
            fake.process(pid, UID, pid - 1, u64::from(pid), &["sh"]);
        }
        fake.process(19, UID, 18, 19, &["ccwm", "hook", "Stop"]);
        let p = ProcFs::new(fake.root());
        assert_eq!(
            p.find_claude(19, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        // One shell less (19 → 17 → … → 11 → 10): claude is the 8th parent.
        fake.process(19, UID, 17, 19, &["ccwm", "hook", "Stop"]);
        assert_eq!(p.find_claude(19, None, UID, BOOT), found(10, 10, true));
        // A hook whose only claude ancestor is pid 1.
        fake.process(30, UID, 1, 30, &["ccwm", "hook", "Stop"]);
        assert_eq!(
            p.find_claude(30, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
    }

    #[test]
    fn the_walk_never_passes_a_process_of_another_user() {
        let fake = FakeProc::new();
        chain(&fake, &["claude"]);
        let p = ProcFs::new(fake.root());
        // A `claude` above a process of another UID (a setuid helper in between).
        fake.process_full(200, "sh", UID, 0, 100, 30, 'S', &[b"sh"]);
        assert_eq!(
            p.find_claude(300, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        fake.process_full(200, "sh", 0, UID, 100, 30, 'S', &[b"sh"]);
        assert_eq!(
            p.find_claude(300, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        // The claude itself running as someone else.
        fake.process(200, UID, 100, 30, &["sh"]);
        fake.process(100, 1001, 50, 20, &["claude"]);
        assert_eq!(
            p.find_claude(300, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        assert_eq!(
            p.find_claude(300, Some(100), UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
    }

    #[test]
    fn a_reused_or_dead_parent_pid_ends_the_walk() {
        let fake = FakeProc::new();
        let p = chain(&fake, &["claude"]);
        // The shell's parent pid now belongs to a claude that started after the shell.
        fake.process(100, UID, 50, 35, &["claude"]);
        assert_eq!(
            p.find_claude(300, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
        // Started at the same tick: fine.
        fake.process(100, UID, 50, 30, &["claude"]);
        assert_eq!(p.find_claude(300, None, UID, BOOT), found(100, 30, true));
        // A zombie.
        fake.process_full(100, "claude", UID, UID, 50, 20, 'Z', &[b"claude"]);
        assert_eq!(
            p.find_claude(300, None, UID, BOOT),
            Err(Refusal::NoClaudeAncestor)
        );
    }

    #[test]
    fn argv0_identifies_claude_by_name_process_title_or_versioned_binary() {
        let claude = |a0: &[u8]| is_claude(&[a0.to_vec(), b"--resume".to_vec()]);
        // 1. The last path component.
        assert!(claude(b"claude"));
        assert!(claude(b"/x/claude"));
        assert!(claude(b"/home/u/.local/bin/claude"));
        assert!(claude(b"./claude"));
        // 2. Claude Code's process titles (O11: a background session's processes).
        assert!(claude(b"claude bg-pty-host"));
        assert!(claude(b"claude bg-spare"));
        assert!(claude(b"claude daemon"));
        // 3. The versioned binary.
        assert!(claude(b"/home/u/.local/share/claude/versions/2.1.321"));
        assert!(claude(b"/home/u/.local/share/claude/versions/2.1.332"));
        assert!(claude(b"claude/versions/3"));
        for not in [
            &b"claude-x"[..],
            b"/x/claude-code",
            b"/x/2.1.332",
            b"/x/versions/2.1.332",
            b"/x/claudex/versions/2.1.332",
            b"/x/claude/versions/2.1.332-beta",
            b"/x/claude/versions/v2.1",
            b"/x/claude/versions/",
            b"/x/claude/version/2.1.332",
            b"node",
            b"Claude",
            b"Claude bg-spare",
            b"claudebg",
            b" claude",
            b"/x/claude/",
            b"",
            b"xclaude",
        ] {
            assert!(!claude(not), "{}", String::from_utf8_lossy(not));
        }
        assert!(!is_claude(&[]));
        // Through the fake tree: node, another name, a bare version are not found.
        for argv in [["/x/2.1.332"], ["node"], ["claude-x"]] {
            let fake = FakeProc::new();
            let p = chain(&fake, &argv);
            assert_eq!(
                p.find_claude(300, None, UID, BOOT),
                Err(Refusal::NoClaudeAncestor),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn the_non_interactive_options_are_recognized_before_dash_dash_only() {
        let argv = |args: &[&str]| -> Vec<Vec<u8>> {
            std::iter::once("claude")
                .chain(args.iter().copied())
                .map(|a| a.as_bytes().to_vec())
                .collect()
        };
        for yes in [
            &["-p"][..],
            &["--print"],
            &["--output-format", "json"],
            &["--output-format=stream-json"],
            &["--input-format", "stream-json"],
            &["--input-format=text"],
            &["--model", "x", "-p", "hello"],
        ] {
            assert!(noninteractive(&argv(yes)), "{yes:?}");
        }
        for no in [
            &[][..],
            &["--resume", "id"],
            &["--", "-p"],
            &["-cp"],
            &["--printx"],
            &["--output-formatx"],
            &["-P"],
            &["hello -p"],
        ] {
            assert!(!noninteractive(&argv(no)), "{no:?}");
        }
        // argv[0] itself is never an option.
        assert!(!noninteractive(&[b"-p".to_vec()]));
    }

    #[test]
    fn stat_is_parsed_after_the_last_parenthesis() {
        let fields = |state: &str, start: u64| {
            let middle = vec!["0"; 18].join(" ");
            format!("{state} {middle} {start} 0 0")
        };
        assert_eq!(
            parse_stat(&format!("42 (claude) {}", fields("S", 777))),
            Some(Stat {
                state: b'S',
                start: 777
            })
        );
        // A command name with spaces and parentheses.
        assert_eq!(
            parse_stat(&format!("42 (a) b (c d)) {}", fields("Z", 9))),
            Some(Stat {
                state: b'Z',
                start: 9
            })
        );
        assert!(parse_stat("42 (claude) S 1 2").is_none(), "too few fields");
        assert!(parse_stat("42 claude S").is_none(), "no parenthesis");
        assert!(parse_stat(&format!("42 (x) SS {}", fields("S", 1))).is_none());
        assert!(parse_stat(&format!(
            "42 (x) {}",
            fields("S", 1).replace(" 1 0 0", " x 0 0")
        ))
        .is_none());
        // Through a fake tree whose comm holds `)` and spaces.
        let fake = FakeProc::new();
        fake.process_full(7, "we) (ird S 1", UID, UID, 1, 55, 'R', &[b"claude"]);
        assert_eq!(
            ProcFs::new(fake.root()).stat(7).unwrap(),
            Stat {
                state: b'R',
                start: 55
            }
        );
    }

    #[test]
    fn status_and_cmdline_parsing() {
        assert_eq!(
            parse_status("Name:\tx\nPPid:\t12\nUid:\t1000\t1001\t1000\t1000\n"),
            Some(Status {
                ruid: 1000,
                euid: 1001,
                ppid: 12
            })
        );
        assert_eq!(
            parse_status("Name:\tx\nUid:\t1000\t1000\n"),
            None,
            "no PPid"
        );
        assert_eq!(
            parse_status("PPid:\t1\nUid:\t1000\n"),
            None,
            "no effective UID"
        );
        assert_eq!(parse_status("PPid:\tx\nUid:\t1\t1\n"), None);
        assert_eq!(
            parse_cmdline(b"claude\0-p\0hi\0", false),
            vec![b"claude".to_vec(), b"-p".to_vec(), b"hi".to_vec()]
        );
        // A title written over argv without NULs is one argument.
        assert_eq!(
            parse_cmdline(b"claude daemon", false),
            vec![b"claude daemon".to_vec()]
        );
        // Cut off at the limit: the last argument is dropped.
        assert_eq!(
            parse_cmdline(b"claude\0-p\0partial", true),
            vec![b"claude".to_vec(), b"-p".to_vec()]
        );
        assert!(parse_cmdline(b"", false).is_empty());
        // A kernel thread has an empty cmdline: never claude.
        let fake = FakeProc::new();
        fake.process_full(9, "kthreadd", UID, UID, 1, 1, 'S', &[]);
        assert!(!is_claude(&ProcFs::new(fake.root()).cmdline(9).unwrap()));
    }

    #[test]
    fn a_long_cmdline_is_read_up_to_its_bound() {
        let fake = FakeProc::new();
        let big = vec![b'x'; usize::try_from(MAX_CMDLINE_BYTES).unwrap()];
        fake.process_full(8, "claude", UID, UID, 1, 1, 'S', &[b"claude", b"-p", &big]);
        let argv = ProcFs::new(fake.root()).cmdline(8).unwrap();
        assert_eq!(argv, vec![b"claude".to_vec(), b"-p".to_vec()]);
        assert!(noninteractive(&argv));
    }

    #[test]
    fn liveness_needs_the_same_start_time_and_no_zombie() {
        let fake = FakeProc::new();
        let p = chain(&fake, &["claude"]);
        let id = Identity {
            pid: 100,
            start: 20,
            boot_id: BOOT.into(),
        };
        assert!(p.alive(&id));
        assert_eq!(p.still_claude(&id, UID, BOOT), Some(true));
        // A changed boot id (a reboot): not the same process.
        assert_eq!(
            p.still_claude(&id, UID, "00000000-0000-4000-8000-000000000000"),
            None
        );
        // The pid reused by another process (another start time).
        fake.process(100, UID, 50, 21, &["claude"]);
        assert!(!p.alive(&id));
        assert_eq!(p.still_claude(&id, UID, BOOT), None);
        // Same start time but no longer claude (exec'd something else), or not the user's.
        fake.process(100, UID, 50, 20, &["vim"]);
        assert!(p.alive(&id));
        assert_eq!(p.still_claude(&id, UID, BOOT), None);
        fake.process(100, 1001, 50, 20, &["claude"]);
        assert_eq!(p.still_claude(&id, UID, BOOT), None);
        // Now non-interactive (read again at start).
        fake.process(100, UID, 50, 20, &["claude", "--print"]);
        assert_eq!(p.still_claude(&id, UID, BOOT), Some(false));
        // A zombie, then gone.
        fake.process_full(100, "claude", UID, UID, 50, 20, 'Z', &[b"claude"]);
        assert!(!p.alive(&id));
        fake.process_full(100, "claude", UID, UID, 50, 20, 'X', &[b"claude"]);
        assert!(!p.alive(&id));
        fake.remove(100);
        assert!(!p.alive(&id));
    }

    #[test]
    fn the_boot_id_must_look_like_one() {
        let fake = FakeProc::new();
        let p = ProcFs::new(fake.root());
        assert_eq!(p.boot_id().unwrap(), BOOT);
        fake.set_boot_id("not a boot id");
        assert!(p.boot_id().is_err());
        assert!(ProcFs::new("/nonexistent-proc").boot_id().is_err());
    }

    /// The real `/proc`: this test process is found by nothing (no claude ancestor is assumed)
    /// but its own identity is alive, and the boot id reads.
    #[test]
    fn the_real_proc_reads() {
        let p = ProcFs::default();
        let boot = p.boot_id().unwrap();
        let me = std::process::id();
        let stat = p.stat(me).unwrap();
        assert!(p.alive(&Identity {
            pid: me,
            start: stat.start,
            boot_id: boot.clone()
        }));
        assert!(!p.alive(&Identity {
            pid: me,
            start: stat.start + 1,
            boot_id: boot
        }));
        let st = p.status(me).unwrap();
        assert_eq!(st.ruid, nix::unistd::getuid().as_raw());
        assert!(!p.cmdline(me).unwrap().is_empty());
    }
}
