//! Resume commands (REQUIREMENTS.md §8): `cd -- '<first recorded cwd>' && claude --resume <id>`.
//! ccwm only ever *shows* this text for copying; it never runs it.
//!
//! The text is **pasted into an interactive terminal**, where the line editor acts on control
//! characters before the shell parses anything: `\x15` (Ctrl-U) kills the line, `\n` accepts it,
//! `ESC[201~` ends a bracketed paste early (M3 security review, M1). Quoting cannot help there, so
//! a cwd with any such character gets **no command** ([`unsafe_cwd`]); it is shown escaped
//! ([`escape`]) with the warning `cwd_unsafe_characters`.

/// Strict UUID syntax: 8-4-4-4-12 hexadecimal digits. Anything else gets no command.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// [`is_uuid`] in lower case only, as Claude Code writes session and prompt ids: another spelling
/// of the same id is not accepted (folding it would let two spellings share one id, M3 review L4).
pub fn is_lower_uuid(s: &str) -> bool {
    is_uuid(s) && !s.bytes().any(|b| b.is_ascii_uppercase())
}

/// POSIX single-quoting: the whole string in `'…'`, each `'` written as `'\''`. Nothing inside
/// single quotes is special to the shell (no `$`, backtick, `\` or newline handling).
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// A character that must never reach a terminal in pasted text: C0 controls (including `\t`,
/// `\n`, `\r` and `ESC`), DEL, C1 controls, and the Unicode bidi/format characters that make
/// text display differently from what it is (`U+202A–U+202E`, `U+2066–U+2069`, `U+200E/F`).
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
}

/// The cwd contains a character [`is_unsafe_char`] rejects: no resume command for it.
pub fn unsafe_cwd(cwd: &str) -> bool {
    cwd.chars().any(is_unsafe_char)
}

/// `s` with every unsafe character written as an escape (`\x15`, `\u{202e}`), for display.
/// A backslash is doubled, so the escaped form is unambiguous.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if is_unsafe_char(c) && (c as u32) < 0x100 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if is_unsafe_char(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `s` unchanged if it is safe to show, else its [`escape`]d form (only then are backslashes
/// doubled, so ordinary paths read as recorded).
pub fn display(s: &str) -> String {
    if unsafe_cwd(s) {
        escape(s)
    } else {
        s.to_string()
    }
}

/// The command, or `None` if the session id is not a strict UUID, there is no cwd, or the cwd
/// contains a character that is unsafe to paste into a terminal ([`unsafe_cwd`]).
pub fn command(cwd: &str, session_id: &str) -> Option<String> {
    if !is_uuid(session_id) || cwd.is_empty() || unsafe_cwd(cwd) {
        return None;
    }
    Some(format!(
        "cd -- {} && claude --resume {session_id}",
        shell_quote(cwd)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const ID: &str = "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f";

    #[test]
    fn uuid_validation_is_strict() {
        assert!(is_uuid(ID));
        assert!(is_uuid("0B7C1F6E-3D2A-4C5B-9E8F-1A2B3C4D5E6F"));
        for bad in [
            "",
            "0b7c1f6e3d2a4c5b9e8f1a2b3c4d5e6f",
            "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6",
            "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f0",
            "0b7c1f6e-3d2a-4c5b-9e8f_1a2b3c4d5e6f",
            "0b7c1f6g-3d2a-4c5b-9e8f-1a2b3c4d5e6f",
            "../../../../etc/passwd-0000-0000-000",
            "0b7c1f6e-3d2a-4c5b-9e8f-1a2b3c4d5e6f; rm -rf ~",
            "$(touch x)-3d2a-4c5b-9e8f-1a2b3c4d5e6f",
        ] {
            assert!(!is_uuid(bad), "{bad}");
            assert!(command("/tmp", bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_command_uses_the_cwd_verbatim_inside_single_quotes() {
        assert_eq!(
            command("/home/u/dev/my project", ID).unwrap(),
            format!("cd -- '/home/u/dev/my project' && claude --resume {ID}")
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert!(command("", ID).is_none());
    }

    /// Paths that are hostile to the shell *parser* but contain no terminal control character:
    /// quoting must make the shell see exactly the original string as `cd`'s argument and execute
    /// nothing from it. Checked by running `/bin/sh` with the quoted text as the argument of
    /// `printf` (never `cd`/`claude`) and comparing the bytes.
    fn shell_hostile_paths(sentinel: &std::path::Path) -> Vec<String> {
        let s = sentinel.display();
        vec![
            "/home/u/with space".to_string(),
            "/home/u/it's".to_string(),
            "/home/u/''".to_string(),
            format!("/home/u/$(touch {s})"),
            format!("/home/u/`touch {s}`"),
            "-rf".to_string(),
            "--".to_string(),
            "/home/u/back\\slash".to_string(),
            "/home/u/semi;colon && touch x".to_string(),
            "/home/u/$HOME/${PATH}".to_string(),
            "/home/u/*?[a]".to_string(),
            "/home/u/ünïcode 雪".to_string(),
        ]
    }

    /// Paths with characters a terminal's line editor acts on before the shell sees them (M3
    /// review, M1): no command at all.
    fn terminal_hostile_paths(sentinel: &std::path::Path) -> Vec<String> {
        let s = sentinel.display();
        vec![
            "/home/u/new\nline".to_string(),
            "/home/u/cr\rreturn".to_string(),
            format!("/home/u/x\u{15}touch {s}\n"),
            format!("/home/u/x\u{1b}[201~touch {s}\n"),
            "/home/u/tab\there".to_string(),
            "/home/u/del\u{7f}".to_string(),
            "/home/u/c1\u{9b}31m".to_string(),
            "/home/u/rlo\u{202e}txt.exe".to_string(),
            "/home/u/lri\u{2066}x".to_string(),
            "/home/u/lrm\u{200e}x".to_string(),
        ]
    }

    #[test]
    fn adversarial_paths_survive_a_real_posix_shell_unchanged() {
        let sentinel_dir = tempfile::tempdir().unwrap();
        let sentinel = sentinel_dir.path().join("pwned");
        for path in shell_hostile_paths(&sentinel) {
            let script = format!("printf '%s' {}", shell_quote(&path));
            let out = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .env_clear()
                .output()
                .unwrap();
            assert!(out.status.success(), "{path:?}");
            assert_eq!(String::from_utf8(out.stdout).unwrap(), path, "{path:?}");
            let cmd = command(&path, ID).unwrap();
            assert!(cmd.starts_with("cd -- '"), "{cmd}");
            assert!(
                cmd.ends_with(&format!("' && claude --resume {ID}")),
                "{cmd}"
            );
        }
        assert!(!sentinel.exists(), "a quoted path executed something");
    }

    #[test]
    fn a_cwd_with_terminal_control_or_bidi_characters_gets_no_command() {
        let sentinel = std::path::Path::new("/nonexistent/pwned");
        for path in terminal_hostile_paths(sentinel) {
            assert!(unsafe_cwd(&path), "{path:?}");
            assert_eq!(command(&path, ID), None, "{path:?}");
            let shown = display(&path);
            assert!(!unsafe_cwd(&shown), "{shown:?} still carries the character");
            assert!(shown.contains('\\'), "{shown:?}");
        }
        for path in shell_hostile_paths(sentinel) {
            assert!(!unsafe_cwd(&path), "{path:?}");
            assert_eq!(display(&path), path, "safe paths are shown as recorded");
        }
        assert_eq!(escape("a\u{15}b\\c\u{202e}"), r"a\x15b\\c\u{202e}");
        assert_eq!(escape("\u{1b}[201~"), r"\x1b[201~");
    }

    /// Feed each of `pastes` to one interactive `bash` (5.x, readline) through a pseudo-terminal,
    /// as a paste from the clipboard would, pressing Enter after each, then exit. `bracketed`: readline's
    /// bracketed-paste mode, with the text wrapped in `ESC[200~ … ESC[201~` as a terminal sends
    /// it. `None` if python3 or bash is not installed (nothing was run); otherwise whether the
    /// driver ran to its end.
    fn paste_into_bash(
        pastes: &[String],
        bracketed: bool,
        path_dir: &std::path::Path,
    ) -> Option<bool> {
        const DRIVER: &str = r#"
import os, pty, select, sys, time
pastes = sys.stdin.buffer.read().split(b"\0")
bracketed = sys.argv[1] == "1"
env = {"PATH": sys.argv[2], "HOME": sys.argv[3], "PS1": "$ ", "TERM": "xterm", "INPUTRC": "/dev/null"}
pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-i"], env)
def drain(seconds):
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                if not os.read(fd, 65536):
                    return
            except OSError:
                return
drain(0.4)
mode = b"on" if bracketed else b"off"
os.write(fd, b"bind 'set enable-bracketed-paste " + mode + b"'\n")
drain(0.3)
for data in pastes:
    os.write(fd, (b"\x1b[200~" + data + b"\x1b[201~") if bracketed else data)
    drain(0.1)
    os.write(fd, b"\n")
    drain(0.15)
drain(0.3)
os.write(fd, b"\x03\nexit\n")
drain(1.0)
try:
    os.kill(pid, 9)
except OSError:
    pass
os.waitpid(pid, 0)
"#;
        use std::io::Write;
        if !std::path::Path::new("/bin/bash").exists() {
            return None;
        }
        let spawned = Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(DRIVER)
            .arg(if bracketed { "1" } else { "0" })
            .arg(format!("{}:/usr/bin:/bin", path_dir.display()))
            .arg(path_dir)
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!("cannot start python3: {e}"),
        };
        let input = pastes.join("\0");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        Some(child.wait().unwrap().success())
    }

    /// Regression test for M3 review M1, with a real line editor: pasting the old command for a
    /// hostile cwd runs the embedded command (control run, proves the harness can see it); every
    /// command ccwm still generates, pasted the same way, runs nothing and never reaches `claude`.
    #[test]
    fn pasting_generated_commands_into_an_interactive_bash_executes_nothing() {
        let t = tempfile::tempdir().unwrap();
        let fake_claude = t.path().join("claude");
        let claude_ran = t.path().join("claude-ran");
        std::fs::write(
            &fake_claude,
            format!("#!/bin/sh\ntouch '{}'\n", claude_ran.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Control: the pre-M3.1 output for a cwd with Ctrl-U + newline, and with an embedded
        // bracketed-paste end marker.
        for (bracketed, marker) in [(false, ""), (true, "\u{1b}[201~")] {
            let sentinel = t.path().join(format!("control-{bracketed}"));
            let cwd = format!("/home/u/x{marker}\u{15}touch {}\n", sentinel.display());
            let old = format!("cd -- {} && claude --resume {ID}", shell_quote(&cwd));
            // Skipped only where the tools are missing, and never in CI (v0.1.0 review,
            // test-coverage gap 7); a driver that fails is a failure, not a skip.
            let Some(ran) = paste_into_bash(&[old], bracketed, t.path()) else {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "python3 and bash are required in CI (the pty paste test)"
                );
                eprintln!("NOTICE: python3 or bash missing; skipping the pty paste test");
                return;
            };
            assert!(ran, "the pty driver failed (bracketed = {bracketed})");
            assert!(
                sentinel.exists(),
                "control run (bracketed = {bracketed}) did not execute: the harness is blind"
            );
            assert_eq!(command(&cwd, ID), None, "ccwm generates no command for it");
        }

        // Every command ccwm generates for the shell-hostile paths, one paste each.
        let sentinel = t.path().join("pwned");
        for bracketed in [false, true] {
            // A last, harmless paste proves bash still read whole lines after every command
            // (none left it inside an open quote).
            let alive = t.path().join(format!("alive-{bracketed}"));
            let mut pastes: Vec<String> = shell_hostile_paths(&sentinel)
                .iter()
                .map(|p| command(p, ID).unwrap())
                .collect();
            pastes.push(format!("touch {}", shell_quote(&alive.to_string_lossy())));
            assert_eq!(paste_into_bash(&pastes, bracketed, t.path()), Some(true));
            assert!(
                alive.exists(),
                "bash did not run the final paste (bracketed = {bracketed})"
            );
        }
        assert!(!sentinel.exists(), "a pasted command executed something");
        assert!(
            !claude_ran.exists(),
            "no test cwd exists, so `cd` must fail"
        );
    }
}
