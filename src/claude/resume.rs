//! Resume commands (REQUIREMENTS.md §8): `cd -- '<first recorded cwd>' && claude --resume <id>`.
//! ccwm only ever *shows* this text for copying; it never runs it.

/// Strict UUID syntax: 8-4-4-4-12 hexadecimal digits. Anything else gets no command.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
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

/// The command, or `None` if the session id is not a strict UUID or there is no cwd.
pub fn command(cwd: &str, session_id: &str) -> Option<String> {
    if !is_uuid(session_id) || cwd.is_empty() {
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

    /// Adversarial paths: the shell must see exactly the original string as `cd`'s argument and
    /// execute nothing from it. Checked by running `/bin/sh` with the quoted text as the argument
    /// of `printf` (never `cd`/`claude`) and comparing the bytes.
    #[test]
    fn adversarial_paths_survive_a_real_posix_shell_unchanged() {
        let sentinel_dir = tempfile::tempdir().unwrap();
        let sentinel = sentinel_dir.path().join("pwned");
        let s = sentinel.display();
        for path in [
            "/home/u/with space".to_string(),
            "/home/u/it's".to_string(),
            "/home/u/''".to_string(),
            format!("/home/u/$(touch {s})"),
            format!("/home/u/`touch {s}`"),
            "/home/u/new\nline".to_string(),
            "-rf".to_string(),
            "--".to_string(),
            "/home/u/back\\slash".to_string(),
            "/home/u/semi;colon && touch x".to_string(),
            "/home/u/$HOME/${PATH}".to_string(),
            "/home/u/*?[a]".to_string(),
            "/home/u/ünïcode 雪".to_string(),
        ] {
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
}
