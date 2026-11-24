//! Pure parsers for the output of the allowlisted Git commands, and remote-URL sanitization.

use serde::Serialize;

/// Files listed per category in a status (counts are always exact).
pub const MAX_LISTED_FILES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

/// `--attr-source` exists from Git 2.41.0 (§6).
pub const MIN_HARDENED: Version = Version(2, 41, 0);

/// `git version 2.43.0` (also `2.39.3 (Apple Git-145)`, `2.43.0.windows.1`, `2.44.0-rc1`).
pub fn parse_version(out: &str) -> Option<Version> {
    let rest = out.trim().strip_prefix("git version ")?;
    let mut nums = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().ok());
    let major = nums.next()??;
    let minor = nums.next()??;
    let patch = nums.next().flatten().unwrap_or(0);
    Some(Version(major, minor, patch))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Files {
    pub staged: Vec<String>,
    pub modified: Vec<String>,
    pub untracked: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// `None` when detached or unborn without a name.
    pub branch: Option<String>,
    pub detached: bool,
    pub upstream: Option<String>,
    pub ahead: Option<u32>,
    pub behind: Option<u32>,
    pub staged: u32,
    pub modified: u32,
    pub untracked: u32,
    pub files: Files,
}

fn push_capped(list: &mut Vec<String>, path: &str) {
    if list.len() < MAX_LISTED_FILES {
        list.push(path.to_string());
    }
}

/// `git status --porcelain=v2 --branch -z`. Returns `None` for output that does not look like it.
pub fn parse_status(raw: &[u8]) -> Option<Status> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut st = Status::default();
    let mut fields = text.split('\0');
    while let Some(rec) = fields.next() {
        if rec.is_empty() {
            continue;
        }
        if let Some(h) = rec.strip_prefix("# ") {
            let (key, value) = h.split_once(' ').unwrap_or((h, ""));
            match key {
                "branch.head" if value == "(detached)" => st.detached = true,
                "branch.head" => st.branch = Some(value.to_string()),
                "branch.upstream" => st.upstream = Some(value.to_string()),
                "branch.ab" => {
                    let mut it = value.split(' ');
                    st.ahead = it.next()?.strip_prefix('+')?.parse().ok();
                    st.behind = it.next()?.strip_prefix('-')?.parse().ok();
                }
                _ => {} // branch.oid, stash and future headers
            }
            continue;
        }
        let (kind, rest) = rec.split_at_checked(1)?;
        let rest = rest.strip_prefix(' ')?;
        let (xy, path) = match kind {
            // 1 XY sub mH mI mW hH hI path
            "1" => {
                let p: Vec<&str> = rest.splitn(8, ' ').collect();
                (*p.first()?, *p.get(7)?)
            }
            // 2 XY sub mH mI mW hH hI Xscore path \0 origPath
            "2" => {
                let p: Vec<&str> = rest.splitn(9, ' ').collect();
                fields.next()?; // the original path
                (*p.first()?, *p.get(8)?)
            }
            // u XY sub m1 m2 m3 mW h1 h2 h3 path: unmerged, counted as modified
            "u" => {
                let p: Vec<&str> = rest.splitn(10, ' ').collect();
                st.modified += 1;
                push_capped(&mut st.files.modified, p.get(9)?);
                continue;
            }
            "?" => {
                st.untracked += 1;
                push_capped(&mut st.files.untracked, rest);
                continue;
            }
            "!" => continue,
            _ => return None,
        };
        let mut xy = xy.chars();
        let (x, y) = (xy.next()?, xy.next()?);
        if x != '.' {
            st.staged += 1;
            push_capped(&mut st.files.staged, path);
        }
        if y != '.' {
            st.modified += 1;
            push_capped(&mut st.files.modified, path);
        }
    }
    Some(st)
}

/// `git config -z --get-regexp ^filter\..*\.(clean|smudge|process)$`: each entry is
/// `key\nvalue\0` (or `key\0` without a value). Returns the driver names (deduplicated, in order).
pub fn filter_driver_names(raw: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in raw.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let key = entry.split(|b| *b == b'\n').next().unwrap_or(entry);
        let key = String::from_utf8_lossy(key);
        let Some(rest) = key.strip_prefix("filter.") else {
            continue;
        };
        let name = ["clean", "smudge", "process"]
            .iter()
            .find_map(|v| rest.strip_suffix(&format!(".{v}")));
        if let Some(name) = name {
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// A driver name can be neutralized with `-c filter.<name>.<var>=` only if `-c` cannot misparse
/// it: Git splits `-c` at the first `=`, so a name containing `=` would set a different key.
pub fn neutralizable(name: &str) -> bool {
    !name.is_empty() && !name.contains('=') && !name.chars().any(char::is_control)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Commit {
    pub hash: String,
    pub subject: String,
    pub author: String,
    pub time: i64,
}

/// `git log -1 --format=%H%x00%s%x00%an%x00%at`.
pub fn parse_log(raw: &[u8]) -> Option<Commit> {
    let text = String::from_utf8_lossy(raw);
    let mut it = text.trim_end_matches('\n').split('\0');
    let hash = it.next()?.to_string();
    if hash.len() < 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let subject = it.next()?.to_string();
    let author = it.next()?.to_string();
    let time = it.next()?.trim().parse().ok()?;
    Some(Commit {
        hash,
        subject: clean(&subject, 500),
        author: clean(&author, 200),
        time,
    })
}

/// Drop control characters and cap the length (display safety; never interpreted).
pub fn clean(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

/// Remove credentials from a remote URL before it is stored or shown (§6): userinfo in
/// `scheme://user:pass@host/…`, the user in scp-like `user@host:path`, and any query or fragment.
pub fn sanitize_remote_url(url: &str) -> String {
    let url = clean(url.trim(), 1024);
    if let Some((scheme, rest)) = url.split_once("://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let path = path.split(['?', '#']).next().unwrap_or("");
        return format!("{scheme}://{host}{path}");
    }
    // scp-like syntax: [user@]host:path, where no '/' comes before the first ':'.
    if let Some(colon) = url.find(':') {
        if !url[..colon].contains('/') {
            let (head, path) = url.split_at(colon);
            let host = head.rsplit_once('@').map_or(head, |(_, h)| h);
            return format!("{host}{path}");
        }
    }
    url // a local path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(
            parse_version("git version 2.43.0\n"),
            Some(Version(2, 43, 0))
        );
        assert_eq!(
            parse_version("git version 2.39.3 (Apple Git-145)"),
            Some(Version(2, 39, 3))
        );
        assert_eq!(
            parse_version("git version 2.43.0.windows.1"),
            Some(Version(2, 43, 0))
        );
        assert_eq!(parse_version("git version 2.44"), Some(Version(2, 44, 0)));
        assert_eq!(parse_version("hg 1.0"), None);
        assert!(Version(2, 40, 9) < MIN_HARDENED && Version(2, 41, 0) >= MIN_HARDENED);
    }

    #[test]
    fn status_counts_lists_and_branch_headers() {
        let raw = b"# branch.oid 1234567890123456789012345678901234567890\0# branch.head main\0# branch.upstream origin/main\0# branch.ab +2 -3\0\
1 M. N... 100644 100644 100644 aaaa bbbb staged.txt\0\
1 .M N... 100644 100644 100644 aaaa bbbb dir/with space.txt\0\
1 MM N... 100644 100644 100644 aaaa bbbb both.txt\0\
2 R. N... 100644 100644 100644 aaaa bbbb R100 new name.txt\0old name.txt\0\
u UU N... 100644 100644 100644 100644 a b c conflict.txt\0\
? untracked dir/\0! ignored.log\0";
        let st = parse_status(raw).unwrap();
        assert_eq!(st.branch.as_deref(), Some("main"));
        assert_eq!(st.upstream.as_deref(), Some("origin/main"));
        assert_eq!((st.ahead, st.behind), (Some(2), Some(3)));
        assert_eq!((st.staged, st.modified, st.untracked), (3, 3, 1));
        assert_eq!(st.files.staged, ["staged.txt", "both.txt", "new name.txt"]);
        assert_eq!(
            st.files.modified,
            ["dir/with space.txt", "both.txt", "conflict.txt"]
        );
        assert_eq!(st.files.untracked, ["untracked dir/"]);
        assert!(!st.detached);
    }

    #[test]
    fn detached_unborn_and_clean_states() {
        let st = parse_status(b"# branch.oid abc\0# branch.head (detached)\0").unwrap();
        assert!(st.detached && st.branch.is_none());
        let st = parse_status(b"# branch.oid (initial)\0# branch.head main\0").unwrap();
        assert_eq!(st.branch.as_deref(), Some("main"));
        assert_eq!((st.ahead, st.upstream), (None, None));
        assert_eq!(parse_status(b"").unwrap(), Status::default());
        assert!(parse_status(b"garbage").is_none());
        assert!(parse_status(b"\xff\xfe").is_none());
        assert!(parse_status(b"# branch.ab 2 3\0").is_none());
    }

    #[test]
    fn file_lists_are_capped_but_counts_are_exact() {
        let mut raw = Vec::new();
        for i in 0..250 {
            raw.extend_from_slice(format!("? f{i}\0").as_bytes());
        }
        let st = parse_status(&raw).unwrap();
        assert_eq!(st.untracked, 250);
        assert_eq!(st.files.untracked.len(), MAX_LISTED_FILES);
    }

    #[test]
    fn filter_driver_names_from_config_output() {
        let raw = b"filter.lfs.clean\ngit-lfs clean -- %f\0filter.lfs.smudge\ngit-lfs smudge\0filter.a.b.process\nx\0filter.novalue.clean\0filter.x=y.clean\nz\0other.key\nv\0";
        assert_eq!(filter_driver_names(raw), ["lfs", "a.b", "novalue", "x=y"]);
        assert!(filter_driver_names(b"").is_empty());
        assert!(neutralizable("lfs") && neutralizable("a.b"));
        assert!(!neutralizable("x=y") && !neutralizable("") && !neutralizable("a\nb"));
    }

    #[test]
    fn log_line() {
        let h = "a".repeat(40);
        let raw = format!("{h}\x00Fix \u{1b}[31mthe bug\x00Ada\x001700000000\n");
        let c = parse_log(raw.as_bytes()).unwrap();
        assert_eq!(c.hash, h);
        assert_eq!(
            c.subject, "Fix [31mthe bug",
            "control characters are dropped"
        );
        assert_eq!((c.author.as_str(), c.time), ("Ada", 1_700_000_000));
        assert!(parse_log(b"").is_none());
        assert!(parse_log(b"nothex\x00s\x00a\x001\n").is_none());
    }

    #[test]
    fn remote_urls_lose_credentials() {
        let cases = [
            (
                "https://user:pa55@github.com/o/r.git",
                "https://github.com/o/r.git",
            ),
            ("https://ghp_TOKEN@github.com/o/r", "https://github.com/o/r"),
            ("https://a@b@host/x", "https://host/x"),
            ("https://host/r.git?token=abc#frag", "https://host/r.git"),
            ("ssh://git@host:22/r.git", "ssh://host:22/r.git"),
            ("git@github.com:o/r.git", "github.com:o/r.git"),
            ("host:o/r.git", "host:o/r.git"),
            ("/srv/git/r.git", "/srv/git/r.git"),
            ("./rel/path:with-colon", "./rel/path:with-colon"),
            ("https://host", "https://host"),
            ("  https://u:p@h/x\n", "https://h/x"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_remote_url(raw), want, "{raw}");
        }
    }
}
