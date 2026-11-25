//! Best-effort secret redaction for everything ccwm displays or stores from sessions (titles and
//! prompts, REQUIREMENTS.md §7.3). It recognises common formats only; it is **not** guaranteed to
//! find every secret (SECURITY.md).

use regex::Regex;
use std::sync::OnceLock;

pub const MASK: &str = "[REDACTED]";

struct Rule {
    re: Regex,
    /// Replacement; `$1` keeps a captured prefix (e.g. `password=`).
    with: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let rule = |pattern: &str, with: &'static str| Rule {
            re: Regex::new(pattern).expect("redaction patterns are valid"),
            with,
        };
        vec![
            // PEM private keys (also an unterminated block at the end of a truncated text).
            rule(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
                "[REDACTED PRIVATE KEY]",
            ),
            // GitHub tokens.
            rule(r"\bgithub_pat_[A-Za-z0-9_]{20,}", MASK),
            rule(r"\bgh[pousr]_[A-Za-z0-9]{20,}", MASK),
            // API keys of the `sk-…` family (Anthropic `sk-ant-…`, OpenAI `sk-proj-…`, …).
            rule(r"\bsk-[A-Za-z0-9_-]{16,}", MASK),
            // AWS access key ids.
            rule(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", MASK),
            // Slack tokens and JSON Web Tokens.
            rule(r"\bxox[abposr]-[A-Za-z0-9-]{10,}", MASK),
            rule(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                MASK,
            ),
            // `Authorization: Bearer …`.
            rule(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}", "$1 [REDACTED]"),
            // `password=…`, `token: …`, `api_key=…` and friends.
            rule(
                r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\s*[=:]\s*)["']?[^\s"',;]+"#,
                "$1$2[REDACTED]",
            ),
            // Credentials in URLs: `scheme://user:pass@host`.
            rule(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", "$1[REDACTED]@"),
        ]
    })
}

/// `text` with every recognised secret replaced.
pub fn redact(text: &str) -> String {
    let mut out = std::borrow::Cow::Borrowed(text);
    for r in rules() {
        if r.re.is_match(&out) {
            out = std::borrow::Cow::Owned(r.re.replace_all(&out, r.with).into_owned());
        }
    }
    out.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_token_formats_are_masked() {
        let cases = [
            ("ghp_abcdefghijklmnopqrstuvwxyz0123", MASK),
            ("github_pat_11ABCDEFG0123456789_abcdefghijklmnop", MASK),
            ("sk-ant-api03-abcdefghijklmnopqrstu", MASK),
            ("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX", MASK),
            ("AKIAIOSFODNN7EXAMPLE", MASK),
            ("xoxb-1234567890-abcdefghij", MASK),
            ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", MASK),
        ];
        for (secret, mask) in cases {
            let out = redact(&format!("use {secret} now"));
            assert_eq!(out, format!("use {mask} now"), "{secret}");
        }
    }

    #[test]
    fn bearer_password_and_url_credentials_keep_their_context() {
        assert_eq!(
            redact("Authorization: Bearer abc.def-ghi_jkl"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            redact("password=hunter22 and TOKEN: 'abcd' x"),
            "password=[REDACTED] and TOKEN: [REDACTED]' x"
        );
        assert_eq!(
            redact("clone https://user:s3cret@example.invalid/r.git"),
            "clone https://[REDACTED]@example.invalid/r.git"
        );
    }

    #[test]
    fn private_keys_are_removed_even_when_truncated() {
        let text = "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nafter";
        assert_eq!(redact(text), "key:\n[REDACTED PRIVATE KEY]\nafter");
        assert_eq!(
            redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE (cut off"),
            "[REDACTED PRIVATE KEY]"
        );
    }

    #[test]
    fn ordinary_text_is_untouched() {
        for t in [
            "Fix the skeleton loader in sketch-mode",
            "the token bucket algorithm",
            "visit https://example.invalid/a:b",
            "",
        ] {
            assert_eq!(redact(t), t);
        }
    }
}
