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
            // PEM and PGP private keys (also an unterminated block at the end of a truncated text).
            rule(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
                "[REDACTED PRIVATE KEY]",
            ),
            // GitHub tokens.
            rule(r"\bgithub_pat_[A-Za-z0-9_]{20,}", MASK),
            rule(r"\bgh[pousr]_[A-Za-z0-9]{20,}", MASK),
            // GitLab personal access tokens, npm tokens, Google API keys.
            rule(r"\bglpat-[A-Za-z0-9_-]{20,}", MASK),
            rule(r"\bnpm_[A-Za-z0-9]{36}\b", MASK),
            rule(r"\bAIza[0-9A-Za-z_-]{35}", MASK),
            // API keys of the `sk-…` family (Anthropic `sk-ant-…`, OpenAI `sk-proj-…`, …) and
            // Stripe-style secret/restricted keys (`sk_live_…`, `rk_test_…`).
            rule(r"\bsk-[A-Za-z0-9_-]{16,}", MASK),
            rule(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}", MASK),
            // AWS access key ids.
            rule(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", MASK),
            // Slack tokens and JSON Web Tokens.
            rule(r"\bxox[abposr]-[A-Za-z0-9-]{10,}", MASK),
            rule(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                MASK,
            ),
            // `Authorization: Bearer …` (any `Bearer <token>`).
            rule(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}", "$1 [REDACTED]"),
            // HTTP Basic credentials: after `Authorization:` any base64 run; a bare `Basic …`
            // only when the run contains a digit, `+`, `/` or `=` (so "basic functionality" is
            // left alone).
            rule(
                r"(?i)\b(authorization\s*[:=]\s*[\x22']?basic)\s+[A-Za-z0-9+/]{8,}={0,2}",
                "$1 [REDACTED]",
            ),
            rule(
                r"\b(Basic)\s+[A-Za-z0-9+/]*[0-9+/][A-Za-z0-9+/]*={0,2}",
                "$1 [REDACTED]",
            ),
            // Assignments whose key **ends** in a secret-like word: `password=`, `DB_PASSWORD=`,
            // `aws_secret_access_key = `, `client_secret: `, and JSON/YAML-quoted keys
            // (`"password": "…"`). A quoted value is masked with its quotes, so none is left
            // dangling.
            rule(
                r#"(?i)(\b[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s"',;]+)"#,
                "$1[REDACTED]",
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
            "password=[REDACTED] and TOKEN: [REDACTED] x",
            "no stray quote is left behind"
        );
        assert_eq!(
            redact("clone https://user:s3cret@example.invalid/r.git"),
            "clone https://[REDACTED]@example.invalid/r.git"
        );
    }

    /// Every row of the M3 security review's M3 table (synthetic values), plus the shapes the
    /// same rules are meant to cover.
    #[test]
    fn the_review_table_is_redacted() {
        let cases: &[(&str, &str)] = &[
            // no word boundary after `_`
            ("DB_PASSWORD=hunter2hunter2", "DB_PASSWORD=[REDACTED]"),
            ("MY_API_KEY=abc123def456", "MY_API_KEY=[REDACTED]"),
            ("client_secret=abc123def456", "client_secret=[REDACTED]"),
            ("client_secret: abc123def456", "client_secret: [REDACTED]"),
            // the AWS secret key has no prefix
            (
                "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
                "export AWS_SECRET_ACCESS_KEY=[REDACTED]",
            ),
            (
                "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
                "aws_secret_access_key = [REDACTED]",
            ),
            // a quote between the key and `:`
            (
                r#"{"password": "hunter2hunter2"}"#,
                r#"{"password": [REDACTED]}"#,
            ),
            (r#"{"api_key": "abc123def456"}"#, r#"{"api_key": [REDACTED]}"#),
            ("password: 'two words'", "password: [REDACTED]"),
            ("private_key: abcdef", "private_key: [REDACTED]"),
            // PGP needs ` BLOCK-----`
            (
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
                "[REDACTED PRIVATE KEY]",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----",
                "[REDACTED PRIVATE KEY]",
            ),
            (
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF",
                "[REDACTED PRIVATE KEY]",
            ),
            // no rule before
            ("sk_live_SYNTHETICabcdefghij0123", MASK),
            ("sk_test_SYNTHETICabcdefghij0123", MASK),
            ("rk_live_SYNTHETICabcdefghij0123", MASK),
            ("glpat-SYNTHETICabcdefghij01", MASK),
            ("npm_SYNTHETICabcdefghijklmnopqrstuvwxyz0", MASK),
            ("AIzaSyA-SYNTHETIC_abcdefghijklmnopqrstu", MASK),
            (
                "Authorization: Basic dXNlcjpwYXNzd29yZA==",
                "Authorization: Basic [REDACTED]",
            ),
            ("Authorization: Basic dXNlcjpwYXNz", "Authorization: Basic [REDACTED]"),
            ("curl -H 'Basic dXNlcjpwYXNzd29yZA=='", "curl -H 'Basic [REDACTED]'"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), *want, "{input}");
        }
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
            "a basic understanding of Basic Rust",
            "max_tokens 4096 and PASSWORD_FILE=/run/secret.txt",
            "",
        ] {
            assert_eq!(redact(t), t);
        }
    }
}
