//! Token primitives: CSPRNG, SHA-256 hashing, constant-time comparison.
//! Tokens are 32 random bytes encoded URL-safe base64 without padding (43 characters).

use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const TOKEN_BYTES: usize = 32;
pub const TOKEN_CHARS: usize = 43;

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| Error::new(format!("operating system random source failed: {e}")))?;
    Ok(buf)
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw)
        .map_err(|e| Error::new(format!("operating system random source failed: {e}")))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// A new random token (plaintext: show it to its owner once, store only [`hash_token`]).
pub fn new_token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<TOKEN_BYTES>()?))
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Cheap structural check before hashing: right length and alphabet.
pub fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_CHARS
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_wellformed_and_hash_stably() {
        let a = new_token().unwrap();
        let b = new_token().unwrap();
        assert_ne!(a, b);
        assert!(is_well_formed(&a) && is_well_formed(&b));
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), hash_token(&b));
    }

    #[test]
    fn malformed_tokens_are_rejected_early() {
        for bad in [
            "",
            "short",
            &"a".repeat(44),
            &format!("{}!", "a".repeat(42)),
            &format!("{}é", "a".repeat(41)),
        ] {
            assert!(!is_well_formed(bad), "{bad}");
        }
    }

    #[test]
    fn known_sha256_vector() {
        let h = hash_token("abc");
        assert_eq!(
            h.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_compare_matches_equality() {
        let a = hash_token("x");
        assert!(digests_equal(&a, &hash_token("x")));
        assert!(!digests_equal(&a, &hash_token("y")));
    }

    #[test]
    fn random_hex_has_expected_length_and_alphabet() {
        let id = random_hex(16).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn base64url_roundtrip() {
        let enc = base64url_encode(b"hello?>");
        assert_eq!(base64url_decode(&enc).unwrap(), b"hello?>");
        assert!(base64url_decode("***").is_none());
    }
}
