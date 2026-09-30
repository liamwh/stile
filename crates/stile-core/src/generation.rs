//! Cryptographically secure secret generation. Output length is derived
//! from declared entropy bytes; values are never printed or logged.

use rand::RngCore;

/// Generation errors.
#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    /// Declared parameters invalid.
    #[error("invalid generation parameters: {0}")]
    Invalid(String),
}

/// A generated secret value held in memory. `Debug` is deliberately
/// manually implemented to never display the value.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedSecret(String);

impl GeneratedSecret {
    /// The raw value. Broker-side use only.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Opaque non-sensitive change indicator (boolean only at the API; the
    /// digest itself stays internal).
    pub fn digest_changed(&self, previous: Option<&str>) -> bool {
        match previous {
            Some(prev) => prev != self.0,
            None => true,
        }
    }
}

impl std::fmt::Debug for GeneratedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeneratedSecret(<{} chars redacted>)", self.0.len())
    }
}

/// Generate `bytes` bytes of entropy encoded as lowercase hex.
pub fn generate_hex(bytes: usize) -> Result<GeneratedSecret, GenerationError> {
    if bytes < 16 {
        return Err(GenerationError::Invalid(format!(
            "{bytes} bytes is below the 16-byte minimum"
        )));
    }
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    Ok(GeneratedSecret(hex_encode(&buf)))
}

/// Generate `bytes` bytes of entropy encoded as unpadded URL-safe base64.
pub fn generate_urlsafe(bytes: usize) -> Result<GeneratedSecret, GenerationError> {
    if bytes < 16 {
        return Err(GenerationError::Invalid(format!(
            "{bytes} bytes is below the 16-byte minimum"
        )));
    }
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    Ok(GeneratedSecret(b64url_encode(&buf)))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn hex_length_is_two_chars_per_byte() {
        let secret = generate_hex(32).expect("generate");
        assert_eq!(secret.as_str().len(), 64);
        assert!(secret.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn urlsafe_charset_and_length() {
        let secret = generate_urlsafe(32).expect("generate");
        assert_eq!(secret.as_str().len(), 43); // ceil(32/3)*4 minus padding
        assert!(
            secret
                .as_str()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn generated_values_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let secret = generate_hex(32).expect("generate");
            assert!(seen.insert(secret.as_str().to_string()), "collision");
        }
    }

    #[test]
    fn rejects_low_entropy() {
        assert!(generate_hex(8).is_err());
        assert!(generate_urlsafe(15).is_err());
    }

    #[test]
    fn debug_never_reveals_value() {
        let secret = generate_hex(32).expect("generate");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains(secret.as_str()));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn digest_changed_is_boolean_only() {
        let secret = generate_hex(32).expect("generate");
        assert!(secret.digest_changed(None));
        assert!(secret.digest_changed(Some("other")));
        assert!(!secret.digest_changed(Some(secret.as_str())));
    }
}
