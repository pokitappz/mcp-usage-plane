//! Encryption at rest for customer billing credentials.
//!
//! AEAD (ChaCha20-Poly1305) with a fresh 12-byte nonce per value, stored as
//! `enc:<base64(nonce||ciphertext)>`.
//!
//! Two things are deliberate. There is no plaintext read path: this table has
//! never held a plaintext credential and never will, so anything without the
//! prefix is an error rather than a value to trust. And the key is a value
//! loaded once at startup rather than an environment lookup on every call, so
//! the crypto is testable without mutating process-global state.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

const PREFIX: &str = "enc:";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// The environment variable the key is read from at startup.
pub const KEY_VAR: &str = "SECRET_SEALING_KEY";

/// Why a secret could not be sealed or opened.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    /// No sealing key is configured.
    #[error("{KEY_VAR} is required to store billing credentials")]
    KeyMissing,
    /// A key is configured but unusable.
    #[error("{KEY_VAR} is set but is not a base64-encoded {KEY_LEN}-byte key")]
    KeyInvalid,
    /// The stored value is not a sealed envelope.
    #[error("stored credential is not sealed")]
    NotSealed,
    /// The envelope is malformed, truncated, or was not sealed with this key.
    #[error("stored credential could not be opened")]
    Unopenable,
}

/// A validated sealing key, loaded once at startup.
#[derive(Clone)]
pub struct SealingKey([u8; KEY_LEN]);

impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealingKey([REDACTED])")
    }
}

/// Parse a base64 key. Separated from the environment so it is testable.
///
/// # Errors
///
/// Returns [`SecretError::KeyInvalid`] unless the value decodes to exactly 32
/// bytes.
pub fn parse_key(raw: &str) -> Result<SealingKey, SecretError> {
    let bytes = STANDARD
        .decode(raw.trim())
        .map_err(|_| SecretError::KeyInvalid)?;
    let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SecretError::KeyInvalid)?;
    Ok(SealingKey(key))
}

/// Load the key from the environment.
///
/// `Ok(None)` means no key is set at all. An `Err` means one is set but wrong,
/// which is the case this exists for: a key that silently degrades to "absent"
/// on a typo is a security control switching itself off, and the right response
/// to a mistake is to refuse to start.
///
/// # Errors
///
/// Returns [`SecretError::KeyInvalid`] when the variable is set but malformed.
pub fn key_from_env() -> Result<Option<SealingKey>, SecretError> {
    let Ok(raw) = std::env::var(KEY_VAR) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    parse_key(&raw).map(Some)
}

impl SealingKey {
    /// Seal a credential for storage.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Unopenable`] if the AEAD refuses the input. It
    /// never falls back to storing plaintext.
    pub fn seal(&self, plaintext: &str) -> Result<String, SecretError> {
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| SecretError::KeyInvalid)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| SecretError::Unopenable)?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&ciphertext);
        Ok(format!("{PREFIX}{}", STANDARD.encode(envelope)))
    }

    /// Open a sealed credential.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError`] when the value is not a sealed envelope or the
    /// envelope does not authenticate under this key.
    pub fn open(&self, stored: &str) -> Result<String, SecretError> {
        let encoded = stored.strip_prefix(PREFIX).ok_or(SecretError::NotSealed)?;
        let raw = STANDARD
            .decode(encoded)
            .map_err(|_| SecretError::Unopenable)?;
        if raw.len() <= NONCE_LEN {
            return Err(SecretError::Unopenable);
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| SecretError::KeyInvalid)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| SecretError::Unopenable)?;
        String::from_utf8(plaintext).map_err(|_| SecretError::Unopenable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SealingKey {
        parse_key(&STANDARD.encode([byte; KEY_LEN])).expect("valid key")
    }

    #[test]
    fn sealing_round_trips() {
        let key = key(7);
        let sealed = key.seal("sk_test_abc123").expect("seals");
        assert!(sealed.starts_with(PREFIX), "envelope must be recognizable");
        assert!(
            !sealed.contains("sk_test_abc123"),
            "the plaintext must not survive in the envelope"
        );
        assert_eq!(key.open(&sealed).expect("opens"), "sk_test_abc123");
    }

    #[test]
    fn a_fresh_nonce_is_used_per_value() {
        let key = key(7);
        assert_ne!(
            key.seal("same-secret").expect("seals"),
            key.seal("same-secret").expect("seals again")
        );
    }

    #[test]
    fn plaintext_is_never_accepted_as_a_stored_value() {
        assert_eq!(key(7).open("sk_test_abc123"), Err(SecretError::NotSealed));
    }

    #[test]
    fn a_tampered_or_truncated_envelope_does_not_authenticate() {
        let key = key(7);
        assert_eq!(key.open("enc:AAAA"), Err(SecretError::Unopenable));
        let sealed = key.seal("secret").expect("seals");
        let tampered = format!("{}A", &sealed[..sealed.len() - 1]);
        assert_eq!(key.open(&tampered), Err(SecretError::Unopenable));
    }

    #[test]
    fn another_key_cannot_open_it() {
        let sealed = key(7).seal("secret").expect("seals");
        assert_eq!(key(9).open(&sealed), Err(SecretError::Unopenable));
    }

    #[test]
    fn a_present_but_wrong_key_is_an_error_not_a_silent_downgrade() {
        assert_eq!(
            parse_key("not-base64!!").unwrap_err(),
            SecretError::KeyInvalid
        );
        // Right encoding, wrong length.
        assert_eq!(
            parse_key(&STANDARD.encode([0u8; 16])).unwrap_err(),
            SecretError::KeyInvalid
        );
    }
}
