//! AEAD-обёртка для SFrame: AES-256-GCM-SHA512-128 (RFC 9605 §5.2, ID `0x0005`).
//!
//! Два базовых операционных элемента:
//!
//! - `build_nonce` — детерминированное построение per-frame nonce из
//!   `sframe_salt` XOR `(zero_pad_4 || counter_be)` по RFC 9605 §5.1.1.
//! - `aes256gcm_encrypt` / `aes256gcm_decrypt` — прямые вызовы
//!   AES-256-GCM через `aes_gcm::Aes256Gcm` с `aad` равным canonical-header
//!   bytes (RFC 9605 §4.4).
//!
//! Ни один из примитивов не требует `&mut self` и не накапливает состояние —
//! `SframeContext` (см. [`crate::sframe::frame`]) управляет ключами, nonce и
//! anti-replay window. Здесь — тонкий crypto-слой без business-logic.
//!
//! AEAD wrapper for SFrame: AES-256-GCM-SHA512-128 (RFC 9605 §5.2, ID `0x0005`).
//!
//! Two operational primitives:
//!
//! - `build_nonce` — deterministic per-frame nonce construction from
//!   `sframe_salt` XOR `(zero_pad_4 || counter_be)` per RFC 9605 §5.1.1.
//! - `aes256gcm_encrypt` / `aes256gcm_decrypt` — direct AES-256-GCM
//!   invocations via `aes_gcm::Aes256Gcm` with `aad` equal to the canonical
//!   header bytes (RFC 9605 §4.4).
//!
//! None of the primitives require `&mut self` or carry state — `SframeContext`
//! (see [`crate::sframe::frame`]) owns keys, nonces, and the anti-replay
//! window. This module is a thin crypto layer with no business logic.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::error::{CallError, Result};
use crate::sframe::ciphersuite::{AEAD_TAG_LEN, SFRAME_KEY_LEN, SFRAME_SALT_LEN};

/// Собирает per-frame nonce по RFC 9605 §5.1.1:
/// `nonce = sframe_salt XOR (zero_pad_4 || counter_be)`.
///
/// `zero_pad_4` — четыре нулевых байта (так что XOR с ними не изменяет первые 4 байта salt),
/// `counter_be` — 8-байтовый big-endian counter, XOR'ится с byte'ами 4..12 salt'а.
/// Nonce уникален в рамках `(sframe_key, counter)`; AEAD требует nonce-uniqueness
/// на один ключ, что гарантируется anti-replay window + per-KID derivation.
///
/// Builds the per-frame nonce per RFC 9605 §5.1.1:
/// `nonce = sframe_salt XOR (zero_pad_4 || counter_be)`.
///
/// `zero_pad_4` — four zero bytes (XOR with them is a no-op over the first
/// 4 salt bytes). `counter_be` — 8 big-endian counter bytes, XOR'd into salt
/// bytes 4..12. The nonce is unique per `(sframe_key, counter)`; AEAD
/// requires nonce uniqueness under one key, guaranteed by the anti-replay
/// window and per-KID derivation.
pub(crate) fn build_nonce(
    sframe_salt: &[u8; SFRAME_SALT_LEN],
    counter: u64,
) -> [u8; SFRAME_SALT_LEN] {
    let mut nonce = *sframe_salt;
    let ctr_be = counter.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= ctr_be[i];
    }
    nonce
}

/// Шифрует plaintext через AES-256-GCM. Возвращает `ciphertext || tag`
/// суммарной длины `plaintext.len() + AEAD_TAG_LEN`.
///
/// `aad` — canonical-header bytes (RFC 9605 §4.4): CONFIG + KID + CTR.
///
/// Encrypts plaintext under AES-256-GCM. Returns `ciphertext || tag` of
/// total length `plaintext.len() + AEAD_TAG_LEN`.
///
/// `aad` — canonical header bytes (RFC 9605 §4.4): CONFIG + KID + CTR.
pub(crate) fn aes256gcm_encrypt(
    sframe_key: &[u8; SFRAME_KEY_LEN],
    nonce: &[u8; SFRAME_SALT_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(sframe_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CallError::AeadAuthFailure)
}

/// Расшифровывает `ciphertext || tag` через AES-256-GCM. Возвращает
/// plaintext либо [`CallError::AeadAuthFailure`] на любой failure
/// (подмена ciphertext / tag / AAD, неверный ключ/nonce, короткий input).
///
/// Decrypts `ciphertext || tag` via AES-256-GCM. Returns plaintext or
/// [`CallError::AeadAuthFailure`] on any failure (tampered ciphertext / tag
/// / AAD, wrong key/nonce, truncated input).
pub(crate) fn aes256gcm_decrypt(
    sframe_key: &[u8; SFRAME_KEY_LEN],
    nonce: &[u8; SFRAME_SALT_LEN],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_with_tag.len() < AEAD_TAG_LEN {
        return Err(CallError::AeadAuthFailure);
    }
    let key = Key::<Aes256Gcm>::from_slice(sframe_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce_obj,
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map_err(|_| CallError::AeadAuthFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let aad = b"header-bytes";
        let pt = b"hello world this is plaintext";
        let ct = aes256gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + AEAD_TAG_LEN);
        let dec = aes256gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn encrypt_empty_plaintext_ok() {
        let key = [0u8; SFRAME_KEY_LEN];
        let nonce = [0u8; SFRAME_SALT_LEN];
        let aad = b"aad";
        let ct = aes256gcm_encrypt(&key, &nonce, aad, b"").unwrap();
        // 0 plaintext + 16 tag = 16 bytes.
        assert_eq!(ct.len(), AEAD_TAG_LEN);
        let dec = aes256gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let aad = b"header";
        let pt = b"payload";
        let mut ct = aes256gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        ct[0] ^= 0x01;
        let err = aes256gcm_decrypt(&key, &nonce, aad, &ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_tampered_tag_fails() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let aad = b"h";
        let pt = b"payload";
        let mut ct = aes256gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        let err = aes256gcm_decrypt(&key, &nonce, aad, &ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_tampered_aad_fails() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let aad = b"header";
        let pt = b"payload";
        let ct = aes256gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        let err = aes256gcm_decrypt(&key, &nonce, b"DIFFERENT", &ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let mut nonce_bad = nonce;
        nonce_bad[0] ^= 0x01;
        let aad = b"h";
        let pt = b"p";
        let ct = aes256gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        let err = aes256gcm_decrypt(&key, &nonce_bad, aad, &ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key_a = [0x42u8; SFRAME_KEY_LEN];
        let key_b = [0x43u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        let ct = aes256gcm_encrypt(&key_a, &nonce, b"aad", b"secret").unwrap();
        let err = aes256gcm_decrypt(&key_b, &nonce, b"aad", &ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_short_input_fails() {
        let key = [0x42u8; SFRAME_KEY_LEN];
        let nonce = [0x11u8; SFRAME_SALT_LEN];
        // Меньше AEAD_TAG_LEN=16 — не может быть валидным ciphertext||tag.
        // Shorter than AEAD_TAG_LEN=16 — cannot be a valid ciphertext||tag.
        let short = [0u8; 8];
        let err = aes256gcm_decrypt(&key, &nonce, b"", &short).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn build_nonce_xors_only_last_8_bytes() {
        let salt = [0u8; SFRAME_SALT_LEN];
        let nonce = build_nonce(&salt, 0x0123_4567_89AB_CDEF);
        // Первые 4 байта нулевые (XOR с нулевым salt = нули).
        // First 4 bytes zero (XOR with zero salt = zero).
        assert_eq!(&nonce[..4], &[0u8; 4]);
        // Последние 8 байт = counter_be.
        // Last 8 bytes = counter_be.
        assert_eq!(
            &nonce[4..],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn build_nonce_with_nonzero_salt_counter_zero() {
        let salt = [0xAAu8; SFRAME_SALT_LEN];
        let nonce = build_nonce(&salt, 0);
        // Counter=0 → XOR no-op → nonce = salt.
        assert_eq!(nonce, salt);
    }

    #[test]
    fn build_nonce_deterministic_same_inputs() {
        let salt = [0x55u8; SFRAME_SALT_LEN];
        let a = build_nonce(&salt, 0xDEAD_BEEF);
        let b = build_nonce(&salt, 0xDEAD_BEEF);
        assert_eq!(a, b);
    }

    #[test]
    fn build_nonce_different_counter_different_nonce() {
        let salt = [0x55u8; SFRAME_SALT_LEN];
        let a = build_nonce(&salt, 1);
        let b = build_nonce(&salt, 2);
        assert_ne!(a, b);
    }
}
