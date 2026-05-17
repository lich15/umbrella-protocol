//! HKDF-SHA256 и HKDF-SHA512 с обязательными domain-separation labels.
//! HKDF-SHA256 and HKDF-SHA512 with mandatory domain-separation labels.
//!
//! RFC 5869. Используется везде где нужно derive ключи из shared secret или master key.
//! Все вызовы требуют explicit `info` label вида `"umbrellax-<purpose>-v1"`.
//!
//! RFC 5869. Used everywhere we derive keys from a shared secret or master key.
//! Every call requires an explicit `info` label like `"umbrellax-<purpose>-v1"`.

#![forbid(unsafe_code)]

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

use crate::error::{CryptoError, Result};
use crate::secret::SecretBytes;

/// Максимальная длина выхода HKDF-SHA256 = 255 × 32 = 8160 байт (RFC 5869 §2.3).
/// Maximum HKDF-SHA256 output length = 255 × 32 = 8160 bytes (RFC 5869 §2.3).
pub const HKDF_SHA256_MAX_OUTPUT: usize = 255 * 32;

/// Максимальная длина выхода HKDF-SHA512 = 255 × 64 = 16320 байт (RFC 5869 §2.3).
/// Maximum HKDF-SHA512 output length = 255 × 64 = 16320 bytes (RFC 5869 §2.3).
pub const HKDF_SHA512_MAX_OUTPUT: usize = 255 * 64;

/// HKDF-SHA256 extract+expand за один шаг; возвращает SecretBytes длины N.
/// HKDF-SHA256 extract+expand in one step; returns SecretBytes of length N.
pub fn hkdf_sha256<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes<N>> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = SecretBytes::<N>::zeroed();
    hk.expand(info, okm.expose_mut())
        .map_err(|_| CryptoError::InvalidLength {
            expected: HKDF_SHA256_MAX_OUTPUT,
            got: N,
        })?;
    Ok(okm)
}

/// HKDF-SHA512 extract+expand за один шаг.
/// HKDF-SHA512 extract+expand in one step.
pub fn hkdf_sha512<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes<N>> {
    let hk = Hkdf::<Sha512>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = SecretBytes::<N>::zeroed();
    hk.expand(info, okm.expose_mut())
        .map_err(|_| CryptoError::InvalidLength {
            expected: HKDF_SHA512_MAX_OUTPUT,
            got: N,
        })?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn rfc5869_test_vector_1_sha256() {
        // RFC 5869 Appendix A.1 — Test Case 1 with SHA-256.
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let okm = hkdf_sha256::<42>(&salt, &ikm, &info).unwrap();
        assert!(bool::from(okm.expose().ct_eq(&expected[..])));
    }

    #[test]
    fn different_info_different_output() {
        let ikm = b"some-ikm-32-bytes-long-padded!!";
        let salt = b"salt";
        let a = hkdf_sha256::<32>(salt, ikm, b"label-a").unwrap();
        let b = hkdf_sha256::<32>(salt, ikm, b"label-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_salt_works() {
        // Когда salt пустой, HKDF интерпретирует как нулевой salt.
        // When salt is empty, HKDF treats it as a zero salt.
        let ikm = b"some-ikm";
        let okm = hkdf_sha512::<32>(b"", ikm, b"info").unwrap();
        assert_eq!(okm.expose().len(), 32);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }
}
