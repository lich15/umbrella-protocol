//! SLH-DSA-SHA2-128f-simple (NIST FIPS 205) wrapper через `fips205 0.4.1`.
//! SLH-DSA-SHA2-128f-simple (NIST FIPS 205) wrapper using `fips205 0.4.1`.
//!
//! Hash-based stateless backup signature scheme. **Не используется в hot path**
//! (17 KB подпись, ~15 ms signing time); только в:
//! - Catastrophic recovery подпись (когда identity key утерян и нужен fallback
//!   через BIP-39 mnemonic + дополнительный SLH-DSA seed).
//! - Version-locking attestation для производственных билдов.
//! - Code signing метаданных KAT vectors в `umbrella-vectors`.
//!
//! Hash-based stateless backup signature scheme. **Not used in hot path**
//! (17 KB signature, ~15 ms signing time); only for:
//! - Catastrophic recovery signature (when identity key is lost and a fallback
//!   via BIP-39 mnemonic + extra SLH-DSA seed is needed).
//! - Version-locking attestation for production builds.
//! - Code signing for KAT vector metadata in `umbrella-vectors`.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};

use crate::constants::{
    SLH_DSA_128F_PUBLIC_KEY_LEN, SLH_DSA_128F_SECRET_KEY_LEN, SLH_DSA_128F_SIGNATURE_LEN,
};
use crate::error::{PqError, Result};

/// SLH-DSA-128f public key (32 bytes по FIPS 205 §10.4).
/// SLH-DSA-128f public key (32 bytes per FIPS 205 §10.4).
#[derive(Clone)]
pub struct SlhDsa128fPublicKey {
    bytes: [u8; SLH_DSA_128F_PUBLIC_KEY_LEN],
}

// Mini-extension блока 8.5 (umbrella-kt KT v2 schema): KtEntryV2 содержит
// `Option<SlhDsa128fPublicKey>` и derive'ит `Debug + PartialEq + Eq`. Чтобы
// `Option<SlhDsa128fPublicKey>` поддерживал эти trait'ы, добавляем manual impls
// здесь — public key не секретный (32 bytes hash output), ordinary equality OK.
//
// Mini-extension for block 8.5 (umbrella-kt KT v2 schema): `KtEntryV2` carries
// `Option<SlhDsa128fPublicKey>` and derives `Debug + PartialEq + Eq`. To make
// `Option<SlhDsa128fPublicKey>` honour those traits we add manual impls here —
// the public key is not secret (32-byte hash output), so plain equality is fine.
impl PartialEq for SlhDsa128fPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SlhDsa128fPublicKey {}

impl fmt::Debug for SlhDsa128fPublicKey {
    /// Truncated debug: показывает префикс 4 byte + общую длину. Public key
    /// не секрет, но избегаем заполнять logs полным 32-byte hex.
    /// Truncated debug: shows the 4-byte prefix plus the total length. The
    /// public key is not secret, but we avoid spamming logs with full 32-byte hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SlhDsa128fPublicKey({:02x}{:02x}{:02x}{:02x}…{}B)",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3], SLH_DSA_128F_PUBLIC_KEY_LEN
        )
    }
}

/// SLH-DSA-128f secret key (64 bytes по FIPS 205 §10.4). В `SecretBox` с zeroize on drop.
/// SLH-DSA-128f secret key (64 bytes per FIPS 205 §10.4). In `SecretBox` with zeroize on drop.
pub struct SlhDsa128fSecretKey {
    inner: SecretBox<[u8; SLH_DSA_128F_SECRET_KEY_LEN]>,
}

/// SLH-DSA-128f signature (17088 bytes). Хранится на heap через `Box`.
/// SLH-DSA-128f signature (17088 bytes). Stored on heap via `Box`.
pub struct SlhDsa128fSignature {
    bytes: Box<[u8; SLH_DSA_128F_SIGNATURE_LEN]>,
}

impl Clone for SlhDsa128fSignature {
    fn clone(&self) -> Self {
        Self {
            bytes: Box::new(*self.bytes),
        }
    }
}

impl SlhDsa128fPublicKey {
    /// Сериализация в bytes.
    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; SLH_DSA_128F_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SLH_DSA_128F_PUBLIC_KEY_LEN {
            return Err(PqError::SlhDsaInvalidPublicKey { got: bytes.len() });
        }
        let mut buf = [0u8; SLH_DSA_128F_PUBLIC_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

impl SlhDsa128fSecretKey {
    pub(crate) fn expose(&self) -> &[u8; SLH_DSA_128F_SECRET_KEY_LEN] {
        self.inner.expose_secret()
    }
}

impl SlhDsa128fSignature {
    /// Сериализация в bytes (slice, без копирования).
    /// Serialize to bytes (slice, no copy).
    pub fn as_bytes(&self) -> &[u8; SLH_DSA_128F_SIGNATURE_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SLH_DSA_128F_SIGNATURE_LEN {
            return Err(PqError::SlhDsaInvalidSignature { got: bytes.len() });
        }
        let mut buf = Box::new([0u8; SLH_DSA_128F_SIGNATURE_LEN]);
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

/// SLH-DSA-128f KeyGen (FIPS 205 §10.4).
///
/// Использует `fips205 0.4.1` который совместим с rand_core 0.6 (наш workspace).
/// Uses `fips205 0.4.1` which is rand_core 0.6 compatible (our workspace).
pub fn slh_dsa_128f_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(SlhDsa128fPublicKey, SlhDsa128fSecretKey)> {
    use fips205::slh_dsa_sha2_128f::KG;
    use fips205::traits::{KeyGen, SerDes};

    let (pk, sk) = KG::try_keygen_with_rng(rng).map_err(|e| PqError::BackendError {
        message: format!("slh_dsa keygen: {e}"),
    })?;

    let pk_bytes_arr: [u8; SLH_DSA_128F_PUBLIC_KEY_LEN] = pk.into_bytes();
    let sk_bytes_arr: [u8; SLH_DSA_128F_SECRET_KEY_LEN] = sk.into_bytes();

    Ok((
        SlhDsa128fPublicKey {
            bytes: pk_bytes_arr,
        },
        SlhDsa128fSecretKey {
            inner: SecretBox::new(Box::new(sk_bytes_arr)),
        },
    ))
}

/// SLH-DSA-128f Sign (FIPS 205 §10.5). Hedged-randomness mode.
///
/// `context` — domain separation byte string (FIPS 205 context).
///
/// Принимает `rng` параметр потому что fips205 0.4.1 без `default-rng` feature
/// предоставляет только `try_sign_with_rng(rng, ...)` (а не `try_sign(...)`).
/// Это согласуется с RNG injection pattern в umbrella-pq.
///
/// `context` — domain separation byte string (FIPS 205 context).
///
/// Takes `rng` parameter because fips205 0.4.1 without `default-rng` feature
/// only exposes `try_sign_with_rng(rng, ...)` (not `try_sign(...)`). This matches
/// the RNG injection pattern across umbrella-pq.
pub fn slh_dsa_128f_sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    sk: &SlhDsa128fSecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<SlhDsa128fSignature> {
    use fips205::slh_dsa_sha2_128f::PrivateKey as FipsSk;
    use fips205::traits::{SerDes, Signer};

    let sk_fips = FipsSk::try_from_bytes(sk.expose()).map_err(|e| PqError::BackendError {
        message: format!("slh_dsa sk decode: {e}"),
    })?;

    // hedged = true — добавляет fault-injection resistance (NIST SP 800-204 рекомендация).
    let sig_arr: [u8; SLH_DSA_128F_SIGNATURE_LEN] = sk_fips
        .try_sign_with_rng(rng, message, context, true)
        .map_err(|e| PqError::BackendError {
            message: format!("slh_dsa sign: {e}"),
        })?;

    Ok(SlhDsa128fSignature {
        bytes: Box::new(sig_arr),
    })
}

/// SLH-DSA-128f проверка подписи (FIPS 205 §10.6).
/// SLH-DSA-128f Verify (FIPS 205 §10.6).
pub fn slh_dsa_128f_verify(
    pk: &SlhDsa128fPublicKey,
    message: &[u8],
    context: &[u8],
    sig: &SlhDsa128fSignature,
) -> Result<()> {
    use fips205::slh_dsa_sha2_128f::PublicKey as FipsPk;
    use fips205::traits::{SerDes, Verifier};

    let pk_fips = FipsPk::try_from_bytes(&pk.bytes).map_err(|e| PqError::BackendError {
        message: format!("slh_dsa pk decode: {e}"),
    })?;

    if pk_fips.verify(message, sig.as_bytes(), context) {
        Ok(())
    } else {
        Err(PqError::SlhDsaSignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn slh_dsa_128f_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let sig = slh_dsa_128f_sign(&mut rng, &sk, b"backup recovery", b"slh-dsa-test").unwrap();
        assert!(slh_dsa_128f_verify(&pk, b"backup recovery", b"slh-dsa-test", &sig).is_ok());
    }

    #[test]
    fn slh_dsa_128f_signature_size_constant() {
        assert_eq!(SLH_DSA_128F_SIGNATURE_LEN, 17_088);
    }

    #[test]
    fn slh_dsa_128f_wrong_message_rejected() {
        let mut rng = OsRng;
        let (pk, sk) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let sig = slh_dsa_128f_sign(&mut rng, &sk, b"original", b"ctx").unwrap();
        assert!(matches!(
            slh_dsa_128f_verify(&pk, b"tampered", b"ctx", &sig),
            Err(PqError::SlhDsaSignatureVerificationFailed)
        ));
    }

    #[test]
    fn slh_dsa_128f_invalid_pubkey_rejected() {
        let bad = [0u8; 100];
        let result = SlhDsa128fPublicKey::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::SlhDsaInvalidPublicKey { got: 100 })
        ));
    }

    #[test]
    fn slh_dsa_128f_invalid_signature_rejected() {
        let bad = vec![0u8; 100];
        let result = SlhDsa128fSignature::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::SlhDsaInvalidSignature { got: 100 })
        ));
    }
}
