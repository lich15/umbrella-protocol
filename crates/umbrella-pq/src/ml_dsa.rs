//! ML-DSA-65 (NIST FIPS 204) wrapper через `libcrux-ml-dsa 0.0.8` derand API.
//! ML-DSA-65 (NIST FIPS 204) wrapper using `libcrux-ml-dsa 0.0.8` derand API.
//!
//! Hedged-randomness mode (NIST SP 800-204): signature использует rng-derived
//! 32-byte randomness вместе с deterministic компонентом для дополнительной
//! защиты от fault injection.
//!
//! Hedged-randomness mode (NIST SP 800-204): signature uses rng-derived 32-byte
//! randomness alongside the deterministic component for extra fault-injection
//! resistance.

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::constants::{
    ML_DSA_65_KEYGEN_RANDOMNESS_LEN, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN, ML_DSA_65_SIGNING_RANDOMNESS_LEN,
};
use crate::error::{PqError, Result};

/// ML-DSA-65 public (verification) key (1952 bytes по FIPS 204).
/// ML-DSA-65 public (verification) key (1952 bytes per FIPS 204).
#[derive(Clone)]
pub struct MlDsa65PublicKey {
    bytes: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

/// ML-DSA-65 secret (signing) key (4032 bytes по FIPS 204). В `SecretBox` с zeroize on drop.
/// ML-DSA-65 secret (signing) key (4032 bytes per FIPS 204). In `SecretBox` with zeroize on drop.
pub struct MlDsa65SecretKey {
    inner: SecretBox<[u8; ML_DSA_65_SECRET_KEY_LEN]>,
}

/// ML-DSA-65 signature (3309 bytes по FIPS 204).
/// ML-DSA-65 signature (3309 bytes per FIPS 204).
#[derive(Clone)]
pub struct MlDsa65Signature {
    bytes: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl MlDsa65PublicKey {
    /// Сериализация в bytes.
    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(PqError::MlDsaInvalidPublicKey { got: bytes.len() });
        }
        let mut buf = [0u8; ML_DSA_65_PUBLIC_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

impl MlDsa65SecretKey {
    pub(crate) fn expose(&self) -> &[u8; ML_DSA_65_SECRET_KEY_LEN] {
        self.inner.expose_secret()
    }
}

impl MlDsa65Signature {
    /// Сериализация в bytes.
    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_SIGNATURE_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(PqError::MlDsaInvalidSignature { got: bytes.len() });
        }
        let mut buf = [0u8; ML_DSA_65_SIGNATURE_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

/// ML-DSA-65 генерация пары ключей (FIPS 204 §6.1).
/// ML-DSA-65 KeyGen (FIPS 204 §6.1).
pub fn ml_dsa_65_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (MlDsa65PublicKey, MlDsa65SecretKey) {
    let mut randomness = [0u8; ML_DSA_65_KEYGEN_RANDOMNESS_LEN];
    rng.fill_bytes(&mut randomness);

    // libcrux::generate_key_pair consumes randomness by value; создаём local stack copy
    // которая после move-consumption всё равно может оставаться в stack frame.
    // libcrux::generate_key_pair consumes randomness by value; we create a local stack
    // copy that may still remain in the stack frame after move-consumption.
    let kp = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(randomness);
    // Очищаем local stack copy of randomness через zeroize::Zeroize.
    // Wipe the local stack copy of randomness via zeroize::Zeroize.
    randomness.zeroize();

    let pk_bytes: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = *kp.verification_key.as_ref();
    let sk_bytes: [u8; ML_DSA_65_SECRET_KEY_LEN] = *kp.signing_key.as_ref();

    (
        MlDsa65PublicKey { bytes: pk_bytes },
        MlDsa65SecretKey {
            inner: SecretBox::new(Box::new(sk_bytes)),
        },
    )
}

/// ML-DSA-65 Sign (FIPS 204 §6.2). Hedged-randomness mode.
///
/// `context` — domain separation byte string длиной до 255 байт (может быть пустым).
/// `context` — domain separation byte string up to 255 bytes (may be empty).
pub fn ml_dsa_65_sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    sk: &MlDsa65SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa65Signature> {
    let mut sign_randomness = [0u8; ML_DSA_65_SIGNING_RANDOMNESS_LEN];
    rng.fill_bytes(&mut sign_randomness);

    let sk_libcrux = libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey::new(*sk.expose());

    // libcrux::sign consumes sign_randomness by value (move); local stack copy остаётся
    // в frame после consumption — zeroize'им через result-binding pattern.
    // libcrux::sign consumes sign_randomness by value (move); the local stack copy
    // remains in the frame after consumption — zeroize via the result-binding pattern.
    let sign_result =
        libcrux_ml_dsa::ml_dsa_65::sign(&sk_libcrux, message, context, sign_randomness);
    sign_randomness.zeroize();
    let sig = sign_result.map_err(|e| PqError::BackendError {
        message: format!("ml_dsa_65 sign: {e:?}"),
    })?;

    let sig_bytes: [u8; ML_DSA_65_SIGNATURE_LEN] = *sig.as_ref();
    Ok(MlDsa65Signature { bytes: sig_bytes })
}

/// ML-DSA-65 проверка подписи (FIPS 204 §6.3).
/// ML-DSA-65 Verify (FIPS 204 §6.3).
pub fn ml_dsa_65_verify(
    pk: &MlDsa65PublicKey,
    message: &[u8],
    context: &[u8],
    sig: &MlDsa65Signature,
) -> Result<()> {
    let pk_libcrux = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey::new(pk.bytes);
    let sig_libcrux = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(sig.bytes);

    libcrux_ml_dsa::ml_dsa_65::verify(&pk_libcrux, message, context, &sig_libcrux)
        .map_err(|_| PqError::MlDsaSignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ml_dsa_65_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let msg = b"hello hybrid pq";
        let ctx = b"test-context";
        let sig = ml_dsa_65_sign(&mut rng, &sk, msg, ctx).unwrap();
        assert!(ml_dsa_65_verify(&pk, msg, ctx, &sig).is_ok());
    }

    #[test]
    fn ml_dsa_65_signature_bit_flip_rejected() {
        let mut rng = OsRng;
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let mut sig = ml_dsa_65_sign(&mut rng, &sk, b"msg", b"ctx").unwrap();
        sig.bytes[100] ^= 0x01;
        assert!(matches!(
            ml_dsa_65_verify(&pk, b"msg", b"ctx", &sig),
            Err(PqError::MlDsaSignatureVerificationFailed)
        ));
    }

    #[test]
    fn ml_dsa_65_wrong_message_rejected() {
        let mut rng = OsRng;
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let sig = ml_dsa_65_sign(&mut rng, &sk, b"original", b"ctx").unwrap();
        assert!(matches!(
            ml_dsa_65_verify(&pk, b"tampered", b"ctx", &sig),
            Err(PqError::MlDsaSignatureVerificationFailed)
        ));
    }

    #[test]
    fn ml_dsa_65_wrong_context_rejected() {
        let mut rng = OsRng;
        let (pk, sk) = ml_dsa_65_keygen(&mut rng);
        let sig = ml_dsa_65_sign(&mut rng, &sk, b"msg", b"ctx-A").unwrap();
        assert!(matches!(
            ml_dsa_65_verify(&pk, b"msg", b"ctx-B", &sig),
            Err(PqError::MlDsaSignatureVerificationFailed)
        ));
    }

    #[test]
    fn ml_dsa_65_invalid_pubkey_rejected() {
        let bad = [0u8; 100];
        let result = MlDsa65PublicKey::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::MlDsaInvalidPublicKey { got: 100 })
        ));
    }

    #[test]
    fn ml_dsa_65_invalid_signature_rejected() {
        let bad = vec![0u8; 100];
        let result = MlDsa65Signature::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::MlDsaInvalidSignature { got: 100 })
        ));
    }

    #[test]
    fn ml_dsa_65_signature_byte_roundtrip() {
        let mut rng = OsRng;
        let (_, sk) = ml_dsa_65_keygen(&mut rng);
        let sig = ml_dsa_65_sign(&mut rng, &sk, b"msg", b"ctx").unwrap();
        let sig_bytes = sig.as_bytes();
        let sig_decoded = MlDsa65Signature::from_bytes(sig_bytes).unwrap();
        assert_eq!(sig_decoded.as_bytes(), sig_bytes);
    }
}
