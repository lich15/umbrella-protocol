//! Hybrid signature: Ed25519 + ML-DSA-65 в AND-mode (NIST SP 800-227 draft 2024).
//! Hybrid signature: Ed25519 + ML-DSA-65 in AND-mode (NIST SP 800-227 draft 2024).
//!
//! Wire format: fixed concatenation `[ed25519_sig 64 bytes || ml_dsa_65_sig 3309 bytes] = 3373 bytes total`.
//!
//! Domain separation context: `b"umbrellax-hybrid-sig-v1"` обязательно
//! prepend'ится к message **только** для Ed25519 component (ML-DSA-65 принимает
//! `context` как нативный параметр через FIPS 204 API).
//!
//! Domain separation context: `b"umbrellax-hybrid-sig-v1"` is mandatory; it is
//! prepended to the message **only** for the Ed25519 component (ML-DSA-65 takes
//! `context` as a native parameter via the FIPS 204 API).
//!
//! Verification — **AND-mode**: оба компонента должны валидировать. Ни один OR-fallback.
//! Verification — **AND-mode**: both components must validate. No OR-fallback.

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, Verifier as _,
    VerifyingKey as EdVerifyingKey, SECRET_KEY_LENGTH,
};
use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::constants::{
    ED25519_SIGNATURE_LEN, HYBRID_CONTEXT, HYBRID_SIGNATURE_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::error::{PqError, Result};
use crate::ml_dsa::{
    ml_dsa_65_keygen, ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey,
    MlDsa65Signature,
};

/// Гибридный публичный ключ: Ed25519 verifying key + ML-DSA-65 verification key.
/// Hybrid public key: Ed25519 verifying key + ML-DSA-65 verification key.
#[derive(Clone)]
pub struct HybridPublicKey {
    /// Ed25519 component (32 bytes pub).
    /// Ed25519 component (32-byte pub).
    pub ed25519: EdVerifyingKey,
    /// ML-DSA-65 component (1952 bytes pub).
    /// ML-DSA-65 component (1952-byte pub).
    pub ml_dsa: MlDsa65PublicKey,
}

/// Гибридный секретный ключ: Ed25519 signing seed + ML-DSA-65 signing key.
/// Hybrid secret key: Ed25519 signing seed + ML-DSA-65 signing key.
pub struct HybridSecretKey {
    /// Ed25519 component (32 bytes seed) в `SecretBox`.
    /// Ed25519 component (32-byte seed) in `SecretBox`.
    pub ed25519: SecretBox<[u8; SECRET_KEY_LENGTH]>,
    /// ML-DSA-65 component (4032 bytes signing key).
    /// ML-DSA-65 component (4032-byte signing key).
    pub ml_dsa: MlDsa65SecretKey,
}

/// Гибридная подпись (3373 байта).
/// Hybrid signature (3373 bytes).
#[derive(Clone)]
pub struct HybridSignature {
    bytes: [u8; HYBRID_SIGNATURE_LEN],
}

impl HybridSignature {
    /// Сериализация в bytes.
    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; HYBRID_SIGNATURE_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SIGNATURE_LEN {
            return Err(PqError::HybridInvalidSignature { got: bytes.len() });
        }
        let mut buf = [0u8; HYBRID_SIGNATURE_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }

    /// Извлечь Ed25519 компонент (первые 64 bytes).
    /// Extract Ed25519 component (first 64 bytes).
    pub fn ed25519_part(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        // Slice [0..64] всегда конвертируется в [u8; 64] — длина гарантирована конструкцией.
        // Slice [0..64] always converts to [u8; 64] — length guaranteed by construction.
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HYBRID_SIGNATURE_LEN > ED25519_SIGNATURE_LEN by const assert"
        )]
        (&self.bytes[..ED25519_SIGNATURE_LEN])
            .try_into()
            .expect("split is valid by construction (HYBRID_SIGNATURE_LEN > ED25519_SIGNATURE_LEN)")
    }

    /// Извлечь ML-DSA-65 компонент (3309 bytes после Ed25519).
    /// Extract ML-DSA-65 component (3309 bytes after Ed25519).
    pub fn ml_dsa_part(&self) -> &[u8; ML_DSA_65_SIGNATURE_LEN] {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: split into ML_DSA_65_SIGNATURE_LEN bytes by construction"
        )]
        (&self.bytes[ED25519_SIGNATURE_LEN..])
            .try_into()
            .expect("split is valid by construction")
    }
}

/// Hybrid keygen: одновременно Ed25519 + ML-DSA-65 keypairs.
/// Hybrid keygen: both Ed25519 + ML-DSA-65 keypairs at once.
pub fn hybrid_keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
    // Ed25519 keypair: ed25519-dalek 2.2 не имеет ::generate(rng); используем manual seed
    // через rng.fill_bytes + SigningKey::from_bytes.
    // Ed25519 keypair: ed25519-dalek 2.2 doesn't have ::generate(rng); use manual seed
    // via rng.fill_bytes + SigningKey::from_bytes.
    let mut ed_seed = [0u8; SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut ed_seed);
    let ed_signing = EdSigningKey::from_bytes(&ed_seed);
    let ed_verifying = ed_signing.verifying_key();
    let ed_secret_bytes = ed_signing.to_bytes();
    // Очищаем временный ed_seed buffer через zeroize::Zeroize ПОСЛЕ from_bytes copy;
    // SigningKey хранит свой owned копию seed (`to_bytes()` производит её) — caller
    // local stack ed_seed теперь уязвим к row 11 Cold-boot если не zeroize'н.
    // Wipe the temporary ed_seed buffer via zeroize::Zeroize AFTER from_bytes copy;
    // SigningKey stores its own owned seed copy (`to_bytes()` produces it) — the
    // caller's local stack ed_seed is now vulnerable to threat row 11 Cold-boot if
    // not zeroized.
    ed_seed.zeroize();

    // ML-DSA-65 keypair
    let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_65_keygen(rng);

    (
        HybridPublicKey {
            ed25519: ed_verifying,
            ml_dsa: ml_dsa_pk,
        },
        HybridSecretKey {
            ed25519: SecretBox::new(Box::new(ed_secret_bytes)),
            ml_dsa: ml_dsa_sk,
        },
    )
}

/// Hybrid sign: подписать message обоими компонентами с domain separation.
///
/// Ed25519 signature: над `HYBRID_CONTEXT || message` (manual prepend).
/// ML-DSA-65 signature: native context API, message = `message`, context = `HYBRID_CONTEXT`.
///
/// Hybrid sign: sign message with both components using domain separation.
///
/// Ed25519 signature: over `HYBRID_CONTEXT || message` (manual prepend).
/// ML-DSA-65 signature: native context API, message = `message`, context = `HYBRID_CONTEXT`.
pub fn hybrid_sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    sk: &HybridSecretKey,
    message: &[u8],
) -> Result<HybridSignature> {
    // Ed25519 part — prepend HYBRID_CONTEXT (Ed25519 не имеет native context API).
    let mut ed_input = Vec::with_capacity(HYBRID_CONTEXT.len() + message.len());
    ed_input.extend_from_slice(HYBRID_CONTEXT);
    ed_input.extend_from_slice(message);

    let ed_signing = EdSigningKey::from_bytes(sk.ed25519.expose_secret());
    let ed_sig: EdSignature = ed_signing.sign(&ed_input);
    let ed_sig_bytes = ed_sig.to_bytes();

    // ML-DSA-65 part — native context API.
    let ml_dsa_sig = ml_dsa_65_sign(rng, &sk.ml_dsa, message, HYBRID_CONTEXT)?;

    // Concatenate: [ed25519 64 || ml_dsa 3309] = 3373 bytes.
    let mut buf = [0u8; HYBRID_SIGNATURE_LEN];
    buf[..ED25519_SIGNATURE_LEN].copy_from_slice(&ed_sig_bytes);
    buf[ED25519_SIGNATURE_LEN..].copy_from_slice(ml_dsa_sig.as_bytes());

    Ok(HybridSignature { bytes: buf })
}

/// Hybrid verify в AND-mode: оба компонента должны валидировать.
///
/// Возвращает `Err(HybridSignatureVerificationFailed { ed25519_ok, ml_dsa_ok })`
/// если хотя бы один из компонентов не валиден. UX/diagnostic полей в ошибке —
/// для отображения причины пользователю (например «обновите ML-DSA backend»),
/// **не** для control flow.
///
/// Hybrid verify in AND-mode: both components must validate.
///
/// Returns `Err(HybridSignatureVerificationFailed { ed25519_ok, ml_dsa_ok })` if
/// at least one component fails. The UX/diagnostic fields in the error are for
/// showing the cause to the user (e.g. "update the ML-DSA backend"), **not** for
/// control flow.
pub fn hybrid_verify(pk: &HybridPublicKey, message: &[u8], sig: &HybridSignature) -> Result<()> {
    // Ed25519 part — verify над `HYBRID_CONTEXT || message`.
    let mut ed_input = Vec::with_capacity(HYBRID_CONTEXT.len() + message.len());
    ed_input.extend_from_slice(HYBRID_CONTEXT);
    ed_input.extend_from_slice(message);

    let ed_sig = EdSignature::from_bytes(sig.ed25519_part());
    let ed25519_ok = pk.ed25519.verify(&ed_input, &ed_sig).is_ok();

    // ML-DSA-65 part — native context API.
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: ml_dsa_part returns &[u8; ML_DSA_65_SIGNATURE_LEN] by type"
    )]
    let ml_dsa_sig =
        MlDsa65Signature::from_bytes(sig.ml_dsa_part()).expect("ml_dsa_part has correct length");
    let ml_dsa_ok = ml_dsa_65_verify(&pk.ml_dsa, message, HYBRID_CONTEXT, &ml_dsa_sig).is_ok();

    if ed25519_ok && ml_dsa_ok {
        Ok(())
    } else {
        Err(PqError::HybridSignatureVerificationFailed {
            ed25519_ok,
            ml_dsa_ok,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, b"hello hybrid").unwrap();
        assert!(hybrid_verify(&pk, b"hello hybrid", &sig).is_ok());
    }

    #[test]
    fn hybrid_signature_size_constant() {
        assert_eq!(HYBRID_SIGNATURE_LEN, 64 + 3309);
        assert_eq!(HYBRID_SIGNATURE_LEN, 3373);
    }

    #[test]
    fn hybrid_ed25519_bit_flip_detected() {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let mut sig = hybrid_sign(&mut rng, &sk, b"msg").unwrap();
        sig.bytes[10] ^= 0x01; // flip in Ed25519 part (offset 0..64)
        let result = hybrid_verify(&pk, b"msg", &sig);
        assert!(matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed {
                ed25519_ok: false,
                ml_dsa_ok: true
            })
        ));
    }

    #[test]
    fn hybrid_ml_dsa_bit_flip_detected() {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let mut sig = hybrid_sign(&mut rng, &sk, b"msg").unwrap();
        sig.bytes[100] ^= 0x01; // flip in ML-DSA part (offset 64..3373)
        let result = hybrid_verify(&pk, b"msg", &sig);
        assert!(matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed {
                ed25519_ok: true,
                ml_dsa_ok: false
            })
        ));
    }

    #[test]
    fn hybrid_wrong_message_detected_in_both_components() {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, b"original").unwrap();
        let result = hybrid_verify(&pk, b"tampered", &sig);
        // Both components должны fail для wrong message.
        assert!(matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed {
                ed25519_ok: false,
                ml_dsa_ok: false
            })
        ));
    }

    #[test]
    fn hybrid_signature_byte_roundtrip() {
        let mut rng = OsRng;
        let (_, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, b"msg").unwrap();
        let sig_bytes = sig.as_bytes();
        let sig_decoded = HybridSignature::from_bytes(sig_bytes).unwrap();
        assert_eq!(sig_decoded.as_bytes(), sig_bytes);
    }

    #[test]
    fn hybrid_invalid_signature_size_rejected() {
        let bad = vec![0u8; 100];
        let result = HybridSignature::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::HybridInvalidSignature { got: 100 })
        ));
    }
}
