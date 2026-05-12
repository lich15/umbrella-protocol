//! Integration tests для hybrid identity layer (Этап 8 ADR-011 Решение 5).
//! Integration tests for the hybrid identity layer (Stage 8 ADR-011 Decision 5).
//!
//! Эти тесты работают через **публичный** API `KeyStore` trait + `InMemoryKeyStore`
//! impl — то есть с точки зрения downstream крейтов (umbrella-mls, umbrella-kt,
//! umbrella-sealed-sender), которые вызовут hybrid identity через тот же trait
//! в production.
//!
//! These tests work through the **public** API of the `KeyStore` trait + the
//! `InMemoryKeyStore` impl — i.e., from the perspective of downstream crates
//! (umbrella-mls, umbrella-kt, umbrella-sealed-sender), which will use the hybrid
//! identity through the same trait in production.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, HybridIdentityKeyPublic, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage,
    HYBRID_IDENTITY_PUBLIC_KEY_LEN,
};
use umbrella_pq::{HybridSignature, PqError, HYBRID_SIGNATURE_LEN};

/// `FixedClock` не экспортирован публично из umbrella-identity (по дизайну keystore::tests::*),
/// поэтому используем простую in-test реализацию `Clock` через `Arc<dyn Clock>`.
/// `FixedClock` is not publicly exported from umbrella-identity (by design — keystore::tests::*),
/// so we provide a simple in-test `Clock` implementation as `Arc<dyn Clock>`.
struct ZeroClock;
impl Clock for ZeroClock {
    fn now_unix_secs(&self) -> u64 {
        0
    }
}

fn fresh_store() -> InMemoryKeyStore {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    InMemoryKeyStore::open(seed, 0, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap()
}

#[test]
fn hybrid_identity_roundtrip_via_keystore() {
    let store = fresh_store();
    let pub_key = store.hybrid_identity_public();
    let msg = b"hybrid identity end-to-end";

    let sig = store.sign_with_hybrid_identity(msg).unwrap();
    pub_key
        .verify(msg, &sig)
        .expect("hybrid signature must verify");
}

#[test]
fn hybrid_signature_size_invariant() {
    let store = fresh_store();
    let sig = store.sign_with_hybrid_identity(b"x").unwrap();
    let bytes = sig.as_bytes();
    assert_eq!(bytes.len(), HYBRID_SIGNATURE_LEN);
    assert_eq!(bytes.len(), 3373);
}

#[test]
fn hybrid_identity_pubkey_size_invariant() {
    let store = fresh_store();
    let bytes = store.hybrid_identity_public().to_bytes();
    assert_eq!(bytes.len(), HYBRID_IDENTITY_PUBLIC_KEY_LEN);
    assert_eq!(bytes.len(), 1984);
}

#[test]
fn hybrid_identity_pubkey_wire_format_roundtrip() {
    let store = fresh_store();
    let original = store.hybrid_identity_public();
    let bytes = original.to_bytes();
    let decoded = HybridIdentityKeyPublic::from_bytes(&bytes, 0).unwrap();
    assert_eq!(original, decoded);

    // Re-encoded bytes должны быть идентичны.
    // Re-encoded bytes must be identical.
    assert_eq!(decoded.to_bytes(), bytes);
}

/// AND-mode invariant: tamper'нутая ML-DSA-65 часть подписи → verify fails с
/// `ed25519_ok=true, ml_dsa_ok=false`.
/// AND-mode invariant: a tampered ML-DSA-65 part of the signature → verify fails with
/// `ed25519_ok=true, ml_dsa_ok=false`.
#[test]
fn hybrid_signature_tampered_ml_dsa_part_detected() {
    let store = fresh_store();
    let sig = store.sign_with_hybrid_identity(b"msg").unwrap();
    let mut bytes = *sig.as_bytes();
    // Меняем bit в ML-DSA части (offset 64..3373).
    // Flip a bit in the ML-DSA part (offset 64..3373).
    bytes[100] ^= 0x01;
    let tampered = HybridSignature::from_bytes(&bytes).unwrap();
    let result = store.hybrid_identity_public().verify(b"msg", &tampered);
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::Pq(
            PqError::HybridSignatureVerificationFailed {
                ed25519_ok: true,
                ml_dsa_ok: false
            }
        ))
    ));
}

/// AND-mode invariant: tamper'нутая Ed25519 часть подписи → verify fails с
/// `ed25519_ok=false, ml_dsa_ok=true`.
/// AND-mode invariant: a tampered Ed25519 part of the signature → verify fails with
/// `ed25519_ok=false, ml_dsa_ok=true`.
#[test]
fn hybrid_signature_tampered_ed25519_part_detected() {
    let store = fresh_store();
    let sig = store.sign_with_hybrid_identity(b"msg").unwrap();
    let mut bytes = *sig.as_bytes();
    bytes[10] ^= 0x01; // в Ed25519 части (offset 0..64)
    let tampered = HybridSignature::from_bytes(&bytes).unwrap();
    let result = store.hybrid_identity_public().verify(b"msg", &tampered);
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::Pq(
            PqError::HybridSignatureVerificationFailed {
                ed25519_ok: false,
                ml_dsa_ok: true
            }
        ))
    ));
}

/// Подмена message → both компоненты fail.
/// Substituting the message → both components fail.
#[test]
fn hybrid_signature_wrong_message_both_components_fail() {
    let store = fresh_store();
    let sig = store.sign_with_hybrid_identity(b"original").unwrap();
    let result = store.hybrid_identity_public().verify(b"tampered", &sig);
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::Pq(
            PqError::HybridSignatureVerificationFailed {
                ed25519_ok: false,
                ml_dsa_ok: false
            }
        ))
    ));
}

#[test]
fn hybrid_device_lifecycle_roundtrip() {
    let store = fresh_store();
    store.add_device(0, None).unwrap();
    let pub_key = store.hybrid_device_public(0).unwrap();

    let sig = store.sign_with_hybrid_device(0, b"device msg").unwrap();
    pub_key.verify(b"device msg", &sig).unwrap();

    // Revocation propagates через single source of truth (classical map).
    // Revocation propagates through the single source of truth (classical map).
    store.revoke_device(0).unwrap();
    let result = store.sign_with_hybrid_device(0, b"x");
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::RevokedDevice { index: 0 })
    ));
}

/// Параллельные подписи от двух устройств одного аккаунта дают независимые,
/// успешно верифицируемые hybrid signatures с разными device pubkey'ами.
/// Parallel signatures from two devices of the same account yield independent,
/// successfully verified hybrid signatures with distinct device pubkeys.
#[test]
fn multi_device_hybrid_independent_signatures() {
    let store = fresh_store();
    store.add_device(0, None).unwrap();
    store.add_device(1, None).unwrap();

    let pub_0 = store.hybrid_device_public(0).unwrap();
    let pub_1 = store.hybrid_device_public(1).unwrap();
    assert_ne!(pub_0.ed25519_bytes(), pub_1.ed25519_bytes());
    assert_ne!(pub_0.ml_dsa_bytes(), pub_1.ml_dsa_bytes());

    let sig_0 = store.sign_with_hybrid_device(0, b"device 0").unwrap();
    let sig_1 = store.sign_with_hybrid_device(1, b"device 1").unwrap();

    pub_0.verify(b"device 0", &sig_0).unwrap();
    pub_1.verify(b"device 1", &sig_1).unwrap();

    // Cross-device signature не валидируется — каждый device key уникален.
    // Cross-device signature does not validate — each device key is unique.
    assert!(pub_1.verify(b"device 0", &sig_0).is_err());
    assert!(pub_0.verify(b"device 1", &sig_1).is_err());
}

/// Domain separation между identity и device слоями: подпись от identity-key с тем же
/// сообщением не валидируется через device-key public, и наоборот.
/// Domain separation between identity and device layers: a signature from the identity
/// key with the same message does not validate through the device pubkey, and vice versa.
#[test]
fn hybrid_identity_and_device_signatures_disjoint() {
    let store = fresh_store();
    store.add_device(0, None).unwrap();
    let id_sig = store.sign_with_hybrid_identity(b"shared").unwrap();
    let dev_sig = store.sign_with_hybrid_device(0, b"shared").unwrap();

    let id_pub = store.hybrid_identity_public();
    let dev_pub = store.hybrid_device_public(0).unwrap();

    // Identity signature не верифицируется через device pubkey.
    // Identity signature does not verify with device pubkey.
    assert!(dev_pub.verify(b"shared", &id_sig).is_err());
    // Device signature не верифицируется через identity pubkey.
    // Device signature does not verify with identity pubkey.
    assert!(id_pub.verify(b"shared", &dev_sig).is_err());

    // Каждая подпись валидна через свой pubkey.
    // Each signature validates against its own pubkey.
    id_pub.verify(b"shared", &id_sig).unwrap();
    dev_pub.verify(b"shared", &dev_sig).unwrap();
}
