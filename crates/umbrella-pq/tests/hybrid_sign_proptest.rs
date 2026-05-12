//! Property-based tests для hybrid signature (Ed25519 + ML-DSA-65 AND-mode).
//! Property-based tests for hybrid signature (Ed25519 + ML-DSA-65 AND-mode).

#![cfg(feature = "ml-dsa")]

use proptest::prelude::*;
use rand::rngs::OsRng;

use umbrella_pq::{
    hybrid_keygen, hybrid_sign, hybrid_verify, HybridSignature, PqError, HYBRID_SIGNATURE_LEN,
};

proptest! {
    /// Property: hybrid_sign(any message) → hybrid_verify(same message) всегда OK.
    /// Property: hybrid_sign(any message) → hybrid_verify(same message) is always OK.
    #[test]
    fn prop_sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, &msg).unwrap();
        prop_assert!(hybrid_verify(&pk, &msg, &sig).is_ok());
    }

    /// Property: hybrid_sign(msg_a) → hybrid_verify(msg_b) — Err когда msg_a != msg_b.
    /// Property: hybrid_sign(msg_a) → hybrid_verify(msg_b) is Err when msg_a != msg_b.
    #[test]
    fn prop_wrong_message_rejected(
        msg_a in prop::collection::vec(any::<u8>(), 1..256),
        msg_b in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(msg_a != msg_b);
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, &msg_a).unwrap();
        let result = hybrid_verify(&pk, &msg_b, &sig);
        // Bind matches! to bool — prop_assert! macro парсит args как format string,
        // фигурные скобки в pattern matching ломают парсер.
        let is_hybrid_err = matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed { .. })
        );
        prop_assert!(is_hybrid_err);
    }

    /// Property: bit-flip в любой позиции ed25519-части (offset 0..64) отвергается
    /// (ed25519_ok=false).
    /// Property: bit-flip in any ed25519-part position (offset 0..64) is rejected
    /// (ed25519_ok=false).
    #[test]
    fn prop_ed25519_bit_flip_detected(offset in 0usize..64, bit in 0u8..8) {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let mut sig = hybrid_sign(&mut rng, &sk, b"property-test").unwrap();
        let mut bytes = *sig.as_bytes();
        bytes[offset] ^= 1u8 << bit;
        sig = HybridSignature::from_bytes(&bytes).unwrap();
        let result = hybrid_verify(&pk, b"property-test", &sig);
        let is_ed25519_failure = matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed { ed25519_ok: false, .. })
        );
        prop_assert!(is_ed25519_failure);
    }

    /// Property: bit-flip в любой позиции ml-dsa-части (offset 64..3373) отвергается
    /// (ml_dsa_ok=false; ed25519_ok=true т.к. ed25519 part untouched).
    /// Property: bit-flip in any ml-dsa-part position (offset 64..3373) is rejected
    /// (ml_dsa_ok=false; ed25519_ok=true since ed25519 part is untouched).
    #[test]
    fn prop_ml_dsa_bit_flip_detected(
        offset in 64usize..HYBRID_SIGNATURE_LEN,
        bit in 0u8..8,
    ) {
        let mut rng = OsRng;
        let (pk, sk) = hybrid_keygen(&mut rng);
        let mut sig = hybrid_sign(&mut rng, &sk, b"property-test").unwrap();
        let mut bytes = *sig.as_bytes();
        bytes[offset] ^= 1u8 << bit;
        sig = HybridSignature::from_bytes(&bytes).unwrap();
        let result = hybrid_verify(&pk, b"property-test", &sig);
        let is_ml_dsa_only_failure = matches!(
            result,
            Err(PqError::HybridSignatureVerificationFailed { ed25519_ok: true, ml_dsa_ok: false })
        );
        prop_assert!(is_ml_dsa_only_failure);
    }

    /// Property: byte-roundtrip serialize → deserialize даёт identical signature.
    /// Property: byte-roundtrip serialize → deserialize yields identical signature.
    #[test]
    fn prop_signature_byte_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut rng = OsRng;
        let (_, sk) = hybrid_keygen(&mut rng);
        let sig = hybrid_sign(&mut rng, &sk, &msg).unwrap();
        let bytes = *sig.as_bytes();
        let decoded = HybridSignature::from_bytes(&bytes).unwrap();
        prop_assert_eq!(*decoded.as_bytes(), bytes);
    }
}
