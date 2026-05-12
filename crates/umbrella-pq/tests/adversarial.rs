//! Adversarial tests: malformed inputs, edge cases, downgrade resistance.
//! Adversarial tests: malformed inputs, edge cases, downgrade resistance.

#![cfg(all(feature = "ml-kem", feature = "ml-dsa", feature = "slh-dsa"))]

use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use std::panic::{catch_unwind, AssertUnwindSafe};

use umbrella_pq::{
    HybridSignature, MlDsa65PublicKey, MlDsa65Signature, MlKem768PublicKey, PqError,
    SlhDsa128fPublicKey, SlhDsa128fSignature, XWingPublicKey,
};

/// All public-key types reject incorrectly-sized bytes.
#[test]
fn invalid_size_rejected_for_all_public_keys() {
    let bad = vec![0u8; 1];
    assert!(matches!(
        MlKem768PublicKey::from_bytes(&bad),
        Err(PqError::MlKemInvalidPublicKey { .. })
    ));
    assert!(matches!(
        XWingPublicKey::from_bytes(&bad),
        Err(PqError::XWingInvalidPublicKey { .. })
    ));
    assert!(matches!(
        MlDsa65PublicKey::from_bytes(&bad),
        Err(PqError::MlDsaInvalidPublicKey { .. })
    ));
    assert!(matches!(
        SlhDsa128fPublicKey::from_bytes(&bad),
        Err(PqError::SlhDsaInvalidPublicKey { .. })
    ));
}

/// All signature types reject incorrectly-sized bytes.
#[test]
fn invalid_size_rejected_for_all_signatures() {
    let bad = vec![0u8; 1];
    assert!(matches!(
        MlDsa65Signature::from_bytes(&bad),
        Err(PqError::MlDsaInvalidSignature { .. })
    ));
    assert!(matches!(
        SlhDsa128fSignature::from_bytes(&bad),
        Err(PqError::SlhDsaInvalidSignature { .. })
    ));
    assert!(matches!(
        HybridSignature::from_bytes(&bad),
        Err(PqError::HybridInvalidSignature { .. })
    ));
}

/// Empty message подписывается и проверяется во всех signature schemes.
/// Empty message signs and verifies across all signature schemes.
#[test]
fn empty_message_supported() {
    let mut rng = OsRng;

    // ML-DSA-65
    let (md_pk, md_sk) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let md_sig = umbrella_pq::ml_dsa_65_sign(&mut rng, &md_sk, b"", b"").unwrap();
    umbrella_pq::ml_dsa_65_verify(&md_pk, b"", b"", &md_sig).unwrap();

    // Hybrid
    let (hy_pk, hy_sk) = umbrella_pq::hybrid_keygen(&mut rng);
    let hy_sig = umbrella_pq::hybrid_sign(&mut rng, &hy_sk, b"").unwrap();
    umbrella_pq::hybrid_verify(&hy_pk, b"", &hy_sig).unwrap();

    // SLH-DSA-128f
    let (sl_pk, sl_sk) = umbrella_pq::slh_dsa_128f_keygen(&mut rng).unwrap();
    let sl_sig = umbrella_pq::slh_dsa_128f_sign(&mut rng, &sl_sk, b"", b"").unwrap();
    umbrella_pq::slh_dsa_128f_verify(&sl_pk, b"", b"", &sl_sig).unwrap();
}

/// Большое сообщение (64 KiB) поддерживается для signatures и hybrid.
/// Large message (64 KiB) is supported for signatures and hybrid.
#[test]
fn large_message_supported() {
    let mut rng = OsRng;
    let big = vec![0xAAu8; 65_536];

    let (md_pk, md_sk) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let md_sig = umbrella_pq::ml_dsa_65_sign(&mut rng, &md_sk, &big, b"").unwrap();
    umbrella_pq::ml_dsa_65_verify(&md_pk, &big, b"", &md_sig).unwrap();

    let (hy_pk, hy_sk) = umbrella_pq::hybrid_keygen(&mut rng);
    let hy_sig = umbrella_pq::hybrid_sign(&mut rng, &hy_sk, &big).unwrap();
    umbrella_pq::hybrid_verify(&hy_pk, &big, &hy_sig).unwrap();
}

/// Wrong public key (от другого keypair) отвергается для всех signature schemes.
/// Wrong public key (from another keypair) is rejected for all signature schemes.
#[test]
fn wrong_public_key_rejected() {
    let mut rng = OsRng;

    // ML-DSA-65
    let (md_pk_a, md_sk_a) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let (md_pk_b, _) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let md_sig = umbrella_pq::ml_dsa_65_sign(&mut rng, &md_sk_a, b"msg", b"ctx").unwrap();
    let _ = md_pk_a; // silence unused
    let result = umbrella_pq::ml_dsa_65_verify(&md_pk_b, b"msg", b"ctx", &md_sig);
    assert!(matches!(
        result,
        Err(PqError::MlDsaSignatureVerificationFailed)
    ));
}

/// Regression for the 2026 libcrux ML-DSA hint-counter bug class:
/// malformed public signatures must be rejected as verification errors,
/// never as process panics.
#[test]
fn ml_dsa_65_overflowed_hint_counter_rejected_without_panic() {
    const COMMITMENT_HASH_LEN: usize = 48;
    const GAMMA1_RING_ELEMENT_LEN: usize = 640;
    const COLUMNS_IN_A: usize = 5;
    const MAX_ONES_IN_HINT: usize = 55;
    const ROWS_IN_A: usize = 6;

    let mut rng = OsRng;
    let (pk, sk) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let message = b"ml-dsa malformed-hint regression";
    let context = b"umbrella-production-regression";
    let sig = umbrella_pq::ml_dsa_65_sign(&mut rng, &sk, message, context).unwrap();

    let mut bytes = *sig.as_bytes();
    let hint_offset = COMMITMENT_HASH_LEN + COLUMNS_IN_A * GAMMA1_RING_ELEMENT_LEN;
    let last_row_counter = hint_offset + MAX_ONES_IN_HINT + ROWS_IN_A - 1;

    // FIPS 204 HintBitUnpack requires every cumulative counter to be <= omega.
    // A vulnerable verifier used the previous counter for this check and could
    // walk past the signature hint section.
    bytes[last_row_counter] = u8::MAX;

    let malformed = MlDsa65Signature::from_bytes(&bytes).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        umbrella_pq::ml_dsa_65_verify(&pk, message, context, &malformed)
    }));

    assert!(
        result.is_ok(),
        "malformed public ML-DSA signatures must not panic the verifier"
    );
    assert!(matches!(
        result.unwrap(),
        Err(PqError::MlDsaSignatureVerificationFailed)
    ));
}

/// X-Wing decaps с corrupted ciphertext возвращает Err (X-Wing combiner отвергает,
/// в отличие от чистого ML-KEM с implicit rejection).
/// X-Wing decaps with corrupted ciphertext returns Err (X-Wing combiner rejects,
/// unlike pure ML-KEM with implicit rejection).
#[test]
fn xwing_corrupted_ciphertext_explicit_rejection() {
    let mut rng = OsRng;
    let (pk, secret) = umbrella_pq::xwing_keygen(&mut rng).unwrap();
    let (mut ct, ss_sender) = umbrella_pq::xwing_encaps(&mut rng, &pk).unwrap();

    // Flip bytes в X25519 части (последние 32 bytes); ML-KEM часть intact.
    ct[umbrella_pq::ML_KEM_768_CIPHERTEXT_LEN] ^= 0xFF;
    ct[umbrella_pq::ML_KEM_768_CIPHERTEXT_LEN + 1] ^= 0xFF;

    // X-Wing combiner защищает от частичной corruption: либо decaps fail, либо
    // другой ss; не тот же.
    match umbrella_pq::xwing_decaps(&secret, &ct) {
        Ok(ss_receiver) => {
            assert_ne!(
                ss_sender.expose_secret(),
                ss_receiver.expose_secret(),
                "corrupted ct must give different ss"
            );
        }
        Err(PqError::XWingDecapsulationFailed) => {
            // Acceptable — explicit rejection.
        }
        Err(other) => {
            panic!("unexpected error: {other:?}");
        }
    }
}
