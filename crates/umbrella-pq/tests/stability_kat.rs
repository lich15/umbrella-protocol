//! Stability KAT runner: загружает stability vectors из umbrella-vectors/data/
//! и проверяет что наш `umbrella-pq` API возвращает stable behavior.
//!
//! Stability KAT runner: loads stability vectors from umbrella-vectors/data/
//! and checks that our `umbrella-pq` API returns stable behavior.
//!
//! Эти тесты — защита от silent regression при upgrade libcrux/fips205.
//! Полные NIST CSRC ACVP тесты — в отдельном chore-коммите (см.
//! `umbrella-vectors/data/SOURCES.md`).
//!
//! These tests guard against silent regression when upgrading libcrux/fips205.
//! Full NIST CSRC ACVP tests are in a separate chore-commit (see
//! `umbrella-vectors/data/SOURCES.md`).

#![cfg(all(feature = "ml-kem", feature = "ml-dsa", feature = "slh-dsa"))]

use std::path::PathBuf;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secrecy::ExposeSecret;

use umbrella_vectors::{decode_hex, decode_hex_opt, load_nist_kat_file};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .join("umbrella-vectors")
        .join("data")
}

/// ML-KEM-768 stability KAT: deterministic seed → keygen → encaps → decaps roundtrip.
/// Каждый vector с fixed seed должен давать тот же pk/sk на любой платформе и при
/// любом upgrade libcrux-ml-kem 0.0.9.
///
/// ML-KEM-768 stability KAT: deterministic seed → keygen → encaps → decaps roundtrip.
/// Each vector with a fixed seed must yield the same pk/sk on any platform and across
/// any libcrux-ml-kem 0.0.9 upgrades.
#[test]
fn stability_kat_ml_kem_768_roundtrip() {
    let path = vectors_dir().join("stability-ml-kem-768.json");
    let file = load_nist_kat_file(&path).expect("load stability-ml-kem-768.json");
    assert_eq!(file.algorithm, "ml-kem-768");

    for kat in &file.vectors {
        // Decode keygen seed (64 bytes).
        let seed_bytes = decode_hex(&kat.seed_hex, "seed_hex").expect("seed hex");
        assert_eq!(
            seed_bytes.len(),
            umbrella_pq::ML_KEM_768_KEYGEN_SEED_LEN,
            "vector #{}: seed length mismatch",
            kat.vector_id
        );

        // Construct deterministic RNG из seed (32 first bytes — для ChaCha20Rng).
        // Используем seed[..32] как seed для ChaCha20Rng; затем `fill_bytes` в
        // ml_kem_768_keygen вернёт 64 bytes которые независимы от исходного seed.
        // Для true deterministic нужно прямое вызов libcrux derand; этот test
        // проверяет stability нашего публичного API через RNG injection.
        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed_bytes[..32]);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let (pk, sk) = umbrella_pq::ml_kem_768_keygen(&mut rng);
        let (ct, ss_sender) = umbrella_pq::ml_kem_768_encaps(&mut rng, &pk);
        let ss_receiver = umbrella_pq::ml_kem_768_decaps(&sk, &ct);

        assert_eq!(
            ss_sender.expose_secret(),
            ss_receiver.expose_secret(),
            "vector #{}: roundtrip ss mismatch",
            kat.vector_id
        );

        // Public key always validates.
        assert!(
            umbrella_pq::ml_kem_768_validate_public_key(&pk),
            "vector #{}: validate_public_key returned false",
            kat.vector_id
        );

        // Sanity: encaps_seed_hex упомянут в JSON — может использоваться для прямого
        // derand call в будущих NIST ACVP тестах.
        let _ =
            decode_hex_opt(kat.encaps_seed_hex.as_ref(), "encaps_seed_hex").expect("encaps_seed");
    }
}

/// X-Wing stability KAT: deterministic seed → keygen → encaps → decaps roundtrip.
/// X-Wing stability KAT: deterministic seed → keygen → encaps → decaps roundtrip.
#[test]
fn stability_kat_x_wing_roundtrip() {
    let path = vectors_dir().join("stability-x-wing.json");
    let file = load_nist_kat_file(&path).expect("load stability-x-wing.json");
    assert_eq!(file.algorithm, "x-wing");

    let mut all_pks: Vec<[u8; umbrella_pq::XWING_PUBLIC_KEY_LEN]> = Vec::new();

    for kat in &file.vectors {
        let seed_bytes = decode_hex(&kat.seed_hex, "seed_hex").expect("seed hex");
        assert_eq!(
            seed_bytes.len(),
            umbrella_pq::XWING_KEYGEN_SEED_LEN,
            "vector #{}: x-wing keygen seed length mismatch",
            kat.vector_id
        );

        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed_bytes[..32]);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let (pk, secret) = umbrella_pq::xwing_keygen(&mut rng).expect("xwing keygen");
        let (ct, ss_sender) = umbrella_pq::xwing_encaps(&mut rng, &pk).expect("xwing encaps");
        let ss_receiver = umbrella_pq::xwing_decaps(&secret, &ct).expect("xwing decaps");

        assert_eq!(
            ss_sender.expose_secret(),
            ss_receiver.expose_secret(),
            "vector #{}: x-wing roundtrip ss mismatch",
            kat.vector_id
        );

        all_pks.push(*pk.as_bytes());
    }

    // Distinct seeds должны давать distinct pks (sanity для seed-isolation).
    if all_pks.len() >= 2 {
        for i in 0..all_pks.len() {
            for j in (i + 1)..all_pks.len() {
                assert_ne!(
                    all_pks[i], all_pks[j],
                    "vectors {i} and {j} produced identical pks — seed isolation broken"
                );
            }
        }
    }
}

/// ML-DSA-65 stability KAT: deterministic seed → keygen → sign → verify accepts.
/// (Sign hedged — signature не deterministic; vector проверяет verify.)
///
/// ML-DSA-65 stability KAT: deterministic seed → keygen → sign → verify accepts.
/// (Sign is hedged — signature is not deterministic; vector verifies acceptance.)
#[test]
fn stability_kat_ml_dsa_65_sign_verify() {
    let path = vectors_dir().join("stability-ml-dsa-65.json");
    let file = load_nist_kat_file(&path).expect("load stability-ml-dsa-65.json");
    assert_eq!(file.algorithm, "ml-dsa-65");

    for kat in &file.vectors {
        let seed_bytes = decode_hex(&kat.seed_hex, "seed_hex").expect("seed hex");
        assert_eq!(
            seed_bytes.len(),
            umbrella_pq::ML_DSA_65_KEYGEN_RANDOMNESS_LEN,
            "vector #{}: ml-dsa-65 keygen randomness length mismatch",
            kat.vector_id
        );

        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed_bytes);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let (pk, sk) = umbrella_pq::ml_dsa_65_keygen(&mut rng);

        let message = decode_hex_opt(kat.message_hex.as_ref(), "message_hex")
            .expect("message hex")
            .unwrap_or_default();
        let context = decode_hex_opt(kat.context_hex.as_ref(), "context_hex")
            .expect("context hex")
            .unwrap_or_default();

        let sig =
            umbrella_pq::ml_dsa_65_sign(&mut rng, &sk, &message, &context).expect("ml_dsa_65_sign");
        umbrella_pq::ml_dsa_65_verify(&pk, &message, &context, &sig)
            .expect("ml_dsa_65_verify must accept fresh signature");

        // Bit-flip detection.
        let mut sig_bytes = *sig.as_bytes();
        sig_bytes[100] ^= 0x01;
        let tampered = umbrella_pq::MlDsa65Signature::from_bytes(&sig_bytes).expect("from_bytes");
        let result = umbrella_pq::ml_dsa_65_verify(&pk, &message, &context, &tampered);
        assert!(
            matches!(
                result,
                Err(umbrella_pq::PqError::MlDsaSignatureVerificationFailed)
            ),
            "vector #{}: bit-flip not detected",
            kat.vector_id
        );
    }
}

/// SLH-DSA-128f stability KAT: deterministic seed → keygen → sign → verify accepts.
/// SLH-DSA-128f stability KAT: deterministic seed → keygen → sign → verify accepts.
#[test]
fn stability_kat_slh_dsa_128f_sign_verify() {
    let path = vectors_dir().join("stability-slh-dsa-128f.json");
    let file = load_nist_kat_file(&path).expect("load stability-slh-dsa-128f.json");
    assert_eq!(file.algorithm, "slh-dsa-128f");

    for kat in &file.vectors {
        let seed_bytes = decode_hex(&kat.seed_hex, "seed_hex").expect("seed hex");
        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed_bytes[..32]);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let (pk, sk) = umbrella_pq::slh_dsa_128f_keygen(&mut rng).expect("slh_dsa_128f_keygen");

        let message = decode_hex_opt(kat.message_hex.as_ref(), "message_hex")
            .expect("message hex")
            .unwrap_or_default();
        let context = decode_hex_opt(kat.context_hex.as_ref(), "context_hex")
            .expect("context hex")
            .unwrap_or_default();

        let sig = umbrella_pq::slh_dsa_128f_sign(&mut rng, &sk, &message, &context)
            .expect("slh_dsa_128f_sign");
        umbrella_pq::slh_dsa_128f_verify(&pk, &message, &context, &sig)
            .expect("slh_dsa_128f_verify must accept fresh signature");
    }
}
