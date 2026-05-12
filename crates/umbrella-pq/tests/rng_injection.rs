//! Тесты RNG injection: API umbrella-pq принимает любую `RngCore + CryptoRng`
//! реализацию. Используем OsRng (production) и ChaCha20Rng (deterministic для KAT).
//!
//! Tests for RNG injection: umbrella-pq API accepts any `RngCore + CryptoRng`
//! implementation. We use OsRng (production) and ChaCha20Rng (deterministic for KAT).

#![cfg(all(feature = "ml-kem", feature = "ml-dsa", feature = "slh-dsa"))]

use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secrecy::ExposeSecret;

/// Same ChaCha20Rng seed → same ML-KEM-768 keypair (deterministic).
/// Different seeds → different keypairs.
#[test]
fn ml_kem_768_chacha20rng_deterministic() {
    let seed = [42u8; 32];
    let mut rng_a = ChaCha20Rng::from_seed(seed);
    let mut rng_b = ChaCha20Rng::from_seed(seed);

    let (pk_a, _) = umbrella_pq::ml_kem_768_keygen(&mut rng_a);
    let (pk_b, _) = umbrella_pq::ml_kem_768_keygen(&mut rng_b);

    assert_eq!(pk_a.as_bytes(), pk_b.as_bytes(), "same seed → same pk");

    let seed_diff = [43u8; 32];
    let mut rng_c = ChaCha20Rng::from_seed(seed_diff);
    let (pk_c, _) = umbrella_pq::ml_kem_768_keygen(&mut rng_c);
    assert_ne!(
        pk_a.as_bytes(),
        pk_c.as_bytes(),
        "different seeds → different pks"
    );
}

/// OsRng работает для всех PQ примитивов (smoke-тест production path).
/// OsRng works for all PQ primitives (production smoke-test).
#[test]
fn os_rng_works_for_all_primitives() {
    let mut rng = OsRng;

    // ML-KEM-768
    let (mk_pk, mk_sk) = umbrella_pq::ml_kem_768_keygen(&mut rng);
    let (mk_ct, mk_ss_a) = umbrella_pq::ml_kem_768_encaps(&mut rng, &mk_pk);
    let mk_ss_b = umbrella_pq::ml_kem_768_decaps(&mk_sk, &mk_ct);
    assert_eq!(mk_ss_a.expose_secret(), mk_ss_b.expose_secret());

    // X-Wing
    let (xw_pk, xw_seed) = umbrella_pq::xwing_keygen(&mut rng).unwrap();
    let (xw_ct, xw_ss_a) = umbrella_pq::xwing_encaps(&mut rng, &xw_pk).unwrap();
    let xw_ss_b = umbrella_pq::xwing_decaps(&xw_seed, &xw_ct).unwrap();
    assert_eq!(xw_ss_a.expose_secret(), xw_ss_b.expose_secret());

    // ML-DSA-65
    let (md_pk, md_sk) = umbrella_pq::ml_dsa_65_keygen(&mut rng);
    let md_sig = umbrella_pq::ml_dsa_65_sign(&mut rng, &md_sk, b"msg", b"ctx").unwrap();
    umbrella_pq::ml_dsa_65_verify(&md_pk, b"msg", b"ctx", &md_sig).unwrap();

    // Hybrid signature
    let (hy_pk, hy_sk) = umbrella_pq::hybrid_keygen(&mut rng);
    let hy_sig = umbrella_pq::hybrid_sign(&mut rng, &hy_sk, b"hybrid").unwrap();
    umbrella_pq::hybrid_verify(&hy_pk, b"hybrid", &hy_sig).unwrap();

    // SLH-DSA-128f
    let (sl_pk, sl_sk) = umbrella_pq::slh_dsa_128f_keygen(&mut rng).unwrap();
    let sl_sig = umbrella_pq::slh_dsa_128f_sign(&mut rng, &sl_sk, b"backup", b"slh").unwrap();
    umbrella_pq::slh_dsa_128f_verify(&sl_pk, b"backup", b"slh", &sl_sig).unwrap();
}

/// Same ChaCha20Rng seed → same hybrid keypair (deterministic keygen).
#[test]
fn hybrid_keygen_chacha20rng_deterministic() {
    let seed = [99u8; 32];
    let mut rng_a = ChaCha20Rng::from_seed(seed);
    let mut rng_b = ChaCha20Rng::from_seed(seed);

    let (pk_a, _) = umbrella_pq::hybrid_keygen(&mut rng_a);
    let (pk_b, _) = umbrella_pq::hybrid_keygen(&mut rng_b);

    assert_eq!(pk_a.ed25519.as_bytes(), pk_b.ed25519.as_bytes());
    assert_eq!(pk_a.ml_dsa.as_bytes(), pk_b.ml_dsa.as_bytes());
}
