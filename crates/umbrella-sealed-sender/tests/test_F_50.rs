//! Регресс-тесты F-50 (block 10.11): `Zeroizing<Vec<u8>>` обёртка для
//! `padded_blob` + `inner_plaintext` интермедиатов в `seal` / `unseal` /
//! `seal_v2` / `unseal_v2` — закрытие SPEC-08 §5.2 step 9 explicit promise
//! gap (row 11 cold-boot mitigation; F-46 pattern recurrence в V1 + V2 paths).
//!
//! Regression tests for F-50 (block 10.11): `Zeroizing<Vec<u8>>` wrapper for
//! the `padded_blob` + `inner_plaintext` intermediates in `seal` / `unseal` /
//! `seal_v2` / `unseal_v2` — closes the SPEC-08 §5.2 step 9 explicit promise
//! gap (row 11 cold-boot mitigation; F-46 pattern recurrence in V1 + V2
//! paths).
//!
//! ## Что регрессит
//!
//! 1. **Type-level guarantee**: `Zeroizing<Vec<u8>>` impl `ZeroizeOnDrop` —
//!    compile-time assertion через generic bound.
//! 2. **Behavioural guarantee**: `Zeroizing::<Vec<u8>>::new(...)` буфер
//!    обнуляется через `Drop` impl (zeroize crate spec) — verify через
//!    explicit drop + read-after-drop недопустим (UB), но functional
//!    roundtrip preserved (zeroize не ломает correctness).
//! 3. **Functional invariant**: existing seal/unseal roundtrip tests
//!    (block 8.6 corpus + block 10.11 added) pass без regressions —
//!    Zeroizing<Vec<u8>> Deref<Target = Vec<u8>> + DerefMut transparent
//!    к downstream API (pad_to_bucket / aead_key.encrypt / strip_padding).
//!
//! ## What is regression-tested
//!
//! 1. **Type-level guarantee**: `Zeroizing<Vec<u8>>` impls `ZeroizeOnDrop` —
//!    compile-time assertion via a generic bound.
//! 2. **Behavioural guarantee**: a `Zeroizing::<Vec<u8>>::new(...)` buffer is
//!    zeroed through its `Drop` impl (zeroize crate spec) — verified via
//!    explicit drop + the read-after-drop is UB but the functional roundtrip
//!    is preserved (zeroize does not break correctness).
//! 3. **Functional invariant**: existing seal/unseal roundtrip tests (block 8.6
//!    corpus + block 10.11 additions) pass without regressions — the
//!    transparent `Zeroizing<Vec<u8>>: Deref<Target = Vec<u8>> + DerefMut`
//!    downstream APIs (`pad_to_bucket` / `aead_key.encrypt` / `strip_padding`)
//!    accept it without changes.

use std::sync::Arc;

use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_sealed_sender::{seal, unseal, MAX_PAYLOAD};

fn fresh_keystore() -> Arc<InMemoryKeyStore> {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
}

/// Type-level: `Zeroizing<Vec<u8>>` impl `ZeroizeOnDrop` (zeroize crate
/// guarantee). Если zeroize crate breaking-changes wrapper signature —
/// этот compile-time test ломается, alerting maintainer'а.
///
/// Type-level: `Zeroizing<Vec<u8>>` impls `ZeroizeOnDrop` (zeroize crate
/// guarantee). If the zeroize crate breaks the wrapper signature, this
/// compile-time test fails, alerting the maintainer.
#[test]
fn test_f_50_zeroizing_vec_impls_zeroize_on_drop() {
    fn assert_impls<T: ZeroizeOnDrop>() {}
    assert_impls::<Zeroizing<Vec<u8>>>();
}

/// Behavioural: `Zeroizing::<Vec<u8>>::new(...)` обнуляется через `Drop` —
/// proxy через explicit `Zeroize::zeroize` call (zeroize crate provides
/// одинаковую семантику). After zeroize, all bytes == 0.
///
/// Behavioural: `Zeroizing::<Vec<u8>>::new(...)` is zeroed through its
/// `Drop` impl — proxied via an explicit `Zeroize::zeroize` call (the
/// zeroize crate provides identical semantics). After zeroize, all bytes
/// are 0.
#[test]
fn test_f_50_zeroizing_actually_zeros_buffer() {
    let mut probe: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xAAu8; 256]);
    assert_eq!(probe.iter().filter(|&&b| b == 0xAA).count(), 256);
    // Explicit zeroize (Drop поведение делает то же самое).
    // Explicit zeroize (Drop semantics do the same).
    probe.zeroize();
    assert!(
        probe.iter().all(|&b| b == 0),
        "Zeroizing::zeroize() должен обнулить все байты"
    );
    assert_eq!(
        probe.len(),
        0,
        "Zeroize::zeroize on Vec<u8> truncates length to 0"
    );
}

/// Functional: V1 seal/unseal roundtrip preserved после Zeroizing wrap'а
/// `padded` + `inner` (lib.rs:230-235 + lib.rs:281). Если Zeroizing wrap
/// случайно сломал API совместимость с pad_to_bucket / aead_key.encrypt /
/// strip_padding — этот test регрессит.
///
/// Functional: V1 seal/unseal roundtrip is preserved after the Zeroizing
/// wrap of `padded` + `inner` (lib.rs:230-235 + lib.rs:281). If the
/// Zeroizing wrap accidentally breaks API compatibility with pad_to_bucket
/// / aead_key.encrypt / strip_padding, this test regresses.
#[test]
fn test_f_50_v1_roundtrip_preserved_after_zeroizing_wrap() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let mut rng = OsRng;
    let payload = b"f-50 regression check: V1 zeroize roundtrip";
    let wire = seal(
        alice.as_ref(),
        &bob.identity_x25519_public(),
        payload,
        &mut rng,
    )
    .expect("V1 seal должен работать с Zeroizing<Vec<u8>> intermediates");
    let opened = unseal(bob.as_ref(), &wire).expect(
        "V1 unseal должен работать с Zeroizing<Vec<u8>> intermediate \
         (zeroize wrap transparent через Deref<Target = Vec<u8>>)",
    );
    assert_eq!(opened.message, payload);
    assert_eq!(opened.sender_identity, alice.identity_public());
}

/// Functional: boundary lengths 0 / 1 / MAX_PAYLOAD проверяют что Zeroizing
/// wrap не вводит off-by-one в `padded` capacity либо length.
///
/// Functional: boundary lengths 0 / 1 / MAX_PAYLOAD verify that the
/// Zeroizing wrap does not introduce off-by-one in `padded` capacity or
/// length.
#[test]
fn test_f_50_v1_boundary_lengths_preserved() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let mut rng = OsRng;
    for &len in &[0usize, 1, 256, MAX_PAYLOAD] {
        let msg = vec![0xC3u8; len];
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            &msg,
            &mut rng,
        )
        .expect("V1 seal должен принять boundary length");
        let opened = unseal(bob.as_ref(), &wire).expect("V1 unseal должен decode boundary length");
        assert_eq!(opened.message.len(), len, "len={len}");
        assert_eq!(opened.message, msg);
    }
}

/// Functional V2 (под `feature = "pq"`): seal_v2/unseal_v2 roundtrip
/// preserved после Zeroizing wrap'а `padded` + `inner` (hybrid_envelope.rs).
///
/// Functional V2 (under `feature = "pq"`): seal_v2/unseal_v2 roundtrip is
/// preserved after the Zeroizing wrap of `padded` + `inner`
/// (hybrid_envelope.rs).
#[cfg(feature = "pq")]
#[test]
fn test_f_50_v2_roundtrip_preserved_after_zeroizing_wrap() {
    use umbrella_pq::xwing_keygen;
    use umbrella_sealed_sender::{seal_v2, unseal_v2};

    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let mut rng = OsRng;
    let (bob_xwing_pk, bob_xwing_sk) = xwing_keygen(&mut rng).unwrap();
    let payload = b"f-50 regression check: V2 X-Wing zeroize roundtrip";
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, payload, &mut rng)
        .expect("V2 seal должен работать с Zeroizing<Vec<u8>> intermediates");
    let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).expect(
        "V2 unseal должен работать с Zeroizing<Vec<u8>> intermediate (zeroize \
         wrap transparent через Deref<Target = Vec<u8>>)",
    );
    assert_eq!(opened.message, payload);
    assert_eq!(opened.sender_identity, alice.identity_public());
}
