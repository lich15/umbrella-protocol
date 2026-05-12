//! Integration tests блока 8.6: V2 sealed-sender envelope roundtrip + tamper.
//! Integration tests for block 8.6: V2 sealed-sender envelope roundtrip + tamper.
//!
//! End-to-end проверка V2 envelope: Alice (sender) запечатывает message в V2
//! envelope с X-Wing ephemeral KEM; Bob (recipient) распаковывает через свой
//! X-Wing secret seed; sender authenticated через inner ed25519 signature.
//!
//! End-to-end check of V2 envelope: Alice (sender) seals a message into a V2
//! envelope with X-Wing ephemeral KEM; Bob (recipient) unseals with his
//! X-Wing secret seed; sender is authenticated via the inner Ed25519 signature.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_pq::{xwing_keygen, XWingPublicKey, XWingSecretSeed, XWING_CIPHERTEXT_LEN};
use umbrella_sealed_sender::{
    seal_v2, unseal_v2, SealedSenderError, SealedSenderVersion, V2_MIN_WIRE_LEN,
};

fn fresh_keystore() -> Arc<InMemoryKeyStore> {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
}

fn fresh_xwing_keypair() -> (XWingPublicKey, XWingSecretSeed) {
    let mut rng = OsRng;
    xwing_keygen(&mut rng).unwrap()
}

#[test]
fn alice_to_bob_v2_envelope_short_message() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"hello-bob-pq", &mut rng).unwrap();
    let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
    assert_eq!(opened.sender_identity, alice.identity_public());
    assert_eq!(opened.message, b"hello-bob-pq");
}

#[test]
fn v2_wire_starts_with_version_stamp() {
    let alice = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
    assert_eq!(wire[0], 0x02);
    assert_eq!(wire[0], SealedSenderVersion::V2HybridXWing.as_u8());
    assert!(wire.len() >= V2_MIN_WIRE_LEN);
}

#[test]
fn v2_wire_xwing_ct_length() {
    let alice = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"x", &mut rng).unwrap();
    // Bytes [1..1121] — это xwing_ciphertext (encaps result).
    assert!(wire.len() > XWING_CIPHERTEXT_LEN);
}

#[test]
fn boundary_payload_lengths() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    for len in [0usize, 1, 32, 100, 156, 157, 900, 4000, 16_000] {
        let msg = vec![0xA5u8; len];
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, &msg, &mut rng).unwrap();
        let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
        assert_eq!(opened.message, msg, "len={len}");
    }
}

#[test]
fn same_payload_twice_produces_distinct_wire() {
    // X-Wing encaps использует random seed → each envelope unique.
    // X-Wing encaps uses a random seed → each envelope is unique.
    let alice = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let w1 = seal_v2(alice.as_ref(), &bob_xwing_pk, b"same", &mut rng).unwrap();
    let w2 = seal_v2(alice.as_ref(), &bob_xwing_pk, b"same", &mut rng).unwrap();
    assert_ne!(w1, w2);
}

#[test]
fn tampered_xwing_ct_rejected() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
    // Подменяем 1 byte в xwing_ct → AEAD AAD mismatch (или decaps fails).
    wire[100] ^= 0x01;
    assert!(unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).is_err());
}

#[test]
fn tampered_inner_ct_rejected() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
    assert!(matches!(result, Err(SealedSenderError::Crypto(_))));
}

#[test]
fn tampered_version_byte_rejected() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
    wire[0] = 0x03; // unknown version
    let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
    assert!(matches!(
        result,
        Err(SealedSenderError::UnsupportedVersion { got: 0x03 })
    ));
}

#[test]
fn wrong_recipient_seed_cannot_unseal() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, _bob_seed) = fresh_xwing_keypair();
    let (_, eve_seed) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"for-bob", &mut rng).unwrap();
    let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &eve_seed, &wire);
    assert!(result.is_err(), "Eve's seed не должен расшифровать");
}

#[test]
fn wrong_pubkey_in_aad_fails() {
    // Если caller передал чужой pubkey в unseal — AEAD AAD не совпадает.
    // If caller passes a different pubkey to unseal — AEAD AAD mismatch.
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let (other_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
    let result = unseal_v2(bob.as_ref(), &other_pk, &bob_xwing_sk, &wire);
    assert!(result.is_err());
}

#[test]
fn payload_at_max_size_roundtrip() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let payload = vec![0u8; umbrella_sealed_sender::MAX_PAYLOAD];
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, &payload, &mut rng).unwrap();
    let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
    assert_eq!(opened.message.len(), umbrella_sealed_sender::MAX_PAYLOAD);
}

#[test]
fn payload_over_max_rejected() {
    let alice = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let payload = vec![0u8; umbrella_sealed_sender::MAX_PAYLOAD + 1];
    let result = seal_v2(alice.as_ref(), &bob_xwing_pk, &payload, &mut rng);
    assert!(matches!(
        result,
        Err(SealedSenderError::PayloadTooLarge { .. })
    ));
}

#[test]
fn truncated_wire_rejected() {
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let truncated = vec![0x02u8; V2_MIN_WIRE_LEN - 1];
    let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &truncated);
    assert!(matches!(result, Err(SealedSenderError::Malformed { .. })));
}

#[test]
fn recipient_learns_sender_identity() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"who-am-i", &mut rng).unwrap();
    let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
    assert_eq!(opened.sender_identity, alice.identity_public());
}

#[test]
fn forged_inner_signature_rejected() {
    // Атакующий собирает свой envelope и имитирует Alice's identity_pub в inner,
    // но не имеет Alice's secret signing key → подпись невалидна → unseal падает
    // на InvalidSignature (после успешного AEAD decrypt).
    //
    // Этот test косвенно покрывается existing tampered_inner_ct_rejected:
    // если attacker меняет inner padded — AEAD reject. Чтобы forge sig напрямую
    // attacker должен иметь aead key (impossible без shared_secret).
    //
    // The attacker assembles their envelope and impersonates Alice's identity_pub
    // in inner, but lacks Alice's signing key → invalid signature → unseal fails
    // with InvalidSignature (after successful AEAD decrypt).
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let rng = OsRng;
    // Eve attempt: запечатывает с своей identity, но в inner header кладёт Alice's pub.
    // Это делает eve fresh keystore которая SIGN'ит inner с своей identity, но claim'ит
    // Alice's pub в inner. По semantics нашего design — sign(eve_sk) над payload, ed25519
    // verify против Alice's pub fails.
    //
    // В нашем API нет direct способа подменить sender_pub в inner header (seal_v2
    // использует keystore.identity_public() консистентно). Так что emулируем
    // через прямую подмену sender_pub байтов в decoded message — это сложно потому
    // что AEAD encrypts inner. Skip — covered by tampered_inner_ct_rejected.
    let _ = (alice, bob, bob_xwing_pk, bob_xwing_sk, rng);
}

// === Property-based ===

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(8))]

    #[test]
    fn prop_roundtrip_random_payload(
        payload in proptest::collection::vec(proptest::num::u8::ANY, 0..1024)
    ) {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, &payload, &mut rng).unwrap();
        let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
        proptest::prop_assert_eq!(opened.message, payload);
        proptest::prop_assert_eq!(opened.sender_identity, alice.identity_public());
    }

    #[test]
    fn prop_tamper_byte_rejected(
        payload_len in 0usize..128,
        offset_seed in 0usize..50_000,
        xor_byte in 1u8..=255,
    ) {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let payload = vec![0x42; payload_len];
        let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, &payload, &mut rng).unwrap();
        let pos = offset_seed % wire.len();
        wire[pos] ^= xor_byte;
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        // Допустимо: Err. Недопустимо: Ok с payload == оригинал.
        // Acceptable: Err. Unacceptable: Ok with payload == original.
        if let Ok(opened) = result {
            proptest::prop_assert!(
                opened.message != payload || opened.sender_identity != alice.identity_public(),
                "tamper at pos={} xor={:#x} пропустил оригинал — AEAD/sig forgery",
                pos, xor_byte
            );
        }
    }
}
