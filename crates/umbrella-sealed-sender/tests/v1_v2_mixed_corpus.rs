//! Integration tests блока 8.6: V1 ↔ V2 dispatcher pattern + mixed wire corpus.
//! Integration tests for block 8.6: V1 ↔ V2 dispatcher pattern + mixed wire corpus.
//!
//! Эти tests fixture'ят invariant'ы:
//! - V1 envelope (leading byte 0x01) **не parses** через `unseal_v2` —
//!   возвращает `UnsupportedVersion { got: 0x01 }`.
//! - V2 envelope (leading byte 0x02) **не parses** через V1 `unseal` —
//!   возвращает `UnsupportedVersion { got: 0x02 }`.
//! - Mixed wire corpus (alternating V1 + V2 bytes) обрабатывается каждой
//!   функцией только для своей версии; никакого silent fallback.
//! - Caller-side dispatcher pattern (peek first byte → choose path) работает
//!   для всех 254 неизвестных значений первого байта.
//! - Empty wire bytes отвергаются обеими функциями (Malformed для V1, Malformed
//!   для V2; стабильный contract для caller'ов).
//!
//! These tests fixture the following invariants:
//! - V1 envelope (leading byte 0x01) **does not parse** through `unseal_v2` —
//!   returns `UnsupportedVersion { got: 0x01 }`.
//! - V2 envelope (leading byte 0x02) **does not parse** through V1 `unseal` —
//!   returns `UnsupportedVersion { got: 0x02 }`.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_pq::{xwing_keygen, XWingPublicKey, XWingSecretSeed};
use umbrella_sealed_sender::{
    seal, seal_v2, unseal, unseal_v2, SealedSenderError, SealedSenderVersion,
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

/// V1 envelope не должна парситься через unseal_v2 — strict V2 dispatcher.
/// V1 envelope must not parse through unseal_v2 — strict V2 dispatcher.
#[test]
fn v1_envelope_rejected_by_unseal_v2() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let v1_wire = seal(
        alice.as_ref(),
        &bob.identity_x25519_public(),
        b"v1-msg",
        &mut rng,
    )
    .unwrap();
    assert_eq!(v1_wire[0], 0x01);

    let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &v1_wire);
    assert!(matches!(
        result,
        Err(SealedSenderError::UnsupportedVersion { got: 0x01 })
    ));
}

/// V2 envelope не должна парситься через V1 unseal — strict V1 dispatcher.
/// V2 envelope must not parse through V1 unseal — strict V1 dispatcher.
#[test]
fn v2_envelope_rejected_by_v1_unseal() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let v2_wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"v2-msg", &mut rng).unwrap();
    assert_eq!(v2_wire[0], 0x02);

    let result = unseal(bob.as_ref(), &v2_wire);
    assert!(matches!(
        result,
        Err(SealedSenderError::UnsupportedVersion { got: 0x02 })
    ));
}

/// Caller dispatcher pattern: peek first byte → выбор seal / seal_v2.
/// Caller dispatcher pattern: peek first byte → choose seal / seal_v2.
#[test]
fn dispatcher_pattern_works_for_v1_and_v2() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;

    let v1_wire = seal(
        alice.as_ref(),
        &bob.identity_x25519_public(),
        b"v1",
        &mut rng,
    )
    .unwrap();
    let v2_wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"v2", &mut rng).unwrap();

    // Dispatcher: peek byte → выбор pathа.
    // Dispatcher: peek byte → choose path.
    let dispatch_unseal = |wire: &[u8]| -> Result<Vec<u8>, SealedSenderError> {
        if wire.is_empty() {
            return Err(SealedSenderError::Malformed {
                reason: "empty wire",
            });
        }
        match SealedSenderVersion::try_from(wire[0])? {
            SealedSenderVersion::V1Classical => {
                let opened = unseal(bob.as_ref(), wire)?;
                Ok(opened.message)
            }
            SealedSenderVersion::V2HybridXWing => {
                let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, wire)?;
                Ok(opened.message)
            }
        }
    };

    assert_eq!(dispatch_unseal(&v1_wire).unwrap(), b"v1");
    assert_eq!(dispatch_unseal(&v2_wire).unwrap(), b"v2");
}

/// Все 254 unknown first bytes должны отвергаться обеими функциями.
/// All 254 unknown first bytes must be rejected by both functions.
#[test]
fn unknown_first_bytes_rejected_by_both() {
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();

    for v in 0u16..=255u16 {
        let v = v as u8;
        if v == 0x01 || v == 0x02 {
            continue; // valid versions
        }
        let mut wire = vec![0u8; umbrella_sealed_sender::MIN_WIRE_LEN.max(1393)];
        wire[0] = v;
        let r_v1 = unseal(bob.as_ref(), &wire);
        let r_v2 = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        assert!(matches!(
            r_v1,
            Err(SealedSenderError::UnsupportedVersion { got }) if got == v
        ));
        assert!(matches!(
            r_v2,
            Err(SealedSenderError::UnsupportedVersion { got }) if got == v
        ));
    }
}

/// V1 и V2 wire format byte-byte различные при same payload + same identity.
/// V1 и V2 не collide.
/// V1 and V2 wire formats are byte-byte distinct for the same payload + same
/// identity. V1 and V2 do not collide.
#[test]
fn v1_v2_wire_formats_differ() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, _) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let v1_wire = seal(
        alice.as_ref(),
        &bob.identity_x25519_public(),
        b"same",
        &mut rng,
    )
    .unwrap();
    let v2_wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"same", &mut rng).unwrap();
    assert_ne!(v1_wire, v2_wire);
    assert_ne!(v1_wire[0], v2_wire[0]);
    assert!(
        v2_wire.len() > v1_wire.len(),
        "V2 envelope значительно больше V1"
    );
}

/// Empty wire отвергается обеими функциями. Stable contract: Malformed (V1)
/// или Malformed (V2) — никаких panic / OOB.
/// Empty wire is rejected by both functions. Stable contract: Malformed (V1)
/// or Malformed (V2) — no panic / OOB.
#[test]
fn empty_wire_rejected_by_both() {
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let r_v1 = unseal(bob.as_ref(), &[]);
    let r_v2 = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &[]);
    assert!(matches!(r_v1, Err(SealedSenderError::Malformed { .. })));
    assert!(matches!(r_v2, Err(SealedSenderError::Malformed { .. })));
}

/// Smoke test: same client posiluje V1 и V2 envelopes; один dispatcher
/// возвращает каждое сообщение корректно.
/// Smoke test: same client sends V1 and V2 envelopes; a single dispatcher
/// returns each message correctly.
#[test]
fn alice_sends_alternating_v1_v2_envelopes() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;

    let messages: &[(&[u8], bool)] = &[
        (b"first-v1", false),
        (b"second-v2", true),
        (b"third-v1", false),
        (b"fourth-v2-pq", true),
    ];

    let mut wires: Vec<Vec<u8>> = Vec::new();
    for &(msg, is_v2) in messages {
        if is_v2 {
            wires.push(seal_v2(alice.as_ref(), &bob_xwing_pk, msg, &mut rng).unwrap());
        } else {
            wires.push(seal(alice.as_ref(), &bob.identity_x25519_public(), msg, &mut rng).unwrap());
        }
    }

    for (wire, &(msg, is_v2)) in wires.iter().zip(messages.iter()) {
        match wire[0] {
            0x01 => {
                assert!(!is_v2);
                let opened = unseal(bob.as_ref(), wire).unwrap();
                assert_eq!(opened.message, msg);
                assert_eq!(opened.sender_identity, alice.identity_public());
            }
            0x02 => {
                assert!(is_v2);
                let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, wire).unwrap();
                assert_eq!(opened.message, msg);
                assert_eq!(opened.sender_identity, alice.identity_public());
            }
            other => panic!("unexpected version byte: 0x{other:02x}"),
        }
    }
}

/// V2 wire prepend'ed leading byte 0x01 не parses ни как V1 (длина / структура
/// не совпадает) ни как V2 (version byte неверный).
/// V2 wire with prepended leading byte 0x01 does not parse as V1 (length /
/// structure mismatch) or as V2 (wrong version byte).
#[test]
fn v2_wire_with_v1_byte_prefix_rejected_by_both() {
    let alice = fresh_keystore();
    let bob = fresh_keystore();
    let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
    let mut rng = OsRng;
    let mut tampered = seal_v2(alice.as_ref(), &bob_xwing_pk, b"x", &mut rng).unwrap();
    tampered[0] = 0x01;

    let r_v1 = unseal(bob.as_ref(), &tampered);
    let r_v2 = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &tampered);

    // V1 parser попробует парсить как X25519 ECDH envelope; eph_pub байты не
    // valid → DH дает корректный shared (X25519 accepts любые 32 bytes), но
    // AEAD AAD не совпадает с тем что использовал sender (V2 AAD!=V1 AAD) →
    // crypto fail. Допустимо как Err(Crypto) либо Malformed.
    // V1 parser will try to parse as X25519 ECDH envelope; eph_pub bytes won't
    // be valid... AEAD AAD will not match (V2 AAD != V1 AAD) → crypto fail.
    // Acceptable as Err(Crypto) or Malformed.
    assert!(r_v1.is_err());
    // V2 parser отвергает 0x01 как UnsupportedVersion strictly.
    assert!(matches!(
        r_v2,
        Err(SealedSenderError::UnsupportedVersion { got: 0x01 })
    ));
}
