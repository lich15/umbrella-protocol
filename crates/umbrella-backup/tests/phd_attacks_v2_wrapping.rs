//! PhD-B Hybrid PQ Audit (2026-05-19) — V2 wrapping layer end-to-end attacks.
//!
//! Spec: `docs/superpowers/specs/2026-05-19-phd-b-hybrid-pq-audit-design.md`.
//!
//! These tests exercise `wrap_v1_into_v2` / `unwrap_v2_to_v1` from
//! `umbrella-backup::cloud_wrap::pq_wrap` against a state-level adversary.
//! Each `attack_*` test embeds a concrete adversary action and asserts the
//! defense fires (or — for negative findings — documents the unexpected
//! behaviour).
//!
//! Outcomes are documented in `docs/audits/phd-b-hybrid-pq-audit-2026-05-19.md`
//! as F-PHD-PQ-{N}-{severity}.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce as AeadNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;

use umbrella_backup::cloud_wrap::{
    unwrap_v2_to_v1, wrap_message_key, wrap_v1_into_v2, CanonicalAad, ThresholdConfig, WrappedKey,
    WrappedKeyV2, WrappingCiphersuite, WrappingParams,
};
use umbrella_backup::cloud_wrap::{ED25519_PUB_LEN, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION};
use umbrella_backup::BackupError;
use umbrella_pq::{
    xwing_decaps, xwing_encaps, xwing_keygen, HedgedWitness, XWingPublicKey, XWingSecretSeed,
    XWING_CIPHERTEXT_LEN,
};

/// Тестовый `HedgedWitness` (zero-byte; sound только в тестах где RNG honest).
/// Test-only `HedgedWitness` (zero-byte; sound only when test RNG is honest).
fn test_hedged_witness() -> HedgedWitness {
    HedgedWitness::zeroed_for_tests_only()
}

// =============================================================================
// Helpers
// =============================================================================

fn sample_aad() -> CanonicalAad {
    CanonicalAad {
        sender_identity_pubkey: [0xAA; ED25519_PUB_LEN],
        recipient_device_pubkey: [0xBB; ED25519_PUB_LEN],
        chat_id: [0xCC; 32],
        msg_seq: 13,
    }
}

fn sample_v1_params(k: Scalar) -> WrappingParams {
    let y = RISTRETTO_BASEPOINT_POINT * k;
    WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys: [[0u8; POINT_LEN]; 5],
        config: ThresholdConfig::default(),
    }
}

fn fresh_xwing_keypair() -> (XWingPublicKey, XWingSecretSeed) {
    let mut rng = OsRng;
    xwing_keygen(&mut rng).unwrap()
}

fn build_baseline_v2(
    rng: &mut OsRng,
) -> (
    WrappedKey,
    WrappedKeyV2,
    XWingPublicKey,
    XWingSecretSeed,
    CanonicalAad,
) {
    let k = Scalar::from(7u64);
    let v1_params = sample_v1_params(k);
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1 = wrap_message_key(&v1_params, &mk, &aad, rng).unwrap();
    let (pk, sk) = fresh_xwing_keypair();
    let v2 = wrap_v1_into_v2(&pk, &v1, &aad, &test_hedged_witness(), rng).unwrap();
    (v1, v2, pk, sk, aad)
}

// =============================================================================
// A1 — Hybrid downgrade enforcement
// =============================================================================
//
// Adversary intercepts V2 envelope from Alice → Bob; flips wire byte 0 from
// 0x02 to 0x01 in the hope that Bob's recipient stack will misclassify the
// V2 wire as V1 and either decrypt successfully (silent fallback) or crash.

/// Attack A1 — V2 wire with version byte forged to 0x01 must be rejected by
/// V1 parser (`WrappedKey::from_bytes`), and the V2 parser must reject 0x01
/// version byte regardless of length. Both directions = no silent fallback.
#[test]
fn attack_a1_forged_v1_byte_on_v2_wire_rejected_by_both_parsers() {
    let mut rng = OsRng;
    let (_, v2, _, _, _) = build_baseline_v2(&mut rng);
    let mut wire = v2.to_bytes().to_vec();
    wire[0] = 0x01; // forge V1 stamp

    // V2 parser: explicit UnsupportedWrappingCiphersuite { got: 0x01 }.
    let r = WrappedKeyV2::from_bytes(&wire);
    assert!(matches!(
        r,
        Err(BackupError::UnsupportedWrappingCiphersuite { got: 0x01 })
    ));

    // V1 parser: WrappedKey expects 81 bytes; 1218 bytes fails.
    let r = WrappedKey::from_bytes(&wire);
    assert!(r.is_err(), "V1 parser must reject mis-sized buffer");
}

/// Attack A1 dual — V1 wire (81 bytes) with version byte forged to 0x02 must
/// be rejected by V2 parser (UnsupportedWrappingCiphersuite OR
/// WrappedKeyV2Truncated). Specifically: V2 from_bytes does version check
/// FIRST, length check second, so 0x01 byte yields UnsupportedWrappingCiphersuite
/// regardless of length. Forge 0x02 first byte on V1 81-byte wire: hits length
/// check → WrappedKeyV2Truncated.
#[test]
fn attack_a1_forged_v2_byte_on_v1_wire_rejected_by_v2_parser() {
    let mut rng = OsRng;
    let k = Scalar::from(7u64);
    let v1_params = sample_v1_params(k);
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1 = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let mut v1_wire = v1.to_bytes().to_vec();
    v1_wire[0] = 0x02; // forge V2 stamp on 81-byte buffer

    let r = WrappedKeyV2::from_bytes(&v1_wire);
    // 0x02 parses as V2 (length check second) → WrappedKeyV2Truncated.
    assert!(matches!(r, Err(BackupError::WrappedKeyV2Truncated)));
}

// =============================================================================
// A4 — V2 envelope domain separation V1 vs V2
// =============================================================================
//
// Adversary attempts cross-protocol replay: derive the V2 AEAD key from
// shared_secret + V2 KDF parameters; encrypt under V1 KDF context; try
// decrypt with V2 unwrap. Must fail at AEAD MAC because of KDF byte-distinct
// salt+info contexts.

/// Attack A4 — adversary crafts a V2 envelope with V1-derived KDF (using
/// V1 domain separator "umbrellax-cloud-wrap-v1" instead of V2's). V2
/// unwrap derives V2-KDF AEAD key and fails MAC.
#[test]
fn attack_a4_v1_kdf_derived_aead_payload_fails_v2_unwrap_mac() {
    let mut rng = OsRng;
    let k = Scalar::from(7u64);
    let v1_params = sample_v1_params(k);
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1 = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let (pk, sk) = fresh_xwing_keypair();

    // Step 1: legitimate X-Wing encaps (adversary has access via observation).
    let (xwing_ct, shared_secret) = xwing_encaps(&mut rng, &pk).expect("encaps");
    use secrecy::ExposeSecret;
    let ss = shared_secret.expose_secret();

    // Step 2: derive AEAD key with V1-style HKDF (wrong salt/info → wrong key).
    let hk = Hkdf::<Sha256>::new(Some(b"umbrellax-cloud-wrap-v1"), ss);
    let mut okm = [0u8; 32 + 12];
    hk.expand(b"umbrellax-cloud-wrap-v1", &mut okm).unwrap();
    let bad_key = &okm[..32];
    let bad_nonce = &okm[32..];

    // Step 3: encrypt V1 wrapped key bytes with this wrong-context AEAD key.
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(bad_key));
    let v1_bytes = v1.to_bytes();
    let aad_bytes = {
        let mut out = Vec::new();
        out.push(0x02u8);
        out.extend_from_slice(&aad.canonical_bytes());
        out.extend_from_slice(pk.as_bytes());
        out
    };
    let blob = cipher
        .encrypt(
            AeadNonce::from_slice(bad_nonce),
            Payload {
                msg: &v1_bytes,
                aad: &aad_bytes,
            },
        )
        .expect("encrypt");
    let mut aead_payload = [0u8; 97];
    aead_payload.copy_from_slice(&blob);

    let forged_v2 = WrappedKeyV2 {
        xwing_ciphertext: xwing_ct,
        aead_payload,
    };

    // V2 unwrap derives the CORRECT V2-KDF key but the payload was sealed
    // under the V1-KDF key → AEAD tag verification fails.
    let result = unwrap_v2_to_v1(&sk, &pk, &forged_v2, &aad);
    assert!(matches!(result, Err(BackupError::AeadDecryptFailed)));
}

/// Attack A4 dual — same shared_secret + V2 KDF but AEAD AAD swapped (use V1
/// AAD format without recipient_xwing_pubkey suffix). MAC fails.
#[test]
fn attack_a4_v2_aad_format_drift_fails_unwrap() {
    let mut rng = OsRng;
    let (v1, _, pk, sk, aad) = build_baseline_v2(&mut rng);

    let (xwing_ct, shared_secret) = xwing_encaps(&mut rng, &pk).expect("encaps");
    use secrecy::ExposeSecret;
    let ss = shared_secret.expose_secret();

    // Derive V2 KDF correctly.
    let info = {
        let mut v = Vec::new();
        v.extend_from_slice(b"umbrellax-cloud-wrap-v2");
        v.extend_from_slice(&xwing_ct);
        v.extend_from_slice(pk.as_bytes());
        v
    };
    let hk = Hkdf::<Sha256>::new(Some(b"umbrellax-cloud-wrap-v2"), ss);
    let mut okm = [0u8; 32 + 12];
    hk.expand(&info, &mut okm).unwrap();
    let aead_key = &okm[..32];
    let nonce = &okm[32..];

    // But use V1 AAD format (no xwing_pubkey suffix) — V2 unwrap composes
    // version || canonical_aad || pubkey; mismatch → MAC fails.
    let bad_aad = {
        let mut v = Vec::new();
        v.push(0x02u8);
        v.extend_from_slice(&aad.canonical_bytes());
        // intentionally omit recipient_xwing_pubkey
        v
    };
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(aead_key));
    let v1_bytes = v1.to_bytes();
    let blob = cipher
        .encrypt(
            AeadNonce::from_slice(nonce),
            Payload {
                msg: &v1_bytes,
                aad: &bad_aad,
            },
        )
        .expect("encrypt");
    let mut aead_payload = [0u8; 97];
    aead_payload.copy_from_slice(&blob);
    let forged_v2 = WrappedKeyV2 {
        xwing_ciphertext: xwing_ct,
        aead_payload,
    };

    let r = unwrap_v2_to_v1(&sk, &pk, &forged_v2, &aad);
    assert!(matches!(r, Err(BackupError::AeadDecryptFailed)));
}

// =============================================================================
// A7 — Implicit rejection + AEAD MAC binding
// =============================================================================
//
// Adversary tampers the X-Wing ciphertext within the V2 envelope. X-Wing
// decapsulation may yield a pseudo-random ss (implicit rejection per FIPS 203
// + draft-10 §5.4). The downstream AEAD ChaCha20-Poly1305 MAC must catch the
// mismatch — caller never observes a successful decrypt with wrong ss.

/// Attack A7 — bit-flip the ML-KEM half of xwing_ciphertext at all 1088
/// positions; verify every attempt either returns XWingDecapsFailed (rare,
/// only on libcrux structural error) or AeadDecryptFailed (common, the
/// MAC check fires).
#[test]
fn attack_a7_v2_aead_mac_catches_all_mlkem_half_bit_flips() {
    let mut rng = OsRng;
    let (_, baseline_v2, pk, sk, aad) = build_baseline_v2(&mut rng);

    let mut aead_failures = 0usize;
    let mut xwing_failures = 0usize;
    let mut success = 0usize;
    for pos in 0..1088 {
        let mut tampered = baseline_v2.clone();
        tampered.xwing_ciphertext[pos] ^= 0x40;
        match unwrap_v2_to_v1(&sk, &pk, &tampered, &aad) {
            Err(BackupError::AeadDecryptFailed) => aead_failures += 1,
            Err(BackupError::XWingDecapsFailed) => xwing_failures += 1,
            Ok(_) => success += 1,
            Err(other) => panic!("unexpected error pos={pos}: {other:?}"),
        }
    }
    assert_eq!(
        success, 0,
        "no tampered xwing_ct (ML-KEM half) may decrypt successfully"
    );
    assert_eq!(
        aead_failures + xwing_failures,
        1088,
        "all 1088 positions accounted for"
    );
    // Diagnostic — most positions trigger AEAD MAC failure (implicit rejection
    // in X-Wing combiner yields pseudo-random ss → wrong AEAD key → MAC fails).
    println!(
        "[A7-V2] ML-KEM-half tamper: AeadDecryptFailed={aead_failures} \
         XWingDecapsFailed={xwing_failures}"
    );
}

/// Attack A7 dual — flip the X25519 half (positions 1088..1120) and verify
/// the wrapper still rejects every variant.
#[test]
fn attack_a7_v2_aead_mac_catches_all_x25519_half_bit_flips() {
    let mut rng = OsRng;
    let (_, baseline_v2, pk, sk, aad) = build_baseline_v2(&mut rng);

    let mut total_rejections = 0usize;
    for pos in 1088..1120 {
        let mut tampered = baseline_v2.clone();
        tampered.xwing_ciphertext[pos] ^= 0x01;
        let r = unwrap_v2_to_v1(&sk, &pk, &tampered, &aad);
        match r {
            Err(BackupError::AeadDecryptFailed) | Err(BackupError::XWingDecapsFailed) => {
                total_rejections += 1;
            }
            other => panic!("X25519-half tamper at pos={pos} unexpectedly: {other:?}"),
        }
    }
    assert_eq!(total_rejections, 32);
}

// =============================================================================
// Cross-cutting attacks
// =============================================================================

/// Adversary mutation-fuzzes a valid V2 wire across 5000 byte positions
/// (deterministic 5x pass over 1218 bytes). NONE of the mutations may produce
/// a successful unwrap — defense-in-depth verified.
#[test]
fn attack_xtra_v2_wire_mutation_5000_iterations_no_silent_decrypt() {
    let mut rng = OsRng;
    let (_, baseline, pk, sk, aad) = build_baseline_v2(&mut rng);
    let baseline_bytes = baseline.to_bytes();

    let mut decrypted = 0usize;
    let mut parse_failures = 0usize;
    let mut unwrap_failures = 0usize;
    for iter in 0..5000u32 {
        let mut buf = baseline_bytes;
        let pos = (iter as usize) % buf.len();
        let bit = (iter as u8) % 8;
        buf[pos] ^= 1u8 << bit;
        match WrappedKeyV2::from_bytes(&buf) {
            Err(_) => parse_failures += 1,
            Ok(parsed) => match unwrap_v2_to_v1(&sk, &pk, &parsed, &aad) {
                Err(_) => unwrap_failures += 1,
                Ok(_) => decrypted += 1,
            },
        }
    }
    assert_eq!(
        decrypted, 0,
        "mutation fuzz must NEVER yield decrypt success"
    );
    println!(
        "[A-xtra] V2 wire mutation 5000 iter: parse_failures={parse_failures} \
         unwrap_failures={unwrap_failures} decrypted={decrypted}"
    );
}

/// Adversary attempts to recover V1 inner WrappedKey via wrong recipient key
/// across 200 distinct keypairs. None of them may unwrap.
#[test]
fn attack_xtra_v2_wrong_recipient_200_keypairs_zero_decrypt() {
    let mut rng = OsRng;
    let (v1, _, sender_pk, _sender_sk, aad) = build_baseline_v2(&mut rng);
    let v2 = wrap_v1_into_v2(&sender_pk, &v1, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let mut successes = 0usize;
    for _ in 0..200 {
        let (wrong_pk, wrong_sk) = fresh_xwing_keypair();
        let r = unwrap_v2_to_v1(&wrong_sk, &wrong_pk, &v2, &aad);
        if r.is_ok() {
            successes += 1;
        }
    }
    assert_eq!(successes, 0, "wrong-recipient unwraps must NEVER succeed");
}

/// Verify-extra — wire-format round-trip stability property (NOT a real
/// attack; renamed per honest classification).
#[test]
fn verify_xtra_v2_byte_roundtrip_50_envelopes_stability() {
    let mut rng = OsRng;
    let k = Scalar::from(1u64);
    let aad = sample_aad();
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let v1_params = sample_v1_params(k);

    let v1 = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let (pk, _sk) = fresh_xwing_keypair();
    for _ in 0..50 {
        let v2 = wrap_v1_into_v2(&pk, &v1, &aad, &test_hedged_witness(), &mut rng).unwrap();
        let bytes = v2.to_bytes();
        let parsed = WrappedKeyV2::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, v2);
        assert_eq!(parsed.to_bytes(), bytes);
    }
}

/// AAD canonical AAD field tamper — chat_id flip; AEAD MAC catches.
#[test]
fn attack_xtra_v2_aad_chat_id_field_tampered_rejected() {
    let mut rng = OsRng;
    let (_, v2, pk, sk, aad) = build_baseline_v2(&mut rng);

    let mut bad_aad = aad.clone();
    bad_aad.chat_id[5] ^= 0x80;
    let r = unwrap_v2_to_v1(&sk, &pk, &v2, &bad_aad);
    assert!(matches!(r, Err(BackupError::AeadDecryptFailed)));
}

/// Attack-extra — adversary attempts envelope collision by repeatedly
/// wrapping identical V1 + recipient. If X-Wing encaps were deterministic
/// (low-entropy CSPRNG), an adversary could detect repeat envelopes
/// (linkability). Generate 100 envelopes; assert all distinct.
#[test]
fn attack_xtra_v2_envelope_collision_100_envelopes_zero_match() {
    let mut rng = OsRng;
    let (v1, _, pk, _, aad) = build_baseline_v2(&mut rng);
    let mut witnesses: Vec<[u8; XWING_CIPHERTEXT_LEN]> = Vec::with_capacity(100);
    for _ in 0..100 {
        let v2 = wrap_v1_into_v2(&pk, &v1, &aad, &test_hedged_witness(), &mut rng).unwrap();
        for prior in &witnesses {
            assert_ne!(*prior, v2.xwing_ciphertext);
        }
        witnesses.push(v2.xwing_ciphertext);
    }
}

/// Verify-extra — V2 wrap+unwrap concurrent stress property (NOT a real
/// attack; renamed per honest classification).
#[test]
fn verify_xtra_v2_concurrent_4threads_25iter_no_race() {
    use std::sync::Arc;
    let mut rng = OsRng;
    let (v1, _, pk, sk, aad) = build_baseline_v2(&mut rng);
    let pk = Arc::new(pk);
    let sk = Arc::new(sk);
    let v1 = Arc::new(v1);
    let aad = Arc::new(aad);

    let handles: Vec<_> = (0..4)
        .map(|tid| {
            let pk = pk.clone();
            let sk = sk.clone();
            let v1 = v1.clone();
            let aad = aad.clone();
            std::thread::spawn(move || {
                let mut local_rng = OsRng;
                for _ in 0..25 {
                    let v2 =
                        wrap_v1_into_v2(&pk, &v1, &aad, &test_hedged_witness(), &mut local_rng)
                            .unwrap();
                    let v1_recovered = unwrap_v2_to_v1(&sk, &pk, &v2, &aad).expect("unwrap");
                    assert_eq!(v1_recovered.to_bytes(), v1.to_bytes());
                }
                tid
            })
        })
        .collect();
    for h in handles {
        let _ = h.join().expect("thread join");
    }
}

/// Attack-extra — adversary enumerates all 256 byte values for the version
/// stamp hoping to find an unexpected accepted value (sanity for unknown
/// version dispatcher). Only 0x01 and 0x02 accepted in pq build.
#[test]
fn attack_xtra_wrapping_ciphersuite_full_byte_enumeration() {
    let mut accepted = 0usize;
    for b in 0u16..=255u16 {
        if WrappingCiphersuite::try_from(b as u8).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 2);
}

/// Verify-extra — X-Wing ss sender/receiver consistency baseline (NOT a
/// real attack; renamed per honest classification).
#[test]
fn verify_xtra_xwing_ss_match_sender_receiver_baseline_50_iter() {
    let mut rng = OsRng;
    let (pk, sk) = fresh_xwing_keypair();
    use secrecy::ExposeSecret;
    let mut mismatches = 0usize;
    for _ in 0..50 {
        let (ct, ss_sender) = xwing_encaps(&mut rng, &pk).unwrap();
        let ss_recv = xwing_decaps(&sk, &ct).unwrap();
        if ss_sender.expose_secret() != ss_recv.expose_secret() {
            mismatches += 1;
        }
    }
    assert_eq!(mismatches, 0);
}

// =============================================================================
// Additional real-attack scenarios (Q2 honest-count gate)
// =============================================================================

/// Attack — adversary captures V2 envelope from Alice → Bob (chat A); replays
/// the same wire to Bob but under chat B's AAD context (different chat_id +
/// msg_seq). AEAD MAC bound to chat_id via AAD must reject the cross-chat
/// replay.
#[test]
fn attack_v2_aad_cross_chat_replay_rejected() {
    let mut rng = OsRng;
    let (v1, v2, pk, sk, original_aad) = build_baseline_v2(&mut rng);

    // Adversary substitutes a different chat_id in AAD (chat B).
    let mut cross_chat_aad = original_aad.clone();
    cross_chat_aad.chat_id = [0xDD; 32]; // different chat_id
    cross_chat_aad.msg_seq = 99; // different msg_seq

    let r = unwrap_v2_to_v1(&sk, &pk, &v2, &cross_chat_aad);
    assert!(
        matches!(r, Err(BackupError::AeadDecryptFailed)),
        "cross-chat replay MUST fail at AEAD MAC: got {r:?}"
    );

    // Sanity — original AAD still works.
    let r_baseline = unwrap_v2_to_v1(&sk, &pk, &v2, &original_aad);
    assert_eq!(r_baseline.unwrap().to_bytes(), v1.to_bytes());
}

/// Attack — adversary captures V2 envelope, substitutes
/// sender_identity_pubkey in AAD with a different value (attempting sender
/// spoof). AEAD MAC catches the tamper.
#[test]
fn attack_v2_aad_sender_identity_substitution_rejected() {
    let mut rng = OsRng;
    let (_, v2, pk, sk, original_aad) = build_baseline_v2(&mut rng);

    let mut spoofed_aad = original_aad.clone();
    spoofed_aad.sender_identity_pubkey = [0xEE; ED25519_PUB_LEN]; // pretend different sender

    let r = unwrap_v2_to_v1(&sk, &pk, &v2, &spoofed_aad);
    assert!(matches!(r, Err(BackupError::AeadDecryptFailed)));
}

/// Attack — adversary captures V2 envelope, substitutes recipient_device_pubkey
/// in AAD (attempting "Eve receives Alice's message addressed to Bob's
/// other device") . MAC fails.
#[test]
fn attack_v2_aad_recipient_device_substitution_rejected() {
    let mut rng = OsRng;
    let (_, v2, pk, sk, original_aad) = build_baseline_v2(&mut rng);

    let mut spoofed_aad = original_aad.clone();
    spoofed_aad.recipient_device_pubkey = [0xFF; ED25519_PUB_LEN];

    let r = unwrap_v2_to_v1(&sk, &pk, &v2, &spoofed_aad);
    assert!(matches!(r, Err(BackupError::AeadDecryptFailed)));
}

/// Attack — adversary tampers msg_seq field of AAD; attempting "this is
/// envelope #42 not #13" replay. AEAD MAC catches the tamper.
#[test]
fn attack_v2_aad_msg_seq_increment_rejected() {
    let mut rng = OsRng;
    let (_, v2, pk, sk, original_aad) = build_baseline_v2(&mut rng);

    let mut tampered = original_aad.clone();
    tampered.msg_seq = original_aad.msg_seq.wrapping_add(1);

    let r = unwrap_v2_to_v1(&sk, &pk, &v2, &tampered);
    assert!(matches!(r, Err(BackupError::AeadDecryptFailed)));
}

/// Attack — adversary swaps inner V1 wrapped key bytes inside V2 envelope.
/// Aim: send Alice → Bob the V2 envelope where the inner V1 wrap is for a
/// DIFFERENT message_key. Defense: AEAD MAC binds aead_payload (which
/// encrypts the inner V1 bytes) to the AAD context; any swap fails MAC.
///
/// We exhaustively flip every byte of `aead_payload` (97 positions) and
/// assert every flip is caught.
#[test]
fn attack_v2_inner_wrapped_key_byte_swap_97_positions_rejected() {
    let mut rng = OsRng;
    let (_, baseline_v2, pk, sk, aad) = build_baseline_v2(&mut rng);

    let mut total_rejected = 0usize;
    for pos in 0..baseline_v2.aead_payload.len() {
        let mut t = baseline_v2.clone();
        t.aead_payload[pos] ^= 0xFF;
        let r = unwrap_v2_to_v1(&sk, &pk, &t, &aad);
        assert!(
            matches!(r, Err(BackupError::AeadDecryptFailed)),
            "byte pos={pos} unexpected: {r:?}"
        );
        total_rejected += 1;
    }
    assert_eq!(total_rejected, baseline_v2.aead_payload.len());
}

/// Attack — adversary replays old V2 envelope (msg_seq=13) AT EXACTLY the
/// boundary of session — verify it remains valid for replay-detection
/// purposes only at higher protocol layer; at unwrap layer it succeeds
/// (this layer doesn't enforce replay).
/// This is a NEGATIVE finding documentation: replay defence is upstream.
#[test]
fn attack_v2_replay_at_unwrap_layer_succeeds_documents_layered_defense() {
    let mut rng = OsRng;
    let (v1, v2, pk, sk, aad) = build_baseline_v2(&mut rng);

    // First "delivery" — succeeds.
    let r1 = unwrap_v2_to_v1(&sk, &pk, &v2, &aad).expect("first unwrap");
    assert_eq!(r1.to_bytes(), v1.to_bytes());

    // "Replay" — adversary submits the same envelope again. unwrap_v2_to_v1
    // is stateless and DOES succeed. This is BY DESIGN — replay protection
    // lives in the upstream Sealed Server ceremony (msg_seq tracking +
    // per-recipient deduplication). The audit confirms the layered defense
    // architecture is consistent with SPEC-12.
    let r2 = unwrap_v2_to_v1(&sk, &pk, &v2, &aad).expect("replay unwrap");
    assert_eq!(r2.to_bytes(), v1.to_bytes());
    // Documented: replay defense = Sealed Server's responsibility, not V2 wrap.
}
