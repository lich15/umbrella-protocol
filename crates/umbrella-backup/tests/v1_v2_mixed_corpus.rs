//! Integration tests для V1 ↔ V2 mixed wire-format corpus + caller-side dispatch.
//! Integration tests for V1 ↔ V2 mixed wire-format corpus + caller-side dispatch.
//!
//! Этап 8 блок 8.7: проверка backward compat V1 + strict V2 dispatcher
//! поведения. V1 wrapped key parsing path и V2 wrapped key parsing path
//! полностью изолированы; никакого silent fallback.
//!
//! Stage 8 block 8.7: backward-compat V1 + strict V2 dispatcher behaviour.
//! V1 and V2 parsing paths are fully isolated; no silent fallback.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use umbrella_backup::cloud_wrap::params::{
    ThresholdConfig, DEFAULT_TOTAL, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION, WRAPPED_KEY_LEN,
};
use umbrella_backup::cloud_wrap::pq_wrap::{wrap_v1_into_v2, WrappedKeyV2, WRAPPED_KEY_V2_LEN};
use umbrella_backup::cloud_wrap::version::WrappingCiphersuite;
use umbrella_backup::cloud_wrap::wire::{CanonicalAad, WrappedKey, ED25519_PUB_LEN};
use umbrella_backup::cloud_wrap::wrap::wrap_message_key;
use umbrella_backup::cloud_wrap::WrappingParams;
use umbrella_backup::error::BackupError;
use umbrella_pq::{xwing_keygen, HedgedWitness};

/// Тестовый `HedgedWitness` (zero-byte; sound только в тестах где RNG honest).
/// Test-only `HedgedWitness` (zero-byte; sound only when test RNG is honest).
fn test_hedged_witness() -> HedgedWitness {
    HedgedWitness::zeroed_for_tests_only()
}

fn sample_v1_params() -> WrappingParams {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let y = RISTRETTO_BASEPOINT_POINT * k;
    WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
        config: ThresholdConfig::default(),
    }
}

fn sample_aad() -> CanonicalAad {
    CanonicalAad {
        sender_identity_pubkey: [0x11; ED25519_PUB_LEN],
        recipient_device_pubkey: [0x22; ED25519_PUB_LEN],
        chat_id: [0x33; 32],
        msg_seq: 1,
    }
}

/// V1 wrapped key (81 bytes, version 0x01) НЕ парсится через V2 parser.
/// V1 wrapped key (81 bytes, version 0x01) does NOT parse through V2 parser.
#[test]
fn v1_wire_rejected_by_v2_parser() {
    let mut rng = OsRng;
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1_wrapped = wrap_message_key(&sample_v1_params(), &mk, &aad, &mut rng).unwrap();

    let v1_bytes = v1_wrapped.to_bytes();
    let result = WrappedKeyV2::from_bytes(&v1_bytes);
    assert!(matches!(
        result,
        Err(BackupError::UnsupportedWrappingCiphersuite { got: 0x01 })
    ));
}

/// V2 wrapped key (1218 bytes, version 0x02) НЕ парсится через V1 parser.
/// V2 wrapped key (1218 bytes, version 0x02) does NOT parse through V1 parser.
#[test]
fn v2_wire_rejected_by_v1_parser() {
    let mut rng = OsRng;
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1_wrapped = wrap_message_key(&sample_v1_params(), &mk, &aad, &mut rng).unwrap();
    let (pk, _) = xwing_keygen(&mut rng).unwrap();
    let v2_wrapped =
        wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let v2_bytes = v2_wrapped.to_bytes();
    // V1 parser (`WrappedKey::from_bytes`) ожидает 81 bytes; V2 wire 1218 bytes.
    // V1 parser expects 81 bytes; V2 wire is 1218 bytes.
    let result = WrappedKey::from_bytes(&v2_bytes);
    assert!(matches!(result, Err(BackupError::WrappedKeyTruncated)));
}

/// Caller-side dispatch pattern: peek `wire[0]` → choose parser.
/// Pattern recommended in design §10.3 для mixed corpus handling.
///
/// Caller-side dispatch pattern: peek `wire[0]` → choose parser.
#[test]
fn caller_side_dispatch_pattern_works() {
    let mut rng = OsRng;
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1_wrapped = wrap_message_key(&sample_v1_params(), &mk, &aad, &mut rng).unwrap();
    let (pk, _) = xwing_keygen(&mut rng).unwrap();
    let v2_wrapped =
        wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let v1_wire = v1_wrapped.to_bytes();
    let v2_wire = v2_wrapped.to_bytes();

    // V1 dispatch.
    let cs_v1 = WrappingCiphersuite::try_from(v1_wire[0]).unwrap();
    assert_eq!(cs_v1, WrappingCiphersuite::V1Classical);
    let parsed_v1 = WrappedKey::from_bytes(&v1_wire).unwrap();
    assert_eq!(parsed_v1.to_bytes(), v1_wrapped.to_bytes());

    // V2 dispatch.
    let cs_v2 = WrappingCiphersuite::try_from(v2_wire[0]).unwrap();
    assert_eq!(cs_v2, WrappingCiphersuite::V2HybridXWing);
    let parsed_v2 = WrappedKeyV2::from_bytes(&v2_wire).unwrap();
    assert_eq!(parsed_v2, v2_wrapped);
}

/// Empty wire отвергается обоими парсерами с правильным error.
/// Empty wire rejected by both parsers with correct error.
#[test]
fn empty_wire_rejected_by_both_parsers() {
    let v1 = WrappedKey::from_bytes(&[]);
    assert!(matches!(v1, Err(BackupError::WrappedKeyTruncated)));

    let v2 = WrappedKeyV2::from_bytes(&[]);
    assert!(matches!(v2, Err(BackupError::WrappedKeyV2Truncated)));
}

/// Все unknown bytes (≠ 0x01, ≠ 0x02) — отвергаются V2 parser специфической
/// `UnsupportedWrappingCiphersuite` ошибкой; для V1 parser — корректная
/// `WrappedKeyVersionMismatch`.
///
/// All unknown bytes (≠ 0x01, ≠ 0x02) are rejected by the V2 parser with
/// specific `UnsupportedWrappingCiphersuite`; the V1 parser yields
/// `WrappedKeyVersionMismatch`.
#[test]
fn unknown_first_bytes_rejected_specifically() {
    for b in 0u8..=0xFF {
        if b == 0x01 || b == 0x02 {
            continue;
        }
        // V2 parser: первый byte check + try_from → UnsupportedWrappingCiphersuite.
        let mut buf_v2 = vec![0u8; WRAPPED_KEY_V2_LEN];
        buf_v2[0] = b;
        let err_v2 = WrappedKeyV2::from_bytes(&buf_v2).unwrap_err();
        assert!(
            matches!(err_v2, BackupError::UnsupportedWrappingCiphersuite { got } if got == b),
            "byte {b:#x} V2: expected UnsupportedWrappingCiphersuite, got {err_v2:?}"
        );

        // V1 parser: длина 81 + первый byte ≠ 0x01 → WrappedKeyVersionMismatch.
        let mut buf_v1 = vec![0u8; WRAPPED_KEY_LEN];
        buf_v1[0] = b;
        let err_v1 = WrappedKey::from_bytes(&buf_v1).unwrap_err();
        assert!(
            matches!(err_v1, BackupError::WrappedKeyVersionMismatch { found, .. } if found == b),
            "byte {b:#x} V1: expected WrappedKeyVersionMismatch, got {err_v1:?}"
        );
    }
}

/// V1-version-byte (0x01) prefix + V2 length → V2 parser отвергает (version mismatch),
/// V1 parser отвергает (length mismatch).
///
/// V1-version-byte (0x01) prefix + V2 length → V2 parser rejects (version mismatch),
/// V1 parser rejects (length mismatch).
#[test]
fn v1_byte_prefix_v2_length_buffer_rejected_by_both() {
    let mut buf = vec![0u8; WRAPPED_KEY_V2_LEN];
    buf[0] = 0x01;

    // V2 parser: byte 0x01 → UnsupportedWrappingCiphersuite.
    let err_v2 = WrappedKeyV2::from_bytes(&buf).unwrap_err();
    assert!(matches!(
        err_v2,
        BackupError::UnsupportedWrappingCiphersuite { got: 0x01 }
    ));

    // V1 parser: длина 1218 ≠ 81 → WrappedKeyTruncated.
    let err_v1 = WrappedKey::from_bytes(&buf).unwrap_err();
    assert!(matches!(err_v1, BackupError::WrappedKeyTruncated));
}

/// V2-version-byte (0x02) prefix + V1 length → оба отвергают.
/// V2-version-byte (0x02) prefix + V1 length → both reject.
#[test]
fn v2_byte_prefix_v1_length_buffer_rejected_by_both() {
    let mut buf = vec![0u8; WRAPPED_KEY_LEN];
    buf[0] = 0x02;

    // V1 parser: 0x02 ≠ 0x01 → WrappedKeyVersionMismatch.
    let err_v1 = WrappedKey::from_bytes(&buf).unwrap_err();
    assert!(matches!(
        err_v1,
        BackupError::WrappedKeyVersionMismatch {
            expected: 0x01,
            found: 0x02
        }
    ));

    // V2 parser: byte 0x02 OK но length 81 ≠ 1218 → WrappedKeyV2Truncated.
    let err_v2 = WrappedKeyV2::from_bytes(&buf).unwrap_err();
    assert!(matches!(err_v2, BackupError::WrappedKeyV2Truncated));
}

/// V1 wrapped key wire format **byte-distinct** от V2: первый byte distinct.
/// V1 wrapped key wire format **byte-distinct** from V2: first byte distinct.
#[test]
fn v1_v2_wire_first_byte_distinct() {
    let mut rng = OsRng;
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();
    let v1_wrapped = wrap_message_key(&sample_v1_params(), &mk, &aad, &mut rng).unwrap();
    let (pk, _) = xwing_keygen(&mut rng).unwrap();
    let v2_wrapped =
        wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let v1_bytes = v1_wrapped.to_bytes();
    let v2_bytes = v2_wrapped.to_bytes();
    assert_eq!(v1_bytes[0], 0x01);
    assert_eq!(v2_bytes[0], 0x02);
    assert_ne!(v1_bytes[0], v2_bytes[0]);
}

/// V1 wire-overhead minimal (81 bytes); V2 wire-overhead +1137.
/// V1 wire-overhead minimal (81 bytes); V2 wire-overhead +1137.
#[test]
fn v1_v2_wire_size_constants() {
    assert_eq!(WRAPPED_KEY_LEN, 81);
    assert_eq!(WRAPPED_KEY_V2_LEN, 1218);
    assert_eq!(WRAPPED_KEY_V2_LEN - WRAPPED_KEY_LEN, 1137);
}

/// Mixed corpus alternating V1/V2 entries (simulates database upgrade scenario):
/// V1 entries обрабатываются V1 unwrap path, V2 entries — V2 unwrap path.
///
/// Mixed corpus alternating V1/V2 entries (simulates a database upgrade scenario):
/// V1 entries flow through V1 unwrap path, V2 entries through V2 unwrap path.
#[test]
fn mixed_v1_v2_alternating_corpus_dispatched_correctly() {
    let mut rng = OsRng;
    let aad = sample_aad();
    let mut entries: Vec<Vec<u8>> = Vec::new();

    // 3 V1 + 3 V2 alternating.
    for i in 0..3 {
        let mk1 = [(i * 2) as u8; MESSAGE_KEY_LEN];
        let v1 = wrap_message_key(&sample_v1_params(), &mk1, &aad, &mut rng).unwrap();
        entries.push(v1.to_bytes().to_vec());

        let mk2 = [(i * 2 + 1) as u8; MESSAGE_KEY_LEN];
        let v1_inner = wrap_message_key(&sample_v1_params(), &mk2, &aad, &mut rng).unwrap();
        let (pk, _) = xwing_keygen(&mut rng).unwrap();
        let v2 = wrap_v1_into_v2(&pk, &v1_inner, &aad, &test_hedged_witness(), &mut rng).unwrap();
        entries.push(v2.to_bytes().to_vec());
    }

    let mut v1_count = 0;
    let mut v2_count = 0;
    for entry in &entries {
        let cs = WrappingCiphersuite::try_from(entry[0]).unwrap();
        match cs {
            WrappingCiphersuite::V1Classical => {
                let parsed = WrappedKey::from_bytes(entry).unwrap();
                assert_eq!(parsed.version, 0x01);
                v1_count += 1;
            }
            WrappingCiphersuite::V2HybridXWing => {
                let parsed = WrappedKeyV2::from_bytes(entry).unwrap();
                assert_eq!(parsed.to_bytes()[0], 0x02);
                v2_count += 1;
            }
        }
    }
    assert_eq!(v1_count, 3);
    assert_eq!(v2_count, 3);
}

/// V2 wire-format первый byte всегда `0x02` независимо от X-Wing recipient или V1 inner.
/// V2 wire-format first byte is always `0x02` regardless of X-Wing recipient or V1 inner.
#[test]
fn v2_first_byte_invariant() {
    let mut rng = OsRng;
    let aad = sample_aad();
    for _ in 0..5 {
        let mk = [0u8; MESSAGE_KEY_LEN];
        let v1 = wrap_message_key(&sample_v1_params(), &mk, &aad, &mut rng).unwrap();
        let (pk, _) = xwing_keygen(&mut rng).unwrap();
        let v2 = wrap_v1_into_v2(&pk, &v1, &aad, &test_hedged_witness(), &mut rng).unwrap();
        let bytes = v2.to_bytes();
        assert_eq!(bytes[0], 0x02);
    }
}
