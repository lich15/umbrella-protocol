//! F-37 regression tests — `tls_codec-0.4.2` parser panic защита через
//! `umbrella_mls::parse_mls_message_safe` + `parse_key_package_safe`.
//!
//! F-37 (HIGH, escalated block 10.4b session #34) был discovered через Pattern Q baseline
//! verification — `prop_mls_keypackage_parser_never_panics` proptest panic'ует на 5-байтовом
//! input `[0,0,0,1,192]` (transitive dep `tls_codec-0.4.2/src/quic_vec.rs:53` assertion
//! `len_len_log <= MAX_LEN_LEN_LOG`). Раньше raw `KeyPackageIn::tls_deserialize` либо
//! `MlsMessageIn::tls_deserialize_exact` propagate panic вверх по стеку = remote process
//! termination (DoS) на любом adversarial wire packet matching этот pattern.
//!
//! Block 10.8 inline-fix (commit `dc1273e`): добавлены `umbrella_mls::parse_*_safe` обёртки в
//! `crates/umbrella-mls/src/parser.rs` с двумя защитными слоями:
//!
//! 1. **Bounds-check** — pre-parse rejection truncated input (< MLS_MESSAGE_MIN_BYTES = 8 либо
//!    < KEY_PACKAGE_MIN_BYTES = 64). Cheap O(1) проверка против F-37 5-byte attack vector +
//!    similar truncation patterns.
//! 2. **`std::panic::catch_unwind`** — defensive layer для других panic patterns. Преобразует
//!    panic в explicit `MlsError::ParserPanic`. Постулат 14: no silent fallback.
//!
//! Эти tests verify что:
//! - F-37 minimal input `[0,0,0,1,192]` rejected с `MlsError::Codec` (bounds-check tier);
//! - Empty + 1-7 byte inputs rejected (bounds-check coverage);
//! - 8+ byte malformed inputs rejected без panic (bounds-check pass + tls_codec returns Err
//!   либо catch_unwind catches panic).
//!
//! F-37 regression tests — `tls_codec-0.4.2` parser-panic protection via
//! `umbrella_mls::parse_mls_message_safe` + `parse_key_package_safe`.
//!
//! F-37 (HIGH, escalated in block 10.4b session #34) was discovered via Pattern Q baseline
//! verification — `prop_mls_keypackage_parser_never_panics` proptest panics on the 5-byte input
//! `[0,0,0,1,192]` (the transitive dep `tls_codec-0.4.2/src/quic_vec.rs:53` assertion
//! `len_len_log <= MAX_LEN_LEN_LOG`). Previously, the raw `KeyPackageIn::tls_deserialize` or
//! `MlsMessageIn::tls_deserialize_exact` propagated the panic up the stack = remote process
//! termination (DoS) on any adversarial wire packet matching this pattern.
//!
//! Block 10.8 inline-fix (commit `dc1273e`) added the `umbrella_mls::parse_*_safe` wrappers in
//! `crates/umbrella-mls/src/parser.rs` with two defensive layers:
//!
//! 1. **Bounds-check** — pre-parse rejection of truncated input (< MLS_MESSAGE_MIN_BYTES = 8
//!    or < KEY_PACKAGE_MIN_BYTES = 64). Cheap O(1) check against the F-37 5-byte attack vector
//!    and similar truncation patterns.
//! 2. **`std::panic::catch_unwind`** — defensive layer for other panic patterns. Converts a
//!    panic into an explicit `MlsError::ParserPanic`. Postulate 14: no silent fallback.
//!
//! These tests verify that:
//! - F-37 minimal input `[0,0,0,1,192]` is rejected with `MlsError::Codec` (bounds-check tier);
//! - Empty and 1–7 byte inputs are rejected (bounds-check coverage);
//! - 8+ byte malformed inputs are rejected without panic (bounds-check pass +
//!   tls_codec returns Err or catch_unwind catches the panic).

use umbrella_mls::{
    parse_key_package_safe, parse_mls_message_safe, MlsError, KEY_PACKAGE_MIN_BYTES,
    MLS_MESSAGE_MIN_BYTES,
};

/// F-37 minimal reproduction input — 5 bytes triggering `tls_codec-0.4.2` panic.
/// Saved seed: `cc 5cd3f3f5272f83529d2f1f4a37f55e5291be5ad12f53072085e87bcdf47c24f9`
/// (proptest-regressions/targets.txt в umbrella-fuzz, gitignored).
const F_37_MINIMAL_INPUT: &[u8] = &[0, 0, 0, 1, 192];

#[test]
fn f_37_mls_message_minimal_input_rejected_without_panic() {
    let result = parse_mls_message_safe(F_37_MINIMAL_INPUT);
    assert!(
        result.is_err(),
        "F-37 minimal input must be rejected, got Ok"
    );
    match result {
        Err(MlsError::Codec { kind }) => {
            assert!(
                kind.contains("MLS_MESSAGE_MIN_BYTES"),
                "expected bounds-check rejection, got Codec {{ kind: {kind} }}"
            );
        }
        other => panic!("expected MlsError::Codec, got {other:?}"),
    }
}

#[test]
fn f_37_key_package_minimal_input_rejected_without_panic() {
    let result = parse_key_package_safe(F_37_MINIMAL_INPUT);
    assert!(
        result.is_err(),
        "F-37 minimal input must be rejected, got Ok"
    );
    match result {
        Err(MlsError::Codec { kind }) => {
            assert!(
                kind.contains("KEY_PACKAGE_MIN_BYTES"),
                "expected bounds-check rejection, got Codec {{ kind: {kind} }}"
            );
        }
        other => panic!("expected MlsError::Codec, got {other:?}"),
    }
}

#[test]
fn f_37_mls_message_empty_input_rejected_without_panic() {
    let result = parse_mls_message_safe(&[]);
    assert!(matches!(result, Err(MlsError::Codec { .. })));
}

#[test]
fn f_37_key_package_empty_input_rejected_without_panic() {
    let result = parse_key_package_safe(&[]);
    assert!(matches!(result, Err(MlsError::Codec { .. })));
}

#[test]
fn f_37_mls_message_one_byte_input_rejected_without_panic() {
    for byte in [0x00u8, 0x01, 0x55, 0x80, 0xC0, 0xFF] {
        let input = vec![byte];
        let result = parse_mls_message_safe(&input);
        assert!(
            matches!(result, Err(MlsError::Codec { .. })),
            "1-byte input {byte:#x} must be rejected by bounds-check"
        );
    }
}

#[test]
fn f_37_key_package_short_inputs_rejected_without_panic() {
    // 1, 2, 4, 8, 16, 32, 63 байта — all below KEY_PACKAGE_MIN_BYTES = 64.
    // 1, 2, 4, 8, 16, 32, 63 bytes — all below KEY_PACKAGE_MIN_BYTES = 64.
    for size in [1usize, 2, 4, 8, 16, 32, 63] {
        let input = vec![0xC0u8; size];
        let result = parse_key_package_safe(&input);
        assert!(
            matches!(result, Err(MlsError::Codec { .. })),
            "{size}-byte 0xC0 input must be rejected by bounds-check"
        );
    }
}

#[test]
fn f_37_mls_message_above_min_invalid_input_no_panic() {
    // Inputs ≥ MLS_MESSAGE_MIN_BYTES (8) проходят bounds-check; должны returns Codec либо
    // ParserPanic — НЕ raw panic propagation.
    // Inputs ≥ MLS_MESSAGE_MIN_BYTES (8) pass the bounds-check; must return Codec or
    // ParserPanic — NOT raw panic propagation.
    for size in [8usize, 16, 32, 64, 128, 256, 512] {
        for fill in [0x00u8, 0xC0, 0xFF] {
            let input = vec![fill; size];
            let result = parse_mls_message_safe(&input);
            assert!(
                result.is_err(),
                "{size}-byte {fill:#x}-fill input должен returns Err, got Ok"
            );
            assert!(
                matches!(
                    result,
                    Err(MlsError::Codec { .. }) | Err(MlsError::ParserPanic { .. })
                ),
                "{size}-byte {fill:#x}-fill input — expected Codec либо ParserPanic, got {result:?}"
            );
        }
    }
}

#[test]
fn f_37_key_package_above_min_invalid_input_no_panic() {
    // Inputs ≥ KEY_PACKAGE_MIN_BYTES (64) проходят bounds-check; должны returns Err без panic.
    // Inputs ≥ KEY_PACKAGE_MIN_BYTES (64) pass the bounds-check; must return Err without panic.
    for size in [64usize, 128, 256, 512, 1024] {
        for fill in [0x00u8, 0xC0, 0xFF] {
            let input = vec![fill; size];
            let result = parse_key_package_safe(&input);
            assert!(
                result.is_err(),
                "{size}-byte {fill:#x}-fill input должен returns Err, got Ok"
            );
            assert!(
                matches!(
                    result,
                    Err(MlsError::Codec { .. })
                        | Err(MlsError::KeyPackage { .. })
                        | Err(MlsError::ParserPanic { .. })
                ),
                "{size}-byte {fill:#x}-fill input — expected Codec/KeyPackage/ParserPanic, got {result:?}"
            );
        }
    }
}

#[test]
fn f_37_min_bytes_constants_have_expected_values() {
    // Sanity check для constants — должны быть 8 и 64 (chosen для conservative bounds-check
    // coverage minimal F-37 attack vector + similar truncation patterns).
    // Sanity check for the constants — must be 8 and 64 (chosen for conservative bounds-check
    // coverage of the minimal F-37 attack vector + similar truncation patterns).
    assert_eq!(MLS_MESSAGE_MIN_BYTES, 8);
    assert_eq!(KEY_PACKAGE_MIN_BYTES, 64);
}

#[test]
fn f_37_padded_minimal_input_above_min_no_panic() {
    // F-37 attack pattern с padding до `MLS_MESSAGE_MIN_BYTES` (8 байт) либо
    // `KEY_PACKAGE_MIN_BYTES` (64 байт) — bounds-check passes, catch_unwind должен catch
    // any panic если tls_codec ещё triggers regression на этом pattern.
    // F-37 attack pattern padded to MLS_MESSAGE_MIN_BYTES (8 bytes) or
    // KEY_PACKAGE_MIN_BYTES (64 bytes) — the bounds-check passes; catch_unwind must catch any
    // panic if tls_codec still triggers a regression on this pattern.
    let mut padded_msg = vec![0u8; MLS_MESSAGE_MIN_BYTES + 4];
    padded_msg[0..5].copy_from_slice(F_37_MINIMAL_INPUT);
    let result = parse_mls_message_safe(&padded_msg);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MlsError::Codec { .. }) | Err(MlsError::ParserPanic { .. })
    ));

    let mut padded_kp = vec![0u8; KEY_PACKAGE_MIN_BYTES + 4];
    padded_kp[0..5].copy_from_slice(F_37_MINIMAL_INPUT);
    let result = parse_key_package_safe(&padded_kp);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(MlsError::Codec { .. })
            | Err(MlsError::KeyPackage { .. })
            | Err(MlsError::ParserPanic { .. })
    ));
}
