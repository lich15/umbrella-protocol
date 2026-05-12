//! Защищённые парсеры MLS wire-format с bounds-check + `std::panic::catch_unwind`.
//! Safe MLS wire-format parsers with bounds-check + `std::panic::catch_unwind`.
//!
//! ## F-37 защита (block 10.8 inline-fix)
//!
//! Транзитивная зависимость `tls_codec-0.4.2` (через `openmls 0.8`) содержит assertion
//! `len_len_log <= MAX_LEN_LEN_LOG` в `tls_codec/src/quic_vec.rs:53`. Adversary способный
//! доставить 5-байтовый malformed input `[0,0,0,1,192]` к `MlsMessageIn::tls_deserialize_exact`
//! либо `KeyPackageIn::tls_deserialize` вызывает panic вместо `Err(tls_codec::Error)`. Crate-level
//! recovery невозможен — panic propagates через openmls → umbrella-mls → umbrella-client = remote
//! process termination (DoS).
//!
//! Этот модуль предоставляет безопасные обёртки:
//!
//! 1. **Bounds-check** — pre-parse rejection обвиозно truncated input (< minimal RFC 9420 §6 §10.1
//!    framing). Cheap O(1) проверка против известного 5-байтового F-37 attack vector + любого
//!    similar-class truncation.
//! 2. **`std::panic::catch_unwind`** — defensive layer. Если panic всё-таки возникает (другой
//!    pattern, не покрытый bounds-check), он catch'ится и преобразуется в explicit
//!    [`MlsError::ParserPanic`]. Это не silent fallback (постулат 14): caller получает `Err` с
//!    diagnostic category и может log/escalate. `AssertUnwindSafe` применён осознанно — closures
//!    не share mutable state с outer scope.
//! 3. **Explicit `Err` mapping** — `Err(tls_codec::Error)` → [`MlsError::Codec`] с category;
//!    panic → [`MlsError::ParserPanic`] с category. Caller различает behaviorally-recoverable
//!    error от parser-bug-class panic для observability + defensive depth.
//!
//! ## F-37 protection (block 10.8 inline-fix)
//!
//! The transitive dependency `tls_codec-0.4.2` (via `openmls 0.8`) carries the assertion
//! `len_len_log <= MAX_LEN_LEN_LOG` at `tls_codec/src/quic_vec.rs:53`. An adversary able to
//! deliver a 5-byte malformed input `[0,0,0,1,192]` to `MlsMessageIn::tls_deserialize_exact` or
//! `KeyPackageIn::tls_deserialize` triggers a panic instead of `Err(tls_codec::Error)`. Crate-level
//! recovery is impossible — the panic propagates through openmls → umbrella-mls → umbrella-client
//! = remote process termination (DoS).
//!
//! This module provides safe wrappers:
//!
//! 1. **Bounds-check** — pre-parse rejection of obviously truncated input (< the minimal
//!    RFC 9420 §6 §10.1 framing). Cheap O(1) check against the known 5-byte F-37 attack vector
//!    and any similar-class truncation.
//! 2. **`std::panic::catch_unwind`** — defensive layer. If a panic still arises (a different
//!    pattern not covered by the bounds check), it is caught and converted to an explicit
//!    [`MlsError::ParserPanic`]. This is not a silent fallback (postulate 14): the caller gets
//!    an `Err` with a diagnostic category and can log/escalate. `AssertUnwindSafe` is applied
//!    deliberately — the closures do not share mutable state with the outer scope.
//! 3. **Explicit `Err` mapping** — `Err(tls_codec::Error)` → [`MlsError::Codec`] with a category;
//!    panic → [`MlsError::ParserPanic`] with a category. The caller distinguishes a
//!    behaviorally recoverable error from a parser-bug-class panic for observability + defence
//!    in depth.

use std::panic::AssertUnwindSafe;

use openmls::framing::MlsMessageIn;
use openmls::key_packages::KeyPackageIn;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;

use crate::error::{MlsError, Result};

/// Минимальный размер TLS-кодированного MLS Message per RFC 9420 §6 framing
/// (protocol_version u16 + wire_format u16 + minimal body framing).
/// Lower-bound для bounds-check pre-parse; обвиозно truncated input
/// отвергается до передачи `tls_codec` parser. F-37 attack vector — 5 байт `[0,0,0,1,192]` —
/// блокируется этой проверкой.
///
/// Minimum size of a TLS-encoded MLS Message per RFC 9420 §6 framing
/// (protocol_version u16 + wire_format u16 + minimal body framing).
/// Lower bound for bounds-check pre-parse; obviously truncated input is rejected before
/// reaching the `tls_codec` parser. The F-37 attack vector — 5 bytes `[0,0,0,1,192]` — is
/// blocked by this check.
pub const MLS_MESSAGE_MIN_BYTES: usize = 8;

/// Минимальный размер TLS-кодированного KeyPackage per RFC 9420 §10.1 (`init_key 32` +
/// `leaf_node` non-trivial + `signature 64` + extensions + length prefixes). Conservative
/// нижняя граница 64 байта — реальный canonical KeyPackage значительно больше (~300+ байт).
/// Защита от F-37 attack vector через `KeyPackageIn::tls_deserialize` (fuzz target reproduces).
///
/// Minimum size of a TLS-encoded KeyPackage per RFC 9420 §10.1 (`init_key 32` + a non-trivial
/// `leaf_node` + `signature 64` + extensions + length prefixes). A conservative lower bound of
/// 64 bytes — the real canonical KeyPackage is significantly larger (~300+ bytes). Defence
/// against the F-37 attack vector via `KeyPackageIn::tls_deserialize` (the fuzz target
/// reproduces).
pub const KEY_PACKAGE_MIN_BYTES: usize = 64;

/// Безопасный парсер `MlsMessageIn` с bounds-check + `std::panic::catch_unwind`. Защита
/// от F-37 panic в `tls_codec-0.4.2` на malformed wire input.
///
/// Возвращает:
/// - `Ok(MlsMessageIn)` при успешном parse;
/// - `Err(MlsError::Codec { .. })` при normal `tls_codec` failure (truncated input,
///   bad framing, тд);
/// - `Err(MlsError::ParserPanic { .. })` при `tls_codec` panic (F-37-class regression
///   в backend parser).
///
/// Caller должен treat обе ветви Err как rejection без silent fallback (постулат 14).
///
/// Safe parser for `MlsMessageIn` with bounds-check + `std::panic::catch_unwind`. Defence
/// against F-37 panic in `tls_codec-0.4.2` on malformed wire input.
///
/// Returns:
/// - `Ok(MlsMessageIn)` on a successful parse;
/// - `Err(MlsError::Codec { .. })` on a normal `tls_codec` failure (truncated input, bad
///   framing, etc.);
/// - `Err(MlsError::ParserPanic { .. })` on a `tls_codec` panic (an F-37-class regression
///   in the backend parser).
///
/// The caller must treat both `Err` branches as rejection without a silent fallback
/// (postulate 14).
pub fn parse_mls_message_safe(bytes: &[u8]) -> Result<MlsMessageIn> {
    if bytes.len() < MLS_MESSAGE_MIN_BYTES {
        return Err(MlsError::Codec {
            kind: "input shorter than MLS_MESSAGE_MIN_BYTES (RFC 9420 §6 framing)",
        });
    }

    // catch_unwind — defensive layer для F-37-class panic. AssertUnwindSafe применён
    // осознанно: closure не share mutable state с outer scope (`bytes` — &[u8] read-only).
    // catch_unwind — defensive layer for F-37-class panics. AssertUnwindSafe is applied
    // deliberately: the closure does not share mutable state with the outer scope (`bytes`
    // is a read-only `&[u8]`).
    let panic_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        MlsMessageIn::tls_deserialize_exact(bytes)
    }));

    match panic_result {
        Ok(Ok(msg)) => Ok(msg),
        Ok(Err(_)) => Err(MlsError::Codec {
            kind: "MlsMessageIn::tls_deserialize_exact returned Err",
        }),
        Err(_) => Err(MlsError::ParserPanic {
            kind: "MlsMessageIn::tls_deserialize_exact panicked",
        }),
    }
}

/// Безопасный парсер `KeyPackageIn` с bounds-check + `std::panic::catch_unwind`. Защита
/// от F-37 panic в `tls_codec-0.4.2` на malformed wire input.
///
/// Безопасное API для downstream callers (umbrella-fuzz `fuzz_mls_keypackage_parser`,
/// umbrella-client KeyPackage validation paths). Возвращает аналогично [`parse_mls_message_safe`].
///
/// Safe parser for `KeyPackageIn` with bounds-check + `std::panic::catch_unwind`. Defence
/// against F-37 panic in `tls_codec-0.4.2` on malformed wire input.
///
/// Safe API for downstream callers (umbrella-fuzz's `fuzz_mls_keypackage_parser`, umbrella-client
/// KeyPackage validation paths). Returns analogously to [`parse_mls_message_safe`].
pub fn parse_key_package_safe(bytes: &[u8]) -> Result<KeyPackageIn> {
    if bytes.len() < KEY_PACKAGE_MIN_BYTES {
        return Err(MlsError::Codec {
            kind: "input shorter than KEY_PACKAGE_MIN_BYTES (RFC 9420 §10.1 framing)",
        });
    }

    let panic_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut cursor: &[u8] = bytes;
        KeyPackageIn::tls_deserialize(&mut cursor)
    }));

    match panic_result {
        Ok(Ok(kp)) => Ok(kp),
        Ok(Err(_)) => Err(MlsError::KeyPackage {
            kind: "KeyPackageIn::tls_deserialize returned Err",
        }),
        Err(_) => Err(MlsError::ParserPanic {
            kind: "KeyPackageIn::tls_deserialize panicked",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-37 minimum reproduction input — 5 bytes `[0,0,0,1,192]` triggers
    /// `tls_codec-0.4.2/src/quic_vec.rs:53` assertion `len_len_log <= MAX_LEN_LEN_LOG`.
    /// Verified в block 10.4b retrospective (Pattern Q baseline).
    ///
    /// F-37 minimum reproduction input — 5 bytes `[0,0,0,1,192]` trigger the
    /// `tls_codec-0.4.2/src/quic_vec.rs:53` assertion `len_len_log <= MAX_LEN_LEN_LOG`.
    /// Verified in the block 10.4b retrospective (Pattern Q baseline).
    const F_37_MINIMAL_INPUT: &[u8] = &[0, 0, 0, 1, 192];

    #[test]
    fn parse_mls_message_safe_rejects_f_37_input_without_panic() {
        let result = parse_mls_message_safe(F_37_MINIMAL_INPUT);
        assert!(result.is_err());
        match result {
            Err(MlsError::Codec { kind }) => {
                assert!(kind.contains("MLS_MESSAGE_MIN_BYTES"));
            }
            other => panic!("expected MlsError::Codec, got {other:?}"),
        }
    }

    #[test]
    fn parse_key_package_safe_rejects_f_37_input_without_panic() {
        let result = parse_key_package_safe(F_37_MINIMAL_INPUT);
        assert!(result.is_err());
        match result {
            Err(MlsError::Codec { kind }) => {
                assert!(kind.contains("KEY_PACKAGE_MIN_BYTES"));
            }
            other => panic!("expected MlsError::Codec, got {other:?}"),
        }
    }

    #[test]
    fn parse_mls_message_safe_rejects_empty_input() {
        let result = parse_mls_message_safe(&[]);
        assert!(matches!(result, Err(MlsError::Codec { .. })));
    }

    #[test]
    fn parse_key_package_safe_rejects_empty_input() {
        let result = parse_key_package_safe(&[]);
        assert!(matches!(result, Err(MlsError::Codec { .. })));
    }

    #[test]
    fn parse_mls_message_safe_rejects_above_min_but_invalid_input() {
        // 8 байт passes bounds-check, но не проходит tls_codec parsing — должен вернуть
        // Codec error либо ParserPanic (catch_unwind), не panic.
        // 8 bytes pass the bounds check but do not parse via tls_codec — must return either
        // a Codec error or ParserPanic (caught), not panic.
        let input = vec![0u8; 8];
        let result = parse_mls_message_safe(&input);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MlsError::Codec { .. }) | Err(MlsError::ParserPanic { .. })
        ));
    }

    #[test]
    fn parse_key_package_safe_rejects_above_min_but_invalid_input() {
        let input = vec![0u8; 64];
        let result = parse_key_package_safe(&input);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MlsError::Codec { .. })
                | Err(MlsError::KeyPackage { .. })
                | Err(MlsError::ParserPanic { .. })
        ));
    }

    #[test]
    fn min_bytes_constants_have_expected_values() {
        assert_eq!(MLS_MESSAGE_MIN_BYTES, 8);
        assert_eq!(KEY_PACKAGE_MIN_BYTES, 64);
    }
}
