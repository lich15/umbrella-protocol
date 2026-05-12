//! F-54 regression-guard (block 10.14): tls_codec parser panic protection в
//! `parse_mls_envelope`. F-54 — server-side propagation F-37 PRIMARY closure (block 10.8
//! umbrella-mls scope; mirrored сюда per ADR-001 architectural separation — server-blind-postman
//! не depends на umbrella-mls).
//!
//! F-54 regression guard (block 10.14): tls_codec parser-panic protection in
//! `parse_mls_envelope`. F-54 is the server-side propagation of the F-37 PRIMARY closure
//! (block 10.8 umbrella-mls scope; mirrored here per ADR-001 architectural separation —
//! server-blind-postman does not depend on umbrella-mls).
//!
//! Verifies:
//!
//! 1. **Bounds-check** (layer 1) — input < `MLS_MESSAGE_MIN_BYTES` отвергается до tls_codec
//!    через `EnvelopeError::Malformed` (cheap O(1)).
//! 2. **`std::panic::catch_unwind`** (layer 2) — любой panic в tls_codec catch'ится и
//!    преобразуется в explicit `EnvelopeError::ParserPanic { kind }` (постулат 14 «no
//!    silent fallback»).
//! 3. **Router::dispatch** не panic'ит на F-37 attack vector + не consumes anti-replay
//!    quota на rejected input (defence-in-depth invariant).
//!
//! Verifies:
//!
//! 1. **Bounds check** (layer 1) — input < `MLS_MESSAGE_MIN_BYTES` is rejected before
//!    tls_codec via `EnvelopeError::Malformed` (cheap O(1)).
//! 2. **`std::panic::catch_unwind`** (layer 2) — any panic in tls_codec is caught and
//!    converted to an explicit `EnvelopeError::ParserPanic { kind }` (postulate 14 «no
//!    silent fallback»).
//! 3. **Router::dispatch** does not panic on the F-37 attack vector and does not consume
//!    the anti-replay quota for rejected input (defence-in-depth invariant).

use umbrella_server_blind_postman::{
    parse_mls_envelope, AllowAll, EnvelopeError, ReplayGuard, Router, RoutingDecision,
    MLS_MESSAGE_MIN_BYTES,
};

/// F-37 минимальный вход воспроизведения panic — 5 байт `[0,0,0,1,192]` триггерят
/// `tls_codec-0.4.2/src/quic_vec.rs:53` assertion `len_len_log <= MAX_LEN_LEN_LOG`.
/// Verified в block 10.4b retrospective + block 10.8 closure (umbrella-mls scope) +
/// block 10.14 closure (umbrella-server-blind-postman scope).
///
/// F-37 minimum reproduction input — 5 bytes `[0,0,0,1,192]` trigger the
/// `tls_codec-0.4.2/src/quic_vec.rs:53` assertion `len_len_log <= MAX_LEN_LEN_LOG`.
/// Verified in the block 10.4b retrospective + block 10.8 closure (umbrella-mls scope) +
/// block 10.14 closure (umbrella-server-blind-postman scope).
const F_37_MINIMAL_INPUT: &[u8] = &[0, 0, 0, 1, 192];

#[test]
fn parse_envelope_rejects_f_37_minimum_panic_input_without_panic() {
    // Layer 1 bounds-check: input.len() == 5 < MLS_MESSAGE_MIN_BYTES = 8 → Malformed
    // без вызова tls_codec; F-37 attack vector blocked ДО panic site.
    // Layer 1 bounds check: input.len() == 5 < MLS_MESSAGE_MIN_BYTES = 8 → Malformed
    // without invoking tls_codec; the F-37 attack vector is blocked before the panic site.
    let result = parse_mls_envelope(F_37_MINIMAL_INPUT);
    assert_eq!(result.unwrap_err(), EnvelopeError::Malformed);
}

#[test]
fn parse_envelope_rejects_empty_input() {
    // 0 < MLS_MESSAGE_MIN_BYTES = 8 → Malformed.
    // 0 < MLS_MESSAGE_MIN_BYTES = 8 → Malformed.
    let result = parse_mls_envelope(&[]);
    assert_eq!(result.unwrap_err(), EnvelopeError::Malformed);
}

#[test]
fn parse_envelope_rejects_below_min_bytes() {
    // 7 байт — strictly < MIN_BYTES=8; bounds-check rejects.
    // 7 bytes — strictly less than MIN_BYTES=8; the bounds check rejects it.
    let bytes = [0u8; 7];
    let result = parse_mls_envelope(&bytes);
    assert_eq!(result.unwrap_err(), EnvelopeError::Malformed);
}

#[test]
fn parse_envelope_handles_above_min_invalid_input_without_panic() {
    // 8 байт passes bounds-check, передаётся в tls_codec → возвращает Malformed (normal Err)
    // либо ParserPanic (catch_unwind поймал panic) — но никогда не uncaught panic. Любой
    // 8-byte sequence для catch_unwind проверки безопасности.
    // 8 bytes pass the bounds check and are handed to tls_codec → returns Malformed (a
    // normal Err) or ParserPanic (catch_unwind caught a panic) — but never an uncaught
    // panic. Any 8-byte sequence is a catch_unwind safety check.
    for sample in [
        [0u8; 8],
        [0xFF; 8],
        [0x00, 0x01, 0x00, 0x02, 0xC0, 0xC0, 0xC0, 0xC0],
        [0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0],
    ] {
        let result = parse_mls_envelope(&sample);
        assert!(result.is_err(), "8-byte sample {sample:?} must return Err");
        assert!(
            matches!(
                result,
                Err(EnvelopeError::Malformed) | Err(EnvelopeError::ParserPanic { .. })
            ),
            "8-byte sample {sample:?} must surface через Malformed либо ParserPanic, got {result:?}"
        );
    }
}

#[test]
fn router_dispatch_rejects_f_37_input_returns_malformed() {
    // F-54 invariant: Router::dispatch не panic'ит на F-37 attack vector; bounds-check
    // layer 1 catches → RoutingDecision::RejectMalformed (layer 1 first).
    // F-54 invariant: Router::dispatch must not panic on the F-37 attack vector; the
    // layer-1 bounds check catches it → RoutingDecision::RejectMalformed (layer 1 fires
    // first).
    let mut r = Router::new(ReplayGuard::with_default_window(), AllowAll);
    let decision = r.dispatch(F_37_MINIMAL_INPUT, b"alice", 100);
    assert_eq!(decision, RoutingDecision::RejectMalformed);
}

#[test]
fn router_dispatch_does_not_consume_replay_quota_on_panic_class_input() {
    // F-54 defence-in-depth: malformed/parser-panic input не записывается в anti-replay
    // store (panic catch detected ДО replay check). Атакующий не может exhaust replay
    // memory через flood малформированных байт.
    // F-54 defence-in-depth: malformed / parser-panic input is not recorded in the
    // anti-replay store (the panic catch is detected before the replay check). An
    // attacker cannot exhaust replay memory via a flood of malformed bytes.
    let mut r = Router::new(ReplayGuard::with_default_window(), AllowAll);
    assert_eq!(r.replay_active_entries(), 0);
    for _ in 0..100 {
        let _ = r.dispatch(F_37_MINIMAL_INPUT, b"alice", 100);
    }
    assert_eq!(
        r.replay_active_entries(),
        0,
        "F-37/F-54 input must not consume replay quota even after 100 dispatch attempts"
    );
}

#[test]
fn mls_message_min_bytes_constant_value() {
    // Invariant: bounds-check threshold align с RFC 9420 §6 framing minimum (mirrors
    // umbrella-mls::parser::MLS_MESSAGE_MIN_BYTES).
    // Invariant: the bounds-check threshold aligns with the RFC 9420 §6 framing minimum
    // (mirrors umbrella-mls::parser::MLS_MESSAGE_MIN_BYTES).
    assert_eq!(MLS_MESSAGE_MIN_BYTES, 8);
}

#[test]
fn parser_panic_variant_carries_diagnostic_kind() {
    // Type-level check: EnvelopeError::ParserPanic exposes static-string `kind` для
    // observability + escalation per Постулат 14 «no silent fallback». ParserPanic должен
    // быть distinguishable от Malformed для caller observability/escalation.
    // Type-level check: EnvelopeError::ParserPanic exposes a static-string `kind` for
    // observability + escalation per Postulate 14 «no silent fallback». ParserPanic must
    // be distinguishable from Malformed for caller observability / escalation.
    let err = EnvelopeError::ParserPanic {
        kind: "MlsMessageIn::tls_deserialize_exact panicked",
    };
    match err {
        EnvelopeError::ParserPanic { kind } => {
            assert!(
                kind.contains("panicked"),
                "diagnostic kind must mention panic for observability"
            );
        }
        other => panic!("expected EnvelopeError::ParserPanic, got {other:?}"),
    }
}
