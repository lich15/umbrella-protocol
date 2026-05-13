//! Host-крейт для cargo-fuzz таргетов (libFuzzer + OSS-Fuzz integration).
//! Host crate for cargo-fuzz targets (libFuzzer + OSS-Fuzz integration).
//!
//! Точки входа fuzz-таргетов живут здесь как обычные функции — это позволяет прогонять их в
//! unit-тестах (smoke-test: никогда не панируют) и в property-тестах (random input coverage),
//! а сами libFuzzer binary targets в `fuzz/fuzz_targets/*.rs` — минимальные обёртки.
//!
//! ## Feature flags
//!
//! - **default**: 16 classical fuzz targets (parse_mls_envelope, strip_padding, verify_inclusion,
//!   OPRF parsers, backup wrapping, QR pairing, Noise IK handshake, ADR-008 authorization,
//!   identity rotation, SFrame header/frame).
//! - **pq** (Этап 9, блок 9.6): добавляет 7 PQ wire-format harnesses
//!   (X-Wing pubkey/ciphertext, hybrid signature, KT v2 entry, sealed-sender V2 envelope,
//!   backup wrap V2, MLS KeyPackage). Тянет `umbrella-pq/full` + `umbrella-mls/pq` +
//!   `umbrella-sealed-sender/pq` + `openmls` + `tls_codec`.
//!
//! Fuzz target entry points live here as plain functions — this lets us exercise them from
//! unit tests (smoke: never panic) and property tests (random-input coverage), while the
//! libFuzzer binary targets in `fuzz/fuzz_targets/*.rs` remain minimal wrappers.
//!
//! ## Feature flags
//!
//! - **default**: 16 classical fuzz targets (parse_mls_envelope, strip_padding, verify_inclusion,
//!   OPRF parsers, backup wrapping, QR pairing, Noise IK handshake, ADR-008 authorization,
//!   identity rotation, SFrame header/frame).
//! - **pq** (Stage 9, block 9.6): adds 7 PQ wire-format harnesses
//!   (X-Wing pubkey/ciphertext, hybrid signature, KT v2 entry, sealed-sender V2 envelope,
//!   backup wrap V2, MLS KeyPackage). Pulls in `umbrella-pq/full` + `umbrella-mls/pq` +
//!   `umbrella-sealed-sender/pq` + `openmls` + `tls_codec`.

#![warn(missing_docs)]

pub mod targets;

pub use targets::{
    fuzz_aead_malleability, fuzz_authorization_approval_parse, fuzz_authorization_request_parse,
    fuzz_authorization_revocation_parse, fuzz_identity_rotation_parse, fuzz_noise_initiator_msg2,
    fuzz_noise_responder_msg1, fuzz_oprf_lagrange_determinism, fuzz_oprf_parse_blinded_request,
    fuzz_oprf_parse_server_evaluation, fuzz_oprf_threshold_combine, fuzz_parse_mls_envelope,
    fuzz_qr_payload_parse, fuzz_sframe_frame_parse, fuzz_sframe_header_parse, fuzz_strip_padding,
    fuzz_unwrap_share_parse, fuzz_verify_inclusion, fuzz_wrapped_key_parse,
};

// Этап 9, блок 9.6 — PQ wire-format fuzz harnesses (feature-gated).
// Stage 9, block 9.6 — PQ wire-format fuzz harnesses (feature-gated).
//
// Block 10.27 (Phase 3 cross-cutting dev crates audit) добавил
// `fuzz_ml_kem_decapsulate` — закрывает 1 GAP col 1 row 10 KyberSlash в
// threat × crate matrix block 10.22 (structural no-panic property для
// FIPS 203 implicit-rejection decaps; KyberSlash timing leak митигирован
// архитектурно через `libcrux_ml_kem 0.0.9` formally-verified backend).
//
// Block 10.27 (Phase 3 cross-cutting dev crates audit) added
// `fuzz_ml_kem_decapsulate` — closes the 1 GAP at col 1 row 10 KyberSlash
// in the block 10.22 threat × crate matrix (structural no-panic property
// for FIPS 203 implicit-rejection decaps; the KyberSlash timing leak is
// mitigated architecturally via the `libcrux_ml_kem 0.0.9` formally
// verified backend).
#[cfg(feature = "pq")]
pub use targets::{
    fuzz_hybrid_signature_parser, fuzz_kt_entry_v2_parser, fuzz_ml_kem_decapsulate,
    fuzz_mls_keypackage_parser, fuzz_sealed_sender_v2_parser, fuzz_wrapped_key_v2_parser,
    fuzz_xwing_ciphertext_parser, fuzz_xwing_pubkey_parser,
};
