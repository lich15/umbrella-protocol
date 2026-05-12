#![no_main]
//! libFuzzer target: OPRF Lagrange determinism property defence-in-depth
//! (Этап 11 блок 11.3).
//! libFuzzer target: OPRF Lagrange determinism property defence-in-depth
//! (Stage 11 block 11.3).
//!
//! Fuzz harness verifies «same input + different valid 3-of-5 subset →
//! bit-identical `OprfLabel`» поверх миллионов random (input, subset_a,
//! subset_b) combinations. Это complementary к 14 explicit regression-guard
//! tests из block 11.2 (`crates/umbrella-oprf/tests/test_lagrange_determinism.rs`)
//! — defence-in-depth поверх accepted-risk MEDIUM-B1 closure ADR-016.
//!
//! Подробное описание свойства, wire-format входа, и violation signal —
//! в docstring `umbrella_fuzz::fuzz_oprf_lagrange_determinism`.
//! Detailed property description, input wire-format, and violation signal —
//! see the docstring on `umbrella_fuzz::fuzz_oprf_lagrange_determinism`.
//!
//! Запуск: `cargo +nightly fuzz run oprf_lagrange_fuzz` (из
//! `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run oprf_lagrange_fuzz` (from
//! `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_oprf_lagrange_determinism(data);
});
