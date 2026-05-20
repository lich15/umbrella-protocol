#![no_main]
//! libFuzzer target: `try_decode_v3` должен отрабатывать на любом attacker-controlled
//! входе без panic / unwrap failure / arithmetic overflow. Закрывает Task 3 carry-over
//! из max_ratchet v3 spec 2026-05-21 (coverage-guided extension proptest harness).
//!
//! libFuzzer target: `try_decode_v3` must handle any attacker-controlled input without
//! panicking. Closes Task 3 carry-over from the max_ratchet v3 spec 2026-05-21
//! (coverage-guided extension of the proptest harness — millions of iterations + persistent
//! corpus vs proptest's 1280 random inputs).
//!
//! Запуск: `cargo +nightly fuzz run max_ratchet_envelope_decode` (из каталога
//! `crates/umbrella-fuzz/fuzz/`).
//!
//! Run: `cargo +nightly fuzz run max_ratchet_envelope_decode` (from
//! `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

// Task 3 (2026-05-21): codec lives в umbrella-mls; функция exported из umbrella-fuzz
// под host-crate feature `pq` (active через fuzz/Cargo.toml `features = ["pq"]`).
fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_max_ratchet_envelope_decode(data);
});
