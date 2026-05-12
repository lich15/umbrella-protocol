#![no_main]
//! libFuzzer target: `DevicePairingQr::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `DevicePairingQr::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run qr_payload_parse` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run qr_payload_parse` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_qr_payload_parse(data);
});
