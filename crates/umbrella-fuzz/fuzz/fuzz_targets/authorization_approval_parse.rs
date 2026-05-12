#![no_main]
//! libFuzzer target: `DeviceAuthorizationApproval::from_bytes` (ADR-008 §A.5.1)
//! должен отрабатывать любые байты без panic.
//! libFuzzer target: `DeviceAuthorizationApproval::from_bytes` (ADR-008 §A.5.1)
//! must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run authorization_approval_parse`
//! (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run authorization_approval_parse`
//! (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_authorization_approval_parse(data);
});
