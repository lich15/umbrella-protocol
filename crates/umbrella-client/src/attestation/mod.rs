//! Platform attestation: Apple App Attest (iOS) + Google Play Integrity (Android).
//!
//! Модуль определяет [`AttestationProvider`] — **асинхронный** callback-трейт,
//! через который `ClientCore` получает свежий platform attestation token.
//! Реальные реализации живут на native side (Swift / Kotlin), прокидываются
//! через FFI в блоках 7.8 / 7.9. В чистом Rust-коде доступен только
//! [`StaticTestAttestationProvider`] для unit- и integration-тестов.
//!
//! Типы [`Platform`] и [`PlatformAttestation`] — канонические из
//! `umbrella-backup::cloud_wrap::signed_request`. Их wire-format зафиксирован
//! ADR-005 / SPEC-05 / SPEC-12, и весь блок 7.4 (`Http2UnwrapTransport`,
//! `SignedUnwrapRequest::{to_bytes, from_bytes}`) уже завязан на них.
//!
//! Интеграция с cloud-unwrap потоком — [`seal_unwrap_request_with_async_attestation`]:
//! симметричное async-обёртывание `umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request`.
//! Избегает [`tokio::task::block_in_place`] (паника в single-threaded runtime —
//! постулат 14 запрещает panic в библиотеке).
//!
//! Platform attestation: Apple App Attest (iOS) + Google Play Integrity
//! (Android).
//!
//! Defines [`AttestationProvider`] — an **async** callback trait that
//! `ClientCore` uses to obtain a fresh platform attestation token. Real
//! implementations live on the native side (Swift / Kotlin) and are bridged
//! through FFI in Blocks 7.8 / 7.9. In pure-Rust code only
//! [`StaticTestAttestationProvider`] is available (for unit and integration
//! tests).
//!
//! [`Platform`] and [`PlatformAttestation`] are the canonical types from
//! `umbrella-backup::cloud_wrap::signed_request`. Their wire format is pinned
//! by ADR-005 / SPEC-05 / SPEC-12, and all of Block 7.4
//! (`Http2UnwrapTransport`, `SignedUnwrapRequest::{to_bytes, from_bytes}`) is
//! already built against them.
//!
//! Cloud-unwrap integration — [`seal_unwrap_request_with_async_attestation`]:
//! an async mirror of
//! `umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request`. It
//! avoids [`tokio::task::block_in_place`] (which panics in the single-threaded
//! runtime — Postulate 14 forbids panics in library code).

pub mod provider_trait;
pub mod unwrap_sealing;

pub use provider_trait::{
    AttestationError, AttestationProvider, Platform, PlatformAttestation,
    StaticTestAttestationProvider,
};
pub use unwrap_sealing::seal_unwrap_request_with_async_attestation;
