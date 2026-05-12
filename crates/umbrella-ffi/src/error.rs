//! `UmbrellaError` — ABI-stable single error enum на FFI границе (ADR-010
//! Решение 6). Все sub-errors из 10 крейтов конвертируются через
//! [`From<umbrella_client::ClientError>`] — flat string payload, чтобы
//! добавление новых вариантов в нижних крейтах было non-breaking для
//! Swift / Kotlin приложений (uniffi `flat_error`).
//!
//! Стратегия `flat_error` — Swift `enum UmbrellaException` / Kotlin
//! `sealed class UmbrellaException`: каждый вариант с `message: String`,
//! без вложенных typed payload'ов. UX-адаптация (показать диалог для
//! `AppNotEligible`, retry с backoff для `ServiceUnavailable`) делается
//! по строковому маркеру или через лог-парсинг — это допустимый trade-off
//! для ABI-стабильности.
//!
//! `UmbrellaError` — ABI-stable single error enum on the FFI boundary
//! (ADR-010 Decision 6). All sub-errors from the 10 internal crates convert
//! through [`From<umbrella_client::ClientError>`] — flat string payload, so
//! adding new variants in lower crates is non-breaking for Swift / Kotlin
//! apps (uniffi `flat_error`).
//!
//! `flat_error` strategy — Swift `enum UmbrellaException` / Kotlin
//! `sealed class UmbrellaException`: every variant carries a `message:
//! String`, no nested typed payloads. UX adaptation (open a dialog for
//! `AppNotEligible`, retry with backoff for `ServiceUnavailable`) keys off
//! the string marker or log parsing — an acceptable trade-off for ABI
//! stability.

use thiserror::Error;
use umbrella_client::ClientError;

/// ABI-stable error enum для FFI границы. 15 variants — соответствуют
/// [`umbrella_client::ClientError`] 1-к-1, но payload — `String` чтобы
/// flatness гарантировала ABI-стабильность для Swift/Kotlin биндингов.
///
/// ABI-stable error enum for the FFI boundary. 15 variants matching
/// [`umbrella_client::ClientError`] 1-to-1, with `String` payloads so that
/// flatness guarantees ABI stability across Swift / Kotlin bindings.
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UmbrellaError {
    /// Sub-error из `umbrella-calls` (DTLS fingerprint mismatch, SFrame failure).
    /// Sub-error from `umbrella-calls`.
    #[error("call: {0}")]
    Call(String),

    /// Sub-error из `umbrella-backup` (Cloud-wrap, device-transfer).
    /// Sub-error from `umbrella-backup`.
    #[error("backup: {0}")]
    Backup(String),

    /// Sub-error из `umbrella-mls` (MLS state machine).
    /// Sub-error from `umbrella-mls`.
    #[error("mls: {0}")]
    Mls(String),

    /// Sub-error из `umbrella-kt` (Key Transparency epoch / proofs).
    /// Sub-error from `umbrella-kt`.
    #[error("kt: {0}")]
    Kt(String),

    /// Sub-error из `umbrella-oprf` (threshold OPRF — contact discovery).
    /// Sub-error from `umbrella-oprf`.
    #[error("oprf: {0}")]
    Oprf(String),

    /// Sub-error из `umbrella-sealed-sender` (HPKE envelope с anonymous
    /// credential).
    /// Sub-error from `umbrella-sealed-sender`.
    #[error("sealed-sender: {0}")]
    SealedSender(String),

    /// Sub-error из `umbrella-identity` (BIP-39 seed, identity / device key).
    /// Sub-error from `umbrella-identity`.
    #[error("identity: {0}")]
    Identity(String),

    /// Sub-error из `umbrella-padding` (length-hiding buckets).
    /// Sub-error from `umbrella-padding`.
    #[error("padding: {0}")]
    Padding(String),

    /// Сетевая ошибка (HTTP/2, TURN, ICE binding).
    /// Network error.
    #[error("network: {0}")]
    Network(String),

    /// Локальное хранилище — SQLite или native Keychain/Keystore через FFI
    /// callback.
    /// Local storage — SQLite or native Keychain/Keystore.
    #[error("storage: {0}")]
    Storage(String),

    /// Platform attestation — App Attest / Play Integrity. Конкретный
    /// underlying-вариант (`AppNotEligible`, `ServiceUnavailable`, …)
    /// сериализуется в строку через `Display`.
    /// Platform attestation — App Attest / Play Integrity.
    #[error("attestation: {0}")]
    Attestation(String),

    /// Платформо-специфичная ошибка: Keychain access denied, Secure Enclave
    /// unavailable, StrongBox unavailable.
    /// Platform-specific error.
    #[error("platform: {0}")]
    Platform(String),

    /// Операция отменена пользователем (hang-up, close chat).
    /// User-initiated cancellation.
    #[error("cancelled")]
    Cancelled,

    /// Режим-специфичное ограничение. На FFI попадает только если runtime
    /// invariant нарушен (compile-fail proof в Rust скрыт от Swift/Kotlin).
    /// Mode-specific violation.
    #[error("mode violation: {0}")]
    ModeViolation(String),

    /// Invariant violation — bug в крейте.
    /// Invariant violation — a crate bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl From<ClientError> for UmbrellaError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Call(e) => UmbrellaError::Call(e.to_string()),
            ClientError::Backup(e) => UmbrellaError::Backup(e.to_string()),
            ClientError::Mls(e) => UmbrellaError::Mls(e.to_string()),
            ClientError::Kt(e) => UmbrellaError::Kt(e.to_string()),
            ClientError::Oprf(e) => UmbrellaError::Oprf(e.to_string()),
            ClientError::SealedSender(e) => UmbrellaError::SealedSender(e.to_string()),
            ClientError::Identity(e) => UmbrellaError::Identity(e.to_string()),
            ClientError::Padding(e) => UmbrellaError::Padding(e.to_string()),
            ClientError::Network(s) => UmbrellaError::Network(s),
            ClientError::Storage(s) => UmbrellaError::Storage(s),
            ClientError::Attestation(e) => UmbrellaError::Attestation(e.to_string()),
            ClientError::Platform(s) => UmbrellaError::Platform(s),
            ClientError::Cancelled => UmbrellaError::Cancelled,
            ClientError::ModeViolation(s) => UmbrellaError::ModeViolation(s.to_string()),
            ClientError::Internal(s) => UmbrellaError::Internal(s),
        }
    }
}
