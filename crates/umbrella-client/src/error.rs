//! Ошибки уровня клиента. Агрегируют sub-errors + network/storage/attestation.
//! На FFI границе (crate umbrella-ffi) транслируются в UmbrellaError с
//! `#[uniffi::Error(flat_error)]` (ADR-010 Решение 6).
//!
//! Client-level errors. Aggregate sub-errors plus network/storage/attestation.
//! Translated to `UmbrellaError` at the FFI boundary (umbrella-ffi crate) with
//! `#[uniffi::Error(flat_error)]` (ADR-010 Decision 6).

use thiserror::Error;

use crate::attestation::AttestationError;

/// Внутренняя ошибка клиента. Используется внутри `umbrella-client`; FFI-слой
/// `umbrella-ffi` конвертирует её в ABI-stable `UmbrellaError` в блоке 7.7.
///
/// Добавление нового варианта — breaking change **только** для внутреннего
/// кода; для Swift/Kotlin приложений — non-breaking (uniffi_flat_error).
///
/// Internal client error. Used within `umbrella-client`; the `umbrella-ffi`
/// layer converts it into the ABI-stable `UmbrellaError` in Block 7.7.
///
/// Adding a new variant is a breaking change **only** for internal code; for
/// Swift/Kotlin applications it is non-breaking (uniffi_flat_error).
#[derive(Debug, Error)]
pub enum ClientError {
    /// Sub-error из `umbrella-calls` (ICE/SRTP scaffolding, SFrame, DTLS fingerprint).
    /// Sub-error from `umbrella-calls`.
    #[error("call: {0}")]
    Call(#[from] umbrella_calls::CallError),

    /// Sub-error из `umbrella-backup` (cloud-wrap, device-transfer).
    /// Sub-error from `umbrella-backup`.
    #[error("backup: {0}")]
    Backup(#[from] umbrella_backup::BackupError),

    /// Sub-error из `umbrella-mls` (MLS RFC 9420 state machine).
    /// Sub-error from `umbrella-mls`.
    #[error("mls: {0}")]
    Mls(#[from] umbrella_mls::MlsError),

    /// Sub-error из `umbrella-kt` (Key Transparency epoch/proofs).
    /// Sub-error from `umbrella-kt`.
    #[error("kt: {0}")]
    Kt(#[from] umbrella_kt::KtError),

    /// Sub-error из `umbrella-oprf` (threshold OPRF для contact discovery).
    /// Sub-error from `umbrella-oprf`.
    #[error("oprf: {0}")]
    Oprf(#[from] umbrella_oprf::OprfError),

    /// Sub-error из `umbrella-sealed-sender` (HPKE envelope с anonymous credential).
    /// Sub-error from `umbrella-sealed-sender`.
    #[error("sealed-sender: {0}")]
    SealedSender(#[from] umbrella_sealed_sender::SealedSenderError),

    /// Sub-error из `umbrella-identity` (BIP-39 seed, identity/device key derive).
    /// Sub-error from `umbrella-identity`.
    #[error("identity: {0}")]
    Identity(#[from] umbrella_identity::IdentityError),

    /// Sub-error из `umbrella-padding` (length-hiding buckets).
    /// Sub-error from `umbrella-padding`.
    #[error("padding: {0}")]
    Padding(#[from] umbrella_padding::PaddingError),

    /// Сетевая ошибка (HTTP/2, TURN allocation, ICE binding). В блоке 7.4
    /// `Http2*Transport` map'ит `reqwest::Error` сюда.
    /// Network error (HTTP/2, TURN allocation, ICE binding).
    #[error("network: {0}")]
    Network(String),

    /// Ошибка локального хранилища — SQLite в блоке 7.3 (`rusqlite::Error`) или
    /// native Keychain/Keystore через FFI callback.
    /// Local storage error — SQLite (Block 7.3) or native Keychain/Keystore via FFI callback.
    #[error("storage: {0}")]
    Storage(String),

    /// Ошибка platform attestation — Apple App Attest или Google Play Integrity
    /// (обёрнутый `AttestationError`). Точный вариант (ServiceUnavailable,
    /// NonceRejected, AppNotEligible, …) сохраняется для UX-адаптации на
    /// клиенте. Появляется через async `AttestationProvider` callback.
    /// Platform attestation error — Apple App Attest or Google Play Integrity
    /// (wrapping `AttestationError`). Precise variant is preserved for UX
    /// adaptation on the client. Surfaced via async `AttestationProvider`
    /// callback.
    #[error("attestation: {0}")]
    Attestation(#[from] AttestationError),

    /// Платформо-специфичная ошибка: Keychain access denied, Secure Enclave
    /// unavailable (not a modern iPhone), StrongBox unavailable (old Android).
    /// Platform-specific error: Keychain access denied, Secure Enclave unavailable, etc.
    #[error("platform: {0}")]
    Platform(String),

    /// Операция отменена пользователем (user hang-up, close chat).
    /// User-initiated cancellation (hang-up, close chat).
    #[error("cancelled")]
    Cancelled,

    /// Режим-специфичное ограничение. Попытка вызвать Cloud-only метод на
    /// `SecretChat` — compile error (ADR-006 Вариант C), но если runtime
    /// invariant нарушен (например, mis-configured `ClientCore`) — этот
    /// вариант сигналит о нарушении.
    /// Mode-specific violation.
    #[error("mode violation: {0}")]
    ModeViolation(&'static str),

    /// Invariant violation — не должен случаться в корректном коде. Если
    /// возник — bug в крейте.
    /// Invariant violation — should never happen in correct code; a crate bug.
    #[error("internal: {0}")]
    Internal(String),

    /// Round-6 distributed identity: low-level cryptographic failure
    /// (Argon2id parameters invalid, HKDF expand failure, etc.). Used by
    /// `keystore::distributed_identity_client`.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Round-6: PIN verification rejected by ≥3 servers. UX must escalate
    /// to 24-word recovery prompt per spec §«Universal entry rule».
    #[error("wrong PIN")]
    WrongPin,

    /// Round-6: account permanently deleted (UNRECOVERABLE_DELETE; duress
    /// PIN, dead-man fire, 5 wrong emergency-12). Subsequent operations
    /// fail with this — same UX as never-registered.
    #[error("account permanently deleted")]
    AccountDeleted,
}

/// Результат операций клиента.
/// Client operation result alias.
pub type Result<T> = core::result::Result<T, ClientError>;
