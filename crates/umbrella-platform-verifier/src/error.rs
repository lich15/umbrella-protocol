//! Ошибки платформенной проверки.
//! Platform verification errors.

use thiserror::Error;

/// Результат платформенной проверки.
/// Result alias for platform verification.
pub type Result<T> = core::result::Result<T, PlatformVerifierError>;

/// Точная причина отказа платформенного проверяющего.
/// Precise platform-verifier rejection reason.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlatformVerifierError {
    /// Токен пустой. Token is empty.
    #[error("platform token is empty")]
    EmptyToken,
    /// Токен слишком большой. Token is too large.
    #[error("platform token too large: {got} > {max}")]
    TokenTooLarge {
        /// Фактический размер. Actual size.
        got: usize,
        /// Максимум. Maximum.
        max: usize,
    },
    /// Платформа не совпала с проверяющим. Platform mismatch.
    #[error("platform mismatch")]
    PlatformMismatch,
    /// Не удалось разобрать токен. Token shape is invalid.
    #[error("invalid platform token shape")]
    InvalidTokenShape,
    /// Серверный вызов не совпал. Server nonce mismatch.
    #[error("server nonce mismatch")]
    ServerNonceMismatch,
    /// Приложение или сайт не совпали. App or site mismatch.
    #[error("app or site mismatch")]
    AppOrSiteMismatch,
    /// Ключ устройства не совпал. Device key mismatch.
    #[error("device key mismatch")]
    DeviceKeyMismatch,
    /// Подпись платформенного доказательства не прошла.
    /// Platform proof signature failed.
    #[error("platform proof signature failed")]
    SignatureFailed,
    /// Счётчик не вырос. Counter did not increase.
    #[error("platform counter did not increase")]
    CounterDidNotIncrease,
    /// Доказательство слишком старое. Proof is too old.
    #[error("platform proof expired")]
    ProofExpired,
    /// Настройки неполные. Configuration is incomplete.
    #[error("production platform verifier configuration is incomplete: {0}")]
    IncompleteConfiguration(&'static str),
    /// Нужен внешний корень доверия или ключ проверки.
    /// External trust material is required.
    #[error("external trust material is not wired: {0}")]
    ExternalTrustMaterialRequired(&'static str),
}
