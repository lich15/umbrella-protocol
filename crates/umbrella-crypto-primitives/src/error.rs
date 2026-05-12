//! Ошибки крипто-операций; завёрнуты так чтобы не утекать секреты в Display.
//! Crypto operation errors; wrapped to avoid leaking secrets in Display.

use thiserror::Error;

/// Result alias для крейта; по умолчанию `CryptoError`.
/// Result alias for the crate; defaults to `CryptoError`.
pub type Result<T, E = CryptoError> = core::result::Result<T, E>;

/// Ошибки крипто-операций; ни одна вариация не содержит секретов в сообщении.
/// Crypto operation errors; no variant carries secrets in its message.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Подпись невалидна.
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Аутентификационный тег AEAD не совпал — ciphertext испорчен или подменён.
    /// AEAD authentication tag mismatch — ciphertext was tampered with.
    #[error("AEAD authentication failure")]
    AeadAuthFailure,

    /// Длина входа не соответствует ожидаемой константе крипто-алгоритма.
    /// Input length does not match the expected crypto-algorithm constant.
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidLength {
        /// Ожидаемая длина в байтах. Expected length in bytes.
        expected: usize,
        /// Полученная длина в байтах. Actual length in bytes.
        got: usize,
    },

    /// Ключ не прошёл валидацию (например, недопустимый низкого порядка X25519 ключ).
    /// Key failed validation (e.g., disallowed low-order X25519 key).
    #[error("invalid key")]
    InvalidKey,

    /// Внутренний сбой бэкенда (например, ошибка RNG источника).
    /// Internal backend failure (e.g., RNG source error).
    #[error("internal backend error")]
    BackendFailure,
}
