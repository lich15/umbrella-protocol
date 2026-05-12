//! Базовые типы ошибок; конкретные крейты добавляют свои error enums.
//! Base error types; concrete crates add their own error enums.

use thiserror::Error;

/// Общий Result alias для крейтов Umbrella.
/// Shared Result alias for Umbrella crates.
pub type Result<T, E = CoreError> = core::result::Result<T, E>;

/// Базовые ошибки уровня core; специфичные ошибки живут в соответствующих крейтах.
/// Core-level base errors; specific errors live in their respective crates.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Некорректная длина входных данных.
    /// Input data has an invalid length.
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidLength {
        /// Ожидаемая длина в байтах. Expected length in bytes.
        expected: usize,
        /// Полученная длина в байтах. Actual length in bytes.
        got: usize,
    },

    /// Данные не прошли валидацию формата.
    /// Data failed format validation.
    #[error("malformed data: {reason}")]
    Malformed {
        /// Человекочитаемая причина. Human-readable reason.
        reason: &'static str,
    },
}
