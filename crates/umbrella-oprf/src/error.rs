//! Типы ошибок OPRF-слоя.
//! OPRF layer error types.

use thiserror::Error;

/// Ошибки операций OPRF-клиента.
/// Errors produced by OPRF client operations.
#[derive(Debug, Error)]
pub enum OprfError {
    /// Входной идентификатор пуст — OPRF требует ненулевого входа.
    /// Input identifier is empty — OPRF requires a non-empty input.
    #[error("OPRF input is empty")]
    EmptyInput,

    /// Длина входа превышает допустимый максимум 512 байт.
    /// Input length exceeds the allowed maximum of 512 bytes.
    #[error("OPRF input too large: {got} bytes (max {max})")]
    InputTooLarge {
        /// Фактическая длина. Actual length.
        got: usize,
        /// Максимум. Maximum.
        max: usize,
    },

    /// Байтовое представление BlindedRequest/ServerEvaluation неверной длины.
    /// Wire-format representation has wrong length.
    #[error("wrong wire length: expected {expected}, got {got}")]
    WrongWireLength {
        /// Ожидалось. Expected.
        expected: usize,
        /// Получено. Got.
        got: usize,
    },

    /// Байты не декодируются как валидная точка Ristretto255.
    /// Bytes do not decode as a valid Ristretto255 point.
    #[error("invalid Ristretto255 encoding")]
    InvalidRistrettoEncoding,

    /// Байты не декодируются как валидный скаляр Z_q.
    /// Bytes do not decode as a valid Z_q scalar.
    #[error("invalid scalar encoding")]
    InvalidScalarEncoding,

    /// Ошибка изнутри voprf при blind/finalize.
    /// Internal error from the voprf crate during blind/finalize.
    #[error("voprf internal error: {0}")]
    VoprfInternal(&'static str),

    /// Ошибка криптографической операции — обычно верификация proof не прошла.
    /// Cryptographic operation error — usually proof verification failure.
    #[error("cryptographic verification failed")]
    CryptoVerificationFailed,

    /// Не достигнут порог валидных evaluations при threshold combine.
    /// Threshold of valid evaluations not met during combine.
    #[error("insufficient valid evaluations: have {valid}, need {required}")]
    InsufficientValidEvaluations {
        /// Сколько валидных. How many valid.
        valid: usize,
        /// Сколько нужно. How many required.
        required: usize,
    },

    /// Индекс witness за пределами допустимого диапазона 1..=5.
    /// Witness index outside the allowed range 1..=5.
    #[error("unknown witness index: {0}")]
    UnknownWitnessIndex(u8),

    /// Повторный индекс witness в наборе evaluations.
    /// Duplicate witness index in the evaluation set.
    #[error("duplicate witness index: {0}")]
    DuplicateWitnessIndex(u8),

    /// Пустой батч или слишком большой.
    /// Empty or oversized batch.
    #[error("invalid batch size: {got} (allowed 1..={max})")]
    InvalidBatchSize {
        /// Размер батча. Batch size.
        got: usize,
        /// Максимум. Maximum.
        max: usize,
    },

    /// Ошибка подписи device-key при attestation-обёртке.
    /// Device-key signing error during attestation wrapping.
    #[error("device signing error: {0}")]
    DeviceSigning(&'static str),

    /// Attestation token не прошёл локальную валидацию формы.
    /// Attestation token failed local shape validation.
    #[error("invalid attestation token shape")]
    InvalidAttestationShape,
}
