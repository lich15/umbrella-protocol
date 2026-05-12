//! Унифицированные ошибки PQ примитивов.
//! Unified errors for PQ primitives.
//!
//! Каждый ошибочный случай — отдельный variant без silent fallback'ов.
//! Each error case is a distinct variant without silent fallbacks.

use thiserror::Error;

/// Type alias для удобства внутри крейта.
/// Type alias for convenience inside the crate.
pub type Result<T> = core::result::Result<T, PqError>;

/// Ошибки PQ примитивов: невалидный input, fail декапсуляции, fail верификации.
/// PQ primitive errors: invalid input, decapsulation failure, verification failure.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PqError {
    /// ML-KEM-768 decapsulation failed (corrupted ciphertext или fault injection).
    /// ML-KEM-768 decapsulation failed (corrupted ciphertext or fault injection).
    #[error("ML-KEM-768 decapsulation failed")]
    MlKemDecapsulationFailed,

    /// Невалидный размер public key для ML-KEM-768 (ожидается 1184 bytes).
    /// Invalid ML-KEM-768 public key length (expected 1184 bytes).
    #[error("invalid ML-KEM-768 public key length: got {got}, expected 1184")]
    MlKemInvalidPublicKey {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер ciphertext для ML-KEM-768 (ожидается 1088 bytes).
    /// Invalid ML-KEM-768 ciphertext length (expected 1088 bytes).
    #[error("invalid ML-KEM-768 ciphertext length: got {got}, expected 1088")]
    MlKemInvalidCiphertext {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер secret key для ML-KEM-768 (ожидается 2400 bytes).
    /// Invalid ML-KEM-768 secret key length (expected 2400 bytes).
    #[error("invalid ML-KEM-768 secret key length: got {got}, expected 2400")]
    MlKemInvalidSecretKey {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// X-Wing decapsulation failed.
    /// X-Wing decapsulation failed.
    #[error("X-Wing decapsulation failed")]
    XWingDecapsulationFailed,

    /// Невалидный размер X-Wing public key (ожидается 1216 bytes).
    /// Invalid X-Wing public key length (expected 1216 bytes).
    #[error("invalid X-Wing public key length: got {got}, expected 1216")]
    XWingInvalidPublicKey {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер X-Wing ciphertext (ожидается 1120 bytes).
    /// Invalid X-Wing ciphertext length (expected 1120 bytes).
    #[error("invalid X-Wing ciphertext length: got {got}, expected 1120")]
    XWingInvalidCiphertext {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер X-Wing secret seed (ожидается 32 bytes).
    /// Используется в `xwing_decaps_raw` где seed bytes приходят от внешнего слоя
    /// (HPKE provider от openmls передаёт sk_r как `&[u8]`).
    /// Invalid X-Wing secret seed length (expected 32 bytes).
    /// Used by `xwing_decaps_raw` where seed bytes arrive from an outer layer
    /// (HPKE provider for openmls passes sk_r as `&[u8]`).
    #[error("invalid X-Wing secret seed length: got {got}, expected 32")]
    XWingInvalidSecretSeed {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// ML-DSA-65 verification failed (signature не валидна для message+pubkey).
    /// ML-DSA-65 verification failed (signature not valid for message+pubkey).
    #[error("ML-DSA-65 signature verification failed")]
    MlDsaSignatureVerificationFailed,

    /// Невалидный размер ML-DSA-65 public key (ожидается 1952 bytes).
    /// Invalid ML-DSA-65 public key length (expected 1952 bytes).
    #[error("invalid ML-DSA-65 public key length: got {got}, expected 1952")]
    MlDsaInvalidPublicKey {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер ML-DSA-65 signature (ожидается 3309 bytes по FIPS 204).
    /// Invalid ML-DSA-65 signature length (expected 3309 bytes per FIPS 204).
    #[error("invalid ML-DSA-65 signature length: got {got}, expected 3309")]
    MlDsaInvalidSignature {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// SLH-DSA-128f verification failed.
    /// SLH-DSA-128f verification failed.
    #[error("SLH-DSA-128f signature verification failed")]
    SlhDsaSignatureVerificationFailed,

    /// Невалидный размер SLH-DSA-128f public key (ожидается 32 bytes).
    /// Invalid SLH-DSA-128f public key length (expected 32 bytes).
    #[error("invalid SLH-DSA-128f public key length: got {got}, expected 32")]
    SlhDsaInvalidPublicKey {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Невалидный размер SLH-DSA-128f signature (ожидается 17088 bytes).
    /// Invalid SLH-DSA-128f signature length (expected 17088 bytes).
    #[error("invalid SLH-DSA-128f signature length: got {got}, expected 17088")]
    SlhDsaInvalidSignature {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Hybrid signature verification failed: один или оба компонента не валидны.
    /// Hybrid signature verification failed: one or both components invalid.
    ///
    /// Поля `ed25519_ok` и `ml_dsa_ok` — для UX/diagnostic, чтобы клиент мог сообщить
    /// какой именно компонент сломался. AND-mode policy: сама ошибка возвращается
    /// если хотя бы один false.
    ///
    /// `ed25519_ok` and `ml_dsa_ok` fields — for UX/diagnostic so the client can
    /// report which component failed. AND-mode policy: the error is returned if at
    /// least one of them is false.
    #[error(
        "hybrid signature verification failed: ed25519_ok={ed25519_ok}, ml_dsa_ok={ml_dsa_ok}"
    )]
    HybridSignatureVerificationFailed {
        /// Прошёл ли Ed25519 компонент.
        /// Whether the Ed25519 component verified.
        ed25519_ok: bool,
        /// Прошёл ли ML-DSA-65 компонент.
        /// Whether the ML-DSA-65 component verified.
        ml_dsa_ok: bool,
    },

    /// Невалидный размер hybrid signature (ожидается 64 + 3309 = 3373 bytes).
    /// Invalid hybrid signature length (expected 64 + 3309 = 3373 bytes).
    #[error("invalid hybrid signature length: got {got}, expected 3373")]
    HybridInvalidSignature {
        /// Полученный размер в байтах.
        /// Received length in bytes.
        got: usize,
    },

    /// Внутренняя ошибка backend библиотеки (libcrux/fips205).
    /// Internal backend library error (libcrux/fips205).
    ///
    /// Возвращается когда backend сообщает ошибку которая не покрыта более
    /// конкретными вариантами выше. Содержит human-readable message для логов;
    /// не использовать для control flow.
    ///
    /// Returned when a backend reports an error not covered by more specific
    /// variants above. Carries a human-readable message for logs; do not use
    /// for control flow.
    #[error("internal backend error: {message}")]
    BackendError {
        /// Human-readable сообщение для логов.
        /// Human-readable message for logs.
        message: String,
    },
}
