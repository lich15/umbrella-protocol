//! Ошибки identity слоя; не утекают секреты в Display.
//! Identity layer errors; no secrets leak in Display.

use thiserror::Error;

/// Result alias крейта.
/// Crate result alias.
pub type Result<T, E = IdentityError> = core::result::Result<T, E>;

/// Ошибки identity-операций (BIP-39, derive, multi-device).
/// Identity operation errors (BIP-39, derive, multi-device).
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Невалидное слово в мнемонической фразе либо неверная checksum.
    /// Invalid word in the mnemonic phrase or wrong checksum.
    #[error("invalid mnemonic")]
    InvalidMnemonic,

    /// Неверное количество слов в мнемонической фразе (ожидаем 24).
    /// Wrong word count in the mnemonic phrase (expected 24).
    #[error("invalid mnemonic word count: expected {expected}, got {got}")]
    InvalidWordCount {
        /// Ожидаемое количество слов. Expected word count.
        expected: usize,
        /// Полученное количество слов. Actual word count.
        got: usize,
    },

    /// Внутренняя ошибка крипто-бэкенда.
    /// Internal crypto backend error.
    #[error("crypto backend error: {0}")]
    Crypto(#[from] umbrella_crypto_primitives::CryptoError),

    /// Путь BIP-32 derivation некорректен (не-hardened индекс или превышение длины).
    /// BIP-32 derivation path is malformed (non-hardened index or length overflow).
    #[error("invalid derivation path: {reason}")]
    InvalidDerivationPath {
        /// Человекочитаемая причина. Human-readable reason.
        reason: &'static str,
    },

    /// Индекс ребёнка не имеет hardened bit (Ed25519 поддерживает только hardened derive).
    /// Child index lacks the hardened bit (Ed25519 supports hardened-only derive).
    #[error("non-hardened child index {index} for Ed25519 (must be >= 0x80000000)")]
    NonHardenedIndex {
        /// Полученный индекс. Provided index.
        index: u32,
    },

    /// Attestation expired относительно переданного wall-clock времени.
    /// Attestation expired relative to the supplied wall-clock time.
    #[error("device attestation expired at {expires_at}, current time {now}")]
    AttestationExpired {
        /// Время истечения. Expiration time.
        expires_at: u64,
        /// Текущее время. Current time.
        now: u64,
    },

    /// Attestation использует неподдерживаемую версию формата.
    /// Attestation uses an unsupported format version.
    #[error("unsupported attestation version {version}")]
    UnsupportedAttestationVersion {
        /// Полученная версия. Received version.
        version: u8,
    },

    /// Запрошенный device_index не зарегистрирован в keystore.
    /// Requested device_index is not registered in the keystore.
    #[error("device index {index} is not registered in this keystore")]
    UnknownDevice {
        /// Запрошенный индекс. Requested index.
        index: u32,
    },

    /// Попытка зарегистрировать device_index, который уже существует.
    /// Attempt to register a device_index that already exists.
    #[error("device index {index} already registered")]
    DuplicateDevice {
        /// Дублирующийся индекс. Duplicated index.
        index: u32,
    },

    /// Попытка использовать revoked device_index.
    /// Attempt to use a revoked device_index.
    #[error("device index {index} is revoked")]
    RevokedDevice {
        /// Revoked индекс. Revoked index.
        index: u32,
    },

    /// Неверное количество слов в коде восстановления (ожидаем 12).
    /// Wrong word count in the code-recovery mnemonic (expected 12).
    #[error("invalid code-recovery word count: expected {expected}, got {got}")]
    InvalidCodeRecoveryWordCount {
        /// Ожидаемое количество слов. Expected word count.
        expected: usize,
        /// Полученное количество слов. Actual word count.
        got: usize,
    },

    /// Невалидное слово в коде восстановления либо неверная checksum.
    /// Invalid word in the code-recovery mnemonic or wrong checksum.
    #[error("invalid code-recovery mnemonic")]
    InvalidCodeRecoveryMnemonic,

    /// Старый identity_pubkey не соответствует переданному seed — ротация не легитимна.
    /// Old identity_pubkey does not match the supplied seed — rotation is not legitimate.
    #[error("old identity_pubkey does not match derived identity from provided seed")]
    OldIdentityMismatch,

    /// Ошибка post-quantum слоя (ML-KEM, ML-DSA, SLH-DSA, hybrid signatures).
    /// Обёртка для прозрачной трансляции `umbrella_pq::PqError` через `?`.
    /// Активна только под feature `pq`.
    ///
    /// Post-quantum layer error (ML-KEM, ML-DSA, SLH-DSA, hybrid signatures).
    /// Wrapper to transparently translate `umbrella_pq::PqError` through `?`.
    /// Active only under feature `pq`.
    #[cfg(feature = "pq")]
    #[error("post-quantum primitive error: {0}")]
    Pq(#[from] umbrella_pq::PqError),
}
