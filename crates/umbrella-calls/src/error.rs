//! Ошибки крейта звонков. Единый enum для всех модулей: wire-parse,
//! derive, AEAD, anti-replay, policy, DTLS binding и passthrough MLS.
//! Никаких generic string-вариантов — каждая причина имеет свой бранч,
//! чтобы adversarial-тесты могли matches'ить конкретный исход.
//!
//! Crate errors for calls. A single enum across all modules: wire parse,
//! derive, AEAD, anti-replay, policy, DTLS binding, and MLS passthrough.
//! No generic string variants — every cause has its own branch so that
//! adversarial tests can `matches!` on a specific outcome.

use thiserror::Error;

/// Все ошибки крейта `umbrella-calls`. Сообщения не содержат секретов и
/// предназначены для логов и ответов API; детальная семантика закодирована
/// в структуре вариантов (поля `sender`, `counter`, `frame_epoch`, …).
///
/// All errors of the `umbrella-calls` crate. Messages contain no secrets
/// and are intended for logs and API responses; detailed semantics are
/// encoded in the variant shape (fields `sender`, `counter`, `frame_epoch`,
/// …).
#[derive(Debug, Error)]
pub enum CallError {
    /// Версия wire-формата не совпала с ожидаемой (`reserved` bit `R` в
    /// CONFIG_BYTE установлен либо зарезервированное значение CS ID).
    ///
    /// Wire-format version mismatch (reserved bit `R` in CONFIG_BYTE set
    /// or reserved ciphersuite ID).
    #[error("wire version mismatch: expected {expected:#04x}, got {found:#04x}")]
    WireVersionMismatch {
        /// Ожидавшееся значение. Expected value.
        expected: u8,
        /// Прочитанное значение. Observed value.
        found: u8,
    },

    /// SFrame header не парсится: слишком короткий input, невалидный
    /// CONFIG_BYTE, обрезанные KID/CTR поля и т.п.
    ///
    /// SFrame header does not parse: too-short input, invalid CONFIG_BYTE,
    /// truncated KID/CTR fields, etc.
    #[error("invalid SFrame header: {0}")]
    InvalidHeader(&'static str),

    /// KID кадра отсутствует в `SframeContext` — нет производных ключей.
    /// Обычно означает что эпоха ещё не пришла или уже эвиктнута.
    ///
    /// Frame KID not found in the `SframeContext` — no derived keys. This
    /// usually means the epoch has not been advanced yet or has already
    /// been evicted from the cache.
    #[error("unknown KID {0:#x}: no matching derivation in context")]
    UnknownKid(u64),

    /// Кадр принадлежит эпохе, которая старше самой старой закешированной
    /// (вышла за пределы 3-эпохального окна `SframeContext`).
    ///
    /// The frame belongs to an epoch older than the oldest cached one
    /// (outside the 3-epoch window of `SframeContext`).
    #[error("stale epoch: frame epoch {frame_epoch}, oldest cached {oldest_cached}")]
    StaleEpoch {
        /// Эпоха кадра. Frame epoch.
        frame_epoch: u64,
        /// Самая старая эпоха в кеше. Oldest cached epoch.
        oldest_cached: u64,
    },

    /// AEAD-проверка не прошла: подмена ciphertext / tag / AAD либо
    /// неверный ключ/nonce.
    ///
    /// AEAD authentication failed: ciphertext / tag / AAD tampering or a
    /// wrong key/nonce.
    #[error("AEAD authentication failure")]
    AeadAuthFailure,

    /// Counter уже обработан (replay внутри окна 64).
    /// Counter already processed (replay within 64-frame window).
    #[error("replay detected: sender {sender}, counter {counter}")]
    Replay {
        /// Leaf-индекс отправителя. Sender leaf index.
        sender: u32,
        /// Номер кадра. Frame counter.
        counter: u64,
    },

    /// Counter старше replay-окна (≥ 64 кадров позади).
    /// Counter older than the replay window (≥ 64 frames behind).
    #[error(
        "counter out of replay window: sender {sender}, counter {counter}, window_start {window_start}"
    )]
    OutOfReplayWindow {
        /// Leaf-индекс отправителя. Sender leaf index.
        sender: u32,
        /// Номер кадра. Frame counter.
        counter: u64,
        /// Начало текущего окна (`highest_seen - 63`).
        /// Current window start (`highest_seen - 63`).
        window_start: u64,
    },

    /// Plaintext кадра превышает `MAX_FRAME_PLAINTEXT_LEN` = 1 MiB.
    /// Decrypt также отвергает слишком большие wire-пакеты до AEAD verify
    /// для защиты от DoS.
    ///
    /// Frame plaintext exceeds `MAX_FRAME_PLAINTEXT_LEN` = 1 MiB. Decrypt
    /// likewise rejects oversized wire packets before AEAD verification
    /// to mitigate DoS.
    #[error("frame plaintext too large: limit {limit}, actual {actual}")]
    FrameTooLarge {
        /// Допустимый максимум. Hard limit.
        limit: usize,
        /// Фактическая длина. Observed length.
        actual: usize,
    },

    /// MLS `exporter_secret` недоступен (группа evicted / openmls вернул
    /// ошибку). Каллер должен прекратить шифрование/расшифровку до
    /// восстановления группы.
    ///
    /// MLS `exporter_secret` unavailable (group evicted / openmls error).
    /// The caller must stop encrypting/decrypting until the group is
    /// restored.
    #[error("MLS exporter unavailable")]
    MlsExporterUnavailable,

    /// Ciphersuite ID в wire-пакете не поддерживается в этой версии крейта
    /// (в Этапе 6 поддерживается только `0x0005 = AES-256-GCM-SHA512-128`).
    ///
    /// The ciphersuite ID in the wire packet is not supported by this
    /// crate version (Stage 6 supports only
    /// `0x0005 = AES-256-GCM-SHA512-128`).
    #[error("unsupported SFrame ciphersuite: {0:#x}")]
    UnsupportedCiphersuite(u16),

    /// DTLS identity fingerprint не прошёл `constant-time`-проверку:
    /// подменённый pubkey, неверный nonce, либо tampered fingerprint.
    ///
    /// DTLS identity fingerprint failed the constant-time check: a
    /// substituted pubkey, a wrong nonce, or a tampered fingerprint.
    #[error("DTLS identity fingerprint verification failed")]
    IdentityBindingFailed,

    /// Проброс ошибок `umbrella-mls` (например из [`exporter_secret`] либо
    /// [`encrypt_application`]).
    ///
    /// Passthrough of `umbrella-mls` errors (for example from
    /// [`exporter_secret`] or [`encrypt_application`]).
    ///
    /// [`exporter_secret`]: umbrella_mls::UmbrellaGroup::exporter_secret
    /// [`encrypt_application`]: umbrella_mls::UmbrellaGroup::encrypt_application
    #[error(transparent)]
    Mls(#[from] umbrella_mls::MlsError),
}

/// Крейт-локальный `Result` alias. Все публичные функции `umbrella-calls`
/// возвращают именно его.
///
/// Crate-local `Result` alias. Every public function in `umbrella-calls`
/// returns this type.
pub type Result<T> = core::result::Result<T, CallError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_wire_version_mismatch_formats_hex() {
        let err = CallError::WireVersionMismatch {
            expected: 0x00,
            found: 0x80,
        };
        let s = format!("{err}");
        assert!(s.contains("0x00"));
        assert!(s.contains("0x80"));
    }

    #[test]
    fn display_invalid_header_carries_static_reason() {
        let err = CallError::InvalidHeader("reserved bit R set");
        assert_eq!(
            format!("{err}"),
            "invalid SFrame header: reserved bit R set"
        );
    }

    #[test]
    fn display_unknown_kid_formats_hex() {
        let err = CallError::UnknownKid(0x0001_0000_0005);
        assert!(format!("{err}").contains("0x100000005"));
    }

    #[test]
    fn display_replay_contains_sender_and_counter() {
        let err = CallError::Replay {
            sender: 3,
            counter: 42,
        };
        let s = format!("{err}");
        assert!(s.contains("sender 3"));
        assert!(s.contains("counter 42"));
    }

    #[test]
    fn display_out_of_replay_window_contains_all_fields() {
        let err = CallError::OutOfReplayWindow {
            sender: 1,
            counter: 5,
            window_start: 100,
        };
        let s = format!("{err}");
        assert!(s.contains("sender 1"));
        assert!(s.contains("counter 5"));
        assert!(s.contains("window_start 100"));
    }

    #[test]
    fn display_frame_too_large_contains_both_numbers() {
        let err = CallError::FrameTooLarge {
            limit: 1_048_576,
            actual: 2_000_000,
        };
        let s = format!("{err}");
        assert!(s.contains("1048576"));
        assert!(s.contains("2000000"));
    }

    #[test]
    fn display_unsupported_ciphersuite_hex_format() {
        let err = CallError::UnsupportedCiphersuite(0x1234);
        assert!(format!("{err}").contains("0x1234"));
    }

    #[test]
    fn from_mls_error_passthrough() {
        let src = umbrella_mls::MlsError::ExternalOperationForbidden;
        let err: CallError = src.into();
        assert!(matches!(err, CallError::Mls(_)));
    }
}
