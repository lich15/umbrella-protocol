//! Публичные параметры threshold-wrap протокола и индексы Sealed Servers.
//! Public threshold-wrap protocol parameters and Sealed Server indices.
//!
//! Главный wrapping scalar `K` существует только в SEV-SNP enclave Sealed
//! Servers в виде Shamir-долей `k_i = f(i) (mod q)` (serverside ceremony в
//! Umbrella server implementation). Клиент крейта knowing только публичные точки: `Y = K·G`
//! (главный pubkey, используется в локальном wrap) и `Y_i = k_i·G` (per-server
//! pubkey, используется опционально для DLEQ proof-verify в Этапе 9).
//!
//! The master wrapping scalar `K` lives only inside SEV-SNP enclaves of
//! Sealed Servers as Shamir shares `k_i = f(i) mod q` (server ceremony in
//! Umbrella server implementation). This crate knows only the public points: `Y = K·G` (main
//! pubkey used in local wrap) and `Y_i = k_i·G` (per-server pubkey used
//! optionally for DLEQ proof-verify in Stage 9).

use crate::error::BackupError;

/// Версия wire-формата и параметров протокола. Protocol wire-format version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Длина compressed Ristretto255 точки в байтах.
/// Compressed Ristretto255 point length in bytes.
pub const POINT_LEN: usize = 32;

/// Длина canonical chat_id (UUID canonicalized to 32 bytes with domain prefix).
/// Canonical chat_id length (UUID canonicalized to 32 bytes with domain prefix).
pub const CHAT_ID_LEN: usize = 32;

/// Длина canonical nonce для ChaCha20-Poly1305 в байтах.
/// Canonical ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Длина AEAD tag (Poly1305). Poly1305 AEAD tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Длина message-key в байтах (AEAD-ключ одноразового сообщения).
/// Message-key length in bytes (one-time message AEAD key).
pub const MESSAGE_KEY_LEN: usize = 32;

/// Длина aead_blob = MESSAGE_KEY_LEN + AEAD_TAG_LEN.
/// AEAD blob length = MESSAGE_KEY_LEN + AEAD_TAG_LEN.
pub const AEAD_BLOB_LEN: usize = MESSAGE_KEY_LEN + AEAD_TAG_LEN;

/// Длина `WrappedKey` в байтах.
/// `WrappedKey` size in bytes.
pub const WRAPPED_KEY_LEN: usize = 1 + POINT_LEN + AEAD_BLOB_LEN;

/// Порог по умолчанию: 3 из 5 Sealed Servers.
/// Default threshold: 3 of 5 Sealed Servers.
pub const DEFAULT_THRESHOLD: u8 = 3;

/// Общее число серверов по умолчанию: 5 (географически распределённые).
/// Default total servers: 5 (geographically distributed).
pub const DEFAULT_TOTAL: u8 = 5;

/// Индекс Sealed Server'а в диапазоне 1..=DEFAULT_TOTAL.
///
/// Sealed Server index in range 1..=DEFAULT_TOTAL.
///
/// Zero и индексы больше `DEFAULT_TOTAL` отвергаются конструктором: Shamir
/// требует `x ≠ 0`, иначе share раскрывает `K` напрямую. Ограничение сверху
/// фиксирует протокол 5 серверов; расширение требует ADR + перестройка
/// серверной ceremony.
///
/// Zero and indices > `DEFAULT_TOTAL` are rejected by the constructor: Shamir
/// requires `x ≠ 0`, otherwise the share trivially leaks `K`. The upper bound
/// fixes the 5-server protocol; extending requires ADR + server ceremony
/// rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct WitnessIndex(u8);

impl WitnessIndex {
    /// Создать с жёсткой проверкой диапазона. Construct with range check.
    ///
    /// # Errors
    /// - [`BackupError::UnknownWitnessIndex`] если `i == 0` или `i > DEFAULT_TOTAL`.
    pub const fn new(i: u8) -> Result<Self, BackupError> {
        if i == 0 || i > DEFAULT_TOTAL {
            Err(BackupError::UnknownWitnessIndex(i))
        } else {
            Ok(Self(i))
        }
    }

    /// Числовое значение индекса. Numeric index value.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Параметры threshold-схемы. Threshold scheme parameters.
///
/// Инварианты (проверяются конструктором):
/// - `threshold >= 1`,
/// - `total >= threshold`,
/// - `total <= DEFAULT_TOTAL`.
///
/// Invariants (enforced by constructor):
/// - `threshold >= 1`,
/// - `total >= threshold`,
/// - `total <= DEFAULT_TOTAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdConfig {
    /// Сколько shares нужно для reconstruction. How many shares reconstruct.
    pub threshold: u8,
    /// Общее число участников схемы. Total number of participants.
    pub total: u8,
}

impl ThresholdConfig {
    /// Построить конфигурацию. Create configuration.
    ///
    /// # Errors
    /// - [`BackupError::InsufficientUnwrapShares`] если threshold=0 или total<threshold.
    /// - [`BackupError::UnknownWitnessIndex`] если total > DEFAULT_TOTAL.
    pub const fn new(threshold: u8, total: u8) -> Result<Self, BackupError> {
        if threshold == 0 {
            return Err(BackupError::InsufficientUnwrapShares {
                valid: 0,
                required: 0,
            });
        }
        if total < threshold {
            return Err(BackupError::InsufficientUnwrapShares {
                valid: total as usize,
                required: threshold as usize,
            });
        }
        if total > DEFAULT_TOTAL {
            return Err(BackupError::UnknownWitnessIndex(total));
        }
        Ok(Self { threshold, total })
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            total: DEFAULT_TOTAL,
        }
    }
}

/// Публичные параметры threshold-wrap протокола версии `-v1`.
///
/// Public threshold-wrap protocol parameters (version `-v1`).
///
/// Эти параметры публикуются из серверной ceremony через transparency log
/// (attestable notary signature), клиент подгружает их при старте и обновляет
/// при client release. `WrappingParams` — **immutable** в runtime: любая
/// ротация требует новой версии.
///
/// These parameters are published from server ceremony via transparency log
/// (attestable notary signature); the client loads them at startup and
/// updates on client release. `WrappingParams` is **immutable** at runtime;
/// any rotation requires a new version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappingParams {
    /// Версия параметров протокола (должна совпадать с `PROTOCOL_VERSION`).
    /// Protocol parameters version (must match `PROTOCOL_VERSION`).
    pub version: u8,
    /// Compressed Ristretto255 для `Y = K · G` — главный wrapping pubkey.
    /// Compressed Ristretto255 of `Y = K · G` — the main wrapping pubkey.
    pub main_pubkey: [u8; POINT_LEN],
    /// Compressed Ristretto255 для `Y_i = k_i · G` для каждого сервера i ∈ 1..=5.
    /// Compressed Ristretto255 of `Y_i = k_i · G` for each server i ∈ 1..=5.
    pub server_pubkeys: [[u8; POINT_LEN]; DEFAULT_TOTAL as usize],
    /// Пороговая конфигурация (обычно 3-of-5). Threshold config (usually 3-of-5).
    pub config: ThresholdConfig,
}

impl WrappingParams {
    /// Построить параметры с валидацией версии.
    /// Construct with version validation.
    ///
    /// # Errors
    /// - [`BackupError::WrappedKeyVersionMismatch`] если `version != PROTOCOL_VERSION`.
    pub fn new(
        version: u8,
        main_pubkey: [u8; POINT_LEN],
        server_pubkeys: [[u8; POINT_LEN]; DEFAULT_TOTAL as usize],
        config: ThresholdConfig,
    ) -> Result<Self, BackupError> {
        if version != PROTOCOL_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        Ok(Self {
            version,
            main_pubkey,
            server_pubkeys,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_index_rejects_zero() {
        let err = WitnessIndex::new(0).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(0)));
    }

    #[test]
    fn witness_index_rejects_six() {
        let err = WitnessIndex::new(6).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(6)));
    }

    #[test]
    fn witness_index_accepts_one_through_five() {
        for i in 1..=DEFAULT_TOTAL {
            assert_eq!(WitnessIndex::new(i).unwrap().get(), i);
        }
    }

    #[test]
    fn config_default_is_3_of_5() {
        let c = ThresholdConfig::default();
        assert_eq!(c.threshold, DEFAULT_THRESHOLD);
        assert_eq!(c.total, DEFAULT_TOTAL);
    }

    #[test]
    fn config_rejects_zero_threshold() {
        let err = ThresholdConfig::new(0, 5).unwrap_err();
        assert!(matches!(err, BackupError::InsufficientUnwrapShares { .. }));
    }

    #[test]
    fn config_rejects_total_less_than_threshold() {
        let err = ThresholdConfig::new(4, 3).unwrap_err();
        assert!(matches!(err, BackupError::InsufficientUnwrapShares { .. }));
    }

    #[test]
    fn config_rejects_total_over_five() {
        let err = ThresholdConfig::new(3, 6).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(6)));
    }

    #[test]
    fn wrapping_params_rejects_wrong_version() {
        let main = [0u8; POINT_LEN];
        let servers = [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize];
        let err = WrappingParams::new(0x02, main, servers, ThresholdConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x02
            }
        ));
    }

    #[test]
    fn wrapping_params_constants_layout() {
        // Защита от случайного изменения размеров: любая правка ломает wire.
        assert_eq!(POINT_LEN, 32);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(AEAD_TAG_LEN, 16);
        assert_eq!(MESSAGE_KEY_LEN, 32);
        assert_eq!(AEAD_BLOB_LEN, 48);
        assert_eq!(WRAPPED_KEY_LEN, 81);
        assert_eq!(DEFAULT_THRESHOLD, 3);
        assert_eq!(DEFAULT_TOTAL, 5);
        assert_eq!(PROTOCOL_VERSION, 0x01);
    }
}
