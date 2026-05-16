//! `ServerUnwrapShare` — wire-format одной partial unwrap-доли от Sealed Server.
//! `ServerUnwrapShare` — wire format of a single partial unwrap share.
//!
//! Каждый Sealed Server i, получив `SignedUnwrapRequest`, вычисляет
//! `partial_i = k_i · R` и возвращает эту структуру. Клиент собирает ≥ 3
//! валидных shares и делает Lagrange combine.
//!
//! After receiving `SignedUnwrapRequest`, each Sealed Server i computes
//! `partial_i = k_i · R` and returns this struct. The client gathers ≥ 3
//! valid shares and runs Lagrange combine.

use core::convert::TryInto;

use crate::error::BackupError;

use super::params::{WitnessIndex, POINT_LEN};

/// Длина `ServerUnwrapShare` в байтах.
/// `ServerUnwrapShare` length in bytes.
pub const SERVER_UNWRAP_SHARE_LEN: usize = 1 + POINT_LEN;

/// Одна partial unwrap-доля от Sealed Server'а.
/// One partial unwrap share from a Sealed Server.
///
/// Layout (33 bytes):
/// ```text
/// [0..1)   witness_index       : u8 (1..=5)
/// [1..33)  partial_compressed  : 32 bytes (compressed Ristretto255)
/// ```
///
/// Инвариант: `witness_index ∈ 1..=total`. Проверяется при построении из
/// bytes; при конструировании напрямую через struct literal ответственность
/// на caller'е (в тестах это ok, в production `from_bytes` всегда валидирует).
///
/// Invariant: `witness_index ∈ 1..=total`. Enforced on byte-parse; direct
/// struct-literal construction is caller's responsibility (tests use it).
#[derive(Clone, PartialEq, Eq)]
pub struct ServerUnwrapShare {
    /// Индекс Sealed Server'а, 1..=5. Sealed Server index, 1..=5.
    pub witness_index: WitnessIndex,
    /// Compressed Ristretto255 для `partial_i = k_i · R`.
    /// Compressed Ristretto255 of `partial_i = k_i · R`.
    pub partial: [u8; POINT_LEN],
}

/// `Debug` скрывает partial share: три такие доли из логов могут восстановить ключ.
/// `Debug` redacts the partial share: three leaked shares can reconstruct the key.
impl core::fmt::Debug for ServerUnwrapShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerUnwrapShare")
            .field("witness_index", &self.witness_index)
            .field("partial_len", &self.partial.len())
            .field("partial", &"<redacted>")
            .finish()
    }
}

impl ServerUnwrapShare {
    /// Сериализация в фиксированный 33-байтовый буфер.
    /// Serialization into a fixed 33-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SERVER_UNWRAP_SHARE_LEN] {
        let mut out = [0u8; SERVER_UNWRAP_SHARE_LEN];
        out[0] = self.witness_index.get();
        out[1..].copy_from_slice(&self.partial);
        out
    }

    /// Парсинг 33 байт с валидацией длины и witness index.
    /// Parse 33 bytes with length and witness-index validation.
    ///
    /// # Errors
    /// - [`BackupError::UnwrapShareTruncated`] если `data.len() != 33`.
    /// - [`BackupError::UnknownWitnessIndex`] если `data[0]` не в 1..=5.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        if data.len() != SERVER_UNWRAP_SHARE_LEN {
            return Err(BackupError::UnwrapShareTruncated);
        }
        let witness_index = WitnessIndex::new(data[0])?;
        let partial: [u8; POINT_LEN] = data[1..]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        Ok(Self {
            witness_index,
            partial,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_unwrap_share_roundtrip() {
        let share = ServerUnwrapShare {
            witness_index: WitnessIndex::new(3).unwrap(),
            partial: [0xAB; POINT_LEN],
        };
        let bytes = share.to_bytes();
        assert_eq!(bytes.len(), SERVER_UNWRAP_SHARE_LEN);
        let parsed = ServerUnwrapShare::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, share);
    }

    #[test]
    fn server_unwrap_share_layout() {
        let share = ServerUnwrapShare {
            witness_index: WitnessIndex::new(5).unwrap(),
            partial: {
                let mut p = [0u8; POINT_LEN];
                p[0] = 0x11;
                p[31] = 0x99;
                p
            },
        };
        let bytes = share.to_bytes();
        assert_eq!(bytes[0], 5);
        assert_eq!(bytes[1], 0x11);
        assert_eq!(bytes[32], 0x99);
    }

    #[test]
    fn server_unwrap_share_debug_redacts_partial_share() {
        let share = ServerUnwrapShare {
            witness_index: WitnessIndex::new(3).unwrap(),
            partial: [0xAB; POINT_LEN],
        };

        let debug = format!("{share:?}");

        assert!(
            !debug.contains("171, 171, 171, 171"),
            "Debug output must not leak partial unwrap share bytes: {debug}"
        );
        assert!(
            debug.contains("partial_len"),
            "Debug output should keep partial share length metadata: {debug}"
        );
    }

    #[test]
    fn server_unwrap_share_rejects_short() {
        let err = ServerUnwrapShare::from_bytes(&[0u8; SERVER_UNWRAP_SHARE_LEN - 1]).unwrap_err();
        assert!(matches!(err, BackupError::UnwrapShareTruncated));
    }

    #[test]
    fn server_unwrap_share_rejects_long() {
        let err = ServerUnwrapShare::from_bytes(&[0u8; SERVER_UNWRAP_SHARE_LEN + 1]).unwrap_err();
        assert!(matches!(err, BackupError::UnwrapShareTruncated));
    }

    #[test]
    fn server_unwrap_share_rejects_zero_witness() {
        let mut bytes = [0u8; SERVER_UNWRAP_SHARE_LEN];
        bytes[0] = 0; // invalid witness
        let err = ServerUnwrapShare::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(0)));
    }

    #[test]
    fn server_unwrap_share_rejects_witness_six() {
        let mut bytes = [0u8; SERVER_UNWRAP_SHARE_LEN];
        bytes[0] = 6; // invalid witness
        let err = ServerUnwrapShare::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(6)));
    }

    #[test]
    fn server_unwrap_share_accepts_all_valid_witness_indices() {
        for i in 1..=5u8 {
            let mut bytes = [0u8; SERVER_UNWRAP_SHARE_LEN];
            bytes[0] = i;
            let share = ServerUnwrapShare::from_bytes(&bytes).unwrap();
            assert_eq!(share.witness_index.get(), i);
        }
    }
}
