//! Sealed Sender wire-format version stamps (Этап 8, блок 8.6).
//! Sealed Sender wire-format version stamps (Stage 8, block 8.6).
//!
//! ## Назначение
//!
//! `SealedSenderVersion` — дискриминатор первого байта wire-format envelope.
//! Введён в Этапе 8 (ADR-011 Решение 4 расширение) для co-existence existing
//! V1 envelope (X25519 ephemeral ECDH) и нового V2 envelope (X-Wing ephemeral
//! KEM) — обе версии сосуществуют для постепенной миграции на post-quantum.
//!
//! ## Wire format invariant
//!
//! Существующий V1 envelope (lib.rs `VERSION = 0x01`) **не меняется** — wire
//! invariant 0.0.11 сохранён. V2 envelope добавляет leading byte `0x02`
//! (`V2HybridXWing.as_u8()`); existing 0.0.11 V1 unseal отвергает любой
//! не-`0x01` первый байт через `SealedSenderError::UnsupportedVersion`
//! (existing behavior).
//!
//! ## Strict dispatch policy
//!
//! Постулат 14 — никакого silent fallback. Caller'ы (downstream code) делают
//! peek первого байта и явно выбирают `seal` / `unseal` (V1, classical
//! X25519) либо `seal_v2` / `unseal_v2` (V2, под `feature = "pq"`).
//!
//! Не предоставляем unified `unseal_any` потому что V1 и V2 unseal принимают
//! **разные** secret material (V1 — classical X25519 в `KeyStore`; V2 — X-Wing
//! secret seed, который пока не живёт в `KeyStore`; KeyStore extension под
//! cfg pq для X-Wing — отдельный block 8.8).
//!
//! ## Purpose
//!
//! `SealedSenderVersion` is the first-byte discriminator for the sealed-sender
//! envelope wire format. Introduced in Stage 8 (ADR-011 Decision 4 extension)
//! to allow the existing V1 envelope (X25519 ephemeral ECDH) and the new V2
//! envelope (X-Wing ephemeral KEM) to coexist for gradual post-quantum
//! migration.

use crate::SealedSenderError;

/// Дискриминатор версии wire-format Sealed Sender envelope.
/// Discriminator for the wire-format Sealed Sender envelope version.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedSenderVersion {
    /// V1 classical: X25519 ephemeral ECDH + ChaCha20-Poly1305 (existing 0.0.11
    /// wire-format в `lib.rs::seal` / `unseal`).
    /// V1 classical: X25519 ephemeral ECDH + ChaCha20-Poly1305 (existing 0.0.11
    /// wire format in `lib.rs::seal` / `unseal`).
    V1Classical = 0x01,

    /// V2 hybrid post-quantum: X-Wing ephemeral KEM (X25519 + ML-KEM-768
    /// combiner draft-10 KAT) + ChaCha20-Poly1305 (`hybrid_envelope.rs::seal_v2` /
    /// `unseal_v2` под `feature = "pq"`).
    ///
    /// V2 hybrid post-quantum: X-Wing ephemeral KEM (X25519 + ML-KEM-768
    /// combiner draft-10 KAT) + ChaCha20-Poly1305 (`hybrid_envelope.rs::seal_v2` /
    /// `unseal_v2` under `feature = "pq"`).
    V2HybridXWing = 0x02,
}

impl SealedSenderVersion {
    /// Возвращает byte-representation version stamp.
    /// Returns the byte representation of the version stamp.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for SealedSenderVersion {
    type Error = SealedSenderError;

    /// Strict version-stamp parsing. Любое значение кроме 0x01 / 0x02 →
    /// `SealedSenderError::UnsupportedVersion { got }` (постулат 14: никакого
    /// silent fallback).
    ///
    /// Strict version-stamp parsing. Any value other than 0x01 / 0x02 yields
    /// `SealedSenderError::UnsupportedVersion { got }` (postulate 14: no
    /// silent fallback).
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(Self::V1Classical),
            0x02 => Ok(Self::V2HybridXWing),
            _ => Err(SealedSenderError::UnsupportedVersion { got: b }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_v1_classical() {
        assert_eq!(
            SealedSenderVersion::try_from(0x01u8).unwrap(),
            SealedSenderVersion::V1Classical
        );
    }

    #[test]
    fn try_from_v2_hybrid() {
        assert_eq!(
            SealedSenderVersion::try_from(0x02u8).unwrap(),
            SealedSenderVersion::V2HybridXWing
        );
    }

    #[test]
    fn try_from_zero_rejected() {
        assert!(matches!(
            SealedSenderVersion::try_from(0x00u8),
            Err(SealedSenderError::UnsupportedVersion { got: 0x00 })
        ));
    }

    #[test]
    fn try_from_three_rejected() {
        assert!(matches!(
            SealedSenderVersion::try_from(0x03u8),
            Err(SealedSenderError::UnsupportedVersion { got: 0x03 })
        ));
    }

    #[test]
    fn try_from_high_byte_rejected() {
        assert!(matches!(
            SealedSenderVersion::try_from(0xFFu8),
            Err(SealedSenderError::UnsupportedVersion { got: 0xFF })
        ));
    }

    #[test]
    fn as_u8_roundtrip_v1() {
        let v = SealedSenderVersion::V1Classical;
        assert_eq!(v.as_u8(), 0x01);
        assert_eq!(SealedSenderVersion::try_from(v.as_u8()).unwrap(), v);
    }

    #[test]
    fn as_u8_roundtrip_v2() {
        let v = SealedSenderVersion::V2HybridXWing;
        assert_eq!(v.as_u8(), 0x02);
        assert_eq!(SealedSenderVersion::try_from(v.as_u8()).unwrap(), v);
    }

    #[test]
    fn try_from_exhaustive_rejection() {
        for b in 0u16..=255u16 {
            let b = b as u8;
            let result = SealedSenderVersion::try_from(b);
            match b {
                0x01 | 0x02 => assert!(result.is_ok()),
                _ => assert!(matches!(
                    result,
                    Err(SealedSenderError::UnsupportedVersion { got }) if got == b
                )),
            }
        }
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(
            SealedSenderVersion::V1Classical,
            SealedSenderVersion::V2HybridXWing
        );
    }
}
