//! Version stamp wrapping ciphersuite для cloud-wrap envelope (Этап 8 блок 8.7).
//! Wrapping ciphersuite version stamp for cloud-wrap envelope (Stage 8 block 8.7).
//!
//! ## Версии
//!
//! - **V1 (`0x01`)** — classical threshold-ElGamal на Ristretto255 (SPEC-12, Этап 1).
//!   Recovery key оборачивается через ElGamal `Y = K · G` с Shamir-распределённым
//!   `K`; AEAD ChaCha20-Poly1305 с deterministic nonce. 81-byte WrappedKey.
//!   Server-side ceremony: 5 Sealed Servers держат scalar shares `k_i = f(i)`.
//!
//! - **V2 (`0x02`, cfg pq)** — Hybrid wrapping layer: X-Wing envelope **над**
//!   V1 WrappedKey. V1 layer полностью сохранён внутри V2 envelope; outer
//!   X-Wing layer добавляет post-quantum confidentiality recovery key. Server
//!   ceremony **не меняется** — Sealed Servers продолжают держать те же scalar
//!   shares. 1218-byte wire format. См. design.md §10.
//!
//! ## Caller-side dispatch pattern
//!
//! ```text
//! match WrappingCiphersuite::try_from(wire[0])? {
//!     WrappingCiphersuite::V1Classical => {
//!         // existing V1 path: WrappedKey::from_bytes + 3-of-5 unwrap
//!     }
//!     #[cfg(feature = "pq")]
//!     WrappingCiphersuite::V2HybridXWing => {
//!         // V2 path: WrappedKeyV2::from_bytes + decapsulate + V1 inner unwrap
//!     }
//! }
//! ```
//!
//! Никакого unified `unwrap_any` API не вводится — V1 и V2 принимают разные
//! secret material (V1 — sealed-server partials; V2 — client recovery X-Wing
//! seed). Type-safe dispatch на caller-уровне (постулат 14: explicit > implicit).
//!
//! ## Domain separation V1 vs V2
//!
//! V1 HKDF использует salt = `chat_id` + info-prefix `"umbrellax-cloud-wrap-v1"`.
//! V2 HKDF использует salt = `"umbrellax-cloud-wrap-v2"` + info = domain_sep
//! || xwing_ct || xwing_pubkey. Cross-protocol replay невозможен — даже при
//! identical (chat_id, msg_seq) AEAD keys для V1 и V2 byte-distinct.

use crate::error::BackupError;

/// Wrapping ciphersuite version stamp.
/// Маркер версии wrap-ciphersuite.
///
/// Wrapping ciphersuite version stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WrappingCiphersuite {
    /// V1 — classical threshold-ElGamal на Ristretto255 (SPEC-12, Этап 1).
    /// V1 — classical threshold-ElGamal on Ristretto255 (SPEC-12, Stage 1).
    V1Classical = 0x01,

    /// V2 — Hybrid wrapping layer: X-Wing envelope над V1 WrappedKey
    /// (cfg pq, Этап 8 блок 8.7).
    ///
    /// V2 — Hybrid wrapping layer: X-Wing envelope over V1 WrappedKey
    /// (cfg pq, Stage 8 block 8.7).
    #[cfg(feature = "pq")]
    V2HybridXWing = 0x02,
}

impl WrappingCiphersuite {
    /// Численное значение версии (1 byte stamp в wire-format).
    /// Numeric version value (1-byte stamp in wire format).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for WrappingCiphersuite {
    type Error = BackupError;

    /// Парсит wire byte в `WrappingCiphersuite`.
    ///
    /// # Errors
    /// - `BackupError::PqFeatureRequiredForCiphersuite { version: 0x02 }` —
    ///   wire byte 0x02 (V2) при сборке `cfg(not(feature = "pq"))`.
    /// - `BackupError::UnsupportedWrappingCiphersuite { got }` — для всех
    ///   остальных значений (включая 0x00, и 0x03..=0xFF).
    ///
    /// Parses a wire byte into `WrappingCiphersuite`.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::V1Classical),
            #[cfg(feature = "pq")]
            0x02 => Ok(Self::V2HybridXWing),
            #[cfg(not(feature = "pq"))]
            0x02 => Err(BackupError::PqFeatureRequiredForCiphersuite { version: 0x02 }),
            other => Err(BackupError::UnsupportedWrappingCiphersuite { got: other }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// V1Classical имеет stamp 0x01.
    /// V1Classical has stamp 0x01.
    #[test]
    fn v1_classical_stamp_is_0x01() {
        assert_eq!(WrappingCiphersuite::V1Classical.as_u8(), 0x01);
    }

    /// V1 try_from accepts 0x01.
    /// V1 try_from accepts 0x01.
    #[test]
    fn try_from_0x01_yields_v1() {
        let cs = WrappingCiphersuite::try_from(0x01u8).unwrap();
        assert_eq!(cs, WrappingCiphersuite::V1Classical);
    }

    /// 0x00 отвергается.
    /// 0x00 is rejected.
    #[test]
    fn try_from_zero_rejected() {
        let err = WrappingCiphersuite::try_from(0x00u8).unwrap_err();
        assert!(matches!(
            err,
            BackupError::UnsupportedWrappingCiphersuite { got: 0x00 }
        ));
    }

    /// Unknown bytes (0x03..=0xFF) отвергаются с конкретной ошибкой.
    /// Unknown bytes (0x03..=0xFF) are rejected with a specific error.
    #[test]
    fn try_from_unknown_bytes_rejected_specifically() {
        for b in 0x03u8..=0xFF {
            let err = WrappingCiphersuite::try_from(b).unwrap_err();
            assert!(
                matches!(err, BackupError::UnsupportedWrappingCiphersuite { got } if got == b),
                "byte {b:#x} expected UnsupportedWrappingCiphersuite, got {err:?}"
            );
        }
    }

    /// Exhaustive 256-byte enumeration: ровно 1 byte (0x01) accepted в no-pq build.
    /// Exhaustive 256-byte enumeration: exactly 1 byte (0x01) accepted in no-pq build.
    #[cfg(not(feature = "pq"))]
    #[test]
    fn exhaustive_256_byte_no_pq_only_0x01_accepted() {
        let mut accepted = 0;
        for b in 0u8..=0xFF {
            if WrappingCiphersuite::try_from(b).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1, "no-pq build accepts exactly 1 byte (0x01)");
    }

    /// Exhaustive 256-byte enumeration: ровно 2 byte (0x01 + 0x02) accepted в pq build.
    /// Exhaustive 256-byte enumeration: exactly 2 bytes (0x01 + 0x02) accepted in pq build.
    #[cfg(feature = "pq")]
    #[test]
    fn exhaustive_256_byte_pq_only_0x01_and_0x02_accepted() {
        let mut accepted = 0;
        for b in 0u8..=0xFF {
            if WrappingCiphersuite::try_from(b).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 2,
            "pq build accepts exactly 2 bytes (0x01 + 0x02)"
        );
    }

    /// Без feature pq: 0x02 → специфическая ошибка `PqFeatureRequiredForCiphersuite`.
    /// Without feature pq: 0x02 → specific `PqFeatureRequiredForCiphersuite` error.
    #[cfg(not(feature = "pq"))]
    #[test]
    fn try_from_0x02_no_pq_gives_pq_required() {
        let err = WrappingCiphersuite::try_from(0x02u8).unwrap_err();
        assert!(matches!(
            err,
            BackupError::PqFeatureRequiredForCiphersuite { version: 0x02 }
        ));
    }

    /// С feature pq: V2HybridXWing имеет stamp 0x02.
    /// With feature pq: V2HybridXWing has stamp 0x02.
    #[cfg(feature = "pq")]
    #[test]
    fn v2_hybrid_xwing_stamp_is_0x02() {
        assert_eq!(WrappingCiphersuite::V2HybridXWing.as_u8(), 0x02);
    }

    /// С feature pq: try_from 0x02 → V2.
    /// With feature pq: try_from 0x02 → V2.
    #[cfg(feature = "pq")]
    #[test]
    fn try_from_0x02_pq_yields_v2() {
        let cs = WrappingCiphersuite::try_from(0x02u8).unwrap();
        assert_eq!(cs, WrappingCiphersuite::V2HybridXWing);
    }

    /// V1 и V2 stamps различны.
    /// V1 and V2 stamps differ.
    #[cfg(feature = "pq")]
    #[test]
    fn v1_v2_stamps_distinct() {
        assert_ne!(
            WrappingCiphersuite::V1Classical.as_u8(),
            WrappingCiphersuite::V2HybridXWing.as_u8()
        );
    }
}
