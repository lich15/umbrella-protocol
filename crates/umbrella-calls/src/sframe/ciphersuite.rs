//! SFrame ciphersuite — в Этапе 6 поддерживается строго одна AEAD-конфигурация
//! AES-256-GCM-SHA512-128 (RFC 9605 §5.2, ID `0x0005`). Выбор ciphersuite в
//! крейте фиксирован типом `SframeCiphersuite`; wire-парсер отвергает любые
//! другие значения с [`CallError::UnsupportedCiphersuite`].
//!
//! ADR-009 (Вариант B по AEAD) обосновывает почему ChaCha20-Poly1305 и
//! AES-128-GCM-SHA256-128 не подключены: 256-битный AES гарантирует маржу
//! для harvest-now-decrypt-later и NSA Suite B Top Secret, ARMv8-Crypto
//! покрывает ~99% целевых устройств, ChaCha20 к тому же удалён из финального
//! RFC 9605 2024. Если через несколько лет этот выбор потребует пересмотра
//! (старые Android без AES-HW станут значимым сегментом, либо найдётся
//! weakness в AES-GCM) — ввод новой ciphersuite делается через отдельный
//! ADR с feature-flag и grace-period, а не `TODO` в этом файле.
//!
//! SFrame ciphersuite — exactly one AEAD configuration is supported in
//! Stage 6: AES-256-GCM-SHA512-128 (RFC 9605 §5.2, ID `0x0005`). The choice
//! is fixed by the `SframeCiphersuite` type; the wire parser rejects any
//! other value with [`CallError::UnsupportedCiphersuite`].
//!
//! ADR-009 (AEAD option B) explains why ChaCha20-Poly1305 and
//! AES-128-GCM-SHA256-128 are not wired in: 256-bit AES gives margin for
//! harvest-now-decrypt-later and NSA Suite B Top Secret, ARMv8-Crypto
//! covers ~99% of target devices, and ChaCha20 was removed from the final
//! RFC 9605 2024. If in a few years this choice needs revisiting (old
//! Android without AES HW becomes a significant segment, or a weakness is
//! found in AES-GCM) — adding a new ciphersuite will go through a separate
//! ADR with a feature-flag and grace-period, not a `TODO` in this file.

use crate::error::{CallError, Result};

/// Длина base_key = Nh (RFC 9605 §5.2). Для AES-256-GCM-SHA512-128 это
/// выход SHA-512 = 64 байта. Используется как длина `exporter_secret`
/// запроса в MLS и как размер входа для HKDF-Expand per-KID.
///
/// Length of base_key = Nh (RFC 9605 §5.2). For AES-256-GCM-SHA512-128 this
/// is the SHA-512 output = 64 bytes. Used as the requested length of the
/// MLS `exporter_secret` and as the PRK length for HKDF-Expand per KID.
pub const BASE_KEY_LEN: usize = 64;

/// Длина sframe_key = Nk (RFC 9605 §5.2). Для AES-256-GCM это 32 байта
/// (256-бит ключ AES).
///
/// Length of sframe_key = Nk (RFC 9605 §5.2). For AES-256-GCM this is 32
/// bytes (256-bit AES key).
pub const SFRAME_KEY_LEN: usize = 32;

/// Длина sframe_salt = Nn (RFC 9605 §5.2). Для AES-256-GCM nonce равен
/// 12 байт (96 бит) — XOR'ится с padded counter в per-frame nonce.
///
/// Length of sframe_salt = Nn (RFC 9605 §5.2). For AES-256-GCM the nonce
/// is 12 bytes (96 bits) — XOR'd with the padded counter in the per-frame
/// nonce.
pub const SFRAME_SALT_LEN: usize = 12;

/// Длина AEAD tag = Nt (RFC 9605 §5.2). Для AES-256-GCM-SHA512-128 это
/// 16 байт (128-бит tag).
///
/// Length of AEAD tag = Nt (RFC 9605 §5.2). For AES-256-GCM-SHA512-128
/// this is 16 bytes (128-bit tag).
pub const AEAD_TAG_LEN: usize = 16;

/// Идентификатор SFrame ciphersuite (RFC 9605 §5.2). Пока поддерживается
/// ровно один вариант — `AES-256-GCM-SHA512-128` (`0x0005`).
///
/// SFrame ciphersuite identifier (RFC 9605 §5.2). Exactly one variant is
/// currently supported — `AES-256-GCM-SHA512-128` (`0x0005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SframeCiphersuite {
    /// AES-256-GCM с HKDF-SHA512, 128-битным tag (RFC 9605 §5.2 ID `0x0005`).
    /// AES-256-GCM with HKDF-SHA512, 128-bit tag (RFC 9605 §5.2 ID `0x0005`).
    Aes256GcmSha512 = 0x0005,
}

impl SframeCiphersuite {
    /// Декодирует идентификатор ciphersuite из u16 wire representation.
    /// Любое значение кроме `0x0005` отвергается с
    /// [`CallError::UnsupportedCiphersuite`] — downgrade-атаки на выбор
    /// ciphersuite невозможны в Этапе 6.
    ///
    /// Decodes a ciphersuite ID from the u16 wire representation. Any value
    /// other than `0x0005` is rejected with
    /// [`CallError::UnsupportedCiphersuite`] — ciphersuite-downgrade
    /// attacks are impossible in Stage 6.
    pub fn try_from_u16(value: u16) -> Result<Self> {
        match value {
            0x0005 => Ok(Self::Aes256GcmSha512),
            other => Err(CallError::UnsupportedCiphersuite(other)),
        }
    }

    /// Numeric ID по RFC 9605 §5.2. Используется при serialize wire-format.
    /// Numeric ID per RFC 9605 §5.2. Used when serializing the wire format.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Длина base_key (Nh). Length of base_key (Nh).
    pub fn base_key_len(self) -> usize {
        BASE_KEY_LEN
    }

    /// Длина sframe_key (Nk). Length of sframe_key (Nk).
    pub fn sframe_key_len(self) -> usize {
        SFRAME_KEY_LEN
    }

    /// Длина sframe_salt (Nn). Length of sframe_salt (Nn).
    pub fn sframe_salt_len(self) -> usize {
        SFRAME_SALT_LEN
    }

    /// Длина AEAD tag (Nt). Length of AEAD tag (Nt).
    pub fn aead_tag_len(self) -> usize {
        AEAD_TAG_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_u16_accepts_aes_256_gcm_sha512() {
        assert_eq!(
            SframeCiphersuite::try_from_u16(0x0005).unwrap(),
            SframeCiphersuite::Aes256GcmSha512
        );
    }

    #[test]
    fn try_from_u16_rejects_unknown_id() {
        let err = SframeCiphersuite::try_from_u16(0x0001).unwrap_err();
        assert!(matches!(err, CallError::UnsupportedCiphersuite(0x0001)));
    }

    #[test]
    fn try_from_u16_rejects_zero_and_max() {
        assert!(matches!(
            SframeCiphersuite::try_from_u16(0x0000),
            Err(CallError::UnsupportedCiphersuite(0x0000))
        ));
        assert!(matches!(
            SframeCiphersuite::try_from_u16(0xFFFF),
            Err(CallError::UnsupportedCiphersuite(0xFFFF))
        ));
    }

    #[test]
    fn aes_256_gcm_sha512_lengths_match_rfc_9605_section_5_2() {
        let cs = SframeCiphersuite::Aes256GcmSha512;
        assert_eq!(cs.base_key_len(), 64, "Nh = SHA-512 output");
        assert_eq!(cs.sframe_key_len(), 32, "Nk = AES-256 key");
        assert_eq!(cs.sframe_salt_len(), 12, "Nn = AES-GCM nonce");
        assert_eq!(cs.aead_tag_len(), 16, "Nt = 128-bit AES-GCM tag");
        assert_eq!(cs.as_u16(), 0x0005);
    }

    #[test]
    fn ciphersuite_is_copy_and_hashable() {
        // Для использования в HashMap<(SframeCiphersuite, u64), _> и копирования
        // в структуры типа `SframeBaseKey` без clone.
        //
        // Needed for use in HashMap<(SframeCiphersuite, u64), _> and for
        // copying into structures like `SframeBaseKey` without `clone`.
        let a = SframeCiphersuite::Aes256GcmSha512;
        let b = a;
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
