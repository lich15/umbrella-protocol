//! SFrame wire-format parse/serialize по RFC 9605 §4.
//!
//! Структура заголовка (RFC 9605 §4.1-4.3):
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |X|  K  |Y|  C  |   CONFIG_BYTE (1 байт)
//! +-+-+-+-+-+-+-+-+
//! |   KID bytes   |   0 или K+1 байт (big-endian) при X=1
//! +---------------+
//! |   CTR bytes   |   0 или C+1 байт (big-endian) при Y=1
//! +---------------+
//! |   ciphertext  |
//! +---------------+
//! | AEAD tag 16 B |
//! +---------------+
//! ```
//!
//! Биты `CONFIG_BYTE` (MSB ↔ LSB):
//!
//! - `X` (bit 0, MSB) — Extended KID flag.
//! - `K` (bits 1..3) — inline KID value (если `X=0`) либо KID length-minus-one
//!   (если `X=1`, после заголовка идёт `K+1` байт KID).
//! - `Y` (bit 4) — Extended CTR flag.
//! - `C` (bits 5..7, LSB) — inline CTR value (если `Y=0`) либо CTR length-minus-one
//!   (если `Y=1`, после KID идёт `C+1` байт CTR).
//!
//! Canonical AAD для AEAD (RFC 9605 §4.4.3) — **полные** bytes заголовка
//! (CONFIG + KID + CTR). Tamper любого байта ломает authentication tag.
//!
//! SFrame wire-format parse/serialize per RFC 9605 §4.
//!
//! Header layout (RFC 9605 §4.1-4.3):
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |X|  K  |Y|  C  |   CONFIG_BYTE (1 byte)
//! +-+-+-+-+-+-+-+-+
//! |   KID bytes   |   0 or K+1 bytes (big-endian) if X=1
//! +---------------+
//! |   CTR bytes   |   0 or C+1 bytes (big-endian) if Y=1
//! +---------------+
//! |   ciphertext  |
//! +---------------+
//! | AEAD tag 16 B |
//! +---------------+
//! ```
//!
//! `CONFIG_BYTE` bits (MSB ↔ LSB):
//!
//! - `X` (bit 0, MSB) — Extended KID flag.
//! - `K` (bits 1..3) — inline KID (if `X=0`) or KID length-minus-one
//!   (if `X=1`, `K+1` KID bytes follow the header).
//! - `Y` (bit 4) — Extended CTR flag.
//! - `C` (bits 5..7, LSB) — inline CTR (if `Y=0`) or CTR length-minus-one
//!   (if `Y=1`, `C+1` CTR bytes follow the KID).
//!
//! Canonical AAD for AEAD (RFC 9605 §4.4.3) is the **entire** header byte
//! sequence (CONFIG + KID + CTR). Tampering any byte breaks the AEAD tag.

use crate::error::{CallError, Result};

/// Максимальная длина заголовка: 1 байт CONFIG + 8 байт KID + 8 байт CTR = 17.
///
/// Maximum header length: 1 CONFIG + 8 KID + 8 CTR = 17 bytes.
pub const MAX_HEADER_LEN: usize = 17;

/// Распарсенный SFrame-заголовок: KID, counter и длина header'а в байтах
/// (для извлечения canonical AAD из wire-пакета).
///
/// Parsed SFrame header: KID, counter, and header length in bytes (used to
/// extract the canonical AAD from the wire packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SframeHeader {
    /// Key ID (формула `(sender_leaf << 16) | (epoch & 0xFFFF)` в крейте).
    /// Key ID (in this crate: `(sender_leaf << 16) | (epoch & 0xFFFF)`).
    pub kid: u64,
    /// Per-frame counter (monotonic per sender-epoch, проверяется replay-окном).
    /// Per-frame counter (monotonic per sender-epoch, checked by the replay window).
    pub counter: u64,
    /// Длина закодированного заголовка в байтах (CONFIG + KID + CTR).
    /// Encoded header length in bytes (CONFIG + KID + CTR).
    pub header_len: usize,
}

impl SframeHeader {
    /// Парсит SFrame-заголовок из начала `bytes`. Возвращает распарсенный
    /// `SframeHeader` и остаток слайса после заголовка (ciphertext + tag).
    ///
    /// Никогда не паникует: любой невалидный input → `CallError::InvalidHeader`.
    ///
    /// # Ошибки
    ///
    /// - `InvalidHeader("empty input")` — пустой слайс.
    /// - `InvalidHeader("truncated KID")` — меньше байт KID, чем требует `K+1`.
    /// - `InvalidHeader("truncated CTR")` — меньше байт CTR, чем требует `C+1`.
    ///
    /// Parses an SFrame header at the start of `bytes`. Returns the parsed
    /// header and the slice tail after the header (ciphertext + AEAD tag).
    ///
    /// Never panics: any invalid input → `CallError::InvalidHeader`.
    ///
    /// # Errors
    ///
    /// - `InvalidHeader("empty input")` — empty slice.
    /// - `InvalidHeader("truncated KID")` — fewer KID bytes than `K+1` demands.
    /// - `InvalidHeader("truncated CTR")` — fewer CTR bytes than `C+1` demands.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.is_empty() {
            return Err(CallError::InvalidHeader("empty input"));
        }
        let config = bytes[0];

        let x_bit = (config >> 7) & 0x01;
        let k_field = (config >> 4) & 0x07;
        let y_bit = (config >> 3) & 0x01;
        let c_field = config & 0x07;

        let mut cursor = 1usize;

        let (kid, kid_bytes) = if x_bit == 0 {
            // Inline 3-bit KID: значение 0..7 в поле K.
            // Inline 3-bit KID: value 0..7 in the K field.
            (u64::from(k_field), 0usize)
        } else {
            let kid_len = (k_field as usize) + 1;
            if bytes.len() < cursor + kid_len {
                return Err(CallError::InvalidHeader("truncated KID"));
            }
            let mut kid_val: u64 = 0;
            for &b in &bytes[cursor..cursor + kid_len] {
                kid_val = (kid_val << 8) | u64::from(b);
            }
            cursor += kid_len;
            (kid_val, kid_len)
        };

        let (counter, ctr_bytes) = if y_bit == 0 {
            // Inline 3-bit CTR: значение 0..7 в поле C.
            // Inline 3-bit CTR: value 0..7 in the C field.
            (u64::from(c_field), 0usize)
        } else {
            let ctr_len = (c_field as usize) + 1;
            if bytes.len() < cursor + ctr_len {
                return Err(CallError::InvalidHeader("truncated CTR"));
            }
            let mut counter_val: u64 = 0;
            for &b in &bytes[cursor..cursor + ctr_len] {
                counter_val = (counter_val << 8) | u64::from(b);
            }
            cursor += ctr_len;
            (counter_val, ctr_len)
        };

        let header_len = 1 + kid_bytes + ctr_bytes;
        let rest = &bytes[cursor..];
        Ok((
            Self {
                kid,
                counter,
                header_len,
            },
            rest,
        ))
    }

    /// Сериализует заголовок в heapless-буфер длиной [`MAX_HEADER_LEN`].
    /// Возвращает число записанных байт. Используется как canonical AAD.
    ///
    /// Кодировка минимальная (RFC 9605 §4.3 «compact unsigned integers»):
    /// `kid < 8` и `counter < 8` идут inline в CONFIG_BYTE, иначе 1..8 байт
    /// big-endian следуют за CONFIG_BYTE.
    ///
    /// Serializes the header into a heapless `[u8; MAX_HEADER_LEN]` buffer.
    /// Returns the number of bytes written. Used as canonical AAD.
    ///
    /// Encoding is minimum-length (RFC 9605 §4.3 "compact unsigned integers"):
    /// `kid < 8` and `counter < 8` go inline in the CONFIG_BYTE; otherwise
    /// 1..8 big-endian bytes follow the CONFIG_BYTE.
    pub fn serialize(kid: u64, counter: u64, out: &mut [u8; MAX_HEADER_LEN]) -> usize {
        let (x_bit, k_field, kid_bytes) = if kid < 8 {
            (0u8, kid as u8, 0usize)
        } else {
            let kl = minimal_be_len(kid);
            (1u8, (kl - 1) as u8, kl)
        };

        let (y_bit, c_field, ctr_bytes) = if counter < 8 {
            (0u8, counter as u8, 0usize)
        } else {
            let cl = minimal_be_len(counter);
            (1u8, (cl - 1) as u8, cl)
        };

        let config = (x_bit << 7) | (k_field << 4) | (y_bit << 3) | c_field;
        out[0] = config;

        let mut pos = 1usize;
        if kid_bytes > 0 {
            let be = kid.to_be_bytes();
            out[pos..pos + kid_bytes].copy_from_slice(&be[8 - kid_bytes..]);
            pos += kid_bytes;
        }
        if ctr_bytes > 0 {
            let be = counter.to_be_bytes();
            out[pos..pos + ctr_bytes].copy_from_slice(&be[8 - ctr_bytes..]);
            pos += ctr_bytes;
        }
        pos
    }
}

/// Минимальная big-endian длина `u64` в байтах (1..=8). Для `v=0` → 1.
///
/// Minimum big-endian length of `u64` in bytes (1..=8). For `v=0` → 1.
fn minimal_be_len(v: u64) -> usize {
    if v == 0 {
        1
    } else {
        let bits = 64 - v.leading_zeros() as usize;
        bits.div_ceil(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_rfc9605_appendix_c_header_example() {
        // RFC 9605 / sframe-wg test vectors: kid=0x123, counter=0x4567 → header=0x99 01 23 45 67.
        // X=1, K=1 (2 KID bytes), Y=1, C=1 (2 CTR bytes). CONFIG = 1_001_1_001 = 0x99.
        //
        // RFC 9605 / sframe-wg test vectors: kid=0x123, counter=0x4567 → header=0x99 01 23 45 67.
        // X=1, K=1 (2 KID bytes), Y=1, C=1 (2 CTR bytes). CONFIG = 1_001_1_001 = 0x99.
        let bytes = [0x99, 0x01, 0x23, 0x45, 0x67, 0xAA, 0xBB];
        let (h, rest) = SframeHeader::parse(&bytes).unwrap();
        assert_eq!(h.kid, 0x0123);
        assert_eq!(h.counter, 0x4567);
        assert_eq!(h.header_len, 5);
        assert_eq!(rest, &[0xAA, 0xBB]);
    }

    #[test]
    fn parse_fully_inline_header_single_byte() {
        // X=0, K=3 (KID=3), Y=0, C=5 (counter=5) → CONFIG = 0_011_0_101 = 0x35.
        // X=0, K=3 (KID=3), Y=0, C=5 (counter=5) → CONFIG = 0_011_0_101 = 0x35.
        let bytes = [0x35, 0xAA];
        let (h, rest) = SframeHeader::parse(&bytes).unwrap();
        assert_eq!(h.kid, 3);
        assert_eq!(h.counter, 5);
        assert_eq!(h.header_len, 1);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn parse_extended_kid_inline_counter() {
        // X=1, K=5 (6 KID bytes), Y=0, C=2 (counter=2) → CONFIG = 1_101_0_010 = 0xD2.
        // X=1, K=5 (6 KID bytes), Y=0, C=2 (counter=2) → CONFIG = 1_101_0_010 = 0xD2.
        let bytes = [0xD2, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xAA];
        let (h, rest) = SframeHeader::parse(&bytes).unwrap();
        assert_eq!(h.kid, 0x0001_0000_0005);
        assert_eq!(h.counter, 2);
        assert_eq!(h.header_len, 7);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn parse_inline_kid_extended_counter() {
        // X=0, K=1 (KID=1), Y=1, C=0 (1 CTR byte) → CONFIG = 0_001_1_000 = 0x18.
        // X=0, K=1 (KID=1), Y=1, C=0 (1 CTR byte) → CONFIG = 0_001_1_000 = 0x18.
        let bytes = [0x18, 0xFF, 0xAA];
        let (h, rest) = SframeHeader::parse(&bytes).unwrap();
        assert_eq!(h.kid, 1);
        assert_eq!(h.counter, 0xFF);
        assert_eq!(h.header_len, 2);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn parse_truncated_kid_rejected() {
        // X=1, K=7 → 8 KID bytes expected, only 2 provided. CONFIG = 0b1111_0000 = 0xF0.
        // X=1, K=7 → 8 KID bytes expected, only 2 provided. CONFIG = 0b1111_0000 = 0xF0.
        let bytes = [0xF0, 0xAA, 0xBB];
        let err = SframeHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, CallError::InvalidHeader("truncated KID")));
    }

    #[test]
    fn parse_truncated_ctr_rejected() {
        // X=0, K=0, Y=1, C=7 → 8 CTR bytes expected, only 2 provided. CONFIG = 0b0000_1111 = 0x0F.
        // X=0, K=0, Y=1, C=7 → 8 CTR bytes expected, only 2 provided. CONFIG = 0b0000_1111 = 0x0F.
        let bytes = [0x0F, 0xAA, 0xBB];
        let err = SframeHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, CallError::InvalidHeader("truncated CTR")));
    }

    #[test]
    fn parse_empty_input_rejected() {
        let err = SframeHeader::parse(&[]).unwrap_err();
        assert!(matches!(err, CallError::InvalidHeader("empty input")));
    }

    #[test]
    fn serialize_rfc9605_header_matches_appendix_c() {
        // See parse_rfc9605_appendix_c_header_example.
        // See parse_rfc9605_appendix_c_header_example.
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(0x0123, 0x4567, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(buf[..n], [0x99, 0x01, 0x23, 0x45, 0x67]);
    }

    #[test]
    fn serialize_fully_inline_single_byte_header() {
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(3, 5, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x35);
    }

    #[test]
    fn serialize_counter_zero_inline() {
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(0, 0, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn serialize_large_kid_counter_roundtrip() {
        let kid = 0x0001_0000_0005u64;
        let counter = 0x00AB_CDEFu64;
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(kid, counter, &mut buf);
        let (h, rest) = SframeHeader::parse(&buf[..n]).unwrap();
        assert_eq!(h.kid, kid);
        assert_eq!(h.counter, counter);
        assert_eq!(h.header_len, n);
        assert!(rest.is_empty());
    }

    #[test]
    fn serialize_counter_max_u64() {
        let mut buf = [0u8; MAX_HEADER_LEN];
        // KID `0x0001_0000_0005` укладывается в 5 байт minimum-encoding (bits=41).
        // counter=u64::MAX → 8 CTR bytes. X=1, K=4 (5 KID bytes), Y=1, C=7 (8 CTR bytes).
        // CONFIG = 1_100_1_111 = 0xCF.
        //
        // KID `0x0001_0000_0005` fits in 5 minimum-encoding bytes (bits=41).
        // counter=u64::MAX → 8 CTR bytes. X=1, K=4 (5 KID bytes), Y=1, C=7 (8 CTR bytes).
        // CONFIG = 1_100_1_111 = 0xCF.
        let n = SframeHeader::serialize(0x0001_0000_0005, u64::MAX, &mut buf);
        assert_eq!(buf[0], 0xCF);
        assert_eq!(n, 1 + 5 + 8);
        let (h, rest) = SframeHeader::parse(&buf[..n]).unwrap();
        assert_eq!(h.counter, u64::MAX);
        assert_eq!(h.kid, 0x0001_0000_0005);
        assert!(rest.is_empty());
    }

    #[test]
    fn serialize_spec_06_worst_case_header() {
        // SPEC-06 §6.2 worst-case: KID=6 bytes, CTR=2 bytes, sender_leaf ≥ 2^24.
        // X=1, K=5 (6 KID bytes), Y=1, C=1 (2 CTR bytes) → CONFIG = 1_101_1_001 = 0xD9.
        //
        // SPEC-06 §6.2 worst-case: KID=6 bytes, CTR=2 bytes, sender_leaf ≥ 2^24.
        // X=1, K=5 (6 KID bytes), Y=1, C=1 (2 CTR bytes) → CONFIG = 1_101_1_001 = 0xD9.
        let sender_leaf: u32 = 0x0100_0000;
        let epoch16: u16 = 0x0005;
        let kid = (u64::from(sender_leaf) << 16) | u64::from(epoch16);
        let counter = 0x0100u64;
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(kid, counter, &mut buf);
        assert_eq!(n, 9, "CONFIG(1) + KID(6) + CTR(2)");
        assert_eq!(
            buf[0], 0xD9,
            "SPEC-06 §6.2 worst-case CONFIG byte (RFC 9605 layout)"
        );
        let (h, _) = SframeHeader::parse(&buf[..n]).unwrap();
        assert_eq!(h.kid, kid);
        assert_eq!(h.counter, counter);
    }

    #[test]
    fn serialize_small_group_compact_header() {
        // Типичная группа ≤ 32 (sender_leaf < 32) + counter < 8 → header = 1 + 3 bytes.
        // sender_leaf=3, epoch16=5 → KID=(3<<16)|5 = 0x0003_0005 = 3 bytes. counter=3 inline.
        // X=1, K=2 (3 KID bytes), Y=0, C=3 → CONFIG = 1_010_0_011 = 0xA3.
        //
        // Typical small group: sender_leaf=3, epoch16=5 → KID=3 bytes, counter=3 inline.
        // X=1, K=2, Y=0, C=3 → CONFIG = 0xA3.
        let sender_leaf: u32 = 3;
        let epoch16: u16 = 0x0005;
        let kid = (u64::from(sender_leaf) << 16) | u64::from(epoch16);
        let counter = 3u64;
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(kid, counter, &mut buf);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0xA3);
        let (h, _) = SframeHeader::parse(&buf[..n]).unwrap();
        assert_eq!(h.kid, kid);
        assert_eq!(h.counter, counter);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_roundtrip_arbitrary_kid_counter(
            kid in any::<u64>(),
            counter in any::<u64>(),
        ) {
            let mut buf = [0u8; MAX_HEADER_LEN];
            let n = SframeHeader::serialize(kid, counter, &mut buf);
            let (h, rest) = SframeHeader::parse(&buf[..n]).unwrap();
            prop_assert_eq!(h.kid, kid);
            prop_assert_eq!(h.counter, counter);
            prop_assert_eq!(h.header_len, n);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_parse_random_bytes_never_panics(
            data in prop::collection::vec(any::<u8>(), 0..32),
        ) {
            // Необязательно парсится успешно — важно чтобы не паниковало.
            // Must not panic; success is not required.
            let _ = SframeHeader::parse(&data);
        }
    }
}
