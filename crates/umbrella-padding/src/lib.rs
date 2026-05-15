//! Bucketed padding для application payload: выравнивание до фиксированных корзин + authenticated length.
//! Bucketed padding for application payloads: align to fixed buckets + authenticated length.
//!
//! ## Назначение
//!
//! Даже после AEAD-шифрования размер зашифрованного blob утекает как сетевая метаданные
//! (Wireshark, ISP-observer). Traffic-analysis attacks (Panchenko et al., NDSS 2016;
//! Rimmer et al., NDSS 2018) классифицируют сообщения по distribution размеров: `<100 байт`
//! = "печатает/короткое сообщение", `1–10 КБ` = "документ", `>1 МБ` = "фото/видео". Даже без
//! расшифровки противник с 80%+ точностью реконструирует категории коммуникации.
//!
//! Mitigation — **bucketed padding**: paylоad округляется до фиксированной корзины (степень 4)
//! до шифрования. После AEAD наружу выходит только размер корзины, не исходный payload.
//!
//! ## Формат padded blob
//!
//! ```text
//! padded_blob = payload_len_be (4 bytes) || payload (N bytes) || zero-padding (bucket - N - 4)
//! ```
//!
//! - `payload_len_be` — длина payload в big-endian u32. Первые 4 байта всегда — authenticated
//!   length header внутри AEAD.
//! - `payload` — оригинальные данные длины N.
//! - `zero-padding` — нулевые байты до края корзины.
//!
//! ## Формат гарантирует
//!
//! - **Authenticated length.** Первые 4 байта зашифрованы и аутентифицированы AEAD-тегом
//!   вышестоящего слоя (MLS application message). Попытка подменить длину → AEAD fail.
//! - **Padding region проверяется на нули при strip.** Если враг flip'ит бит в padding после
//!   decrypt — мы обнаруживаем. Это дополнительная защита помимо AEAD integrity.
//! - **Бакет-size детерминистически определяется по payload_len.** Отправитель и получатель
//!   приходят к одному бакету без метаданных в wire-format.
//!
//! ## Purpose
//!
//! Even after AEAD encryption, the encrypted blob size leaks as network metadata (Wireshark,
//! ISP-observer). Traffic-analysis attacks (Panchenko et al., NDSS 2016; Rimmer et al., NDSS
//! 2018) classify messages by size distribution with 80%+ accuracy.
//!
//! Mitigation — **bucketed padding**: the payload is rounded to a fixed bucket (power of 4)
//! before encryption. Only the bucket size leaks, not the original payload.
//!
//! ## Padded blob format
//!
//! See above. Length header is authenticated (covered by the outer AEAD tag). The padding
//! region is verified to be zeros on strip — tampering is detected even beyond AEAD integrity.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Размер authenticated length header (big-endian u32).
/// Size of the authenticated length header (big-endian u32).
pub const LENGTH_HEADER_LEN: usize = 4;

/// Бакеты padding: 256 → 1K → 4K → 16K → 64K → 256K → 1M байт (степени 4).
/// Padding buckets: 256 → 1K → 4K → 16K → 64K → 256K → 1M bytes (powers of 4).
pub const BUCKETS: [usize; 7] = [
    256,       // 4^4
    1_024,     // 4^5
    4_096,     // 4^6
    16_384,    // 4^7
    65_536,    // 4^8
    262_144,   // 4^9
    1_048_576, // 4^10
];

/// Максимальный размер бакета.
/// Maximum bucket size.
pub const MAX_BUCKET: usize = 1_048_576;

/// Максимальный размер payload (без length header).
/// Maximum payload size (excluding the length header).
pub const MAX_PAYLOAD: usize = MAX_BUCKET - LENGTH_HEADER_LEN;

/// Ошибки padding-операций.
/// Padding operation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PaddingError {
    /// Payload превышает максимальный бакет (1 МБ минус header).
    /// Payload exceeds the maximum bucket (1 MiB minus header).
    #[error("payload too large: {payload_len} bytes (max {max})")]
    PayloadTooLarge {
        /// Запрошенная длина. Requested length.
        payload_len: usize,
        /// Максимум. Maximum.
        max: usize,
    },

    /// Размер padded blob не совпадает ни с одним бакетом.
    /// Padded blob size does not match any bucket.
    #[error("input length {actual} is not a valid bucket size")]
    InvalidBucketSize {
        /// Полученный размер. Actual size.
        actual: usize,
    },

    /// Length-header объявляет размер больше чем bucket - header.
    /// Length header claims more bytes than bucket minus header.
    #[error("authenticated length {declared} exceeds bucket capacity {bucket_max}")]
    LengthPrefixExceedsBucket {
        /// Декларированная длина. Declared length.
        declared: usize,
        /// Ёмкость бакета без header. Bucket capacity without header.
        bucket_max: usize,
    },

    /// В padding region обнаружены не-нулевые байты — признак tampering.
    /// Non-zero bytes detected in the padding region — evidence of tampering.
    #[error("non-zero byte detected in padding region (tamper indicator)")]
    NonZeroPadding,

    /// Padded blob короче минимального header (4 байта).
    /// Padded blob is shorter than the minimum header (4 bytes).
    #[error("padded blob too short: {actual} bytes (minimum {minimum})")]
    MalformedTooShort {
        /// Фактический размер. Actual size.
        actual: usize,
        /// Минимум. Minimum.
        minimum: usize,
    },
}

/// Result alias крейта. Crate result alias.
pub type Result<T, E = PaddingError> = core::result::Result<T, E>;

/// Возвращает наименьший бакет, вмещающий `payload_len + LENGTH_HEADER_LEN` байт.
/// Returns the smallest bucket that fits `payload_len + LENGTH_HEADER_LEN` bytes.
///
/// `None` если payload не помещается даже в максимальный бакет.
/// `None` if the payload does not fit even in the largest bucket.
pub fn chosen_bucket(payload_len: usize) -> Option<usize> {
    let needed = payload_len.checked_add(LENGTH_HEADER_LEN)?;
    BUCKETS.iter().copied().find(|&b| b >= needed)
}

/// Паддит payload до ближайшего бакета с authenticated length header.
/// Pads the payload up to the nearest bucket with an authenticated length header.
///
/// Формат результата: `len(payload, BE u32) || payload || zeros_to_bucket`.
/// Result format: `len(payload, BE u32) || payload || zeros_to_bucket`.
pub fn pad_to_bucket(payload: &[u8]) -> Result<Vec<u8>> {
    let bucket = chosen_bucket(payload.len()).ok_or(PaddingError::PayloadTooLarge {
        payload_len: payload.len(),
        max: MAX_PAYLOAD,
    })?;

    let mut out = vec![0u8; bucket];
    let len_be = (payload.len() as u32).to_be_bytes();
    out[..LENGTH_HEADER_LEN].copy_from_slice(&len_be);
    out[LENGTH_HEADER_LEN..LENGTH_HEADER_LEN + payload.len()].copy_from_slice(payload);
    // Хвост уже нулевой благодаря `vec![0u8; bucket]`.
    // Tail is already zero thanks to `vec![0u8; bucket]`.
    Ok(out)
}

/// Снимает padding, проверяя целостность header и нулевой padding region.
/// Strips the padding, verifying header integrity and the zero padding region.
///
/// Возвращает клон payload'а (копия, не заимствование). Если `padded` получен после decrypt
/// и больше не нужен вызывающему — рекомендуется вызвать [`Zeroize::zeroize`] на нём.
///
/// Returns a copy of the payload (not a borrow). If `padded` came from decrypt and is no
/// longer needed by the caller, call [`Zeroize::zeroize`] on it afterwards.
pub fn strip_padding(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < LENGTH_HEADER_LEN {
        return Err(PaddingError::MalformedTooShort {
            actual: padded.len(),
            minimum: LENGTH_HEADER_LEN,
        });
    }

    if !BUCKETS.contains(&padded.len()) {
        return Err(PaddingError::InvalidBucketSize {
            actual: padded.len(),
        });
    }

    let mut len_bytes = [0u8; LENGTH_HEADER_LEN];
    len_bytes.copy_from_slice(&padded[..LENGTH_HEADER_LEN]);
    let declared = u32::from_be_bytes(len_bytes) as usize;

    let bucket_max = padded.len() - LENGTH_HEADER_LEN;
    if declared > bucket_max {
        return Err(PaddingError::LengthPrefixExceedsBucket {
            declared,
            bucket_max,
        });
    }

    let payload_end = LENGTH_HEADER_LEN + declared;
    // Проверка padding region на нули через constant-time OR-reduction (SPEC-10 §6.3) —
    // защита от bit-flip после AEAD decrypt без timing leak. `iter().fold` всегда
    // обходит весь tail без short-circuit на первом non-zero байте; финальное сравнение
    // с нулём — `subtle::ConstantTimeEq` чтобы compiler не оптимизировал в branchful
    // form. Offset первого non-zero не публикуется — это закрывает потенциальный
    // timing oracle через error variant content (см. F-51 block 10.12).
    //
    // Constant-time OR-reduction zero check across the padding region (SPEC-10 §6.3) —
    // defence against post-AEAD-decrypt bit-flip with no timing leak. `iter().fold` always
    // iterates the entire tail with no short-circuit on the first non-zero byte; the final
    // comparison to zero uses `subtle::ConstantTimeEq` to prevent the compiler from
    // optimising it into a branchful form. The offset of the first non-zero byte is not
    // exposed — closing a potential timing oracle through error-variant content (see
    // F-51 block 10.12).
    let acc = padded[payload_end..].iter().fold(0u8, |acc, &b| acc | b);
    if !bool::from(acc.ct_eq(&0u8)) {
        return Err(PaddingError::NonZeroPadding);
    }

    Ok(padded[LENGTH_HEADER_LEN..payload_end].to_vec())
}

/// Вариант strip_padding который возвращает `zeroize`-обёрнутый Vec для автостирания.
/// Variant of strip_padding that returns a `zeroize`-wrapped Vec for auto-zeroisation.
///
/// Используется когда вытащенный payload будет передаваться дальше как секрет (например,
/// ключ или чувствительное сообщение) и должен быть стёрт при drop.
///
/// Used when the stripped payload will be passed on as a secret (e.g. a key or sensitive
/// message) and must be wiped on drop.
pub fn strip_padding_zeroizing(padded: &[u8]) -> Result<ZeroizingPayload> {
    let v = strip_padding(padded)?;
    Ok(ZeroizingPayload(v))
}

/// Обёртка `Vec<u8>` которая zeroизирует содержимое при drop.
/// `Vec<u8>` wrapper that zeroises the contents on drop.
pub struct ZeroizingPayload(Vec<u8>);

/// `Debug` скрывает payload: после снятия padding это уже исходное сообщение/секрет.
/// `Debug` redacts the payload: after unpadding this is the original message/secret.
impl core::fmt::Debug for ZeroizingPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ZeroizingPayload")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl ZeroizingPayload {
    /// Доступ к payload как срез.
    /// Access the payload as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Размер payload.
    /// Payload length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True если payload пустой.
    /// True if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Извлекает owned Vec, потребляя обёртку (zeroize уже не нужен — caller владеет).
    /// Extracts the owned Vec, consuming the wrapper (zeroise is caller's responsibility).
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for ZeroizingPayload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // === Базовые свойства бакетов ===

    #[test]
    fn buckets_are_strictly_increasing() {
        for pair in BUCKETS.windows(2) {
            assert!(pair[0] < pair[1]);
        }
    }

    #[test]
    fn buckets_are_powers_of_four() {
        // 256 = 4^4, 1024 = 4^5, ..., 1_048_576 = 4^10
        for (i, &b) in BUCKETS.iter().enumerate() {
            let exponent = 4 + i as u32;
            assert_eq!(
                b,
                4usize.pow(exponent),
                "bucket[{i}] = {b} должен быть 4^{exponent}"
            );
        }
    }

    #[test]
    fn max_payload_is_max_bucket_minus_header() {
        assert_eq!(MAX_PAYLOAD, MAX_BUCKET - LENGTH_HEADER_LEN);
        assert_eq!(MAX_PAYLOAD, 1_048_572);
    }

    // === Выбор бакета ===

    #[test]
    fn chosen_bucket_empty_payload_yields_smallest() {
        assert_eq!(chosen_bucket(0), Some(256));
    }

    #[test]
    fn chosen_bucket_exact_fit_stays_in_same_bucket() {
        // 252 payload + 4 header = 256 → bucket 256
        assert_eq!(chosen_bucket(252), Some(256));
        // 1020 + 4 = 1024 → bucket 1024
        assert_eq!(chosen_bucket(1_020), Some(1_024));
    }

    #[test]
    fn chosen_bucket_one_over_boundary_moves_to_next() {
        // 253 + 4 = 257 > 256 → bucket 1024
        assert_eq!(chosen_bucket(253), Some(1_024));
        assert_eq!(chosen_bucket(1_021), Some(4_096));
    }

    #[test]
    fn chosen_bucket_max_payload_yields_max_bucket() {
        assert_eq!(chosen_bucket(MAX_PAYLOAD), Some(MAX_BUCKET));
    }

    #[test]
    fn chosen_bucket_over_max_yields_none() {
        assert_eq!(chosen_bucket(MAX_PAYLOAD + 1), None);
        assert_eq!(chosen_bucket(usize::MAX), None);
    }

    #[test]
    fn chosen_bucket_is_monotonic() {
        // Для любых n1 <= n2 bucket(n1) <= bucket(n2).
        for &small in &[0usize, 1, 100, 1000, 10_000, 100_000] {
            for &large in &[small, small + 1, small + 100, MAX_PAYLOAD] {
                let b_small = chosen_bucket(small);
                let b_large = chosen_bucket(large);
                if let (Some(bs), Some(bl)) = (b_small, b_large) {
                    assert!(bs <= bl, "bucket({small}) > bucket({large})");
                }
            }
        }
    }

    // === pad_to_bucket ===

    #[test]
    fn pad_empty_payload_to_smallest_bucket() {
        let padded = pad_to_bucket(&[]).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..4], &[0, 0, 0, 0]);
        assert!(padded[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_short_payload_stored_exactly() {
        let payload = b"hello";
        let padded = pad_to_bucket(payload).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..4], &[0, 0, 0, 5]);
        assert_eq!(&padded[4..4 + 5], payload);
        assert!(padded[4 + 5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_exact_bucket_fit_no_overflow() {
        let payload = vec![0xAB; 252];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..4], &[0, 0, 0, 252]);
        assert_eq!(&padded[4..], payload.as_slice());
    }

    #[test]
    fn pad_just_over_boundary_moves_bucket() {
        let payload = vec![0xCD; 253];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), 1_024);
    }

    #[test]
    fn pad_max_payload_uses_max_bucket() {
        let payload = vec![0xEE; MAX_PAYLOAD];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), MAX_BUCKET);
    }

    #[test]
    fn pad_rejects_payload_over_max() {
        let payload = vec![0xFF; MAX_PAYLOAD + 1];
        assert!(matches!(
            pad_to_bucket(&payload).unwrap_err(),
            PaddingError::PayloadTooLarge { .. }
        ));
    }

    // === strip_padding ===

    #[test]
    fn strip_round_trip_empty() {
        let padded = pad_to_bucket(&[]).unwrap();
        assert_eq!(strip_padding(&padded).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn strip_round_trip_short() {
        let payload = b"hello world";
        let padded = pad_to_bucket(payload).unwrap();
        assert_eq!(strip_padding(&padded).unwrap(), payload);
    }

    #[test]
    fn strip_round_trip_boundary() {
        for len in [252, 253, 1_020, 1_021, 4_092, 4_093] {
            let payload = vec![0x42; len];
            let padded = pad_to_bucket(&payload).unwrap();
            let stripped = strip_padding(&padded).unwrap();
            assert_eq!(stripped, payload, "len={len}");
        }
    }

    #[test]
    fn strip_rejects_invalid_bucket_size() {
        let bad = vec![0u8; 300]; // not a bucket
        assert!(matches!(
            strip_padding(&bad).unwrap_err(),
            PaddingError::InvalidBucketSize { actual: 300 }
        ));
    }

    #[test]
    fn strip_rejects_too_short() {
        assert!(matches!(
            strip_padding(&[0, 0]).unwrap_err(),
            PaddingError::MalformedTooShort { actual: 2, .. }
        ));
    }

    #[test]
    fn strip_rejects_declared_length_over_bucket_capacity() {
        // Bucket 256, declared length = 1000 > 256 - 4.
        let mut tampered = vec![0u8; 256];
        tampered[..4].copy_from_slice(&(1000u32).to_be_bytes());
        assert!(matches!(
            strip_padding(&tampered).unwrap_err(),
            PaddingError::LengthPrefixExceedsBucket { .. }
        ));
    }

    #[test]
    fn strip_rejects_non_zero_padding() {
        let mut padded = pad_to_bucket(b"hi").unwrap();
        // hi занимает 4 + 2 = 6 байт, остальное должно быть 0.
        padded[100] = 0xAB;
        assert_eq!(
            strip_padding(&padded).unwrap_err(),
            PaddingError::NonZeroPadding
        );
    }

    #[test]
    fn strip_rejects_non_zero_padding_at_end() {
        let mut padded = pad_to_bucket(b"hi").unwrap();
        let last = padded.len() - 1;
        padded[last] = 0x01;
        assert_eq!(
            strip_padding(&padded).unwrap_err(),
            PaddingError::NonZeroPadding
        );
    }

    #[test]
    fn strip_allows_zero_payload_with_zero_length() {
        // Padding с length=0 → payload пустой, всё остальное zeros. Валидно.
        let padded = vec![0u8; 256];
        assert_eq!(strip_padding(&padded).unwrap(), Vec::<u8>::new());
    }

    // === Zeroising ===

    #[test]
    fn zeroizing_strip_returns_correct_payload() {
        let payload = b"secret-key-material";
        let padded = pad_to_bucket(payload).unwrap();
        let z = strip_padding_zeroizing(&padded).unwrap();
        assert_eq!(z.as_slice(), payload);
        assert_eq!(z.len(), payload.len());
        assert!(!z.is_empty());
    }

    #[test]
    fn zeroizing_into_inner_yields_owned_vec() {
        let padded = pad_to_bucket(b"abc").unwrap();
        let z = strip_padding_zeroizing(&padded).unwrap();
        let v = z.into_inner();
        assert_eq!(v, b"abc");
    }

    #[test]
    fn zeroizing_empty_reports_empty() {
        let padded = pad_to_bucket(&[]).unwrap();
        let z = strip_padding_zeroizing(&padded).unwrap();
        assert_eq!(z.len(), 0);
        assert!(z.is_empty());
    }

    #[test]
    fn zeroizing_payload_debug_redacts_bytes() {
        let payload = ZeroizingPayload(b"secret-message-after-unpadding".to_vec());

        let debug = format!("{payload:?}");

        assert!(
            !debug.contains("115, 101, 99, 114, 101, 116"),
            "Debug output must not leak stripped payload bytes: {debug}"
        );
        assert!(
            debug.contains("len"),
            "Debug output should keep payload length metadata: {debug}"
        );
    }

    // === Property-based ===

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_round_trip_random_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..8_192)
        ) {
            let padded = pad_to_bucket(&payload).unwrap();
            prop_assert!(BUCKETS.contains(&padded.len()));
            let stripped = strip_padding(&padded).unwrap();
            prop_assert_eq!(stripped, payload);
        }

        #[test]
        fn prop_bucket_monotonic_in_payload_len(
            len_small in 0usize..1000,
            len_large in 1000usize..10_000,
        ) {
            let b_small = chosen_bucket(len_small).unwrap();
            let b_large = chosen_bucket(len_large).unwrap();
            prop_assert!(b_small <= b_large);
        }

        #[test]
        fn prop_tamper_any_padding_byte_detected(
            payload_len in 0usize..200,
            tamper_offset in 0usize..256,
            tamper_byte in 1u8..=255,
        ) {
            let payload = vec![0x42; payload_len];
            let mut padded = pad_to_bucket(&payload).unwrap();
            let start = LENGTH_HEADER_LEN + payload_len;
            if start < padded.len() {
                let pos = start + (tamper_offset % (padded.len() - start));
                padded[pos] = tamper_byte;
                let result = strip_padding(&padded);
                prop_assert_eq!(result.unwrap_err(), PaddingError::NonZeroPadding);
            }
        }

        #[test]
        fn prop_tamper_length_prefix_over_capacity_detected(
            bucket_index in 0usize..BUCKETS.len(),
            bad_len in 0u32..100_000_000,
        ) {
            let bucket = BUCKETS[bucket_index];
            let capacity = bucket - LENGTH_HEADER_LEN;
            prop_assume!(bad_len as usize > capacity);
            let mut padded = vec![0u8; bucket];
            padded[..4].copy_from_slice(&bad_len.to_be_bytes());
            let result = strip_padding(&padded);
            let matched = matches!(result, Err(PaddingError::LengthPrefixExceedsBucket { .. }));
            prop_assert!(matched);
        }

        #[test]
        fn prop_invalid_size_detected(size in 1usize..10_000) {
            prop_assume!(!BUCKETS.contains(&size));
            prop_assume!(size >= LENGTH_HEADER_LEN);
            let blob = vec![0u8; size];
            let result = strip_padding(&blob);
            let matched = matches!(result, Err(PaddingError::InvalidBucketSize { .. }));
            prop_assert!(matched);
        }
    }
}
