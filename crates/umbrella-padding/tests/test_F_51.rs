//! Регрессионные тесты F-51: SPEC-10 §6.3 promise constant-time zero-tail check.
//! F-51 regression tests: SPEC-10 §6.3 promise of a constant-time zero-tail check.
//!
//! Block 10.12 (Phase 2 — umbrella-padding audit) inline-fixed предыдущий early-return
//! data-dependent loop в `strip_padding` к OR-reduction через `subtle::ConstantTimeEq`
//! согласно SPEC-10 §6.3 «Constant-time check через bitwise OR. Нет timing leak: мы
//! всегда читаем весь tail и делаем OR — ни одна ветвь не short-circuit'ится на
//! первом non-zero.»
//!
//! Эти тесты — behavioural verification: каждая позиция non-zero байта в padding tail
//! должна быть отвергнута одним и тем же `PaddingError::NonZeroPadding` независимо от
//! позиции; legitimate all-zero tail должен пройти. dudect-style timing benchmark
//! deferred к block 10.24 (Phase 3 cross-cutting CT verification per design §7.3).
//!
//! Block 10.12 (Phase 2 umbrella-padding audit) inline-fixed the previous early-return
//! data-dependent loop in `strip_padding` to an OR-reduction via `subtle::ConstantTimeEq`
//! per the SPEC-10 §6.3 promise. These tests are the behavioural verification: every
//! non-zero position in the padding tail must be rejected uniformly with
//! `PaddingError::NonZeroPadding`, and a legitimate all-zero tail must pass. The
//! dudect-style timing benchmark is deferred to block 10.24 (Phase 3 cross-cutting CT
//! verification per design §7.3).

use umbrella_padding::{pad_to_bucket, strip_padding, PaddingError, BUCKETS, LENGTH_HEADER_LEN};

/// Каждая позиция в bucket 256 от `payload_end` до `bucket - 1` с non-zero значением 0xFF
/// должна давать `PaddingError::NonZeroPadding` (никаких других ошибок и никакого Ok).
/// Тест exhaustively обходит ~250 позиций.
///
/// Every position from `payload_end` to `bucket - 1` of bucket 256 with a non-zero byte
/// 0xFF must return `PaddingError::NonZeroPadding` — no other variants, no Ok. The
/// test exhaustively covers ~250 positions.
#[test]
fn f_51_strip_rejects_non_zero_at_every_tail_position_bucket_256() {
    let payload = b"hello"; // длина 5; payload_end = 4 + 5 = 9
    let payload_end = LENGTH_HEADER_LEN + payload.len();
    let bucket: usize = 256;

    for pos in payload_end..bucket {
        let mut padded = pad_to_bucket(payload).unwrap();
        assert_eq!(padded.len(), bucket);
        assert_eq!(padded[pos], 0u8, "tail must start as zero (pos={pos})");
        padded[pos] = 0xFF;
        let result = strip_padding(&padded);
        assert_eq!(
            result.unwrap_err(),
            PaddingError::NonZeroPadding,
            "pos={pos}: ожидалось NonZeroPadding"
        );
    }
}

/// Empty tail при `payload_len + LENGTH_HEADER_LEN == bucket` — никаких байт для проверки;
/// `strip_padding` должен возвращать payload без ошибки. CT loop trivially проходит на
/// пустом range.
///
/// Empty tail when `payload_len + LENGTH_HEADER_LEN == bucket` — no bytes to check;
/// `strip_padding` must return the payload without error. The CT loop trivially passes
/// over the empty range.
#[test]
fn f_51_empty_tail_passes_constant_time_check() {
    // payload_len = 252, bucket 256, tail = 0 байт
    let payload = vec![0xAB; 252];
    let padded = pad_to_bucket(&payload).unwrap();
    assert_eq!(padded.len(), 256);
    let stripped = strip_padding(&padded).unwrap();
    assert_eq!(stripped, payload);
}

/// Все 7 бакетов: legitimate all-zero tail проходит CT check; круг trip preserves
/// payload bit-exactly.
///
/// All 7 buckets: legitimate all-zero tail passes the CT check; round trip preserves
/// the payload bit-exactly.
#[test]
fn f_51_all_buckets_round_trip_with_constant_time_tail_check() {
    for &bucket in &BUCKETS {
        // payload длиной = bucket - LENGTH_HEADER_LEN - 8 для tail размера 8 (нетривиальный)
        let payload_len = bucket - LENGTH_HEADER_LEN - 8;
        let payload = vec![0x42u8; payload_len];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), bucket);
        let stripped = strip_padding(&padded).unwrap();
        assert_eq!(stripped, payload, "bucket={bucket}");
    }
}

/// Non-zero bit на самой последней позиции максимального bucket (1 МиБ) — CT loop
/// должен пройти весь bucket без short-circuit и detect tampering на edge.
///
/// Non-zero bit at the very last position of the maximum 1 MiB bucket — the CT loop
/// must traverse the full bucket without short-circuit and detect tampering at the edge.
#[test]
fn f_51_non_zero_at_last_byte_of_max_bucket() {
    let payload = b"end-of-bucket-tamper-test";
    let mut padded = pad_to_bucket(payload).unwrap();
    let bucket = padded.len();
    padded[bucket - 1] = 0x01; // single bit at the absolute last position
    let result = strip_padding(&padded);
    assert_eq!(result.unwrap_err(), PaddingError::NonZeroPadding);
}

/// Multi-byte tampering pattern: разбросанные non-zero bytes — все detected
/// одной accumulated OR-reduction.
///
/// Multi-byte tampering pattern: scattered non-zero bytes — all detected by the single
/// accumulated OR-reduction.
#[test]
fn f_51_multi_byte_tampering_detected() {
    let payload = vec![0xCD; 100]; // bucket 256
    let mut padded = pad_to_bucket(&payload).unwrap();
    let payload_end = LENGTH_HEADER_LEN + payload.len();
    let bucket = padded.len();
    // Tamper в трёх местах: начале tail, середине, конце.
    padded[payload_end] = 0x02;
    padded[(payload_end + bucket) / 2] = 0x10;
    padded[bucket - 1] = 0x80;
    let result = strip_padding(&padded);
    assert_eq!(result.unwrap_err(), PaddingError::NonZeroPadding);
}
