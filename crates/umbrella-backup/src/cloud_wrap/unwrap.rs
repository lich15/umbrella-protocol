//! Client unwrap: собрать partial shares, сделать Lagrange combine, вернуть
//! message_key через AEAD decrypt. При AEAD-fail на выбранных 3 shares —
//! пробовать другие подмножества (если есть ≥ 4 валидных point-encoded).
//!
//! Client unwrap: gather partial shares, run Lagrange combine, return
//! message_key via AEAD decrypt. On AEAD failure with the chosen 3 shares,
//! try alternative subsets when ≥ 4 valid point-encoded shares are available.

use crate::error::BackupError;

use super::aead::{aead_open, decompress_point};
use super::params::{WrappingParams, MESSAGE_KEY_LEN};
use super::share::ServerUnwrapShare;
use super::threshold::{lagrange_at_zero, threshold_combine};
use super::wire::{canonical_nonce, CanonicalAad, WrappedKey};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

/// Максимум попыток subset-retry при AEAD-fail.
/// Maximum subset-retry attempts on AEAD failure.
const MAX_RETRY_SUBSETS: usize = 10;

/// Развернуть `wrapped_key` через кооперацию ≥ 3 Sealed Servers.
///
/// Unwrap `wrapped_key` via cooperation of ≥ 3 Sealed Servers.
///
/// Алгоритм:
/// 1. Декомпрессируем `R` из `wrapped.ephemeral_r`.
/// 2. Пробуем initial subset: первые `threshold` shares в порядке прибытия →
///    Lagrange combine → AEAD decrypt.
/// 3. При AEAD fail, если есть больше shares: перебираем другие subsets.
/// 4. Если все subsets дали AEAD-fail — `AllSubsetsFailedUnwrap` (catastrophic,
///    signals ≥ 3 malicious servers). Если недостаточно валидных decompress'ов
///    в принципе — `InsufficientUnwrapShares`.
///
/// Algorithm: decompress `R`, try initial subset, retry with other subsets on
/// AEAD failure, fail with `AllSubsetsFailedUnwrap` if everything rejects, or
/// `InsufficientUnwrapShares` if too few valid point-encoded shares.
///
/// # Errors
/// - [`BackupError::InvalidRistrettoEncoding`] если `wrapped.ephemeral_r` невалиден.
/// - [`BackupError::InsufficientUnwrapShares`] если validly-encoded shares < threshold.
/// - [`BackupError::DuplicateWitnessIndex`] если какой-то witness повторяется.
/// - [`BackupError::UnknownWitnessIndex`] если witness вне диапазона.
/// - [`BackupError::AllSubsetsFailedUnwrap`] если все комбинации дали AEAD-fail.
pub fn unwrap_message_key(
    params: &WrappingParams,
    wrapped: &WrappedKey,
    aad: &CanonicalAad,
    shares: &[ServerUnwrapShare],
) -> Result<[u8; MESSAGE_KEY_LEN], BackupError> {
    // Сначала валидируем witness indices и отсутствие дубликатов (reuse threshold_combine pre-check).
    // Делаем это явно вызвав threshold_combine на initial subset; ошибки там — те же что мы хотим пробросить.
    if shares.len() < params.config.threshold as usize {
        return Err(BackupError::InsufficientUnwrapShares {
            valid: shares.len(),
            required: params.config.threshold as usize,
        });
    }

    // Dedup и проверка диапазона.
    let mut seen = [false; 6];
    for share in shares {
        let i = share.witness_index.get();
        if i == 0 || i > params.config.total {
            return Err(BackupError::UnknownWitnessIndex(i));
        }
        if seen[i as usize] {
            return Err(BackupError::DuplicateWitnessIndex(i));
        }
        seen[i as usize] = true;
    }

    // Декомпрессируем R.
    let r_point = decompress_point(&wrapped.ephemeral_r)?;
    let _ = r_point; // R нам нужно не напрямую, а через combine в shared_point.

    // Декомпрессируем все partial точки заранее, отфильтровываем невалидные.
    let mut valid: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
    for share in shares {
        if let Ok(pt) = decompress_point(&share.partial) {
            if valid.push((share.witness_index.get(), pt)).is_err() {
                break; // capacity overflow — больше чем DEFAULT_TOTAL shares
            }
        }
    }

    if valid.len() < params.config.threshold as usize {
        return Err(BackupError::InsufficientUnwrapShares {
            valid: valid.len(),
            required: params.config.threshold as usize,
        });
    }

    let t = params.config.threshold as usize;
    let n = valid.len();
    let nonce = canonical_nonce(&aad.chat_id, aad.msg_seq);

    // Перебираем подмножества размера t из n, начиная с первого (arrival order).
    for (attempts, combo) in subset_combinations(n, t).into_iter().enumerate() {
        if attempts >= MAX_RETRY_SUBSETS {
            break;
        }

        // Собираем points подмножества.
        let mut subset: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
        for &idx in &combo {
            #[allow(
                unknown_lints,
                no_unwrap_in_lib,
                reason = "infallible: heapless capacity 8 ≥ threshold 3"
            )]
            subset
                .push(valid[idx])
                .expect("subset capacity 8 >= threshold 3");
        }

        // Lagrange combine.
        let mut acc = RistrettoPoint::identity();
        for (i, pt) in &subset {
            let lambda = lagrange_at_zero(*i, &subset);
            acc += pt * lambda;
        }
        let shared_point = acc;

        // AEAD decrypt attempt.
        match aead_open(&shared_point, aad, &nonce, &wrapped.aead_blob) {
            Ok(mk) => return Ok(mk),
            Err(BackupError::AeadDecryptFailed) => continue,
            Err(other) => return Err(other),
        }
    }

    // Если n == threshold (минимум), это был единственный subset и он failed —
    // возвращаем AllSubsetsFailedUnwrap чтобы сигнализировать ≥ threshold malicious.
    // Если n > threshold, мы перебрали все combinations но ни одна не прошла —
    // тоже AllSubsetsFailedUnwrap.
    Err(BackupError::AllSubsetsFailedUnwrap)
}

/// Чистая версия unwrap'а которая не делает retry — использует ровно
/// первые `threshold` shares через Lagrange combine.
///
/// Pure unwrap without retry — uses exactly the first `threshold` shares
/// with Lagrange combine.
///
/// Используется когда вызывающая сторона уверена в валидности всех shares
/// (интеграционные тесты, happy path).
///
/// Used when caller is confident in all shares (integration tests, happy path).
///
/// # Errors
/// Все ошибки `threshold_combine` + `aead_open`.
pub fn unwrap_message_key_no_retry(
    params: &WrappingParams,
    wrapped: &WrappedKey,
    aad: &CanonicalAad,
    shares: &[ServerUnwrapShare],
) -> Result<[u8; MESSAGE_KEY_LEN], BackupError> {
    let _ = decompress_point(&wrapped.ephemeral_r)?;
    let shared_point = threshold_combine(shares, params.config)?;
    let nonce = canonical_nonce(&aad.chat_id, aad.msg_seq);
    aead_open(&shared_point, aad, &nonce, &wrapped.aead_blob)
}

/// Генератор всех сочетаний размера `t` из `n` в lexicographic order. Первый
/// возвращаемый combo — `[0, 1, ..., t-1]` (arrival order). До
/// `MAX_RETRY_SUBSETS` шт.
///
/// Generates all size-`t` combinations from `n` items in lex order. The
/// first yielded combo is `[0, 1, ..., t-1]` (arrival order). Up to
/// `MAX_RETRY_SUBSETS` total.
fn subset_combinations(n: usize, t: usize) -> Vec<Vec<usize>> {
    let mut result: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = (0..t).collect();
    if t > n || t == 0 {
        return result;
    }
    result.push(cur.clone());

    while result.len() < MAX_RETRY_SUBSETS {
        // next combination algorithm: find rightmost index we can increment.
        let mut i = t;
        while i > 0 {
            i -= 1;
            let max_val = n - (t - i);
            if cur[i] < max_val {
                cur[i] += 1;
                for j in (i + 1)..t {
                    cur[j] = cur[j - 1] + 1;
                }
                result.push(cur.clone());
                break;
            }
            if i == 0 {
                return result;
            }
        }
        if cur[0] > n - t {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use crate::cloud_wrap::params::{
        ThresholdConfig, WitnessIndex, DEFAULT_TOTAL, POINT_LEN, PROTOCOL_VERSION,
    };
    use crate::cloud_wrap::threshold::shamir_split_for_testing;
    use crate::cloud_wrap::wire::ED25519_PUB_LEN;
    use crate::cloud_wrap::wrap::wrap_message_key;

    fn sample_aad() -> CanonicalAad {
        CanonicalAad {
            sender_identity_pubkey: [0x11; ED25519_PUB_LEN],
            recipient_device_pubkey: [0x22; ED25519_PUB_LEN],
            chat_id: [0x33; 32],
            msg_seq: 42,
        }
    }

    fn make_params_and_shares() -> (WrappingParams, Scalar, Vec<(WitnessIndex, Scalar)>) {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        let y = RISTRETTO_BASEPOINT_POINT * k;
        let params = WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
            config,
        };
        let shares_vec: Vec<(WitnessIndex, Scalar)> = shares.iter().copied().collect();
        (params, k, shares_vec)
    }

    fn compute_server_share(
        wi: WitnessIndex,
        k_i: Scalar,
        wrapped: &WrappedKey,
    ) -> ServerUnwrapShare {
        let r_point = decompress_point(&wrapped.ephemeral_r).unwrap();
        let partial = (k_i * r_point).compress().to_bytes();
        ServerUnwrapShare {
            witness_index: wi,
            partial,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip_happy_path() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0xCC; MESSAGE_KEY_LEN];

        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        // Любые 3 из 5 shares.
        let server_shares: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, ki)| compute_server_share(*wi, *ki, &wrapped))
            .collect();

        let recovered = unwrap_message_key(&params, &wrapped, &aad, &server_shares).unwrap();
        assert_eq!(recovered, mk);
    }

    #[test]
    fn wrap_unwrap_roundtrip_all_ten_subsets() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x77; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        // Все 10 подмножеств 3-of-5.
        let all_subsets: [[usize; 3]; 10] = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ];
        for combo in &all_subsets {
            let set: Vec<ServerUnwrapShare> = combo
                .iter()
                .map(|&idx| {
                    let (wi, ki) = shares[idx];
                    compute_server_share(wi, ki, &wrapped)
                })
                .collect();
            let recovered = unwrap_message_key_no_retry(&params, &wrapped, &aad, &set).unwrap();
            assert_eq!(recovered, mk, "subset {combo:?}");
        }
    }

    #[test]
    fn unwrap_fails_on_below_threshold() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x11; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let only_two: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(2)
            .map(|(wi, ki)| compute_server_share(*wi, *ki, &wrapped))
            .collect();

        let err = unwrap_message_key(&params, &wrapped, &aad, &only_two).unwrap_err();
        assert!(matches!(
            err,
            BackupError::InsufficientUnwrapShares {
                valid: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn unwrap_fails_on_tampered_aad() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x11; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let mut bad_aad = aad.clone();
        bad_aad.msg_seq = 99;

        let set: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, ki)| compute_server_share(*wi, *ki, &wrapped))
            .collect();

        let err = unwrap_message_key(&params, &wrapped, &bad_aad, &set).unwrap_err();
        // AEAD-decrypt under changed AAD fails; since same single subset, retry
        // list exhausted → AllSubsetsFailedUnwrap.
        assert!(matches!(err, BackupError::AllSubsetsFailedUnwrap));
    }

    #[test]
    fn unwrap_retries_alternate_subset_on_aead_fail() {
        // Scenario: 1 из 3 partial shares tampered (под другим k). AEAD decrypt на
        // initial subset {0,1,2} даст неправильный shared_point → fail. Если у
        // нас есть ≥ 4 shares (и хотя бы одна валидная альтернатива), retry на
        // другом подмножестве успешен.
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x99; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        // 4 valid shares + 1 tampered (под случайным k').
        let (wi0, k0) = shares[0];
        let (wi1, _k1) = shares[1];
        let (wi2, k2) = shares[2];
        let (wi3, k3) = shares[3];
        let (wi4, k4) = shares[4];
        let wrong_k = Scalar::random(&mut OsRng);

        let tampered = compute_server_share(wi1, wrong_k, &wrapped);
        let set: Vec<ServerUnwrapShare> = vec![
            compute_server_share(wi0, k0, &wrapped),
            tampered,
            compute_server_share(wi2, k2, &wrapped),
            compute_server_share(wi3, k3, &wrapped),
            compute_server_share(wi4, k4, &wrapped),
        ];

        // С initial subset {0, tampered, 2} AEAD fails; retry находит valid subset.
        let recovered = unwrap_message_key(&params, &wrapped, &aad, &set).unwrap();
        assert_eq!(recovered, mk);
    }

    #[test]
    fn unwrap_fails_when_too_many_tampered() {
        // 3 из 5 tampered: 2 валидных shares не достигают threshold 3.
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x77; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let (wi0, _) = shares[0];
        let (wi1, _) = shares[1];
        let (wi2, _) = shares[2];
        let (wi3, k3) = shares[3];
        let (wi4, k4) = shares[4];
        let wrong_k1 = Scalar::random(&mut OsRng);
        let wrong_k2 = Scalar::random(&mut OsRng);
        let wrong_k3 = Scalar::random(&mut OsRng);

        let set: Vec<ServerUnwrapShare> = vec![
            compute_server_share(wi0, wrong_k1, &wrapped),
            compute_server_share(wi1, wrong_k2, &wrapped),
            compute_server_share(wi2, wrong_k3, &wrapped),
            compute_server_share(wi3, k3, &wrapped),
            compute_server_share(wi4, k4, &wrapped),
        ];

        let err = unwrap_message_key(&params, &wrapped, &aad, &set).unwrap_err();
        assert!(matches!(err, BackupError::AllSubsetsFailedUnwrap));
    }

    #[test]
    fn unwrap_rejects_invalid_ephemeral_r() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x77; MESSAGE_KEY_LEN];
        let wrapped_valid = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        // Собираем валидные shares под original (valid) R...
        let set: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, ki)| compute_server_share(*wi, *ki, &wrapped_valid))
            .collect();

        // ...но подсовываем corrupted R в `wrapped` при вызове unwrap.
        let wrapped_corrupt = WrappedKey {
            version: wrapped_valid.version,
            ephemeral_r: [0xFFu8; POINT_LEN], // very likely invalid
            aead_blob: wrapped_valid.aead_blob,
        };

        let res = unwrap_message_key(&params, &wrapped_corrupt, &aad, &set);
        match res {
            Ok(_) => panic!("must not succeed with corrupted R"),
            Err(BackupError::InvalidRistrettoEncoding)
            | Err(BackupError::AllSubsetsFailedUnwrap) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_duplicate_witness() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0x77; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let (wi1, k1) = shares[0];
        let (wi2, k2) = shares[1];
        let set: Vec<ServerUnwrapShare> = vec![
            compute_server_share(wi1, k1, &wrapped),
            compute_server_share(wi2, k2, &wrapped),
            compute_server_share(wi2, k2, &wrapped), // duplicate
        ];

        let err = unwrap_message_key(&params, &wrapped, &aad, &set).unwrap_err();
        assert!(
            matches!(err, BackupError::DuplicateWitnessIndex(i) if i == wi2.get()),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn subset_combinations_generates_correct_count() {
        // C(5,3) = 10
        let all = subset_combinations(5, 3);
        assert_eq!(all.len(), 10);
        // Первое подмножество — [0,1,2].
        assert_eq!(all[0], vec![0, 1, 2]);
        // Последнее (в lexicographic) — [2,3,4].
        assert_eq!(all[9], vec![2, 3, 4]);
    }

    #[test]
    fn subset_combinations_empty_when_t_zero_or_greater_than_n() {
        assert!(subset_combinations(5, 0).is_empty());
        assert!(subset_combinations(3, 5).is_empty());
    }

    #[test]
    fn unwrap_consistent_with_no_retry_on_happy_path() {
        let (params, _k, shares) = make_params_and_shares();
        let aad = sample_aad();
        let mk = [0xAB; MESSAGE_KEY_LEN];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let set: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, ki)| compute_server_share(*wi, *ki, &wrapped))
            .collect();

        let a = unwrap_message_key(&params, &wrapped, &aad, &set).unwrap();
        let b = unwrap_message_key_no_retry(&params, &wrapped, &aad, &set).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, mk);
    }
}
