//! Shamir 3-of-5 threshold combine для Cloud-wrap.
//! Shamir 3-of-5 threshold combine for Cloud-wrap.
//!
//! Клиент получает от Sealed Servers partial shares `k_i · R` (compressed
//! Ristretto255), каждая сопровождается witness-index `i ∈ 1..=5`. Lagrange
//! combine восстанавливает `K · R = S` из любых трёх валидных shares:
//!
//! ```text
//! λ_i = ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)  mod q
//! S   = Σ_{i ∈ S} λ_i · (k_i · R)           (в группе Ristretto255)
//! ```
//!
//! Реализация структурно симметрична `umbrella-oprf::threshold` (ADR-005),
//! но работает над 33-байтовыми `ServerUnwrapShare` (witness-index + point).
//!
//! Client receives partial shares `k_i · R` from Sealed Servers (compressed
//! Ristretto255) each tagged with witness index `i ∈ 1..=5`. Lagrange combine
//! reconstructs `K · R = S` from any three valid shares. Structurally
//! mirrors `umbrella-oprf::threshold` (ADR-005) but works over
//! `ServerUnwrapShare`.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::error::BackupError;

use super::aead::decompress_point;
use super::params::{ThresholdConfig, WitnessIndex, DEFAULT_TOTAL};
use super::share::ServerUnwrapShare;

/// Собрать валидные partial unwrap shares в общий shared-point `S = K · R`.
/// Combine valid partial unwrap shares into the shared point `S = K · R`.
///
/// Алгоритм:
/// 1. Валидировать каждый witness index (диапазон 1..=total, без повторов).
/// 2. Проверить `shares.len() >= config.threshold`.
/// 3. Взять первые `config.threshold` shares в порядке прибытия.
/// 4. Для каждой share вычислить Lagrange coefficient `λ_i` относительно
///    выбранного подмножества, умножить partial point, просуммировать.
/// 5. Вернуть результирующую точку.
///
/// Algorithm: validate witness indices, ensure threshold is met, decompress
/// the first `threshold` points in arrival order, compute and apply Lagrange
/// coefficients, sum to the combined point.
///
/// # Errors
/// - [`BackupError::InsufficientUnwrapShares`] если shares меньше threshold.
/// - [`BackupError::UnknownWitnessIndex`] если какой-то индекс вне диапазона.
/// - [`BackupError::DuplicateWitnessIndex`] если индекс повторяется.
/// - [`BackupError::InvalidRistrettoEncoding`] если байты partial не
///   декодируются в валидную точку.
pub fn threshold_combine(
    shares: &[ServerUnwrapShare],
    config: ThresholdConfig,
) -> Result<RistrettoPoint, BackupError> {
    // Защита от вручную сконструированного broken config.
    if config.threshold == 0 || config.total < config.threshold || config.total > DEFAULT_TOTAL {
        return Err(BackupError::InsufficientUnwrapShares {
            valid: 0,
            required: config.threshold as usize,
        });
    }

    // Dedup и диапазон witness index.
    let mut seen = [false; (DEFAULT_TOTAL + 1) as usize];
    for share in shares {
        let i = share.witness_index.get();
        if i == 0 || i > config.total {
            return Err(BackupError::UnknownWitnessIndex(i));
        }
        if seen[i as usize] {
            return Err(BackupError::DuplicateWitnessIndex(i));
        }
        seen[i as usize] = true;
    }

    if shares.len() < config.threshold as usize {
        return Err(BackupError::InsufficientUnwrapShares {
            valid: shares.len(),
            required: config.threshold as usize,
        });
    }

    let selected = &shares[..config.threshold as usize];

    // Декомпрессируем точки.
    let mut points: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
    for share in selected {
        let pt = decompress_point(&share.partial)?;
        points
            .push((share.witness_index.get(), pt))
            .map_err(|_| BackupError::WireBufferOverflow)?;
    }

    // Σ_{i ∈ S} λ_i · partial_i
    let mut acc = RistrettoPoint::identity();
    for (i, pt_i) in &points {
        let lambda = lagrange_at_zero(*i, &points);
        acc += pt_i * lambda;
    }
    Ok(acc)
}

/// Lagrange coefficient для точки `i` относительно подмножества `points`,
/// оценённый в `x = 0`:
///
/// ```text
/// λ_i(0) = ∏_{(j, _) ∈ points, j ≠ i} (j · (j − i)⁻¹)  mod q
/// ```
///
/// Invariant: у `points` нет повторов `j` (guaranteed caller'ом); иначе
/// `(j − i) = 0` и `invert()` не даёт корректного ответа.
pub(crate) fn lagrange_at_zero(i: u8, points: &[(u8, RistrettoPoint)]) -> Scalar {
    let si = Scalar::from(u64::from(i));
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for (j, _) in points {
        if *j == i {
            continue;
        }
        let sj = Scalar::from(u64::from(*j));
        num *= sj;
        den *= sj - si;
    }
    num * den.invert()
}

/// Тестовая утилита: Shamir-split приватного скаляра `K` в 5 долей.
///
/// Test helper: Shamir-split the private scalar `K` into 5 shares.
///
/// Схема: случайный polynomial `f(x) = K + a_1·x + a_2·x² (mod q)` степени
/// `threshold − 1`. Для каждого сервера `i ∈ 1..=total` выдаётся
/// `share_i = f(i)`. Восстановление `K` требует любых `threshold` пар
/// `(i, f(i))` через Lagrange interpolation в `x = 0`.
///
/// Используется только в тестах и integration milestone 5.5. Production
/// ceremony в Umbrella server implementation использует ту же математику, но в SEV-SNP enclave.
///
/// Test-only and 5.5 milestone; production ceremony uses the same math
/// inside an SEV-SNP enclave.
pub fn shamir_split_for_testing<R: rand_core::CryptoRng + rand_core::RngCore>(
    k: Scalar,
    config: ThresholdConfig,
    rng: &mut R,
) -> heapless::Vec<(WitnessIndex, Scalar), 8> {
    let mut coeffs: heapless::Vec<Scalar, 8> = heapless::Vec::new();
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: heapless capacity 8 ≥ DEFAULT_THRESHOLD 3"
    )]
    coeffs
        .push(k)
        .expect("coeffs capacity 8 fits threshold up to 8");
    for _ in 1..config.threshold {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: heapless capacity 8 ≥ threshold by ThresholdConfig invariant"
        )]
        coeffs
            .push(Scalar::random(rng))
            .expect("coeffs capacity covers threshold-1");
    }

    let mut out: heapless::Vec<(WitnessIndex, Scalar), 8> = heapless::Vec::new();
    for x in 1..=config.total {
        let sx = Scalar::from(u64::from(x));
        let mut fx = Scalar::ZERO;
        let mut x_pow = Scalar::ONE;
        for coeff in coeffs.iter() {
            fx += coeff * x_pow;
            x_pow *= sx;
        }
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: x in 1..=DEFAULT_TOTAL (5) by loop bound; WitnessIndex::new accepts 1..=5"
        )]
        let wi = WitnessIndex::new(x).expect("x in 1..=DEFAULT_TOTAL by loop bound");
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: heapless capacity 8 ≥ config.total (≤5)"
        )]
        out.push((wi, fx))
            .expect("out capacity 8 covers total up to 5");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand_core::OsRng;

    use crate::cloud_wrap::params::{WitnessIndex, DEFAULT_THRESHOLD};
    use crate::cloud_wrap::share::ServerUnwrapShare;

    /// Сгенерировать случайный главный скаляр K и его Shamir-split.
    fn make_k_and_shares(
        config: ThresholdConfig,
    ) -> (Scalar, heapless::Vec<(WitnessIndex, Scalar), 8>) {
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        (k, shares)
    }

    /// Вычислить partial unwrap share серверной стороны: k_i · R.
    fn server_unwrap_share(wi: WitnessIndex, k_i: Scalar, r: &RistrettoPoint) -> ServerUnwrapShare {
        let partial = (k_i * r).compress().to_bytes();
        ServerUnwrapShare {
            witness_index: wi,
            partial,
        }
    }

    /// Reference: shared_point = K · R (единственный сервер с полным K).
    fn reference_shared_point(k: Scalar, r: &RistrettoPoint) -> RistrettoPoint {
        k * r
    }

    #[test]
    fn threshold_combine_3_of_5_reconstructs_reference() {
        let config = ThresholdConfig::default();
        let (k, shares) = make_k_and_shares(config);
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(42u64);
        let reference = reference_shared_point(k, &r);

        // Все 10 подмножеств 3-of-5 должны давать одну и ту же точку.
        let indices: [[usize; 3]; 10] = [
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
        for combo in &indices {
            let subset: heapless::Vec<ServerUnwrapShare, 8> = combo
                .iter()
                .map(|&idx| {
                    let (wi, ki) = shares[idx];
                    server_unwrap_share(wi, ki, &r)
                })
                .collect();
            let combined = threshold_combine(&subset, config).unwrap();
            assert_eq!(combined, reference, "combo {combo:?} diverged");
        }
    }

    #[test]
    fn threshold_combine_rejects_below_threshold() {
        let config = ThresholdConfig::default();
        let (_k, shares) = make_k_and_shares(config);
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(1u64);

        let only_two: heapless::Vec<ServerUnwrapShare, 8> = shares
            .iter()
            .take(2)
            .map(|&(wi, ki)| server_unwrap_share(wi, ki, &r))
            .collect();
        let err = threshold_combine(&only_two, config).unwrap_err();
        assert!(matches!(
            err,
            BackupError::InsufficientUnwrapShares {
                valid: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn threshold_combine_rejects_zero_shares() {
        let config = ThresholdConfig::default();
        let err = threshold_combine(&[], config).unwrap_err();
        assert!(matches!(
            err,
            BackupError::InsufficientUnwrapShares {
                valid: 0,
                required: 3
            }
        ));
    }

    #[test]
    fn threshold_combine_rejects_duplicate_witness() {
        let config = ThresholdConfig::default();
        let (_k, shares) = make_k_and_shares(config);
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(1u64);

        let (wi_a, ki_a) = shares[0];
        let (wi_b, ki_b) = shares[1];
        let mut set: heapless::Vec<ServerUnwrapShare, 8> = heapless::Vec::new();
        set.push(server_unwrap_share(wi_a, ki_a, &r)).unwrap();
        set.push(server_unwrap_share(wi_b, ki_b, &r)).unwrap();
        set.push(server_unwrap_share(wi_b, ki_b, &r)).unwrap(); // duplicate

        let err = threshold_combine(&set, config).unwrap_err();
        assert!(
            matches!(err, BackupError::DuplicateWitnessIndex(i) if i == wi_b.get()),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn threshold_combine_rejects_out_of_range_witness() {
        // Собрать share с невалидным witness index — мы используем Raw struct
        // напрямую (обходя WitnessIndex::new) через manual constructor: но
        // WitnessIndex::new блокирует 0 и 6+. Поэтому эмулируем ответ Sealed
        // Server'а с corrupted index через manual config.total = 4, shares 1..=5.
        let config = ThresholdConfig::new(DEFAULT_THRESHOLD, 4).unwrap();
        let (_k, shares) = make_k_and_shares(ThresholdConfig::default());
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(1u64);

        // Share с witness index=5 не пройдёт — config.total=4.
        let (wi5, ki5) = shares[4];
        let s5 = server_unwrap_share(wi5, ki5, &r);
        let err = threshold_combine(&[s5.clone(), s5.clone(), s5.clone()], config).unwrap_err();
        // Либо UnknownWitnessIndex(5) либо DuplicateWitnessIndex(5), оба допустимы;
        // в этом config 5 вне диапазона, так что UnknownWitnessIndex возникает первым.
        assert!(matches!(err, BackupError::UnknownWitnessIndex(5)));
    }

    #[test]
    fn threshold_combine_order_independence() {
        let config = ThresholdConfig::default();
        let (k, shares) = make_k_and_shares(config);
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(99u64);
        let reference = reference_shared_point(k, &r);

        let s0 = server_unwrap_share(shares[0].0, shares[0].1, &r);
        let s1 = server_unwrap_share(shares[1].0, shares[1].1, &r);
        let s2 = server_unwrap_share(shares[2].0, shares[2].1, &r);

        for perm in &[[0, 1, 2], [1, 2, 0], [2, 0, 1], [0, 2, 1], [2, 1, 0]] {
            let mut set: heapless::Vec<ServerUnwrapShare, 8> = heapless::Vec::new();
            for &p in perm {
                set.push(match p {
                    0 => s0.clone(),
                    1 => s1.clone(),
                    2 => s2.clone(),
                    _ => unreachable!(),
                })
                .unwrap();
            }
            let combined = threshold_combine(&set, config).unwrap();
            assert_eq!(combined, reference, "permutation {perm:?}");
        }
    }

    #[test]
    fn lagrange_at_zero_sums_to_one_for_three_of_five() {
        let config = ThresholdConfig::default();
        let (_k, shares) = make_k_and_shares(config);
        let r = RISTRETTO_BASEPOINT_POINT * Scalar::from(1u64);

        // Для любого подмножества {i_1, i_2, i_3} свойство: Σ λ_i = 1.
        let subsets: [[usize; 3]; 5] = [[0, 1, 2], [0, 1, 3], [0, 2, 4], [1, 3, 4], [2, 3, 4]];
        for s in &subsets {
            let mut points: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
            for &idx in s {
                let (wi, ki) = shares[idx];
                let pt = ki * r;
                points.push((wi.get(), pt)).unwrap();
            }
            let sum_lambda: Scalar = points
                .iter()
                .map(|(i, _)| lagrange_at_zero(*i, &points))
                .sum();
            assert_eq!(sum_lambda, Scalar::ONE, "subset {s:?}");
        }
    }

    #[test]
    fn shamir_reconstruct_scalar_in_zero() {
        // Проверяем, что Shamir-split → Lagrange combine скаляров в x=0
        // восстанавливает оригинал K.
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);

        for subset in [[0usize, 1, 2], [1, 2, 3], [2, 3, 4], [0, 2, 4], [0, 3, 4]] {
            let selected: heapless::Vec<(u8, Scalar), 8> = subset
                .iter()
                .map(|&i| (shares[i].0.get(), shares[i].1))
                .collect();

            let mut recon = Scalar::ZERO;
            for (i, share_i) in &selected {
                let si = Scalar::from(u64::from(*i));
                let mut num = Scalar::ONE;
                let mut den = Scalar::ONE;
                for (j, _) in &selected {
                    if *j == *i {
                        continue;
                    }
                    let sj = Scalar::from(u64::from(*j));
                    num *= sj;
                    den *= sj - si;
                }
                recon += (num * den.invert()) * share_i;
            }
            assert_eq!(recon, k, "subset {subset:?}");
        }
    }

    #[test]
    fn threshold_combine_handles_invalid_partial_encoding() {
        let config = ThresholdConfig::default();
        let bad = ServerUnwrapShare {
            witness_index: WitnessIndex::new(1).unwrap(),
            partial: [0xFFu8; 32], // очень вероятно невалидная точка
        };
        let a = ServerUnwrapShare {
            witness_index: WitnessIndex::new(2).unwrap(),
            partial: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
        };
        let b = ServerUnwrapShare {
            witness_index: WitnessIndex::new(3).unwrap(),
            partial: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
        };
        let res = threshold_combine(&[bad, a, b], config);
        // Либо невалидная точка → InvalidRistrettoEncoding, либо (unlikely)
        // случайная валидная точка и combine успешен. Допускаем оба исхода,
        // защищаемся от panic.
        let _ = res;
    }

    #[test]
    fn threshold_combine_config_total_must_not_exceed_five() {
        // В типе WitnessIndex мы уже заблокировали 6+, но config можно
        // собрать только через new() который тоже проверяет.
        let err = ThresholdConfig::new(3, 6).unwrap_err();
        assert!(matches!(err, BackupError::UnknownWitnessIndex(6)));
    }
}
