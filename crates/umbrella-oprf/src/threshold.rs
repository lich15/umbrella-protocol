//! Shamir 3-из-5 threshold combine для OPRF.
//! Shamir 3-of-5 threshold combine for OPRF.
//!
//! Клиент получает ответы от до 5 Sealed Servers. Каждый сервер `i` держит
//! долю `k_i = f(i)` общего секрета `k`, где `f` — случайный polynomial
//! степени 2 с `f(0) = k`. Клиент выбирает любые 3 из 5 валидных ответов и
//! восстанавливает общий OPRF-output через Lagrange combine:
//!
//! ```text
//! λ_i = ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)  mod q
//! E   = Σ_{i ∈ S} λ_i · E_i               (в группе Ristretto255)
//! ```
//!
//! где `S ⊂ {1..=5}`, `|S| = 3`, `E_i = k_i · B` — partial evaluation от
//! сервера `i`. Результат `E = k · B` алгебраически идентичен тому, что
//! вернул бы единственный сервер с полным `k`.
//!
//! Client obtains up to 5 responses from Sealed Servers. Each server `i`
//! holds share `k_i = f(i)` of the master secret `k` where `f` is a random
//! degree-2 polynomial with `f(0) = k`. Client picks any 3 valid responses
//! and reconstructs the full OPRF output via Lagrange combine. Result is
//! algebraically identical to a single-server evaluation under full `k`.
//!
//! Lagrange combine выполняется **на клиенте** (не на координаторе), что
//! снимает с координатора знания о подмножестве серверов-ответчиков. См.
//! ADR-005 §3 для обоснования.
//!
//! Lagrange combine runs **on the client**; see ADR-005 §3 for rationale.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::error::OprfError;
use crate::primitives::ServerEvaluation;

/// Порог по умолчанию: 3 из 5. Default threshold: 3 of 5.
pub const DEFAULT_THRESHOLD: u8 = 3;

/// Общее число серверов по умолчанию: 5. Default total servers: 5.
pub const DEFAULT_TOTAL: u8 = 5;

/// Индекс witness-сервера в диапазоне 1..=255 (в протоколе 1..=5).
/// Witness index, protocol range 1..=5.
///
/// Zero и индексы больше `DEFAULT_TOTAL` отвергаются конструктором — Shamir
/// требует `x ≠ 0` (иначе share раскрывает `k` напрямую).
///
/// Zero and indices > `DEFAULT_TOTAL` rejected by the constructor — Shamir
/// requires `x ≠ 0` or the share trivially leaks `k`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WitnessIndex(u8);

impl WitnessIndex {
    /// Создать с жёсткой проверкой диапазона. Construct with range check.
    ///
    /// # Errors
    /// - [`OprfError::UnknownWitnessIndex`] если `i == 0` или `i > DEFAULT_TOTAL`.
    pub const fn new(i: u8) -> Result<Self, OprfError> {
        if i == 0 || i > DEFAULT_TOTAL {
            Err(OprfError::UnknownWitnessIndex(i))
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
/// Инварианты (проверяются в `threshold_combine`):
/// - `threshold >= 1`,
/// - `total >= threshold`,
/// - `total <= DEFAULT_TOTAL` (расширение до больших total требует
///   пересмотра `WitnessIndex::new`).
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
    /// - [`OprfError::InsufficientValidEvaluations`] если параметры не
    ///   проходят инварианты (threshold=0, total < threshold, total > 5).
    pub const fn new(threshold: u8, total: u8) -> Result<Self, OprfError> {
        if threshold == 0 {
            return Err(OprfError::InsufficientValidEvaluations {
                valid: 0,
                required: 0,
            });
        }
        if total < threshold {
            return Err(OprfError::InsufficientValidEvaluations {
                valid: total as usize,
                required: threshold as usize,
            });
        }
        if total > DEFAULT_TOTAL {
            return Err(OprfError::UnknownWitnessIndex(total));
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

/// Собрать валидные partial evaluations 3-из-5 в combined `ServerEvaluation`.
/// Combine 3-of-5 valid partial evaluations into a combined `ServerEvaluation`.
///
/// Алгоритм:
/// 1. Валидировать каждый witness index (диапазон 1..=total, без повторов).
/// 2. Проверить что `shares.len() >= config.threshold`.
/// 3. Взять первые `config.threshold` shares (in arrival order).
/// 4. Для каждой share вычислить Lagrange coefficient `λ_i` относительно
///    выбранного подмножества, умножить partial evaluation, просуммировать.
/// 5. Сериализовать результат обратно в `ServerEvaluation`.
///
/// Algorithm:
/// 1. Validate each witness index (range, no duplicates).
/// 2. Ensure `shares.len() >= config.threshold`.
/// 3. Take the first `config.threshold` shares in arrival order.
/// 4. For each share compute Lagrange coefficient over the chosen subset,
///    multiply the partial evaluation, accumulate.
/// 5. Serialize the result back to `ServerEvaluation`.
///
/// # Errors
/// - [`OprfError::InsufficientValidEvaluations`] если shares.len() < threshold.
/// - [`OprfError::UnknownWitnessIndex`] если какой-то индекс вне диапазона.
/// - [`OprfError::DuplicateWitnessIndex`] если индекс повторяется.
/// - [`OprfError::InvalidRistrettoEncoding`] если байты партиала не
///   декодируются (инвариант `ServerEvaluation` гарантирует что нет, но
///   проверяем defense-in-depth).
pub fn threshold_combine(
    shares: &[(WitnessIndex, ServerEvaluation)],
    config: ThresholdConfig,
) -> Result<ServerEvaluation, OprfError> {
    // Базовая валидация конфига (на случай если пришёл собранный вручную).
    if config.threshold == 0 || config.total < config.threshold || config.total > DEFAULT_TOTAL {
        return Err(OprfError::InsufficientValidEvaluations {
            valid: 0,
            required: config.threshold as usize,
        });
    }

    // Dedup и диапазон witness index.
    let mut seen = [false; (DEFAULT_TOTAL + 1) as usize];
    for (wi, _) in shares {
        let i = wi.get();
        if i == 0 || i > config.total {
            return Err(OprfError::UnknownWitnessIndex(i));
        }
        let idx = i as usize;
        if seen[idx] {
            return Err(OprfError::DuplicateWitnessIndex(i));
        }
        seen[idx] = true;
    }

    if shares.len() < config.threshold as usize {
        return Err(OprfError::InsufficientValidEvaluations {
            valid: shares.len(),
            required: config.threshold as usize,
        });
    }

    // Берём первые threshold shares в порядке прибытия.
    let selected = &shares[..config.threshold as usize];

    // Декомпрессируем точки.
    let mut points: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
    for (wi, eval) in selected {
        let compressed = CompressedRistretto(*eval.as_bytes());
        let point = compressed
            .decompress()
            .ok_or(OprfError::InvalidRistrettoEncoding)?;
        points
            .push((wi.get(), point))
            .map_err(|_| OprfError::InsufficientValidEvaluations {
                valid: 0,
                required: config.threshold as usize,
            })?;
    }

    // Σ_{i ∈ S} λ_i · E_i
    let mut acc = RistrettoPoint::identity();
    for (i, pt_i) in &points {
        let lambda_i = lagrange_at_zero(*i, &points);
        acc += pt_i * lambda_i;
    }

    let compressed = acc.compress();
    Ok(ServerEvaluation::from_trusted_bytes(compressed.to_bytes()))
}

/// Lagrange coefficient для точки `i` относительно подмножества `points`,
/// оценённый в `x = 0`:
///
/// ```text
/// λ_i(0) = ∏_{(j, _) ∈ points, j ≠ i} (j · (j − i)⁻¹)  mod q
/// ```
///
/// Инвариант: у `points` нет повторов `j` (гарантировано caller'ом через
/// dedup); иначе `(j − i) = 0` и `invert()` не даст корректного ответа.
fn lagrange_at_zero(i: u8, points: &[(u8, RistrettoPoint)]) -> Scalar {
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

/// Тестовая утилита: Shamir-split приватного скаляра `k` в 5 долей.
/// Test helper: Shamir-split private scalar `k` into 5 shares.
///
/// Схема: случайный polynomial `f(x) = k + a_1·x + a_2·x² (mod q)` степени
/// `threshold − 1`. Для каждого сервера `i ∈ 1..=total` выдаётся
/// `share_i = f(i)`. Восстановление `k` требует любых `threshold` пар
/// `(i, f(i))` через Lagrange interpolation в `x = 0`.
///
/// Random polynomial of degree `threshold - 1` with `f(0) = k`. Server `i`
/// gets `share_i = f(i)`. Recovery of `k` requires any `threshold` pairs.
///
/// Используется только в тестах и интеграционном milestone 4.5. Production
/// ceremony в Umbrella server implementation использует ту же математику, но в SEV-SNP enclave.
///
/// Test-only and 4.5 milestone; production ceremony in Umbrella server implementation uses the
/// same math inside SEV-SNP enclave.
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
    coeffs.push(k).unwrap();
    for _ in 1..config.threshold {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: heapless capacity 8 ≥ threshold by ThresholdConfig invariant"
        )]
        coeffs.push(Scalar::random(rng)).unwrap();
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
        // SAFETY: 1..=config.total ⊆ 1..=DEFAULT_TOTAL, invariant config.
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
        out.push((wi, fx)).unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::input::OprfInput;
    use crate::label::OprfLabel;
    use crate::primitives::{
        blind, evaluate_for_testing, finalize, generate_test_private_key, SCALAR_LEN,
    };

    /// Helper: OPRF flow через single-сервер с известным k. Reference точка.
    fn single_server_oprf(input: &[u8], sk: &[u8; SCALAR_LEN]) -> OprfLabel {
        let oprf_input = OprfInput::new(input).unwrap();
        let (blinded, state) = blind(oprf_input, &mut OsRng).unwrap();
        let eval = evaluate_for_testing(&blinded, sk).unwrap();
        finalize(&state, oprf_input, &eval).unwrap()
    }

    /// Helper: threshold OPRF flow. Реконструкция через любые `selected_idxs`.
    fn threshold_oprf(
        input: &[u8],
        shares: &[(WitnessIndex, [u8; SCALAR_LEN])],
        selected_idxs: &[usize],
        config: ThresholdConfig,
    ) -> Result<OprfLabel, OprfError> {
        let oprf_input = OprfInput::new(input).unwrap();
        let (blinded, state) = blind(oprf_input, &mut OsRng).unwrap();

        let mut partial: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
        for &idx in selected_idxs {
            let (wi, sk) = shares[idx];
            let eval = evaluate_for_testing(&blinded, &sk)?;
            partial.push((wi, eval)).unwrap();
        }
        let combined = threshold_combine(&partial, config)?;
        finalize(&state, oprf_input, &combined)
    }

    /// Helper: создать 5 shares `k_i` из одного master `k`.
    fn make_shares(
        config: ThresholdConfig,
    ) -> ([u8; SCALAR_LEN], Vec<(WitnessIndex, [u8; SCALAR_LEN])>) {
        let master_sk = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk).unwrap();
        let raw_shares = shamir_split_for_testing(k, config, &mut OsRng);

        let shares: Vec<(WitnessIndex, [u8; SCALAR_LEN])> = raw_shares
            .iter()
            .map(|(wi, share)| (*wi, share.to_bytes()))
            .collect();
        (master_sk, shares)
    }

    #[test]
    fn witness_index_rejects_zero() {
        let err = WitnessIndex::new(0).unwrap_err();
        assert!(matches!(err, OprfError::UnknownWitnessIndex(0)));
    }

    #[test]
    fn witness_index_rejects_six() {
        let err = WitnessIndex::new(6).unwrap_err();
        assert!(matches!(err, OprfError::UnknownWitnessIndex(6)));
    }

    #[test]
    fn witness_index_accepts_one_through_five() {
        for i in 1..=5u8 {
            assert_eq!(WitnessIndex::new(i).unwrap().get(), i);
        }
    }

    #[test]
    fn config_rejects_zero_threshold() {
        let err = ThresholdConfig::new(0, 5).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InsufficientValidEvaluations { .. }
        ));
    }

    #[test]
    fn config_rejects_total_less_than_threshold() {
        let err = ThresholdConfig::new(4, 3).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InsufficientValidEvaluations { .. }
        ));
    }

    #[test]
    fn config_rejects_total_over_five() {
        let err = ThresholdConfig::new(3, 6).unwrap_err();
        assert!(matches!(err, OprfError::UnknownWitnessIndex(6)));
    }

    #[test]
    fn config_default_is_3_of_5() {
        let c = ThresholdConfig::default();
        assert_eq!(c.threshold, 3);
        assert_eq!(c.total, 5);
    }

    #[test]
    fn threshold_combine_3_of_5_reconstructs_single_server() {
        let config = ThresholdConfig::default();
        let (master_sk, shares) = make_shares(config);

        let reference = single_server_oprf(b"+12125551212", &master_sk);

        // Любой выбор 3 из 5 должен дать тот же label что один сервер с полным k.
        for combo in [
            &[0usize, 1, 2][..],
            &[1, 2, 3],
            &[2, 3, 4],
            &[0, 2, 4],
            &[0, 3, 4],
        ] {
            let via_threshold = threshold_oprf(b"+12125551212", &shares, combo, config).unwrap();
            assert_eq!(
                via_threshold, reference,
                "threshold failed for combo {combo:?}"
            );
        }
    }

    #[test]
    fn threshold_combine_rejects_below_threshold() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_shares(config);
        let err = threshold_oprf(b"x", &shares, &[0, 1], config).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InsufficientValidEvaluations {
                valid: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn threshold_combine_rejects_duplicate_index() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_shares(config);
        let oprf_input = OprfInput::new(b"x").unwrap();
        let (blinded, _state) = blind(oprf_input, &mut OsRng).unwrap();

        // Три элемента, но второй и третий — один и тот же WitnessIndex.
        let (wi_a, sk_a) = shares[0];
        let (wi_b, sk_b) = shares[1];
        let eval_a = evaluate_for_testing(&blinded, &sk_a).unwrap();
        let eval_b = evaluate_for_testing(&blinded, &sk_b).unwrap();
        let eval_b_dup = evaluate_for_testing(&blinded, &sk_b).unwrap();

        let vec: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = {
            let mut v: heapless::Vec<_, 8> = heapless::Vec::new();
            v.push((wi_a, eval_a)).unwrap();
            v.push((wi_b, eval_b)).unwrap();
            v.push((wi_b, eval_b_dup)).unwrap();
            v
        };
        let err = threshold_combine(&vec, config).unwrap_err();
        assert!(
            matches!(err, OprfError::DuplicateWitnessIndex(i) if i == wi_b.get()),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn threshold_combine_order_independence() {
        // Combined output не должен зависеть от порядка shares в массиве:
        // Lagrange формула симметрична.
        let config = ThresholdConfig::default();
        let (master_sk, shares) = make_shares(config);
        let reference = single_server_oprf(b"id", &master_sk);

        let l1 = threshold_oprf(b"id", &shares, &[0, 1, 2], config).unwrap();
        let l2 = threshold_oprf(b"id", &shares, &[2, 0, 1], config).unwrap();
        let l3 = threshold_oprf(b"id", &shares, &[1, 2, 0], config).unwrap();
        assert_eq!(l1, reference);
        assert_eq!(l2, reference);
        assert_eq!(l3, reference);
    }

    #[test]
    fn threshold_tampered_share_breaks_combine() {
        // Подмена одного partial evaluation в подмножестве из 3 ломает результат.
        // Но ВЫБОР другого подмножества (без tampered) — всё ещё корректный.
        let config = ThresholdConfig::default();
        let (master_sk, shares) = make_shares(config);
        let reference = single_server_oprf(b"x", &master_sk);

        let oprf_input = OprfInput::new(b"x").unwrap();
        let (blinded, state) = blind(oprf_input, &mut OsRng).unwrap();

        let (wi_a, sk_a) = shares[0];
        let (wi_b, _sk_b) = shares[1];
        let (wi_c, sk_c) = shares[2];

        let eval_a = evaluate_for_testing(&blinded, &sk_a).unwrap();
        // Tampered: evaluate with WRONG key.
        let wrong_sk = generate_test_private_key(&mut OsRng);
        let eval_b_bad = evaluate_for_testing(&blinded, &wrong_sk).unwrap();
        let eval_c = evaluate_for_testing(&blinded, &sk_c).unwrap();

        let shares_with_bad: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = {
            let mut v: heapless::Vec<_, 8> = heapless::Vec::new();
            v.push((wi_a, eval_a)).unwrap();
            v.push((wi_b, eval_b_bad)).unwrap();
            v.push((wi_c, eval_c)).unwrap();
            v
        };

        let combined_bad = threshold_combine(&shares_with_bad, config).unwrap();
        let label_bad = finalize(&state, oprf_input, &combined_bad).unwrap();
        // Результат с tampered share — отличается от reference.
        assert_ne!(label_bad, reference);

        // А правильные 3 из оставшихся (без tampered b) — совпадают.
        let correct = threshold_oprf(b"x", &shares, &[0, 2, 3], config).unwrap();
        assert_eq!(correct, reference);
    }

    #[test]
    fn lagrange_at_zero_sums_to_one() {
        // Свойство Lagrange базиса: Σ_{i ∈ S} λ_i(0) = 1 для любого S.
        // Тестируем для 3-из-5 subsets.
        let config = ThresholdConfig::default();
        let (_, shares) = make_shares(config);
        let oprf_input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(oprf_input, &mut OsRng).unwrap();

        let mut points: heapless::Vec<(u8, RistrettoPoint), 8> = heapless::Vec::new();
        for &(wi, sk) in &shares[..3] {
            let eval = evaluate_for_testing(&blinded, &sk).unwrap();
            let compressed = CompressedRistretto(*eval.as_bytes());
            points
                .push((wi.get(), compressed.decompress().unwrap()))
                .unwrap();
        }
        let sum: Scalar = points
            .iter()
            .map(|(i, _)| lagrange_at_zero(*i, &points))
            .sum();
        assert_eq!(sum, Scalar::ONE);
    }

    #[test]
    fn shamir_split_reconstructs_original_scalar() {
        // Проверяем, что Shamir-split → Lagrange combine скаляров в x=0
        // восстанавливает оригинал. Это fundamental для OPRF threshold.
        let config = ThresholdConfig::default();
        let master_sk = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk).unwrap();

        let raw_shares = shamir_split_for_testing(k, config, &mut OsRng);

        // Возьмём любые 3 из 5, восстановим k через Lagrange в x=0.
        for &subset in &[[0usize, 1, 2], [1, 2, 3], [2, 3, 4], [0, 2, 4], [0, 3, 4]] {
            let selected: heapless::Vec<(u8, Scalar), 8> = subset
                .iter()
                .map(|&i| (raw_shares[i].0.get(), raw_shares[i].1))
                .collect();

            // Используем upstream lagrange_at_zero, но для скаляров:
            // λ_i(0) вычислим напрямую, затем k_reconstructed = Σ λ_i · share_i.
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
                let lambda_i = num * den.invert();
                recon += lambda_i * share_i;
            }
            assert_eq!(
                recon, k,
                "Shamir reconstruction failed for subset {subset:?}"
            );
        }
    }
}
