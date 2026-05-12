//! Клиентский фасад над primitives + threshold.
//! Client-side facade over primitives + threshold.
//!
//! Экспортирует два уровня API:
//!
//! 1. [`ContactQuery`] — один идентификатор, полный flow blind → collect
//!    evaluations → threshold combine → finalize. Предназначен для
//!    ad-hoc запросов (добавление одного контакта).
//! 2. [`batch_contact_query`] + [`batch_finalize`] — батч 1..=1024
//!    идентификаторов, оптимизированный для sync первой адресной книги
//!    (~1000 номеров за один сеанс).
//!
//! API isolates callers from voprf-internals: вызывающая сторона видит
//! только типы `BlindedRequest`, `ServerEvaluation`, `OprfLabel`,
//! `BlindingState` (opaque). Threshold-параметры передаются через
//! [`ThresholdConfig`]; по умолчанию 3-из-5.
//!
//! Exports two layers: single-item `ContactQuery` and batch
//! `batch_contact_query` + `batch_finalize`. Callers never touch voprf
//! directly.

use rand_core::{CryptoRng, RngCore};

use crate::error::OprfError;
use crate::input::OprfInput;
use crate::label::OprfLabel;
use crate::primitives::{blind, finalize, BlindedRequest, BlindingState, ServerEvaluation};
use crate::threshold::{threshold_combine, ThresholdConfig, WitnessIndex};

/// Максимальный размер батча. Maximum batch size.
///
/// Типичная адресная книга смартфона ~200 контактов. 1024 даёт запас на
/// heavy users и роутинг-оптимизации. Больше — разбивается на несколько
/// последовательных батчей (ответственность вызывающей стороны).
///
/// Typical phone book is ~200 contacts. 1024 caps heavy users and routing
/// optimization. Larger sets must be chunked by the caller.
pub const MAX_BATCH_SIZE: usize = 1024;

/// Единичный OPRF-запрос. Single OPRF query.
///
/// Использование:
///
/// ```text
/// let (request, state) = ContactQuery::prepare(input, &mut rng)?;
/// // ... отправить request к 5 Sealed Servers, получить evaluations ...
/// let label = ContactQuery::finalize(&evaluations, &state, input, config)?;
/// ```
///
/// Tip: `input` должен совпадать между `prepare` и `finalize` — по этому же
/// `input` считается финальный hash.
///
/// Usage pattern: `prepare` → dispatch to Sealed Servers → `finalize` with
/// collected valid evaluations. Same `input` must be passed to both calls
/// because the final hash binds the input.
pub struct ContactQuery;

impl ContactQuery {
    /// Первый шаг: ослепить `input` и подготовить `BlindedRequest` для
    /// рассылки к Sealed Servers. First step: blind and prepare request.
    ///
    /// # Errors
    /// См. [`blind`].
    pub fn prepare<R: CryptoRng + RngCore>(
        input: OprfInput<'_>,
        rng: &mut R,
    ) -> Result<(BlindedRequest, BlindingState), OprfError> {
        blind(input, rng)
    }

    /// Финальный шаг: собрать 3-из-5 валидных evaluations через threshold
    /// combine, затем unblind + hash → [`OprfLabel`].
    ///
    /// # Errors
    /// - Ошибки [`threshold_combine`].
    /// - [`OprfError::VoprfInternal`] из финализации.
    pub fn finalize(
        evaluations: &[(WitnessIndex, ServerEvaluation)],
        state: &BlindingState,
        input: OprfInput<'_>,
        config: ThresholdConfig,
    ) -> Result<OprfLabel, OprfError> {
        let combined = threshold_combine(evaluations, config)?;
        finalize(state, input, &combined)
    }
}

/// Батч: ослепить N идентификаторов. Batch: blind N identifiers.
///
/// Возвращает параллельные вектора `requests[i]` и `states[i]` длины N.
/// Отправка: сериализовать все `requests` в один HTTP body (на стороне
/// Umbrella server implementation координатор поддерживает batch API).
///
/// # Errors
/// - [`OprfError::InvalidBatchSize`] если `inputs.is_empty()` или
///   `inputs.len() > MAX_BATCH_SIZE`.
/// - Ошибки [`blind`] для каждого элемента.
#[allow(clippy::type_complexity)]
pub fn batch_contact_query<R: CryptoRng + RngCore>(
    inputs: &[OprfInput<'_>],
    rng: &mut R,
) -> Result<(Vec<BlindedRequest>, Vec<BlindingState>), OprfError> {
    if inputs.is_empty() || inputs.len() > MAX_BATCH_SIZE {
        return Err(OprfError::InvalidBatchSize {
            got: inputs.len(),
            max: MAX_BATCH_SIZE,
        });
    }

    let mut requests = Vec::with_capacity(inputs.len());
    let mut states = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let (req, state) = blind(*inp, rng)?;
        requests.push(req);
        states.push(state);
    }
    Ok((requests, states))
}

/// Батч: финализация N threshold-combined labels.
/// Batch: finalize N threshold-combined labels.
///
/// `evaluations_per_position[i]` — `Vec<(WitnessIndex, ServerEvaluation)>`
/// для i-го запроса (каждый содержит до 5 evaluations от Sealed Servers).
/// `states[i]` — соответствующий `BlindingState`. `inputs[i]` — тот же
/// input что был в `batch_contact_query`.
///
/// # Errors
/// - [`OprfError::InvalidBatchSize`] если длины не совпадают или N=0.
/// - Любые ошибки [`ContactQuery::finalize`] — дойдут через `?`.
pub fn batch_finalize(
    evaluations_per_position: &[Vec<(WitnessIndex, ServerEvaluation)>],
    states: &[BlindingState],
    inputs: &[OprfInput<'_>],
    config: ThresholdConfig,
) -> Result<Vec<OprfLabel>, OprfError> {
    let n = evaluations_per_position.len();
    if n == 0 || n > MAX_BATCH_SIZE || states.len() != n || inputs.len() != n {
        return Err(OprfError::InvalidBatchSize {
            got: n,
            max: MAX_BATCH_SIZE,
        });
    }

    let mut labels = Vec::with_capacity(n);
    for i in 0..n {
        let label =
            ContactQuery::finalize(&evaluations_per_position[i], &states[i], inputs[i], config)?;
        labels.push(label);
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use super::*;
    use crate::primitives::{evaluate_for_testing, generate_test_private_key, SCALAR_LEN};
    use crate::threshold::shamir_split_for_testing;

    fn make_mock_cluster(
        config: ThresholdConfig,
    ) -> ([u8; SCALAR_LEN], Vec<(WitnessIndex, [u8; SCALAR_LEN])>) {
        let master_sk = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk).unwrap();
        let raw = shamir_split_for_testing(k, config, &mut OsRng);
        let shares: Vec<_> = raw.iter().map(|(wi, s)| (*wi, s.to_bytes())).collect();
        (master_sk, shares)
    }

    fn evaluate_at(
        shares: &[(WitnessIndex, [u8; SCALAR_LEN])],
        blinded: &BlindedRequest,
    ) -> Vec<(WitnessIndex, ServerEvaluation)> {
        shares
            .iter()
            .map(|(wi, sk)| {
                let eval = evaluate_for_testing(blinded, sk).unwrap();
                (*wi, eval)
            })
            .collect()
    }

    #[test]
    fn single_contact_query_happy_path() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_mock_cluster(config);

        let input = OprfInput::new(b"+12125551212").unwrap();
        let (req, state) = ContactQuery::prepare(input, &mut OsRng).unwrap();
        let evals = evaluate_at(&shares, &req);
        let label = ContactQuery::finalize(&evals, &state, input, config).unwrap();

        // Второй вызов с теми же параметрами даёт тот же label.
        let (req2, state2) = ContactQuery::prepare(input, &mut OsRng).unwrap();
        let evals2 = evaluate_at(&shares, &req2);
        let label2 = ContactQuery::finalize(&evals2, &state2, input, config).unwrap();
        assert_eq!(label, label2);
    }

    #[test]
    fn single_contact_query_fails_with_two_evaluations() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_mock_cluster(config);

        let input = OprfInput::new(b"x").unwrap();
        let (req, state) = ContactQuery::prepare(input, &mut OsRng).unwrap();
        let mut evals = evaluate_at(&shares, &req);
        evals.truncate(2);

        let err = ContactQuery::finalize(&evals, &state, input, config).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InsufficientValidEvaluations {
                valid: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn batch_rejects_empty() {
        let err = batch_contact_query::<OsRng>(&[], &mut OsRng).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InvalidBatchSize {
                got: 0,
                max: MAX_BATCH_SIZE
            }
        ));
    }

    #[test]
    fn batch_rejects_oversize() {
        // Без аллокации — используем тот же input во всём векторе.
        let inp = OprfInput::new(b"x").unwrap();
        let inputs = vec![inp; MAX_BATCH_SIZE + 1];
        let err = batch_contact_query(&inputs, &mut OsRng).unwrap_err();
        assert!(matches!(
            err,
            OprfError::InvalidBatchSize { got, max: MAX_BATCH_SIZE } if got == MAX_BATCH_SIZE + 1
        ));
    }

    #[test]
    fn batch_happy_path_5_contacts() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_mock_cluster(config);

        let raw_inputs: Vec<&[u8]> = vec![
            b"+12125551212",
            b"+4915112345678",
            b"alice@example.com",
            b"bob@example.com",
            b"+8613712345678",
        ];
        let inputs: Vec<OprfInput<'_>> = raw_inputs
            .iter()
            .map(|b| OprfInput::new(b).unwrap())
            .collect();

        let (requests, states) = batch_contact_query(&inputs, &mut OsRng).unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(states.len(), 5);

        let evals_per_pos: Vec<Vec<(WitnessIndex, ServerEvaluation)>> =
            requests.iter().map(|r| evaluate_at(&shares, r)).collect();

        let labels = batch_finalize(&evals_per_pos, &states, &inputs, config).unwrap();
        assert_eq!(labels.len(), 5);

        // Все labels различны (разные inputs).
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(
                    labels[i], labels[j],
                    "collision in labels[{i}] vs labels[{j}]"
                );
            }
        }
    }

    #[test]
    fn batch_finalize_rejects_mismatched_lengths() {
        let config = ThresholdConfig::default();
        let inp = OprfInput::new(b"x").unwrap();
        let (_, shares) = make_mock_cluster(config);
        let (req, state) = ContactQuery::prepare(inp, &mut OsRng).unwrap();
        let evals = evaluate_at(&shares, &req);

        // 2 evaluations_per_position, 1 state, 1 input: mismatch.
        let evals_2 = vec![evals.clone(), evals];
        let states_1 = vec![state];
        let inputs_1 = vec![inp];
        let err = batch_finalize(&evals_2, &states_1, &inputs_1, config).unwrap_err();
        assert!(matches!(err, OprfError::InvalidBatchSize { got: 2, .. }));
    }

    #[test]
    fn batch_label_matches_single_query_for_same_input() {
        let config = ThresholdConfig::default();
        let (_, shares) = make_mock_cluster(config);
        let inp = OprfInput::new(b"shared").unwrap();

        // Single-query path
        let (req_s, state_s) = ContactQuery::prepare(inp, &mut OsRng).unwrap();
        let evals_s = evaluate_at(&shares, &req_s);
        let label_single = ContactQuery::finalize(&evals_s, &state_s, inp, config).unwrap();

        // Batch-path с одним элементом
        let inputs = vec![inp];
        let (reqs, states) = batch_contact_query(&inputs, &mut OsRng).unwrap();
        let evals: Vec<_> = reqs.iter().map(|r| evaluate_at(&shares, r)).collect();
        let labels = batch_finalize(&evals, &states, &inputs, config).unwrap();

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], label_single);
    }
}
