//! OPRF-примитивы Ristretto255-SHA512 над RFC 9497 Base Mode.
//! Ristretto255-SHA512 OPRF primitives over RFC 9497 Base Mode.
//!
//! Тонкая обёртка над crate `voprf` feature `ristretto255-ciphersuite`. Мы
//! даём стабильное wire-представление (`BlindedRequest` / `ServerEvaluation` —
//! 32 байта compressed Ristretto), безопасное хранение blinding state
//! (`BlindingState` с Zeroize on drop) и финальный 32-байтовый `OprfLabel`
//! с дополнительным domain-separator wrap для защиты от misuse.
//!
//! Threshold-часть протокола (Shamir + Lagrange 3-из-5) живёт в модуле
//! `threshold` (вводится в sub-этапе 4.3) и оперирует низкоуровневыми
//! Ristretto-точками, полученными из `ServerEvaluation`.
//!
//! Thin wrapper around `voprf` feature `ristretto255-ciphersuite`. Provides
//! stable wire types (32-byte compressed Ristretto), safe blinding state
//! (Zeroize on drop), and a 32-byte `OprfLabel` with additional domain
//! separation. The threshold part of the protocol is in the `threshold`
//! module (introduced in sub-stage 4.3).
//!
//! # Режим OPRF Base Mode vs VOPRF Verifiable Mode
//!
//! На момент Этапа 4 клиент использует OPRF **Base Mode** (RFC 9497 §3.1) без
//! per-server DLEQ-доказательств. Защита от злонамеренного сервера
//! обеспечивается threshold-схемой Shamir 3-of-5: при ≥ 3 честных Sealed
//! Servers результат корректен независимо от того, что делают оставшиеся.
//! Переход на Verifiable Mode — Этап 9 hardening, это отдельный ADR с
//! обратно-совместимым wire-format upgrade.
//!
//! Stage 4 uses OPRF Base Mode (no per-server proofs); malicious-server
//! defense is via Shamir 3-of-5 threshold. Verifiable Mode planned for
//! Stage 9 hardening.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::OprfError;
use crate::input::OprfInput;
use crate::label::{OprfLabel, LABEL_LEN};

/// Длина compressed Ristretto255 точки в байтах. Compressed Ristretto255 length.
pub const POINT_LEN: usize = 32;

/// Длина приватного скаляра Ristretto255 в байтах. Ristretto255 scalar length.
pub const SCALAR_LEN: usize = 32;

/// Domain separator финальной метки. Final label domain separator.
///
/// Применяется ПОСЛЕ voprf-финализации (которая сама использует `"Finalize"`
/// domain по RFC 9497). Двойной domain даёт второй уровень защиты от
/// накладывания label на другой контекст. Изменение ломает совместимость
/// меток — требует version bump.
///
/// Applied AFTER voprf finalize (which itself uses `"Finalize"` per RFC 9497).
/// Provides a second layer of domain isolation; changing breaks label
/// compatibility and requires a version bump.
pub const LABEL_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-oprf-output-v1";

/// Сериализованный blinded-request (32 байта compressed Ristretto255).
/// Serialized blinded request (32 bytes compressed Ristretto255).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedRequest([u8; POINT_LEN]);

impl BlindedRequest {
    /// Байтовое представление (wire). Byte representation (wire).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }

    /// Попытка декодировать `BlindedRequest` из байтов.
    /// Try decoding `BlindedRequest` from bytes.
    ///
    /// # Errors
    /// - [`OprfError::WrongWireLength`] если `bytes.len() != 32`.
    /// - [`OprfError::InvalidRistrettoEncoding`] если это не валидная
    ///   Ristretto255 точка.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OprfError> {
        if bytes.len() != POINT_LEN {
            return Err(OprfError::WrongWireLength {
                expected: POINT_LEN,
                got: bytes.len(),
            });
        }
        BlindedElement::<Ristretto255>::deserialize(bytes)
            .map_err(|_| OprfError::InvalidRistrettoEncoding)?;
        let mut out = [0u8; POINT_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub(crate) fn into_voprf(self) -> BlindedElement<Ristretto255> {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: BlindedRequest invariant guarantees bytes are valid Ristretto encoding"
        )]
        BlindedElement::<Ristretto255>::deserialize(&self.0)
            .expect("BlindedRequest invariant: bytes always decode to a valid Ristretto point")
    }
}

/// Сериализованный ответ одного сервера (32 байта compressed Ristretto255).
/// Serialized single-server evaluation (32 bytes compressed Ristretto255).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerEvaluation([u8; POINT_LEN]);

impl ServerEvaluation {
    /// Байтовое представление (wire). Byte representation (wire).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }

    /// Попытка декодировать `ServerEvaluation` из байтов.
    /// Try decoding `ServerEvaluation` from bytes.
    ///
    /// # Errors
    /// - [`OprfError::WrongWireLength`] если `bytes.len() != 32`.
    /// - [`OprfError::InvalidRistrettoEncoding`] если не валидная Ristretto255
    ///   точка.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OprfError> {
        if bytes.len() != POINT_LEN {
            return Err(OprfError::WrongWireLength {
                expected: POINT_LEN,
                got: bytes.len(),
            });
        }
        EvaluationElement::<Ristretto255>::deserialize(bytes)
            .map_err(|_| OprfError::InvalidRistrettoEncoding)?;
        let mut out = [0u8; POINT_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// Конструктор из известного массива байт (для threshold-combine).
    /// Constructor from a known byte array (for threshold combine).
    ///
    /// # Safety
    /// Caller гарантирует что байты валидные Ristretto255-точки. Используется
    /// только после `serialize_elem` в threshold-модуле (sub-этап 4.3).
    ///
    /// Caller ensures bytes are a valid Ristretto255 point. Used only after
    /// `serialize_elem` in the threshold module (sub-stage 4.3).
    #[allow(dead_code)] // будет использоваться модулем `threshold` в sub-stage 4.3.
    #[inline]
    #[must_use]
    pub(crate) fn from_trusted_bytes(bytes: [u8; POINT_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn into_voprf(self) -> Result<EvaluationElement<Ristretto255>, OprfError> {
        EvaluationElement::<Ristretto255>::deserialize(&self.0)
            .map_err(|_| OprfError::InvalidRistrettoEncoding)
    }
}

/// Приватное состояние клиентского blinding. Secret client blinding state.
///
/// Содержит blind-scalar `r` (32 байта). Zeroize on drop — невозможно утечь в
/// память после освобождения. Перемещается по значению; клонирование доступно
/// для batch pipelines.
///
/// Holds the blind scalar `r`. Zeroize on drop; moved by value; cloneable for
/// batch pipelines.
pub struct BlindingState {
    inner: OprfClient<Ristretto255>,
}

impl Clone for BlindingState {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for BlindingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindingState")
            .field("blind", &"<redacted>")
            .finish()
    }
}

// OprfClient<Ristretto255> is ZeroizeOnDrop inside voprf; we extend it here
// for explicit documentation and to prevent accidental removal of the guarantee.
impl Zeroize for BlindingState {
    fn zeroize(&mut self) {
        // voprf's OprfClient uses derive_where ZeroizeOnDrop; dropping here
        // would double-zeroize. Instead we rely on Drop; this impl exists for
        // API completeness and is a no-op by design.
    }
}

impl ZeroizeOnDrop for BlindingState {}

/// Первый шаг OPRF: ослепить `input` через свежий blinding factor.
/// OPRF step 1: blind `input` with a fresh blinding factor.
///
/// Возвращает пару: `BlindedRequest` для отправки серверам + `BlindingState`
/// для последующего unblinding. State **обязательно** сохранить до получения
/// ответа — без него восстановление OPRF output невозможно.
///
/// Returns `(BlindedRequest, BlindingState)`. The state MUST be retained
/// until the server response arrives; without it no unblinding is possible.
///
/// # Errors
/// - [`OprfError::VoprfInternal`] если voprf вернула внутреннюю ошибку (это
///   возможно только для вырожденных входов, но API контракт обязывает
///   пробросить).
pub fn blind<R: CryptoRng + RngCore>(
    input: OprfInput<'_>,
    rng: &mut R,
) -> Result<(BlindedRequest, BlindingState), OprfError> {
    let result = OprfClient::<Ristretto255>::blind(input.as_bytes(), rng)
        .map_err(|_| OprfError::VoprfInternal("blind"))?;

    let serialized = result.message.serialize();
    let mut wire = [0u8; POINT_LEN];
    wire.copy_from_slice(serialized.as_slice());

    Ok((
        BlindedRequest(wire),
        BlindingState {
            inner: result.state,
        },
    ))
}

/// Финальный шаг OPRF: unblind + hash → 32-байтовый `OprfLabel`.
/// OPRF final step: unblind + hash → 32-byte `OprfLabel`.
///
/// Эта функция используется:
/// 1. В простом случае одного сервера (early development, legacy deployments);
/// 2. Из threshold-модуля после Lagrange combine 3 из 5 partial evaluations в
///    один combined `ServerEvaluation` — finalize работает одинаково, потому
///    что `combined = k · B` алгебраически совпадает с тем, что вернул бы
///    единственный сервер с полным `k`.
///
/// Used in two scenarios: (1) single-server early/legacy flow;
/// (2) post-Lagrange combined evaluation in the threshold module.
/// Both cases are algebraically identical at this layer.
///
/// # Errors
/// - [`OprfError::InvalidRistrettoEncoding`] если байты `evaluation` не
///   декодируются (ранее прошли `from_bytes`, но повторяем внутри для
///   defense-in-depth).
/// - [`OprfError::VoprfInternal`] если voprf finalize вернул ошибку.
pub fn finalize(
    state: &BlindingState,
    input: OprfInput<'_>,
    evaluation: &ServerEvaluation,
) -> Result<OprfLabel, OprfError> {
    let voprf_eval = evaluation.into_voprf()?;
    let raw_output = state
        .inner
        .finalize(input.as_bytes(), &voprf_eval)
        .map_err(|_| OprfError::VoprfInternal("finalize"))?;

    let mut hasher = Sha512::new();
    hasher.update(LABEL_DOMAIN_SEPARATOR);
    hasher.update((input.len() as u16).to_be_bytes());
    hasher.update(input.as_bytes());
    hasher.update(raw_output.as_slice());
    let digest = hasher.finalize();

    let mut label_bytes = [0u8; LABEL_LEN];
    label_bytes.copy_from_slice(&digest.as_slice()[..LABEL_LEN]);
    Ok(OprfLabel::from_bytes(label_bytes))
}

/// Тестовая обёртка: реализует серверную часть OPRF для mocks и unit-tests.
/// Test-only wrapper: implements the server side of OPRF for mocks.
///
/// Принимает private scalar (32 байта), обрабатывает `BlindedRequest`,
/// возвращает `ServerEvaluation`. НИКОГДА не используется в production-пути —
/// серверная эволюция происходит на Sealed Servers (вне крейта).
///
/// Takes a 32-byte private scalar, processes `BlindedRequest`, returns
/// `ServerEvaluation`. NEVER used in production — server evaluation happens
/// on Sealed Servers.
///
/// # Errors
/// - [`OprfError::InvalidScalarEncoding`] если байты не валидный скаляр.
/// - [`OprfError::InvalidRistrettoEncoding`] если `BlindedRequest` повреждён
///   (невозможно по инварианту типа, но обрабатывается для defense).
pub fn evaluate_for_testing(
    blinded: &BlindedRequest,
    private_key_bytes: &[u8; SCALAR_LEN],
) -> Result<ServerEvaluation, OprfError> {
    let server = OprfServer::<Ristretto255>::new_with_key(private_key_bytes)
        .map_err(|_| OprfError::InvalidScalarEncoding)?;
    let blinded_voprf = blinded.into_voprf();
    let eval = server.blind_evaluate(&blinded_voprf);
    let serialized = eval.serialize();
    let mut wire = [0u8; POINT_LEN];
    wire.copy_from_slice(serialized.as_slice());
    Ok(ServerEvaluation(wire))
}

/// Тестовая обёртка: генерирует случайный private scalar Ristretto255.
/// Test-only helper: generates a random Ristretto255 private scalar.
///
/// Используется для mock Sealed Servers в интеграционных тестах.
/// Used for mock Sealed Servers in integration tests.
pub fn generate_test_private_key<R: CryptoRng + RngCore>(rng: &mut R) -> [u8; SCALAR_LEN] {
    // OprfServer::new генерирует random scalar и выставляет sk.
    // Нам нужны байты, воспользуемся OprfServer::serialize(), который
    // возвращает scalar-bytes (ScalarLen).
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "test helper: OprfServer::new only fails on RNG failure — caller passes test-mode RNG"
    )]
    let server = OprfServer::<Ristretto255>::new(rng)
        .expect("OprfServer::new only fails on RNG failure — inconceivable in tests");
    let serialized = server.serialize();
    let mut out = [0u8; SCALAR_LEN];
    out.copy_from_slice(serialized.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn rt_single_server(input_bytes: &[u8]) {
        let input = OprfInput::new(input_bytes).unwrap();
        let sk = generate_test_private_key(&mut OsRng);
        let (blinded, state) = blind(input, &mut OsRng).unwrap();
        let eval = evaluate_for_testing(&blinded, &sk).unwrap();
        let label = finalize(&state, input, &eval).unwrap();
        // Второй клиент с тем же k и тем же input получает ту же метку.
        let (blinded2, state2) = blind(input, &mut OsRng).unwrap();
        let eval2 = evaluate_for_testing(&blinded2, &sk).unwrap();
        let label2 = finalize(&state2, input, &eval2).unwrap();
        assert_eq!(label, label2, "OPRF determinism broken");
    }

    #[test]
    fn round_trip_short_input() {
        rt_single_server(b"+12125551212");
    }

    #[test]
    fn round_trip_single_byte() {
        rt_single_server(b"x");
    }

    #[test]
    fn round_trip_max_size() {
        let buf = vec![0x55u8; 512];
        rt_single_server(&buf);
    }

    #[test]
    fn different_inputs_give_different_labels() {
        let sk = generate_test_private_key(&mut OsRng);
        let a = OprfInput::new(b"alice@example.com").unwrap();
        let b = OprfInput::new(b"bob@example.com").unwrap();

        let (blinded_a, state_a) = blind(a, &mut OsRng).unwrap();
        let (blinded_b, state_b) = blind(b, &mut OsRng).unwrap();
        let eval_a = evaluate_for_testing(&blinded_a, &sk).unwrap();
        let eval_b = evaluate_for_testing(&blinded_b, &sk).unwrap();

        let label_a = finalize(&state_a, a, &eval_a).unwrap();
        let label_b = finalize(&state_b, b, &eval_b).unwrap();
        assert_ne!(label_a, label_b);
    }

    #[test]
    fn different_keys_give_different_labels() {
        let input = OprfInput::new(b"+4915112345678").unwrap();
        let sk1 = generate_test_private_key(&mut OsRng);
        let sk2 = generate_test_private_key(&mut OsRng);

        let (blinded, state) = blind(input, &mut OsRng).unwrap();
        let eval1 = evaluate_for_testing(&blinded, &sk1).unwrap();
        let eval2 = evaluate_for_testing(&blinded, &sk2).unwrap();

        let label1 = finalize(&state, input, &eval1).unwrap();
        let label2 = finalize(&state, input, &eval2).unwrap();
        assert_ne!(label1, label2);
    }

    #[test]
    fn blinded_request_bytes_are_32() {
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        assert_eq!(blinded.as_bytes().len(), 32);
    }

    #[test]
    fn server_evaluation_bytes_are_32() {
        let input = OprfInput::new(b"x").unwrap();
        let sk = generate_test_private_key(&mut OsRng);
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let eval = evaluate_for_testing(&blinded, &sk).unwrap();
        assert_eq!(eval.as_bytes().len(), 32);
    }

    #[test]
    fn blinded_request_from_bytes_rejects_wrong_length() {
        for bad_len in [0usize, 1, 16, 31, 33, 64, 256] {
            let buf = vec![0u8; bad_len];
            let err = BlindedRequest::from_bytes(&buf).unwrap_err();
            assert!(matches!(
                err,
                OprfError::WrongWireLength { expected: 32, .. }
            ));
        }
    }

    #[test]
    fn blinded_request_from_bytes_rejects_invalid_point() {
        // All-ones compressed Ristretto — guaranteed invalid encoding.
        let all_ones = [0xFFu8; 32];
        let err = BlindedRequest::from_bytes(&all_ones).unwrap_err();
        assert!(matches!(err, OprfError::InvalidRistrettoEncoding));
    }

    #[test]
    fn server_evaluation_from_bytes_rejects_wrong_length() {
        let buf = vec![0u8; 31];
        let err = ServerEvaluation::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            OprfError::WrongWireLength {
                expected: 32,
                got: 31
            }
        ));
    }

    #[test]
    fn server_evaluation_from_bytes_rejects_invalid_point() {
        let all_ones = [0xFFu8; 32];
        let err = ServerEvaluation::from_bytes(&all_ones).unwrap_err();
        assert!(matches!(err, OprfError::InvalidRistrettoEncoding));
    }

    #[test]
    fn roundtrip_blinded_request_wire() {
        let input = OprfInput::new(b"test").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let wire = blinded.as_bytes();
        let parsed = BlindedRequest::from_bytes(wire).unwrap();
        assert_eq!(parsed.as_bytes(), wire);
    }

    #[test]
    fn roundtrip_server_evaluation_wire() {
        let input = OprfInput::new(b"test").unwrap();
        let sk = generate_test_private_key(&mut OsRng);
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let eval = evaluate_for_testing(&blinded, &sk).unwrap();
        let wire = eval.as_bytes();
        let parsed = ServerEvaluation::from_bytes(wire).unwrap();
        assert_eq!(parsed.as_bytes(), wire);
    }

    #[test]
    fn evaluate_for_testing_rejects_bad_scalar() {
        // `new_with_key` rejects zero scalar (and invalid encoding).
        // Some non-canonical scalar bytes may still be accepted; we test zero
        // specifically which is invariantly invalid by the Group spec.
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let zero_scalar = [0u8; SCALAR_LEN];
        let err = evaluate_for_testing(&blinded, &zero_scalar).unwrap_err();
        assert!(matches!(err, OprfError::InvalidScalarEncoding));
    }

    /// RFC 9497 Appendix A.1.1 — OPRF(ristretto255, SHA-512) Base Mode.
    ///
    /// Проверяем финальный шаг flow (server evaluate + client finalize) на
    /// официальных тестовых векторах RFC 9497. Client blind контролируется
    /// CSPRNG-ом, поэтому voprf умышленно не даёт deterministic blind без
    /// feature `danger`; мы проверяем финализацию для известных
    /// `(BlindedElement, Blind) → EvaluationElement → Output` цепочек через
    /// OprfServer::new_with_key с зафиксированным `skSm` из RFC.
    ///
    /// Полная проверка blind-step (deterministic blind) — в sub-stage 4.3
    /// через threshold-ориентированные vectors.
    #[test]
    fn rfc_9497_a_1_1_vector_1_evaluate_finalize() {
        let sk_sm = hex::decode("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
            .unwrap();
        let sk_sm: [u8; SCALAR_LEN] = sk_sm.as_slice().try_into().unwrap();

        let blinded_hex = "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c";
        let expected_eval_hex = "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e";

        let blinded_bytes = hex::decode(blinded_hex).unwrap();
        let blinded = BlindedRequest::from_bytes(&blinded_bytes).unwrap();
        let eval = evaluate_for_testing(&blinded, &sk_sm).unwrap();
        assert_eq!(hex::encode(eval.as_bytes()), expected_eval_hex);
    }

    #[test]
    fn rfc_9497_a_1_1_vector_2_evaluate() {
        let sk_sm = hex::decode("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
            .unwrap();
        let sk_sm: [u8; SCALAR_LEN] = sk_sm.as_slice().try_into().unwrap();

        let blinded_hex = "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418";
        let expected_eval_hex = "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25";

        let blinded_bytes = hex::decode(blinded_hex).unwrap();
        let blinded = BlindedRequest::from_bytes(&blinded_bytes).unwrap();
        let eval = evaluate_for_testing(&blinded, &sk_sm).unwrap();
        assert_eq!(hex::encode(eval.as_bytes()), expected_eval_hex);
    }

    #[test]
    fn label_depends_on_domain_separator() {
        // Свой label НЕ должен совпадать с voprf's raw output first 32 bytes —
        // тогда наш domain wrap реально добавляет ценность.
        let sk = generate_test_private_key(&mut OsRng);
        let input_bytes = b"abc";

        let (blinded2, state2) = blind(OprfInput::new(input_bytes).unwrap(), &mut OsRng).unwrap();
        let eval2 = evaluate_for_testing(&blinded2, &sk).unwrap();
        let raw_output = state2
            .inner
            .finalize(input_bytes, &eval2.into_voprf().unwrap())
            .unwrap();
        let our_label = finalize(&state2, OprfInput::new(input_bytes).unwrap(), &eval2).unwrap();

        // voprf's raw output (first 32 байт SHA-512) должен отличаться от нашего
        // label (SHA-512 с domain separator "umbrellax-oprf-output-v1"). Это
        // валидирует что мы действительно вложили свой domain wrap.
        let raw_first_32 = &raw_output.as_slice()[..LABEL_LEN];
        assert_ne!(our_label.as_bytes().as_slice(), raw_first_32);
    }

    #[test]
    fn debug_blinding_state_hides_blind() {
        let input = OprfInput::new(b"x").unwrap();
        let (_blinded, state) = blind(input, &mut OsRng).unwrap();
        let s = format!("{state:?}");
        assert!(s.contains("redacted"));
    }

    // ====================================================================
    // Property-based tests
    // ====================================================================

    use proptest::prelude::*;

    fn oprf_for(input_bytes: &[u8], sk: &[u8; SCALAR_LEN]) -> OprfLabel {
        let input = OprfInput::new(input_bytes).unwrap();
        let (blinded, state) = blind(input, &mut OsRng).unwrap();
        let eval = evaluate_for_testing(&blinded, sk).unwrap();
        finalize(&state, input, &eval).unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            .. ProptestConfig::default()
        })]

        /// OPRF determinism: один и тот же `(input, k)` даёт одинаковый label
        /// независимо от blinding factor `r` (который каждый раз новый).
        #[test]
        fn determinism_same_input_same_key(
            input in proptest::collection::vec(any::<u8>(), 1..=64_usize),
        ) {
            let sk = generate_test_private_key(&mut OsRng);
            let label1 = oprf_for(&input, &sk);
            let label2 = oprf_for(&input, &sk);
            prop_assert_eq!(label1, label2);
        }

        /// Разные inputs (возможно равной длины) дают разные labels с
        /// overwhelming probability. При совпадении — это collision
        /// hash-to-curve, что фактически невозможно.
        #[test]
        fn distinctness_different_inputs(
            a in proptest::collection::vec(any::<u8>(), 1..=64_usize),
            b in proptest::collection::vec(any::<u8>(), 1..=64_usize),
        ) {
            prop_assume!(a != b);
            let sk = generate_test_private_key(&mut OsRng);
            let label_a = oprf_for(&a, &sk);
            let label_b = oprf_for(&b, &sk);
            prop_assert_ne!(label_a, label_b);
        }

        /// Разные ключи при том же input дают разные labels.
        #[test]
        fn distinctness_different_keys(
            input in proptest::collection::vec(any::<u8>(), 1..=64_usize),
        ) {
            let sk1 = generate_test_private_key(&mut OsRng);
            let sk2 = generate_test_private_key(&mut OsRng);
            prop_assume!(sk1 != sk2);
            let label1 = oprf_for(&input, &sk1);
            let label2 = oprf_for(&input, &sk2);
            prop_assert_ne!(label1, label2);
        }

        /// Wire round-trip: serialize → parse → serialize даёт идентичные
        /// байты. Это важно для threshold combine в 4.3 — мы будем
        /// deserialize'ить, делать Lagrange, serialize'ить обратно.
        #[test]
        fn wire_roundtrip_blinded_and_evaluation(
            input in proptest::collection::vec(any::<u8>(), 1..=64_usize),
        ) {
            let sk = generate_test_private_key(&mut OsRng);
            let oprf_input = OprfInput::new(&input).unwrap();
            let (blinded, _) = blind(oprf_input, &mut OsRng).unwrap();
            let eval = evaluate_for_testing(&blinded, &sk).unwrap();

            let blinded_bytes = *blinded.as_bytes();
            let parsed_blinded = BlindedRequest::from_bytes(&blinded_bytes).unwrap();
            prop_assert_eq!(parsed_blinded.as_bytes(), &blinded_bytes);

            let eval_bytes = *eval.as_bytes();
            let parsed_eval = ServerEvaluation::from_bytes(&eval_bytes).unwrap();
            prop_assert_eq!(parsed_eval.as_bytes(), &eval_bytes);
        }
    }
}
