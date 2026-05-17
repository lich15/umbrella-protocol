//! Ошибки слоя discovery — единая иерархия для PSI, username lookup,
//! KT-binding, rate-limit и replay-защиты.
//!
//! Errors of the discovery layer — a unified hierarchy for PSI, username
//! lookup, KT binding, rate limiting and replay protection.
//!
//! ## Семантика
//!
//! - Network / transport layer ошибки **не входят** сюда — они материализуются
//!   на уровне router/IO и оборачиваются в `DiscoveryError::TransportFailure`
//!   только если переданы клиентскому коду.
//! - Любая ошибка KT-bind (несовпадение proof, повреждённые байты, неверный
//!   epoch root) превращается в `KtBindFailed { kind }` чтобы клиент мог сразу
//!   reject ответа (D-3 mitigation).
//! - Replay-rejection — отдельный variant `ReplayDetected`, потому что D-5
//!   требует наблюдаемого fail-stop.

use thiserror::Error;

/// Тип неудачи при проверке KT-bind в discovery ответе.
/// Cause of a discovery KT-bind verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KtBindKind {
    /// Discovery-ответ пришёл без inclusion proof.
    /// Discovery response arrived without an inclusion proof.
    #[error("KT inclusion proof missing from discovery response")]
    ProofMissing,

    /// Inclusion proof не валидируется против заявленного root.
    /// Inclusion proof does not validate against the claimed root.
    #[error("KT inclusion proof does not match claimed epoch root")]
    ProofMismatch,

    /// Заявленный root отличается от того, что клиент уже зафиксировал
    /// для этой эпохи (split-view либо silent swap).
    /// The claimed root differs from the one already pinned by the client for
    /// this epoch (split-view or silent swap).
    #[error("KT epoch root forked from previously observed root")]
    RootForked,

    /// Поле `tree_size` либо `leaf_index` несовместимы с proof.
    /// `tree_size` or `leaf_index` inconsistent with the proof shape.
    #[error("KT inclusion proof shape inconsistent with tree size / leaf index")]
    ProofShapeInvalid,

    /// Leaf-payload (canonical encoding device_pubkey) повреждён / не
    /// соответствует ожиданиям клиента.
    /// Leaf payload (canonical device_pubkey encoding) is corrupted or does
    /// not match the client's expectation.
    #[error("KT leaf payload mismatched expected device pubkey encoding")]
    LeafPayloadMismatch,
}

/// Единый error-type для всех операций крейта.
/// Unified error type for all crate operations.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Любая ошибка OPRF слоя (blind/finalize, threshold combine, wire decode).
    /// Any OPRF-layer error (blind/finalize, threshold combine, wire decode).
    #[error("OPRF layer failure: {0}")]
    Oprf(#[from] umbrella_oprf::OprfError),

    /// Ошибка KT-bind проверки в discovery-ответе (D-3 attack mitigation).
    /// KT-bind verification error in a discovery response (D-3 mitigation).
    #[error("KT bind failed: {kind}")]
    KtBindFailed {
        /// Тип KT-bind отказа.
        /// Specific KT-bind failure kind.
        kind: KtBindKind,
    },

    /// Replay detected: пришёл ответ с уже использованным server nonce
    /// или client transcript binding (D-5 attack mitigation).
    /// Replay detected: a response arrived with an already-seen server nonce
    /// or client transcript binding (D-5 mitigation).
    #[error("replay detected: same server nonce or transcript binding observed twice")]
    ReplayDetected,

    /// Anon-id reuse в пределах одного rolling window: client invariant
    /// violated (D-6 mitigation). Должно быть невозможно by construction —
    /// indicates broken usage; ошибка escalates.
    /// Anon-id reuse inside one rolling window — client invariant violated
    /// (D-6 mitigation). Should be impossible by construction.
    #[error("anonymous-id reuse detected: same anon_id used for two queries")]
    AnonIdReuse,

    /// Превышена квота запросов discovery в текущем budget window (D-7
    /// mitigation). Caller должен подождать `retry_after_secs` и попробовать
    /// снова с свежим transcript binding.
    /// Discovery rate-limit budget exhausted (D-7 mitigation).
    #[error("rate-limit exhausted: retry after {retry_after_secs} seconds")]
    RateLimited {
        /// Сколько секунд ждать до следующей попытки.
        /// Seconds the caller must wait before retrying.
        retry_after_secs: u64,
    },

    /// Невалидный PSI-batch: размер выходит за пределы [1, MAX_PSI_BATCH].
    /// Invalid PSI batch size (out of [1, MAX_PSI_BATCH]).
    #[error("invalid PSI batch size {got}, must be in 1..={max}")]
    InvalidPsiBatchSize {
        /// Полученный размер.
        /// Received size.
        got: usize,
        /// Максимально допустимый.
        /// Maximum allowed.
        max: usize,
    },

    /// Wire format: нечитаемые байты, mismatched длина поля.
    /// Wire format: undecodable bytes, mismatched field length.
    #[error("wire decode error: {reason}")]
    WireDecode {
        /// Однострочное описание для error log.
        /// One-line description for the error log.
        reason: &'static str,
    },

    /// Внутренняя ошибка крипто-провайдера (HKDF expand, ChaCha20 nonce,
    /// HMAC verify) — fail-stop.
    /// Internal crypto provider failure (HKDF expand, ChaCha20 nonce, HMAC
    /// verify) — fail-stop.
    #[error("internal crypto failure: {0}")]
    CryptoInternal(&'static str),

    /// Не хватает валидных server responses чтобы достичь threshold.
    /// Insufficient valid server responses to reach threshold.
    #[error("insufficient server responses: got {valid}, need {required}")]
    InsufficientResponses {
        /// Сколько валидных пришло.
        /// How many valid responses arrived.
        valid: usize,
        /// Сколько требуется.
        /// How many are required.
        required: usize,
    },

    /// Wire-rejected: длина username/phone больше политики (256 байт max).
    /// Wire-rejected: username/phone longer than policy (256 bytes max).
    #[error("input rejected: {0}")]
    InputRejected(&'static str),

    /// Forge-detected: проверка username lookup encrypted record failed (HMAC
    /// либо AEAD tag mismatch). Server вернул impostor запись.
    /// Forge detected: username lookup encrypted record failed HMAC/AEAD tag.
    #[error("username lookup forge detected: encrypted record tag failed")]
    UsernameForgeDetected,
}

/// Сокращение `Result` с фиксированным `DiscoveryError`.
/// Shorthand `Result` with `DiscoveryError`.
pub type DiscoveryResult<T> = core::result::Result<T, DiscoveryError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_error_displays_retry_after() {
        let e = DiscoveryError::RateLimited {
            retry_after_secs: 42,
        };
        let s = format!("{e}");
        assert!(s.contains("42"));
    }

    #[test]
    fn kt_bind_kind_distinct_messages() {
        let kinds = [
            KtBindKind::ProofMissing,
            KtBindKind::ProofMismatch,
            KtBindKind::RootForked,
            KtBindKind::ProofShapeInvalid,
            KtBindKind::LeafPayloadMismatch,
        ];
        let messages: Vec<String> = kinds.iter().map(|k| format!("{k}")).collect();
        // Все 5 типов разные сообщения.
        let unique = messages
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn oprf_error_converts_through_from() {
        let oprf_err = umbrella_oprf::OprfError::InvalidRistrettoEncoding;
        let disc: DiscoveryError = oprf_err.into();
        assert!(matches!(disc, DiscoveryError::Oprf(_)));
    }

    #[test]
    fn anon_id_reuse_error_displays_distinct() {
        let e = DiscoveryError::AnonIdReuse;
        let s = format!("{e}");
        assert!(s.contains("anonymous-id reuse"));
    }

    #[test]
    fn replay_error_displays_distinct() {
        let e = DiscoveryError::ReplayDetected;
        let s = format!("{e}");
        assert!(s.contains("replay"));
    }

    #[test]
    fn username_forge_distinct_error() {
        let e = DiscoveryError::UsernameForgeDetected;
        let s = format!("{e}");
        assert!(s.contains("forge"));
    }
}
