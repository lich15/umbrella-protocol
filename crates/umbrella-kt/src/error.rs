//! Ошибки Key Transparency клиента.
//! Key Transparency client errors.

use thiserror::Error;

/// Псевдоним Result для крейта. Crate result alias.
pub type Result<T, E = KtError> = core::result::Result<T, E>;

/// Ошибки проверки KT-доказательств.
/// KT proof verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KtError {
    /// Merkle inclusion proof не сходится с указанным корнем.
    /// Merkle inclusion proof does not match the expected root.
    #[error("merkle inclusion proof root mismatch")]
    InclusionRootMismatch,

    /// Leaf index за пределами размера дерева.
    /// Leaf index is beyond the tree size.
    #[error("leaf index {index} is outside tree of size {tree_size}")]
    LeafIndexOutOfRange {
        /// Запрошенный индекс. Requested index.
        index: u64,
        /// Размер дерева. Tree size.
        tree_size: u64,
    },

    /// Длина audit path не соответствует размеру дерева и индексу.
    /// Audit path length does not match tree size and index.
    #[error("audit path length {got} invalid for tree size {tree_size}, index {index} (expected {expected})")]
    InvalidProofLength {
        /// Размер дерева. Tree size.
        tree_size: u64,
        /// Индекс листа. Leaf index.
        index: u64,
        /// Ожидаемая длина. Expected length.
        expected: usize,
        /// Фактическая длина. Actual length.
        got: usize,
    },

    /// Размер дерева нулевой (не может содержать лист).
    /// Tree size is zero (cannot contain a leaf).
    #[error("tree size is zero — no leaves can exist")]
    EmptyTree,

    /// Self-monitoring: identity-ключ в KT-записи не совпадает с ожидаемым.
    /// Self-monitoring: identity key in the KT entry does not match the expected one.
    #[error("self-monitoring mismatch in field {field}")]
    SelfMonitoringMismatch {
        /// Имя поля с расхождением. Field name with mismatch.
        field: &'static str,
    },

    /// Canonical encoding записи длиннее допустимого (защита от resource exhaustion).
    /// Canonical entry encoding longer than allowed (resource exhaustion guard).
    #[error("entry encoding too large: {got} bytes (max {max})")]
    EntryTooLarge {
        /// Фактический размер. Actual size.
        got: usize,
        /// Максимум. Maximum.
        max: usize,
    },

    /// Недостаточно валидных witness-подписей для принятия эпохи.
    /// Insufficient valid witness signatures to accept the epoch.
    #[error("insufficient valid witness signatures: got {valid}, required {required}")]
    InsufficientValidSignatures {
        /// Количество валидных уникальных подписей. Number of valid unique signatures.
        valid: usize,
        /// Требуемый порог. Required threshold.
        required: usize,
    },

    /// Public KT observation is malformed or cannot represent a valid trust decision.
    /// Публичное KT-наблюдение испорчено или не может дать валидное решение доверия.
    #[error("invalid KT observation: {0}")]
    InvalidObservation(&'static str),

    // ADR-008 расширения (блок 5.7.3). SPEC-09 §7.4 (error variants).
    // ADR-008 extensions (block 5.7.3). SPEC-09 §7.4 (error variants).
    /// Общая ошибка entry-уровня: некорректный inter-entry state, нарушение
    /// epoch-monotonicity, duplicate publish, и т.п. Сопровождается стабильной
    /// строкой-тегом (SPEC-09 §7.4 `InvalidEntry(&'static str)`).
    ///
    /// Generic entry-layer error: inconsistent inter-entry state, epoch
    /// monotonicity violation, duplicate publish, etc. Carries a stable string
    /// tag (SPEC-09 §7.4 `InvalidEntry(&'static str)`).
    #[error("invalid entry: {0}")]
    InvalidEntry(&'static str),

    /// Подпись entry (approval / revocation / rotation) не прошла проверку
    /// над canonical signing input с ожидаемым pubkey. SPEC-09 §7.4
    /// `EntrySignatureInvalid`.
    ///
    /// Entry signature (approval / revocation / rotation) failed to verify
    /// over the canonical signing input with the expected pubkey. SPEC-09 §7.4
    /// `EntrySignatureInvalid`.
    #[error("entry signature verification failed")]
    EntrySignatureInvalid,

    /// `apply_authorization_approval` не нашёл device-entry в состоянии `Pending` для
    /// `new_device_pubkey`. Без pending-entry approval семантически некорректен:
    /// либо entry ещё не опубликован, либо уже в Active/Revoked.
    ///
    /// `apply_authorization_approval` did not find a `Pending` device-entry for
    /// `new_device_pubkey`. Without a pending entry the approval is semantically
    /// invalid: either the entry was never published or it is already Active/Revoked.
    #[error("authorization approval references a device without a pending entry")]
    PendingStateNotFound,

    /// Approver / revoker не в состоянии `Active` в текущем log mirror. По ADR-008
    /// одобрять и отзывать устройства могут только уже активные устройства того же
    /// identity (либо `BootstrapActive` при первом approval catastrophic-recovery).
    ///
    /// The approver / revoker is not in the `Active` state in the current log
    /// mirror. Per ADR-008 only already-active devices of the same identity may
    /// approve and revoke other devices (with `BootstrapActive` as the one exception
    /// for the first catastrophic-recovery approval).
    #[error("authorization approver / revoker is not an active device")]
    ApproverNotActive,

    /// `BootstrapActive` state использован вне двух легитимных сценариев
    /// (primary bootstrap либо catastrophic-recovery bootstrap) — SPEC-09 §7.2
    /// правило 4. Попытка bootstrap'нуть в log где уже есть другие device-entries
    /// под тем же identity.
    ///
    /// `BootstrapActive` state used outside the two legitimate scenarios (primary
    /// bootstrap or catastrophic-recovery bootstrap) — SPEC-09 §7.2 rule 4.
    /// An attempt to bootstrap into a log that already contains other
    /// device-entries under the same identity.
    #[error("bootstrap-active state not allowed in this scenario")]
    BootstrapNotAllowed,

    /// `IdentityRotationRecord` содержит инвалидную пару подписей (старый/новый
    /// identity). По SPEC-12 §A.5.1 обе подписи обязаны пройти verify над
    /// одинаковым canonical input — это защита от MITM где один из identity-keys
    /// подменён.
    ///
    /// `IdentityRotationRecord` carries an invalid pair of signatures (old/new
    /// identity). Per SPEC-12 §A.5.1 both must verify over the same canonical
    /// input — protection against MITM substitution of either identity key.
    #[error("identity rotation dual signature verification failed")]
    RotationDualSignatureFailed,

    /// `old_identity_pubkey` в `IdentityRotationRecord` не совпадает с текущим
    /// `current_identity_pubkey` в log mirror — попытка ротировать identity
    /// которого нет в логе либо применить rotation дважды.
    ///
    /// `old_identity_pubkey` in `IdentityRotationRecord` does not match the
    /// current `current_identity_pubkey` in the log mirror — an attempt to
    /// rotate an identity not in the log or to apply the rotation twice.
    #[error("identity rotation old_identity_pubkey mismatch with log state")]
    RotationOldIdentityMismatch,

    /// `old_identity_pubkey == new_identity_pubkey` в `IdentityRotationRecord`.
    /// По ADR-008 ротация обязана менять identity — тождественная rotation
    /// бессмысленна и отвергается на уровне parser'а и на уровне apply.
    ///
    /// `old_identity_pubkey == new_identity_pubkey` in `IdentityRotationRecord`.
    /// Per ADR-008 rotation must change the identity — identity-unchanged
    /// rotation is meaningless and is rejected at parse time and at apply time.
    #[error("identity rotation old and new pubkeys are identical")]
    RotationIdenticalPubkeys,

    // Этап 8 расширения (блок 8.5). KT v2 schema (design.md §8 + ADR-011 Решение 6).
    // Stage 8 extensions (block 8.5). KT v2 schema (design.md §8 + ADR-011 Decision 6).
    /// Первый байт wire-format entry не соответствует ни одной известной
    /// версии. V1 entries (existing 0.0.11 wire format) **не имеют** version
    /// stamp в `KtEntry::canonical_encoding` и не парсятся через
    /// `KtEntryVersion::try_from` — они конструируются как Rust-структуры
    /// напрямую через authorization records (см. `authorization_entries.rs`).
    /// V2 entries (Этап 8) имеют leading byte `0x02`. Любое другое значение
    /// приведённое к `KtEntryVersion::try_from` — corruption либо неизвестная
    /// будущая версия; entry treated as malformed.
    ///
    /// The first byte of a wire-format entry does not match any known version.
    /// V1 entries (existing 0.0.11 wire format) **do not carry** a version
    /// stamp in `KtEntry::canonical_encoding` and are not parsed via
    /// `KtEntryVersion::try_from` — they are constructed as Rust structs
    /// directly through authorization records (see `authorization_entries.rs`).
    /// V2 entries (Stage 8) carry a leading byte `0x02`. Any other value
    /// passed to `KtEntryVersion::try_from` is corruption or an unknown
    /// future version; the entry is treated as malformed.
    #[error("unknown KT entry version byte 0x{version:02x}")]
    UnknownEntryVersion {
        /// Полученный version-байт. Received version byte.
        version: u8,
    },

    /// Wire-format entry имеет нулевую длину — нет даже version-байта для
    /// dispatch'а. Detected перед `KtEntryVersion::try_from` чтобы избежать
    /// out-of-bounds на `bytes[0]`.
    ///
    /// Wire-format entry has zero length — no version byte to dispatch on.
    /// Detected before `KtEntryVersion::try_from` to avoid an out-of-bounds
    /// read of `bytes[0]`.
    #[error("KT entry bytes are empty — no version byte to dispatch")]
    EmptyEntry,

    /// V2 entry wire-format invalid: длина не соответствует expected layout
    /// (variable-length из-за optional SLH-DSA backup pubkey). Содержит
    /// стабильный string tag для классификации причины (e.g. `"too_short"`,
    /// `"slh_dsa_flag_invalid"`, `"trailing_bytes"`).
    ///
    /// V2 entry wire-format invalid: length does not match the expected
    /// layout (variable-length due to optional SLH-DSA backup pubkey). Carries
    /// a stable string tag classifying the cause (e.g. `"too_short"`,
    /// `"slh_dsa_flag_invalid"`, `"trailing_bytes"`).
    #[error("invalid KT V2 entry wire format: {0}")]
    InvalidV2Entry(&'static str),
}
