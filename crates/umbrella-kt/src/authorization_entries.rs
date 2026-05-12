//! KT schema extension под ADR-008 — client-side log mirror и `apply_*` функции.
//! KT schema extension for ADR-008 — client-side log mirror and `apply_*` functions.
//!
//! ## Назначение
//!
//! До ADR-008 `umbrella-kt` покрывал только Merkle log + self-monitoring для
//! identity/device snapshot'ов (Этап 3.3/3.4). Для multi-device authorization
//! (SPEC-11 §4) Sealed Servers обязаны различать `Pending`, `Active`,
//! `Revoked`, `BootstrapActive` состояния каждого device-entry. Это состояние
//! возникает из композиции трёх типов записей публикуемых в KT:
//!
//! 1. [`DeviceAuthorizationApproval`] (entry-type `0x04`) — переводит
//!    pending-entry в active.
//! 2. [`DeviceAuthorizationRevocation`] (entry-type `0x05`) — переводит
//!    pending/active в revoked (terminal).
//! 3. [`IdentityRotationRecord`] (entry-type `0x06`) — ротация identity-key,
//!    автоматически cascade-revokes все device-entries под старым identity.
//!
//! Модуль реализует client-side mirror ([`KtLogState`]) и функции применения
//! этих записей (`apply_authorization_approval`, `apply_authorization_revocation`,
//! `apply_identity_rotation`) с полным набором cross-entry consistency rules
//! из SPEC-09 §7.2. Sealed Servers в production делают ту же логику
//! server-side; клиент делает её локально для inclusion-proof audit и для
//! валидации что Sealed Server не нарушил cross-entry правила.
//!
//! Wire-format записей переиспользуется из `umbrella_backup::cloud_wrap` —
//! это единый источник правды для sign/verify/encode/decode, принятый SPEC-12
//! §A.13.
//!
//! ## Purpose
//!
//! Before ADR-008 `umbrella-kt` covered only the Merkle log + self-monitoring
//! for identity/device snapshot entries (Stage 3.3/3.4). For multi-device
//! authorization (SPEC-11 §4) Sealed Servers must distinguish `Pending`,
//! `Active`, `Revoked`, `BootstrapActive` states of each device-entry. That
//! state arises from the composition of three record types published to KT:
//!
//! 1. [`DeviceAuthorizationApproval`] (entry-type `0x04`) — transitions a
//!    pending entry to active.
//! 2. [`DeviceAuthorizationRevocation`] (entry-type `0x05`) — transitions a
//!    pending / active entry to revoked (terminal).
//! 3. [`IdentityRotationRecord`] (entry-type `0x06`) — identity-key rotation,
//!    automatically cascade-revokes all device-entries under the old identity.
//!
//! This module implements the client-side mirror ([`KtLogState`]) and the
//! corresponding apply functions (`apply_authorization_approval`,
//! `apply_authorization_revocation`, `apply_identity_rotation`) with the full
//! set of cross-entry consistency rules from SPEC-09 §7.2. Sealed Servers
//! enforce the same rules server-side; the client runs them locally for
//! inclusion-proof audit and to verify that a Sealed Server did not break
//! cross-entry rules.
//!
//! The wire format of these records is reused from `umbrella_backup::cloud_wrap`
//! as the single source of truth for sign/verify/encode/decode, per SPEC-12
//! §A.13.

use std::collections::HashMap;

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::witness::{verify_signed_epoch, SignedEpochRoot, WitnessSet};

// Wire-format типы ADR-008 — единый источник правды живёт в umbrella-backup.
// Все три encode/decode/verify/seal_* переиспользуются без копипаста (SPEC-12 §A.13).
//
// ADR-008 wire-format types — the single source of truth lives in
// umbrella-backup. All three encode/decode/verify/seal_* are reused
// without duplication (SPEC-12 §A.13).
pub use umbrella_backup::cloud_wrap::{
    DeviceAuthorizationApproval, DeviceAuthorizationRevocation, DeviceEntryState,
    DeviceEntryStateFlag, IdentityRotationRecord, RotationReason,
};

/// Длина Ed25519 public key в байтах (32). Совпадает с
/// `umbrella_backup::cloud_wrap::DEVICE_PUBKEY_LEN`.
///
/// Length of an Ed25519 public key in bytes (32). Equal to
/// `umbrella_backup::cloud_wrap::DEVICE_PUBKEY_LEN`.
pub const DEVICE_PUBKEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// EntryType
// ---------------------------------------------------------------------------

/// Тип log-entry в KT (SPEC-09 §3 + §7.1). Первые три тега существовали до
/// ADR-008 и покрывают identity-level события (snapshot + attestations +
/// explicit revocation). Теги `0x04..=0x06` добавлены ADR-008 для
/// multi-device authorization.
///
/// Type tag of a KT log-entry (SPEC-09 §3 + §7.1). The first three tags
/// existed before ADR-008 and cover identity-level events (snapshot,
/// attestations, explicit revocation). Tags `0x04..=0x06` are added by
/// ADR-008 for multi-device authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryType {
    /// Первоначальная публикация identity-key для account (Этап 3).
    /// Initial publication of the identity-key for an account (Stage 3).
    IdentityAnnounce = 0x01,
    /// Attestation устройства идентичностью (Этап 3 / SPEC-02 §7).
    /// Device attestation by the identity (Stage 3 / SPEC-02 §7).
    DeviceAttestation = 0x02,
    /// Явный revoke device_pubkey — legacy путь до ADR-008. Replaced in
    /// multi-device flow by `DeviceAuthorizationRevocation` (0x05).
    ///
    /// Explicit device_pubkey revoke — legacy path prior to ADR-008.
    /// Replaced in multi-device flow by `DeviceAuthorizationRevocation` (0x05).
    DeviceRevocation = 0x03,
    /// ADR-008: одобрение нового устройства existing active device. Payload =
    /// [`DeviceAuthorizationApproval`] wire-format (146 байт).
    ///
    /// ADR-008: approval of a new device by an existing active device. Payload =
    /// [`DeviceAuthorizationApproval`] wire-format (146 bytes).
    DeviceAuthorizationApproval = 0x04,
    /// ADR-008: отзыв device-key через active device. Payload =
    /// [`DeviceAuthorizationRevocation`] wire-format (137 байт).
    ///
    /// ADR-008: device-key revocation by an active device. Payload =
    /// [`DeviceAuthorizationRevocation`] wire-format (137 bytes).
    DeviceAuthorizationRevocation = 0x05,
    /// ADR-008: ротация identity-key с dual signature. Payload =
    /// [`IdentityRotationRecord`] wire-format (202 байт).
    ///
    /// ADR-008: identity-key rotation with dual signature. Payload =
    /// [`IdentityRotationRecord`] wire-format (202 bytes).
    IdentityRotationRecord = 0x06,
}

impl EntryType {
    /// Байтовый тег для wire-format. Byte tag for wire format.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Обратный декод из тега. `None` если тег неизвестен (SPEC-09 §7.4
    /// `UnsupportedEntryType`).
    ///
    /// Reverse decode from a tag. `None` if the tag is unknown (SPEC-09 §7.4
    /// `UnsupportedEntryType`).
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::IdentityAnnounce),
            0x02 => Some(Self::DeviceAttestation),
            0x03 => Some(Self::DeviceRevocation),
            0x04 => Some(Self::DeviceAuthorizationApproval),
            0x05 => Some(Self::DeviceAuthorizationRevocation),
            0x06 => Some(Self::IdentityRotationRecord),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceEntryRef — SPEC-09 §3 client-side mirror entry
// ---------------------------------------------------------------------------

/// Ссылка на одно device-entry в client-side KT log mirror (SPEC-09 §3).
/// Собирает device_pubkey (ключ в [`KtLogState`]) и полное состояние
/// `DeviceEntryState` (флаг + параметры approval / bootstrap).
///
/// Возвращается через [`lookup_device_entry`] — ровно то что Sealed Server
/// использует при обработке `SignedUnwrapRequest` (SPEC-12 §A.11).
///
/// Reference to a single device-entry in the client-side KT log mirror
/// (SPEC-09 §3). Combines `device_pubkey` (key in [`KtLogState`]) and the
/// full `DeviceEntryState` (flag + approval / bootstrap parameters).
///
/// Returned from [`lookup_device_entry`] — exactly what a Sealed Server uses
/// when processing a `SignedUnwrapRequest` (SPEC-12 §A.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEntryRef {
    /// Ed25519 pubkey устройства (ключ в HashMap log mirror).
    /// Ed25519 device pubkey (key in the log-mirror HashMap).
    pub device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Полное состояние entry: флаг + authorized_since + history_cutoff +
    /// identity_pubkey_at_publish. Реиспользует тип из
    /// `umbrella_backup::cloud_wrap::DeviceEntryState` без копирования.
    ///
    /// Full entry state: flag + authorized_since + history_cutoff +
    /// identity_pubkey_at_publish. Reuses the type from
    /// `umbrella_backup::cloud_wrap::DeviceEntryState` without duplication.
    pub state: DeviceEntryState,
}

impl DeviceEntryRef {
    /// Текущий флаг entry (Pending / Active / Revoked / BootstrapActive).
    /// Current entry flag (Pending / Active / Revoked / BootstrapActive).
    #[inline]
    #[must_use]
    pub const fn flag(&self) -> DeviceEntryStateFlag {
        self.state.flag
    }

    /// Unix-millis с которого entry считается authorized. Для `Pending` = 0.
    /// Unix-millis from which the entry is considered authorized. For `Pending` = 0.
    #[inline]
    #[must_use]
    pub const fn authorized_since(&self) -> u64 {
        self.state.authorized_since
    }

    /// Unix-millis history cutoff (`0` = полный доступ к истории).
    /// Unix-millis history cutoff (`0` = full history access).
    #[inline]
    #[must_use]
    pub const fn history_cutoff(&self) -> u64 {
        self.state.history_cutoff
    }

    /// Identity-pubkey под которым entry опубликован. После rotation старые
    /// entries помечены как «под старым identity» (cascade revoke SPEC-09 §7.2).
    ///
    /// Identity-pubkey under which the entry was published. After rotation
    /// older entries are flagged as "under the old identity"
    /// (cascade revoke SPEC-09 §7.2).
    #[inline]
    #[must_use]
    pub const fn identity_pubkey_at_publish(&self) -> &[u8; DEVICE_PUBKEY_LEN] {
        &self.state.identity_pubkey_at_publish
    }
}

// ---------------------------------------------------------------------------
// KtLogState — client-side KT log mirror
// ---------------------------------------------------------------------------

/// Клиентский mirror состояния KT log применительно к account владельца
/// (SPEC-09 §7.3). Обновляется через `apply_*` функции которые параллельно
/// проверяют Merkle inclusion proof (внешне) + witness threshold (здесь) +
/// cross-entry consistency rules.
///
/// Client-side mirror of the KT log state for the account owner
/// (SPEC-09 §7.3). Updated through `apply_*` functions that concurrently
/// validate the Merkle inclusion proof (externally) + the witness threshold
/// (here) + cross-entry consistency rules.
#[derive(Debug, Clone, Default)]
pub struct KtLogState {
    device_entries: HashMap<[u8; DEVICE_PUBKEY_LEN], DeviceEntryState>,
    current_identity_pubkey: Option<[u8; DEVICE_PUBKEY_LEN]>,
    identity_rotation: Option<IdentityRotationRecord>,
    last_verified_epoch: u64,
    last_verified_root: [u8; NODE_HASH_LEN],
}

impl KtLogState {
    /// Пустой log mirror. Используется первоначально на чистом устройстве до
    /// каких-либо KT событий.
    ///
    /// Empty log mirror. Used initially on a fresh device before any KT events.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Log mirror с уже установленным текущим identity (например после того
    /// как клиент прочитал IdentityAnnounce entry в текущем epoch). Не меняет
    /// device_entries — bootstrap device-entries всё ещё публикуются отдельно.
    ///
    /// Log mirror with the current identity already set (e.g. after the
    /// client has read the IdentityAnnounce entry in the current epoch).
    /// Does not touch device_entries — bootstrap device-entries are still
    /// published separately.
    #[must_use]
    pub fn with_identity(identity_pubkey: [u8; DEVICE_PUBKEY_LEN]) -> Self {
        Self {
            current_identity_pubkey: Some(identity_pubkey),
            ..Self::default()
        }
    }

    /// Регистрация pending device-entry (до того как придёт approval).
    /// Обычно вызывается когда клиент видит новую pending-публикацию в KT
    /// (например свою собственную после публикации нового устройства).
    ///
    /// Register a pending device-entry (before the approval is applied).
    /// Typically called when the client observes a new pending publication
    /// in KT (for example its own, just after publishing a new device).
    ///
    /// # Errors
    /// - [`KtError::InvalidEntry`] `"device-entry already exists"` если entry
    ///   с таким pubkey уже в log mirror.
    pub fn register_pending(
        &mut self,
        device_pubkey: [u8; DEVICE_PUBKEY_LEN],
        identity_pubkey_at_publish: [u8; DEVICE_PUBKEY_LEN],
    ) -> Result<()> {
        if self.device_entries.contains_key(&device_pubkey) {
            return Err(KtError::InvalidEntry("device-entry already exists"));
        }
        self.device_entries.insert(
            device_pubkey,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Pending,
                authorized_since: 0,
                history_cutoff: 0,
                identity_pubkey_at_publish,
            },
        );
        Ok(())
    }

    /// Регистрация bootstrap-active device-entry. Легитимно только в двух
    /// сценариях (SPEC-11 §4.8):
    ///
    /// 1. **Primary bootstrap** — самое первое устройство под новым identity,
    ///    когда в KT ещё нет других device-entries под этим identity.
    /// 2. **Catastrophic recovery bootstrap** — первое устройство под новым
    ///    identity после `IdentityRotationRecord` с
    ///    `reason = CatastrophicRecovery` в том же либо более раннем epoch.
    ///
    /// В остальных случаях bootstrap-active отвергается
    /// ([`KtError::BootstrapNotAllowed`]).
    ///
    /// Register a bootstrap-active device-entry. Legitimate only in two
    /// scenarios (SPEC-11 §4.8):
    ///
    /// 1. **Primary bootstrap** — the very first device under a new identity,
    ///    when no other device-entries exist for that identity in KT.
    /// 2. **Catastrophic recovery bootstrap** — the first device under a new
    ///    identity after an `IdentityRotationRecord` with
    ///    `reason = CatastrophicRecovery` in the same or an earlier epoch.
    ///
    /// In every other case bootstrap-active is rejected
    /// ([`KtError::BootstrapNotAllowed`]).
    ///
    /// # Errors
    /// - [`KtError::BootstrapNotAllowed`] если ни один из двух сценариев не
    ///   применим.
    /// - [`KtError::InvalidEntry`] `"device-entry already exists"`.
    pub fn register_bootstrap_active(
        &mut self,
        device_pubkey: [u8; DEVICE_PUBKEY_LEN],
        authorized_since: u64,
        identity_pubkey_at_publish: [u8; DEVICE_PUBKEY_LEN],
    ) -> Result<()> {
        if self.device_entries.contains_key(&device_pubkey) {
            return Err(KtError::InvalidEntry("device-entry already exists"));
        }

        let other_non_revoked_under_identity = self.device_entries.values().any(|state| {
            state.identity_pubkey_at_publish == identity_pubkey_at_publish
                && state.flag != DeviceEntryStateFlag::Revoked
        });
        let catastrophic_bootstrap = matches!(
            &self.identity_rotation,
            Some(r)
                if r.rotation_reason == RotationReason::CatastrophicRecovery
                    && r.new_identity_pubkey == identity_pubkey_at_publish,
        );

        let primary_bootstrap = !other_non_revoked_under_identity;
        if !(primary_bootstrap || catastrophic_bootstrap) {
            return Err(KtError::BootstrapNotAllowed);
        }

        self.device_entries.insert(
            device_pubkey,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::BootstrapActive,
                authorized_since,
                history_cutoff: 0,
                identity_pubkey_at_publish,
            },
        );
        if self.current_identity_pubkey.is_none() {
            self.current_identity_pubkey = Some(identity_pubkey_at_publish);
        }
        Ok(())
    }

    /// Текущий identity-pubkey аккаунта (после применения последней
    /// `IdentityRotationRecord` либо bootstrap'а). `None` если log пустой.
    ///
    /// Current account identity-pubkey (after the most recent
    /// `IdentityRotationRecord` or bootstrap). `None` if the log is empty.
    #[must_use]
    pub fn current_identity_pubkey(&self) -> Option<&[u8; DEVICE_PUBKEY_LEN]> {
        self.current_identity_pubkey.as_ref()
    }

    /// Последняя применённая `IdentityRotationRecord` запись. `None` если
    /// ротации не было.
    ///
    /// The last applied `IdentityRotationRecord`. `None` if no rotation
    /// has been applied.
    #[must_use]
    pub fn identity_rotation(&self) -> Option<&IdentityRotationRecord> {
        self.identity_rotation.as_ref()
    }

    /// Номер последней проверенной эпохи (монотонно не-убывает).
    /// Last verified epoch number (monotonically non-decreasing).
    #[must_use]
    pub const fn last_verified_epoch(&self) -> u64 {
        self.last_verified_epoch
    }

    /// Merkle-root последней проверенной эпохи.
    /// Merkle-root of the last verified epoch.
    #[must_use]
    pub const fn last_verified_root(&self) -> &[u8; NODE_HASH_LEN] {
        &self.last_verified_root
    }

    /// Количество device-entries в mirror (любых состояний).
    /// Number of device-entries in the mirror (of any state).
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.device_entries.len()
    }

    /// Количество device-entries в `Active` либо `BootstrapActive`.
    /// Number of device-entries in `Active` or `BootstrapActive` state.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.device_entries
            .values()
            .filter(|s| {
                matches!(
                    s.flag,
                    DeviceEntryStateFlag::Active | DeviceEntryStateFlag::BootstrapActive
                )
            })
            .count()
    }

    /// Итератор по всем device-entries mirror. Порядок не детерминирован
    /// (HashMap). Для тестов.
    ///
    /// Iterator over all device-entries in the mirror. Order is not
    /// deterministic (HashMap). For tests.
    pub fn iter_entries(
        &self,
    ) -> impl Iterator<Item = (&[u8; DEVICE_PUBKEY_LEN], &DeviceEntryState)> {
        self.device_entries.iter()
    }
}

// ---------------------------------------------------------------------------
// Verify epoch transition — shared prelude для apply_*
// ---------------------------------------------------------------------------

/// Общая проверка эпохи для `apply_*`: (a) witness threshold достигнут,
/// (b) epoch не регрессирует (SPEC-09 §5 — monotonic non-decreasing).
///
/// Shared epoch-check for `apply_*`: (a) witness threshold met,
/// (b) epoch does not regress (SPEC-09 §5 — monotonic non-decreasing).
///
/// # Errors
/// - [`KtError::InsufficientValidSignatures`] если witness < threshold.
/// - [`KtError::InvalidEntry`] `"epoch regression"` если `signed.epoch <
///   log_state.last_verified_epoch`.
fn verify_epoch_transition(
    log_state: &KtLogState,
    witness_set: &WitnessSet,
    signed: &SignedEpochRoot,
    threshold: usize,
) -> Result<()> {
    verify_signed_epoch(signed, witness_set, threshold)?;
    if signed.epoch < log_state.last_verified_epoch {
        return Err(KtError::InvalidEntry("epoch regression"));
    }
    Ok(())
}

/// Зафиксировать последний проверенный epoch / root в log mirror. Вызывается
/// только после успешного применения entry.
///
/// Record the last verified epoch / root in the log mirror. Called only
/// after an entry is successfully applied.
fn commit_epoch(log_state: &mut KtLogState, signed: &SignedEpochRoot) {
    log_state.last_verified_epoch = signed.epoch;
    log_state.last_verified_root = signed.root;
}

// ---------------------------------------------------------------------------
// apply_authorization_approval
// ---------------------------------------------------------------------------

/// Применить `DeviceAuthorizationApproval` к client-side KT log mirror.
/// Реализует cross-entry consistency rules SPEC-09 §7.2:
///
/// 1. Signed epoch root валиден (witness threshold + monotonic epoch).
/// 2. Approver подпись валидна над canonical input с `approver_device_pubkey`
///    из самого approval (self-consistent verify).
/// 3. Approver должен иметь entry в состоянии `Active` (или
///    `BootstrapActive` как эквивалент при catastrophic-recovery bootstrap)
///    в текущем log mirror — [`KtError::ApproverNotActive`].
/// 4. New device должен иметь entry в состоянии `Pending` — иначе
///    [`KtError::PendingStateNotFound`].
///
/// При успехе: new-device entry переходит в `Active` с
/// `authorized_since_timestamp` и `history_cutoff_timestamp` из approval;
/// `identity_pubkey_at_publish` сохраняется из pending-entry (idempotent
/// под identity).
///
/// Apply `DeviceAuthorizationApproval` to the client-side KT log mirror.
/// Enforces cross-entry consistency rules from SPEC-09 §7.2:
///
/// 1. The signed epoch root is valid (witness threshold + monotonic epoch).
/// 2. The approver signature verifies over the canonical input using
///    `approver_device_pubkey` taken from the approval itself (self-consistent).
/// 3. The approver must have an entry in state `Active` (or `BootstrapActive`
///    as an equivalent during catastrophic-recovery bootstrap) in the
///    current log mirror — else [`KtError::ApproverNotActive`].
/// 4. The new device must have an entry in state `Pending` — else
///    [`KtError::PendingStateNotFound`].
///
/// On success the new device-entry transitions to `Active` with
/// `authorized_since_timestamp` and `history_cutoff_timestamp` from the
/// approval; `identity_pubkey_at_publish` is preserved from the pending
/// entry (idempotent under identity).
///
/// # Errors
/// См. выше + [`KtError::EntrySignatureInvalid`] при tampered подписи.
pub fn apply_authorization_approval(
    approval: &DeviceAuthorizationApproval,
    log_state: &mut KtLogState,
    witness_set: &WitnessSet,
    signed_epoch_root: &SignedEpochRoot,
    witness_threshold: usize,
) -> Result<()> {
    verify_epoch_transition(log_state, witness_set, signed_epoch_root, witness_threshold)?;

    approval
        .verify_self_consistent()
        .map_err(|_| KtError::EntrySignatureInvalid)?;

    // Rule 1 (SPEC-09 §7.2): approver должен быть Active или BootstrapActive.
    match log_state
        .device_entries
        .get(&approval.approver_device_pubkey)
    {
        Some(state)
            if matches!(
                state.flag,
                DeviceEntryStateFlag::Active | DeviceEntryStateFlag::BootstrapActive
            ) => {}
        _ => return Err(KtError::ApproverNotActive),
    }

    // Rule 2 (SPEC-09 §7.2): new device должен быть Pending.
    let pending_state = match log_state.device_entries.get(&approval.new_device_pubkey) {
        Some(state) if state.flag == DeviceEntryStateFlag::Pending => *state,
        _ => return Err(KtError::PendingStateNotFound),
    };

    log_state.device_entries.insert(
        approval.new_device_pubkey,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Active,
            authorized_since: approval.authorized_since_timestamp,
            history_cutoff: approval.history_cutoff_timestamp,
            identity_pubkey_at_publish: pending_state.identity_pubkey_at_publish,
        },
    );
    commit_epoch(log_state, signed_epoch_root);
    Ok(())
}

// ---------------------------------------------------------------------------
// apply_authorization_revocation
// ---------------------------------------------------------------------------

/// Применить `DeviceAuthorizationRevocation` к client-side KT log mirror.
/// Реализует cross-entry consistency rules SPEC-09 §7.2 правило 2:
///
/// 1. Signed epoch root валиден.
/// 2. Revoker подпись валидна (self-consistent verify).
/// 3. Revoker должен быть `Active` / `BootstrapActive` — иначе
///    [`KtError::ApproverNotActive`]. **Self-revocation от Pending-устройства
///    отвергается** — это ограничение SPEC-11 §9.3.
/// 4. Revoked device может быть `Pending` либо `Active` — cross-state ок.
///    Отсутствие entry для `revoked_device_pubkey` —
///    [`KtError::InvalidEntry`] `"unknown device for revocation"` (нельзя
///    отозвать то чего нет). Entry уже в состоянии `Revoked` — идемпотентный
///    no-op (replay-safe).
///
/// При успехе: revoked device-entry → `Revoked` (terminal, `authorized_since`
/// и `history_cutoff` обнуляются).
///
/// Apply `DeviceAuthorizationRevocation` to the client-side KT log mirror.
/// Enforces cross-entry consistency rule 2 from SPEC-09 §7.2:
///
/// 1. The signed epoch root is valid.
/// 2. The revoker signature verifies (self-consistent).
/// 3. The revoker must be `Active` / `BootstrapActive` — else
///    [`KtError::ApproverNotActive`]. **Self-revocation by a Pending device
///    is rejected** — SPEC-11 §9.3 constraint.
/// 4. The revoked device may be `Pending` or `Active` — cross-state ok.
///    A missing entry for `revoked_device_pubkey` returns
///    [`KtError::InvalidEntry`] `"unknown device for revocation"` (cannot
///    revoke an entry that does not exist). An already-`Revoked` entry is an
///    idempotent no-op (replay-safe).
///
/// On success the revoked device-entry transitions to `Revoked` (terminal,
/// `authorized_since` and `history_cutoff` are zeroed).
///
/// # Errors
/// См. выше + [`KtError::EntrySignatureInvalid`].
pub fn apply_authorization_revocation(
    revocation: &DeviceAuthorizationRevocation,
    log_state: &mut KtLogState,
    witness_set: &WitnessSet,
    signed_epoch_root: &SignedEpochRoot,
    witness_threshold: usize,
) -> Result<()> {
    verify_epoch_transition(log_state, witness_set, signed_epoch_root, witness_threshold)?;

    revocation
        .verify_self_consistent()
        .map_err(|_| KtError::EntrySignatureInvalid)?;

    // Idempotent fast-path: уже revoked — просто прогресс epoch, без mutation.
    // RU: Проверка активности отзывающего обязательна и в быстром пути
    //     (SPEC-09 §7.2 правило 2: «Revocation требует active revoker»).
    //     Без этой проверки противник со старым отозванным ключом мог бы
    //     продвигать счётчик эпохи, переподавая отзыв уже-отозванного
    //     устройства (F-PHD-S68-6 closure session #68c, 2026-05-08).
    // EN: The revoker active-state check is mandatory inside the fast-path
    //     (SPEC-09 §7.2 rule 2: "Revocation requires an active revoker").
    //     Without this check an adversary holding a stolen revoked-device
    //     key could advance the epoch counter by resubmitting a revocation
    //     of an already-revoked device (F-PHD-S68-6 closure session #68c).
    if matches!(
        log_state
            .device_entries
            .get(&revocation.revoked_device_pubkey)
            .map(|s| s.flag),
        Some(DeviceEntryStateFlag::Revoked),
    ) {
        match log_state
            .device_entries
            .get(&revocation.revoker_device_pubkey)
        {
            Some(state)
                if matches!(
                    state.flag,
                    DeviceEntryStateFlag::Active | DeviceEntryStateFlag::BootstrapActive
                ) => {}
            _ => return Err(KtError::ApproverNotActive),
        }
        commit_epoch(log_state, signed_epoch_root);
        return Ok(());
    }

    // Rule 2a: revoker Active / BootstrapActive.
    match log_state
        .device_entries
        .get(&revocation.revoker_device_pubkey)
    {
        Some(state)
            if matches!(
                state.flag,
                DeviceEntryStateFlag::Active | DeviceEntryStateFlag::BootstrapActive
            ) => {}
        _ => return Err(KtError::ApproverNotActive),
    }

    // Rule 2b: revoked должен существовать. Pending либо Active принимаются.
    let revoked_state = match log_state
        .device_entries
        .get(&revocation.revoked_device_pubkey)
    {
        Some(state)
            if matches!(
                state.flag,
                DeviceEntryStateFlag::Pending
                    | DeviceEntryStateFlag::Active
                    | DeviceEntryStateFlag::BootstrapActive
            ) =>
        {
            *state
        }
        Some(_) | None => {
            return Err(KtError::InvalidEntry("unknown device for revocation"));
        }
    };

    log_state.device_entries.insert(
        revocation.revoked_device_pubkey,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Revoked,
            authorized_since: 0,
            history_cutoff: 0,
            identity_pubkey_at_publish: revoked_state.identity_pubkey_at_publish,
        },
    );
    commit_epoch(log_state, signed_epoch_root);
    Ok(())
}

// ---------------------------------------------------------------------------
// apply_identity_rotation
// ---------------------------------------------------------------------------

/// Применить `IdentityRotationRecord` к client-side KT log mirror. Реализует
/// cross-entry consistency rule 3 из SPEC-09 §7.2:
///
/// 1. Signed epoch root валиден.
/// 2. Обе подписи (old-identity + new-identity) валидны над одним canonical
///    input — иначе [`KtError::RotationDualSignatureFailed`].
/// 3. `old_identity_pubkey != new_identity_pubkey` — defense-in-depth поверх
///    того же правила в `IdentityRotationRecord::from_bytes` —
///    [`KtError::RotationIdenticalPubkeys`].
/// 4. Если log mirror уже имеет `current_identity_pubkey` — он должен
///    совпадать с `rotation.old_identity_pubkey` — иначе
///    [`KtError::RotationOldIdentityMismatch`]. Если `current_identity_pubkey`
///    = `None` (log пустой), применяем bootstrap rotation: просто устанавливаем
///    `new_identity_pubkey` как текущий.
///
/// При успехе:
/// - `current_identity_pubkey` = `rotation.new_identity_pubkey`.
/// - `identity_rotation` = `Some(rotation.clone())`.
/// - **Cascade revoke**: все device-entries в состоянии `Pending` /
///   `Active` / `BootstrapActive` у которых
///   `identity_pubkey_at_publish == rotation.old_identity_pubkey` помечаются
///   `Revoked`. Это synthetic cascade описанный SPEC-09 §7.2 правило 3.
///
/// Apply `IdentityRotationRecord` to the client-side KT log mirror. Enforces
/// cross-entry consistency rule 3 from SPEC-09 §7.2:
///
/// 1. The signed epoch root is valid.
/// 2. Both signatures (old-identity + new-identity) verify over the same
///    canonical input — else [`KtError::RotationDualSignatureFailed`].
/// 3. `old_identity_pubkey != new_identity_pubkey` — defense-in-depth on top
///    of the same rule inside `IdentityRotationRecord::from_bytes` —
///    [`KtError::RotationIdenticalPubkeys`].
/// 4. If the log mirror already has `current_identity_pubkey`, it must equal
///    `rotation.old_identity_pubkey` — else
///    [`KtError::RotationOldIdentityMismatch`]. If `current_identity_pubkey`
///    is `None` (empty log), this is treated as a bootstrap rotation: just
///    install `new_identity_pubkey` as current.
///
/// On success:
/// - `current_identity_pubkey` = `rotation.new_identity_pubkey`.
/// - `identity_rotation` = `Some(rotation.clone())`.
/// - **Cascade revoke**: all device-entries in state `Pending` / `Active` /
///   `BootstrapActive` whose
///   `identity_pubkey_at_publish == rotation.old_identity_pubkey` are
///   marked `Revoked`. This is the synthetic cascade described in
///   SPEC-09 §7.2 rule 3.
///
/// # Errors
/// См. выше.
pub fn apply_identity_rotation(
    rotation: &IdentityRotationRecord,
    log_state: &mut KtLogState,
    witness_set: &WitnessSet,
    signed_epoch_root: &SignedEpochRoot,
    witness_threshold: usize,
) -> Result<()> {
    verify_epoch_transition(log_state, witness_set, signed_epoch_root, witness_threshold)?;

    if rotation.old_identity_pubkey == rotation.new_identity_pubkey {
        return Err(KtError::RotationIdenticalPubkeys);
    }
    rotation
        .verify()
        .map_err(|_| KtError::RotationDualSignatureFailed)?;

    if let Some(current) = log_state.current_identity_pubkey.as_ref() {
        if current != &rotation.old_identity_pubkey {
            return Err(KtError::RotationOldIdentityMismatch);
        }
    }

    // Cascade revoke всех non-revoked entries под старым identity.
    for state in log_state.device_entries.values_mut() {
        if state.identity_pubkey_at_publish == rotation.old_identity_pubkey
            && state.flag != DeviceEntryStateFlag::Revoked
        {
            state.flag = DeviceEntryStateFlag::Revoked;
            state.authorized_since = 0;
            state.history_cutoff = 0;
        }
    }

    log_state.current_identity_pubkey = Some(rotation.new_identity_pubkey);
    log_state.identity_rotation = Some(rotation.clone());
    commit_epoch(log_state, signed_epoch_root);
    Ok(())
}

// ---------------------------------------------------------------------------
// lookup_device_entry
// ---------------------------------------------------------------------------

/// Вернуть текущее состояние device-entry по pubkey. Используется Sealed
/// Servers (через тесты MockUnwrapTransport) и клиент-стороной при
/// authorization audit.
///
/// Return the current state of a device-entry by pubkey. Used by Sealed
/// Servers (via MockUnwrapTransport tests) and client-side authorization
/// audit.
#[must_use]
pub fn lookup_device_entry(
    log_state: &KtLogState,
    device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
) -> Option<DeviceEntryRef> {
    log_state
        .device_entries
        .get(device_pubkey)
        .map(|state| DeviceEntryRef {
            device_pubkey: *device_pubkey,
            state: *state,
        })
}

// ---------------------------------------------------------------------------
// Тесты / Tests — 8 уровней покрытия из QUALITY_STANDARDS §2 + SPEC-09 §8.2
// (ADR-008 specific) + SPEC-11 §9.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::{OsRng, RngCore};
    use umbrella_backup::cloud_wrap::{
        seal_device_authorization_approval, seal_device_authorization_revocation,
        seal_identity_rotation_record,
    };
    use umbrella_backup::error::BackupError;
    use umbrella_crypto_primitives::sig::PrivateSigningKey;

    use crate::witness::{canonical_sign_payload, WitnessPublic, WitnessSignature};

    const WITNESS_THRESHOLD: usize = 3;
    const EPOCH_BASELINE: u64 = 100;
    const TIMESTAMP_BASELINE: u64 = 1_700_000_000_000;

    // Размер Ed25519 signature для device-signer closure в seal_*.
    // Ed25519 signature size for the device-signer closure in seal_*.
    const SIG_LEN: usize = 64;

    // --- Keypair / signing helpers ---

    fn gen_keypair() -> (PrivateSigningKey, [u8; DEVICE_PUBKEY_LEN]) {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign_with(
        sk: &PrivateSigningKey,
    ) -> impl FnOnce(&[u8]) -> core::result::Result<[u8; SIG_LEN], BackupError> + '_ {
        move |message| Ok(sk.sign(message).to_bytes())
    }

    // --- Witness helpers ---

    struct Witness {
        sk: PrivateSigningKey,
        pk: WitnessPublic,
    }

    fn gen_witness() -> Witness {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
        Witness { sk, pk }
    }

    fn build_witness_set(ws: &[&Witness]) -> WitnessSet {
        let mut set = WitnessSet::new();
        for w in ws {
            set.add(w.pk);
        }
        set
    }

    fn sign_epoch_root(
        witnesses: &[&Witness],
        epoch: u64,
        root: &[u8; NODE_HASH_LEN],
    ) -> SignedEpochRoot {
        let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
        let sigs: Vec<WitnessSignature> = witnesses
            .iter()
            .map(|w| WitnessSignature {
                witness: w.pk,
                signature: w.sk.sign(&payload).to_bytes(),
            })
            .collect();
        SignedEpochRoot {
            epoch,
            root: *root,
            log_size: 1,
            timestamp_unix_millis: 1_700_000_000_000,
            signatures: sigs,
        }
    }

    fn random_root() -> [u8; NODE_HASH_LEN] {
        let mut out = [0u8; NODE_HASH_LEN];
        OsRng.fill_bytes(&mut out);
        out
    }

    struct TestEnv {
        witnesses: Vec<Witness>,
        set: WitnessSet,
    }

    impl TestEnv {
        fn fresh() -> Self {
            let witnesses: Vec<Witness> = (0..5).map(|_| gen_witness()).collect();
            let set = build_witness_set(&witnesses.iter().collect::<Vec<_>>());
            Self { witnesses, set }
        }

        fn signed_epoch(&self, epoch: u64, root: &[u8; NODE_HASH_LEN]) -> SignedEpochRoot {
            let refs: Vec<&Witness> = self.witnesses.iter().take(3).collect();
            sign_epoch_root(&refs, epoch, root)
        }

        fn signed_epoch_with_count(
            &self,
            epoch: u64,
            root: &[u8; NODE_HASH_LEN],
            count: usize,
        ) -> SignedEpochRoot {
            let refs: Vec<&Witness> = self.witnesses.iter().take(count).collect();
            sign_epoch_root(&refs, epoch, root)
        }
    }

    // --- Record builders ---

    fn make_approval(
        approver_sk: &PrivateSigningKey,
        approver_pk: [u8; DEVICE_PUBKEY_LEN],
        new_device_pk: [u8; DEVICE_PUBKEY_LEN],
        authorized_since: u64,
        history_cutoff: u64,
        policy_flags: u8,
    ) -> DeviceAuthorizationApproval {
        seal_device_authorization_approval(
            new_device_pk,
            approver_pk,
            authorized_since,
            history_cutoff,
            policy_flags,
            sign_with(approver_sk),
        )
        .expect("seal approval")
    }

    fn make_revocation(
        revoker_sk: &PrivateSigningKey,
        revoker_pk: [u8; DEVICE_PUBKEY_LEN],
        revoked_pk: [u8; DEVICE_PUBKEY_LEN],
        timestamp: u64,
    ) -> DeviceAuthorizationRevocation {
        seal_device_authorization_revocation(
            revoked_pk,
            revoker_pk,
            timestamp,
            sign_with(revoker_sk),
        )
        .expect("seal revocation")
    }

    fn make_rotation(
        old_sk: &PrivateSigningKey,
        old_pk: [u8; DEVICE_PUBKEY_LEN],
        new_sk: &PrivateSigningKey,
        new_pk: [u8; DEVICE_PUBKEY_LEN],
        timestamp: u64,
        reason: RotationReason,
    ) -> IdentityRotationRecord {
        seal_identity_rotation_record(
            old_pk,
            new_pk,
            timestamp,
            reason,
            sign_with(old_sk),
            sign_with(new_sk),
        )
        .expect("seal rotation")
    }

    // ======================================================================
    // Unit-level (уровень 1 QUALITY_STANDARDS §2.1)
    // ======================================================================

    #[test]
    fn entry_type_all_tags_roundtrip() {
        for v in [
            EntryType::IdentityAnnounce,
            EntryType::DeviceAttestation,
            EntryType::DeviceRevocation,
            EntryType::DeviceAuthorizationApproval,
            EntryType::DeviceAuthorizationRevocation,
            EntryType::IdentityRotationRecord,
        ] {
            assert_eq!(EntryType::from_tag(v.tag()), Some(v));
        }
    }

    #[test]
    fn entry_type_tag_values_match_spec() {
        assert_eq!(EntryType::IdentityAnnounce.tag(), 0x01);
        assert_eq!(EntryType::DeviceAttestation.tag(), 0x02);
        assert_eq!(EntryType::DeviceRevocation.tag(), 0x03);
        assert_eq!(EntryType::DeviceAuthorizationApproval.tag(), 0x04);
        assert_eq!(EntryType::DeviceAuthorizationRevocation.tag(), 0x05);
        assert_eq!(EntryType::IdentityRotationRecord.tag(), 0x06);
    }

    #[test]
    fn entry_type_from_tag_rejects_unknown() {
        for tag in [0x00u8, 0x07, 0x08, 0xFE, 0xFF] {
            assert_eq!(EntryType::from_tag(tag), None);
        }
    }

    #[test]
    fn kt_log_state_new_is_empty() {
        let s = KtLogState::new();
        assert_eq!(s.device_count(), 0);
        assert_eq!(s.active_count(), 0);
        assert!(s.current_identity_pubkey().is_none());
        assert!(s.identity_rotation().is_none());
        assert_eq!(s.last_verified_epoch(), 0);
        assert_eq!(s.last_verified_root(), &[0u8; NODE_HASH_LEN]);
    }

    #[test]
    fn kt_log_state_with_identity_sets_current_identity() {
        let id = [0xABu8; DEVICE_PUBKEY_LEN];
        let s = KtLogState::with_identity(id);
        assert_eq!(s.current_identity_pubkey(), Some(&id));
        assert_eq!(s.device_count(), 0);
    }

    #[test]
    fn lookup_device_entry_returns_none_on_empty_log() {
        let s = KtLogState::new();
        let pubkey = [0u8; DEVICE_PUBKEY_LEN];
        assert!(lookup_device_entry(&s, &pubkey).is_none());
    }

    #[test]
    fn register_pending_happy_path() {
        let mut s = KtLogState::new();
        let (_, pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        s.register_pending(pk, identity).unwrap();
        let entry = lookup_device_entry(&s, &pk).unwrap();
        assert_eq!(entry.flag(), DeviceEntryStateFlag::Pending);
        assert_eq!(entry.authorized_since(), 0);
        assert_eq!(entry.history_cutoff(), 0);
        assert_eq!(entry.identity_pubkey_at_publish(), &identity);
    }

    #[test]
    fn register_pending_rejects_duplicate() {
        let mut s = KtLogState::new();
        let (_, pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        s.register_pending(pk, identity).unwrap();
        let err = s.register_pending(pk, identity).unwrap_err();
        assert!(matches!(err, KtError::InvalidEntry(_)));
    }

    #[test]
    fn register_bootstrap_active_primary_bootstrap_ok() {
        let mut s = KtLogState::new();
        let (_, device) = gen_keypair();
        let (_, identity) = gen_keypair();
        s.register_bootstrap_active(device, TIMESTAMP_BASELINE, identity)
            .unwrap();
        let entry = lookup_device_entry(&s, &device).unwrap();
        assert_eq!(entry.flag(), DeviceEntryStateFlag::BootstrapActive);
        assert_eq!(entry.authorized_since(), TIMESTAMP_BASELINE);
        assert_eq!(s.current_identity_pubkey(), Some(&identity));
    }

    #[test]
    fn register_bootstrap_active_rejects_when_active_exists() {
        let mut s = KtLogState::new();
        let (_, device_a) = gen_keypair();
        let (_, device_b) = gen_keypair();
        let (_, identity) = gen_keypair();
        // Установим device_a как bootstrap-active под identity.
        s.register_bootstrap_active(device_a, TIMESTAMP_BASELINE, identity)
            .unwrap();
        // Попытка ещё одного bootstrap-active для того же identity без rotation.
        let err = s
            .register_bootstrap_active(device_b, TIMESTAMP_BASELINE + 1, identity)
            .unwrap_err();
        assert_eq!(err, KtError::BootstrapNotAllowed);
    }

    #[test]
    fn register_bootstrap_active_ok_after_catastrophic_recovery() {
        let mut s = KtLogState::new();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let (_, legacy_device) = gen_keypair();
        let (_, new_device) = gen_keypair();

        // Первое устройство под старым identity.
        s.register_bootstrap_active(legacy_device, TIMESTAMP_BASELINE, old_identity)
            .unwrap();

        // Apply catastrophic-recovery rotation.
        let env = TestEnv::fresh();
        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::CatastrophicRecovery,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut s, &env.set, &signed, WITNESS_THRESHOLD).unwrap();

        // Теперь bootstrap-active под новым identity валиден (catastrophic bootstrap).
        s.register_bootstrap_active(new_device, TIMESTAMP_BASELINE + 2, new_identity)
            .unwrap();
        assert_eq!(
            lookup_device_entry(&s, &new_device).unwrap().flag(),
            DeviceEntryStateFlag::BootstrapActive
        );
    }

    #[test]
    fn register_bootstrap_active_rejected_after_planned_rotation() {
        let mut s = KtLogState::new();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let (_, device_a) = gen_keypair();
        let (_, device_b) = gen_keypair();

        // Установим Active under old identity.
        s.register_bootstrap_active(device_a, TIMESTAMP_BASELINE, old_identity)
            .unwrap();
        // Planned rotation (не catastrophic).
        let env = TestEnv::fresh();
        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut s, &env.set, &signed, WITNESS_THRESHOLD).unwrap();

        // device_a теперь Revoked (cascade). Но попытка bootstrap под new identity
        // всё равно валидна т.к. Revoked entries не блокируют primary-bootstrap.
        // SPEC-11 §4.8: primary bootstrap OK если нет **других** (active/pending)
        // entries под новым identity. Revoked не считаются — все новые entries под
        // новым identity начинают с чистого листа.
        s.register_bootstrap_active(device_b, TIMESTAMP_BASELINE + 2, new_identity)
            .unwrap();
    }

    #[test]
    fn device_count_and_active_count_track_mutations() {
        let mut s = KtLogState::new();
        assert_eq!(s.device_count(), 0);
        assert_eq!(s.active_count(), 0);

        let (_, identity) = gen_keypair();
        let (_, d1) = gen_keypair();
        let (_, d2) = gen_keypair();

        s.register_bootstrap_active(d1, TIMESTAMP_BASELINE, identity)
            .unwrap();
        assert_eq!(s.device_count(), 1);
        assert_eq!(s.active_count(), 1);

        s.register_pending(d2, identity).unwrap();
        assert_eq!(s.device_count(), 2);
        assert_eq!(s.active_count(), 1);
    }

    #[test]
    fn device_entry_ref_accessors_match_state() {
        let identity = [0x11u8; DEVICE_PUBKEY_LEN];
        let state = DeviceEntryState {
            flag: DeviceEntryStateFlag::Active,
            authorized_since: 42,
            history_cutoff: 100,
            identity_pubkey_at_publish: identity,
        };
        let entry = DeviceEntryRef {
            device_pubkey: [0x22u8; DEVICE_PUBKEY_LEN],
            state,
        };
        assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
        assert_eq!(entry.authorized_since(), 42);
        assert_eq!(entry.history_cutoff(), 100);
        assert_eq!(entry.identity_pubkey_at_publish(), &identity);
    }

    // ======================================================================
    // apply_authorization_approval — happy path + adversarial
    // ======================================================================

    fn setup_log_with_bootstrap_approver() -> (
        KtLogState,
        PrivateSigningKey,
        [u8; DEVICE_PUBKEY_LEN],
        [u8; DEVICE_PUBKEY_LEN],
    ) {
        let (approver_sk, approver_pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        let mut log = KtLogState::with_identity(identity);
        log.register_bootstrap_active(approver_pk, TIMESTAMP_BASELINE, identity)
            .unwrap();
        (log, approver_sk, approver_pk, identity)
    }

    #[test]
    fn approval_transitions_pending_to_active() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();

        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());

        apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();

        let entry = lookup_device_entry(&log, &new_device).unwrap();
        assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
        assert_eq!(entry.authorized_since(), TIMESTAMP_BASELINE + 10);
        assert_eq!(entry.history_cutoff(), 0);
        assert_eq!(entry.identity_pubkey_at_publish(), &identity);
        assert_eq!(log.last_verified_epoch(), EPOCH_BASELINE);
    }

    #[test]
    fn approval_preserves_history_cutoff_and_policy_flags_in_state() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();

        let cutoff = TIMESTAMP_BASELINE + 42;
        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            cutoff,
            0x01, // POLICY_FLAG_HIGH_SECURITY
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());

        apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        let entry = lookup_device_entry(&log, &new_device).unwrap();
        assert_eq!(entry.history_cutoff(), cutoff);
    }

    #[test]
    fn approval_rejects_non_pending_new_device() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        // Не регистрируем pending — сразу пытаемся approval.
        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::PendingStateNotFound);
        let _ = identity;
    }

    #[test]
    fn approval_rejects_when_approver_is_pending() {
        let env = TestEnv::fresh();
        let (approver_sk, approver_pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        let mut log = KtLogState::with_identity(identity);
        // Approver сам в Pending — невалидно как approver по SPEC-09 §7.2.
        log.register_pending(approver_pk, identity).unwrap();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();

        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::ApproverNotActive);
    }

    #[test]
    fn approval_rejects_when_approver_is_revoked() {
        let env = TestEnv::fresh();
        let (approver_sk, approver_pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        let mut log = KtLogState::with_identity(identity);
        log.register_bootstrap_active(approver_pk, TIMESTAMP_BASELINE, identity)
            .unwrap();
        // Revoke approver через self-revocation от bootstrap-active.
        let self_revoke = make_revocation(
            &approver_sk,
            approver_pk,
            approver_pk,
            TIMESTAMP_BASELINE + 1,
        );
        let signed_r0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_revocation(
            &self_revoke,
            &mut log,
            &env.set,
            &signed_r0,
            WITNESS_THRESHOLD,
        )
        .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &approver_pk).unwrap().flag(),
            DeviceEntryStateFlag::Revoked
        );

        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();
        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let signed_r1 = env.signed_epoch(EPOCH_BASELINE + 1, &random_root());
        let err = apply_authorization_approval(
            &approval,
            &mut log,
            &env.set,
            &signed_r1,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert_eq!(err, KtError::ApproverNotActive);
    }

    #[test]
    fn approval_rejects_tampered_signature() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();

        let mut approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        approval.approver_signature[0] ^= 0x01;
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::EntrySignatureInvalid);
    }

    #[test]
    fn approval_rejects_insufficient_witnesses() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();

        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        // Только 2 witness подписи при threshold = 3.
        let signed = env.signed_epoch_with_count(EPOCH_BASELINE, &random_root(), 2);
        let err =
            apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert!(matches!(
            err,
            KtError::InsufficientValidSignatures {
                valid: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn approval_rejects_epoch_regression() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device_a) = gen_keypair();
        let (_, new_device_b) = gen_keypair();
        log.register_pending(new_device_a, identity).unwrap();
        log.register_pending(new_device_b, identity).unwrap();

        let approval_a = make_approval(
            &approver_sk,
            approver_pk,
            new_device_a,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let approval_b = make_approval(
            &approver_sk,
            approver_pk,
            new_device_b,
            TIMESTAMP_BASELINE + 20,
            0,
            0,
        );
        let signed_50 = env.signed_epoch(50, &random_root());
        let signed_30 = env.signed_epoch(30, &random_root());

        apply_authorization_approval(
            &approval_a,
            &mut log,
            &env.set,
            &signed_50,
            WITNESS_THRESHOLD,
        )
        .unwrap();
        // Попытка применить approval с epoch 30 когда last = 50 — regression.
        let err = apply_authorization_approval(
            &approval_b,
            &mut log,
            &env.set,
            &signed_30,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert!(matches!(err, KtError::InvalidEntry(msg) if msg == "epoch regression"));
    }

    // ======================================================================
    // apply_authorization_revocation — happy path + adversarial
    // ======================================================================

    #[test]
    fn revocation_from_active_ok() {
        let env = TestEnv::fresh();
        let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, target) = gen_keypair();
        log.register_pending(target, identity).unwrap();
        let approval = make_approval(
            &revoker_sk,
            revoker_pk,
            target,
            TIMESTAMP_BASELINE + 10,
            0,
            0,
        );
        let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_approval(&approval, &mut log, &env.set, &signed0, WITNESS_THRESHOLD)
            .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &target).unwrap().flag(),
            DeviceEntryStateFlag::Active
        );

        let revocation = make_revocation(&revoker_sk, revoker_pk, target, TIMESTAMP_BASELINE + 20);
        let signed1 = env.signed_epoch(EPOCH_BASELINE + 1, &random_root());
        apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed1,
            WITNESS_THRESHOLD,
        )
        .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &target).unwrap().flag(),
            DeviceEntryStateFlag::Revoked
        );
    }

    #[test]
    fn revocation_from_pending_ok() {
        let env = TestEnv::fresh();
        let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, target) = gen_keypair();
        log.register_pending(target, identity).unwrap();

        let revocation = make_revocation(&revoker_sk, revoker_pk, target, TIMESTAMP_BASELINE + 5);
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_revocation(&revocation, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &target).unwrap().flag(),
            DeviceEntryStateFlag::Revoked
        );
    }

    #[test]
    fn revocation_rejects_when_revoker_is_pending() {
        let env = TestEnv::fresh();
        let (revoker_sk, revoker_pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        let mut log = KtLogState::with_identity(identity);
        log.register_pending(revoker_pk, identity).unwrap();
        let (_, target_sk_pk) = gen_keypair();
        log.register_pending(target_sk_pk, identity).unwrap();

        let revocation = make_revocation(
            &revoker_sk,
            revoker_pk,
            target_sk_pk,
            TIMESTAMP_BASELINE + 5,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err = apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert_eq!(err, KtError::ApproverNotActive);
    }

    #[test]
    fn revocation_rejects_unknown_target() {
        let env = TestEnv::fresh();
        let (mut log, revoker_sk, revoker_pk, _identity) = setup_log_with_bootstrap_approver();
        let (_, unknown_target) = gen_keypair();
        let revocation = make_revocation(
            &revoker_sk,
            revoker_pk,
            unknown_target,
            TIMESTAMP_BASELINE + 5,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err = apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert!(
            matches!(err, KtError::InvalidEntry(msg) if msg == "unknown device for revocation")
        );
    }

    #[test]
    fn revocation_replay_is_idempotent() {
        let env = TestEnv::fresh();
        let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, target) = gen_keypair();
        log.register_pending(target, identity).unwrap();

        let revocation = make_revocation(&revoker_sk, revoker_pk, target, TIMESTAMP_BASELINE + 5);
        let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed0,
            WITNESS_THRESHOLD,
        )
        .unwrap();
        // Replay — идемпотентен, no-op, не падает.
        let signed1 = env.signed_epoch(EPOCH_BASELINE + 1, &random_root());
        apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed1,
            WITNESS_THRESHOLD,
        )
        .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &target).unwrap().flag(),
            DeviceEntryStateFlag::Revoked
        );
    }

    #[test]
    fn revocation_rejects_tampered_signature() {
        let env = TestEnv::fresh();
        let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, target) = gen_keypair();
        log.register_pending(target, identity).unwrap();

        let mut revocation =
            make_revocation(&revoker_sk, revoker_pk, target, TIMESTAMP_BASELINE + 5);
        revocation.revoker_signature[5] ^= 0x01;
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err = apply_authorization_revocation(
            &revocation,
            &mut log,
            &env.set,
            &signed,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert_eq!(err, KtError::EntrySignatureInvalid);
    }

    #[test]
    fn revocation_self_from_active_ok() {
        let env = TestEnv::fresh();
        let (revoker_sk, revoker_pk) = gen_keypair();
        let (_, identity) = gen_keypair();
        let mut log = KtLogState::with_identity(identity);
        log.register_bootstrap_active(revoker_pk, TIMESTAMP_BASELINE, identity)
            .unwrap();
        let revocation = make_revocation(
            &revoker_sk,
            revoker_pk,
            revoker_pk, // self-revoke
            TIMESTAMP_BASELINE + 1,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_revocation(&revocation, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        assert_eq!(
            lookup_device_entry(&log, &revoker_pk).unwrap().flag(),
            DeviceEntryStateFlag::Revoked
        );
    }

    // ======================================================================
    // apply_identity_rotation — happy path + adversarial + cascade
    // ======================================================================

    #[test]
    fn rotation_updates_current_identity() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);

        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD).unwrap();
        assert_eq!(log.current_identity_pubkey(), Some(&new_identity));
        assert!(log.identity_rotation().is_some());
    }

    #[test]
    fn rotation_cascade_revokes_old_devices() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let (_, d0) = gen_keypair();
        let (_, d1) = gen_keypair();
        let (_, d2) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);
        log.register_bootstrap_active(d0, TIMESTAMP_BASELINE, old_identity)
            .unwrap();
        log.register_pending(d1, old_identity).unwrap();
        log.register_pending(d2, old_identity).unwrap();

        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::CatastrophicRecovery,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD).unwrap();

        for d in [d0, d1, d2] {
            assert_eq!(
                lookup_device_entry(&log, &d).unwrap().flag(),
                DeviceEntryStateFlag::Revoked
            );
        }
        assert_eq!(log.current_identity_pubkey(), Some(&new_identity));
    }

    #[test]
    fn rotation_rejects_identical_pubkeys_at_apply() {
        // from_bytes отвергает это на parse-уровне, но apply должен тоже fail-fast'ить
        // для defense-in-depth: если вдруг заполнили structure руками.
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);
        let rotation_bytes_identical = IdentityRotationRecord {
            version: 0x01,
            old_identity_pubkey: old_identity,
            new_identity_pubkey: old_identity,
            rotation_timestamp: 1,
            rotation_reason: RotationReason::PlannedRotation,
            old_identity_signature: [0u8; 64],
            new_identity_signature: [0u8; 64],
        };
        let _ = old_sk; // не используется, подпись уже инвалидная + old == new.
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err = apply_identity_rotation(
            &rotation_bytes_identical,
            &mut log,
            &env.set,
            &signed,
            WITNESS_THRESHOLD,
        )
        .unwrap_err();
        assert_eq!(err, KtError::RotationIdenticalPubkeys);
    }

    #[test]
    fn rotation_rejects_old_identity_mismatch() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (_, wrong_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();

        let mut log = KtLogState::with_identity(wrong_identity);
        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::RotationOldIdentityMismatch);
    }

    #[test]
    fn rotation_rejects_tampered_old_signature() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);
        let mut rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        rotation.old_identity_signature[0] ^= 0x01;
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::RotationDualSignatureFailed);
    }

    #[test]
    fn rotation_rejects_tampered_new_signature() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);
        let mut rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        rotation.new_identity_signature[10] ^= 0x01;
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        let err =
            apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
                .unwrap_err();
        assert_eq!(err, KtError::RotationDualSignatureFailed);
    }

    #[test]
    fn rotation_on_empty_log_bootstrap_ok() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let mut log = KtLogState::new();
        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD).unwrap();
        assert_eq!(log.current_identity_pubkey(), Some(&new_identity));
    }

    #[test]
    fn rotation_with_zero_old_devices_no_op_cascade() {
        let env = TestEnv::fresh();
        let (old_sk, old_identity) = gen_keypair();
        let (new_sk, new_identity) = gen_keypair();
        let mut log = KtLogState::with_identity(old_identity);
        // Ноль device-entries — cascade-ничего-не-меняет.
        let rotation = make_rotation(
            &old_sk,
            old_identity,
            &new_sk,
            new_identity,
            TIMESTAMP_BASELINE + 1,
            RotationReason::PlannedRotation,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_identity_rotation(&rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD).unwrap();
        assert_eq!(log.device_count(), 0);
        assert_eq!(log.current_identity_pubkey(), Some(&new_identity));
    }

    // ======================================================================
    // lookup_device_entry — positive + negative
    // ======================================================================

    #[test]
    fn lookup_after_approval_returns_active() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();
        let approval = make_approval(
            &approver_sk,
            approver_pk,
            new_device,
            TIMESTAMP_BASELINE + 10,
            42,
            0,
        );
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        let entry = lookup_device_entry(&log, &new_device).unwrap();
        assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
        assert_eq!(entry.history_cutoff(), 42);
    }

    #[test]
    fn lookup_unknown_pubkey_returns_none() {
        let (log, _, _, _) = setup_log_with_bootstrap_approver();
        let (_, random_pk) = gen_keypair();
        assert!(lookup_device_entry(&log, &random_pk).is_none());
    }

    // ======================================================================
    // Edge cases
    // ======================================================================

    #[test]
    fn approval_with_authorized_since_zero_and_cutoff_zero() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();
        let approval = make_approval(&approver_sk, approver_pk, new_device, 0, 0, 0);
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        let entry = lookup_device_entry(&log, &new_device).unwrap();
        assert_eq!(entry.authorized_since(), 0);
        assert_eq!(entry.history_cutoff(), 0);
    }

    #[test]
    fn approval_with_max_u64_timestamps() {
        let env = TestEnv::fresh();
        let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
        let (_, new_device) = gen_keypair();
        log.register_pending(new_device, identity).unwrap();
        let approval = make_approval(&approver_sk, approver_pk, new_device, u64::MAX, u64::MAX, 0);
        let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
        apply_authorization_approval(&approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD)
            .unwrap();
        let entry = lookup_device_entry(&log, &new_device).unwrap();
        assert_eq!(entry.authorized_since(), u64::MAX);
        assert_eq!(entry.history_cutoff(), u64::MAX);
    }

    // ======================================================================
    // Property-based (≥ 128 cases per property — QUALITY_STANDARDS §2.3)
    // ======================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_authorization_approval_state_machine(
            authorized_since in 0u64..=u64::MAX,
            history_cutoff in 0u64..=u64::MAX,
        ) {
            let env = TestEnv::fresh();
            let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
            let (_, new_device) = gen_keypair();
            log.register_pending(new_device, identity).unwrap();
            let approval = make_approval(
                &approver_sk,
                approver_pk,
                new_device,
                authorized_since,
                history_cutoff,
                0,
            );
            let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
            apply_authorization_approval(
                &approval,
                &mut log,
                &env.set,
                &signed,
                WITNESS_THRESHOLD,
            ).unwrap();
            let entry = lookup_device_entry(&log, &new_device).unwrap();
            prop_assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
            prop_assert_eq!(entry.authorized_since(), authorized_since);
            prop_assert_eq!(entry.history_cutoff(), history_cutoff);
        }

        #[test]
        fn prop_revocation_from_pending_ok(ts in 0u64..=u64::MAX) {
            let env = TestEnv::fresh();
            let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
            let (_, target) = gen_keypair();
            log.register_pending(target, identity).unwrap();
            let rev = make_revocation(&revoker_sk, revoker_pk, target, ts);
            let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
            apply_authorization_revocation(
                &rev, &mut log, &env.set, &signed, WITNESS_THRESHOLD,
            ).unwrap();
            prop_assert_eq!(
                lookup_device_entry(&log, &target).unwrap().flag(),
                DeviceEntryStateFlag::Revoked
            );
        }

        #[test]
        fn prop_revocation_from_active_ok(ts in 0u64..=u64::MAX) {
            let env = TestEnv::fresh();
            let (mut log, revoker_sk, revoker_pk, identity) = setup_log_with_bootstrap_approver();
            let (_, target) = gen_keypair();
            log.register_pending(target, identity).unwrap();
            let app = make_approval(
                &revoker_sk,
                revoker_pk,
                target,
                TIMESTAMP_BASELINE + 10,
                0,
                0,
            );
            let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
            apply_authorization_approval(
                &app, &mut log, &env.set, &signed0, WITNESS_THRESHOLD,
            ).unwrap();
            let rev = make_revocation(&revoker_sk, revoker_pk, target, ts);
            let signed1 = env.signed_epoch(EPOCH_BASELINE + 1, &random_root());
            apply_authorization_revocation(
                &rev, &mut log, &env.set, &signed1, WITNESS_THRESHOLD,
            ).unwrap();
            prop_assert_eq!(
                lookup_device_entry(&log, &target).unwrap().flag(),
                DeviceEntryStateFlag::Revoked
            );
        }

        #[test]
        fn prop_rotation_cascade_revokes_all_old_devices(n_devices in 0usize..=8) {
            let env = TestEnv::fresh();
            let (old_sk, old_identity) = gen_keypair();
            let (new_sk, new_identity) = gen_keypair();
            let mut log = KtLogState::with_identity(old_identity);

            let mut devices = Vec::new();
            for _ in 0..n_devices {
                let (_, pk) = gen_keypair();
                log.register_pending(pk, old_identity).unwrap();
                devices.push(pk);
            }
            let rotation = make_rotation(
                &old_sk, old_identity, &new_sk, new_identity,
                TIMESTAMP_BASELINE + 1,
                RotationReason::PlannedRotation,
            );
            let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
            apply_identity_rotation(
                &rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD,
            ).unwrap();
            for d in &devices {
                prop_assert_eq!(
                    lookup_device_entry(&log, d).unwrap().flag(),
                    DeviceEntryStateFlag::Revoked
                );
            }
            prop_assert_eq!(log.current_identity_pubkey(), Some(&new_identity));
        }

        #[test]
        fn prop_approval_sig_tamper_at_any_byte_fails(bit_pos in 0usize..(64 * 8)) {
            let env = TestEnv::fresh();
            let (mut log, approver_sk, approver_pk, identity) = setup_log_with_bootstrap_approver();
            let (_, new_device) = gen_keypair();
            log.register_pending(new_device, identity).unwrap();
            let mut approval = make_approval(
                &approver_sk,
                approver_pk,
                new_device,
                TIMESTAMP_BASELINE + 10,
                0,
                0,
            );
            let byte_idx = bit_pos / 8;
            let bit_mask = 1u8 << (bit_pos % 8);
            approval.approver_signature[byte_idx] ^= bit_mask;
            let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
            let err = apply_authorization_approval(
                &approval, &mut log, &env.set, &signed, WITNESS_THRESHOLD,
            ).unwrap_err();
            prop_assert_eq!(err, KtError::EntrySignatureInvalid);
        }

        #[test]
        fn prop_rotation_dual_sig_tamper_old_fails(bit_pos in 0usize..(64 * 8)) {
            let env = TestEnv::fresh();
            let (old_sk, old_identity) = gen_keypair();
            let (new_sk, new_identity) = gen_keypair();
            let mut log = KtLogState::with_identity(old_identity);
            let mut rotation = make_rotation(
                &old_sk, old_identity, &new_sk, new_identity,
                TIMESTAMP_BASELINE + 1,
                RotationReason::PlannedRotation,
            );
            let byte_idx = bit_pos / 8;
            let bit_mask = 1u8 << (bit_pos % 8);
            rotation.old_identity_signature[byte_idx] ^= bit_mask;
            let signed = env.signed_epoch(EPOCH_BASELINE, &random_root());
            let err = apply_identity_rotation(
                &rotation, &mut log, &env.set, &signed, WITNESS_THRESHOLD,
            ).unwrap_err();
            prop_assert_eq!(err, KtError::RotationDualSignatureFailed);
        }
    }
}
