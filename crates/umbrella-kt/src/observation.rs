//! Public KT epoch observations and split-view evidence.
//! Публичные наблюдения эпох KT и доказательства раздвоения журнала.
//!
//! This module intentionally stores only public epoch-head data: log id,
//! previous root, current signed root, log size, timestamp, and witness
//! signatures. It does not store account id, phone number, contact graph,
//! chat id, or a raw device list.
//! Модуль намеренно хранит только публичные данные головы эпохи: id журнала,
//! предыдущий корень, текущий подписанный корень, размер журнала, время и
//! подписи свидетелей. Здесь нет account_id, телефона, графа контактов,
//! chat_id или сырого списка устройств.

use umbrella_crypto_primitives::sig::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::witness::{verify_signed_epoch, SignedEpochRoot, WitnessSet, WitnessSignature};

/// Current public observation wire-format version.
/// Текущая версия публичного формата наблюдения.
pub const KT_OBSERVATION_VERSION: u8 = 0x01;

/// Maximum witness signatures accepted in one public observation.
/// Максимум подписей свидетелей в одном публичном наблюдении.
pub const MAX_OBSERVATION_SIGNATURES: usize = 64;

/// Public id of a KT log. It must not encode a user identifier.
/// Публичный id KT-журнала. Он не должен кодировать пользователя.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KtLogId([u8; 32]);

impl KtLogId {
    /// Builds a log id from public bytes.
    /// Создаёт id журнала из публичных байтов.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the public bytes.
    /// Возвращает публичные байты.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Public observation of one signed KT epoch head.
/// Публичное наблюдение одной подписанной головы эпохи KT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtObservation {
    /// Wire-format version. Версия формата.
    pub version: u8,
    /// Public log id. Публичный id журнала.
    pub log_id: KtLogId,
    /// Previous epoch root claimed by this observation.
    /// Предыдущий корень эпохи, заявленный этим наблюдением.
    pub previous_root: [u8; NODE_HASH_LEN],
    /// Signed current epoch root.
    /// Подписанный текущий корень эпохи.
    pub signed: SignedEpochRoot,
}

impl KtObservation {
    /// Creates a current-version public observation.
    /// Создаёт публичное наблюдение текущей версии.
    #[must_use]
    pub fn new(
        log_id: KtLogId,
        previous_root: [u8; NODE_HASH_LEN],
        signed: SignedEpochRoot,
    ) -> Self {
        Self {
            version: KT_OBSERVATION_VERSION,
            log_id,
            previous_root,
            signed,
        }
    }

    /// Verifies version and witness threshold.
    /// Проверяет версию и порог подписей свидетелей.
    pub fn validate(&self, witness_set: &WitnessSet, threshold: usize) -> Result<()> {
        if self.version != KT_OBSERVATION_VERSION {
            return Err(KtError::InvalidObservation(
                "unsupported observation version",
            ));
        }
        verify_signed_epoch(&self.signed, witness_set, threshold)
    }

    /// True when two observations describe the same log epoch.
    /// True, если два наблюдения описывают одну эпоху одного журнала.
    #[must_use]
    pub fn same_log_epoch(&self, other: &Self) -> bool {
        self.log_id == other.log_id && self.signed.epoch == other.signed.epoch
    }

    /// True when two same-epoch observations cannot both be the same view.
    /// True, если два наблюдения одной эпохи не могут быть одной и той же версией.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.same_log_epoch(other)
            && (self.previous_root != other.previous_root
                || self.signed.root != other.signed.root
                || self.signed.log_size != other.signed.log_size)
    }

    /// Encodes only public observation data.
    /// Кодирует только публичные данные наблюдения.
    #[must_use]
    pub fn encode_public(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 32
                + NODE_HASH_LEN
                + 8
                + NODE_HASH_LEN
                + 8
                + 8
                + 2
                + self.signed.signatures.len() * (PUBLIC_KEY_LEN + SIGNATURE_LEN),
        );
        out.push(self.version);
        out.extend_from_slice(&self.log_id.to_bytes());
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.signed.epoch.to_be_bytes());
        out.extend_from_slice(&self.signed.root);
        out.extend_from_slice(&self.signed.log_size.to_be_bytes());
        out.extend_from_slice(&self.signed.timestamp_unix_millis.to_be_bytes());
        let count = u16::try_from(self.signed.signatures.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for sig in &self.signed.signatures {
            out.extend_from_slice(&sig.witness.to_bytes());
            out.extend_from_slice(&sig.signature);
        }
        out
    }

    /// Decodes public observation data.
    /// Декодирует публичные данные наблюдения.
    pub fn decode_public(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0usize;
        let version = take::<1>(bytes, &mut offset)?[0];
        if version != KT_OBSERVATION_VERSION {
            return Err(KtError::InvalidObservation(
                "unsupported observation version",
            ));
        }
        let log_id = KtLogId::from_bytes(take::<32>(bytes, &mut offset)?);
        let previous_root = take::<NODE_HASH_LEN>(bytes, &mut offset)?;
        let epoch = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let root = take::<NODE_HASH_LEN>(bytes, &mut offset)?;
        let log_size = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let timestamp_unix_millis = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let signature_count = u16::from_be_bytes(take::<2>(bytes, &mut offset)?) as usize;
        if signature_count > MAX_OBSERVATION_SIGNATURES {
            return Err(KtError::InvalidObservation(
                "too many observation signatures",
            ));
        }
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            let witness = crate::witness::WitnessPublic::from_bytes(take::<PUBLIC_KEY_LEN>(
                bytes,
                &mut offset,
            )?);
            let signature = take::<SIGNATURE_LEN>(bytes, &mut offset)?;
            signatures.push(WitnessSignature { witness, signature });
        }
        if offset != bytes.len() {
            return Err(KtError::InvalidObservation("trailing observation bytes"));
        }
        Ok(Self {
            version,
            log_id,
            previous_root,
            signed: SignedEpochRoot {
                epoch,
                root,
                log_size,
                timestamp_unix_millis,
                signatures,
            },
        })
    }
}

/// Verifiable proof that a KT log showed two signed views for one epoch.
/// Проверяемое доказательство, что KT-журнал показал две подписанные версии одной эпохи.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationEvidence {
    first: KtObservation,
    second: KtObservation,
}

impl EquivocationEvidence {
    /// Builds evidence only when both observations are valid and conflicting.
    /// Создаёт доказательство только когда оба наблюдения валидны и конфликтуют.
    pub fn try_new(
        first: KtObservation,
        second: KtObservation,
        witness_set: &WitnessSet,
        threshold: usize,
    ) -> Result<Self> {
        first.validate(witness_set, threshold)?;
        second.validate(witness_set, threshold)?;
        if first.log_id != second.log_id {
            return Err(KtError::InvalidObservation("different log id"));
        }
        if first.signed.epoch != second.signed.epoch {
            return Err(KtError::InvalidObservation("different epoch"));
        }
        if !first.conflicts_with(&second) {
            return Err(KtError::InvalidObservation("observations do not conflict"));
        }
        Ok(Self { first, second })
    }

    /// Re-verifies the evidence.
    /// Повторно проверяет доказательство.
    pub fn verify(&self, witness_set: &WitnessSet, threshold: usize) -> Result<()> {
        Self::try_new(
            self.first.clone(),
            self.second.clone(),
            witness_set,
            threshold,
        )
        .map(|_| ())
    }

    /// First conflicting observation.
    /// Первое конфликтующее наблюдение.
    #[must_use]
    pub const fn first(&self) -> &KtObservation {
        &self.first
    }

    /// Second conflicting observation.
    /// Второе конфликтующее наблюдение.
    #[must_use]
    pub const fn second(&self) -> &KtObservation {
        &self.second
    }
}

/// Trust decision after comparing KT observations.
/// Решение доверия после сравнения KT-наблюдений.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KtTrustDecision {
    /// The observations are valid and consistent.
    /// Наблюдения валидны и согласованы.
    Accepted,
    /// One valid observation is not enough to prove global consistency.
    /// Одного валидного наблюдения мало для доказательства общей согласованности.
    NeedsObservation,
    /// Same log epoch has two valid conflicting views.
    /// У одной эпохи журнала есть две валидные конфликтующие версии.
    EquivocationDetected(Box<EquivocationEvidence>),
}

/// Compares two public observations.
/// Сравнивает два публичных наблюдения.
pub fn compare_observations(
    first: &KtObservation,
    second: &KtObservation,
    witness_set: &WitnessSet,
    threshold: usize,
) -> Result<KtTrustDecision> {
    first.validate(witness_set, threshold)?;
    second.validate(witness_set, threshold)?;
    if first.log_id != second.log_id {
        return Err(KtError::InvalidObservation("different log id"));
    }
    if first.conflicts_with(second) {
        return Ok(KtTrustDecision::EquivocationDetected(Box::new(
            EquivocationEvidence::try_new(first.clone(), second.clone(), witness_set, threshold)?,
        )));
    }
    if first.same_log_epoch(second) {
        return Ok(KtTrustDecision::Accepted);
    }
    Ok(KtTrustDecision::NeedsObservation)
}

/// Local history of public KT observations for one log.
/// Локальная история публичных KT-наблюдений одного журнала.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KtObservationHistory {
    log_id: Option<KtLogId>,
    last: Option<KtObservation>,
}

impl KtObservationHistory {
    /// Creates an empty observation history.
    /// Создаёт пустую историю наблюдений.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes a signed epoch head and returns a trust decision.
    /// Запоминает подписанную голову эпохи и возвращает решение доверия.
    pub fn observe(
        &mut self,
        observation: KtObservation,
        witness_set: &WitnessSet,
        threshold: usize,
    ) -> Result<KtTrustDecision> {
        observation.validate(witness_set, threshold)?;
        match self.log_id {
            Some(existing) if existing != observation.log_id => {
                return Err(KtError::InvalidObservation("different log id"));
            }
            None => self.log_id = Some(observation.log_id),
            Some(_) => {}
        }

        let Some(last) = self.last.clone() else {
            self.last = Some(observation);
            return Ok(KtTrustDecision::NeedsObservation);
        };

        if observation.signed.epoch < last.signed.epoch {
            return Err(KtError::InvalidEntry("epoch regression"));
        }

        if observation.signed.epoch == last.signed.epoch {
            if observation.conflicts_with(&last) {
                return Ok(KtTrustDecision::EquivocationDetected(Box::new(
                    EquivocationEvidence::try_new(last, observation, witness_set, threshold)?,
                )));
            }
            self.last = Some(observation);
            return Ok(KtTrustDecision::Accepted);
        }

        if observation.previous_root != last.signed.root {
            return Err(KtError::InvalidEntry("epoch chain broken"));
        }

        self.last = Some(observation);
        Ok(KtTrustDecision::Accepted)
    }

    /// Returns the last accepted observation.
    /// Возвращает последнее принятое наблюдение.
    #[must_use]
    pub const fn last(&self) -> Option<&KtObservation> {
        self.last.as_ref()
    }
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(KtError::InvalidObservation("observation offset overflow"))?;
    if end > bytes.len() {
        return Err(KtError::InvalidObservation("truncated observation"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(out)
}
