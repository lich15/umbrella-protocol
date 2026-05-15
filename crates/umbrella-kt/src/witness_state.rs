//! Local witness non-equivocation state.
//! Локальное состояние свидетеля против двойной подписи.

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::observation::KtLogId;
use crate::witness::SignedEpochRoot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WitnessLedgerEntry {
    log_id: KtLogId,
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
}

/// Decision returned by witness signing memory.
/// Решение памяти свидетеля перед подписью.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessSigningDecision {
    /// First head recorded for this log epoch.
    /// Первая голова для этой эпохи журнала.
    FirstSignature,
    /// Same root and size were already recorded.
    /// Такой же корень и размер уже были записаны.
    RepeatedSameHead,
}

/// Small local ledger preventing a witness from signing two heads for one epoch.
/// Малый локальный журнал, который не даёт свидетелю подписать две головы одной эпохи.
#[derive(Clone, Debug, Default)]
pub struct WitnessSigningLedger {
    entries: Vec<WitnessLedgerEntry>,
}

impl WitnessSigningLedger {
    /// Creates an empty ledger.
    /// Создаёт пустой журнал.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a head or rejects a same-epoch fork.
    /// Записывает голову или отвергает раздвоение той же эпохи.
    pub fn record_or_reject(
        &mut self,
        log_id: KtLogId,
        signed: &SignedEpochRoot,
    ) -> Result<WitnessSigningDecision> {
        for entry in &self.entries {
            if entry.log_id == log_id && entry.epoch == signed.epoch {
                if entry.root == signed.root && entry.log_size == signed.log_size {
                    return Ok(WitnessSigningDecision::RepeatedSameHead);
                }
                return Err(KtError::InvalidEntry("witness equivocation attempt"));
            }
        }
        self.entries.push(WitnessLedgerEntry {
            log_id,
            epoch: signed.epoch,
            root: signed.root,
            log_size: signed.log_size,
        });
        Ok(WitnessSigningDecision::FirstSignature)
    }

    /// Number of recorded log epochs.
    /// Количество записанных эпох журнала.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no head was recorded.
    /// True, если ещё нет записей.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
