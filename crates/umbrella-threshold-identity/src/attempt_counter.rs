//! # Attempt counter state machine
//!
//! ```text
//! PIN_state ─wrong×3─► Recovery24_state ─wrong×3─► Emergency12_state ─wrong×5─► Deleted
//!     │                       │                            │
//!     │                       └─────────── correct ────────┴──► Authenticated
//!     │
//!     └─────────── correct ───► Authenticated
//! ```
//!
//! Counters persist across server restarts. Each transition is atomic w.r.t.
//! storage (single SQL UPDATE on Postgres / write to mlock'd file on simple
//! deployments).
//!
//! Wrong-attempt limits per round-6 spec §«Universal entry rule»:
//! - PIN: 3 wrong → escalate to 24-word recovery.
//! - 24-word: 3 wrong → escalate to 12-word emergency.
//! - 12-word: 5 wrong → permanent delete (UNRECOVERABLE).

use crate::error::{PolicyRejection, ThresholdIdentityError, ThresholdIdentityResult};
use crate::{WRONG_12WORD_LIMIT, WRONG_24WORD_LIMIT, WRONG_PIN_LIMIT};

/// Current escalation level for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationLevel {
    /// Daily-unlock state, PIN required.
    Pin,
    /// 3+ wrong PIN: caller must enter 24-word recovery (+ OTP if enabled).
    Recovery24,
    /// 3+ wrong 24-word: caller must enter 12-word emergency.
    Emergency12,
    /// 5+ wrong 12-word: account permanently deleted, no further auth possible.
    Deleted,
}

/// In-memory attempt counter. Production server persists each transition to
/// durable storage (one row per `(server_id, account_id)`).
#[derive(Debug, Clone)]
pub struct AttemptCounter {
    /// Current escalation level.
    pub level: EscalationLevel,
    /// Wrong attempts within current level.
    pub wrong_at_level: u8,
}

impl Default for AttemptCounter {
    fn default() -> Self {
        Self {
            level: EscalationLevel::Pin,
            wrong_at_level: 0,
        }
    }
}

impl AttemptCounter {
    /// Resets to a fresh PIN state — called on successful auth at any level.
    pub fn reset_to_pin(&mut self) {
        self.level = EscalationLevel::Pin;
        self.wrong_at_level = 0;
    }

    /// Records one wrong attempt at the current level. Returns the new level
    /// (which may be escalated). Returns `Err(AccountDeleted)` if the wrong
    /// attempt at `Emergency12` reaches the delete threshold.
    pub fn record_wrong(&mut self) -> ThresholdIdentityResult<EscalationLevel> {
        let limit = match self.level {
            EscalationLevel::Pin => WRONG_PIN_LIMIT,
            EscalationLevel::Recovery24 => WRONG_24WORD_LIMIT,
            EscalationLevel::Emergency12 => WRONG_12WORD_LIMIT,
            EscalationLevel::Deleted => {
                return Err(ThresholdIdentityError::AccountDeleted);
            }
        };
        self.wrong_at_level = self.wrong_at_level.saturating_add(1);
        if self.wrong_at_level >= limit {
            // Reached limit — escalate.
            self.level = match self.level {
                EscalationLevel::Pin => EscalationLevel::Recovery24,
                EscalationLevel::Recovery24 => EscalationLevel::Emergency12,
                EscalationLevel::Emergency12 => EscalationLevel::Deleted,
                EscalationLevel::Deleted => EscalationLevel::Deleted,
            };
            self.wrong_at_level = 0;
            // Surface `AccountDeleted` if escalation reached Deleted.
            if self.level == EscalationLevel::Deleted {
                return Err(ThresholdIdentityError::AccountDeleted);
            }
        }
        Ok(self.level)
    }

    /// Returns rejection reason if the account cannot accept auth at the
    /// expected level.
    pub fn check_can_attempt(
        &self,
        expected_level: EscalationLevel,
    ) -> ThresholdIdentityResult<()> {
        if self.level == EscalationLevel::Deleted {
            return Err(ThresholdIdentityError::AccountDeleted);
        }
        if self.level != expected_level {
            return Err(ThresholdIdentityError::PolicyReject(match self.level {
                EscalationLevel::Pin => PolicyRejection::PinAttemptsExhausted,
                EscalationLevel::Recovery24 => PolicyRejection::PinAttemptsExhausted,
                EscalationLevel::Emergency12 => PolicyRejection::Recovery24Exhausted,
                EscalationLevel::Deleted => PolicyRejection::Emergency12Exhausted,
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_pin_3_wrong_to_recovery24() {
        let mut c = AttemptCounter::default();
        assert_eq!(c.record_wrong().unwrap(), EscalationLevel::Pin);
        assert_eq!(c.record_wrong().unwrap(), EscalationLevel::Pin);
        // 3rd wrong escalates.
        assert_eq!(c.record_wrong().unwrap(), EscalationLevel::Recovery24);
        assert_eq!(c.wrong_at_level, 0);
    }

    #[test]
    fn escalation_recovery24_3_wrong_to_emergency12() {
        let mut c = AttemptCounter {
            level: EscalationLevel::Recovery24,
            wrong_at_level: 0,
        };
        c.record_wrong().unwrap();
        c.record_wrong().unwrap();
        let after = c.record_wrong().unwrap();
        assert_eq!(after, EscalationLevel::Emergency12);
    }

    #[test]
    fn emergency12_5_wrong_permanently_deletes() {
        let mut c = AttemptCounter {
            level: EscalationLevel::Emergency12,
            wrong_at_level: 0,
        };
        c.record_wrong().unwrap();
        c.record_wrong().unwrap();
        c.record_wrong().unwrap();
        c.record_wrong().unwrap();
        let err = c.record_wrong().unwrap_err();
        assert!(matches!(err, ThresholdIdentityError::AccountDeleted));
        assert_eq!(c.level, EscalationLevel::Deleted);
    }

    #[test]
    fn reset_clears_after_successful_auth() {
        let mut c = AttemptCounter {
            level: EscalationLevel::Recovery24,
            wrong_at_level: 2,
        };
        c.reset_to_pin();
        assert_eq!(c.level, EscalationLevel::Pin);
        assert_eq!(c.wrong_at_level, 0);
    }

    #[test]
    fn deleted_account_rejects_further_attempts() {
        let mut c = AttemptCounter {
            level: EscalationLevel::Deleted,
            wrong_at_level: 0,
        };
        let err = c.record_wrong().unwrap_err();
        assert!(matches!(err, ThresholdIdentityError::AccountDeleted));
    }
}
