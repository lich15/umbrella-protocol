//! # Time-locked recovery
//!
//! Round-6 design: восстановление с нового устройства через 24-слова занимает
//! ровно 24 часа. В течение этого времени primary device пользователя получает
//! push-notification и может отменить recovery. Если primary device уже потерян,
//! recovery идёт до конца — adversary который владеет 24-словами без
//! сговора с primary device получит доступ через 24 часа, что даёт жертве окно
//! для замены ключей либо изоляции.
//!
//! Optional acceleration: при вводе старого PIN time-lock сокращается до 1 часа.
//! Это «soft factor» — старый PIN мог быть украден, но обычно атакующий с
//! устройством + 24-словами + PIN — крайне редкое сочетание (sub-percent).
//!
//! Time-locked recovery: 24h delay with push to primary device. Optional 1h
//! acceleration via old PIN.

use std::time::SystemTime;

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};
use crate::{RECOVERY_TIME_LOCK_ACCELERATED_SECS, RECOVERY_TIME_LOCK_SECS};

/// State одного recovery-запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryState {
    /// Recovery initiated, waiting for time-lock to elapse.
    Pending {
        /// When the recovery is allowed to complete (UNIX seconds).
        unlock_at: u64,
        /// Whether primary device push was confirmed sent.
        push_sent: bool,
    },
    /// Primary device cancelled the recovery.
    Cancelled,
    /// Time-lock elapsed, recovery completed.
    Completed,
}

/// Recovery request tracker. Server-side persistent state.
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    /// Anonymous account ID being recovered.
    pub anonymous_id: [u8; 32],
    /// Current state.
    pub state: RecoveryState,
    /// Whether old PIN acceleration was applied (1h vs 24h time-lock).
    pub accelerated: bool,
}

impl RecoveryRequest {
    /// Initiates a recovery — sets `unlock_at = now + 24h` (or 1h if `old_pin_valid`).
    /// Caller responsible for sending push to primary device after this call.
    pub fn initiate(
        anonymous_id: [u8; 32],
        now: SystemTime,
        old_pin_valid: bool,
    ) -> ThresholdIdentityResult<Self> {
        let delay = if old_pin_valid {
            RECOVERY_TIME_LOCK_ACCELERATED_SECS
        } else {
            RECOVERY_TIME_LOCK_SECS
        };
        let unlock_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ThresholdIdentityError::Io("system clock before epoch".into()))?
            .as_secs()
            + delay;
        Ok(Self {
            anonymous_id,
            state: RecoveryState::Pending {
                unlock_at,
                push_sent: false,
            },
            accelerated: old_pin_valid,
        })
    }

    /// Marks that push has been sent to primary device.
    pub fn mark_push_sent(&mut self) {
        if let RecoveryState::Pending {
            ref mut push_sent, ..
        } = self.state
        {
            *push_sent = true;
        }
    }

    /// Primary device received push and cancelled — invalidate recovery.
    pub fn cancel(&mut self) -> ThresholdIdentityResult<()> {
        match self.state {
            RecoveryState::Pending { .. } => {
                self.state = RecoveryState::Cancelled;
                Ok(())
            }
            RecoveryState::Cancelled => Err(ThresholdIdentityError::RecoveryCancelled),
            RecoveryState::Completed => Err(ThresholdIdentityError::PolicyReject(
                crate::error::PolicyRejection::HeartbeatMissing,
            )),
        }
    }

    /// Attempts to complete recovery. Returns error if time-lock not elapsed
    /// yet, or if cancelled.
    pub fn try_complete(&mut self, now: SystemTime) -> ThresholdIdentityResult<()> {
        match self.state {
            RecoveryState::Pending { unlock_at, .. } => {
                let now_secs = now
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| ThresholdIdentityError::Io("system clock".into()))?
                    .as_secs();
                if now_secs < unlock_at {
                    return Err(ThresholdIdentityError::TimeLockNotElapsed {
                        remaining_secs: unlock_at - now_secs,
                    });
                }
                self.state = RecoveryState::Completed;
                Ok(())
            }
            RecoveryState::Cancelled => Err(ThresholdIdentityError::RecoveryCancelled),
            RecoveryState::Completed => Ok(()),
        }
    }

    /// Returns remaining seconds until time-lock elapses, or `None` if not pending.
    pub fn remaining_secs(&self, now: SystemTime) -> Option<u64> {
        if let RecoveryState::Pending { unlock_at, .. } = self.state {
            let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
            Some(unlock_at.saturating_sub(now_secs))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    #[test]
    fn full_24h_time_lock_no_acceleration() {
        let r = RecoveryRequest::initiate([1; 32], t0(), false).unwrap();
        assert_eq!(r.remaining_secs(t0()), Some(86_400));
        let mut r = r;
        let err = r
            .try_complete(t0() + Duration::from_secs(86_399))
            .unwrap_err();
        assert!(matches!(
            err,
            ThresholdIdentityError::TimeLockNotElapsed { .. }
        ));
        // At 24h+1, completes.
        r.try_complete(t0() + Duration::from_secs(86_401)).unwrap();
        assert!(matches!(r.state, RecoveryState::Completed));
    }

    #[test]
    fn accelerated_1h_with_old_pin() {
        let r = RecoveryRequest::initiate([1; 32], t0(), true).unwrap();
        assert_eq!(r.remaining_secs(t0()), Some(3_600));
        assert!(r.accelerated);
    }

    #[test]
    fn cancel_by_primary_device_blocks_completion() {
        let mut r = RecoveryRequest::initiate([1; 32], t0(), false).unwrap();
        r.cancel().unwrap();
        let err = r
            .try_complete(t0() + Duration::from_secs(100_000))
            .unwrap_err();
        assert!(matches!(err, ThresholdIdentityError::RecoveryCancelled));
    }

    #[test]
    fn cancel_twice_returns_cancelled_error() {
        let mut r = RecoveryRequest::initiate([1; 32], t0(), false).unwrap();
        r.cancel().unwrap();
        let err = r.cancel().unwrap_err();
        assert!(matches!(err, ThresholdIdentityError::RecoveryCancelled));
    }

    #[test]
    fn mark_push_sent_transitions_state() {
        let mut r = RecoveryRequest::initiate([1; 32], t0(), false).unwrap();
        r.mark_push_sent();
        match r.state {
            RecoveryState::Pending { push_sent, .. } => assert!(push_sent),
            _ => panic!("expected Pending"),
        }
    }
}
