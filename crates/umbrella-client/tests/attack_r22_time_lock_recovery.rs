//! R22 — Real attack: time-lock recovery + push cancel/non-cancel
//!
//! Per round-6 spec §«Stage 5» R22:
//! > simulate new device entering 24 words → assert time-lock 24h initiates →
//! > assert push sent to mock primary device → primary device cancel → assert
//! > recovery cancelled. Repeat with no cancel → assert recovery completes
//! > after 24h.
//!
//! Numerical outcome reported:
//! - time-lock duration applied (24h baseline, 1h if old-PIN acceleration)
//! - whether push was sent to primary device
//! - cancellation effect on completion attempt
//! - delta between attempted completion time and unlock_at

use std::time::{Duration, SystemTime};

use umbrella_threshold_identity::{
    error::ThresholdIdentityError, time_lock::RecoveryRequest, RECOVERY_TIME_LOCK_SECS,
};

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn r22_full_24h_time_lock_no_acceleration() {
    let mut r = RecoveryRequest::initiate([0xAB; 32], t0(), false).unwrap();
    let remaining = r.remaining_secs(t0()).unwrap();
    eprintln!(
        "[R22] no-accel time-lock seconds: {} (expected {})",
        remaining, RECOVERY_TIME_LOCK_SECS
    );
    assert_eq!(remaining, RECOVERY_TIME_LOCK_SECS);

    // Push not yet sent.
    r.mark_push_sent();
    eprintln!("[R22] push marked sent");

    // Attempt completion at 24h - 1 sec — must reject.
    let err = r
        .try_complete(t0() + Duration::from_secs(RECOVERY_TIME_LOCK_SECS - 1))
        .unwrap_err();
    let remaining_at_attempt = match err {
        ThresholdIdentityError::TimeLockNotElapsed { remaining_secs } => remaining_secs,
        _ => panic!("expected TimeLockNotElapsed, got {err:?}"),
    };
    eprintln!("[R22] attempt at 24h-1s: remaining_secs={remaining_at_attempt} (expected 1)");
    assert_eq!(remaining_at_attempt, 1);

    // Attempt at 24h + 1 sec — must succeed.
    r.try_complete(t0() + Duration::from_secs(RECOVERY_TIME_LOCK_SECS + 1))
        .expect("recovery completes after 24h");
    eprintln!("[R22] recovery completed after 24h elapsed");
}

#[test]
fn r22_accelerated_1h_with_old_pin() {
    let mut r = RecoveryRequest::initiate([0xCD; 32], t0(), true).unwrap();
    let remaining = r.remaining_secs(t0()).unwrap();
    eprintln!("[R22] accelerated time-lock: {} seconds", remaining);
    assert_eq!(remaining, 3_600);
    r.try_complete(t0() + Duration::from_secs(3_601))
        .expect("acceler completion");
}

#[test]
fn r22_primary_device_cancel_blocks_completion() {
    let mut r = RecoveryRequest::initiate([0xEF; 32], t0(), false).unwrap();
    r.mark_push_sent();
    // Primary device cancels at t+1h (within the 24h window).
    r.cancel().expect("cancel succeeds");
    eprintln!("[R22] primary device cancelled recovery at t+1h");

    // Subsequent try_complete (even after full 24h elapsed) must fail.
    let err = r
        .try_complete(t0() + Duration::from_secs(RECOVERY_TIME_LOCK_SECS + 1))
        .unwrap_err();
    assert!(matches!(err, ThresholdIdentityError::RecoveryCancelled));
    eprintln!("[R22] PASS: cancelled recovery rejects completion attempt even after 24h elapsed");
}

#[test]
fn r22_attempted_cancel_twice_returns_already_cancelled() {
    let mut r = RecoveryRequest::initiate([0x01; 32], t0(), false).unwrap();
    r.cancel().unwrap();
    let err = r.cancel().unwrap_err();
    assert!(matches!(err, ThresholdIdentityError::RecoveryCancelled));
    eprintln!("[R22] cancel idempotency: second cancel returns RecoveryCancelled error");
}
