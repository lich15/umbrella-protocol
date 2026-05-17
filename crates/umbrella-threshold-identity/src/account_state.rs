//! # Server-side account state
//!
//! State per-account (per-server-id) хранимое сервером:
//! - `anonymous_id`: 32 bytes, derived from master_key — server's view of account.
//! - `encrypted_share`: FROST `KeyPackage` зашифрованный по `pin_hash` (Argon2id).
//! - `pin_hash` + `pin_salt`: 32 + 16 bytes для verify-PIN роли.
//! - `attempt_counter`: 3/3/5 ratchet.
//! - `recovery_state`: Optional time-lock state.
//! - `dead_man`: Opt-in dead-man switch.
//! - `last_heartbeat`: monotonic timestamp от любого client device.
//! - `revoked`: bool — UNRECOVERABLE_DELETE marker.
//!
//! In production, this struct backs a row in `account_state` table (Postgres
//! / SQLite). The in-memory model in this crate is the canonical schema.
//!
//! Server-side account state — single source of truth for one user-server pair.

use std::time::SystemTime;

use crate::attempt_counter::{AttemptCounter, EscalationLevel};
use crate::dead_man::DeadManState;
use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};
use crate::pin_kdf;
use crate::time_lock::RecoveryRequest;

/// Опции, заданные пользователем при регистрации.
#[derive(Debug, Clone, Default)]
pub struct AccountOptions {
    /// OTP TOTP shared-secret (если пользователь включил 2FA).
    pub otp_secret: Option<[u8; 20]>,
    /// Phone number (E.164) for friend discovery only. Never used for recovery.
    pub phone_e164: Option<String>,
    /// Push-channel endpoint для primary device.
    pub push_endpoint: Option<String>,
}

/// Один аккаунт на одном сервере. 5 серверов имеют 5 независимых `AccountState`
/// для того же пользователя; cross-server correlation требует `master_key`.
#[derive(Debug)]
pub struct AccountState {
    /// Anonymous ID (от master_key + server_id).
    pub anonymous_id: [u8; 32],
    /// 32-byte Argon2id-derived PIN hash (для verify roles).
    pub pin_hash: [u8; pin_kdf::OUTPUT_LEN],
    /// 16-byte PIN salt (public, per-account).
    pub pin_salt: [u8; pin_kdf::SALT_LEN],
    /// Encrypted FROST share + envelope (production: stored encrypted via PIN-derived key).
    pub encrypted_share: Vec<u8>,
    /// Universal entry rule counter.
    pub counter: AttemptCounter,
    /// Optional active recovery request (24h time-lock).
    pub recovery: Option<RecoveryRequest>,
    /// Opt-in dead-man switch.
    pub dead_man: DeadManState,
    /// Account options at registration.
    pub options: AccountOptions,
    /// Set true after UNRECOVERABLE_DELETE.
    pub revoked: bool,
}

impl AccountState {
    /// Constructs a fresh account state with given PIN.
    pub fn new(
        anonymous_id: [u8; 32],
        pin: &[u8],
        pin_salt: [u8; pin_kdf::SALT_LEN],
        encrypted_share: Vec<u8>,
        options: AccountOptions,
        now: SystemTime,
    ) -> ThresholdIdentityResult<Self> {
        let derived = pin_kdf::derive_pin_root(pin, &pin_salt)?;
        let pin_hash = *derived.expose();
        Ok(Self {
            anonymous_id,
            pin_hash,
            pin_salt,
            encrypted_share,
            counter: AttemptCounter::default(),
            recovery: None,
            dead_man: DeadManState::new(std::time::Duration::from_secs(30 * 86_400), now),
            options,
            revoked: false,
        })
    }

    /// PIN-entry endpoint. Returns Ok if PIN matches and account not revoked,
    /// otherwise updates counter and surfaces an error.
    pub fn try_pin(&mut self, candidate: &[u8]) -> ThresholdIdentityResult<()> {
        if self.revoked {
            return Err(ThresholdIdentityError::AccountDeleted);
        }
        self.counter.check_can_attempt(EscalationLevel::Pin)?;
        let ok = pin_kdf::verify_pin(candidate, &self.pin_salt, &self.pin_hash)?;
        if ok {
            self.counter.reset_to_pin();
            Ok(())
        } else {
            self.counter.record_wrong()?;
            Err(ThresholdIdentityError::WrongPin)
        }
    }

    /// Issues UNRECOVERABLE_DELETE. Wipes encrypted_share + pin_hash. Idempotent.
    pub fn unrecoverable_delete(&mut self) {
        use zeroize::Zeroize;
        self.pin_hash.zeroize();
        self.encrypted_share.zeroize();
        self.encrypted_share.clear();
        self.revoked = true;
        self.recovery = None;
        self.counter = AttemptCounter::default();
        self.counter.level = EscalationLevel::Deleted;
    }

    /// Heartbeat from device — updates dead-man timer.
    pub fn record_heartbeat(&mut self, now: SystemTime) {
        self.dead_man.record_heartbeat(now);
    }

    /// Periodic check (e.g. cron) — fires dead-man auto-wipe if grace period
    /// elapsed without heartbeat. Idempotent.
    pub fn poll_dead_man(&mut self, now: SystemTime) {
        if self.dead_man.has_fired(now) && !self.revoked {
            self.unrecoverable_delete();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
    }

    fn make_account(pin: &[u8]) -> AccountState {
        AccountState::new(
            [42; 32],
            pin,
            [7; pin_kdf::SALT_LEN],
            b"opaque-share-bytes".to_vec(),
            AccountOptions::default(),
            t0(),
        )
        .unwrap()
    }

    #[test]
    fn correct_pin_resets_counter() {
        let mut a = make_account(b"123456");
        a.try_pin(b"123456").unwrap();
        assert_eq!(a.counter.level, EscalationLevel::Pin);
        assert_eq!(a.counter.wrong_at_level, 0);
    }

    #[test]
    fn wrong_pin_3_times_escalates() {
        let mut a = make_account(b"123456");
        assert!(matches!(
            a.try_pin(b"000000"),
            Err(ThresholdIdentityError::WrongPin)
        ));
        assert!(matches!(
            a.try_pin(b"000000"),
            Err(ThresholdIdentityError::WrongPin)
        ));
        assert!(matches!(
            a.try_pin(b"000000"),
            Err(ThresholdIdentityError::WrongPin)
        ));
        assert_eq!(a.counter.level, EscalationLevel::Recovery24);
        // Subsequent PIN entry now rejected because level escalated.
        assert!(matches!(
            a.try_pin(b"123456"),
            Err(ThresholdIdentityError::PolicyReject(_))
        ));
    }

    #[test]
    fn unrecoverable_delete_wipes_share_and_pin_hash() {
        let mut a = make_account(b"123456");
        a.unrecoverable_delete();
        assert!(a.revoked);
        assert!(a.encrypted_share.is_empty());
        assert_eq!(a.pin_hash, [0u8; pin_kdf::OUTPUT_LEN]);
    }

    #[test]
    fn deleted_account_rejects_pin() {
        let mut a = make_account(b"123456");
        a.unrecoverable_delete();
        assert!(matches!(
            a.try_pin(b"123456"),
            Err(ThresholdIdentityError::AccountDeleted)
        ));
    }

    #[test]
    fn poll_dead_man_auto_wipes_after_grace() {
        let mut a = make_account(b"abc");
        a.dead_man.grace = std::time::Duration::from_secs(60);
        a.dead_man.enable(t0());
        a.poll_dead_man(t0() + std::time::Duration::from_secs(61));
        assert!(a.revoked);
    }
}
