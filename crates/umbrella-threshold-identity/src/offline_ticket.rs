//! # 24-hour offline ticket
//!
//! После successful unlock server выпускает short-lived offline-ticket. Device
//! может оперировать (открывать MLS chats, decrypt local messages) offline до
//! 24 часов с момента выпуска. По истечении — required re-unlock через PIN.
//!
//! Ticket binds к `(device_key_handle, account_anonymous_id, expires_at)` через
//! Ed25519 signature server-side. Client кэширует ticket в `MlockedSecret`.
//!
//! 24-hour offline ticket — server-signed, device caches in MlockedSecret,
//! re-unlock required after expiry.

use std::time::SystemTime;

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};
use crate::OFFLINE_TICKET_VALIDITY_SECS;

/// Plaintext (pre-signing) offline ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineTicket {
    /// Anonymous account ID (one of 5 per-server values).
    pub anonymous_id: [u8; 32],
    /// Device handle / public key bytes.
    pub device_handle: [u8; 32],
    /// UNIX seconds when ticket expires.
    pub expires_at: u64,
}

impl OfflineTicket {
    /// Creates a ticket valid for the standard 24-hour window from `now`.
    pub fn issue(
        anonymous_id: [u8; 32],
        device_handle: [u8; 32],
        now: SystemTime,
    ) -> ThresholdIdentityResult<Self> {
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ThresholdIdentityError::Io("clock pre-epoch".into()))?
            .as_secs();
        Ok(Self {
            anonymous_id,
            device_handle,
            expires_at: now_secs + OFFLINE_TICKET_VALIDITY_SECS,
        })
    }

    /// Returns true iff `now` is at or after `expires_at`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let now_secs = match now.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return false, // clock skew, treat as live.
        };
        now_secs >= self.expires_at
    }

    /// Returns remaining lifetime in seconds.
    pub fn remaining_secs(&self, now: SystemTime) -> Option<u64> {
        let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
        Some(self.expires_at.saturating_sub(now_secs))
    }

    /// Returns 72-byte canonical wire encoding for signing.
    pub fn to_signing_bytes(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..32].copy_from_slice(&self.anonymous_id);
        out[32..64].copy_from_slice(&self.device_handle);
        out[64..].copy_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// Returns whether `now` invalidates ticket (replaces is_expired with
    /// `Err(OfflineTicketExpired)`).
    pub fn check_alive(&self, now: SystemTime) -> ThresholdIdentityResult<()> {
        if self.is_expired(now) {
            Err(ThresholdIdentityError::OfflineTicketExpired)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn ticket_lifecycle() {
        let t = OfflineTicket::issue([1; 32], [2; 32], t0()).unwrap();
        assert!(!t.is_expired(t0()));
        assert!(!t.is_expired(t0() + Duration::from_secs(86_399)));
        assert!(t.is_expired(t0() + Duration::from_secs(86_400)));
        assert_eq!(t.remaining_secs(t0()), Some(86_400));
    }

    #[test]
    fn signing_bytes_canonical() {
        let t = OfflineTicket {
            anonymous_id: [0xAB; 32],
            device_handle: [0xCD; 32],
            expires_at: 0x0102030405060708,
        };
        let bytes = t.to_signing_bytes();
        assert_eq!(&bytes[..32], &[0xAB; 32]);
        assert_eq!(&bytes[32..64], &[0xCD; 32]);
        assert_eq!(&bytes[64..], &0x0102030405060708u64.to_be_bytes());
    }

    #[test]
    fn check_alive_returns_expired_error() {
        let t = OfflineTicket::issue([0; 32], [0; 32], t0()).unwrap();
        assert!(t.check_alive(t0() + Duration::from_secs(86_399)).is_ok());
        assert!(matches!(
            t.check_alive(t0() + Duration::from_secs(86_401)),
            Err(ThresholdIdentityError::OfflineTicketExpired)
        ));
    }
}
