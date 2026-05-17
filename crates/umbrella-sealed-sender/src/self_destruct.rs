//! # Self-destruct TTL для sealed envelopes (round-6 Stage 4)
//!
//! Wraps any HPKE sealed envelope с TTL header. Receiver invokes
//! [`MessageRetention`] from `umbrella-mls::screenshot_policy` after open;
//! when TTL expires, raw ciphertext can be wiped from local storage.
//!
//! Self-destruct TTL wrapper для sealed envelopes — anti-forensic в secret
//! chats per round-6 spec §«Stage 4 — Anti-forensic in chats».

use std::time::{Duration, SystemTime};

/// 32-byte sender-set TTL header attached to sealed envelope. Encoded as:
/// `version_byte(1) || ttl_secs(8) || one_time_flag(1) || notify_flag(1) || reserved(21)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfDestructHeader {
    /// Version (currently 1).
    pub version: u8,
    /// TTL after first view (seconds).
    pub ttl_secs: u64,
    /// One-time view flag.
    pub one_time: bool,
    /// Notify sender on screenshot.
    pub notify_on_screenshot: bool,
}

impl SelfDestructHeader {
    /// Returns canonical 32-byte wire encoding.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = self.version;
        out[1..9].copy_from_slice(&self.ttl_secs.to_be_bytes());
        out[9] = if self.one_time { 1 } else { 0 };
        out[10] = if self.notify_on_screenshot { 1 } else { 0 };
        out
    }

    /// Parses 32-byte wire encoding.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        if bytes[0] != 1 {
            return None;
        }
        let mut ttl_buf = [0u8; 8];
        ttl_buf.copy_from_slice(&bytes[1..9]);
        Some(Self {
            version: bytes[0],
            ttl_secs: u64::from_be_bytes(ttl_buf),
            one_time: bytes[9] != 0,
            notify_on_screenshot: bytes[10] != 0,
        })
    }

    /// Returns true iff message should be wiped at `now` given `viewed_at`.
    pub fn should_wipe(&self, viewed_at: SystemTime, now: SystemTime) -> bool {
        if self.one_time {
            return true;
        }
        if self.ttl_secs == 0 {
            return false;
        }
        let ttl = Duration::from_secs(self.ttl_secs);
        match now.duration_since(viewed_at) {
            Ok(elapsed) => elapsed >= ttl,
            Err(_) => false,
        }
    }
}

/// Builder pattern.
impl SelfDestructHeader {
    /// Constructs a one-time-view header (wipes on first view).
    pub fn one_time(notify: bool) -> Self {
        Self {
            version: 1,
            ttl_secs: 0,
            one_time: true,
            notify_on_screenshot: notify,
        }
    }

    /// Constructs a TTL header (wipes `secs` after first view).
    pub fn ttl_secs(secs: u64, notify: bool) -> Self {
        Self {
            version: 1,
            ttl_secs: secs,
            one_time: false,
            notify_on_screenshot: notify,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn one_time_header_always_wipes() {
        let h = SelfDestructHeader::one_time(false);
        assert!(h.should_wipe(t0(), t0()));
        assert!(h.should_wipe(t0(), t0() + Duration::from_secs(0)));
    }

    #[test]
    fn ttl_header_wipes_after_duration() {
        let h = SelfDestructHeader::ttl_secs(60, false);
        assert!(!h.should_wipe(t0(), t0() + Duration::from_secs(59)));
        assert!(h.should_wipe(t0(), t0() + Duration::from_secs(60)));
    }

    #[test]
    fn ttl_zero_never_wipes() {
        let h = SelfDestructHeader::ttl_secs(0, false);
        assert!(!h.should_wipe(t0(), t0() + Duration::from_secs(86_400)));
    }

    #[test]
    fn wire_encoding_roundtrip() {
        let h = SelfDestructHeader::ttl_secs(42, true);
        let bytes = h.to_bytes();
        let parsed = SelfDestructHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn invalid_version_rejected() {
        let mut bytes = [0u8; 32];
        bytes[0] = 99; // bad version
        assert!(SelfDestructHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn notify_flag_persists() {
        let with_notify = SelfDestructHeader::one_time(true);
        let parsed = SelfDestructHeader::from_bytes(&with_notify.to_bytes()).unwrap();
        assert!(parsed.notify_on_screenshot);
        let without = SelfDestructHeader::one_time(false);
        let parsed2 = SelfDestructHeader::from_bytes(&without.to_bytes()).unwrap();
        assert!(!parsed2.notify_on_screenshot);
    }
}
