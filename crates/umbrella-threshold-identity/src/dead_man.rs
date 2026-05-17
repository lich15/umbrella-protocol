//! # Dead-man switch
//!
//! Opt-in setting: пользователь задаёт `N` дней. Если в течение N дней ни одно
//! устройство аккаунта не отправит heartbeat, серверы автоматически удаляют
//! доли (UNRECOVERABLE_DELETE).
//!
//! Защищает от сценария: жертва похищена / убита, attacker имеет физический
//! доступ к устройствам но не знает PIN. После N дней content неизвлекаем.
//!
//! Opt-in dead-man switch — automatic UNRECOVERABLE_DELETE after N days of
//! no heartbeat. Protects against post-mortem device capture.

use std::time::{Duration, SystemTime};

/// Per-account dead-man switch state.
#[derive(Debug, Clone)]
pub struct DeadManState {
    /// Whether dead-man is enabled by user.
    pub enabled: bool,
    /// User-configured grace period.
    pub grace: Duration,
    /// Last observed heartbeat from any device.
    pub last_heartbeat: SystemTime,
}

impl DeadManState {
    /// Creates a fresh state with given grace period (e.g. 30 days).
    pub fn new(grace: Duration, now: SystemTime) -> Self {
        Self {
            enabled: false,
            grace,
            last_heartbeat: now,
        }
    }

    /// Enables the switch.
    pub fn enable(&mut self, now: SystemTime) {
        self.enabled = true;
        self.last_heartbeat = now;
    }

    /// Disables the switch.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Records a heartbeat from a device. Updates `last_heartbeat`.
    pub fn record_heartbeat(&mut self, now: SystemTime) {
        self.last_heartbeat = now;
    }

    /// Checks whether the dead-man timer has fired. Returns true iff
    /// `enabled && now - last_heartbeat > grace`.
    pub fn has_fired(&self, now: SystemTime) -> bool {
        if !self.enabled {
            return false;
        }
        match now.duration_since(self.last_heartbeat) {
            Ok(elapsed) => elapsed > self.grace,
            Err(_) => false, // clock skew — treat as not fired.
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
    fn dead_man_disabled_never_fires() {
        let s = DeadManState::new(Duration::from_secs(60), t0());
        assert!(!s.has_fired(t0() + Duration::from_secs(3600)));
    }

    #[test]
    fn dead_man_fires_after_grace() {
        let mut s = DeadManState::new(Duration::from_secs(60), t0());
        s.enable(t0());
        assert!(!s.has_fired(t0() + Duration::from_secs(30)));
        assert!(!s.has_fired(t0() + Duration::from_secs(60)));
        assert!(s.has_fired(t0() + Duration::from_secs(61)));
    }

    #[test]
    fn heartbeat_resets_timer() {
        let mut s = DeadManState::new(Duration::from_secs(60), t0());
        s.enable(t0());
        s.record_heartbeat(t0() + Duration::from_secs(50));
        // 50 + 60 = 110; at t=109 not yet fired.
        assert!(!s.has_fired(t0() + Duration::from_secs(109)));
        assert!(s.has_fired(t0() + Duration::from_secs(120)));
    }

    #[test]
    fn disable_stops_firing() {
        let mut s = DeadManState::new(Duration::from_secs(60), t0());
        s.enable(t0());
        s.disable();
        assert!(!s.has_fired(t0() + Duration::from_secs(3600)));
    }
}
