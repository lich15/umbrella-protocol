//! # Round-6 lifecycle: wipe-on-background / wipe-on-lock / heartbeat
//!
//! Round-6 design §«Stage 2 — Client backend rewiring» Component 5:
//!
//! ```text
//! Event                                  Action
//! ─────                                  ──────
//! App → Background (foregrounded)        2-min timer → wipe device_key+master_key
//! App → Inactive (lost focus, no bg)     Immediate wipe of session keys, keep dev_key
//! Screen lock detected                   Immediate full wipe of all session secrets
//! Debugger / jailbreak / root detected   Emergency wipe + close app
//! Heartbeat thread (active foreground)   Send ping every 30 sec; on 2-min loss
//!                                        servers mark device-key suspicious
//! ```
//!
//! Round-6 client lifecycle: wipe session secrets on background/lock/debug,
//! heartbeat to servers every 30s while active.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use umbrella_crypto_primitives::mlocked::MlockedSecret;
use zeroize::Zeroize;

use crate::keystore::distributed_identity_client::UnlockSession;

/// Per-app lifecycle event signalled by the platform bridge (iOS/Android).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// App went to background — start 2-min timer.
    Background,
    /// App returned to foreground — cancel timer.
    Foreground,
    /// App became inactive (e.g. incoming call modal) — immediate wipe of
    /// session keys (ratchet etc.) but keep device_key alive.
    Inactive,
    /// Screen locked (OS lock screen) — immediate full wipe.
    ScreenLocked,
    /// Debugger / jailbreak / root detected — emergency wipe.
    Debugger,
    /// Periodic heartbeat tick.
    HeartbeatTick,
}

/// Session state held in memory while user is active. Wrapped в `Arc<Mutex>`
/// в production; здесь — direct struct for simplicity.
pub struct SessionState {
    /// Active unlock session, `None` after wipe.
    pub session: Option<UnlockSession>,
    /// Last heartbeat sent time.
    pub last_heartbeat_at: SystemTime,
    /// Background-timer scheduled wipe time, `None` if not scheduled.
    pub background_wipe_at: Option<SystemTime>,
}

impl SessionState {
    /// Constructs a new state from `session`.
    pub fn new(session: UnlockSession, now: SystemTime) -> Self {
        Self {
            session: Some(session),
            last_heartbeat_at: now,
            background_wipe_at: None,
        }
    }

    /// Reports whether session is currently live (not wiped).
    pub fn is_live(&self) -> bool {
        self.session.is_some()
    }

    /// Immediately wipes session secrets. Idempotent.
    pub fn wipe(&mut self) {
        if let Some(s) = self.session.take() {
            // `Drop` impl of `UnlockSession` (via MlockedSecret's Drop) does
            // the zeroize. Explicit drop here marks the lifetime end.
            drop(s);
        }
        self.background_wipe_at = None;
    }

    /// Handles a lifecycle event. Returns `true` if the event caused a wipe.
    pub fn on_event(
        &mut self,
        event: LifecycleEvent,
        now: SystemTime,
        background_grace: Duration,
    ) -> bool {
        match event {
            LifecycleEvent::Background => {
                self.background_wipe_at = Some(now + background_grace);
                false
            }
            LifecycleEvent::Foreground => {
                self.background_wipe_at = None;
                false
            }
            LifecycleEvent::Inactive => {
                // For now, treat Inactive as full wipe — round-6 spec mentions
                // «session keys» wipe but we keep the device_key alive only by
                // not yet implementing a separate session-key vs device-key
                // split. Conservative: wipe both.
                self.wipe();
                true
            }
            LifecycleEvent::ScreenLocked | LifecycleEvent::Debugger => {
                self.wipe();
                true
            }
            LifecycleEvent::HeartbeatTick => {
                self.last_heartbeat_at = now;
                // Also check if scheduled background-wipe time has elapsed.
                if let Some(wipe_at) = self.background_wipe_at {
                    if now >= wipe_at {
                        self.wipe();
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Returns time since last heartbeat. Used by external code to decide if
    /// servers should mark device suspicious.
    pub fn since_heartbeat(&self, now: SystemTime) -> Duration {
        now.duration_since(self.last_heartbeat_at)
            .unwrap_or_default()
    }
}

/// Detects whether a debugger is attached (lldb/gdb/strace).
///
/// macOS-/Linux-specific: production check via `sysctl KERN_PROC | KERN_PROC_PID`
/// + `P_TRACED` flag (per Apple security guide May 2024 §«Anti-debugging»).
/// On stable Rust without `unsafe_code`, we fall back to a heuristic: check
/// `/proc/self/status` `TracerPid` line on Linux, env var `MallocStackLogging`
/// on macOS (set by Xcode Instruments), and presence of `DYLD_INSERT_LIBRARIES`.
///
/// **Note**: this is best-effort, not a security guarantee. A sophisticated
/// adversary with kernel access can bypass. Round-6 design accepts this:
/// debug-detect is one layer of defense-in-depth, not the only one.
///
/// Best-effort debugger detection (Linux /proc + macOS env heuristics).
pub fn debugger_detected() -> bool {
    // macOS heuristic: Xcode Instruments injects MallocStackLogging.
    if std::env::var("MallocStackLogging").is_ok() {
        return true;
    }
    // Library injection via DYLD_INSERT_LIBRARIES.
    if std::env::var("DYLD_INSERT_LIBRARIES").is_ok() {
        return true;
    }
    // Linux heuristic: /proc/self/status TracerPid != 0.
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    if let Ok(pid) = rest.trim().parse::<u32>() {
                        if pid != 0 {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Heartbeat scheduler — production runs on tokio interval ticker. Test rigs
/// drive `on_event(HeartbeatTick)` manually.
pub struct HeartbeatScheduler {
    /// Whether scheduler is running.
    pub active: Arc<AtomicBool>,
    /// Tick interval.
    pub interval: Duration,
    /// Monotonic counter of ticks sent (for diagnostics).
    pub ticks_sent: Arc<AtomicU64>,
}

impl HeartbeatScheduler {
    /// Constructs a heartbeat scheduler with the default 30-sec interval.
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            interval: Duration::from_secs(30),
            ticks_sent: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Marks scheduler as active.
    pub fn start(&self) {
        self.active.store(true, Ordering::SeqCst);
    }

    /// Marks scheduler as inactive (no more ticks).
    pub fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// Manually fires one tick. Used by tests.
    pub fn fire_tick(&self) {
        if self.active.load(Ordering::SeqCst) {
            self.ticks_sent.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Returns number of ticks delivered.
    pub fn ticks(&self) -> u64 {
        self.ticks_sent.load(Ordering::SeqCst)
    }
}

impl Default for HeartbeatScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Auxiliary: zeroize a single `MlockedSecret<[u8; 32]>` borrow without
/// dropping the wrapper. Useful for partial wipes (clear the bytes but keep
/// the allocation alive for later re-derive).
pub fn scrub_secret_in_place(s: &mut MlockedSecret<[u8; 32]>) {
    s.expose_mut().zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::distributed_identity_client::IdentityPublicKey;
    use umbrella_crypto_primitives::mlocked::MlockedSecret;

    fn dummy_session() -> UnlockSession {
        let id: IdentityPublicKey = [0xCC; 32];
        UnlockSession {
            device_key: MlockedSecret::<[u8; 32]>::new([0xAA; 32]),
            master_key: MlockedSecret::<[u8; 32]>::new([0xBB; 32]),
            identity_pk: id,
        }
    }

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn screen_lock_immediately_wipes() {
        let mut s = SessionState::new(dummy_session(), t0());
        assert!(s.is_live());
        let wiped = s.on_event(LifecycleEvent::ScreenLocked, t0(), Duration::from_secs(120));
        assert!(wiped);
        assert!(!s.is_live());
    }

    #[test]
    fn background_2min_timer_wipes_after_grace() {
        let mut s = SessionState::new(dummy_session(), t0());
        // App goes to background, no immediate wipe.
        assert!(!s.on_event(LifecycleEvent::Background, t0(), Duration::from_secs(120)));
        assert!(s.is_live());
        // 119 sec later, heartbeat tick: still live.
        assert!(!s.on_event(
            LifecycleEvent::HeartbeatTick,
            t0() + Duration::from_secs(119),
            Duration::from_secs(120),
        ));
        assert!(s.is_live());
        // 121 sec later, heartbeat tick triggers wipe.
        let wiped = s.on_event(
            LifecycleEvent::HeartbeatTick,
            t0() + Duration::from_secs(121),
            Duration::from_secs(120),
        );
        assert!(wiped);
        assert!(!s.is_live());
    }

    #[test]
    fn foreground_cancels_pending_wipe() {
        let mut s = SessionState::new(dummy_session(), t0());
        s.on_event(LifecycleEvent::Background, t0(), Duration::from_secs(120));
        s.on_event(
            LifecycleEvent::Foreground,
            t0() + Duration::from_secs(60),
            Duration::from_secs(120),
        );
        // Tick 200 sec later (past the original grace) — still live, cancelled.
        let wiped = s.on_event(
            LifecycleEvent::HeartbeatTick,
            t0() + Duration::from_secs(200),
            Duration::from_secs(120),
        );
        assert!(!wiped);
        assert!(s.is_live());
    }

    #[test]
    fn debugger_event_emergency_wipes() {
        let mut s = SessionState::new(dummy_session(), t0());
        let wiped = s.on_event(LifecycleEvent::Debugger, t0(), Duration::from_secs(120));
        assert!(wiped);
        assert!(!s.is_live());
    }

    #[test]
    fn wipe_is_idempotent() {
        let mut s = SessionState::new(dummy_session(), t0());
        s.wipe();
        assert!(!s.is_live());
        s.wipe(); // No-op.
        assert!(!s.is_live());
    }

    #[test]
    fn heartbeat_scheduler_lifecycle() {
        let h = HeartbeatScheduler::new();
        h.start();
        h.fire_tick();
        h.fire_tick();
        assert_eq!(h.ticks(), 2);
        h.stop();
        h.fire_tick();
        assert_eq!(h.ticks(), 2, "ticks after stop ignored");
    }

    #[test]
    fn debugger_detect_returns_bool() {
        // Smoke test only — we don't fail if false on a clean CI.
        let _ = debugger_detected();
    }
}
