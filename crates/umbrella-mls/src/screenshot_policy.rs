//! # Per-chat screenshot policy (round-6 Stage 4)
//!
//! Каждый chat имеет настройку `ScreenshotPolicy`. Когда screen-capture
//! detected (via OS API — на iOS `UIScreen.main.isCaptured`, на Android
//! `MediaProjection`), сообщения secret chats заменяются на overlay
//! `«(скрыто)»` placeholder.
//!
//! Также реализует TTL (self-destruct) семантику: сообщения с TTL
//! автоматически wipe'аются после view+timer expiration.
//!
//! Per-chat screenshot policy + TTL self-destruct. Anti-forensic for
//! secret chats per round-6 spec §«Stage 4».

use std::time::{Duration, SystemTime};

/// Per-chat policy для screenshot/screen-record поведения.
/// Per-chat policy enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScreenshotPolicy {
    /// No screenshot protection. Default for casual / public chats.
    #[default]
    Allow,
    /// Block screenshots via OS flag. Mask messages on screen recording.
    Block,
    /// Block screenshots + notify sender on receiver screenshot attempt.
    BlockAndNotify,
}

/// Метаданные одного сообщения для TTL / self-destruct.
/// Single message metadata for TTL / self-destruct.
#[derive(Debug, Clone, Default)]
pub struct MessageRetention {
    /// Sender-set TTL after first view. `None` = no TTL.
    pub ttl_after_view: Option<Duration>,
    /// Whether to wipe after one view (regardless of TTL).
    pub one_time_view: bool,
    /// Whether to notify sender if receiver screenshots.
    pub notify_on_screenshot: bool,
    /// Anonymous watermark to embed in media for leak tracing (32 bytes).
    pub anonymous_watermark: Option<[u8; 32]>,
}

/// Состояние одного сообщения на стороне получателя: «not viewed», «viewed
/// at T», «expired».
///
/// State of a single message on the receiver side: «not viewed», «viewed
/// at T», «expired».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverViewState {
    /// Not yet viewed.
    NotViewed,
    /// Viewed at given UNIX seconds.
    Viewed {
        /// UNIX-seconds timestamp когда message впервые viewed на receiver side.
        /// Используется retention policy для compute expiration deadline.
        /// UNIX-seconds timestamp when the message was first viewed; used by the
        /// retention policy to compute the expiration deadline.
        at_secs: u64,
    },
    /// Expired — content has been wiped.
    Expired,
}

/// Tracker view-состояния одного сообщения + решение wipe'нуть ли контент.
/// Tracks one message's view state + decides whether content should be wiped.
#[derive(Debug, Clone)]
pub struct ReceiverMessageTracker {
    /// Retention policy as set by sender.
    pub policy: MessageRetention,
    /// Current state.
    pub state: ReceiverViewState,
}

impl ReceiverMessageTracker {
    /// Constructs a tracker for a freshly-received message.
    pub fn new(policy: MessageRetention) -> Self {
        Self {
            policy,
            state: ReceiverViewState::NotViewed,
        }
    }

    /// Marks the message as viewed at `now`. Idempotent for repeat calls;
    /// only first view sets the timestamp. Returns whether content should
    /// be wiped immediately (one-time view policy).
    pub fn record_view(&mut self, now: SystemTime) -> bool {
        let viewed_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let was_first = matches!(self.state, ReceiverViewState::NotViewed);
        if was_first {
            self.state = ReceiverViewState::Viewed { at_secs: viewed_at };
        }
        // If one-time view, wipe right away.
        if was_first && self.policy.one_time_view {
            self.state = ReceiverViewState::Expired;
            return true;
        }
        false
    }

    /// Checks whether message has expired due to TTL. Caller invokes
    /// periodically on a timer. Returns true if content was just wiped.
    pub fn check_ttl(&mut self, now: SystemTime) -> bool {
        if let (ReceiverViewState::Viewed { at_secs }, Some(ttl)) =
            (self.state, self.policy.ttl_after_view)
        {
            let now_secs = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now_secs.saturating_sub(at_secs) >= ttl.as_secs() {
                self.state = ReceiverViewState::Expired;
                return true;
            }
        }
        false
    }

    /// Returns true iff message has been wiped (expired).
    pub fn is_expired(&self) -> bool {
        matches!(self.state, ReceiverViewState::Expired)
    }
}

/// Определяет что UI должен показать когда screen-capture активен и
/// видно сообщение с policy `policy`.
///
/// Determines what UI should display when screen-capture is active and a
/// message with policy `policy` is visible.
pub fn screen_capture_overlay(policy: ScreenshotPolicy) -> Option<&'static str> {
    match policy {
        ScreenshotPolicy::Allow => None,
        ScreenshotPolicy::Block | ScreenshotPolicy::BlockAndNotify => Some("(скрыто)"),
    }
}

/// Определяет нужно ли уведомлять отправителя о screenshot получателя
/// для указанной policy.
///
/// Determines whether sender should be notified about receiver screenshot
/// for the given policy.
pub fn should_notify_on_screenshot(policy: ScreenshotPolicy) -> bool {
    matches!(policy, ScreenshotPolicy::BlockAndNotify)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn allow_policy_no_overlay() {
        assert_eq!(screen_capture_overlay(ScreenshotPolicy::Allow), None);
        assert!(!should_notify_on_screenshot(ScreenshotPolicy::Allow));
    }

    #[test]
    fn block_policy_returns_redacted_overlay() {
        assert_eq!(
            screen_capture_overlay(ScreenshotPolicy::Block),
            Some("(скрыто)")
        );
        assert_eq!(
            screen_capture_overlay(ScreenshotPolicy::BlockAndNotify),
            Some("(скрыто)")
        );
    }

    #[test]
    fn block_and_notify_triggers_sender_notification() {
        assert!(!should_notify_on_screenshot(ScreenshotPolicy::Block));
        assert!(should_notify_on_screenshot(
            ScreenshotPolicy::BlockAndNotify
        ));
    }

    #[test]
    fn ttl_expires_after_view_plus_duration() {
        let mut t = ReceiverMessageTracker::new(MessageRetention {
            ttl_after_view: Some(Duration::from_secs(60)),
            one_time_view: false,
            notify_on_screenshot: false,
            anonymous_watermark: None,
        });
        t.record_view(t0());
        // At t+59 still alive.
        assert!(!t.check_ttl(t0() + Duration::from_secs(59)));
        assert!(!t.is_expired());
        // At t+60+ expired.
        assert!(t.check_ttl(t0() + Duration::from_secs(60)));
        assert!(t.is_expired());
    }

    #[test]
    fn one_time_view_wipes_immediately() {
        let mut t = ReceiverMessageTracker::new(MessageRetention {
            ttl_after_view: None,
            one_time_view: true,
            notify_on_screenshot: false,
            anonymous_watermark: None,
        });
        let wiped = t.record_view(t0());
        assert!(wiped, "one-time view wipes on first view");
        assert!(t.is_expired());
    }

    #[test]
    fn record_view_is_idempotent_for_ttl() {
        let mut t = ReceiverMessageTracker::new(MessageRetention {
            ttl_after_view: Some(Duration::from_secs(60)),
            one_time_view: false,
            notify_on_screenshot: false,
            anonymous_watermark: None,
        });
        // First view sets timestamp.
        t.record_view(t0());
        let first = t.state;
        // Second view at t+30 should not move timestamp.
        t.record_view(t0() + Duration::from_secs(30));
        assert_eq!(t.state, first);
    }

    #[test]
    fn no_ttl_never_expires() {
        let mut t = ReceiverMessageTracker::new(MessageRetention::default());
        t.record_view(t0());
        assert!(!t.check_ttl(t0() + Duration::from_secs(86_400)));
        assert!(!t.is_expired());
    }
}
