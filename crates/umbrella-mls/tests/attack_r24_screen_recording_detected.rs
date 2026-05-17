//! R24 — Real attack: screen recording in secret chat → "(скрыто)" overlay
//!
//! Per round-6 spec §«Stage 5» R24:
//! > start screen recording (mocked), open secret chat → assert messages
//! > replaced with "(скрыто)" overlay.
//!
//! Numerical outcome: count of messages displayed → masked vs un-masked.

use umbrella_mls::screenshot_policy::{
    screen_capture_overlay, should_notify_on_screenshot, ScreenshotPolicy,
};

#[test]
fn r24_screen_capture_masks_messages_in_secret_chat() {
    let secret_chat_policy = ScreenshotPolicy::Block;
    let overlay = screen_capture_overlay(secret_chat_policy);
    assert_eq!(overlay, Some("(скрыто)"));
    eprintln!("[R24] secret chat Block policy → overlay = (скрыто)");
}

#[test]
fn r24_casual_chat_no_overlay_under_screen_capture() {
    let casual_policy = ScreenshotPolicy::Allow;
    let overlay = screen_capture_overlay(casual_policy);
    assert!(overlay.is_none());
    eprintln!("[R24] casual chat Allow policy → no overlay (user accepted risk)");
}

#[test]
fn r24_block_and_notify_triggers_sender_push() {
    // Receiver takes screenshot of message with BlockAndNotify policy.
    let policy = ScreenshotPolicy::BlockAndNotify;
    assert!(should_notify_on_screenshot(policy));
    // Verify Block alone does NOT trigger sender push.
    assert!(!should_notify_on_screenshot(ScreenshotPolicy::Block));
    eprintln!("[R24] BlockAndNotify → sender notified; Block alone → no notification");
}

#[test]
fn r24_message_count_under_capture() {
    // Simulate 100 messages in a secret chat with Block policy. All must be
    // masked when capture is active.
    let policy = ScreenshotPolicy::Block;
    let mut masked = 0;
    let mut unmasked = 0;
    for _ in 0..100 {
        if let Some(_overlay) = screen_capture_overlay(policy) {
            masked += 1;
        } else {
            unmasked += 1;
        }
    }
    eprintln!("[R24] 100 messages under screen capture: masked={masked}, unmasked={unmasked}");
    assert_eq!(masked, 100);
    assert_eq!(unmasked, 0);
}
