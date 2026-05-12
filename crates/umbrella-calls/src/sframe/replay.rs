//! Anti-replay sliding 64-битный bitmap per-`(sender_leaf, epoch)`.
//! SRTP-style как в RFC 3711 §3.3.2.
//!
//! ## Алгоритм
//!
//! ```text
//! highest_seen │ u64   — максимальный counter, принятый для пары (sender, epoch)
//! bitmap       │ u64   — bit_i = counter(highest_seen - i) уже принят
//! initialized  │ bool  — true после первого accept
//! ```
//!
//! Приём нового counter:
//!
//! 1. Первый counter → `highest_seen = counter`, `bitmap = 1` (bit 0 установлен).
//! 2. `counter > highest_seen` → shift bitmap влево на `delta` (reset если `delta >= 64`),
//!    установить bit 0, обновить `highest_seen`, accept.
//! 3. `counter == highest_seen` → bit 0 уже установлен → `Replay`.
//! 4. `counter < highest_seen`, `delta = highest_seen - counter < 64`:
//!    - bit `delta` уже установлен → `Replay`;
//!    - иначе установить bit `delta`, accept.
//! 5. `counter < highest_seen`, `delta >= 64` → `OutOfReplayWindow`.
//!
//! ## Изоляция
//!
//! Окно живёт per-`(sender_leaf, epoch)` в `SframeContext::replay: HashMap<...>`.
//! Смена эпохи (MLS commit) создаёт новые окна; выбитая эпоха → соответствующие
//! окна очищаются в [`crate::sframe::frame::SframeContext::advance_epoch`].
//!
//! Anti-replay sliding 64-bit bitmap per-`(sender_leaf, epoch)`. SRTP-style
//! per RFC 3711 §3.3.2.
//!
//! State:
//!
//! ```text
//! highest_seen │ u64   — highest counter accepted for (sender, epoch)
//! bitmap       │ u64   — bit_i = counter(highest_seen - i) already processed
//! initialized  │ bool  — true after the first accept
//! ```
//!
//! New-counter handling:
//!
//! 1. First counter → `highest_seen = counter`, `bitmap = 1` (bit 0 set).
//! 2. `counter > highest_seen` → shift bitmap left by `delta` (reset on
//!    `delta >= 64`), set bit 0, update `highest_seen`, accept.
//! 3. `counter == highest_seen` → bit 0 already set → `Replay`.
//! 4. `counter < highest_seen`, `delta = highest_seen - counter < 64`:
//!    - bit `delta` set → `Replay`;
//!    - else set bit `delta`, accept.
//! 5. `counter < highest_seen`, `delta >= 64` → `OutOfReplayWindow`.
//!
//! Isolation: one window per `(sender_leaf, epoch)` lives in
//! `SframeContext::replay: HashMap<...>`. Epoch advance (MLS commit) creates
//! new windows; an evicted epoch causes the corresponding windows to be
//! dropped in [`crate::sframe::frame::SframeContext::advance_epoch`].

use crate::error::{CallError, Result};

/// Ширина окна в кадрах. 64 ≈ 1 секунда реordering-толерантности @ 60 fps,
/// ~2 секунды @ 30 fps, ~1.3 секунды @ 50 fps audio (20 ms frames).
///
/// Window width in frames. 64 ≈ 1 second of reorder tolerance at 60 fps,
/// ~2 s at 30 fps, ~1.3 s at 50 fps audio (20 ms frames).
pub const REPLAY_WINDOW_WIDTH: u64 = 64;

/// Sliding 64-битный bitmap для одного `(sender_leaf, epoch)`.
/// Bit `i` установлен означает «counter = highest_seen - i уже обработан».
///
/// Sliding 64-bit bitmap for one `(sender_leaf, epoch)`. Bit `i` set means
/// "counter = highest_seen - i has been processed".
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest_seen: u64,
    bitmap: u64,
    initialized: bool,
    sender: u32,
}

impl ReplayWindow {
    /// Создаёт новое пустое окно для заданного `sender`. Первый вызов
    /// [`check_and_update`](Self::check_and_update) инициализирует окно.
    ///
    /// Creates a new empty window for a given `sender`. The first
    /// [`check_and_update`](Self::check_and_update) call initializes it.
    pub fn new(sender: u32) -> Self {
        Self {
            highest_seen: 0,
            bitmap: 0,
            initialized: false,
            sender,
        }
    }

    /// Проверяет `counter` и обновляет bitmap при accept.
    /// Возвращает `Ok(())` на accept либо конкретный `CallError` на reject.
    ///
    /// # Ошибки
    ///
    /// - [`CallError::Replay`] — bit уже установлен (повторный counter).
    /// - [`CallError::OutOfReplayWindow`] — `counter < highest_seen - 63`
    ///   (слишком старый кадр).
    ///
    /// Checks `counter` and updates the bitmap on accept. Returns `Ok(())`
    /// on accept, or a specific `CallError` on reject.
    ///
    /// # Errors
    ///
    /// - [`CallError::Replay`] — bit already set (duplicated counter).
    /// - [`CallError::OutOfReplayWindow`] — `counter < highest_seen - 63`
    ///   (frame too old).
    pub fn check_and_update(&mut self, counter: u64) -> Result<()> {
        if !self.initialized {
            self.highest_seen = counter;
            self.bitmap = 1;
            self.initialized = true;
            return Ok(());
        }

        if counter > self.highest_seen {
            let shift = counter - self.highest_seen;
            self.bitmap = if shift >= REPLAY_WINDOW_WIDTH {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest_seen = counter;
            Ok(())
        } else {
            let delta = self.highest_seen - counter;
            if delta >= REPLAY_WINDOW_WIDTH {
                let window_start = self.highest_seen - (REPLAY_WINDOW_WIDTH - 1);
                return Err(CallError::OutOfReplayWindow {
                    sender: self.sender,
                    counter,
                    window_start,
                });
            }
            let mask = 1u64 << delta;
            if (self.bitmap & mask) != 0 {
                return Err(CallError::Replay {
                    sender: self.sender,
                    counter,
                });
            }
            self.bitmap |= mask;
            Ok(())
        }
    }

    /// Максимальный counter, принятый в этом окне. Used для diagnostics/tests.
    /// Highest counter accepted in this window. Used for diagnostics/tests.
    pub fn highest_seen(&self) -> u64 {
        self.highest_seen
    }

    /// `true` если окно уже приняло хотя бы один counter.
    /// `true` if the window has accepted at least one counter.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_counter_accepted() {
        let mut w = ReplayWindow::new(0);
        assert!(!w.is_initialized());
        w.check_and_update(10).unwrap();
        assert!(w.is_initialized());
        assert_eq!(w.highest_seen(), 10);
    }

    #[test]
    fn increasing_counters_accepted() {
        let mut w = ReplayWindow::new(0);
        for c in 0..20 {
            w.check_and_update(c)
                .expect("counter rejected unexpectedly");
        }
        assert_eq!(w.highest_seen(), 19);
    }

    #[test]
    fn reorder_within_window_accepted() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(10).unwrap();
        w.check_and_update(5).unwrap();
        w.check_and_update(8).unwrap();
        assert_eq!(w.highest_seen(), 10);
    }

    #[test]
    fn replay_same_counter_rejected() {
        let mut w = ReplayWindow::new(7);
        w.check_and_update(5).unwrap();
        let err = w.check_and_update(5).unwrap_err();
        assert!(matches!(
            err,
            CallError::Replay {
                sender: 7,
                counter: 5
            }
        ));
    }

    #[test]
    fn replay_within_window_rejected() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(10).unwrap();
        w.check_and_update(5).unwrap();
        let err = w.check_and_update(5).unwrap_err();
        assert!(matches!(err, CallError::Replay { counter: 5, .. }));
    }

    #[test]
    fn old_counter_out_of_window_rejected() {
        let mut w = ReplayWindow::new(3);
        w.check_and_update(100).unwrap();
        let err = w.check_and_update(10).unwrap_err();
        assert!(matches!(
            err,
            CallError::OutOfReplayWindow {
                sender: 3,
                counter: 10,
                window_start: 37,
            }
        ));
    }

    #[test]
    fn advance_far_future_resets_window() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(5).unwrap();
        w.check_and_update(200).unwrap();
        // 5 теперь out-of-window (200 - 5 = 195 >= 64).
        // 5 is now out-of-window (200 - 5 = 195 >= 64).
        let err = w.check_and_update(5).unwrap_err();
        assert!(matches!(err, CallError::OutOfReplayWindow { .. }));
        // 140 в окне (200 - 60 = 140, delta=60 < 64).
        // 140 in-window (200 - 60 = 140, delta=60 < 64).
        w.check_and_update(140).unwrap();
    }

    #[test]
    fn boundary_exactly_at_window_edge() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(100).unwrap();
        // delta=63 → в окне (accept).
        // delta=63 → in-window (accept).
        w.check_and_update(37).unwrap();
        // delta=64 → out-of-window (reject).
        // delta=64 → out-of-window (reject).
        let err = w.check_and_update(36).unwrap_err();
        assert!(matches!(err, CallError::OutOfReplayWindow { .. }));
    }

    #[test]
    fn counter_zero_accepted_as_first_then_replay() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(0).unwrap();
        assert_eq!(w.highest_seen(), 0);
        let err = w.check_and_update(0).unwrap_err();
        assert!(matches!(err, CallError::Replay { counter: 0, .. }));
    }

    #[test]
    fn counter_u64_max_accepted() {
        let mut w = ReplayWindow::new(0);
        w.check_and_update(u64::MAX).unwrap();
        assert_eq!(w.highest_seen(), u64::MAX);
    }

    #[test]
    fn different_sender_reported_in_error() {
        let mut w = ReplayWindow::new(0xAB);
        w.check_and_update(0).unwrap();
        let err = w.check_and_update(0).unwrap_err();
        match err {
            CallError::Replay { sender, .. } => assert_eq!(sender, 0xAB),
            other => panic!("expected Replay with sender 0xAB, got {other:?}"),
        }
    }

    #[test]
    fn reorder_large_window_all_unique_accepted() {
        // Тест заполняет окно 63 unique counters в reverse order — все должны пройти.
        // Fills the window with 63 unique counters in reverse order — all must pass.
        let mut w = ReplayWindow::new(0);
        w.check_and_update(100).unwrap();
        for c in (37..100).rev() {
            w.check_and_update(c).unwrap();
        }
        // Повтор любого из них → Replay.
        // Replaying any of them → Replay.
        for c in 37..=100 {
            let err = w.check_and_update(c).unwrap_err();
            assert!(matches!(err, CallError::Replay { .. }), "c={c} must replay");
        }
    }
}
