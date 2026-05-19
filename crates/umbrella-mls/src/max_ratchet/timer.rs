//! Таймер 5 минут принудительного rekey.
//!
//! При вызове [`check_should_trigger`] сравнивает текущий unix-timestamp с
//! `last_rekey_at_unix` группы. Если разница ≥ `timer_seconds` — возвращает true (нужно
//! делать [`UmbrellaGroup::force_rekey`](crate::group::UmbrellaGroup::force_rekey)).
//!
//! Закрывает scenario когда атакующий получил доступ к ключу и **ждёт** пока жертва
//! сделает паузу в переписке. Без таймера ключ может жить часами; с таймером — максимум
//! 5 минут.
//!
//! 5-minute forced rekey timer.
//!
//! [`check_should_trigger`] compares the current unix-timestamp with the group's
//! `last_rekey_at_unix`. If the difference ≥ `timer_seconds` it returns true (call
//! [`UmbrellaGroup::force_rekey`](crate::group::UmbrellaGroup::force_rekey)).
//!
//! Closes the scenario where an attacker gained access to the current key and **waits**
//! for the victim to pause the conversation. Without a timer the key could live for hours;
//! with the timer the lifetime is bounded at 5 minutes.

/// Возвращает true если с момента последнего rekey прошло достаточно времени.
///
/// - `last_rekey_at_unix` — timestamp последнего успешного rekey (из
///   [`UmbrellaGroup::last_rekey_at_unix`](crate::group::UmbrellaGroup::last_rekey_at_unix)).
/// - `now_unix` — текущий timestamp.
/// - `timer_seconds` — настроенный период (по умолчанию 300 = 5 минут).
/// - `timer_seconds == 0` → таймер отключён, всегда false.
///
/// `saturating_sub` защищает от случая когда часы прыгнули назад (clock skew).
///
/// Returns true if enough time has elapsed since the last rekey.
pub fn check_should_trigger(last_rekey_at_unix: u64, now_unix: u64, timer_seconds: u64) -> bool {
    if timer_seconds == 0 {
        return false;
    }
    let elapsed = now_unix.saturating_sub(last_rekey_at_unix);
    elapsed >= timer_seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_trigger_when_elapsed_less_than_timer() {
        assert!(!check_should_trigger(100, 200, 300));
    }

    #[test]
    fn triggers_when_elapsed_equals_timer() {
        assert!(check_should_trigger(100, 400, 300));
    }

    #[test]
    fn triggers_when_elapsed_greater_than_timer() {
        assert!(check_should_trigger(100, 500, 300));
    }

    #[test]
    fn handles_clock_skew_backwards() {
        // now_unix < last_rekey_at_unix (часы перевели назад). saturating_sub даст 0.
        assert!(!check_should_trigger(500, 100, 300));
    }

    #[test]
    fn timer_zero_disabled_never_triggers() {
        assert!(!check_should_trigger(0, u64::MAX, 0));
        assert!(!check_should_trigger(100, 10_000_000, 0));
    }
}
