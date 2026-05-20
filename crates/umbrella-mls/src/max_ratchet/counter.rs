//! Счётчик commits для post-quantum X-Wing ratchet каждые N commits.
//!
//! Логика: каждый N-й commit (counter % N == 0, counter > 0) помечается для
//! дополнительной X-Wing post-quantum combine на уровне provider'a. Это даёт защиту от
//! квантового противника который мог бы вычислить epoch_secret из observed classical-only
//! commits.
//!
//! Counter for post-quantum X-Wing ratchet every N commits.
//!
//! Logic: every N-th commit (counter % N == 0, counter > 0) is flagged for an additional
//! X-Wing post-quantum combine at the provider level. This protects against a quantum
//! adversary who could otherwise compute the epoch_secret from observed classical-only
//! commits.

/// Возвращает true если текущее значение counter'а кратно N (и оба > 0).
///
/// - `counter == 0` → false (нет смысла triggering PQ на самом первом commit'е)
/// - `counter == N` → true (первое срабатывание после N commits)
/// - `counter == 2 * N` → true
/// - `every_n == 0` → false (PQ ratchet отключён)
///
/// Returns true if the current counter is a multiple of N (and both > 0).
pub fn should_trigger_pq(counter: u32, every_n: u32) -> bool {
    if every_n == 0 || counter == 0 {
        return false;
    }
    counter.is_multiple_of(every_n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_trigger_at_zero() {
        assert!(!should_trigger_pq(0, 3));
    }

    #[test]
    fn does_not_trigger_at_1_2() {
        assert!(!should_trigger_pq(1, 3));
        assert!(!should_trigger_pq(2, 3));
    }

    #[test]
    fn triggers_at_3_6_9_12() {
        assert!(should_trigger_pq(3, 3));
        assert!(should_trigger_pq(6, 3));
        assert!(should_trigger_pq(9, 3));
        assert!(should_trigger_pq(12, 3));
    }

    #[test]
    fn does_not_trigger_between_multiples() {
        assert!(!should_trigger_pq(4, 3));
        assert!(!should_trigger_pq(5, 3));
        assert!(!should_trigger_pq(7, 3));
        assert!(!should_trigger_pq(8, 3));
        assert!(!should_trigger_pq(10, 3));
        assert!(!should_trigger_pq(11, 3));
    }

    #[test]
    fn zero_every_n_never_triggers() {
        for counter in 0..100 {
            assert!(!should_trigger_pq(counter, 0));
        }
    }

    #[test]
    fn every_one_triggers_after_first() {
        assert!(!should_trigger_pq(0, 1));
        for counter in 1..50 {
            assert!(should_trigger_pq(counter, 1));
        }
    }
}
