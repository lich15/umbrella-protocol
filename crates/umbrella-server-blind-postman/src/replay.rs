//! Anti-replay через time-windowed HashSet хешей сообщений.
//! Anti-replay via time-windowed HashSet of message hashes.
//!
//! ## Почему время-оконный, а не бесконечный
//!
//! Бесконечный replay-лог стирает forward secrecy не ухудшает, но создаёт денежный burden:
//! сервер обязан хранить миллиарды hash-entries на всю жизнь аккаунта. Практика: окно 60 секунд
//! в несколько раз превышает разумный RTT+retry, но короче любого реалистичного
//! unique-message interval. Законный ретрай-посыл того же commit (client переотправил из-за
//! потери сети) приходит в пределах окна — сервер отвергает duplicate и клиент уже обновил
//! своё состояние.
//!
//! ## Why time-windowed rather than unbounded
//!
//! An unbounded replay log does not hurt forward secrecy but imposes a monetary burden: the
//! server must retain billions of hash entries for an account's lifetime. In practice: a
//! 60-second window is several times larger than any reasonable RTT+retry but shorter than any
//! realistic unique-message interval. A legitimate retry of the same commit (client resends
//! due to network loss) arrives within the window — the server rejects the duplicate and the
//! client has already advanced its own state.

use std::collections::{HashSet, VecDeque};

/// Дефолтное окно anti-replay (60 секунд).
/// Default anti-replay window (60 seconds).
pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 60;

/// Решение anti-replay проверки. Outcome of an anti-replay check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDecision {
    /// Сообщение принято — либо это первый раз в окне, либо окно истекло с предыдущего.
    /// Message accepted — either first occurrence in the window, or window expired since last.
    Accept,
    /// Сообщение уже видели в текущем окне.
    /// Message already seen in the current window.
    Duplicate,
}

/// Time-windowed anti-replay guard.
///
/// Хранит SHA-256 hash'и сообщений с их `arrival_unix`. При проверке:
/// 1. Удаляет из окна все записи старее `now_unix - window_secs`.
/// 2. Если hash есть в активном окне → `Duplicate`.
/// 3. Иначе → `Accept`, записываем hash с `now_unix`.
///
/// Потребление памяти: O(rate × window). При 10K msg/s и окне 60s — 600K записей (~40 MB).
///
/// Stores message SHA-256 hashes with their `arrival_unix`. On check:
/// 1. Evicts from the window all entries older than `now_unix - window_secs`.
/// 2. If the hash is in the active window → `Duplicate`.
/// 3. Otherwise → `Accept`, records hash with `now_unix`.
///
/// Memory footprint: O(rate × window). At 10K msg/s with a 60s window — 600K entries (~40 MB).
pub struct ReplayGuard {
    window_secs: u64,
    /// Хеши в активном окне (для O(1) lookup).
    /// Hashes in the active window (for O(1) lookup).
    active: HashSet<[u8; 32]>,
    /// Очередь (arrival_unix, hash) в хронологическом порядке — для GC.
    /// Queue (arrival_unix, hash) in chronological order — for GC.
    queue: VecDeque<(u64, [u8; 32])>,
}

impl ReplayGuard {
    /// Создаёт новый guard с указанным окном.
    /// Creates a new guard with the specified window.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            active: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// Создаёт guard с дефолтным окном [`DEFAULT_REPLAY_WINDOW_SECS`].
    /// Creates a guard with the default window [`DEFAULT_REPLAY_WINDOW_SECS`].
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SECS)
    }

    /// Число активных записей в окне. Number of active entries in the window.
    pub fn active_entries(&self) -> usize {
        self.active.len()
    }

    /// Проверяет hash против окна и записывает если уникальное.
    /// Checks the hash against the window and records it if unique.
    pub fn check_and_record(&mut self, hash: [u8; 32], now_unix: u64) -> ReplayDecision {
        if self.is_duplicate(hash, now_unix) {
            return ReplayDecision::Duplicate;
        }

        self.record(hash, now_unix);
        ReplayDecision::Accept
    }

    /// Проверяет, есть ли hash в активном окне, но не записывает новый.
    /// Checks whether the hash is active without recording a new one.
    pub fn is_duplicate(&mut self, hash: [u8; 32], now_unix: u64) -> bool {
        self.evict_expired(now_unix);
        self.active.contains(&hash)
    }

    /// Записывает hash в окно после всех внешних разрешающих проверок.
    /// Records the hash after all external allow checks have passed.
    pub fn record(&mut self, hash: [u8; 32], now_unix: u64) {
        self.evict_expired(now_unix);
        if self.active.insert(hash) {
            self.queue.push_back((now_unix, hash));
        }
    }

    /// Удаляет из окна записи старее `now_unix - window_secs`.
    /// Evicts entries older than `now_unix - window_secs`.
    fn evict_expired(&mut self, now_unix: u64) {
        let cutoff = now_unix.saturating_sub(self.window_secs);
        while let Some(&(ts, hash)) = self.queue.front() {
            if ts < cutoff {
                self.queue.pop_front();
                self.active.remove(&hash);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    #[test]
    fn first_occurrence_accepted() {
        let mut g = ReplayGuard::new(60);
        assert_eq!(g.check_and_record(hash(1), 1_000), ReplayDecision::Accept);
    }

    #[test]
    fn second_occurrence_in_window_duplicate() {
        let mut g = ReplayGuard::new(60);
        g.check_and_record(hash(1), 1_000);
        assert_eq!(
            g.check_and_record(hash(1), 1_030),
            ReplayDecision::Duplicate,
            "in-window replay must be detected"
        );
    }

    #[test]
    fn replay_outside_window_accepted_again() {
        let mut g = ReplayGuard::new(60);
        g.check_and_record(hash(1), 1_000);
        // 61 секунд спустя — вне окна, принимаем снова (предыдущая запись вытеснена).
        assert_eq!(
            g.check_and_record(hash(1), 1_061),
            ReplayDecision::Accept,
            "out-of-window retry should be accepted"
        );
    }

    #[test]
    fn distinct_hashes_do_not_collide() {
        let mut g = ReplayGuard::new(60);
        assert_eq!(g.check_and_record(hash(1), 1_000), ReplayDecision::Accept);
        assert_eq!(g.check_and_record(hash(2), 1_000), ReplayDecision::Accept);
        assert_eq!(g.check_and_record(hash(3), 1_000), ReplayDecision::Accept);
        assert_eq!(g.active_entries(), 3);
    }

    #[test]
    fn eviction_shrinks_active_set() {
        let mut g = ReplayGuard::new(30);
        g.check_and_record(hash(1), 1_000);
        g.check_and_record(hash(2), 1_010);
        g.check_and_record(hash(3), 1_020);
        assert_eq!(g.active_entries(), 3);
        // Продвигаем время вперёд: hash(1) и hash(2) должны истечь.
        g.check_and_record(hash(4), 1_045);
        assert_eq!(
            g.active_entries(),
            2,
            "entries from t=1000 and t=1010 must be evicted at t=1045 (window=30)"
        );
    }

    #[test]
    fn eviction_frees_hash_for_reuse_without_collision() {
        let mut g = ReplayGuard::new(10);
        g.check_and_record(hash(1), 1_000);
        assert_eq!(g.check_and_record(hash(1), 1_011), ReplayDecision::Accept);
        assert_eq!(
            g.check_and_record(hash(1), 1_012),
            ReplayDecision::Duplicate,
            "same hash again within new window must duplicate"
        );
    }

    #[test]
    fn default_window_is_60_seconds() {
        assert_eq!(DEFAULT_REPLAY_WINDOW_SECS, 60);
        let g = ReplayGuard::with_default_window();
        assert_eq!(g.window_secs, 60);
    }

    #[test]
    fn saturating_now_unix_zero_does_not_panic() {
        // now_unix=0 и window_secs=60 — cutoff = 0 (saturating_sub). Не panic.
        let mut g = ReplayGuard::new(60);
        assert_eq!(g.check_and_record(hash(1), 0), ReplayDecision::Accept);
    }
}
