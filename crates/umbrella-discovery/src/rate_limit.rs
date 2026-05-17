//! Rate-limit + replay protection для discovery.
//!
//! Rate limit + replay protection for discovery.
//!
//! ## Что закрывает
//!
//! - **D-5 OPRF replay:** server nonce + transcript binding записываются в
//!   client cache. Повторное появление = `ReplayDetected`.
//! - **D-7 rate-limit bypass:** discovery-budget tracker на стороне клиента,
//!   coordinated через `anon_id` registry на 5 серверах (см.
//!   `docs/spec/discovery-backend-spec.md` для серверной стороны).
//!
//! ## Threshold-coordinated rate limit
//!
//! Чтобы 5 sibling-устройств одного аккаунта не могли обойти лимит, anon_id
//! каждой query derived из master_key, который одинаковый у sibling-устройств.
//! Сервер видит anon_id на этой эпохе → коллапс budget в один счётчик per
//! account (через blinded count, согласованный 3 of 5).
//!
//! На клиенте мы поддерживаем conservative бюджет:
//! - 100 lookups / hour (типичная адресная книга refresh периодически).
//! - exponential backoff при бурсте.
//! - per-thread reuse-detector (replay) с rolling window 1000 nonces.
//!
//! ## What it covers
//!
//! - **D-5 OPRF replay:** server nonce + transcript binding go into a client
//!   cache; reoccurrence = `ReplayDetected`.
//! - **D-7 rate-limit bypass:** discovery budget tracker on the client side,
//!   coordinated with `anon_id` registry across 5 servers (see backend spec
//!   for the server side).

use core::time::Duration;
use std::collections::{HashSet, VecDeque};

use crate::error::{DiscoveryError, DiscoveryResult};
use crate::wire::SERVER_NONCE_LEN;

/// Размер rolling window для nonce replay detector (1000 nonces).
/// Rolling window size for nonce replay detector (1000 nonces).
pub const NONCE_WINDOW_SIZE: usize = 1000;

/// Базовый бюджет: 100 lookups в час по умолчанию.
/// Default base budget: 100 lookups per hour.
pub const DEFAULT_BUDGET_PER_HOUR: u32 = 100;

/// Long-term cap: 5000 lookups в сутки (safety net против compromised client).
/// Long-term cap: 5000 lookups per 24h.
pub const DEFAULT_BUDGET_PER_DAY: u32 = 5_000;

/// Минимальный delay при exhaustion (секунды).
/// Minimum delay on exhaustion (seconds).
pub const MIN_BACKOFF_SECS: u64 = 5;

/// Логические time-инструкции (для детерминированных тестов).
/// Logical clock abstraction (for deterministic tests).
pub trait DiscoveryClock {
    /// Текущее время в секундах с UNIX_EPOCH.
    /// Current time in seconds since UNIX_EPOCH.
    fn now_unix_secs(&self) -> u64;
}

/// Реальные системные часы.
/// Real system clock.
pub struct SystemClock;
impl DiscoveryClock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// Mock-клок для тестов (детерминированный).
/// Mock clock for tests (deterministic).
pub struct MockClock {
    /// Текущее логическое время (секунды).
    /// Current logical time (seconds).
    pub now: std::sync::atomic::AtomicU64,
}

impl MockClock {
    /// Конструктор: задать стартовое время.
    /// Constructor with initial time.
    pub fn new(start: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(start),
        }
    }

    /// Сдвинуть часы на `secs` секунд вперёд.
    /// Advance the clock by `secs` seconds.
    pub fn advance(&self, secs: u64) {
        use std::sync::atomic::Ordering;
        let cur = self.now.load(Ordering::SeqCst);
        self.now.store(cur + secs, Ordering::SeqCst);
    }
}

impl DiscoveryClock for MockClock {
    fn now_unix_secs(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Состояние client-side budget'а: queue of timestamps по hourly/daily окнам.
/// Client-side budget state: queue of timestamps over hourly/daily windows.
pub struct ClientBudgetState {
    per_hour: u32,
    per_day: u32,
    timestamps_hour: VecDeque<u64>,
    timestamps_day: VecDeque<u64>,
    burst_misses: u32,
}

impl ClientBudgetState {
    /// Конструктор с дефолтными лимитами.
    /// Constructor with default limits.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_BUDGET_PER_HOUR, DEFAULT_BUDGET_PER_DAY)
    }

    /// Конструктор с явными лимитами.
    /// Constructor with explicit limits.
    pub fn with_limits(per_hour: u32, per_day: u32) -> Self {
        Self {
            per_hour,
            per_day,
            timestamps_hour: VecDeque::new(),
            timestamps_day: VecDeque::new(),
            burst_misses: 0,
        }
    }

    /// Проверить можно ли сейчас сделать ещё одну query.
    ///
    /// # Errors
    /// - [`DiscoveryError::RateLimited`] с `retry_after_secs`.
    pub fn check_and_register<C: DiscoveryClock>(&mut self, clock: &C) -> DiscoveryResult<()> {
        let now = clock.now_unix_secs();
        // Удалить timestamps старше 1h из hourly window.
        while let Some(&oldest) = self.timestamps_hour.front() {
            if now.saturating_sub(oldest) >= 3600 {
                self.timestamps_hour.pop_front();
            } else {
                break;
            }
        }
        while let Some(&oldest) = self.timestamps_day.front() {
            if now.saturating_sub(oldest) >= 86_400 {
                self.timestamps_day.pop_front();
            } else {
                break;
            }
        }
        if self.timestamps_hour.len() as u32 >= self.per_hour {
            self.burst_misses = self.burst_misses.saturating_add(1);
            let exp_backoff = MIN_BACKOFF_SECS
                .saturating_mul(2u64.saturating_pow(self.burst_misses.min(8)));
            // Минимум до того момента когда самый старый timestamp вылетит.
            let next_free = self
                .timestamps_hour
                .front()
                .map(|&t| t + 3600 - now)
                .unwrap_or(MIN_BACKOFF_SECS);
            let retry_after_secs = exp_backoff.max(next_free);
            return Err(DiscoveryError::RateLimited { retry_after_secs });
        }
        if self.timestamps_day.len() as u32 >= self.per_day {
            let retry_after_secs = self
                .timestamps_day
                .front()
                .map(|&t| t + 86_400 - now)
                .unwrap_or(86_400);
            return Err(DiscoveryError::RateLimited { retry_after_secs });
        }
        // Свободно: добавить и обнулить burst.
        self.timestamps_hour.push_back(now);
        self.timestamps_day.push_back(now);
        self.burst_misses = 0;
        Ok(())
    }

    /// Текущее число запросов в окне.
    /// Current count in the rolling window.
    pub fn current_hourly_count(&self) -> usize {
        self.timestamps_hour.len()
    }
}

impl Default for ClientBudgetState {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay detector: keeps a rolling window of recently-seen server nonces.
/// Replay detector: keeps a rolling window of recently-seen server nonces.
pub struct NonceReplayGuard {
    seen: HashSet<[u8; SERVER_NONCE_LEN]>,
    order: VecDeque<[u8; SERVER_NONCE_LEN]>,
    cap: usize,
}

impl NonceReplayGuard {
    /// Конструктор с дефолтной capacity.
    /// Constructor with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(NONCE_WINDOW_SIZE)
    }

    /// Конструктор с явной capacity.
    /// Constructor with explicit capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Записать новый nonce. Возвращает `ReplayDetected` если уже виден.
    ///
    /// # Errors
    /// - [`DiscoveryError::ReplayDetected`] если nonce был замечен ранее.
    pub fn register(&mut self, nonce: &[u8; SERVER_NONCE_LEN]) -> DiscoveryResult<()> {
        if self.seen.contains(nonce) {
            return Err(DiscoveryError::ReplayDetected);
        }
        if self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        self.seen.insert(*nonce);
        self.order.push_back(*nonce);
        Ok(())
    }

    /// Текущая загрузка окна.
    /// Current window occupancy.
    pub fn current_size(&self) -> usize {
        self.order.len()
    }
}

impl Default for NonceReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_allows_under_hourly_limit() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(5, 100);
        for _ in 0..5 {
            state.check_and_register(&clock).unwrap();
        }
        // Шестой превышает.
        let err = state.check_and_register(&clock).unwrap_err();
        assert!(matches!(err, DiscoveryError::RateLimited { .. }));
    }

    #[test]
    fn budget_resets_after_one_hour() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(2, 100);
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        assert!(state.check_and_register(&clock).is_err());
        clock.advance(3600);
        state.check_and_register(&clock).unwrap();
    }

    #[test]
    fn budget_returns_exponential_backoff() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(1, 1000);
        state.check_and_register(&clock).unwrap();
        let err1 = state.check_and_register(&clock).unwrap_err();
        let s1 = match err1 {
            DiscoveryError::RateLimited { retry_after_secs } => retry_after_secs,
            other => panic!("expected RateLimited, got {other:?}"),
        };
        // На следующих попытках backoff exponential, минимум MIN_BACKOFF * 2^k.
        let err2 = state.check_and_register(&clock).unwrap_err();
        let s2 = match err2 {
            DiscoveryError::RateLimited { retry_after_secs } => retry_after_secs,
            other => panic!("expected RateLimited, got {other:?}"),
        };
        // Каждый retry_after_secs ≥ MIN_BACKOFF_SECS.
        assert!(s1 >= MIN_BACKOFF_SECS);
        assert!(s2 >= MIN_BACKOFF_SECS);
    }

    #[test]
    fn replay_guard_rejects_duplicate() {
        let mut guard = NonceReplayGuard::new();
        let n = [1u8; SERVER_NONCE_LEN];
        guard.register(&n).unwrap();
        let err = guard.register(&n).unwrap_err();
        assert!(matches!(err, DiscoveryError::ReplayDetected));
    }

    #[test]
    fn replay_guard_evicts_oldest() {
        // capacity=4: вмещает 4 уникальных nonce; на 5-м вытесняется oldest.
        let mut guard = NonceReplayGuard::with_capacity(4);
        let n1 = [1u8; SERVER_NONCE_LEN];
        let n2 = [2u8; SERVER_NONCE_LEN];
        let n3 = [3u8; SERVER_NONCE_LEN];
        let n4 = [4u8; SERVER_NONCE_LEN];
        let n5 = [5u8; SERVER_NONCE_LEN];
        guard.register(&n1).unwrap();
        guard.register(&n2).unwrap();
        guard.register(&n3).unwrap();
        guard.register(&n4).unwrap();
        // n2, n3, n4 ещё в окне → replay detected.
        let err = guard.register(&n2).unwrap_err();
        assert!(matches!(err, DiscoveryError::ReplayDetected));
        // n5 — новый, accept. Это вытесняет n1.
        guard.register(&n5).unwrap();
        // n1 после eviction теперь принимается (вылетел из окна).
        guard.register(&n1).unwrap();
        // Это в свою очередь вытесняет n2. Теперь n2 принимается.
        guard.register(&n2).unwrap();
    }

    #[test]
    fn replay_guard_independent_nonces() {
        let mut guard = NonceReplayGuard::with_capacity(10);
        for i in 0..10 {
            let n = [i as u8; SERVER_NONCE_LEN];
            guard.register(&n).unwrap();
        }
        // 10 разных nonces — все приняты.
        assert_eq!(guard.current_size(), 10);
    }

    #[test]
    fn budget_daily_cap_enforces_eventual_lock() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(10_000, 3);
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        let err = state.check_and_register(&clock).unwrap_err();
        assert!(matches!(err, DiscoveryError::RateLimited { .. }));
    }

    #[test]
    fn budget_daily_cap_resets_after_24h() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(10_000, 2);
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        assert!(state.check_and_register(&clock).is_err());
        clock.advance(86_400);
        state.check_and_register(&clock).unwrap();
    }

    #[test]
    fn budget_burst_attack_blocked_then_eventually_recovers() {
        let clock = MockClock::new(1_700_000_000);
        let mut state = ClientBudgetState::with_limits(3, 100);
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        state.check_and_register(&clock).unwrap();
        // Burst of 100 quick attempts — все blocked.
        let mut blocked = 0;
        for _ in 0..100 {
            if state.check_and_register(&clock).is_err() {
                blocked += 1;
            }
        }
        assert_eq!(blocked, 100);
        // Через час hourly window истекает → один запрос проходит.
        clock.advance(3600);
        state.check_and_register(&clock).unwrap();
    }
}
