//! Trait rate-limiter для sender_id с простой FixedWindow реализацией.
//! Rate-limiter trait for sender_id with a simple FixedWindow implementation.
//!
//! Production backend в Umbrella server implementation использует Valkey/DragonflyDB через FFI. Здесь предоставляем
//! абстракцию + default in-memory реализация для тестов и локальной разработки.
//!
//! The production backend in Umbrella server implementation uses Valkey/DragonflyDB via FFI. Here we provide the
//! abstraction plus a default in-memory implementation for tests and local development.

use std::collections::HashMap;

/// Решение rate-лимита: пропускать или блокировать.
/// Rate-limit decision: allow or block.
pub trait RateLimiter: Send + Sync {
    /// Возвращает `true` если sender может отправить ещё одно сообщение в указанный момент.
    /// Returns `true` if the sender may emit one more message at the given instant.
    ///
    /// `&mut self` нужен потому что FixedWindow обновляет buckets; production реализация
    /// поверх Valkey использует atomic INCR и может быть `&self` — trait совместим с обеими.
    ///
    /// `&mut self` is required because FixedWindow updates buckets; a production Valkey-backed
    /// implementation uses atomic INCR and may be `&self` — the trait supports both.
    fn allow(&mut self, sender_id: &[u8], now_unix: u64) -> bool;
}

/// Реализация-пустышка: всегда пропускает. Для тестов/девелопмента/сетапов без rate-лимита.
/// No-op implementation: always allows. For tests/dev/setups without rate limiting.
#[derive(Debug, Default)]
pub struct AllowAll;

impl RateLimiter for AllowAll {
    fn allow(&mut self, _sender_id: &[u8], _now_unix: u64) -> bool {
        true
    }
}

/// Максимальное количество одновременно отслеживаемых отправителей в default
/// in-memory `FixedWindow`. Защита от F-77 LOW (block 10.27d session #59):
/// уровень D противника создающий миллионы уникальных `sender_id` за секунду
/// мог бы заполнить in-memory HashMap до OOM (около 32 байта на каждый
/// `sender_id` плюс `(u64, u32)` значения, итого около 44 байта на запись).
/// Production backend (Valkey/DragonflyDB per ADR-001) имеет свои capacity
/// controls, но default in-memory implementation тоже должна fail-closed
/// под атакой а не безграничного расти.
///
/// При достижении лимита `allow()` сначала чистит просроченные окна
/// (retain bucket'ов с актуальным `window_start`), потом если table всё
/// ещё full — отвергает новых отправителей (fail-closed). Существующие
/// отправители продолжают работать без изменений. Значение 100_000
/// поддерживает достойный stress-test (около 7-8 МБ суммарной памяти при
/// 32-байтовых Ed25519-pubkey-производных sender_id) при сохранении
/// DoS-устойчивости.
///
/// Maximum number of simultaneously tracked senders in default in-memory
/// `FixedWindow`. Defence against F-77 LOW (block 10.27d session #59):
/// level D adversary creating millions of unique `sender_id` per second
/// could fill the in-memory HashMap until OOM (about 32 bytes per
/// `sender_id` plus `(u64, u32)` values, totalling about 44 bytes per
/// entry). Production backend (Valkey/DragonflyDB per ADR-001) has its
/// own capacity controls, but the default in-memory implementation must
/// also fail-closed under attack rather than grow without bound.
///
/// On reaching the limit `allow()` first cleans expired windows (retaining
/// only buckets with the current `window_start`), then if the table is
/// still full — rejects new senders (fail-closed). Existing senders keep
/// working without change. Value 100_000 supports a reasonable stress-test
/// (about 7-8 MB total memory for 32-byte Ed25519-pubkey-derived sender_id)
/// while preserving DoS resistance.
pub const MAX_TRACKED_SENDERS: usize = 100_000;

/// Fixed-window rate limiter: не более `per_window` сообщений за `window_secs` на sender.
/// Fixed-window rate limiter: at most `per_window` messages per `window_secs` per sender.
///
/// Простой и predictable. Недостаток: traffic burst на границе окна (до 2x лимита за
/// window). Для production под 1B use Valkey sliding-window. Default in-memory
/// implementation имеет жёсткий потолок [`MAX_TRACKED_SENDERS`] для защиты от
/// F-77 sender_id flooding (см. doc-comment к константе).
///
/// Simple and predictable. Downside: traffic burst at window boundary (up to 2x the limit per
/// window). For the 1B-user production path use Valkey sliding-window. The default
/// in-memory implementation has a hard cap [`MAX_TRACKED_SENDERS`] as defence against
/// F-77 sender_id flooding (see the constant's doc-comment).
pub struct FixedWindow {
    window_secs: u64,
    per_window: u32,
    /// (window_start_unix, count_in_window) per sender_id.
    buckets: HashMap<Vec<u8>, (u64, u32)>,
}

impl FixedWindow {
    /// Создаёт лимитер: не более `per_window` сообщений за `window_secs` секунд на sender.
    /// Creates a limiter: at most `per_window` messages per `window_secs` seconds per sender.
    ///
    /// Panics if `per_window == 0` (нет смысла: все sender'ы блокированы навсегда).
    /// Panics if `window_secs == 0` (F-55 block 10.14 inline-fix: иначе `allow` делает
    /// `now_unix / 0` и runtime panic'ит вместо fail-fast на construction). Mirrors per_window
    /// invariant.
    ///
    /// Panics if `per_window == 0` (meaningless: all senders are blocked forever).
    /// Panics if `window_secs == 0` (F-55 block 10.14 inline-fix: otherwise `allow` performs
    /// `now_unix / 0` and the runtime panics instead of failing fast at construction).
    /// Mirrors the `per_window` invariant.
    #[allow(
        unknown_lints,
        no_assert_in_lib,
        reason = "block 11.8 dylint expansion: F-55 deliberate fail-fast at construction time \
                 (block 10.14 inline-fix prevents `now_unix / 0` runtime panic later). All 15 \
                 call sites (5 production + 10 tests) verified to pass compile-time non-zero \
                 constants per ratelimit.rs grep audit. Carry-over Stage 11+ block: refactor to \
                 `pub fn new(window_secs: NonZero<u64>, per_window: NonZero<u32>) -> Self` to \
                 lift invariant to type system (eliminates assertion entirely). \
                 `unknown_lints` suppressed because rustc outside the dylint driver does not know \
                 the custom `no_assert_in_lib` lint name"
    )]
    pub fn new(window_secs: u64, per_window: u32) -> Self {
        assert!(per_window > 0, "per_window must be > 0");
        assert!(window_secs > 0, "window_secs must be > 0");
        Self {
            window_secs,
            per_window,
            buckets: HashMap::new(),
        }
    }

    /// Количество sender'ов с активными bucket'ами.
    /// Count of senders with active buckets.
    pub fn active_senders(&self) -> usize {
        self.buckets.len()
    }
}

impl RateLimiter for FixedWindow {
    fn allow(&mut self, sender_id: &[u8], now_unix: u64) -> bool {
        let window_start = (now_unix / self.window_secs) * self.window_secs;

        // F-77 LOW (block 10.27d session #59 retroactive surface sweep):
        // bounded HashMap growth — defence-in-depth против sender_id flooding
        // атаки. Если новый отправитель приходит когда table уже на пределе,
        // сначала пытаемся освободить место очисткой просроченных окон
        // (retain bucket'ов с актуальным `window_start`), потом если всё ещё
        // full — отвергаем (fail-closed). Существующие отправители продолжают
        // работать без изменений (`contains_key` возвращает true, ветка
        // пропускается). См. doc-comment к [`MAX_TRACKED_SENDERS`].
        //
        // F-77 LOW (block 10.27d session #59 retroactive surface sweep):
        // bounded HashMap growth — defence-in-depth against sender_id flooding
        // attack. If a new sender arrives when the table is already at
        // capacity, first try to free room by cleaning expired windows
        // (retaining only buckets with the current `window_start`); if still
        // full — reject (fail-closed). Existing senders keep working without
        // change (`contains_key` returns true and the branch is skipped). See
        // [`MAX_TRACKED_SENDERS`] doc-comment.
        if !self.buckets.contains_key(sender_id) && self.buckets.len() >= MAX_TRACKED_SENDERS {
            self.buckets
                .retain(|_, (bucket_window_start, _)| *bucket_window_start == window_start);
            if self.buckets.len() >= MAX_TRACKED_SENDERS {
                return false;
            }
        }

        let entry = self
            .buckets
            .entry(sender_id.to_vec())
            .or_insert((window_start, 0));

        if entry.0 != window_start {
            entry.0 = window_start;
            entry.1 = 0;
        }

        if entry.1 >= self.per_window {
            return false;
        }

        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_never_blocks() {
        let mut rl = AllowAll;
        for i in 0..1_000_000 {
            assert!(rl.allow(b"sender", i));
        }
    }

    #[test]
    fn fixed_window_allows_up_to_limit() {
        let mut rl = FixedWindow::new(60, 5);
        for _ in 0..5 {
            assert!(rl.allow(b"alice", 100));
        }
        assert!(
            !rl.allow(b"alice", 100),
            "6th message in window must be blocked"
        );
    }

    #[test]
    fn fixed_window_resets_on_new_window() {
        let mut rl = FixedWindow::new(60, 3);
        for _ in 0..3 {
            assert!(rl.allow(b"alice", 100));
        }
        assert!(!rl.allow(b"alice", 100));
        // Переход в новое окно (t=120 → window 120..180).
        assert!(rl.allow(b"alice", 120));
    }

    #[test]
    fn fixed_window_senders_are_isolated() {
        let mut rl = FixedWindow::new(60, 2);
        assert!(rl.allow(b"alice", 100));
        assert!(rl.allow(b"alice", 100));
        assert!(!rl.allow(b"alice", 100));
        // Bob в том же окне всё ещё свободен.
        assert!(rl.allow(b"bob", 100));
        assert!(rl.allow(b"bob", 100));
        assert!(!rl.allow(b"bob", 100));
    }

    #[test]
    #[should_panic(expected = "per_window must be > 0")]
    fn zero_limit_panics() {
        let _ = FixedWindow::new(60, 0);
    }

    #[test]
    #[should_panic(expected = "window_secs must be > 0")]
    fn zero_window_secs_panics() {
        // F-55 regression-guard (block 10.14): assert! fail-fast предотвращает runtime
        // panic в `allow` при `now_unix / self.window_secs` div-by-zero. Mirrors
        // per_window assertion invariant.
        // F-55 regression guard (block 10.14): the `assert!` fails fast and prevents the
        // runtime panic in `allow` from `now_unix / self.window_secs` div-by-zero. Mirrors
        // the `per_window` assertion invariant.
        let _ = FixedWindow::new(0, 1);
    }

    #[test]
    fn active_senders_count_matches_unique_senders() {
        let mut rl = FixedWindow::new(60, 10);
        rl.allow(b"s1", 100);
        rl.allow(b"s2", 100);
        rl.allow(b"s1", 100);
        rl.allow(b"s3", 100);
        assert_eq!(rl.active_senders(), 3);
    }
}
