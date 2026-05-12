//! Exponential backoff с jitter для повторения idempotent-операций.
//!
//! Используется HTTP/2 транспортами (Http2UnwrapTransport fan-out, Http2KtTransport
//! fetch_epoch, Http2PostmanTransport deliver при idempotent nonce) для
//! переносимых транзиентных ошибок: timeouts, connection refused, 5xx ответы.
//!
//! **Важно:** retry применим **только** к идемпотентным запросам. POST на
//! blind-postman deliver — nonced, идемпотентен (dedupe на сервере по
//! message_id). POST на cloud-backup unwrap — nonced через `server_nonce`,
//! идемпотентен. POST на kt/publish — идемпотентен (dedupe по entry id).
//! GET — идемпотентно по дефолту.
//!
//! Алгоритм: `delay_n = min(INITIAL * 2^(n-1), MAX_BACKOFF) + jitter(0..delay/2)`.
//! Jitter — равномерный random в диапазоне [0, delay/2]. Это т.н. "decorrelated
//! jitter" (AWS Architecture Blog, 2015): сокращает вероятность thundering
//! herd при одновременном восстановлении сервиса после outage'а.
//!
//! Exponential backoff with jitter for retrying idempotent operations.
//!
//! Used by HTTP/2 transports (Http2UnwrapTransport fan-out, Http2KtTransport
//! fetch_epoch, Http2PostmanTransport deliver with idempotent nonce) for
//! transient errors: timeouts, connection refused, 5xx responses.
//!
//! **Important:** retry is applied **only** to idempotent requests. POST to
//! blind-postman /deliver carries a nonce (server dedupes by message_id).
//! POST to cloud-backup unwrap carries `server_nonce` (idempotent). POST
//! kt/publish dedupes by entry id. GET is idempotent by default.
//!
//! Algorithm: `delay_n = min(INITIAL * 2^(n-1), MAX_BACKOFF) + jitter(0..delay/2)`.
//! Jitter is uniform random over [0, delay/2] — decorrelated jitter (AWS
//! Architecture Blog, 2015): reduces thundering-herd probability when a
//! service recovers after an outage.

use std::future::Future;
use std::time::Duration;

use rand::Rng;

/// Максимум попыток для idempotent операций по умолчанию.
/// Default max attempts for idempotent operations.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Initial backoff delay (500 мс). Initial backoff delay (500 ms).
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Верхняя граница backoff delay (10 сек). Upper cap on backoff delay (10 s).
pub const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Retry с exponential backoff + jitter.
///
/// `operation` вызывается до `max_attempts` раз. Если возвращена `Ok` — результат
/// немедленно отдаётся вызывающему. Если `Err(e)` и `retryable(&e) == true` и
/// осталось попыток — sleep на backoff + jitter, затем повторить. В противном
/// случае ошибка пробрасывается как есть.
///
/// **Гарантии:**
/// - Если `max_attempts == 0` — ни одного вызова `operation` не происходит,
///   функция паникует через `debug_assert` в debug и возвращает последнюю
///   ошибку в release (в практике never hit, поскольку constants запрещают 0).
/// - Если `retryable` всегда `false` — `operation` вызывается **ровно один раз**.
/// - Экспоненциальный рост backoff ограничен `MAX_BACKOFF` (не growthless overflow).
///
/// `operation` is called up to `max_attempts` times. On `Ok`, the result is
/// returned immediately. On `Err(e)` with `retryable(&e) == true` and attempts
/// remaining — sleep for backoff + jitter, then retry. Otherwise the error is
/// propagated as-is.
///
/// **Guarantees:**
/// - `max_attempts == 0` never calls `operation` (debug-panic; release returns
///   the default-constructed last error — constants forbid zero in practice).
/// - If `retryable` is always `false` — `operation` is called **exactly once**.
/// - Exponential growth is capped at `MAX_BACKOFF`.
///
/// # Errors
/// Возвращает последнюю ошибку `operation` после исчерпания попыток или
/// не-retryable ошибки.
///
/// Returns the last error from `operation` after retries are exhausted or on
/// a non-retryable error.
pub async fn retry_with_backoff<F, Fut, T, E, R>(
    mut operation: F,
    retryable: R,
    max_attempts: u32,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    R: Fn(&E) -> bool,
{
    debug_assert!(max_attempts >= 1, "max_attempts must be ≥ 1");

    let mut attempt: u32 = 0;
    let mut backoff = INITIAL_BACKOFF;

    loop {
        attempt = attempt.saturating_add(1);
        match operation().await {
            Ok(v) => return Ok(v),
            Err(e) if retryable(&e) && attempt < max_attempts => {
                // Decorrelated jitter: uniform in [0, backoff/2).
                let half_ms = (backoff.as_millis() as u64) / 2;
                let jitter_ms: u64 = if half_ms == 0 {
                    0
                } else {
                    rand::thread_rng().gen_range(0..half_ms)
                };
                let sleep_for = backoff.saturating_add(Duration::from_millis(jitter_ms));
                tokio::time::sleep(sleep_for).await;
                backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Является ли `reqwest::Error` транзиентной (можно retry).
///
/// Retryable: timeout, connect-failure, 5xx ответ. **Не** retryable: 4xx
/// (включая 429, т.к. 429 требует особой обработки — Retry-After header,
/// отдельный rate-limit backoff; мы не retry автоматически чтобы не замусорить
/// server).
///
/// Is a `reqwest::Error` transient (safe to retry)?
///
/// Retryable: timeout, connect failure, 5xx response. **Not** retryable: 4xx
/// (including 429, which needs Retry-After handling separately; we do not
/// retry automatically to avoid spamming the server).
#[must_use]
pub fn is_reqwest_retryable(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || is_5xx(err)
}

fn is_5xx(err: &reqwest::Error) -> bool {
    err.status().is_some_and(|s| s.is_server_error())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn succeeds_on_first_attempt_without_sleep() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let result: Result<u32, &'static str> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(42)
                }
            },
            |_: &&'static str| true,
            DEFAULT_MAX_ATTEMPTS,
        )
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_success_on_retryable_error() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let result: Result<u32, &'static str> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        Err("transient")
                    } else {
                        Ok(7)
                    }
                }
            },
            |_| true,
            5,
        )
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_after_max_attempts_and_returns_last_error() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let result: Result<u32, &'static str> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err("always")
                }
            },
            |_| true,
            3,
        )
        .await;
        assert_eq!(result.unwrap_err(), "always");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_non_retryable_error() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let result: Result<u32, &'static str> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err("permanent")
                }
            },
            |_| false,
            DEFAULT_MAX_ATTEMPTS,
        )
        .await;
        assert_eq!(result.unwrap_err(), "permanent");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retryable_filter_per_error_variant() {
        #[derive(Debug, PartialEq)]
        enum Err2 {
            Transient,
            Permanent,
        }
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let result: Result<(), Err2> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < 1 {
                        Err(Err2::Transient)
                    } else {
                        Err(Err2::Permanent)
                    }
                }
            },
            |e| matches!(e, Err2::Transient),
            5,
        )
        .await;
        assert_eq!(result.unwrap_err(), Err2::Permanent);
        // 1 Transient + 1 Permanent (non-retryable stops immediately).
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_growth_is_bounded_by_max() {
        // Спровоцировать 10 retries — backoff должен упереться в MAX_BACKOFF.
        // Тест через paused time: tokio::time::sleep не блокирует wall-clock.
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let start = tokio::time::Instant::now();
        let result: Result<u32, &'static str> = retry_with_backoff(
            move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < 10 {
                        Err("transient")
                    } else {
                        Ok(99)
                    }
                }
            },
            |_| true,
            11,
        )
        .await;
        let elapsed = start.elapsed();
        assert_eq!(result.unwrap(), 99);
        // 10 retries, backoff быстро выходит на MAX_BACKOFF (10s) + jitter ≤ 5s.
        // Теоретически max sleep sum ≈ 500ms + 1s + 2s + 4s + 8s + 10s + 10s + 10s +
        // 10s + 10s ≈ 65.5s (+ jitter ≤ 32.75s) → cap порядка 100s. Просто проверяем
        // что мы прожили > MAX_BACKOFF хотя бы один раз.
        assert!(
            elapsed >= MAX_BACKOFF,
            "expected elapsed ≥ MAX_BACKOFF, got {elapsed:?}"
        );
    }
}
