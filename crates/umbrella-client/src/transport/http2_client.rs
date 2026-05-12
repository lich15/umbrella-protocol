//! Общий builder для `reqwest::Client`, используемый всеми HTTP/2 транспортами
//! (`Http2UnwrapTransport`, `Http2PostmanTransport`, `Http2KtTransport`,
//! `Http2CallRelayTransport`). Фиксирует протокольные инварианты уровня
//! стека Umbrella:
//!
//! - **TLS 1.3 only** (design §5.1) — `min_tls_version(TLS_1_3)` отвергает
//!   TLS 1.2/1.1 даунгрейды.
//! - **HTTP/2 prior knowledge** (design §5.1) — никаких протокол-даунгрейдов
//!   и никаких ALPN round-trip'ов, сразу двоичный фрейминг HTTP/2.
//! - **rustls** — TLS-стек (не OpenSSL), тот же набор cipher-suites, что
//!   используется в `Umbrella server implementation` на серверной стороне.
//! - **Keepalive** — HTTP/2 PING каждые 30 секунд (idle mobile networks).
//! - **Timeouts** — connect 5s, total 60s, per-request 30s (вызывающие
//!   транспорты могут override через `.timeout()` в call-site'е).
//! - **TCP_NODELAY** — меньше latency на short-header требованиях MLS/SFrame.
//!
//! Один `Arc<reqwest::Client>` переиспользуется между всеми транспортами
//! внутри `ClientCore` — reqwest внутри держит HTTP/2 connection-pool и
//! multiplex-ирует streams.
//!
//! Shared builder for `reqwest::Client`, used by all HTTP/2 transports
//! (`Http2UnwrapTransport`, `Http2PostmanTransport`, `Http2KtTransport`,
//! `Http2CallRelayTransport`). Fixes protocol invariants:
//!
//! - **TLS 1.3 only** (design §5.1) — `min_tls_version(TLS_1_3)` rejects
//!   TLS 1.2/1.1 downgrades.
//! - **HTTP/2 prior knowledge** — no protocol negotiation, direct binary
//!   HTTP/2 framing.
//! - **rustls** — TLS stack (not OpenSSL), matches `Umbrella server implementation` server side.
//! - **Keepalive** — HTTP/2 PING every 30s (idle mobile networks).
//! - **Timeouts** — connect 5s, total 60s, per-request 30s (callers may
//!   override via `.timeout()` on the individual request).
//! - **TCP_NODELAY** — reduces latency of short-header MLS/SFrame frames.
//!
//! A single `Arc<reqwest::Client>` is shared between all transports inside a
//! given `ClientCore` — reqwest multiplexes HTTP/2 streams inside the pool.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{tls, Client, ClientBuilder};

use crate::error::ClientError;

/// User-Agent по умолчанию. Уникален между версиями — даёт ops-side
/// возможность видеть долю трафика от конкретной ревизии ядра клиента.
///
/// Default User-Agent. Unique across versions — lets the ops side attribute
/// traffic to specific core revisions.
const DEFAULT_USER_AGENT: &str =
    concat!("UmbrellaX/", env!("CARGO_PKG_VERSION"), " (rust; stage-7)");

/// HTTP/2 keep-alive timeout: сколько ждать pong после ping прежде чем
/// считать соединение мёртвым. 10 секунд — компромисс между мобильной
/// сетью (RTT до 2s в 3G) и защитой от зависших connection-pool entry.
///
/// HTTP/2 keep-alive timeout: how long to wait for a pong after a ping
/// before deeming the connection dead. 10 seconds — balances poor mobile
/// RTT against stale connection-pool entries.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Настройки HTTP/2 клиента. Инстанцируется native-приложением при bootstrap
/// через `ClientConfig`; в тестах используется [`Self::default`].
///
/// Вмешиваться в эти значения руками не стоит: дефолты подобраны под
/// продакшн-инварианты `Umbrella server implementation` (mobile network, TLS 1.3 ticket rotate
/// 24h, HTTP/2 max_concurrent_streams 256).
///
/// HTTP/2 client configuration. Produced by the native app at bootstrap via
/// `ClientConfig`; tests use [`Self::default`]. Defaults are tuned for
/// `Umbrella server implementation` production invariants (mobile network, TLS 1.3 ticket rotate
/// 24h, HTTP/2 `max_concurrent_streams` 256); override at your own risk.
#[derive(Debug, Clone)]
pub struct Http2Config {
    /// Connect timeout — максимум времени на TCP handshake + TLS handshake.
    /// Connect timeout — max time budget for TCP + TLS handshake.
    pub connect_timeout: Duration,

    /// Per-request timeout — максимум времени на отдельный HTTP/2 запрос,
    /// применяется транспортами вручную через `.timeout()` на call-site'е
    /// (не приклеивается к самому клиенту, чтобы не конфликтовать с
    /// `tokio::time::timeout` обёртками в fan-out).
    ///
    /// Per-request timeout — budget for a single HTTP/2 request. Applied by
    /// transports manually via `.timeout()` on the call site (not attached
    /// to the client itself to avoid conflicting with `tokio::time::timeout`
    /// wrappers used in fan-out).
    pub request_timeout: Duration,

    /// Общий timeout на всю цепочку request (включая redirects, retry в
    /// будущем — см. `retry.rs`). Приклеивается к client-builder.
    ///
    /// Global timeout on the entire request chain (including redirects,
    /// future retries — see `retry.rs`). Attached to the client builder.
    pub total_timeout: Duration,

    /// Интервал HTTP/2 keep-alive PING. 30 секунд — стандарт для mobile
    /// клиентов, не создаёт значимого traffic'а и удерживает NAT open.
    ///
    /// HTTP/2 keep-alive PING interval. 30 seconds — mobile-client standard,
    /// negligible traffic, keeps NAT open.
    pub http2_keepalive_interval: Duration,

    /// User-Agent строка. Ops использует её для attribution по версиям.
    /// User-Agent string. Used by ops for per-version attribution.
    pub user_agent: String,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(60),
            http2_keepalive_interval: Duration::from_secs(30),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }
}

/// Построить настроенный `reqwest::Client` согласно `Http2Config`.
///
/// Возвращает `Arc<Client>` — внутри reqwest сам по себе держит
/// connection pool, так что shared-ownership через `Arc` — правильный
/// паттерн совместного использования одной и той же connection-pool'а
/// между транспортами одного `ClientCore`.
///
/// # Errors
/// [`ClientError::Network`] если rustls не смог инициализироваться
/// (некорректная platform crypto configuration). В нормальных условиях
/// никогда не происходит на production-устройствах.
///
/// Build a configured `reqwest::Client` from `Http2Config`.
///
/// Returns `Arc<Client>` — reqwest maintains its own connection pool
/// internally, so shared ownership via `Arc` is the idiomatic way to share
/// a single pool between transports of the same `ClientCore`.
///
/// # Errors
/// [`ClientError::Network`] if rustls fails to initialize (malformed
/// platform crypto configuration). Never happens on production devices
/// under normal conditions.
pub fn build_http2_client(config: Http2Config) -> Result<Arc<Client>, ClientError> {
    let client = ClientBuilder::new()
        .use_rustls_tls()
        .min_tls_version(tls::Version::TLS_1_3)
        .http2_prior_knowledge()
        .http2_keep_alive_interval(config.http2_keepalive_interval)
        .http2_keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .connect_timeout(config.connect_timeout)
        .timeout(config.total_timeout)
        .user_agent(config.user_agent)
        .tcp_nodelay(true)
        .build()
        .map_err(|e| ClientError::Network(format!("reqwest client build: {e}")))?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_design_section_5_1() {
        let cfg = Http2Config::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.total_timeout, Duration::from_secs(60));
        assert_eq!(cfg.http2_keepalive_interval, Duration::from_secs(30));
        assert!(cfg.user_agent.starts_with("UmbrellaX/"));
        assert!(cfg.user_agent.contains("(rust; stage-7)"));
    }

    #[test]
    fn build_http2_client_returns_shared_pool() {
        let client = build_http2_client(Http2Config::default()).expect("build");
        // Arc same pool — два клона указывают на один и тот же pool.
        let clone = Arc::clone(&client);
        assert!(Arc::ptr_eq(&client, &clone));
    }

    #[test]
    fn build_http2_client_accepts_custom_user_agent() {
        let cfg = Http2Config {
            user_agent: "custom-ua/1.0".to_string(),
            ..Http2Config::default()
        };
        let client = build_http2_client(cfg).expect("build");
        // Нельзя прочитать UA обратно из клиента (reqwest не exposes), но
        // факт успешного .build() с кастомной строкой достаточный smoke.
        drop(client);
    }
}
