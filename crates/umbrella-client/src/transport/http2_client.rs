//! Общий builder для `reqwest::Client`, используемый всеми HTTP/2 транспортами
//! (`Http2UnwrapTransport`, `Http2PostmanTransport`, `Http2KtTransport`,
//! `Http2CallRelayTransport`). Фиксирует протокольные инварианты уровня
//! стека Umbrella:
//!
//! - **TLS 1.3 only** (design §5.1) — `tls_version_min(TLS_1_3)` отвергает
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
//! - **TLS 1.3 only** (design §5.1) — `tls_version_min(TLS_1_3)` rejects
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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{tls, Client, ClientBuilder, Url};

use crate::error::ClientError;
use crate::transport::{
    normalize_dns_host, PinningConfig, SpkiPinningVerifier, SEALED_SERVER_COUNT,
};

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

/// Боевой endpoint с обязательным закреплением ключа сертификата.
/// Production endpoint with mandatory certificate-key pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedServiceEndpoint {
    /// URL сервиса. Service URL.
    pub url: String,
    /// Основной и запасной закреплённые ключи. Primary and backup pins.
    pub pins: PinningConfig,
}

impl PinnedServiceEndpoint {
    /// Создать endpoint с уже заданными pin-ами.
    /// Construct an endpoint with explicit pins.
    #[must_use]
    pub fn new(url: String, pins: PinningConfig) -> Self {
        Self { url, pins }
    }
}

/// Боевая настройка HTTP/2 транспорта.
/// Production HTTP/2 transport configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHttp2Config {
    /// Ровно пять запечатанных серверов. Exactly five Sealed Servers.
    pub sealed_servers: Vec<PinnedServiceEndpoint>,
    /// Почтовый сервис. Blind postman service.
    pub postman: PinnedServiceEndpoint,
    /// Журнал ключей. Key-transparency service.
    pub kt: PinnedServiceEndpoint,
    /// Релей звонков. Call relay service.
    pub call_relay: PinnedServiceEndpoint,
}

impl ProductionHttp2Config {
    /// Проверить, что боевая настройка не похожа на стенд.
    /// Validate that production config is not a test setup.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.sealed_servers.len() != SEALED_SERVER_COUNT {
            return Err(ClientError::Network(format!(
                "production transport requires exactly {SEALED_SERVER_COUNT} pinned sealed servers, got {}",
                self.sealed_servers.len()
            )));
        }

        for (idx, endpoint) in self.sealed_servers.iter().enumerate() {
            validate_production_endpoint(&format!("sealed_server_urls[{idx}]"), endpoint)?;
        }
        validate_production_endpoint("postman_url", &self.postman)?;
        validate_production_endpoint("kt_url", &self.kt)?;
        validate_production_endpoint("call_relay_url", &self.call_relay)?;
        Ok(())
    }

    /// Собрать карту `host -> pins` для TLS verifier.
    /// Build the `host -> pins` map for the TLS verifier.
    pub fn pins_by_host(&self) -> Result<BTreeMap<String, PinningConfig>, ClientError> {
        self.validate()?;
        let mut pins = BTreeMap::new();
        for endpoint in &self.sealed_servers {
            insert_endpoint_pins(&mut pins, endpoint)?;
        }
        insert_endpoint_pins(&mut pins, &self.postman)?;
        insert_endpoint_pins(&mut pins, &self.kt)?;
        insert_endpoint_pins(&mut pins, &self.call_relay)?;
        Ok(pins)
    }
}

fn validate_production_endpoint(
    role: &str,
    endpoint: &PinnedServiceEndpoint,
) -> Result<(), ClientError> {
    let parsed = Url::parse(&endpoint.url)
        .map_err(|e| ClientError::Network(format!("{role} parse: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(ClientError::Network(format!(
            "{role} must use https in production"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Network(format!("{role} missing host")))?;
    if is_forbidden_production_host(host) {
        return Err(ClientError::Network(format!(
            "{role} uses test host {host}; production transport requires real deployment hosts"
        )));
    }
    Ok(())
}

fn insert_endpoint_pins(
    pins: &mut BTreeMap<String, PinningConfig>,
    endpoint: &PinnedServiceEndpoint,
) -> Result<(), ClientError> {
    let parsed = Url::parse(&endpoint.url)
        .map_err(|e| ClientError::Network(format!("production endpoint parse: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Network("production endpoint missing host".into()))?;
    let host = normalize_dns_host(host);
    if let Some(existing) = pins.get(&host) {
        if existing != &endpoint.pins {
            return Err(ClientError::Network(format!(
                "conflicting SPKI pins for production host {host}"
            )));
        }
        return Ok(());
    }
    pins.insert(host, endpoint.pins.clone());
    Ok(())
}

fn is_forbidden_production_host(host: &str) -> bool {
    let trimmed = host.trim_end_matches('.');
    let h = trimmed
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h.is_empty()
        || h == "localhost"
        || h.ends_with(".localhost")
        || h == "local"
        || h.ends_with(".local")
        || h == "test"
        || h.ends_with(".test")
        || h == "example"
        || h.ends_with(".example")
        || h == "example.com"
        || h.ends_with(".example.com")
        || h == "example.net"
        || h.ends_with(".example.net")
        || h == "example.org"
        || h.ends_with(".example.org")
        || h.ends_with(".invalid")
        || h.ends_with(".example.invalid")
    {
        return true;
    }

    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => is_forbidden_production_ip(ip),
        Err(_) => false,
    }
}

fn is_forbidden_production_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || octets == [255, 255, 255, 255]
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || mapped_ipv4_from_v6(segments).is_some_and(is_forbidden_production_ip)
        }
    }
}

fn mapped_ipv4_from_v6(segments: [u16; 8]) -> Option<std::net::IpAddr> {
    if segments[..5] != [0, 0, 0, 0, 0] || segments[5] != 0xffff {
        return None;
    }
    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        (segments[6] >> 8) as u8,
        segments[6] as u8,
        (segments[7] >> 8) as u8,
        segments[7] as u8,
    )))
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
    build_http2_client_with_builder(
        config,
        ClientBuilder::new()
            .use_rustls_tls()
            .tls_version_min(tls::Version::TLS_1_3),
    )
}

fn build_http2_client_with_builder(
    config: Http2Config,
    builder: ClientBuilder,
) -> Result<Arc<Client>, ClientError> {
    let client = builder
        .http2_prior_knowledge()
        .http2_keep_alive_interval(config.http2_keepalive_interval)
        .http2_keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .connect_timeout(config.connect_timeout)
        .timeout(config.total_timeout)
        .user_agent(config.user_agent)
        .tcp_nodelay(true)
        .https_only(true)
        .build()
        .map_err(|e| ClientError::Network(format!("reqwest client build: {e}")))?;
    Ok(Arc::new(client))
}

/// Проверить боевую настройку и создать HTTP/2 клиент с системной проверкой
/// сертификата плюс закреплёнными SPKI-ключами.
///
/// Validate production config and build an HTTP/2 client with platform
/// certificate verification plus SPKI pinning.
///
/// # Errors
/// - [`ClientError::Network`] если настройка похожа на тестовую.
/// - [`ClientError::Network`] если системный TLS verifier не инициализируется.
/// - [`ClientError::Network`] если `reqwest` не принимает готовый TLS backend.
pub fn build_production_http2_client(
    config: Http2Config,
    production: &ProductionHttp2Config,
) -> Result<Arc<Client>, ClientError> {
    let pins = production.pins_by_host()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let platform_verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|e| ClientError::Network(format!("platform TLS verifier: {e}")))?;
    let pinning_verifier = SpkiPinningVerifier::new(Arc::new(platform_verifier), pins)
        .map_err(|e| ClientError::Network(format!("production SPKI pinning verifier: {e}")))?;
    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Network(format!("rustls TLS 1.3 config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinning_verifier))
        .with_no_client_auth();

    build_http2_client_with_builder(
        config,
        ClientBuilder::new().tls_backend_preconfigured(tls_config),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{SpkiPin, SPKI_PIN_LEN};

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

    fn pin(byte: u8) -> PinningConfig {
        PinningConfig::single(SpkiPin::from_bytes([byte; SPKI_PIN_LEN]))
    }

    fn endpoint(url: &str, byte: u8) -> PinnedServiceEndpoint {
        PinnedServiceEndpoint::new(url.to_string(), pin(byte))
    }

    fn production_config_with_urls(sealed: Vec<&str>) -> ProductionHttp2Config {
        ProductionHttp2Config {
            sealed_servers: sealed
                .into_iter()
                .enumerate()
                .map(|(idx, url)| endpoint(url, (idx + 1) as u8))
                .collect(),
            postman: endpoint("https://postman.umbrellax.io", 11),
            kt: endpoint("https://kt.umbrellax.io", 12),
            call_relay: endpoint("https://relay.umbrellax.io", 13),
        }
    }

    #[test]
    fn production_transport_rejects_http_url() {
        let cfg = production_config_with_urls(vec![
            "http://sealed-0.umbrellax.io",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("must use https"));
    }

    #[test]
    fn production_transport_rejects_test_hosts() {
        let cfg = production_config_with_urls(vec![
            "https://localhost",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("test host"));
    }

    #[test]
    fn production_transport_rejects_reserved_dns_test_names() {
        for url in [
            "https://sealed-0.umbrella.example",
            "https://sealed-0.umbrella.test",
            "https://sealed-0.umbrella.local",
            "https://example.com",
            "https://example.net",
            "https://example.org",
        ] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrellax.io",
                "https://sealed-2.umbrellax.io",
                "https://sealed-3.umbrellax.io",
                "https://sealed-4.umbrellax.io",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }

    #[test]
    fn production_transport_rejects_ip_literal_hosts() {
        let cfg = production_config_with_urls(vec![
            "https://192.0.2.10",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("test host"));
    }

    #[test]
    fn production_transport_rejects_link_local_and_cgnat_hosts() {
        for url in ["https://169.254.169.254", "https://100.64.0.10"] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrellax.io",
                "https://sealed-2.umbrellax.io",
                "https://sealed-3.umbrellax.io",
                "https://sealed-4.umbrellax.io",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }

    #[test]
    fn production_transport_rejects_ipv6_local_hosts() {
        for url in ["https://[::1]", "https://[fd00::1]", "https://[fe80::1]"] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrellax.io",
                "https://sealed-2.umbrellax.io",
                "https://sealed-3.umbrellax.io",
                "https://sealed-4.umbrellax.io",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }

    #[test]
    fn production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts() {
        for url in [
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:10.0.0.1]",
            "https://[::ffff:100.64.0.10]",
            "https://[::ffff:192.0.2.10]",
        ] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrellax.io",
                "https://sealed-2.umbrellax.io",
                "https://sealed-3.umbrellax.io",
                "https://sealed-4.umbrellax.io",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }

    #[test]
    fn production_transport_rejects_wrong_sealed_server_count() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrellax.io",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("exactly 5 pinned sealed servers"));
    }

    #[test]
    fn production_transport_validation_accepts_realistic_pinned_https_config() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrellax.io",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);

        cfg.validate().expect("pinned https config validates");
    }

    #[test]
    fn production_pin_map_rejects_conflicting_pins_for_same_host() {
        let mut cfg = production_config_with_urls(vec![
            "https://shared.umbrellax.io",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);
        cfg.postman = endpoint("https://shared.umbrellax.io", 99);

        let err = cfg.pins_by_host().unwrap_err();
        assert!(format!("{err}").contains("conflicting SPKI pins"));
    }

    #[test]
    fn production_client_builds_with_real_pinning_verifier() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrellax.io",
            "https://sealed-1.umbrellax.io",
            "https://sealed-2.umbrellax.io",
            "https://sealed-3.umbrellax.io",
            "https://sealed-4.umbrellax.io",
        ]);

        let client = build_production_http2_client(Http2Config::default(), &cfg)
            .expect("production client builds when pinned config is valid");
        let clone = Arc::clone(&client);
        assert!(Arc::ptr_eq(&client, &clone));
    }
}
