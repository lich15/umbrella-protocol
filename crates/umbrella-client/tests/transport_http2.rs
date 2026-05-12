//! Integration-тесты HTTP/2 транспорт-слоя `umbrella-client` через `wiremock`.
//!
//! **Замечание про HTTP/2.** Wiremock по умолчанию — HTTP/1.1 без TLS; наш
//! production `Http2Config` настроен на `http2_prior_knowledge()` + TLS 1.3.
//! Чтобы эти smoke-тесты могли разговаривать с mock server'ом, каждый тест
//! строит минимальный `reqwest::Client::new()` вручную (без prior-knowledge
//! HTTP/2), а `Http2Config::default` покрыт unit-тестами в
//! `transport::http2_client::tests` (crate-level).
//!
//! Integration tests of the HTTP/2 transport layer via `wiremock`. Note: the
//! mock server is HTTP/1.1, so each test builds a plain `reqwest::Client::new()`
//! locally; default `Http2Config` is exercised by unit tests in the crate.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use umbrella_backup::cloud_wrap::params::WitnessIndex;
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::signed_request::{PlatformAttestation, SignedUnwrapRequest};
use umbrella_backup::cloud_wrap::wire::ED25519_PUB_LEN;
use umbrella_backup::cloud_wrap::Platform;
use umbrella_client::transport::{
    AsyncUnwrapTransport, CallSecurityLevelWire, Http2CallRelayTransport, Http2KtTransport,
    Http2PostmanTransport, Http2UnwrapTransport,
};
use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_client() -> Arc<reqwest::Client> {
    Arc::new(reqwest::Client::new())
}

fn mock_url(server: &MockServer) -> Url {
    Url::parse(&server.uri()).expect("wiremock URI must be parseable")
}

fn make_share(witness_index: u8, fill: u8) -> ServerUnwrapShare {
    ServerUnwrapShare {
        witness_index: WitnessIndex::new(witness_index).expect("valid witness index"),
        partial: [fill; 32],
    }
}

fn make_signed_request() -> SignedUnwrapRequest {
    SignedUnwrapRequest {
        ephemeral_r: [0x0A; 32],
        chat_id: [0x0B; 32],
        recipient_device_pubkey: [0x0C; ED25519_PUB_LEN],
        timestamp_unix_millis: 1_700_000_000_000,
        server_nonce: [0x0D; 32],
        attestation: PlatformAttestation::new(Platform::Testing, b"test-token")
            .expect("valid token"),
        device_signature: [0x0E; 64],
        device_pubkey: [0x0F; ED25519_PUB_LEN],
    }
}

// ---------------------------------------------------------------------------
// Http2PostmanTransport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn postman_deliver_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/deliver"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let postman = Http2PostmanTransport::new(test_client(), mock_url(&server));
    postman.deliver(b"envelope bytes".to_vec()).await.unwrap();
}

#[tokio::test]
async fn postman_deliver_5xx_is_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/deliver"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let postman = Http2PostmanTransport::new(test_client(), mock_url(&server));
    let err = postman.deliver(b"x".to_vec()).await.unwrap_err();
    assert!(format!("{err}").contains("503"));
}

#[tokio::test]
async fn postman_fetch_inbox_parses_length_prefixed() {
    let server = MockServer::start().await;
    let mut body = Vec::new();
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");
    body.extend_from_slice(&3u32.to_be_bytes());
    body.extend_from_slice(b"bye");
    Mock::given(method("GET"))
        .and(path("/inbox"))
        .and(query_param("since", "42"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;
    let postman = Http2PostmanTransport::new(test_client(), mock_url(&server));
    let envelopes = postman.fetch_inbox(42).await.unwrap();
    assert_eq!(envelopes, vec![b"hello".to_vec(), b"bye".to_vec()]);
}

#[tokio::test]
async fn postman_ack_uses_delete_method() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/inbox/[0-9a-f]{32}$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let postman = Http2PostmanTransport::new(test_client(), mock_url(&server));
    postman
        .ack([0xAB; 16])
        .await
        .expect("DELETE should succeed");
}

// ---------------------------------------------------------------------------
// Http2KtTransport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kt_transport_fetch_epoch_returns_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/kt/account/[0-9a-f]{64}/epoch/7$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"epoch-body".to_vec()))
        .mount(&server)
        .await;
    let kt = Http2KtTransport::new(test_client(), mock_url(&server));
    let bytes = kt.fetch_epoch(&[0x12; 32], 7).await.unwrap();
    assert_eq!(bytes, b"epoch-body");
}

#[tokio::test]
async fn kt_transport_fetch_signed_roots_parses_five_frames() {
    let server = MockServer::start().await;
    let mut body = Vec::new();
    for i in 0u8..5 {
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&[i, i, i, i]);
    }
    Mock::given(method("GET"))
        .and(path("/kt/signed-roots/13"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;
    let kt = Http2KtTransport::new(test_client(), mock_url(&server));
    let roots = kt.fetch_signed_roots(13).await.unwrap();
    assert_eq!(roots.len(), 5);
    assert_eq!(roots[0], vec![0u8, 0, 0, 0]);
    assert_eq!(roots[4], vec![4u8, 4, 4, 4]);
}

#[tokio::test]
async fn kt_transport_publish_posts_entry_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kt/publish"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let kt = Http2KtTransport::new(test_client(), mock_url(&server));
    kt.publish(vec![1, 2, 3, 4]).await.unwrap();
}

// ---------------------------------------------------------------------------
// Http2CallRelayTransport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn call_relay_allocate_parses_json() {
    let server = MockServer::start().await;
    let body = r#"{
        "primary_url": "turns:relay1.example:5349",
        "secondary_url": null,
        "username": "1700:peer_dead",
        "password_hmac_hex": "aa",
        "valid_until_ms": 1700000000000
    }"#;
    Mock::given(method("POST"))
        .and(path("/turn/allocate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;
    let relay = Http2CallRelayTransport::new(test_client(), mock_url(&server));
    let allocation = relay
        .allocate([0xDE; 32], CallSecurityLevelWire::Sensitive)
        .await
        .unwrap();
    assert_eq!(allocation.primary_url, "turns:relay1.example:5349");
    assert!(allocation.secondary_url.is_none());
    assert_eq!(allocation.valid_until_ms, 1_700_000_000_000);
}

#[tokio::test]
async fn call_relay_allocate_propagates_4xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/turn/allocate"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let relay = Http2CallRelayTransport::new(test_client(), mock_url(&server));
    let err = relay
        .allocate([0; 32], CallSecurityLevelWire::Default)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("429"));
}

// ---------------------------------------------------------------------------
// Http2UnwrapTransport — fan-out 3-of-5 scenarios
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unwrap_fanout_happy_collects_three_shares_and_early_returns() {
    // Каждый из 5 серверов возвращает свой валидный share.
    // Early-return при ≥ 3 — возможно собрали больше 3, но мы проверяем только ≥ 3.
    let servers: Vec<MockServer> = futures_lite_spawn(5).await;

    for (idx, srv) in servers.iter().enumerate() {
        let witness_idx = (idx + 1) as u8;
        let share_bytes = make_share(witness_idx, 0xA0 | witness_idx)
            .to_bytes()
            .to_vec();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(share_bytes))
            .mount(srv)
            .await;
    }

    let urls = urls_of(&servers);
    let transport = Http2UnwrapTransport::new(test_client(), urls);

    let shares = transport
        .dispatch(&make_signed_request(), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        shares.len() >= 3 && shares.len() <= 5,
        "expected 3..=5 shares, got {}",
        shares.len()
    );
    // Проверить что собраны без дубликатов witness_index.
    let mut indices: Vec<u8> = shares.iter().map(|s| s.witness_index.get()).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices.len(), shares.len(), "no duplicate witness indices");
    for idx in &indices {
        assert!(*idx >= 1 && *idx <= 5);
    }
}

#[tokio::test]
async fn unwrap_fanout_all_servers_fail_returns_empty() {
    let servers: Vec<MockServer> = futures_lite_spawn(5).await;
    for srv in &servers {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(srv)
            .await;
    }
    let urls = urls_of(&servers);
    let transport = Http2UnwrapTransport::new(test_client(), urls);
    let shares = transport
        .dispatch(&make_signed_request(), Duration::from_millis(500))
        .await
        .unwrap();
    assert!(
        shares.is_empty(),
        "5×500 → zero shares, got {}",
        shares.len()
    );
}

#[tokio::test]
async fn unwrap_fanout_server_returning_wrong_witness_index_is_dropped() {
    let servers: Vec<MockServer> = futures_lite_spawn(5).await;
    // Server #1 возвращает share с witness_index=2 (вместо ожидаемого 1) — drop.
    // Servers #2..=5 — OK.
    for (idx, srv) in servers.iter().enumerate() {
        let witness_idx = (idx + 1) as u8;
        let returned_idx = if idx == 0 { 2u8 } else { witness_idx };
        let share = make_share(returned_idx, 0xB0);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(share.to_bytes().to_vec()))
            .mount(srv)
            .await;
    }
    let urls = urls_of(&servers);
    let transport = Http2UnwrapTransport::new(test_client(), urls);
    let shares = transport
        .dispatch(&make_signed_request(), Duration::from_secs(2))
        .await
        .unwrap();
    // Валидных shares — 4 (server #1 отброшен), но early return при ≥3.
    // Server #2 вернул idx=2 с correct witness_idx=2 — accepted.
    // Итого коллизия witness_index=2 потенциально на server #1 (rejected) + server #2 (accepted)
    // → collected shares must have unique witness_idx from {2..=5}.
    assert!(
        shares.len() >= 3 && shares.len() <= 4,
        "expected 3..=4 shares (server #1 rejected), got {}",
        shares.len()
    );
    for s in &shares {
        let got = s.witness_index.get();
        assert!(
            (2..=5).contains(&got),
            "expected witness index 2..=5, got {got}"
        );
    }
}

#[tokio::test]
async fn unwrap_fanout_server_returning_malformed_body_is_dropped() {
    let servers: Vec<MockServer> = futures_lite_spawn(5).await;
    // Server #1 возвращает gibberish (не-33-byte body) — drop.
    for (idx, srv) in servers.iter().enumerate() {
        let body = if idx == 0 {
            b"garbage".to_vec() // too short for ServerUnwrapShare
        } else {
            make_share((idx + 1) as u8, 0xCC).to_bytes().to_vec()
        };
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(srv)
            .await;
    }
    let urls = urls_of(&servers);
    let transport = Http2UnwrapTransport::new(test_client(), urls);
    let shares = transport
        .dispatch(&make_signed_request(), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        shares.len() >= 3 && shares.len() <= 4,
        "expected 3..=4 shares (malformed #1 rejected), got {}",
        shares.len()
    );
    for s in &shares {
        assert_ne!(s.witness_index.get(), 1, "server #1 must be rejected");
    }
}

#[tokio::test]
async fn unwrap_fanout_respects_timeout_with_zero_valid_servers() {
    // Ни одного mock на серверах — все 5 запросов получают 404 wiremock default
    // ("no match" → 500). Timeout истекает, возвращается пустой Vec.
    let servers: Vec<MockServer> = futures_lite_spawn(5).await;
    // Intentionally no mocks mounted.
    let urls = urls_of(&servers);
    let transport = Http2UnwrapTransport::new(test_client(), urls);
    let start = std::time::Instant::now();
    let shares = transport
        .dispatch(&make_signed_request(), Duration::from_millis(200))
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(shares.is_empty());
    // Timeout primarily bounds top — проверяем что мы не блокировались "надолго".
    assert!(
        elapsed < Duration::from_secs(2),
        "dispatch took too long: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Стартует `n` независимых `wiremock::MockServer`. Простой utility без
/// `futures_lite` deps (name отражает паттерн "parallel spawn" несмотря на
/// последовательную реализацию — wiremock start'ы дешёвые).
///
/// Spawns `n` independent `wiremock::MockServer` instances. Simple utility
/// without `futures_lite` deps (name hints at a parallel-spawn pattern;
/// implementation is sequential since wiremock starts are cheap).
async fn futures_lite_spawn(n: usize) -> Vec<MockServer> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(MockServer::start().await);
    }
    out
}

fn urls_of(servers: &[MockServer]) -> [Url; 5] {
    assert_eq!(servers.len(), 5, "fan-out requires exactly 5 servers");
    [
        mock_url(&servers[0]),
        mock_url(&servers[1]),
        mock_url(&servers[2]),
        mock_url(&servers[3]),
        mock_url(&servers[4]),
    ]
}
