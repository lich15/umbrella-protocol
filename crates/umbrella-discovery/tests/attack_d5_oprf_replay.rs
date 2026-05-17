//! D-5 regression: capture a server response and replay it; protected by
//! per-request server nonce + replay guard.
//!
//! D-5 атака: захват server response → replay; защита через server nonce +
//! replay guard на стороне клиента.
//!
//! ## Attack model
//!
//! Adversary records a PsiResponse byte trace (containing server_nonce и
//! transcript_tag). Затем повторяет к другому клиенту OR к тому же клиенту
//! в другую query. Ожидается отказ:
//! - Если new query — server_nonce уже в client's NonceReplayGuard → reject.
//! - Сервер сам отказывается принимать replay через свой nonce log (вне
//!   нашего скоупа, описано в backend spec).
//!
//! ## Defense
//!
//! `NonceReplayGuard`: rolling window 1000 nonces. Регистрация duplicate
//! nonce → `DiscoveryError::ReplayDetected`.

use rand_core::OsRng;
use rand_core::RngCore;
use umbrella_discovery::{DiscoveryError, NonceReplayGuard, SERVER_NONCE_LEN};

#[test]
fn d5_attack_replay_same_server_nonce_rejected() {
    let mut guard = NonceReplayGuard::new();
    let mut captured_nonce = [0u8; SERVER_NONCE_LEN];
    OsRng.fill_bytes(&mut captured_nonce);

    // First time: фиксируется.
    guard.register(&captured_nonce).unwrap();
    // Replay: detected.
    let err = guard.register(&captured_nonce).unwrap_err();
    assert!(matches!(err, DiscoveryError::ReplayDetected));
}

#[test]
fn d5_attack_replay_within_1000_query_window() {
    // Адверсарь captured nonce, ждёт пока клиент выполнит ещё 50 query,
    // затем replays. Должен быть отказ — nonce ещё в окне.
    let mut guard = NonceReplayGuard::new();
    let mut captured_nonce = [0u8; SERVER_NONCE_LEN];
    OsRng.fill_bytes(&mut captured_nonce);
    guard.register(&captured_nonce).unwrap();
    // Adversary triggers 50 legit queries в between.
    for _ in 0..50 {
        let mut n = [0u8; SERVER_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        guard.register(&n).unwrap();
    }
    let err = guard.register(&captured_nonce).unwrap_err();
    assert!(matches!(err, DiscoveryError::ReplayDetected));
}

#[test]
fn d5_attack_replay_after_window_eviction_passes_but_protocol_still_safe() {
    // Если adversary ждёт пока nonce evict из окна (1000+ новых query), он
    // может зарегистрировать его снова. Но: server-side nonce log (out of
    // scope этого крейта; в backend spec) дублирующе блокирует. Здесь
    // показываем что client-side window работает в expected пределах.
    let mut guard = NonceReplayGuard::with_capacity(100); // small for fast test
    let mut captured = [0u8; SERVER_NONCE_LEN];
    OsRng.fill_bytes(&mut captured);
    guard.register(&captured).unwrap();
    // 100 новых: вытесняет captured.
    for _ in 0..100 {
        let mut n = [0u8; SERVER_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        guard.register(&n).unwrap();
    }
    // Replay now passes на клиенте (но в реальности backend сам отказывает).
    // Documenting this boundary — это test что граница работает как заявлено.
    let result = guard.register(&captured);
    assert!(
        result.is_ok(),
        "client-side replay guard correctly evicts old nonces; server-side independently filters via its own nonce log"
    );
}

#[test]
fn d5_attack_distinct_nonces_all_accepted() {
    // Sanity: 100 distinct nonces всё проходят.
    let mut guard = NonceReplayGuard::new();
    for _ in 0..100 {
        let mut n = [0u8; SERVER_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        guard.register(&n).unwrap();
    }
    assert_eq!(guard.current_size(), 100);
}

#[test]
fn d5_attack_concurrent_query_distinct_nonces() {
    // Если два sibling-устройства одновременно отправляют запросы с разным
    // client_nonce, никакой переплет не возникает.
    let mut guard = NonceReplayGuard::new();
    let mut n1 = [0u8; SERVER_NONCE_LEN];
    let mut n2 = [0u8; SERVER_NONCE_LEN];
    OsRng.fill_bytes(&mut n1);
    OsRng.fill_bytes(&mut n2);
    assert_ne!(n1, n2);
    guard.register(&n1).unwrap();
    guard.register(&n2).unwrap();
}
