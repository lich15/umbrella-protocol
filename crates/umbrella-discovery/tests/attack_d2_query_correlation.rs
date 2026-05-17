//! D-2 regression: server cannot correlate @username queries from the same
//! client across time without master_key.
//!
//! D-2 атака: сервер не может корреллировать @username queries одного клиента
//! без master_key.
//!
//! ## Attack model
//!
//! - Adversary controls 1 of 5 servers (eg. server #2). Sees все anon_id это
//!   server увидел за день (~10K queries from many users).
//! - Adversary хочет вернуть: "среди этих 10K queries, какие N запросов
//!   принадлежат пользователю Alice?"
//!
//! ## Defense
//!
//! Per-query anon_id = HKDF(master_key, server_id, salt). Salt fresh per
//! query → каждый запрос Alice производит distinct anon_id с overwhelming
//! probability (2^256 collision space).
//!
//! ## Acceptance criterion
//!
//! 1000 queries из одного master_key → 1000 distinct anon_ids, 0 collisions.
//! Это measurable как обычный HashSet test.

use rand_core::OsRng;
use std::collections::HashSet;

use umbrella_discovery::prepare_username_query;

#[test]
fn d2_attack_1000_username_queries_zero_correlations() {
    // Adversary controlling server 1 видит anon_id каждого запроса.
    // Если он сможет linkify два anon_id к одному клиенту, атака удалась.
    let mk = [0xDEu8; 32];
    let handle = b"@alice";
    let mut seen_anon_ids = HashSet::new();
    let mut seen_blinded = HashSet::new();
    let mut seen_nonces = HashSet::new();

    for i in 0..1000 {
        let (req, _state) = prepare_username_query(&mk, handle, 1, &mut OsRng).unwrap();
        assert!(
            seen_anon_ids.insert(req.anon_id),
            "ANON_ID COLLISION at query {i}: linkability achievable"
        );
        // Blinded должно тоже быть unique (random r каждый раз).
        assert!(
            seen_blinded.insert(req.blinded),
            "BLINDED COLLISION at query {i}"
        );
        // Client nonce должны быть unique.
        assert!(
            seen_nonces.insert(req.client_nonce),
            "CLIENT_NONCE COLLISION at query {i}"
        );
    }
    assert_eq!(seen_anon_ids.len(), 1000);
    assert_eq!(seen_blinded.len(), 1000);
    assert_eq!(seen_nonces.len(), 1000);
}

#[test]
fn d2_attack_cross_server_correlation_impossible_without_master_key() {
    // Adversary controlling 2 servers (1 и 3) видит:
    // - anon_id_1 = HKDF(MK, 1, salt) от server 1.
    // - anon_id_3 = HKDF(MK, 3, salt) от server 3.
    // Чтобы корреллировать "anon_id_1 на server 1 = anon_id_3 на server 3 от
    // одного клиента", нужен MK.
    //
    // Проверка: anon_id_1 и anon_id_3 имеют 0 informational overlap по
    // bit-correlation (тестируем что они разные и независимые).
    let mk = [0xAFu8; 32];
    let handle = b"@bob";

    let mut anons_srv1 = Vec::new();
    let mut anons_srv3 = Vec::new();
    for _ in 0..500 {
        let (req1, _) = prepare_username_query(&mk, handle, 1, &mut OsRng).unwrap();
        let (req3, _) = prepare_username_query(&mk, handle, 3, &mut OsRng).unwrap();
        anons_srv1.push(req1.anon_id);
        anons_srv3.push(req3.anon_id);
    }
    // Все 500 srv1 anon_ids distinct.
    let srv1_set: HashSet<_> = anons_srv1.iter().copied().collect();
    let srv3_set: HashSet<_> = anons_srv3.iter().copied().collect();
    assert_eq!(srv1_set.len(), 500);
    assert_eq!(srv3_set.len(), 500);
    // Пересечение между srv1 и srv3 — пустое.
    let cross: HashSet<_> = srv1_set.intersection(&srv3_set).collect();
    assert_eq!(cross.len(), 0, "cross-server anon_id overlap detected");
}

#[test]
fn d2_attack_different_clients_yield_distinct_anon_ids() {
    // Adversary видит anon_id и хочет понять: один ли это клиент с
    // разными query, или разные клиенты. Без MK не различимо by design.
    let mk_alice = [0x11u8; 32];
    let mk_bob = [0x22u8; 32];
    let handle = b"@target";

    let (req_a, _) = prepare_username_query(&mk_alice, handle, 1, &mut OsRng).unwrap();
    let (req_b, _) = prepare_username_query(&mk_bob, handle, 1, &mut OsRng).unwrap();
    assert_ne!(
        req_a.anon_id, req_b.anon_id,
        "two different clients produced same anon_id — MK leakage"
    );
}
