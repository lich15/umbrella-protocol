//! D-6 regression: anonymous-id reuse across queries must be impossible
//! by construction.
//!
//! D-6 атака: повторное использование anonymous-id между запросами должно
//! быть невозможно by construction.
//!
//! ## Attack model
//!
//! Buggy client implementation reuses salt → reuses anon_id → server can
//! correlate queries. Our derivation is deterministic from (master_key,
//! server_id, salt); so reuse comes from salt reuse.
//!
//! ## Defense
//!
//! `fresh_query_salt(rng)` всегда из CSPRNG (32 bytes). Любая two-distinct
//! query вызов автоматически имеет distinct salt → distinct anon_id.
//!
//! ## Acceptance criterion
//!
//! - 10000 calls to `fresh_query_salt` → all unique.
//! - High-volume `prepare_psi_query` + `prepare_username_query` → no anon_id
//!   collisions.

use rand_core::OsRng;
use std::collections::HashSet;
use umbrella_discovery::{
    derive_per_query_anon_id, fresh_query_salt, prepare_psi_query, prepare_username_query,
};

#[test]
fn d6_attack_10000_salts_zero_collisions() {
    let mut seen = HashSet::new();
    for i in 0..10000 {
        let salt = fresh_query_salt(&mut OsRng);
        assert!(seen.insert(salt), "salt collision at iteration {i}");
    }
    assert_eq!(seen.len(), 10000);
}

#[test]
fn d6_attack_anon_id_unique_under_10000_queries() {
    let mk = [0x42u8; 32];
    let mut seen = HashSet::new();
    for _ in 0..10000 {
        let salt = fresh_query_salt(&mut OsRng);
        let id = derive_per_query_anon_id(&mk, 1, &salt).unwrap();
        assert!(seen.insert(id), "anon_id collision at {} entries", seen.len());
    }
    assert_eq!(seen.len(), 10000);
}

#[test]
fn d6_attack_prepare_psi_query_no_anon_id_reuse_in_a_thousand_calls() {
    let mk = [0x42u8; 32];
    let phones: Vec<&[u8]> = vec![b"+12125551001"];
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let (req, _) = prepare_psi_query(&mk, &phones, 1, &mut OsRng).unwrap();
        let aid = req.entries[0].anon_id;
        assert!(seen.insert(aid), "anon_id reuse — invariant broken");
    }
    assert_eq!(seen.len(), 1000);
}

#[test]
fn d6_attack_prepare_username_query_no_anon_id_reuse_in_a_thousand_calls() {
    let mk = [0xDEu8; 32];
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let (req, _) = prepare_username_query(&mk, b"@alice", 1, &mut OsRng).unwrap();
        assert!(seen.insert(req.anon_id), "anon_id reuse");
    }
    assert_eq!(seen.len(), 1000);
}

#[test]
fn d6_attack_attempted_reuse_with_same_salt_still_distinct_per_server() {
    // Если каким-то образом два salt совпали (impossible 1 in 2^256), всё
    // равно anon_id на разные servers различаются.
    let mk = [0xAA; 32];
    let salt = [0x33u8; 32];
    let mut server_anons = HashSet::new();
    for sid in 1u16..=5 {
        let id = derive_per_query_anon_id(&mk, sid, &salt).unwrap();
        assert!(server_anons.insert(id));
    }
    assert_eq!(server_anons.len(), 5);
}

#[test]
fn d6_attack_master_key_recovery_from_anon_ids_infeasible() {
    // Adversary видит много anon_ids. Может ли recover master_key?
    // anon_id = HKDF-SHA-256(MK, info). HKDF is PRF — adversary не может
    // invert. Тест behavioral: показываем что anon_ids от разных MK
    // никак не корреллируют.
    let mk_a = [0x11; 32];
    let mk_b = [0x12; 32]; // близкий MK
    let salt = [0x99; 32];
    let id_a = derive_per_query_anon_id(&mk_a, 1, &salt).unwrap();
    let id_b = derive_per_query_anon_id(&mk_b, 1, &salt).unwrap();
    // anon_ids от близких MK выглядят полностью независимыми (avalanche).
    let mut common_bits = 0;
    for i in 0..32 {
        let xor = id_a[i] ^ id_b[i];
        common_bits += 8 - xor.count_ones();
    }
    // Avalanche: ~50% bits same. Допустим up to 75% common (statistical
    // headroom), но не 100%.
    assert!(
        common_bits < (32 * 8 * 75 / 100),
        "avalanche broken: {common_bits} common bits between similar MK anon_ids"
    );
}
