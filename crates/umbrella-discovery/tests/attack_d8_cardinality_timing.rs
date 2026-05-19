//! D-8 regression: measure intersection-cardinality side-channel leak.
//!
//! D-8 атака: измерение side-channel leak через intersection-cardinality.
//!
//! ## Attack model
//!
//! Адверсарь видит latency полного round-trip discovery (request → response →
//! intersection). Hypothesis: интерсекшен размером 0 vs 1 vs 500 имеет
//! distinguishable latency, что leak'ит cardinality.
//!
//! ## Defense
//!
//! Constant-time intersection: цикл по client labels проверяет membership в
//! HashMap; HashMap lookup ~ O(1) для каждого, total ~ O(N_client). NOT
//! зависит от intersection size — зависит от N_client (запроса) only. Это
//! "padding"-style invariance.
//!
//! Однако: hash-table internal probing IS data-dependent. Реальная защита
//! — query padding to fixed N (т.е. адресная книга паддится до 500 contacts
//! даже если меньше). Это policy в `docs/spec/discovery-integration.md`.
//!
//! ## Acceptance criterion
//!
//! Measure cardinality-leak: 0, 50, 250, 500 intersection sizes (N_client=500
//! fixed) → measure intersection time. Документируем relative variance.
//!
//! Note: на macOS dev host цифры реальные, не cryptographically-bounded;
//! production пользует dudect-style верификацию (out of scope этого test
//! — covered round 2 для OPRF blind/unblind hot path).

use rand_core::OsRng;
use std::collections::HashSet;
use std::time::Instant;
use umbrella_discovery::{intersect_with_server_table, simulate_server_table};
use umbrella_oprf::{
    blind, finalize, generate_test_private_key, BlindedRequest, OprfInput, OprfLabel,
};

fn make_client_labels(master_sk: &[u8; 32], contacts: &[&[u8]]) -> Vec<OprfLabel> {
    contacts
        .iter()
        .map(|c| {
            let inp = OprfInput::new(c).unwrap();
            let (req, state) = blind(inp, &mut OsRng).unwrap();
            let eval = umbrella_oprf::evaluate_for_testing(&req, master_sk).unwrap();
            let _ = BlindedRequest::from_bytes(req.as_bytes()).unwrap();
            finalize(&state, inp, &eval).unwrap()
        })
        .collect()
}

#[test]
fn d8_attack_cardinality_timing_measured_and_bounded() {
    // Fixed N_client = 500 contacts; vary intersection size 0/50/250/500.
    let master_sk = generate_test_private_key(&mut OsRng);
    let n_client = 500;
    let client_contacts: Vec<String> = (0..n_client).map(|i| format!("+1212555{i:04}")).collect();
    let client_refs: Vec<&[u8]> = client_contacts.iter().map(|s| s.as_bytes()).collect();

    let client_labels = make_client_labels(&master_sk, &client_refs);

    // Делаем 4 server-таблицы:
    // - 0 of 500 в intersection (server table = другие phones).
    // - 50 of 500 (первые 50 client contacts present).
    // - 250 of 500.
    // - 500 of 500 (все present).
    let other_phones: Vec<String> = (0..1000).map(|i| format!("+9019999{i:04}")).collect();
    let other_refs: Vec<&[u8]> = other_phones.iter().map(|s| s.as_bytes()).collect();

    let mk_table = |overlap: usize| -> HashSet<[u8; 32]> {
        let mut all: Vec<&[u8]> = other_refs.clone();
        all.extend_from_slice(&client_refs[..overlap]);
        let table = simulate_server_table(&master_sk, &all).unwrap();
        table.keys().copied().collect()
    };

    let cases = [0usize, 50, 250, 500];
    let mut timings_ns: Vec<(usize, u128)> = Vec::new();
    for &c in &cases {
        let table = mk_table(c);
        // Warm-up.
        for _ in 0..3 {
            let _ = intersect_with_server_table(&client_labels, &table);
        }
        let t0 = Instant::now();
        let iters = 100u32;
        for _ in 0..iters {
            let _ = intersect_with_server_table(&client_labels, &table);
        }
        let avg = t0.elapsed().as_nanos() / iters as u128;
        timings_ns.push((c, avg));
    }

    eprintln!("D-8 intersection cardinality timing measurements (n_client=500):");
    for (c, ns) in &timings_ns {
        eprintln!("  intersection_size={c:>3}  avg_ns={ns}");
    }

    // Документируем: variance acceptable пока в пределах same order of magnitude.
    let min_ns = timings_ns.iter().map(|(_, n)| *n).min().unwrap();
    let max_ns = timings_ns.iter().map(|(_, n)| *n).max().unwrap();
    let ratio = max_ns as f64 / min_ns.max(1) as f64;
    eprintln!("D-8 timing min={min_ns}ns max={max_ns}ns ratio={ratio:.2}");

    // Сам тест passing: ratio < 5x. Если ratio становится huge, мы видим
    // side-channel; в данном HashSet implementation ratio ~ 1.0-1.5x.
    assert!(
        ratio < 5.0,
        "D-8 cardinality side-channel: ratio={ratio:.2} > 5x — investigate"
    );

    // Также проверяем: result correctness — что intersection cardinality
    // правильная для каждого случая.
    for &c in &cases {
        let table = mk_table(c);
        let inter = intersect_with_server_table(&client_labels, &table);
        assert_eq!(inter.len(), c);
    }
}

#[test]
fn d8_attack_zero_overlap_correctness() {
    // Edge case: 0 overlap → intersection empty.
    let master_sk = generate_test_private_key(&mut OsRng);
    let client_refs: Vec<&[u8]> = vec![b"+11111111111", b"+22222222222"];
    let server_refs: Vec<&[u8]> = vec![b"+33333333333", b"+44444444444"];
    let client_labels = make_client_labels(&master_sk, &client_refs);
    let table = simulate_server_table(&master_sk, &server_refs).unwrap();
    let keys: HashSet<[u8; 32]> = table.keys().copied().collect();
    let inter = intersect_with_server_table(&client_labels, &keys);
    assert_eq!(inter.len(), 0);
}

#[test]
fn d8_attack_full_overlap_correctness() {
    // Edge case: 100% overlap → intersection.len() == N_client.
    let master_sk = generate_test_private_key(&mut OsRng);
    let phones: Vec<String> = (0..50).map(|i| format!("+1{i:010}")).collect();
    let refs: Vec<&[u8]> = phones.iter().map(|s| s.as_bytes()).collect();
    let client_labels = make_client_labels(&master_sk, &refs);
    let table = simulate_server_table(&master_sk, &refs).unwrap();
    let keys: HashSet<[u8; 32]> = table.keys().copied().collect();
    let inter = intersect_with_server_table(&client_labels, &keys);
    assert_eq!(inter.len(), 50);
}
