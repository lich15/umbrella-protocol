//! Realistic PSI scenario: 500 client contacts vs 1M registered users.
//!
//! Run: `cargo run --release --example psi_realistic_scenario`
//!
//! Reports:
//! - intersection size (random subset of 500 ∩ 1M),
//! - request wire size,
//! - response wire size,
//! - end-to-end wall-clock time on the local host.

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use std::collections::HashSet;
use std::time::Instant;
use umbrella_discovery::{
    finalize_psi_query, intersect_with_server_table, prepare_psi_query, psi_server_respond,
    simulate_server_table,
};
use umbrella_oprf::{
    generate_test_private_key, shamir_split_for_testing, ThresholdConfig, WitnessIndex,
};

fn main() {
    let n_client = 500;
    let n_registered = 1_000_000;
    let n_overlap = 73; // random но deterministic

    println!("[D-8 realistic] preparing 5-of-3 sealed-server cluster + master OPRF key...");
    let master_sk = generate_test_private_key(&mut OsRng);
    let k = Scalar::from_canonical_bytes(master_sk).unwrap();
    let cfg = ThresholdConfig::default();
    let raw = shamir_split_for_testing(k, cfg, &mut OsRng);
    let shares: Vec<(WitnessIndex, [u8; 32])> =
        raw.iter().map(|(wi, s)| (*wi, s.to_bytes())).collect();

    let mk = [0x42u8; 32];

    println!("[psi-realistic] building {n_client} client contacts...");
    let client_phones: Vec<String> = (0..n_client).map(|i| format!("+1212{i:07}")).collect();
    let client_refs: Vec<&[u8]> = client_phones.iter().map(|s| s.as_bytes()).collect();

    println!("[psi-realistic] building {n_registered} registered users (slow)...");
    let mut registered = Vec::with_capacity(n_registered);
    for i in 0..n_registered {
        if i < n_overlap {
            registered.push(format!("+1212{i:07}")); // первые `n_overlap` == client overlap
        } else {
            registered.push(format!("+9999{i:07}"));
        }
    }
    let reg_refs: Vec<&[u8]> = registered.iter().map(|s| s.as_bytes()).collect();

    println!("[psi-realistic] computing server table (1M OPRF labels, slow)...");
    let t0 = Instant::now();
    let table = simulate_server_table(&master_sk, &reg_refs).unwrap();
    let server_table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();
    println!(
        "[psi-realistic] server table built in {:.2}s ({} entries)",
        t0.elapsed().as_secs_f64(),
        server_table_keys.len()
    );

    println!("[psi-realistic] client → blind 500 contacts...");
    let t1 = Instant::now();
    let (req, state) = prepare_psi_query(&mk, &client_refs, 1, &mut OsRng).unwrap();
    println!(
        "[psi-realistic] prepare_psi_query: {:.3}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );
    let req_wire = req.encode();
    println!(
        "[psi-realistic] PSI request wire size: {} bytes",
        req_wire.len()
    );

    println!("[psi-realistic] 3 of 5 sealed servers evaluate each blinded request...");
    let mut responses = Vec::new();
    let t2 = Instant::now();
    for &(wi, sk) in shares.iter().take(3) {
        let resp = psi_server_respond(&req, &sk, &mut OsRng).unwrap();
        let wire = resp.encode();
        println!(
            "[psi-realistic]   server #{} response wire size: {} bytes",
            wi.get(),
            wire.len()
        );
        responses.push((wi, resp));
    }
    println!(
        "[psi-realistic] all 3 server evaluations: {:.3}ms",
        t2.elapsed().as_secs_f64() * 1000.0
    );

    println!("[psi-realistic] client threshold-combine + finalize 500 labels...");
    let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();
    let t3 = Instant::now();
    let labels = finalize_psi_query(&state, &resp_refs, ThresholdConfig::default()).unwrap();
    println!(
        "[psi-realistic] finalize_psi_query: {:.3}ms",
        t3.elapsed().as_secs_f64() * 1000.0
    );

    println!("[psi-realistic] intersection with server table...");
    let t4 = Instant::now();
    let intersection = intersect_with_server_table(&labels, &server_table_keys);
    println!(
        "[psi-realistic] intersect: {:.3}ms",
        t4.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "[psi-realistic] intersection size: {} (expected: {n_overlap})",
        intersection.len()
    );
    assert_eq!(intersection.len(), n_overlap);

    println!(
        "[psi-realistic] DONE — total {:.2}s",
        t0.elapsed().as_secs_f64()
    );
}
