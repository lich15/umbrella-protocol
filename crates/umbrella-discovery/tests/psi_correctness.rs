//! Happy-path correctness test for the OPRF-PSI protocol end-to-end.
//!
//! Happy-path correctness test for OPRF-PSI end-to-end.

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use std::collections::HashSet;
use umbrella_discovery::{
    finalize_psi_query, intersect_with_server_table, prepare_psi_query, psi_server_respond,
    simulate_server_table,
};
use umbrella_oprf::{
    generate_test_private_key, shamir_split_for_testing, ThresholdConfig, WitnessIndex,
};

fn make_cluster() -> ([u8; 32], Vec<(WitnessIndex, [u8; 32])>) {
    let master_sk = generate_test_private_key(&mut OsRng);
    let k = Scalar::from_canonical_bytes(master_sk).unwrap();
    let cfg = ThresholdConfig::default();
    let raw = shamir_split_for_testing(k, cfg, &mut OsRng);
    let shares: Vec<_> = raw.iter().map(|(wi, s)| (*wi, s.to_bytes())).collect();
    (master_sk, shares)
}

#[test]
fn psi_correctness_50_vs_500_intersection_120_works() {
    // 50 client contacts; 500 registered; first 30 are common.
    let (master_sk, shares) = make_cluster();
    let mk = [0x42u8; 32];

    let client_contacts: Vec<String> = (0..50).map(|i| format!("+1212555{i:04}")).collect();
    let client_refs: Vec<&[u8]> = client_contacts.iter().map(|s| s.as_bytes()).collect();

    let mut registered: Vec<String> = (0..30).map(|i| format!("+1212555{i:04}")).collect();
    for i in 30..500 {
        registered.push(format!("+9999000{i:04}"));
    }
    let reg_refs: Vec<&[u8]> = registered.iter().map(|s| s.as_bytes()).collect();
    let table = simulate_server_table(&master_sk, &reg_refs).unwrap();
    let table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();

    let (req, state) = prepare_psi_query(&mk, &client_refs, 1, &mut OsRng).unwrap();
    let mut responses = Vec::new();
    for idx in 0..3 {
        let (wi, sk) = shares[idx];
        responses.push((wi, psi_server_respond(&req, &sk, &mut OsRng).unwrap()));
    }
    let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();
    let labels = finalize_psi_query(&state, &resp_refs, ThresholdConfig::default()).unwrap();
    assert_eq!(labels.len(), 50);

    let intersection = intersect_with_server_table(&labels, &table_keys);
    // Первые 30 contacts должны быть в intersection.
    let expected: Vec<usize> = (0..30).collect();
    assert_eq!(intersection, expected);
}

#[test]
fn psi_correctness_no_overlap_zero_intersection() {
    let (master_sk, shares) = make_cluster();
    let mk = [0x42u8; 32];

    let client_refs: Vec<&[u8]> = vec![b"+12125550000", b"+12125550001"];
    let reg_refs: Vec<&[u8]> = vec![b"+99999990000", b"+99999990001"];
    let table = simulate_server_table(&master_sk, &reg_refs).unwrap();
    let table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();

    let (req, state) = prepare_psi_query(&mk, &client_refs, 1, &mut OsRng).unwrap();
    let mut responses = Vec::new();
    for idx in 0..3 {
        let (wi, sk) = shares[idx];
        responses.push((wi, psi_server_respond(&req, &sk, &mut OsRng).unwrap()));
    }
    let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();
    let labels = finalize_psi_query(&state, &resp_refs, ThresholdConfig::default()).unwrap();
    let intersection = intersect_with_server_table(&labels, &table_keys);
    assert!(intersection.is_empty());
}

#[test]
fn psi_correctness_full_overlap_complete_intersection() {
    let (master_sk, shares) = make_cluster();
    let mk = [0x42u8; 32];

    let phones: Vec<String> = (0..20).map(|i| format!("+1212555{i:04}")).collect();
    let refs: Vec<&[u8]> = phones.iter().map(|s| s.as_bytes()).collect();

    let table = simulate_server_table(&master_sk, &refs).unwrap();
    let table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();

    let (req, state) = prepare_psi_query(&mk, &refs, 1, &mut OsRng).unwrap();
    let mut responses = Vec::new();
    for idx in 0..3 {
        let (wi, sk) = shares[idx];
        responses.push((wi, psi_server_respond(&req, &sk, &mut OsRng).unwrap()));
    }
    let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();
    let labels = finalize_psi_query(&state, &resp_refs, ThresholdConfig::default()).unwrap();

    let intersection = intersect_with_server_table(&labels, &table_keys);
    assert_eq!(intersection.len(), 20);
}
