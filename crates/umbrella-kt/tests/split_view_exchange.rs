use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    canonical_sign_payload, compare_observations, verify_signed_epoch, EquivocationEvidence,
    KtLogId, KtObservation, KtTrustDecision, SignedEpochRoot, WitnessPublic, WitnessSet,
    WitnessSignature, NODE_HASH_LEN,
};

fn make_witnesses() -> Vec<(PrivateSigningKey, WitnessPublic)> {
    (0..5)
        .map(|_| {
            let mut rng = OsRng;
            let sk = PrivateSigningKey::generate(&mut rng);
            let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
            (sk, pk)
        })
        .collect()
}

fn witness_set(witnesses: &[(PrivateSigningKey, WitnessPublic)]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for (_, public) in witnesses {
        set.add(*public);
    }
    set
}

fn signed_view(
    witnesses: &[(PrivateSigningKey, WitnessPublic)],
    signer_indices: &[usize],
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
    timestamp_unix_millis: u64,
) -> SignedEpochRoot {
    let payload = canonical_sign_payload(epoch, &root, log_size, timestamp_unix_millis);
    let signatures = signer_indices
        .iter()
        .map(|idx| {
            let (sk, public) = &witnesses[*idx];
            WitnessSignature {
                witness: *public,
                signature: sk.sign(&payload).to_bytes(),
            }
        })
        .collect();
    SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis,
        signatures,
    }
}

fn random_root() -> [u8; NODE_HASH_LEN] {
    let mut root = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut root);
    root
}

#[test]
fn threshold_signed_split_views_verify_locally_but_production_api_detects_divergence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([7u8; 32]);
    let previous_root = random_root();
    let honest_root = random_root();
    let evil_root = random_root();
    assert_ne!(honest_root, evil_root);

    let alice_view = signed_view(
        &witnesses,
        &[0, 1, 2],
        42,
        honest_root,
        50_000,
        1_700_000_100,
    );
    let bob_view = signed_view(&witnesses, &[0, 1, 2], 42, evil_root, 50_001, 1_700_000_101);

    verify_signed_epoch(&alice_view, &set, 3).expect("alice sees a locally valid 3-of-5 epoch");
    verify_signed_epoch(&bob_view, &set, 3).expect("bob sees a locally valid 3-of-5 epoch");

    let alice = KtObservation::new(log_id, previous_root, alice_view);
    let bob = KtObservation::new(log_id, previous_root, bob_view);

    let decision = compare_observations(&alice, &bob, &set, 3).expect("comparison must run");
    let evidence = match decision {
        KtTrustDecision::EquivocationDetected(evidence) => evidence,
        other => panic!("expected equivocation evidence, got {other:?}"),
    };

    evidence
        .verify(&set, 3)
        .expect("evidence must be independently verifiable");
    assert_eq!(evidence.first().signed.epoch, 42);
    assert_eq!(evidence.second().signed.epoch, 42);
    assert_ne!(evidence.first().signed.root, evidence.second().signed.root);
}

#[test]
fn invalid_second_view_does_not_become_equivocation_evidence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([9u8; 32]);
    let previous_root = random_root();
    let root_a = random_root();
    let root_b = random_root();

    let valid = signed_view(&witnesses, &[0, 1, 2], 7, root_a, 99, 1_700_000_200);
    let invalid = signed_view(&witnesses, &[0, 1], 7, root_b, 100, 1_700_000_201);

    let a = KtObservation::new(log_id, previous_root, valid);
    let b = KtObservation::new(log_id, previous_root, invalid);

    let err = EquivocationEvidence::try_new(a, b, &set, 3).unwrap_err();
    assert!(
        format!("{err}").contains("insufficient valid witness signatures"),
        "bad second view must reject as invalid proof, got {err}"
    );
}
