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

#[test]
fn public_observation_encoding_round_trips_without_private_account_data() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xA5; 32]);
    let previous_root = [0x11; NODE_HASH_LEN];
    let private_account_marker = [0x44; 32];
    let signed = signed_view(
        &witnesses,
        &[0, 1, 2],
        77,
        [0x22; NODE_HASH_LEN],
        1234,
        1_700_000_300,
    );
    let observation = KtObservation::new(log_id, previous_root, signed);

    let encoded = observation.encode_public();
    assert!(
        !encoded
            .windows(private_account_marker.len())
            .any(|w| w == private_account_marker),
        "public KT observation must not contain account_id or private account marker"
    );

    let decoded = KtObservation::decode_public(&encoded).expect("public observation decodes");
    assert_eq!(decoded, observation);
    decoded
        .validate(&set, 3)
        .expect("decoded observation remains valid");
}

#[test]
fn public_observation_decoder_rejects_truncated_and_trailing_bytes() {
    let witnesses = make_witnesses();
    let signed = signed_view(
        &witnesses,
        &[0, 1, 2],
        78,
        [0x33; NODE_HASH_LEN],
        99,
        1_700_000_301,
    );
    let observation = KtObservation::new(KtLogId::from_bytes([0xB6; 32]), [0x10; 32], signed);
    let encoded = observation.encode_public();

    let truncated = &encoded[..encoded.len() - 1];
    assert!(KtObservation::decode_public(truncated).is_err());

    let mut trailing = encoded;
    trailing.push(0x99);
    assert!(KtObservation::decode_public(&trailing).is_err());
}

#[test]
fn witness_signing_ledger_rejects_second_different_root_for_same_epoch() {
    let witnesses = make_witnesses();
    let log_id = KtLogId::from_bytes([0xC7; 32]);
    let first = signed_view(
        &witnesses,
        &[0],
        88,
        [0x41; NODE_HASH_LEN],
        500,
        1_700_000_400,
    );
    let same = signed_view(
        &witnesses,
        &[0],
        88,
        [0x41; NODE_HASH_LEN],
        500,
        1_700_000_401,
    );
    let fork = signed_view(
        &witnesses,
        &[0],
        88,
        [0x42; NODE_HASH_LEN],
        501,
        1_700_000_402,
    );

    let mut ledger = umbrella_kt::WitnessSigningLedger::new();
    assert_eq!(
        ledger.record_or_reject(log_id, &first).unwrap(),
        umbrella_kt::WitnessSigningDecision::FirstSignature
    );
    assert_eq!(
        ledger.record_or_reject(log_id, &same).unwrap(),
        umbrella_kt::WitnessSigningDecision::RepeatedSameHead
    );

    let err = ledger.record_or_reject(log_id, &fork).unwrap_err();
    assert!(
        format!("{err}").contains("witness equivocation attempt"),
        "same witness must refuse second different root for same log epoch, got {err}"
    );
}

#[test]
fn observation_history_rejects_epoch_regression_and_broken_chain() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xD8; 32]);
    let genesis = [0x00; NODE_HASH_LEN];
    let root_10 = [0x10; NODE_HASH_LEN];
    let root_11 = [0x11; NODE_HASH_LEN];
    let wrong_previous = [0x99; NODE_HASH_LEN];

    let epoch_10 = KtObservation::new(
        log_id,
        genesis,
        signed_view(&witnesses, &[0, 1, 2], 10, root_10, 10_000, 1_700_000_500),
    );
    let epoch_9 = KtObservation::new(
        log_id,
        genesis,
        signed_view(
            &witnesses,
            &[0, 1, 2],
            9,
            [0x09; NODE_HASH_LEN],
            9_000,
            1_700_000_501,
        ),
    );
    let broken_11 = KtObservation::new(
        log_id,
        wrong_previous,
        signed_view(&witnesses, &[0, 1, 2], 11, root_11, 11_000, 1_700_000_502),
    );

    let mut history = umbrella_kt::KtObservationHistory::new();
    assert_eq!(
        history.observe(epoch_10, &set, 3).unwrap(),
        KtTrustDecision::NeedsObservation
    );

    let regression = history.observe(epoch_9, &set, 3).unwrap_err();
    assert!(format!("{regression}").contains("epoch regression"));

    let broken = history.observe(broken_11, &set, 3).unwrap_err();
    assert!(format!("{broken}").contains("epoch chain broken"));
}

#[test]
fn observation_history_returns_evidence_for_same_epoch_conflict() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xE9; 32]);
    let previous = [0x33; NODE_HASH_LEN];

    let first = KtObservation::new(
        log_id,
        previous,
        signed_view(
            &witnesses,
            &[0, 1, 2],
            50,
            [0x50; NODE_HASH_LEN],
            50,
            1_700_000_600,
        ),
    );
    let second = KtObservation::new(
        log_id,
        previous,
        signed_view(
            &witnesses,
            &[0, 1, 2],
            50,
            [0x51; NODE_HASH_LEN],
            51,
            1_700_000_601,
        ),
    );

    let mut history = umbrella_kt::KtObservationHistory::new();
    history.observe(first, &set, 3).unwrap();
    let decision = history.observe(second, &set, 3).unwrap();
    assert!(matches!(decision, KtTrustDecision::EquivocationDetected(_)));
}
