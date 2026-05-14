use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    canonical_sign_payload, verify_signed_epoch, SignedEpochRoot, WitnessPublic, WitnessSet,
    WitnessSignature, NODE_HASH_LEN,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct KtObservation {
    client: &'static str,
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
}

fn split_view_detected(a: &KtObservation, b: &KtObservation) -> bool {
    a.client != b.client && a.epoch == b.epoch && (a.root != b.root || a.log_size != b.log_size)
}

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

#[test]
fn threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);

    let mut honest_root = [0u8; NODE_HASH_LEN];
    let mut evil_root = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut honest_root);
    OsRng.fill_bytes(&mut evil_root);

    let alice_view = signed_view(
        &witnesses,
        &[0, 1, 2],
        42,
        honest_root,
        50_000,
        1_700_000_100,
    );
    let bob_view = signed_view(
        &witnesses,
        &[0, 1, 2],
        42,
        evil_root,
        50_001,
        1_700_000_101,
    );

    verify_signed_epoch(&alice_view, &set, 3).expect("alice sees a locally valid 3-of-5 epoch");
    verify_signed_epoch(&bob_view, &set, 3).expect("bob sees a locally valid 3-of-5 epoch");

    let alice_observation = KtObservation {
        client: "alice",
        epoch: alice_view.epoch,
        root: alice_view.root,
        log_size: alice_view.log_size,
    };
    let bob_observation = KtObservation {
        client: "bob",
        epoch: bob_view.epoch,
        root: bob_view.root,
        log_size: bob_view.log_size,
    };

    assert!(
        split_view_detected(&alice_observation, &bob_observation),
        "client observation exchange must detect same-epoch KT split-view"
    );
}
