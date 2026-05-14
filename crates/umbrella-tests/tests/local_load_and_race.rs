use std::sync::{Arc, Mutex};
use std::thread;

use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    build_audit_path, canonical_sign_payload, leaf_hash, merkle_root, verify_inclusion,
    verify_signed_epoch, SignedEpochRoot, WitnessPublic, WitnessSet, WitnessSignature,
    NODE_HASH_LEN,
};
use umbrella_server_blind_postman::{ReplayDecision, ReplayGuard};

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

fn signed_epoch(
    witnesses: &[(PrivateSigningKey, WitnessPublic)],
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
) -> SignedEpochRoot {
    let timestamp_unix_millis = 1_700_000_000 + epoch;
    let payload = canonical_sign_payload(epoch, &root, log_size, timestamp_unix_millis);
    let signatures = witnesses
        .iter()
        .take(3)
        .map(|(sk, public)| WitnessSignature {
            witness: *public,
            signature: sk.sign(&payload).to_bytes(),
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
fn local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots() {
    const LEAVES: usize = 4096;
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);

    let leaves: Vec<[u8; NODE_HASH_LEN]> = (0..LEAVES)
        .map(|idx| leaf_hash(format!("account-{idx}:device-{}", idx % 8).as_bytes()))
        .collect();
    let root = merkle_root(&leaves);
    let signed = signed_epoch(&witnesses, 77, root, LEAVES as u64);

    verify_signed_epoch(&signed, &set, 3)
        .expect("local load root must keep 3-of-5 witness validity");

    for idx in [0usize, 1, 255, 1024, 2048, 4095] {
        let path = build_audit_path(&leaves, idx).expect("audit path must build");
        verify_inclusion(&leaves[idx], idx as u64, LEAVES as u64, &path, &root)
            .expect("selected loaded leaves must keep valid inclusion proof");
    }
}

#[test]
fn concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest() {
    let guard = Arc::new(Mutex::new(ReplayGuard::new(60)));
    let mut hash = [0u8; 32];
    OsRng.fill_bytes(&mut hash);

    let handles: Vec<_> = (0..32)
        .map(|_| {
            let guard = Arc::clone(&guard);
            thread::spawn(move || {
                guard
                    .lock()
                    .expect("replay guard mutex poisoned")
                    .check_and_record(hash, 1_700_000_000)
            })
        })
        .collect();

    let mut accepts = 0usize;
    let mut duplicates = 0usize;
    for handle in handles {
        match handle.join().expect("worker thread must not panic") {
            ReplayDecision::Accept => accepts += 1,
            ReplayDecision::Duplicate => duplicates += 1,
        }
    }

    assert_eq!(accepts, 1, "exactly one racing replay must be accepted");
    assert_eq!(duplicates, 31, "all other racing replays must be rejected");
}

#[test]
fn concurrent_witness_verification_has_no_shared_state_corruption() {
    let witnesses = make_witnesses();
    let set = Arc::new(witness_set(&witnesses));

    let signed_epochs: Vec<_> = (0..64u64)
        .map(|epoch| {
            let mut root = [0u8; NODE_HASH_LEN];
            root[0..8].copy_from_slice(&epoch.to_be_bytes());
            signed_epoch(&witnesses, epoch, root, 1024 + epoch)
        })
        .collect();

    let handles: Vec<_> = signed_epochs
        .into_iter()
        .map(|signed| {
            let set = Arc::clone(&set);
            thread::spawn(move || verify_signed_epoch(&signed, &set, 3))
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .expect("witness verification thread must not panic")
            .expect("signed epoch must verify");
    }
}
