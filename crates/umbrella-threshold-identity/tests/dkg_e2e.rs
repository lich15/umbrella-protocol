//! Round-6 Stage 1 acceptance gate test: FROST DKG works between 5 mock
//! servers; threshold sign produces a valid Ed25519 signature.
//!
//! Spec reference: `docs/superpowers/specs/2026-05-19-phd-b-distributed-identity-pin-design.md`
//! §«Universal acceptance gate» #1.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use umbrella_threshold_identity::{
    dkg::run_in_process_dkg,
    signing::run_in_process_sign,
    {THRESHOLD, TOTAL_SERVERS},
};

#[test]
fn acceptance_gate_dkg_5_servers_threshold_3() {
    // 5 mock servers, threshold 3-of-5 per round-6 spec.
    let mut rng = ChaCha20Rng::seed_from_u64(0x000A_CCED_F0F0_F0F0_u64);
    let (key_packages, public_key_package) =
        run_in_process_dkg(TOTAL_SERVERS, THRESHOLD, &mut rng).expect("5-of-3 DKG must succeed");

    assert_eq!(
        key_packages.len(),
        TOTAL_SERVERS as usize,
        "5 KeyPackages output"
    );

    // Round 1: identity public key derivable + observable by anyone.
    let pk_bytes = public_key_package
        .verifying_key()
        .serialize()
        .expect("Ed25519 pk serialise");
    assert_eq!(pk_bytes.len(), 32, "Ed25519 pk is 32 bytes");

    // Round 2: threshold sign with any 3-of-5 subset.
    for subset in [&[0usize, 1, 2][..], &[0, 2, 4][..], &[1, 3, 4][..]] {
        let msg = format!("round-6 acceptance: subset {subset:?}");
        let sig = run_in_process_sign(
            &key_packages,
            &public_key_package,
            subset,
            msg.as_bytes(),
            &mut rng,
        )
        .unwrap_or_else(|e| panic!("threshold sign failed for {subset:?}: {e:?}"));

        // FROST verify.
        public_key_package
            .verifying_key()
            .verify(msg.as_bytes(), &sig)
            .unwrap_or_else(|e| panic!("FROST verify fail for {subset:?}: {e:?}"));

        // Cross-check via dalek (independent Ed25519 implementation).
        let sig_bytes = sig.serialize().expect("sig serialise");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 sig is 64 bytes");
        let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes.as_slice().try_into().expect("32-byte pk"),
        )
        .expect("dalek parse");
        let dalek_sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().expect("64-byte sig"),
        );
        dalek_pk
            .verify_strict(msg.as_bytes(), &dalek_sig)
            .unwrap_or_else(|e| panic!("dalek strict verify fail for {subset:?}: {e:?}"));
    }
}

#[test]
fn quorum_below_threshold_rejects() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (key_packages, pubkey_package) =
        run_in_process_dkg(TOTAL_SERVERS, THRESHOLD, &mut rng).unwrap();

    // 2 of 5 cannot sign — FROST aggregate fails.
    let msg = b"below threshold";
    let r = run_in_process_sign(&key_packages, &pubkey_package, &[0, 1], msg, &mut rng);
    assert!(r.is_err(), "2-of-5 below threshold must fail");
}
