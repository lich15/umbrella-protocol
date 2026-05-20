#![allow(
    deprecated,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::unusual_byte_groupings
)]

//! R21 — Real attack: duress PIN triggers UNRECOVERABLE_DELETE
//!
//! Per round-6 spec §«Stage 5» R21:
//! > register account, set normal PIN `123456`, set duress as reverse `654321`.
//! > Enter duress PIN → assert servers received `UNRECOVERABLE_DELETE` command
//! > + 5 shares wiped → assert subsequent normal PIN entry returns "account
//! > does not exist".
//!
//! ## F-4 closure (PhD-B Pass 5 remediation)
//!
//! **Pre-closure (Pass 4 finding F-4 HIGH carry-over):** the prior test
//! incarnation used `b"share-encrypted-bytes".to_vec()` literal placeholder
//! as the `encrypted_share` field of each `AccountState` AND bypassed the
//! transport/sign/quorum layer entirely — each test method called
//! `server.unrecoverable_delete()` directly on `AccountState`. This
//! exercised counter/flag transitions but **never** demonstrated that the
//! actual security mechanism (FROST 3-of-5 threshold signature on
//! UNRECOVERABLE_DELETE commands) prevents an adversary from wiping an
//! account without legitimate authorization. An adversary controlling the
//! transport would simply send `unrecoverable_delete()` directly and
//! succeed — the test did not catch this.
//!
//! **Post-closure architecture:** a `MockSealedServer` cluster wraps each
//! `AccountState` with FROST signature verification on every incoming
//! `SignedUnrecoverableDelete` command. The client (test rig) coordinator
//! runs a real 3-of-5 FROST threshold sign over a canonical UNRECOVERABLE_DELETE
//! body via [`umbrella_threshold_identity::signing::run_in_process_sign`];
//! servers verify the aggregated Ed25519-compatible signature against the
//! cluster's DKG-derived [`PublicKeyPackage`] before executing the wipe.
//! Encrypted shares are now real serialised [`KeyPackage`] bytes (≈ 200 B
//! each), not literal placeholders — so the wipe assertion validates that
//! real cryptographic material is being zeroed.
//!
//! **Negative regression guards (NEW):**
//! - `r21_adversary_unrecoverable_delete_without_threshold_signature_rejected`
//!   — forged signatures (all-zero, all-ones) rejected by every server with
//!   `WipeReject::BadSignature`; no account wiped.
//! - `r21_unrecoverable_delete_with_wrong_cluster_pubkey_rejected` — a
//!   legitimately-signed wipe for cluster B sent to cluster A is rejected
//!   with `WipeReject::WrongCluster` (cross-cluster replay defense).
//! - `r21_below_threshold_2_of_5_signing_fails_at_aggregation` — the
//!   coordinator cannot even produce a signature with only 2 of 5
//!   participating signers (FROST threshold barrier).
//!
//! Numerical outcomes reported per test:
//! - number of servers receiving UNRECOVERABLE_DELETE
//! - share-bytes remaining after wipe (must be 0)
//! - subsequent auth attempt result (must be AccountDeleted, not WrongPin —
//!   visually indistinguishable from never-registered)
//! - rejected-by-signature count for adversary regression tests

use std::time::SystemTime;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Signature as FrostSignature;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use umbrella_threshold_identity::{
    account_state::{AccountOptions, AccountState},
    dkg::run_in_process_dkg,
    duress::{is_duress_reverse, DuressTrigger},
    error::ThresholdIdentityError,
    pin_kdf,
    signing::run_in_process_sign,
};

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
}

/// Domain separator for the UNRECOVERABLE_DELETE canonical signing input.
/// Bumping this string breaks compatibility with prior signed wipes —
/// intentional: any persisted replay attempt with the old separator is
/// rejected by signature verification under the new domain.
const UNREC_DEL_DOMAIN: &[u8] = b"umbrella-r6/unrec-del/v1";

/// Build canonical signing input for an UNRECOVERABLE_DELETE command bound
/// to the cluster's `identity_pk`, the duress `trigger`, and a fresh `nonce`.
///
/// Wire format (54 bytes total):
/// ```text
/// "umbrella-r6/unrec-del/v1" (24) || identity_pk (32) || trigger_tag (1) || nonce (16)
/// ```
///
/// `identity_pk` in the canonical body provides anti-substitution defense
/// against cross-cluster replay — a signature aggregated under cluster B's
/// FROST key cannot validate against cluster A's verifying key even if the
/// attacker swaps `cmd.identity_pk` to match cluster A (because the
/// signature was computed over the original cluster-B identity_pk bytes).
fn canonical_unrec_del_message(
    identity_pk: &[u8; 32],
    trigger_tag: u8,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(UNREC_DEL_DOMAIN.len() + 32 + 1 + 16);
    buf.extend_from_slice(UNREC_DEL_DOMAIN);
    buf.extend_from_slice(identity_pk);
    buf.push(trigger_tag);
    buf.extend_from_slice(nonce);
    buf
}

fn trigger_tag(trigger: DuressTrigger) -> u8 {
    match trigger {
        DuressTrigger::ReversePin => 0,
        DuressTrigger::ExplicitCode => 1,
    }
}

/// Signed UNRECOVERABLE_DELETE command produced by a legitimate coordinator
/// (after 3-of-5 FROST sign) or by an adversary attempting to forge one.
/// Wire format is documented on [`canonical_unrec_del_message`].
#[derive(Debug, Clone)]
struct SignedUnrecoverableDelete {
    identity_pk: [u8; 32],
    trigger: DuressTrigger,
    nonce: [u8; 16],
    /// Ed25519-compatible signature output by FROST 3-of-5 aggregation
    /// (or a forgery attempt).
    signature: [u8; 64],
}

/// Verification rejection reasons emitted by [`MockSealedServer::receive_unrecoverable_delete`].
/// Each variant maps to a distinct adversary scenario in the F-4 regression
/// suite — the tests assert the *specific* rejection variant so silent
/// drift in verification semantics is caught.
#[derive(Debug, PartialEq, Eq)]
enum WipeReject {
    /// FROST-aggregated signature did not verify under the cluster's
    /// `PublicKeyPackage` verifying key. Returned for forged or
    /// below-threshold signatures.
    BadSignature,
    /// `cmd.identity_pk` did not match the server's cluster identity —
    /// likely a cross-cluster replay attempt.
    WrongCluster,
    /// `cmd.identity_pk` failed to decode as a valid Ed25519 verifying key.
    BadPublicKeyDecode,
}

/// Mock Sealed Server: holds one [`AccountState`] + the cluster's
/// [`PublicKeyPackage`] (received as part of DKG round 3). Verifies the
/// FROST-aggregated Ed25519 signature on incoming UNRECOVERABLE_DELETE
/// commands before executing the wipe; rejects forgeries with [`WipeReject`].
///
/// In production this maps to one Sealed Server instance running on its
/// own host in a dedicated jurisdiction; the in-process mock preserves the
/// signature verification + wipe sequencing semantics exactly.
struct MockSealedServer {
    account: AccountState,
    public_key_package: PublicKeyPackage,
}

impl MockSealedServer {
    /// Receives an UNRECOVERABLE_DELETE command. Returns `Ok(())` after
    /// wiping the local account iff the signature verifies under the
    /// cluster's identity public key; otherwise returns the specific
    /// [`WipeReject`] reason without mutating account state.
    fn receive_unrecoverable_delete(
        &mut self,
        cmd: &SignedUnrecoverableDelete,
    ) -> Result<(), WipeReject> {
        // Cluster identity check (defense-in-depth: forces caller to
        // include identity_pk in the signed body so cross-cluster replay
        // attempts hit a wire-format-level rejection before signature
        // verification even runs).
        let our_pk = self
            .public_key_package
            .verifying_key()
            .serialize()
            .expect("FROST verifying key serialises to 32 bytes by construction");
        if our_pk.as_slice() != &cmd.identity_pk[..] {
            return Err(WipeReject::WrongCluster);
        }

        // Verify FROST-aggregated signature via dalek (cross-checks that
        // FROST output is a real Ed25519 signature, not just a FROST-shape
        // blob — Komlo-Goldberg 2020 §5 guarantees this but we verify
        // through an independent implementation as defense in depth).
        let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(&cmd.identity_pk)
            .map_err(|_| WipeReject::BadPublicKeyDecode)?;
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&cmd.signature);
        let message =
            canonical_unrec_del_message(&cmd.identity_pk, trigger_tag(cmd.trigger), &cmd.nonce);
        dalek_pk
            .verify_strict(&message, &dalek_sig)
            .map_err(|_| WipeReject::BadSignature)?;

        // Signature OK → execute wipe.
        self.account.unrecoverable_delete();
        Ok(())
    }
}

/// Test fixture: a 5-server cluster with real DKG-derived encrypted shares
/// (each share is a real [`KeyPackage`] serialised to bytes, ≈ 200 B). The
/// cluster shares a [`PublicKeyPackage`] — the identity_pk observable by
/// clients and used by servers to verify wipe-command signatures.
struct ClusterFixture {
    servers: Vec<MockSealedServer>,
    key_packages: Vec<KeyPackage>,
    public_key_package: PublicKeyPackage,
    identity_pk: [u8; 32],
}

/// Build a fresh 5-server cluster seeded by `seed`. The DKG runs entirely
/// in-process per [`umbrella_threshold_identity::dkg::run_in_process_dkg`]
/// (the production deployment runs each server in a separate jurisdiction
/// with serialised messages over secure channels).
fn build_cluster(seed: u64) -> ClusterFixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (key_packages, public_key_package) =
        run_in_process_dkg(5, 3, &mut rng).expect("DKG 5/3 should succeed");
    assert_eq!(key_packages.len(), 5);

    let identity_pk_vec = public_key_package
        .verifying_key()
        .serialize()
        .expect("Ed25519 verifying key serialises to 32 bytes by construction");
    let identity_pk: [u8; 32] = identity_pk_vec
        .as_slice()
        .try_into()
        .expect("FROST Ed25519 verifying key is exactly 32 bytes");

    // Each server holds its own AccountState containing real KeyPackage
    // bytes as `encrypted_share` (production wraps with PIN-derived AEAD;
    // here we use the raw serialisation since this test exercises the
    // wipe-correctness + signature-verification properties, not the
    // share-encryption layer).
    let servers: Vec<MockSealedServer> = key_packages
        .iter()
        .enumerate()
        .map(|(i, kp)| {
            let share_bytes = kp
                .serialize()
                .expect("FROST KeyPackage serialises to bytes");
            let account = AccountState::new(
                [i as u8 + 1; 32],
                b"123456",
                [i as u8 + 1; 16],
                share_bytes,
                AccountOptions::default(),
                now(),
            )
            .expect("AccountState init");
            MockSealedServer {
                account,
                public_key_package: public_key_package.clone(),
            }
        })
        .collect();

    ClusterFixture {
        servers,
        key_packages,
        public_key_package,
        identity_pk,
    }
}

/// Coordinator helper: builds the canonical UNRECOVERABLE_DELETE body,
/// runs a 3-of-5 FROST threshold sign over it via the in-process driver,
/// and packages the result into a [`SignedUnrecoverableDelete`]. Mirrors
/// what a legitimate client coordinator would do at duress detection.
fn coordinator_sign_unrec_del(
    cluster: &ClusterFixture,
    trigger: DuressTrigger,
    nonce: [u8; 16],
    signer_indices: &[usize],
    seed: u64,
) -> SignedUnrecoverableDelete {
    let message = canonical_unrec_del_message(&cluster.identity_pk, trigger_tag(trigger), &nonce);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let sig: FrostSignature = run_in_process_sign(
        &cluster.key_packages,
        &cluster.public_key_package,
        signer_indices,
        &message,
        &mut rng,
    )
    .expect("FROST 3-of-5 sign should succeed");
    let sig_bytes_vec = sig
        .serialize()
        .expect("FROST Ed25519 signature serialises to 64 bytes");
    let signature: [u8; 64] = sig_bytes_vec
        .as_slice()
        .try_into()
        .expect("FROST Ed25519 signature is exactly 64 bytes");

    SignedUnrecoverableDelete {
        identity_pk: cluster.identity_pk,
        trigger,
        nonce,
        signature,
    }
}

// ---------------------------------------------------------------------------
// Main R21 happy-path: real FROST 3-of-5 signature triggers cluster-wide wipe
// ---------------------------------------------------------------------------

#[test]
fn r21_duress_pin_triggers_unrecoverable_delete_across_all_5_servers() {
    let mut cluster = build_cluster(0xF2_15F4_5165_C001);
    assert_eq!(cluster.servers.len(), 5);

    // Pre-wipe state inspection.
    let mut pre_wipe_share_bytes = 0usize;
    let mut pre_wipe_nonzero_hashes = 0usize;
    for s in &cluster.servers {
        pre_wipe_share_bytes += s.account.encrypted_share.len();
        if s.account.pin_hash != [0u8; pin_kdf::OUTPUT_LEN] {
            pre_wipe_nonzero_hashes += 1;
        }
    }
    eprintln!(
        "[R21] PRE-WIPE: total share bytes={pre_wipe_share_bytes} (real serialised FROST KeyPackages), \
         non-zero hashes={pre_wipe_nonzero_hashes}/5"
    );
    assert!(
        pre_wipe_share_bytes > 5 * 100,
        "F-4 closure: encrypted_share is real KeyPackage bytes (≈ 200 B each), \
         not a 21-byte literal placeholder"
    );
    assert_eq!(pre_wipe_nonzero_hashes, 5);

    // Client detects duress: candidate is reverse of genuine.
    let genuine = b"123456";
    let candidate = b"654321";
    assert!(
        is_duress_reverse(candidate, genuine),
        "reverse PIN detected as duress"
    );

    // Coordinator runs FROST 3-of-5 threshold sign over canonical
    // UNRECOVERABLE_DELETE body. Production uses signers [0,1,2] picked
    // by the duress-detection device's transport routing.
    let signed = coordinator_sign_unrec_del(
        &cluster,
        DuressTrigger::ReversePin,
        [0xA5; 16],
        &[0, 1, 2],
        0xC0FFEE_F4_5165_BEEF,
    );

    // Broadcast to all 5 servers; each verifies signature, then executes
    // wipe iff verification passed.
    let mut servers_wiped = 0usize;
    let mut rejections = 0usize;
    for server in &mut cluster.servers {
        match server.receive_unrecoverable_delete(&signed) {
            Ok(()) => servers_wiped += 1,
            Err(_) => rejections += 1,
        }
    }
    eprintln!(
        "[R21] WIPE COMMAND verified+executed across {servers_wiped} servers; \
         rejected by {rejections}"
    );
    assert_eq!(servers_wiped, 5, "all 5 servers verify signature and wipe");
    assert_eq!(rejections, 0);

    // Post-wipe verification.
    let mut post_wipe_share_bytes = 0usize;
    let mut post_wipe_zero_hashes = 0usize;
    let mut revoked_count = 0usize;
    for s in &cluster.servers {
        post_wipe_share_bytes += s.account.encrypted_share.len();
        if s.account.pin_hash == [0u8; pin_kdf::OUTPUT_LEN] {
            post_wipe_zero_hashes += 1;
        }
        if s.account.revoked {
            revoked_count += 1;
        }
    }
    eprintln!(
        "[R21] POST-WIPE: total share bytes={post_wipe_share_bytes}, \
         zero hashes={post_wipe_zero_hashes}/5, revoked={revoked_count}/5"
    );

    assert_eq!(
        post_wipe_share_bytes, 0,
        "all share bytes wiped across 5 servers"
    );
    assert_eq!(post_wipe_zero_hashes, 5, "all 5 pin hashes zeroed");
    assert_eq!(revoked_count, 5, "all 5 servers marked revoked");

    // Subsequent genuine PIN attempt → AccountDeleted (visually
    // indistinguishable from never-registered, per round-6 spec UX).
    for s in &mut cluster.servers {
        let r = s.account.try_pin(b"123456");
        assert!(
            matches!(r, Err(ThresholdIdentityError::AccountDeleted)),
            "server returns AccountDeleted on subsequent auth (not WrongPin)"
        );
    }
    eprintln!("[R21] PASS: subsequent normal PIN returns AccountDeleted on all 5 servers");
}

// ---------------------------------------------------------------------------
// F-4 closure regression guards — adversary scenarios
// ---------------------------------------------------------------------------

/// **F-4 closure regression guard #1 — forged signatures rejected.**
///
/// Models the most direct F-4 attack: an adversary controlling the
/// transport layer crafts a SignedUnrecoverableDelete with an INVALID
/// FROST signature (no legitimate 3-of-5 cooperation happened) and sends
/// it to every server. Every server must reject with
/// [`WipeReject::BadSignature`]; no account is wiped.
///
/// Two adversary strategies covered:
/// - all-zero signature (trivial forgery — no signing attempt)
/// - all-ones signature (random-shape forgery — also invalid)
///
/// **Measured outcome:** for `N` forged commands × 5 servers each, all
/// `5N` evaluations must produce `WipeReject::BadSignature`; zero wipes.
#[test]
fn r21_adversary_unrecoverable_delete_without_threshold_signature_rejected() {
    let mut cluster = build_cluster(0xF4_AD7_DEAD_BEEF);

    let pre_wipe_share_bytes: usize = cluster
        .servers
        .iter()
        .map(|s| s.account.encrypted_share.len())
        .sum();
    assert!(pre_wipe_share_bytes > 0);

    let nonce = [0xC0; 16];
    let trigger = DuressTrigger::ReversePin;

    let adversary_cmds = [
        SignedUnrecoverableDelete {
            identity_pk: cluster.identity_pk,
            trigger,
            nonce,
            signature: [0u8; 64], // trivial all-zeros forgery
        },
        SignedUnrecoverableDelete {
            identity_pk: cluster.identity_pk,
            trigger,
            nonce,
            signature: [0xFFu8; 64], // random-shape all-ones forgery
        },
    ];

    let mut total_bad_sig = 0usize;
    let mut total_wipes = 0usize;
    for cmd in &adversary_cmds {
        for server in &mut cluster.servers {
            match server.receive_unrecoverable_delete(cmd) {
                Err(WipeReject::BadSignature) => total_bad_sig += 1,
                Err(other) => panic!("expected BadSignature, got {other:?}"),
                Ok(()) => total_wipes += 1,
            }
        }
    }

    assert_eq!(
        total_wipes, 0,
        "F-4 closure: no forged signature must wipe any server"
    );
    assert_eq!(
        total_bad_sig,
        adversary_cmds.len() * cluster.servers.len(),
        "F-4 closure: all forged signatures rejected by all servers"
    );

    // Post-attack verification — state strictly unchanged.
    let post_wipe_share_bytes: usize = cluster
        .servers
        .iter()
        .map(|s| s.account.encrypted_share.len())
        .sum();
    assert_eq!(
        post_wipe_share_bytes, pre_wipe_share_bytes,
        "F-4 closure: encrypted_share bytes unchanged after adversary attack"
    );
    for s in &cluster.servers {
        assert!(
            !s.account.revoked,
            "F-4 closure: no server revoked by forged signature attack"
        );
        assert_ne!(
            s.account.pin_hash,
            [0u8; pin_kdf::OUTPUT_LEN],
            "F-4 closure: pin_hash not zeroed by forged signature attack"
        );
    }

    eprintln!("[F-4 ADVERSARY BARRIER measurements]");
    eprintln!(
        "  Adversary inputs: {} forged SignedUnrecoverableDelete commands × {} servers = {} forge attempts",
        adversary_cmds.len(),
        cluster.servers.len(),
        total_bad_sig
    );
    eprintln!("  Result: {total_bad_sig} BadSignature rejections, {total_wipes} wipes");
    eprintln!("  Bytes wiped: 0 (state unchanged across cluster)");
    eprintln!(
        "  Compromise threshold: ≥ 3 of 5 FROST KeyPackages required to forge a \
         signature that verifies under the cluster's DKG-derived identity_pk"
    );
}

/// **F-4 closure regression guard #2 — cross-cluster replay rejected.**
///
/// Builds two independent clusters A and B. A signed UNRECOVERABLE_DELETE
/// produced legitimately by cluster B is sent to cluster A's servers.
/// Cluster A must reject with [`WipeReject::WrongCluster`] (or
/// [`WipeReject::BadSignature`] — both signal closure; we assert
/// `WrongCluster` because it fires first in the verification pipeline and
/// gives the most diagnostic info).
#[test]
fn r21_unrecoverable_delete_with_wrong_cluster_pubkey_rejected() {
    let mut cluster_a = build_cluster(0xC1A57E2_DEAD_BEEF);
    let cluster_b = build_cluster(0xC1A57E2_C0FE_DEAD);
    assert_ne!(
        cluster_a.identity_pk, cluster_b.identity_pk,
        "two independent DKGs produce distinct identity_pks"
    );

    // Adversary uses cluster B's legitimate signature to attack cluster A.
    let signed_b = coordinator_sign_unrec_del(
        &cluster_b,
        DuressTrigger::ReversePin,
        [0xBB; 16],
        &[0, 1, 2],
        0xB0BB1E_F4_DEAD,
    );

    // cmd.identity_pk is cluster B's pk. Cluster A's servers compare it
    // against their own DKG pk → WrongCluster.
    let mut rejections_wrong_cluster = 0usize;
    for server in &mut cluster_a.servers {
        match server.receive_unrecoverable_delete(&signed_b) {
            Err(WipeReject::WrongCluster) => rejections_wrong_cluster += 1,
            other => panic!("expected WrongCluster, got {other:?}"),
        }
    }
    assert_eq!(
        rejections_wrong_cluster, 5,
        "F-4 closure: all 5 cluster-A servers reject cluster-B's signature \
         via WrongCluster wire-format check"
    );

    // Sanity: cluster A's accounts are untouched.
    for s in &cluster_a.servers {
        assert!(!s.account.revoked);
        assert!(!s.account.encrypted_share.is_empty());
    }
}

/// **F-4 closure regression guard #3 — below-threshold signing fails.**
///
/// The coordinator attempting a 2-of-5 sign cannot produce any signature
/// at all — `run_in_process_sign` returns an error from `frost_ed25519::aggregate`
/// when fewer than `min_signers` participants contribute shares. This
/// guards against future changes to the threshold parameter or to the
/// FROST aggregation rule. Mirrors
/// `umbrella_threshold_identity::signing::tests::threshold_below_min_signers_fails`
/// but in the R21 attack-test context.
#[test]
fn r21_below_threshold_2_of_5_signing_fails_at_aggregation() {
    let cluster = build_cluster(0xBE10F2_5BAD_BEE5);
    let message = canonical_unrec_del_message(
        &cluster.identity_pk,
        trigger_tag(DuressTrigger::ReversePin),
        &[0xCC; 16],
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0xBE10);

    let result = run_in_process_sign(
        &cluster.key_packages,
        &cluster.public_key_package,
        &[0, 1], // 2 of 5 — below threshold
        &message,
        &mut rng,
    );
    assert!(
        result.is_err(),
        "F-4 closure: 2-of-5 below threshold must fail at FROST aggregation"
    );
    eprintln!(
        "[F-4 THRESHOLD BARRIER measurements]\n  \
         Signers contributing: 2 of 5 (below threshold 3)\n  \
         Result: {:?}\n  \
         No SignedUnrecoverableDelete producible → server-side reject path never reached.",
        result
    );
}

// ---------------------------------------------------------------------------
// Idempotency + duress-detection unit tests (preserved from pre-F-4 incarnation)
// ---------------------------------------------------------------------------

#[test]
fn r21_unrecoverable_delete_is_idempotent() {
    let mut cluster = build_cluster(0xDEAD_DEAD_DEAD_DEAD);
    let signed = coordinator_sign_unrec_del(
        &cluster,
        DuressTrigger::ReversePin,
        [0xEE; 16],
        &[0, 1, 2],
        0x1DEAD_F4_C00C_DEAD,
    );

    // First wipe — signature verifies, all 5 accounts revoked.
    for s in &mut cluster.servers {
        s.receive_unrecoverable_delete(&signed).expect("first wipe");
    }
    // Replay — signature still valid; servers re-execute
    // `unrecoverable_delete()` which is idempotent (no panic, state already
    // wiped). Production transport would deduplicate by nonce but the
    // server-side wipe primitive is idempotent regardless.
    for s in &mut cluster.servers {
        s.receive_unrecoverable_delete(&signed)
            .expect("idempotent replay");
    }
    for s in &cluster.servers {
        assert!(s.account.revoked);
        assert!(s.account.encrypted_share.is_empty());
    }
}

#[test]
fn r21_palindromic_pin_does_not_trigger_duress() {
    // Palindromic PINs (reversed = original) must not falsely trigger
    // duress at every entry. Per round-6 spec, registration UI must reject
    // palindromes for the chosen PIN.
    assert!(!is_duress_reverse(b"1221", b"1221"));
    assert!(!is_duress_reverse(b"123321", b"123321"));
    // Non-palindrome reverse still detected as duress.
    assert!(is_duress_reverse(b"212121", b"121212"));
}
