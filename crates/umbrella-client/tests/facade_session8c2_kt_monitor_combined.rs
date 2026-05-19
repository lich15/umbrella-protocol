//! F-CLIENT-FACADE-1 closure session 8c2 (2026-05-19): contract tests for
//! [`umbrella_client::kt_monitor::run_kt_self_monitor_once`] — combined
//! single-call KT self-monitor pass. Verifies:
//!
//! 1. **Both checks pass** when entry is honest + 3-of-5 witness signatures
//!    valid → `Ok(())`.
//! 2. **Own-entry error short-circuits** witness check — when log returns
//!    tampered identity_ed25519_pub, helper fails on first step без
//!    fetching/verifying witness signatures (no witness setup required
//!    for the test to fail; absence of staged signed root would otherwise
//!    surface `InsufficientValidSignatures` if witness check ran).
//! 3. **Witness error propagates** after own-entry succeeds — when entry
//!    is honest but threshold not met (2-of-5 staged signatures), helper
//!    returns witness error.
//! 4. **Both fail-closed** when no data staged at all — own-entry fails
//!    first with `entry_absent_from_log` (witness never reached).
//!
//! Engineering scope wire-up — composes verified session-8a + session-8b
//! helpers without introducing new cryptographic primitives. Real
//! Ed25519 keypairs + real signatures (per feedback_real_not_paperwork).
//!
//! ## Deployment note
//!
//! Production: native UI thread (iOS / Android) calls this helper at
//! `ClientConfig.kt_monitor_interval_secs` cadence (default 3600s = 1h)
//! либо через OS-scheduled background task (BGProcessingTask /
//! WorkManager). In-process Rust tokio periodic task **deliberately not
//! introduced** in session 8c2 — battery + OS lifecycle constraints on
//! mobile prefer foreground/scheduled native invocation over
//! long-running Rust runtime task.

use std::sync::Arc;

use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::kt_monitor::run_kt_self_monitor_once;
use umbrella_client::{ClientConfig, ClientError, UmbrellaClient};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_identity::{
    Clock, DeviceKeyPublic, IdentityKeyPublic, IdentitySeed, IdentityX25519KeyPublic,
    InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_kt::{
    canonical_sign_payload, DeviceAttestationRef, KtEntry, KtError, SignedEpochRoot, WitnessPublic,
    WitnessSet, WitnessSignature,
};

const TEST_EPOCH: u64 = 42;
const TEST_LOG_SIZE: u64 = 1_000_000;
const TEST_TIMESTAMP_MS: u64 = 1_715_000_000_000;
const TEST_THRESHOLD: usize = 3;

fn test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://stub-postman:8080".into(),
        kt_url: "http://stub-kt:8080".into(),
        call_relay_url: "http://stub-call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5 ThresholdConfig"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

#[allow(
    deprecated,
    reason = "test seed gen — same pattern as session 8a/8b tests"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

/// Honest KtEntry matching Alice's keystore (mirrors session 8a helper).
fn honest_alice_entry(alice: &Arc<UmbrellaClient>, epoch: u64) -> KtEntry {
    let ks = alice.core().mls_keystore();
    let identity_ed = ks.identity_public();
    let identity_x = ks.identity_x25519_public();
    let account_id = KtEntry::derive_account_id(&identity_ed);
    let device_pub = ks.device_public(0).expect("alice device 0 registered");
    KtEntry {
        account_id,
        epoch,
        identity_ed25519_pub: identity_ed,
        identity_x25519_pub: identity_x,
        devices: vec![DeviceAttestationRef {
            device_index: 0,
            device_pub,
            attestation_valid_until: u64::MAX,
        }],
    }
}

fn fresh_independent_keystore() -> Arc<InMemoryKeyStore> {
    let seed = test_seed();
    let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
    ks.add_device(0, None).unwrap();
    Arc::new(ks)
}

fn eve_identity_pubkeys() -> (IdentityKeyPublic, IdentityX25519KeyPublic, DeviceKeyPublic) {
    let eve = fresh_independent_keystore();
    (
        eve.identity_public(),
        eve.identity_x25519_public(),
        eve.device_public(0).unwrap(),
    )
}

struct TestWitness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

fn fresh_witness() -> TestWitness {
    let sk = PrivateSigningKey::generate(&mut OsRng);
    let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
    TestWitness { sk, pk }
}

fn fresh_witness_set_of_5() -> (Vec<TestWitness>, WitnessSet) {
    let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
    let mut set = WitnessSet::new();
    for w in &ws {
        set.add(w.pk);
    }
    (ws, set)
}

fn sign_canonical(
    witness: &TestWitness,
    epoch: u64,
    root: &[u8; 32],
    log_size: u64,
    timestamp_ms: u64,
) -> WitnessSignature {
    let payload = canonical_sign_payload(epoch, root, log_size, timestamp_ms);
    let sig = witness.sk.sign(&payload);
    WitnessSignature {
        witness: witness.pk,
        signature: sig.to_bytes(),
    }
}

/// Stage Alice's honest KtEntry + signed root + witness set for `count_signers`
/// of `total_witnesses=5`. Returns the staged tree root, useful for
/// substitution-tampering tests.
async fn stage_honest_alice_log(
    alice: &Arc<UmbrellaClient>,
    epoch: u64,
    count_signers: usize,
) -> [u8; 32] {
    // Own-entry side.
    let entry = honest_alice_entry(alice, epoch);
    let account_id = entry.account_id;
    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, epoch, entry);

    // Witness side.
    let (ws, witness_set) = fresh_witness_set_of_5();
    let root: [u8; 32] = [0xAB; 32]; // arbitrary fixed root
    let signatures = ws
        .iter()
        .take(count_signers)
        .map(|w| sign_canonical(w, epoch, &root, TEST_LOG_SIZE, TEST_TIMESTAMP_MS))
        .collect();
    let signed = SignedEpochRoot {
        epoch,
        root,
        log_size: TEST_LOG_SIZE,
        timestamp_unix_millis: TEST_TIMESTAMP_MS,
        signatures,
    };
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(epoch, signed);
    alice.core().set_kt_witness_set(witness_set).await;
    root
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn run_kt_self_monitor_once_succeeds_when_entry_honest_and_witness_threshold_met() {
    // Combined helper passes both checks: 5/5 honest witness signatures
    // (well above threshold 3) + entry matching Alice's keystore identity.
    let alice = bootstrap_client().await;
    let _root = stage_honest_alice_log(&alice, TEST_EPOCH, 5).await;

    run_kt_self_monitor_once(&alice.core(), TEST_EPOCH, TEST_THRESHOLD)
        .await
        .expect(
            "combined monitor MUST succeed on honest entry + 5/5 signatures over \
             threshold 3",
        );
}

#[tokio::test]
async fn run_kt_self_monitor_once_short_circuits_on_own_entry_failure_skipping_witness_check() {
    // **KEY SHORT-CIRCUIT TEST**: stage a tampered entry (Eve's identity_pk
    // substituted) but DELIBERATELY do NOT stage any signed root либо install
    // a witness set. If short-circuit semantics held — helper fails on
    // own-entry verify with `identity_ed25519_pub` mismatch BEFORE reaching
    // the witness threshold check. If short-circuit broken — helper would
    // continue into witness step which would surface a different error
    // (`InsufficientValidSignatures { valid: 0 }` from absent signed root +
    // empty witness set), exposing the regression.
    let alice = bootstrap_client().await;
    let (eve_identity_ed, _, _) = eve_identity_pubkeys();
    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    tampered.identity_ed25519_pub = eve_identity_ed;
    let account_id = tampered.account_id;
    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, tampered);

    // Deliberately skip: signed root staging, witness set install.

    let result = run_kt_self_monitor_once(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;
    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "identity_ed25519_pub",
                "short-circuit invariant: tampered identity_ed25519_pub MUST be \
                 detected by step 1 (own-entry verify) — witness check MUST NOT \
                 run; if it did, we would see `InsufficientValidSignatures` \
                 instead because no signed root staged and witness set empty; \
                 got field={field}"
            );
        }
        other => panic!(
            "expected `identity_ed25519_pub` mismatch from short-circuit; \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn run_kt_self_monitor_once_propagates_witness_threshold_failure_after_entry_passes() {
    // Stage honest entry + only 2-of-5 signatures (below threshold 3).
    // Step 1 (own-entry verify) MUST pass; step 2 (witness verify) MUST fail
    // with `InsufficientValidSignatures { valid: 2, required: 3 }`. Helper
    // returns the witness error.
    let alice = bootstrap_client().await;
    let _root = stage_honest_alice_log(&alice, TEST_EPOCH, 2).await;

    let result = run_kt_self_monitor_once(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;
    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(valid, 2, "expected 2 valid signatures");
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "expected witness step InsufficientValidSignatures {{ valid: 2, \
             required: 3 }} after own-entry success; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn run_kt_self_monitor_once_fails_with_entry_absent_when_nothing_staged_at_all() {
    // Nothing staged: no entry, no signed root, no witness set. First step
    // (own-entry verify) fails-closed with `entry_absent_from_log` per
    // постулат 14; witness step is short-circuited.
    let alice = bootstrap_client().await;

    let result = run_kt_self_monitor_once(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;
    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "entry_absent_from_log",
                "first step MUST surface entry_absent_from_log fail-closed; \
                 witness step MUST NOT run (else we'd see \
                 InsufficientValidSignatures here); got field={field}"
            );
        }
        other => panic!("expected entry_absent_from_log; got {other:?}"),
    }
}
