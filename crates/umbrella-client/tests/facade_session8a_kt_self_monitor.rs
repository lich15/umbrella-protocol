//! F-CLIENT-FACADE-1 closure session 8a (2026-05-19): contract tests for
//! [`umbrella_client::kt_monitor::verify_own_kt_entry_for_epoch`]. Closes
//! the **ghost participant** attack class (Levy & Robinson, Lawfare 2018)
//! at the facade-on-demand level: client stages own expected KtEntry via
//! [`StubKtTransport::push_staged_entry`], facade fetches + verifies; any
//! substitution attack (foreign identity_pk / X25519 / device_pub / wrong
//! account_id / missing entry / device-count drift) → fail-closed
//! `ClientError::Kt(KtError::SelfMonitoringMismatch { field })` per
//! постулат 14 (no silent acceptance).
//!
//! ## Coverage (7 tests)
//!
//! 1. `verify_own_kt_entry_succeeds_on_honest_staged_entry_matching_keystore_identity_and_device_set`
//!    — happy path: stub stages entry with Alice's correct identity_ed25519,
//!    X25519, account_id, device 0 → verify succeeds.
//! 2. `verify_own_kt_entry_fails_closed_when_no_entry_staged_for_epoch`
//!    — постулат 14 fail-closed: missing entry → SelfMonitoringMismatch
//!    `entry_absent_from_log`.
//! 3. `verify_own_kt_entry_detects_substituted_identity_ed25519_pub_ghost_participant_attack`
//!    — KEY TEST: stub stages entry with Eve's identity_ed25519_pub
//!    (substitution) → mismatch `identity_ed25519_pub`.
//! 4. `verify_own_kt_entry_detects_substituted_identity_x25519_pub_sealed_sender_ghost_attack`
//!    — stub stages entry with Eve's X25519 (would route sealed-sender
//!    envelopes к Eve) → mismatch `identity_x25519_pub`.
//! 5. `verify_own_kt_entry_detects_injected_foreign_device_pubkey_mitm_attack`
//!    — stub stages entry with foreign device_pub for index 0
//!    (adversary-controlled device-key injection) → mismatch
//!    `device_set_missing_expected` / `device_set_unexpected_entry`.
//! 6. `verify_own_kt_entry_detects_wrong_account_id_log_corruption_or_identity_rotation_inconsistency`
//!    — stub stages entry with mismatched account_id (≠ SHA-256(identity_ed))
//!    → mismatch `account_id`.
//! 7. `verify_own_kt_entry_detects_missing_device_via_device_count_field_mismatch`
//!    — stub stages entry without expected device 0 → mismatch
//!    `device_count`.

use std::sync::Arc;

use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::kt_monitor::verify_own_kt_entry_for_epoch;
use umbrella_client::{ClientConfig, ClientError, UmbrellaClient};
use umbrella_identity::{
    Clock, DeviceKeyPublic, IdentityKeyPublic, IdentitySeed, IdentityX25519KeyPublic,
    InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_kt::{DeviceAttestationRef, KtEntry, KtError};

const TEST_EPOCH: u64 = 42;

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
    reason = "test seed gen — same pattern as facade_session6_postman.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

/// Construct an honest KtEntry that matches Alice's keystore: same
/// identity_ed25519_pub, identity_x25519_pub, derived account_id, and her
/// own device 0 pubkey.
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

/// Build a fresh independent keystore (Eve / foreign device key source).
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

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn verify_own_kt_entry_succeeds_on_honest_staged_entry_matching_keystore_identity_and_device_set(
) {
    let alice = bootstrap_client().await;
    let entry = honest_alice_entry(&alice, TEST_EPOCH);
    let account_id = entry.account_id;

    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, entry);

    verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH)
        .await
        .expect(
            "honest staged entry matching Alice's identity_pks + device 0 \
             MUST pass self-monitor without errors",
        );
}

#[tokio::test]
async fn verify_own_kt_entry_fails_closed_when_no_entry_staged_for_epoch() {
    let alice = bootstrap_client().await;
    // Deliberately do NOT push any entry — KT log "returns" nothing для
    // Alice's (account_id, TEST_EPOCH) lookup.
    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "entry_absent_from_log",
                "missing entry MUST report `entry_absent_from_log` field token \
                 (постулат 14 fail-closed — no silent Ok); got {field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: \"entry_absent_from_log\" }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_detects_substituted_identity_ed25519_pub_ghost_participant_attack() {
    // Levy-Robinson "ghost participant" attack: KT log serves entry с Eve's
    // identity_ed25519_pub под Alice's account_id. Если monitor пропустит —
    // MLS примет Eve как Alice через credential mismatch downstream.
    let alice = bootstrap_client().await;
    let (eve_identity_ed, _, _) = eve_identity_pubkeys();

    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    tampered.identity_ed25519_pub = eve_identity_ed;
    let account_id = tampered.account_id;

    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, tampered);

    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "identity_ed25519_pub",
                "ghost-participant substitution of identity_ed25519_pub MUST \
                 be detected; got field={field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: \"identity_ed25519_pub\" }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_detects_substituted_identity_x25519_pub_sealed_sender_ghost_attack() {
    // X25519 substitution attack: KT log entry carries Eve's X25519 — future
    // sealed-sender envelopes routed к Alice's contacts encrypt'aлись бы под
    // Eve's X25519 (Eve decrypts, не Alice). Monitor должен detect'ить.
    let alice = bootstrap_client().await;
    let (_, eve_identity_x, _) = eve_identity_pubkeys();

    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    tampered.identity_x25519_pub = eve_identity_x;
    let account_id = tampered.account_id;

    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, tampered);

    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "identity_x25519_pub",
                "X25519 substitution attack MUST be detected; got field={field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: \"identity_x25519_pub\" }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_detects_injected_foreign_device_pubkey_mitm_attack() {
    // Device-key injection: log entry содержит Alice's identity_pks (passes
    // first 2 checks), но device 0 pubkey = Eve's device pubkey. MLS group
    // дальше уважал бы Eve's device_pub при signing → Eve decrypts group
    // messages.
    let alice = bootstrap_client().await;
    let (_, _, eve_device_pub) = eve_identity_pubkeys();

    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    tampered.devices[0].device_pub = eve_device_pub;
    let account_id = tampered.account_id;

    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, tampered);

    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            // verify_own_entry's device-set check iteratively сравнивает: для
            // Alice's expected device 0 не находит matching `(0, device_pub)`
            // в entry → "device_set_missing_expected". Если Alice имела бы
            // multiple devices и entry содержал бы их + foreign extra,
            // surfaced бы как "device_set_unexpected_entry". Single-device
            // setup гарантирует первый branch.
            assert!(
                field == "device_set_missing_expected" || field == "device_set_unexpected_entry",
                "foreign device pubkey injection MUST be detected; expected \
                 `device_set_missing_expected` либо `device_set_unexpected_entry`; \
                 got field={field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: device_set_* }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_detects_wrong_account_id_log_corruption_or_identity_rotation_inconsistency(
) {
    // account_id MUST = SHA-256(identity_ed25519_pub) per KtEntry::derive_account_id.
    // Entry с substituted account_id (но correct identity_ed) сигнализирует
    // log corruption либо identity rotation desync.
    let alice = bootstrap_client().await;
    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    let real_account_id = tampered.account_id;
    let bogus_account_id = [0xAAu8; 32];
    tampered.account_id = bogus_account_id;

    // Note: we stage entry под bogus key (matches what server would return
    // when it serves Alice's account_id lookup но с corrupted entry data).
    // Actually wait — the stub fetches by key (account_id, epoch). So if we
    // stage под bogus_account_id, fetch under real_account_id returns None
    // → entry_absent_from_log. To exercise the account_id mismatch path,
    // stage entry с tampered.account_id = bogus, но push it under REAL
    // account_id key (server bug: lookup hit на real key but entry has wrong
    // account_id inside).
    alice
        .core()
        .kt_transport()
        .push_staged_entry(real_account_id, TEST_EPOCH, tampered);

    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "account_id",
                "wrong account_id inside otherwise-correct entry MUST be \
                 detected; got field={field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: \"account_id\" }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_detects_missing_device_via_device_count_field_mismatch() {
    // Server returns entry без Alice's primary device 0 (denial-of-device or
    // device-list truncation attack). Alice expects device 0, log says no
    // devices → mismatch on device_count.
    let alice = bootstrap_client().await;
    let mut tampered = honest_alice_entry(&alice, TEST_EPOCH);
    tampered.devices.clear();
    let account_id = tampered.account_id;

    alice
        .core()
        .kt_transport()
        .push_staged_entry(account_id, TEST_EPOCH, tampered);

    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "device_count",
                "missing device 0 MUST be detected through device_count \
                 mismatch (entry has 0 devices, expected has 1); got \
                 field={field}"
            );
        }
        other => panic!(
            "expected ClientError::Kt(SelfMonitoringMismatch {{ field: \"device_count\" }}), \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_own_kt_entry_invariant_separate_account_ids_isolate_alice_from_bob_lookups() {
    // Sanity guard на stub keying: Bob's entry (stored под Bob's account_id)
    // НЕ влияет на Alice's lookup. Alice's lookup with no Alice entry staged
    // returns entry_absent_from_log даже когда Bob's entry присутствует под
    // его account_id. Prevents test scaffolding bugs where stub
    // cross-pollinates entries across accounts.
    let alice = bootstrap_client().await;
    let bob = bootstrap_client().await;

    let bob_entry = honest_alice_entry(&bob, TEST_EPOCH);
    let bob_account_id = bob_entry.account_id;
    alice
        .core()
        .kt_transport()
        .push_staged_entry(bob_account_id, TEST_EPOCH, bob_entry);

    // Alice's monitor lookup MUST NOT find Bob's entry.
    let result = verify_own_kt_entry_for_epoch(&alice.core(), TEST_EPOCH).await;
    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "entry_absent_from_log",
                "stub keying invariant: Bob's entry MUST NOT be returned for \
                 Alice's account_id lookup; got field={field}"
            );
        }
        other => panic!("expected entry_absent_from_log for Alice, got {other:?}"),
    }

    // Sanity check: Bob CAN find his own entry on this stub (proves the entry
    // was actually staged, не silently dropped).
    let bob_account_real = bob.core().mls_keystore().identity_public();
    let bob_acc_id = KtEntry::derive_account_id(&bob_account_real);
    assert_eq!(bob_acc_id, bob_account_id);
    let bob_fetched = alice
        .core()
        .kt_transport()
        .fetch_staged_entry(&bob_account_id, TEST_EPOCH);
    assert!(
        bob_fetched.is_some(),
        "Bob's entry was staged and should still be fetchable by account_id"
    );
}
