//! Integration test: real X-Wing combine integration в max ratchet PQ-extension.
//!
//! Закрывает Task 4.7 carry-over из max-ratchet v3 spec 2026-05-20 §7.1: до этого
//! `pq_extension_used` был flag-only (paperwork finding); теперь под ciphersuite 0x004D
//! + `UmbrellaXWingProvider` PQ-derived shared secret реально извлекается из exporter
//! нового epoch'a и комбинируется с classical epoch secret через
//! `spqr::pq_extend_epoch_secret` для SPQR HMAC keying material.
//!
//! Тестируем что:
//! 1. [`UmbrellaGroup::force_rekey_with_pq`] возвращает non-zero pq_shared под X-Wing
//!    ciphersuite + `UmbrellaXWingProvider`.
//! 2. Последовательные `force_rekey_with_pq` produce различные pq_shared (per-epoch fresh).
//! 3. [`MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`] устанавливает
//!    `pq_extension_used=true` ровно на каждом 3-м commit'е (counter triggers).
//! 4. SPQR HMAC при PQ-extension через `pq_extend_epoch_secret(classical, pq)` отличается
//!    от classical-only HMAC того же ciphertext'а — proves что pq_shared реально
//!    задействован в keying material для PQ-triggered sends.
//! 5. Counter resets PQ-extension flag правильно (sends 1, 2 — no PQ; send 3 — PQ;
//!    sends 4, 5 — no PQ; send 6 — PQ).
//!
//! Integration test: real X-Wing combine integration in max ratchet PQ-extension. Closes
//! Task 4.7 carry-over from the max-ratchet v3 spec 2026-05-20 §7.1.
//!
//! Без feature `pq` тест compile-time skip'ается через `#![cfg(feature = "pq")]`.
//!
//! Without feature `pq`, this test is compile-time skipped via
//! `#![cfg(feature = "pq")]`.

#![cfg(feature = "pq")]

use std::sync::Arc;

use openmls::group::GroupId;

#[allow(deprecated)]
use umbrella_identity::IdentitySeed;
use umbrella_identity::{
    keystore::FixedClock, Clock, InMemoryKeyStore, KeyStore, MnemonicLanguage,
};
use umbrella_mls::max_ratchet::spqr;
use umbrella_mls::{
    provider::UmbrellaXWingProvider, MaxRatchetGroup, UmbrellaCiphersuite, UmbrellaGroup,
};

/// X-Wing ciphersuite (0x004D) — real PQ combine MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.
const CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519;

const T0: u64 = 1_700_000_000;

/// Тестовый клиент: keystore + UmbrellaXWingProvider + device index.
struct PqClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaXWingProvider,
    device_index: u32,
}

impl PqClient {
    fn new(device_index: u32) -> Self {
        let mut rng = rand_core::OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let clock = FixedClock::new(T0);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(clock) as Arc<dyn Clock>)
            .expect("InMemoryKeyStore::open");
        ks.add_device(device_index, None).expect("add_device");
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaXWingProvider::new_for_kat_tests_only(),
            device_index,
        }
    }
}

fn fresh_xwing_group(client: &PqClient, tag: u8) -> UmbrellaGroup {
    UmbrellaGroup::create_private(
        &client.provider,
        client.ks.as_ref(),
        client.device_index,
        CS,
        GroupId::from_slice(&[tag; 16]),
        T0,
    )
    .expect("UmbrellaGroup::create_private with X-Wing ciphersuite 0x004D")
}

// =============================================================================
// Test 1: force_rekey_with_pq returns non-zero PQ-derived secret
// =============================================================================

#[test]
fn force_rekey_with_pq_returns_nonzero_pq_shared_on_xwing_group() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xC1);
    assert!(
        group.ciphersuite().is_post_quantum_hybrid(),
        "test setup: ciphersuite must be PQ hybrid"
    );

    let (commit_bytes, pq_secret) = group
        .force_rekey_with_pq(&alice.provider, alice.ks.as_ref(), T0 + 1)
        .expect("force_rekey_with_pq under X-Wing ciphersuite must succeed");

    assert!(
        !commit_bytes.is_empty(),
        "commit_bytes must be non-empty TLS-serialized MlsMessage"
    );
    assert_ne!(
        pq_secret,
        [0u8; 32],
        "pq_secret must not be all-zero — exporter under X-Wing ciphersuite must yield real keying material"
    );
    assert_ne!(
        pq_secret,
        [0xFFu8; 32],
        "pq_secret must not be all-0xFF (sanity check that bytes are filled from exporter, not stack garbage)"
    );
}

// =============================================================================
// Test 2: consecutive epochs produce different PQ shared secrets
// =============================================================================

#[test]
fn force_rekey_with_pq_changes_pq_shared_across_consecutive_epochs() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xC2);

    let initial_epoch = group.epoch();

    let (_commit1, secret1) = group
        .force_rekey_with_pq(&alice.provider, alice.ks.as_ref(), T0 + 1)
        .expect("first force_rekey_with_pq");
    assert_eq!(group.epoch(), initial_epoch + 1);

    let (_commit2, secret2) = group
        .force_rekey_with_pq(&alice.provider, alice.ks.as_ref(), T0 + 2)
        .expect("second force_rekey_with_pq");
    assert_eq!(group.epoch(), initial_epoch + 2);

    assert_ne!(
        secret1, secret2,
        "consecutive force_rekey_with_pq must produce different pq_shared (per-epoch fresh)"
    );
}

// =============================================================================
// Test 3: PQ extension flag triggers on every 3rd send by default
// =============================================================================

#[test]
fn encrypt_with_rekey_pq_authenticated_triggers_pq_extension_on_3rd_send() {
    let alice = PqClient::new(0);
    let group = fresh_xwing_group(&alice, 0xC3);
    let mut max_group = MaxRatchetGroup::new(group);

    // Send 6 messages; default pq_ratchet_every_n_commits = 3 → triggers on commit 3 and 6.
    let mut outgoings = Vec::with_capacity(6);
    for i in 1..=6u64 {
        let outgoing = max_group
            .encrypt_with_rekey_pq_authenticated(
                &alice.provider,
                alice.ks.as_ref(),
                format!("message {}", i).as_bytes(),
                T0 + i,
            )
            .unwrap_or_else(|e| panic!("encrypt_with_rekey_pq_authenticated send #{i}: {e:?}"));
        outgoings.push(outgoing);
    }

    // Sends 1, 2, 4, 5 — no PQ extension; sends 3, 6 — PQ extension.
    assert!(!outgoings[0].pq_extension_used, "send #1 must not trigger PQ");
    assert!(!outgoings[1].pq_extension_used, "send #2 must not trigger PQ");
    assert!(
        outgoings[2].pq_extension_used,
        "send #3 must trigger PQ (counter % 3 == 0)"
    );
    assert!(!outgoings[3].pq_extension_used, "send #4 must not trigger PQ");
    assert!(!outgoings[4].pq_extension_used, "send #5 must not trigger PQ");
    assert!(
        outgoings[5].pq_extension_used,
        "send #6 must trigger PQ (counter % 3 == 0)"
    );

    // All 6 must have SPQR mac present.
    for (i, outgoing) in outgoings.iter().enumerate() {
        let mac = outgoing
            .spqr_mac
            .as_ref()
            .unwrap_or_else(|| panic!("send #{} must have SPQR mac", i + 1));
        assert_eq!(
            mac.len(),
            32,
            "send #{} SPQR mac must be 32 bytes (HMAC-SHA256)",
            i + 1
        );
    }
}

// =============================================================================
// Test 4: PQ-triggered SPQR mac uses pq_extended keying material
// =============================================================================
//
// Demonstrates: на 3-ем sentence, SPQR mac вычислен через pq_extend_epoch_secret(classical, pq).
// Если бы мы взяли тот же ciphertext + только classical_epoch_secret из того же epoch'a,
// HMAC бы отличался. Это доказывает что pq_shared реально влияет на keying material
// (не просто flag toggling).

#[test]
fn pq_triggered_mac_differs_from_classical_only_mac_on_same_ciphertext() {
    let alice = PqClient::new(0);
    let group = fresh_xwing_group(&alice, 0xC4);
    let mut max_group = MaxRatchetGroup::new(group);

    // Drive counter до 3 (PQ trigger point).
    for i in 1..=3u64 {
        max_group
            .encrypt_with_rekey_pq_authenticated(
                &alice.provider,
                alice.ks.as_ref(),
                format!("warmup {}", i).as_bytes(),
                T0 + i,
            )
            .expect("warmup send");
    }

    // Now send #3 just happened — pq_extension_used=true. Get the last outgoing.
    // Send another (4) → next triggered on #6. To get a triggered send, we already have
    // outgoing #3 from warmup loop. Re-call instead.
    let triggered_outgoing = {
        let alice2 = PqClient::new(1);
        let group2 = fresh_xwing_group(&alice2, 0xC5);
        let mut max_group2 = MaxRatchetGroup::new(group2);
        // Drive до send 3 — это будет PQ-triggered.
        for i in 1..=2u64 {
            max_group2
                .encrypt_with_rekey_pq_authenticated(
                    &alice2.provider,
                    alice2.ks.as_ref(),
                    format!("warm {}", i).as_bytes(),
                    T0 + i,
                )
                .expect("warm send");
        }
        // Send 3 — PQ trigger:
        let out = max_group2
            .encrypt_with_rekey_pq_authenticated(
                &alice2.provider,
                alice2.ks.as_ref(),
                b"trigger payload",
                T0 + 3,
            )
            .expect("trigger send");
        assert!(out.pq_extension_used, "this send must be PQ-triggered");
        (out, alice2, max_group2)
    };

    // Compute classical-only mac over the same ciphertext (using just exporter_secret of the
    // current epoch, без pq_extend). Если результат отличается от triggered_outgoing.spqr_mac,
    // тогда pq_shared реально комбинируется в SPQR keying.
    let (outgoing, alice2, max_group2) = triggered_outgoing;
    let exporter = max_group2
        .inner()
        .exporter_secret(&alice2.provider, "umbrellax-spqr-deniable-auth", b"", 32)
        .expect("exporter_secret");
    let classical_only_secret =
        spqr::derive_epoch_secret_from_exporter(&exporter.expose()[..32])
            .expect("classical epoch secret");
    let classical_only_mac = spqr::compute_hmac(&classical_only_secret, &outgoing.ciphertext_bytes);

    let pq_extended_mac = outgoing
        .spqr_mac
        .as_ref()
        .expect("PQ-triggered send must have spqr_mac");
    assert_eq!(pq_extended_mac.len(), 32);

    assert_ne!(
        classical_only_mac.as_slice(),
        pq_extended_mac.as_slice(),
        "PQ-extended HMAC must differ from classical-only HMAC of the same ciphertext — proves \
         pq_shared is really used in SPQR keying material (not just a flag)"
    );
}

// =============================================================================
// Test 5: epoch advances on every send (aggressive DH preserved)
// =============================================================================

#[test]
fn encrypt_with_rekey_pq_authenticated_advances_epoch_per_message() {
    let alice = PqClient::new(0);
    let group = fresh_xwing_group(&alice, 0xC6);
    let mut max_group = MaxRatchetGroup::new(group);

    let initial_epoch = max_group.inner().epoch();

    for i in 1..=4u64 {
        let out = max_group
            .encrypt_with_rekey_pq_authenticated(
                &alice.provider,
                alice.ks.as_ref(),
                b"epoch test",
                T0 + i,
            )
            .expect("send");
        assert_eq!(
            max_group.inner().epoch(),
            initial_epoch + i,
            "epoch must advance by 1 on each PQ-authenticated send (aggressive DH ratchet preserved under PQ provider)"
        );
        assert_eq!(out.epoch_after_send, initial_epoch + i);
        assert!(out.commit_bytes.is_some(), "commit_bytes must be present");
    }
}

// =============================================================================
// Test 6: counter precisely matches commit_counter() public accessor
// =============================================================================

#[test]
fn commit_counter_increments_under_pq_authenticated_path() {
    let alice = PqClient::new(0);
    let group = fresh_xwing_group(&alice, 0xC7);
    let mut max_group = MaxRatchetGroup::new(group);

    assert_eq!(max_group.commit_counter(), 0, "initial counter");

    for i in 1..=5u64 {
        max_group
            .encrypt_with_rekey_pq_authenticated(
                &alice.provider,
                alice.ks.as_ref(),
                b"counter test",
                T0 + i,
            )
            .expect("send");
        assert_eq!(
            max_group.commit_counter(),
            i as u32,
            "counter must equal send number"
        );
    }
}
