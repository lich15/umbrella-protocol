//! Integration test: real X-Wing combine integration via `MaxRatchetState` borrowed-mode path.
//!
//! Task 1 (post-v3) carry-over closure 2026-05-21: `MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`
//! уже доказан в `test_max_ratchet_pq_real.rs` (owned-mode wrapper). Текущий integration test
//! доказывает что **borrowed-mode** `MaxRatchetState` (используемый facade-слоем CloudChat /
//! SecretChat через `ClientCore.ratchet_states` HashMap) тоже корректно routes к real X-Wing
//! combine integration когда caller передаёт `UmbrellaXWingProvider` + group создан на ciphersuite
//! 0x004D.
//!
//! Закрывает API gap noted в memory `project_max_ratchet_v3_spec` 2026-05-20:
//! «MaxRatchetState path (используемая в facade) не routes к encrypt_with_rekey_pq_authenticated
//! automatically для ciphersuite 0x004D groups». После этого commit метод существует и доступен
//! direct callers; facade dispatch (требует `pq_provider` field в ClientCore — sweeping refactor)
//! остаётся carry-over к Stage 11+.
//!
//! Тестируем (parallel coverage с `MaxRatchetGroup` test suite):
//! 1. `MaxRatchetState::encrypt_with_rekey_pq_authenticated` triggers PQ extension на каждом 3-м
//!    commit'е (counter % 3 == 0).
//! 2. SPQR HMAC на PQ-triggered send отличается от classical-only HMAC того же ciphertext —
//!    доказывает что pq_shared реально влияет на keying material через borrowed-mode path
//!    (не только через owned-mode).
//! 3. Epoch advances on every send (aggressive DH ratchet preserved).
//! 4. Commit counter increments под borrowed-mode path.
//!
//! Integration test: real X-Wing combine integration via `MaxRatchetState` borrowed-mode path.
//! Closes the post-v3 carry-over API gap for facade-layer PQ routing. Without feature `pq` the
//! test is compile-time skipped via `#![cfg(feature = "pq")]`.

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
    provider::UmbrellaXWingProvider, MaxRatchetState, UmbrellaCiphersuite, UmbrellaGroup,
};

const CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519;
const T0: u64 = 1_700_000_000;

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
// Test 1: borrowed-mode state PQ path triggers PQ extension on send 3 + 6
// =============================================================================

#[test]
fn state_encrypt_pq_authenticated_triggers_pq_on_every_3rd_send() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xD1);
    let mut state = MaxRatchetState::new();

    let mut outgoings = Vec::with_capacity(6);
    for i in 1..=6u64 {
        let outgoing = state
            .encrypt_with_rekey_pq_authenticated(
                &mut group,
                &alice.provider,
                alice.ks.as_ref(),
                format!("borrowed-mode msg {i}").as_bytes(),
                T0 + i,
            )
            .unwrap_or_else(|e| {
                panic!("state.encrypt_with_rekey_pq_authenticated send #{i}: {e:?}")
            });
        outgoings.push(outgoing);
    }

    // Default pq_ratchet_every_n_commits = 3 → triggers on sends 3 and 6.
    assert!(
        !outgoings[0].pq_extension_used,
        "send #1 must not trigger PQ"
    );
    assert!(
        !outgoings[1].pq_extension_used,
        "send #2 must not trigger PQ"
    );
    assert!(
        outgoings[2].pq_extension_used,
        "send #3 must trigger PQ (counter % 3 == 0) under borrowed-mode state path"
    );
    assert!(
        !outgoings[3].pq_extension_used,
        "send #4 must not trigger PQ"
    );
    assert!(
        !outgoings[4].pq_extension_used,
        "send #5 must not trigger PQ"
    );
    assert!(
        outgoings[5].pq_extension_used,
        "send #6 must trigger PQ (counter % 3 == 0)"
    );

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
// Test 2: PQ-triggered mac differs from classical-only — real X-Wing keying via state path
// =============================================================================

#[test]
fn state_pq_triggered_mac_differs_from_classical_only_mac_on_same_ciphertext() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xD2);
    let mut state = MaxRatchetState::new();

    // Warm-up sends 1 + 2 (no PQ trigger).
    for i in 1..=2u64 {
        state
            .encrypt_with_rekey_pq_authenticated(
                &mut group,
                &alice.provider,
                alice.ks.as_ref(),
                format!("warm {i}").as_bytes(),
                T0 + i,
            )
            .expect("warm send");
    }

    // Send 3 — PQ trigger.
    let triggered = state
        .encrypt_with_rekey_pq_authenticated(
            &mut group,
            &alice.provider,
            alice.ks.as_ref(),
            b"trigger payload via state path",
            T0 + 3,
        )
        .expect("trigger send");
    assert!(
        triggered.pq_extension_used,
        "send #3 must be PQ-triggered under borrowed-mode state path"
    );

    // Compute classical-only mac of the same ciphertext using ONLY the exporter_secret
    // of the current epoch (no pq_extend). If the two macs differ → pq_shared влияет
    // на SPQR keying через borrowed-mode path (real X-Wing integration, not paperwork flag).
    let exporter = group
        .exporter_secret(&alice.provider, "umbrellax-spqr-deniable-auth", b"", 32)
        .expect("exporter_secret");
    let classical_only_secret = spqr::derive_epoch_secret_from_exporter(&exporter.expose()[..32])
        .expect("classical epoch secret");
    let classical_only_mac =
        spqr::compute_hmac(&classical_only_secret, &triggered.ciphertext_bytes);

    let pq_extended_mac = triggered
        .spqr_mac
        .as_ref()
        .expect("PQ-triggered send must have spqr_mac");
    assert_eq!(pq_extended_mac.len(), 32);
    assert_ne!(
        classical_only_mac.as_slice(),
        pq_extended_mac.as_slice(),
        "PQ-extended HMAC must differ from classical-only HMAC of the same ciphertext under \
         borrowed-mode state path — proves pq_shared реально комбинируется в SPQR keying \
         material через MaxRatchetState (parity с MaxRatchetGroup owned-mode coverage)"
    );
}

// =============================================================================
// Test 3: epoch advances every send (aggressive DH ratchet preserved on borrowed-mode path)
// =============================================================================

#[test]
fn state_encrypt_pq_authenticated_advances_epoch_per_message() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xD3);
    let mut state = MaxRatchetState::new();

    let initial_epoch = group.epoch();

    for i in 1..=4u64 {
        let out = state
            .encrypt_with_rekey_pq_authenticated(
                &mut group,
                &alice.provider,
                alice.ks.as_ref(),
                b"borrowed epoch test",
                T0 + i,
            )
            .expect("send");
        assert_eq!(
            group.epoch(),
            initial_epoch + i,
            "epoch must advance by 1 on each PQ-authenticated send under borrowed-mode state path"
        );
        assert_eq!(out.epoch_after_send, initial_epoch + i);
        assert!(
            out.commit_bytes.is_some(),
            "commit_bytes must be present on aggressive DH path"
        );
    }
}

// =============================================================================
// Test 4: commit counter increments under borrowed-mode PQ path
// =============================================================================

#[test]
fn state_commit_counter_increments_under_pq_authenticated_path() {
    let alice = PqClient::new(0);
    let mut group = fresh_xwing_group(&alice, 0xD4);
    let mut state = MaxRatchetState::new();

    assert_eq!(
        state.commit_counter(),
        0,
        "initial counter under state path"
    );

    for i in 1..=5u64 {
        state
            .encrypt_with_rekey_pq_authenticated(
                &mut group,
                &alice.provider,
                alice.ks.as_ref(),
                b"borrowed counter test",
                T0 + i,
            )
            .expect("send");
        assert_eq!(
            state.commit_counter(),
            i as u32,
            "counter must equal send number under borrowed-mode state path"
        );
    }
}

// =============================================================================
// Test 5: parity — borrowed-mode and owned-mode produce identical externals for same group
// =============================================================================
//
// Real evidence что borrowed-mode path не drift'ит от owned-mode: same plaintext + same
// group + same provider должны давать identical externals (epoch advance, counter trigger,
// pq_extension_used flag, ciphertext byte-equality NOT required — MLS nonce changes per call).
// Тестируем что counter + epoch invariants выполняются равно.

#[test]
fn state_and_group_paths_agree_on_counter_and_pq_trigger_semantics() {
    use umbrella_mls::MaxRatchetGroup;

    // Borrowed-mode path.
    let alice_a = PqClient::new(0);
    let mut group_a = fresh_xwing_group(&alice_a, 0xD5);
    let mut state = MaxRatchetState::new();
    let mut state_outs = Vec::new();
    for i in 1..=4u64 {
        state_outs.push(
            state
                .encrypt_with_rekey_pq_authenticated(
                    &mut group_a,
                    &alice_a.provider,
                    alice_a.ks.as_ref(),
                    b"parity",
                    T0 + i,
                )
                .expect("borrowed send"),
        );
    }

    // Owned-mode path on fresh group.
    let alice_b = PqClient::new(1);
    let group_b = fresh_xwing_group(&alice_b, 0xD6);
    let mut max_group = MaxRatchetGroup::new(group_b);
    let mut group_outs = Vec::new();
    for i in 1..=4u64 {
        group_outs.push(
            max_group
                .encrypt_with_rekey_pq_authenticated(
                    &alice_b.provider,
                    alice_b.ks.as_ref(),
                    b"parity",
                    T0 + i,
                )
                .expect("owned send"),
        );
    }

    // Counter trigger semantics — must match across both paths.
    assert_eq!(state.commit_counter(), max_group.commit_counter());
    for i in 0..4 {
        assert_eq!(
            state_outs[i].pq_extension_used,
            group_outs[i].pq_extension_used,
            "send #{} pq_extension_used must agree между borrowed-mode и owned-mode paths",
            i + 1
        );
        assert_eq!(
            state_outs[i].epoch_after_send,
            group_outs[i].epoch_after_send,
            "send #{} epoch_after_send must agree (both paths advance epoch identically)",
            i + 1
        );
    }
}
