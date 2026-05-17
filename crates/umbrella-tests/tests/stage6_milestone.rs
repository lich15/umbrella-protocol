//! Milestone end-to-end сценарии для Этапа 6 — Calls.
//! Milestone end-to-end scenarios for Stage 6 — Calls.
//!
//! Пять сценариев по private calls and IP privacy notes §10.3 и SPEC-06 §13:
//!
//! 1. DTLS identity binding (mutual fingerprint).
//! 2. Group call 5 участников — 100 кадров round-trip через MLS base_key.
//! 3. Rekey при MLS epoch advance (Add Dave).
//! 4. Forward-secrecy после Remove (Carol).
//! 5. Anti-replay realistic (reorder + replay reject + повторный accept).
//!
//! Никаких mock'ов — полная интеграция `umbrella-calls` + `umbrella-mls` +
//! `umbrella-identity`. Проверяем что слои 6.2-6.5 работают вместе на
//! реальном пути: MLS exporter → SframeBaseKey → encrypt_frame →
//! decrypt_frame на стороне получателя.
//!
//! No mocks — full integration of `umbrella-calls` + `umbrella-mls` +
//! `umbrella-identity`. Checks that blocks 6.2-6.5 actually compose on the
//! real path: MLS exporter → SframeBaseKey → encrypt_frame → decrypt_frame
//! on the receiver side.

use std::sync::Arc;

use openmls::group::GroupId;
use secrecy::ExposeSecret;

use umbrella_calls::{
    compute_mutual_identity_binding, CallError, IdentityDtlsFingerprint, SframeBaseKey,
    SframeCiphersuite, SframeContext, BASE_KEY_LEN, MLS_EXPORTER_LABEL,
};
use umbrella_identity::{IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider, UMBRELLA_DEFAULT_CIPHERSUITE,
};

const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;
const T0: u64 = 1_700_000_000;

// ================= Helpers =================

/// Один тестовый клиент: keystore + provider + device_index.
/// One test client: keystore + provider + device_index.
struct Client {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
    identity_pubkey: [u8; 32],
}

impl Client {
    fn new() -> Self {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock)).unwrap();
        ks.add_device(0, None).unwrap();
        let identity_pubkey = ks.identity_public().to_bytes();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index: 0,
            identity_pubkey,
        }
    }

    fn publish_key_package(&self) -> openmls::key_packages::KeyPackage {
        build_device_key_package(
            &self.provider,
            self.ks.as_ref() as &dyn KeyStore,
            self.device_index,
            CS,
        )
        .unwrap()
        .key_package()
        .clone()
    }
}

/// Выводит SFrame base_key из MLS группы для текущей эпохи.
/// Derives SFrame base_key from the MLS group for the current epoch.
fn base_key_from_group(group: &UmbrellaGroup, provider: &UmbrellaProvider) -> SframeBaseKey {
    let epoch = group.epoch();
    let epoch_ctx = epoch.to_be_bytes();
    let secret = group
        .exporter_secret(provider, MLS_EXPORTER_LABEL, &epoch_ctx, BASE_KEY_LEN)
        .expect("exporter_secret");
    let mut bytes = [0u8; BASE_KEY_LEN];
    // Round-5 device-capture closure F-PHD-DC-R11-1: `secret` теперь
    // `MlockedSecret<[u8; MAX_EXPORTER_LEN]>` → `.expose()` вместо `.expose_secret()`.
    // Round-5 device-capture closure F-PHD-DC-R11-1: `secret` is now
    // `MlockedSecret<[u8; MAX_EXPORTER_LEN]>` → `.expose()` instead of `.expose_secret()`.
    bytes.copy_from_slice(&secret.expose()[..BASE_KEY_LEN]);
    SframeBaseKey::from_mls_exporter(bytes, SframeCiphersuite::Aes256GcmSha512, epoch)
}

fn fresh_gid(tag: u8) -> GroupId {
    GroupId::from_slice(&[tag; 16])
}

// ================= Сценарий 1: DTLS identity binding =================

#[test]
fn scenario_1_dtls_identity_binding_mutual() {
    let alice = Client::new();
    let bob = Client::new();
    let session_nonce = [0x42u8; 16];

    // Alice и Bob независимо выводят mutual fingerprint — результаты совпадают.
    // Alice and Bob independently derive the mutual fingerprint — outputs agree.
    let from_alice = compute_mutual_identity_binding(
        &alice.identity_pubkey,
        &bob.identity_pubkey,
        &session_nonce,
    );
    let from_bob = compute_mutual_identity_binding(
        &bob.identity_pubkey,
        &alice.identity_pubkey,
        &session_nonce,
    );
    assert_eq!(from_alice, from_bob, "mutual fingerprint must be symmetric");

    // Personal fingerprints — разные.
    // Personal fingerprints — different.
    let alice_fp = IdentityDtlsFingerprint::derive(&alice.identity_pubkey, &session_nonce);
    let bob_fp = IdentityDtlsFingerprint::derive(&bob.identity_pubkey, &session_nonce);
    assert!(!alice_fp.verify_constant_time(&bob_fp));

    // Tampered identity → mutual не совпадает с честно вычисленным.
    // Tampered identity → mutual no longer matches the honest value.
    let mut tampered = alice.identity_pubkey;
    tampered[0] ^= 0x01;
    let from_tampered =
        compute_mutual_identity_binding(&tampered, &bob.identity_pubkey, &session_nonce);
    assert_ne!(from_tampered, from_alice);
}

// ================= Сценарий 2: Group call 5 участников, 100 кадров =================

#[test]
fn scenario_2_group_call_5_participants_100_frames() {
    let alice = Client::new();
    let bob = Client::new();
    let carol = Client::new();
    let dave = Client::new();
    let eve = Client::new();

    let bob_kp = bob.publish_key_package();
    let carol_kp = carol.publish_key_package();
    let dave_kp = dave.publish_key_package();
    let eve_kp = eve.publish_key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        fresh_gid(0x51),
        T0,
    )
    .unwrap();

    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp, carol_kp, dave_kp, eve_kp],
            T0 + 10,
        )
        .unwrap();

    let welcome = outcome.welcome.expect("welcome present");

    let bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();
    let carol_g = UmbrellaGroup::join_from_welcome(
        &carol.provider,
        carol.ks.as_ref() as &dyn KeyStore,
        carol.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();
    let dave_g = UmbrellaGroup::join_from_welcome(
        &dave.provider,
        dave.ks.as_ref() as &dyn KeyStore,
        dave.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();
    let eve_g = UmbrellaGroup::join_from_welcome(
        &eve.provider,
        eve.ks.as_ref() as &dyn KeyStore,
        eve.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();

    assert_eq!(alice_g.member_count(), 5);
    assert_eq!(alice_g.epoch(), 1);

    // Все выводят одинаковый base_key (дополнительно проверяем cross-instance consistency
    // через derived PerKidKey для одного kid).
    //
    // Each derives the same base_key (cross-checked via derived PerKidKey for one KID).
    let alice_bk = base_key_from_group(&alice_g, &alice.provider);
    let bob_bk = base_key_from_group(&bob_g, &bob.provider);
    let kid = umbrella_calls::compute_kid(0, 1);
    assert_eq!(
        alice_bk.derive_per_kid(kid).key_bytes(),
        bob_bk.derive_per_kid(kid).key_bytes(),
        "alice and bob must derive identical sframe_key for the same KID"
    );

    let mut alice_sf = SframeContext::new();
    alice_sf.advance_epoch(alice_bk);
    let mut bob_sf = SframeContext::new();
    bob_sf.advance_epoch(bob_bk);
    let mut carol_sf = SframeContext::new();
    carol_sf.advance_epoch(base_key_from_group(&carol_g, &carol.provider));
    let mut dave_sf = SframeContext::new();
    dave_sf.advance_epoch(base_key_from_group(&dave_g, &dave.provider));
    let mut eve_sf = SframeContext::new();
    eve_sf.advance_epoch(base_key_from_group(&eve_g, &eve.provider));

    let alice_sender = alice_g.own_leaf_index();

    for counter in 0u64..100 {
        let pt = format!("frame-{counter}-from-alice");
        let ct = alice_sf
            .encrypt_frame(alice_sender, counter, pt.as_bytes())
            .unwrap();

        for rx in [&mut bob_sf, &mut carol_sf, &mut dave_sf, &mut eve_sf] {
            let dec = rx.decrypt_frame(&ct).unwrap();
            assert_eq!(dec.plaintext, pt.as_bytes());
            assert_eq!(dec.counter, counter);
            assert_eq!(dec.sender_leaf, alice_sender);
            assert_eq!(dec.epoch, 1);
        }
    }
}

// ================= Сценарий 3: Rekey on MLS epoch advance =================

#[test]
fn scenario_3_rekey_on_mls_epoch_advance() {
    let alice = Client::new();
    let bob = Client::new();
    let carol = Client::new();
    let dave = Client::new();

    let bob_kp = bob.publish_key_package();
    let carol_kp = carol.publish_key_package();
    let dave_kp = dave.publish_key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        fresh_gid(0x52),
        T0,
    )
    .unwrap();
    let outcome1 = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp, carol_kp],
            T0 + 10,
        )
        .unwrap();
    let welcome1 = outcome1.welcome.expect("welcome present");

    let mut bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &welcome1,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();
    let mut carol_g = UmbrellaGroup::join_from_welcome(
        &carol.provider,
        carol.ks.as_ref() as &dyn KeyStore,
        carol.device_index,
        &welcome1,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();

    let alice_sender = alice_g.own_leaf_index();

    let mut alice_sf = SframeContext::new();
    alice_sf.advance_epoch(base_key_from_group(&alice_g, &alice.provider));
    let mut bob_sf = SframeContext::new();
    bob_sf.advance_epoch(base_key_from_group(&bob_g, &bob.provider));

    // Кадр в epoch=1 — Bob успешно decrypt.
    // Frame in epoch=1 — Bob decrypts successfully.
    let ct_e1 = alice_sf
        .encrypt_frame(alice_sender, 0, b"epoch-1-frame")
        .unwrap();
    let dec_e1 = bob_sf.decrypt_frame(&ct_e1).unwrap();
    assert_eq!(dec_e1.plaintext, b"epoch-1-frame");
    assert_eq!(dec_e1.epoch, 1);

    // Alice добавляет Dave → epoch становится 2.
    // Alice adds Dave → epoch becomes 2.
    let outcome2 = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[dave_kp],
            T0 + 20,
        )
        .unwrap();
    let commit2 = outcome2.commit;
    let welcome2 = outcome2.welcome.expect("welcome present");

    match bob_g.process_incoming(&bob.provider, &commit2).unwrap() {
        IncomingMessage::CommitApplied { epoch, .. } => assert_eq!(epoch, 2),
        other => panic!("bob expected CommitApplied, got {other:?}"),
    }
    match carol_g.process_incoming(&carol.provider, &commit2).unwrap() {
        IncomingMessage::CommitApplied { epoch, .. } => assert_eq!(epoch, 2),
        other => panic!("carol expected CommitApplied, got {other:?}"),
    }
    let dave_g = UmbrellaGroup::join_from_welcome(
        &dave.provider,
        dave.ks.as_ref() as &dyn KeyStore,
        dave.device_index,
        &welcome2,
        GroupPolicy::Private,
        T0 + 20,
    )
    .unwrap();

    // Все 4 стороны advance_epoch под новый base_key.
    // All four parties advance_epoch with the new base_key.
    alice_sf.advance_epoch(base_key_from_group(&alice_g, &alice.provider));
    bob_sf.advance_epoch(base_key_from_group(&bob_g, &bob.provider));
    let mut carol_sf = SframeContext::new();
    carol_sf.advance_epoch(base_key_from_group(&carol_g, &carol.provider));
    let mut dave_sf = SframeContext::new();
    dave_sf.advance_epoch(base_key_from_group(&dave_g, &dave.provider));

    let ct_e2 = alice_sf
        .encrypt_frame(alice_sender, 0, b"epoch-2-frame")
        .unwrap();
    assert_eq!(
        bob_sf.decrypt_frame(&ct_e2).unwrap().plaintext,
        b"epoch-2-frame"
    );
    assert_eq!(
        carol_sf.decrypt_frame(&ct_e2).unwrap().plaintext,
        b"epoch-2-frame"
    );
    assert_eq!(
        dave_sf.decrypt_frame(&ct_e2).unwrap().plaintext,
        b"epoch-2-frame"
    );

    // Dave читает следующий кадр в той же эпохе.
    // Dave reads the next frame in the same epoch.
    let ct_e2_second = alice_sf
        .encrypt_frame(alice_sender, 1, b"epoch-2-second")
        .unwrap();
    assert_eq!(
        dave_sf.decrypt_frame(&ct_e2_second).unwrap().plaintext,
        b"epoch-2-second"
    );
}

// ================= Сценарий 4: Forward-secrecy после Remove =================

#[test]
fn scenario_4_forward_secrecy_after_remove() {
    let alice = Client::new();
    let bob = Client::new();
    let carol = Client::new();

    let bob_kp = bob.publish_key_package();
    let carol_kp = carol.publish_key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        fresh_gid(0x53),
        T0,
    )
    .unwrap();
    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp, carol_kp],
            T0 + 10,
        )
        .unwrap();
    let welcome = outcome.welcome.expect("welcome present");

    let mut bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();
    let mut carol_g = UmbrellaGroup::join_from_welcome(
        &carol.provider,
        carol.ks.as_ref() as &dyn KeyStore,
        carol.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();

    let mut alice_sf = SframeContext::new();
    alice_sf.advance_epoch(base_key_from_group(&alice_g, &alice.provider));
    let mut bob_sf = SframeContext::new();
    bob_sf.advance_epoch(base_key_from_group(&bob_g, &bob.provider));
    let mut carol_sf = SframeContext::new();
    carol_sf.advance_epoch(base_key_from_group(&carol_g, &carol.provider));

    // Alice remove Carol (leaf_index=2).
    // Alice removes Carol (leaf_index=2).
    let remove_outcome = alice_g
        .remove_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[2],
            T0 + 20,
        )
        .unwrap();
    let commit = remove_outcome.commit;

    match bob_g.process_incoming(&bob.provider, &commit).unwrap() {
        IncomingMessage::CommitApplied { epoch, .. } => assert_eq!(epoch, 2),
        other => panic!("bob expected CommitApplied, got {other:?}"),
    }
    // Carol видит себя evicted-ой при применении commit'а.
    // Carol sees herself evicted when processing the commit.
    match carol_g.process_incoming(&carol.provider, &commit).unwrap() {
        IncomingMessage::CommitApplied { self_removed, .. } => assert!(
            self_removed,
            "carol must see herself as removed after processing remove-commit"
        ),
        other => panic!("carol expected CommitApplied, got {other:?}"),
    }

    // Alice и Bob advance_epoch под новый base_key; Carol не может (нет ключа).
    // Alice and Bob advance to the new epoch's base_key; Carol cannot (no key).
    alice_sf.advance_epoch(base_key_from_group(&alice_g, &alice.provider));
    bob_sf.advance_epoch(base_key_from_group(&bob_g, &bob.provider));

    let alice_sender = alice_g.own_leaf_index();
    let ct_e2 = alice_sf
        .encrypt_frame(alice_sender, 0, b"post-remove")
        .unwrap();

    // Bob читает успешно.
    // Bob decrypts successfully.
    assert_eq!(
        bob_sf.decrypt_frame(&ct_e2).unwrap().plaintext,
        b"post-remove"
    );

    // Carol НЕ может расшифровать (forward secrecy) — epoch=2 ей недоступен.
    // Carol CANNOT decrypt (forward secrecy) — epoch=2 is out of reach for her.
    let err = carol_sf.decrypt_frame(&ct_e2).unwrap_err();
    assert!(
        matches!(
            err,
            CallError::StaleEpoch { .. } | CallError::AeadAuthFailure
        ),
        "removed Carol must not decrypt post-remove frames; got {err:?}",
    );
}

// ================= Сценарий 5: Anti-replay realistic =================

#[test]
fn scenario_5_anti_replay_realistic() {
    let alice = Client::new();
    let bob = Client::new();
    let bob_kp = bob.publish_key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        fresh_gid(0x54),
        T0,
    )
    .unwrap();
    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp],
            T0 + 10,
        )
        .unwrap();
    let bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &outcome.welcome.expect("welcome present"),
        GroupPolicy::Private,
        T0 + 10,
    )
    .unwrap();

    let mut alice_sf = SframeContext::new();
    alice_sf.advance_epoch(base_key_from_group(&alice_g, &alice.provider));
    let mut bob_sf = SframeContext::new();
    bob_sf.advance_epoch(base_key_from_group(&bob_g, &bob.provider));

    let alice_sender = alice_g.own_leaf_index();

    // Alice шлёт 20 кадров (counter 0..20).
    // Alice sends 20 frames (counter 0..20).
    let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
    for c in 0u64..20 {
        let pt = format!("msg-{c}").into_bytes();
        let ct = alice_sf.encrypt_frame(alice_sender, c, &pt).unwrap();
        frames.push((c, ct));
    }

    // Bob получает в порядке reorder: 10, 5, 15, 3, 18 — все в окне 64 → accept.
    // Bob receives in reorder: 10, 5, 15, 3, 18 — all within window 64 → accept.
    for &i in &[10usize, 5, 15, 3, 18] {
        let (counter, ct) = &frames[i];
        let dec = bob_sf.decrypt_frame(ct).unwrap();
        assert_eq!(dec.counter, *counter);
        assert_eq!(dec.plaintext, format!("msg-{counter}").as_bytes());
    }

    // Повтор counter=5 → Replay.
    // Replay of counter=5 → Replay error.
    let err = bob_sf.decrypt_frame(&frames[5].1).unwrap_err();
    assert!(matches!(err, CallError::Replay { counter: 5, .. }));

    // Counter=1 (delta = 18 - 1 = 17 < 64) → accept.
    // Counter=1 (delta = 17 < 64) → accept.
    let dec_1 = bob_sf.decrypt_frame(&frames[1].1).unwrap();
    assert_eq!(dec_1.plaintext, b"msg-1");

    // Counter=17 ещё не виден — accept.
    // Counter=17 not seen yet — accept.
    let dec_17 = bob_sf.decrypt_frame(&frames[17].1).unwrap();
    assert_eq!(dec_17.counter, 17);

    // Повтор counter=17 → Replay.
    // Replay of counter=17 → Replay.
    let err = bob_sf.decrypt_frame(&frames[17].1).unwrap_err();
    assert!(matches!(err, CallError::Replay { counter: 17, .. }));
}
