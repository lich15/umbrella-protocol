//! Milestone Этапа 3: полный стек приватности метаданных end-to-end.
//! Stage 3 milestone: full metadata-privacy stack end-to-end.
//!
//! Сценарий:
//! 1. Mock KT state: строим KtEntry для Alice и Bob, вычисляем Merkle root, собираем
//!    witness signatures 3-of-5.
//! 2. Bob выполняет self-monitoring: его собственная запись в KT соответствует ожиданиям.
//! 3. Alice читает Bob's entry из KT, проверяет inclusion proof + signed epoch
//!    (3-of-5 witnesses). Берёт из entry Bob's X25519 identity pubkey.
//! 4. Alice создаёт UmbrellaGroup (приватный чат), приглашает Bob по его MLS KeyPackage.
//! 5. Alice encrypts application message через UmbrellaGroup → получает MLS wire bytes.
//! 6. Alice seals MLS wire через umbrella-sealed-sender (с padding внутри) на Bob's X25519 →
//!    получает sealed-envelope bytes. Сервер в этой передаче видит только recipient_group_id
//!    (извлекаемый из MLS wire) и размер bucket, не отправителя.
//! 7. Bob unseals → получает MLS wire + подтверждённый sender_identity Alice.
//! 8. Bob сверяет sender_identity с KT Alice's entry — если совпадает, доверяем.
//! 9. Bob UmbrellaGroup.process_incoming(MLS wire) → расшифрованный plaintext.
//!
//! Дополнительно: тесты отказа — self-monitoring детектирует ghost device, witness-порог
//! 2/5 отвергается, insertion proof с подменённым root отвергается.

use std::sync::Arc;

use openmls::group::GroupId;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_kt::{
    build_audit_path, canonical_sign_payload, merkle_root, verify_inclusion, verify_own_entry,
    verify_signed_epoch, DeviceAttestationRef, KtEntry, OwnExpectations, SignedEpochRoot,
    WitnessPublic, WitnessSet, WitnessSignature, NODE_HASH_LEN,
};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider, UMBRELLA_DEFAULT_CIPHERSUITE,
};
use umbrella_sealed_sender::{seal, unseal, OpenedEnvelope};

use umbrella_crypto_primitives::sig::PrivateSigningKey;

const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;
const T0: u64 = 1_700_000_000;

struct Client {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl Client {
    fn new(device_index: u32) -> Self {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        ks.add_device(device_index, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index,
        }
    }

    fn kt_entry(&self, epoch: u64) -> KtEntry {
        let identity_ed = self.ks.identity_public();
        let identity_x = self.ks.identity_x25519_public();
        let account_id = KtEntry::derive_account_id(&identity_ed);
        let devices = vec![DeviceAttestationRef {
            device_index: self.device_index,
            device_pub: self.ks.device_public(self.device_index).unwrap(),
            attestation_valid_until: u64::MAX,
        }];
        KtEntry {
            account_id,
            epoch,
            identity_ed25519_pub: identity_ed,
            identity_x25519_pub: identity_x,
            devices,
        }
    }
}

struct Witness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

impl Witness {
    fn new() -> Self {
        let mut rng = rand_core::OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
        Self { sk, pk }
    }

    fn sign(&self, epoch: u64, root: &[u8; NODE_HASH_LEN]) -> WitnessSignature {
        let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
        WitnessSignature {
            witness: self.pk,
            signature: self.sk.sign(&payload).to_bytes(),
        }
    }
}

/// Собирает KT-snapshot эпохи: leaves для Alice и Bob, Merkle root, witness signatures.
fn build_kt_snapshot(
    alice_entry: &KtEntry,
    bob_entry: &KtEntry,
    witnesses: &[Witness],
    epoch: u64,
) -> (
    Vec<[u8; NODE_HASH_LEN]>,
    [u8; NODE_HASH_LEN],
    SignedEpochRoot,
) {
    let alice_leaf = alice_entry.merkle_leaf_hash().unwrap();
    let bob_leaf = bob_entry.merkle_leaf_hash().unwrap();
    let leaves = vec![alice_leaf, bob_leaf];
    let root = merkle_root(&leaves);
    let signatures: Vec<_> = witnesses.iter().map(|w| w.sign(epoch, &root)).collect();
    let signed = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures,
    };
    (leaves, root, signed)
}

// =========================================================================================
// Главный milestone: полный поток приватности метаданных.
// =========================================================================================

#[test]
fn full_stack_privacy_flow_alice_to_bob() {
    let alice = Client::new(0);
    let bob = Client::new(0);

    // === KT публикация эпохи 1 ===
    // В эпохе 1 журнал содержит записи Alice и Bob. 5 witness'ов подписывают root.
    let alice_entry = alice.kt_entry(1);
    let bob_entry = bob.kt_entry(1);
    let witnesses: Vec<Witness> = (0..5).map(|_| Witness::new()).collect();
    let (leaves, root, signed_epoch) = build_kt_snapshot(&alice_entry, &bob_entry, &witnesses, 1);

    let mut witness_set = WitnessSet::new();
    for w in &witnesses {
        witness_set.add(w.pk);
    }

    // === Bob self-monitoring: его запись соответствует ожиданиям ===
    let bob_identity_ed = bob.ks.identity_public();
    let bob_identity_x = bob.ks.identity_x25519_public();
    let bob_expected_devices = vec![(0u32, bob.ks.device_public(0).unwrap())];
    let bob_exp = OwnExpectations {
        identity_ed25519: &bob_identity_ed,
        identity_x25519: &bob_identity_x,
        devices: &bob_expected_devices,
    };
    verify_own_entry(&bob_entry, &bob_exp).expect("bob self-monitoring must pass");

    // === Alice проверяет эпоху (3 из 5 witnesses) и inclusion Bob's entry ===
    verify_signed_epoch(&signed_epoch, &witness_set, 3).expect("epoch must be accepted with 5/5");

    let bob_leaf = bob_entry.merkle_leaf_hash().unwrap();
    let bob_path = build_audit_path(&leaves, 1).unwrap();
    verify_inclusion(&bob_leaf, 1, leaves.len() as u64, &bob_path, &root)
        .expect("Bob's entry inclusion proof must verify");

    // Alice извлекает Bob's X25519 identity из verified entry.
    let bob_x25519_from_kt = bob_entry.identity_x25519_pub;

    // === MLS: Alice создаёт UmbrellaGroup, приглашает Bob ===
    let bob_kp = build_device_key_package(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        CS,
    )
    .unwrap()
    .key_package()
    .clone();

    let mut alice_group = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        GroupId::from_slice(&[0xAA; 16]),
        T0,
    )
    .unwrap();
    let outcome = alice_group
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp],
            T0 + 1,
        )
        .unwrap();
    let welcome_bytes = outcome.welcome.expect("welcome present");

    let mut bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0 + 1,
    )
    .unwrap();

    // === Alice: encrypt через MLS, seal через sealed-sender ===
    let plaintext = b"sealed-over-mls-payload";
    let mls_wire = alice_group
        .encrypt_application(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            plaintext,
        )
        .unwrap();

    let mut rng = rand_core::OsRng;
    let sealed_bytes = seal(
        alice.ks.as_ref() as &dyn KeyStore,
        &bob_x25519_from_kt,
        &mls_wire,
        &mut rng,
    )
    .unwrap();

    // === Network: sealed_bytes передаются Bob (тело запроса к delivery endpoint) ===

    // === Bob: unseal → MLS wire + подтверждённый sender ===
    let opened: OpenedEnvelope = unseal(bob.ks.as_ref() as &dyn KeyStore, &sealed_bytes).unwrap();
    // Bob сверяет sender_identity с Alice's KT entry.
    assert_eq!(
        opened.sender_identity, alice_entry.identity_ed25519_pub,
        "sealed sender identity должен совпадать с Alice's Ed25519 pub из KT entry"
    );

    // Bob процессит MLS wire через UmbrellaGroup.
    match bob_group
        .process_incoming(&bob.provider, &opened.message)
        .unwrap()
    {
        IncomingMessage::Application { payload, .. } => {
            assert_eq!(payload, plaintext);
        }
        other => panic!("expected Application, got {other:?}"),
    }
}

// =========================================================================================
// Ghost device в KT entry детектируется self-monitoring'ом.
// =========================================================================================

#[test]
fn self_monitoring_detects_injected_ghost_device() {
    let alice = Client::new(0);
    let attacker = Client::new(99);

    let mut alice_entry = alice.kt_entry(1);
    // Атакующий key-svc вставил свой device в Alice's entry.
    alice_entry.devices.push(DeviceAttestationRef {
        device_index: 99,
        device_pub: attacker.ks.device_public(99).unwrap(),
        attestation_valid_until: u64::MAX,
    });

    let identity_ed = alice.ks.identity_public();
    let identity_x = alice.ks.identity_x25519_public();
    let expected_devices = vec![(0u32, alice.ks.device_public(0).unwrap())];
    let exp = OwnExpectations {
        identity_ed25519: &identity_ed,
        identity_x25519: &identity_x,
        devices: &expected_devices,
    };

    let result = verify_own_entry(&alice_entry, &exp);
    assert!(
        result.is_err(),
        "ghost device должен детектироваться self-monitoring'ом"
    );
}

// =========================================================================================
// 2/5 witness подписей недостаточно для принятия эпохи.
// =========================================================================================

#[test]
fn epoch_with_only_two_of_five_signatures_rejected() {
    let alice = Client::new(0);
    let bob = Client::new(0);
    let alice_entry = alice.kt_entry(1);
    let bob_entry = bob.kt_entry(1);
    let all_witnesses: Vec<Witness> = (0..5).map(|_| Witness::new()).collect();
    // Только 2 из 5 подписали (атака или сетевая проблема).
    let signing_witnesses: Vec<&Witness> = all_witnesses.iter().take(2).collect();

    let alice_leaf = alice_entry.merkle_leaf_hash().unwrap();
    let bob_leaf = bob_entry.merkle_leaf_hash().unwrap();
    let leaves = vec![alice_leaf, bob_leaf];
    let root = merkle_root(&leaves);
    let signatures: Vec<_> = signing_witnesses.iter().map(|w| w.sign(1, &root)).collect();
    let signed_epoch = SignedEpochRoot {
        epoch: 1,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures,
    };

    let mut witness_set = WitnessSet::new();
    for w in &all_witnesses {
        witness_set.add(w.pk);
    }

    let result = verify_signed_epoch(&signed_epoch, &witness_set, 3);
    assert!(
        result.is_err(),
        "2/5 подписей не должно проходить при threshold=3"
    );
}

// =========================================================================================
// Tampered Merkle root в inclusion proof отвергается.
// =========================================================================================

#[test]
fn inclusion_proof_with_tampered_root_rejected() {
    let alice = Client::new(0);
    let bob = Client::new(0);
    let alice_entry = alice.kt_entry(1);
    let bob_entry = bob.kt_entry(1);

    let alice_leaf = alice_entry.merkle_leaf_hash().unwrap();
    let bob_leaf = bob_entry.merkle_leaf_hash().unwrap();
    let leaves = vec![alice_leaf, bob_leaf];
    let honest_root = merkle_root(&leaves);
    let path = build_audit_path(&leaves, 1).unwrap();

    // Attacker подменяет root в своём ответе клиенту.
    let mut tampered_root = honest_root;
    tampered_root[0] ^= 0xFF;

    let result = verify_inclusion(&bob_leaf, 1, 2, &path, &tampered_root);
    assert!(
        result.is_err(),
        "inclusion proof с подменённым root должен отвергаться"
    );
}

// =========================================================================================
// Sealed-sender без правильного X25519 (Eve получатель) не расшифровывает.
// =========================================================================================

#[test]
fn sealed_sender_not_opened_by_eve() {
    let alice = Client::new(0);
    let bob = Client::new(0);
    let eve = Client::new(0);

    let mut rng = rand_core::OsRng;
    let sealed = seal(
        alice.ks.as_ref() as &dyn KeyStore,
        &bob.ks.identity_x25519_public(),
        b"for-bob",
        &mut rng,
    )
    .unwrap();

    // Eve пытается unseal — не должна смочь.
    let result = unseal(eve.ks.as_ref() as &dyn KeyStore, &sealed);
    assert!(
        result.is_err(),
        "Eve не должна расшифровать envelope адресованный Bob"
    );
}
