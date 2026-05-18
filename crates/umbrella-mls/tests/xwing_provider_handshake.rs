//! Integration test для UmbrellaXWingProvider — full Alice ↔ Bob MLS handshake
//! на ciphersuite 0x004D (X-Wing) с обменом application messages и проверкой
//! exporter_secret API (фундамент для Этап 6.2 SFrame derivation).
//!
//! Integration test for UmbrellaXWingProvider — full Alice ↔ Bob MLS handshake
//! on ciphersuite 0x004D (X-Wing) with application message exchange and
//! exporter_secret API verification (foundation for Stage 6.2 SFrame derivation).
//!
//! Без feature `pq` крейт `umbrella-mls` не включает `provider/xwing.rs` в
//! модуль-tree, и тест compile-time skip'ается через `#![cfg(feature = "pq")]`.
//!
//! Without feature `pq`, `umbrella-mls` does not include `provider/xwing.rs` in
//! its module tree, and this test is compile-time skipped via
//! `#![cfg(feature = "pq")]`.

#![cfg(feature = "pq")]

use std::sync::Arc;

use openmls::group::GroupId;
use openmls::key_packages::KeyPackage;

use umbrella_identity::{
    keystore::FixedClock, Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage,
};
use umbrella_mls::{
    build_device_key_package, provider::UmbrellaXWingProvider, GroupPolicy, IncomingMessage,
    UmbrellaCiphersuite, UmbrellaGroup, MAX_EXPORTER_LEN,
};

// Round-5 device-capture closure F-PHD-DC-R11-1: exporter_secret теперь
// `MlockedSecret<T>` (not `SecretBox<T>`); `secrecy::ExposeSecret` больше не нужен.
// Round-5 device-capture closure F-PHD-DC-R11-1: exporter_secret is now
// `MlockedSecret<T>` (not `SecretBox<T>`); `secrecy::ExposeSecret` is no longer needed.

/// X-Wing ciphersuite (0x004D) — единственный ciphersuite этого теста.
/// X-Wing ciphersuite (0x004D) — the only ciphersuite for this test.
const CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519;

/// Стандартный unix-timestamp.
/// Standard unix timestamp.
const T0: u64 = 1_700_000_000;

/// Изолированный клиент: keystore + UmbrellaXWingProvider + device index.
/// Isolated client: keystore + UmbrellaXWingProvider + device index.
struct Client {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaXWingProvider,
    device_index: u32,
}

impl Client {
    fn new(device_index: u32) -> Self {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let clock = FixedClock::new(T0);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(clock) as Arc<dyn Clock>).unwrap();
        ks.add_device(device_index, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaXWingProvider::new_for_kat_tests_only(),
            device_index,
        }
    }

    fn publish_key_package(&self) -> KeyPackage {
        build_device_key_package(&self.provider, self.ks.as_ref(), self.device_index, CS)
            .expect("build_device_key_package")
            .key_package()
            .clone()
    }
}

/// Alice создаёт private group → Bob accepts Welcome → обмен 3 application
/// messages в обе стороны.
/// Alice creates a private group → Bob accepts Welcome → 3 application
/// messages exchanged in both directions.
#[test]
fn alice_bob_xwing_handshake_and_application_messages() {
    let alice = Client::new(0);
    let bob = Client::new(1);

    // Alice создаёт group с X-Wing ciphersuite.
    // Alice creates a group with X-Wing ciphersuite.
    let group_id = GroupId::from_slice(b"xwing-test-group-001");
    let mut alice_group = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref(),
        alice.device_index,
        CS,
        group_id,
        T0,
    )
    .expect("Alice create_private must succeed for X-Wing");
    assert_eq!(alice_group.ciphersuite(), CS);

    // Bob публикует KeyPackage (X-Wing).
    // Bob publishes a KeyPackage (X-Wing).
    let bob_kp = bob.publish_key_package();
    assert_eq!(bob_kp.ciphersuite() as u16, 0x004D);

    // Alice добавляет Bob → выдаёт commit + Welcome.
    // Alice adds Bob → emits commit + Welcome.
    let outcome = alice_group
        .add_members(
            &alice.provider,
            alice.ks.as_ref(),
            std::slice::from_ref(&bob_kp),
            T0,
        )
        .expect("Alice add Bob must succeed for X-Wing");
    let welcome_bytes = outcome.welcome.expect("welcome must be Some");

    // Bob join_from_welcome через свой UmbrellaXWingProvider.
    // Bob joins via his own UmbrellaXWingProvider.
    let mut bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref(),
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0,
    )
    .expect("Bob join_from_welcome must succeed for X-Wing");
    assert_eq!(bob_group.ciphersuite(), CS);
    assert_eq!(bob_group.epoch(), alice_group.epoch());
    assert_eq!(bob_group.member_count(), 2);

    // Application message: Alice → Bob.
    let alice_msg = b"hello from Alice via X-Wing";
    let alice_ct = alice_group
        .encrypt_application(&alice.provider, alice.ks.as_ref(), alice_msg)
        .expect("Alice encrypt_application must succeed");
    let received = bob_group
        .process_incoming(&bob.provider, &alice_ct)
        .expect("Bob process_incoming must succeed");
    match received {
        IncomingMessage::Application {
            sender_index,
            payload,
        } => {
            assert_eq!(payload, alice_msg);
            assert_eq!(sender_index, alice_group.own_leaf_index());
        }
        other => panic!("expected Application, got {other:?}"),
    }

    // Application message: Bob → Alice.
    let bob_msg = b"hello back from Bob via X-Wing";
    let bob_ct = bob_group
        .encrypt_application(&bob.provider, bob.ks.as_ref(), bob_msg)
        .expect("Bob encrypt_application must succeed");
    let received = alice_group
        .process_incoming(&alice.provider, &bob_ct)
        .expect("Alice process_incoming must succeed");
    match received {
        IncomingMessage::Application {
            sender_index,
            payload,
        } => {
            assert_eq!(payload, bob_msg);
            assert_eq!(sender_index, bob_group.own_leaf_index());
        }
        other => panic!("expected Application, got {other:?}"),
    }

    // Multi-message: 3 в каждую сторону под new epoch.
    // Multi-message: 3 each direction in the same epoch.
    for i in 0..3u8 {
        let msg = format!("alice msg #{i}");
        let ct = alice_group
            .encrypt_application(&alice.provider, alice.ks.as_ref(), msg.as_bytes())
            .unwrap();
        let r = bob_group.process_incoming(&bob.provider, &ct).unwrap();
        match r {
            IncomingMessage::Application { payload, .. } => {
                assert_eq!(payload, msg.as_bytes())
            }
            other => panic!("expected app, got {other:?}"),
        }
    }
}

/// exporter_secret API через X-Wing ciphersuite даёт стабильный групповой
/// secret (фундамент для SFrame derivation, Этап 6.2). Alice и Bob с
/// одинаковым label/context получают совпадающий output.
/// exporter_secret API via X-Wing ciphersuite yields a stable group secret
/// (foundation for SFrame derivation, Stage 6.2). Alice and Bob with the same
/// label/context get a matching output.
#[test]
fn xwing_group_exporter_secret_matches_between_members() {
    let alice = Client::new(0);
    let bob = Client::new(1);

    let group_id = GroupId::from_slice(b"xwing-export-grp");
    let mut alice_group = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref(),
        alice.device_index,
        CS,
        group_id,
        T0,
    )
    .expect("Alice create_private");

    let bob_kp = bob.publish_key_package();
    let outcome = alice_group
        .add_members(
            &alice.provider,
            alice.ks.as_ref(),
            std::slice::from_ref(&bob_kp),
            T0,
        )
        .expect("add Bob");
    let welcome_bytes = outcome.welcome.expect("welcome");

    let bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref(),
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0,
    )
    .expect("Bob join");

    // Common exporter input: label + context.
    let label = "umbrellax-mls-xwing-test-exporter-v1";
    let context = b"epoch-1-context-bytes";
    let len = 32;

    let alice_secret = alice_group
        .exporter_secret(&alice.provider, label, context, len)
        .expect("Alice exporter_secret");
    let bob_secret = bob_group
        .exporter_secret(&bob.provider, label, context, len)
        .expect("Bob exporter_secret");

    // Round-5 device-capture closure F-PHD-DC-R11-1: exporter_secret теперь
    // `MlockedSecret<[u8; MAX_EXPORTER_LEN]>`; expose() возвращает &[u8; N].
    // Round-5 device-capture closure F-PHD-DC-R11-1: exporter_secret is now
    // `MlockedSecret<[u8; MAX_EXPORTER_LEN]>`; expose() returns &[u8; N].
    assert_eq!(
        &alice_secret.expose()[..len],
        &bob_secret.expose()[..len],
        "exporter_secret должен совпадать между Alice и Bob (same epoch + label + context)"
    );

    // Различный label → различный output (domain separation).
    // Different label → different output (domain separation).
    let other = alice_group
        .exporter_secret(&alice.provider, "other-label", context, len)
        .expect("alice other-label");
    assert_ne!(
        &alice_secret.expose()[..len],
        &other.expose()[..len],
        "разный label обязан давать разный exporter_secret"
    );

    // MAX_EXPORTER_LEN — sanity check константы (не зависит от X-Wing, но проверяем что
    // exporter buffer fits целиком в SecretBox<[u8; MAX_EXPORTER_LEN]>).
    // MAX_EXPORTER_LEN — sanity check (constant; exporter buffer must fit a
    // SecretBox<[u8; MAX_EXPORTER_LEN]>).
    assert!(len <= MAX_EXPORTER_LEN);
}

/// KeyPackage с X-Wing ciphersuite корректно построен и signature key равен
/// device public key. Sanity check для X-Wing build_device_key_package path.
/// A KeyPackage with X-Wing ciphersuite is built correctly and signature key
/// equals the device public key. Sanity for the X-Wing
/// build_device_key_package path.
#[test]
fn xwing_key_package_signature_key_equals_device_pubkey() {
    let alice = Client::new(0);
    let bundle =
        build_device_key_package(&alice.provider, alice.ks.as_ref(), alice.device_index, CS)
            .expect("build X-Wing KeyPackage");
    assert_eq!(bundle.ciphersuite(), CS);
    assert_eq!(bundle.device_index(), alice.device_index);

    let device_pub = alice
        .ks
        .device_public(alice.device_index)
        .unwrap()
        .to_bytes();
    let kp_sig_key: &[u8] = bundle.key_package().leaf_node().signature_key().as_slice();
    assert_eq!(kp_sig_key, device_pub);
}
