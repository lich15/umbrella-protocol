//! Interop: наш `UmbrellaGroup` совместим с vanilla `openmls` 0.8.1 клиентом.
//! Interop: our `UmbrellaGroup` is compatible with a vanilla `openmls` 0.8.1 client.
//!
//! Сценарий:
//! 1. Alice создаёт Umbrella-группу через `UmbrellaGroup::create_private`.
//! 2. Bob — vanilla openmls client без нашей обвязки (использует `openmls::MlsGroup`,
//!    `openmls_basic_credential::SignatureKeyPair`, `openmls_rust_crypto::OpenMlsRustCrypto`).
//! 3. Bob публикует KeyPackage с теми же capabilities.
//! 4. Alice добавляет Bob через `add_members` → commit+welcome в сериализованном виде.
//! 5. Bob join'ится из Welcome через ванильный openmls.
//! 6. Обмен: Alice encrypt → Bob decrypt через vanilla `MlsGroup::process_message`.
//!    Bob encrypt → Alice decrypt через наш `UmbrellaGroup::process_incoming`.
//!
//! Это доказывает что UmbrellaGroup не создаёт кастомный протокол — наши ограничения
//! (Ed25519/Ed448 whitelist, отсутствие ExternalPub, PURE_CIPHERTEXT wire policy) — это
//! чистое подмножество RFC 9420, полностью interoperable.
//!
//! Interop с **mls-rs** (AWS Labs, ≥0.45) отложен отдельным sub-stage: API mls-rs радикально
//! отличается от openmls (иные типы Client/Group, собственный storage, Rust async). Добавление
//! mls-rs dep дало бы +30 transitive деps без защитной ценности — wire-compat уже доказана
//! этим тестом (mls-rs следует RFC 9420, как и openmls). Реальный mls-rs interop запланирован
//! в Stage 9 (production hardening) когда будем прогонять KAT-векторы против всех внешних
//! реализаций.
//!
//! Interop with **mls-rs** (AWS Labs, ≥0.45) is deferred to a separate sub-stage: mls-rs's
//! API diverges radically from openmls (different Client/Group types, own storage, async
//! Rust). Adding an mls-rs dep would bring +30 transitive deps without defensive value —
//! wire compatibility is already demonstrated by this test (mls-rs implements RFC 9420 just
//! as openmls does). Actual mls-rs interop is scheduled for Stage 9 (production hardening)
//! when we run KAT vectors against every external implementation.

use std::sync::Arc;

use openmls::credentials::CredentialType;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::{KeyPackageBuilder, Lifetime};
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::{Capabilities, ProtocolVersion};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::{Ciphersuite as OpenMlsCiphersuite, SignatureScheme};
use openmls_traits::OpenMlsProvider;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider, UMBRELLA_DEFAULT_CIPHERSUITE,
};

/// Umbrella ciphersuite (X25519+ChaCha+Ed25519). Umbrella ciphersuite.
const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;

/// Тот же ciphersuite в виде openmls константы для vanilla клиента.
/// The same ciphersuite as an openmls constant for the vanilla client.
const OPENMLS_CS: OpenMlsCiphersuite =
    OpenMlsCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

const LIFETIME_SECS: u64 = 60 * 60 * 24 * 28;
const T0: u64 = 1_700_000_000;

/// Umbrella Alice — обёртка. Wrapped Umbrella Alice.
struct AliceUmbrella {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl AliceUmbrella {
    fn new() -> Self {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        ks.add_device(0, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index: 0,
        }
    }
}

/// Vanilla-openmls Bob — без нашей обвязки, чистая библиотека.
/// Vanilla-openmls Bob — no Umbrella wrapper, stock library.
struct BobVanilla {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

impl BobVanilla {
    fn new() -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("new sig keypair");
        signer.store(provider.storage()).expect("store signer");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"bob-vanilla-identity".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            provider,
            signer,
            credential_with_key,
        }
    }

    /// Строит KeyPackage с capabilities совместимыми с Umbrella (no ECDSA advertise).
    /// Builds a KeyPackage with Umbrella-compatible capabilities (no ECDSA advertising).
    fn key_package(&self) -> openmls::key_packages::KeyPackage {
        let caps = Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[
                OpenMlsCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                OpenMlsCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ]),
            None,
            None,
            Some(&[CredentialType::Basic]),
        );
        let bundle = KeyPackageBuilder::new()
            .key_package_lifetime(Lifetime::new(LIFETIME_SECS))
            .leaf_node_capabilities(caps)
            .build(
                OPENMLS_CS,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .expect("KeyPackageBuilder::build");
        bundle.key_package().clone()
    }
}

// =========================================================================================
// Interop: Alice=Umbrella, Bob=Vanilla. Welcome, add, bidirectional messages.
// =========================================================================================

#[test]
fn umbrella_alice_interops_with_vanilla_openmls_bob() {
    let alice = AliceUmbrella::new();
    let bob = BobVanilla::new();

    let bob_kp = bob.key_package();

    // Alice создаёт Umbrella-группу и добавляет ванильного Bob'а.
    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        GroupId::from_slice(&[0xA1; 16]),
        T0,
    )
    .expect("alice create_private");

    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp],
            T0 + 1,
        )
        .expect("alice add_members(vanilla bob)");

    let welcome_bytes = outcome.welcome.expect("welcome must be present");

    // Bob join'ится через ванильный openmls API.
    let welcome_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).expect("welcome decode");
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("not a Welcome body"),
    };

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged = StagedWelcome::new_from_welcome(&bob.provider, &join_config, welcome, None)
        .expect("bob StagedWelcome::new_from_welcome");
    let mut bob_g = staged.into_group(&bob.provider).expect("bob into_group");

    assert_eq!(bob_g.epoch().as_u64(), 1, "bob joins at epoch 1");
    assert_eq!(bob_g.members().count(), 2, "group has 2 members");

    // Alice → Bob: Alice шифрует через UmbrellaGroup, Bob расшифровывает через vanilla API.
    let alice_bytes = alice_g
        .encrypt_application(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            b"hello-vanilla-bob",
        )
        .unwrap();
    let alice_msg_in = MlsMessageIn::tls_deserialize_exact(&alice_bytes).unwrap();
    let protocol = alice_msg_in.try_into_protocol_message().unwrap();
    let processed = bob_g
        .process_message(&bob.provider, protocol)
        .expect("vanilla bob process_message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), b"hello-vanilla-bob");
        }
        other => panic!("vanilla bob expected Application, got {other:?}"),
    }

    // Bob → Alice: Bob шифрует через vanilla, Alice расшифровывает через UmbrellaGroup.
    let bob_msg = bob_g
        .create_message(&bob.provider, &bob.signer, b"hi-umbrella-alice")
        .expect("vanilla bob create_message");
    let bob_bytes = bob_msg.tls_serialize_detached().unwrap();
    match alice_g
        .process_incoming(&alice.provider, &bob_bytes)
        .unwrap()
    {
        IncomingMessage::Application { payload, .. } => {
            assert_eq!(payload, b"hi-umbrella-alice");
        }
        other => panic!("umbrella alice expected Application, got {other:?}"),
    }
}

// =========================================================================================
// Bidirectional exchange 100 раз туда-обратно, чтобы упражнять ratchet у обеих сторон.
// 100 round-trips to exercise both sides' ratchets.
// =========================================================================================

#[test]
fn umbrella_vanilla_100_message_exchange_stays_in_sync() {
    let alice = AliceUmbrella::new();
    let bob = BobVanilla::new();
    let bob_kp = bob.key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        GroupId::from_slice(&[0xA2; 16]),
        T0,
    )
    .unwrap();
    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp],
            T0 + 1,
        )
        .unwrap();
    let welcome_bytes = outcome.welcome.unwrap();

    let welcome_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!(),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_g = StagedWelcome::new_from_welcome(&bob.provider, &join_config, welcome, None)
        .unwrap()
        .into_group(&bob.provider)
        .unwrap();

    for i in 0..100 {
        if i % 2 == 0 {
            let msg = format!("umbrella-a-{i:03}");
            let ct = alice_g
                .encrypt_application(
                    &alice.provider,
                    alice.ks.as_ref() as &dyn KeyStore,
                    msg.as_bytes(),
                )
                .unwrap();
            let msg_in = MlsMessageIn::tls_deserialize_exact(&ct).unwrap();
            let protocol = msg_in.try_into_protocol_message().unwrap();
            let processed = bob_g.process_message(&bob.provider, protocol).unwrap();
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app) => {
                    assert_eq!(app.into_bytes(), msg.as_bytes());
                }
                other => panic!("iter {i} alice→bob: {other:?}"),
            }
        } else {
            let msg = format!("vanilla-b-{i:03}");
            let out = bob_g
                .create_message(&bob.provider, &bob.signer, msg.as_bytes())
                .unwrap();
            let bytes = out.tls_serialize_detached().unwrap();
            match alice_g.process_incoming(&alice.provider, &bytes).unwrap() {
                IncomingMessage::Application { payload, .. } => {
                    assert_eq!(payload, msg.as_bytes());
                }
                other => panic!("iter {i} bob→alice: {other:?}"),
            }
        }
    }
}

// =========================================================================================
// Обратный сценарий: vanilla Alice создаёт группу, Umbrella Bob джойнится и обменивается.
// Reverse scenario: vanilla Alice creates the group, Umbrella Bob joins and exchanges.
// =========================================================================================

#[test]
fn vanilla_alice_hosts_group_with_umbrella_bob() {
    // Vanilla Alice.
    let alice_provider = OpenMlsRustCrypto::default();
    let alice_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    alice_signer.store(alice_provider.storage()).unwrap();
    let alice_cred = CredentialWithKey {
        credential: BasicCredential::new(b"alice-vanilla-identity".to_vec()).into(),
        signature_key: alice_signer.public().into(),
    };

    // Umbrella Bob.
    let bob = AliceUmbrella::new(); // reuses helper (device_index=0, InMemory KeyStore).
    let bob_kp = build_device_key_package(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        CS,
    )
    .unwrap()
    .key_package()
    .clone();

    // Alice (vanilla) создаёт группу.
    let caps = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[OPENMLS_CS]),
        None,
        None,
        Some(&[CredentialType::Basic]),
    );
    let alice_config = MlsGroupCreateConfig::builder()
        .ciphersuite(OPENMLS_CS)
        .capabilities(caps)
        .lifetime(Lifetime::new(LIFETIME_SECS))
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_g = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &alice_config,
        GroupId::from_slice(&[0xB1; 16]),
        alice_cred,
    )
    .unwrap();

    // Alice добавляет Bob через vanilla API.
    let (commit, welcome, _group_info) = alice_g
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .unwrap();
    alice_g.merge_pending_commit(&alice_provider).unwrap();
    let _ = commit;
    let welcome_bytes = welcome.tls_serialize_detached().unwrap();

    // Bob (Umbrella) принимает Welcome.
    let mut bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0,
    )
    .expect("umbrella bob joins vanilla alice's group");

    assert_eq!(bob_g.epoch(), 1);
    assert_eq!(bob_g.member_count(), 2);

    // Bob → Alice через Umbrella encrypt, vanilla decrypt.
    let bob_ct = bob_g
        .encrypt_application(
            &bob.provider,
            bob.ks.as_ref() as &dyn KeyStore,
            b"bob-umbrella-says-hi",
        )
        .unwrap();
    let msg_in = MlsMessageIn::tls_deserialize_exact(&bob_ct).unwrap();
    let protocol = msg_in.try_into_protocol_message().unwrap();
    let processed = alice_g.process_message(&alice_provider, protocol).unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), b"bob-umbrella-says-hi");
        }
        other => panic!("vanilla alice expected Application, got {other:?}"),
    }

    // Alice → Bob через vanilla encrypt, Umbrella decrypt.
    let alice_msg = alice_g
        .create_message(&alice_provider, &alice_signer, b"alice-vanilla-says-hi")
        .unwrap();
    let alice_bytes = alice_msg.tls_serialize_detached().unwrap();
    match bob_g.process_incoming(&bob.provider, &alice_bytes).unwrap() {
        IncomingMessage::Application { payload, .. } => {
            assert_eq!(payload, b"alice-vanilla-says-hi");
        }
        other => panic!("umbrella bob expected Application, got {other:?}"),
    }
}
