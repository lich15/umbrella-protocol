//! Downgrade-resistance тесты: смешанная группа classical/PQ peers + защита
//! от misuse classical provider'а с X-Wing ciphersuite.
//!
//! Downgrade-resistance tests: mixed classical/PQ peer group + protection
//! against misuse of the classical provider with the X-Wing ciphersuite.
//!
//! ## Покрытие
//!
//! 1. **Classical UmbrellaProvider с X-Wing ciphersuite → reject.** Попытка
//!    создать группу с CS=0x004D через `UmbrellaProvider` (=OpenMlsRustCrypto)
//!    должна fail'ить, потому что openmls_rust_crypto-0.5.1 не supports
//!    0x004D в `OpenMlsCrypto::supports`. Защита от случайного использования
//!    PQ ciphersuite через non-PQ provider (постулат 14: никаких runtime
//!    panic).
//!
//! 2. **PQ peer + classical peer обмен на classical CS работает.** Alice с
//!    `UmbrellaXWingProvider` (поддерживает classical + PQ) и Bob с
//!    `UmbrellaProvider` (только classical) могут создать группу на CS=0x0003
//!    (classical default). PQ provider — superset, classical provider —
//!    subset; intersection = classical → группа downgraded на classical, что
//!    expected behaviour для mixed PQ/non-PQ deployments.
//!
//! 3. **Classical peer не может join'ить X-Wing Welcome.** Alice создаёт
//!    группу на 0x004D, sending Welcome → Bob с classical UmbrellaProvider
//!    fails при join_from_welcome (openmls_rust_crypto не supports X-Wing
//!    HPKE для расшифровки Welcome).
//!
//! ## Coverage
//!
//! 1. **Classical UmbrellaProvider with X-Wing ciphersuite → reject.** An
//!    attempt to create a group with CS=0x004D via `UmbrellaProvider`
//!    (=OpenMlsRustCrypto) must fail, because openmls_rust_crypto-0.5.1 does
//!    not support 0x004D in `OpenMlsCrypto::supports`. Protection against
//!    accidental use of PQ ciphersuite via non-PQ provider (postulate 14: no
//!    runtime panic).
//!
//! 2. **PQ peer + classical peer can communicate on a classical CS.** Alice
//!    with `UmbrellaXWingProvider` (supports classical + PQ) and Bob with
//!    `UmbrellaProvider` (classical only) can create a group on CS=0x0003
//!    (classical default). PQ provider is a superset, classical provider is a
//!    subset; intersection = classical → group is downgraded to classical,
//!    which is expected for mixed PQ/non-PQ deployments.
//!
//! 3. **Classical peer cannot join an X-Wing Welcome.** Alice creates a group
//!    on 0x004D and sends a Welcome → Bob with classical UmbrellaProvider
//!    fails at join_from_welcome (openmls_rust_crypto cannot HPKE-decrypt the
//!    X-Wing Welcome).

#![cfg(feature = "pq")]

use std::sync::Arc;

use openmls::group::GroupId;

use umbrella_identity::{
    keystore::FixedClock, Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage,
};
use umbrella_mls::{
    build_device_key_package,
    provider::{UmbrellaProvider, UmbrellaXWingProvider},
    GroupPolicy, IncomingMessage, MlsError, UmbrellaCiphersuite, UmbrellaGroup,
};

/// X-Wing ciphersuite (0x004D).
const CS_XWING: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519;
/// Classical default — ChaCha20-Poly1305 + X25519 + Ed25519.
const CS_CLASSICAL: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;

const T0: u64 = 1_700_000_000;

fn fresh_keystore_for_device(device_index: u32) -> Arc<InMemoryKeyStore> {
    let mut rng = rand_core::OsRng;
    #[allow(deprecated)]
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let clock = FixedClock::new(T0);
    let ks = InMemoryKeyStore::open(seed, 0, Arc::new(clock) as Arc<dyn Clock>).unwrap();
    ks.add_device(device_index, None).unwrap();
    Arc::new(ks)
}

/// Попытка создать группу с CS=0x004D через classical provider должна fail'ить
/// (openmls_rust_crypto-0.5.1 returns CryptoError::UnsupportedCiphersuite на
/// X-Wing). Защита постулата 14 — никаких runtime panic.
/// Creating a group with CS=0x004D via the classical provider must fail
/// (openmls_rust_crypto-0.5.1 returns CryptoError::UnsupportedCiphersuite for
/// X-Wing). Postulate-14 protection — no runtime panic.
#[test]
fn create_private_with_classical_provider_and_xwing_ciphersuite_fails() {
    let ks = fresh_keystore_for_device(0);
    let classical_provider = UmbrellaProvider::default();
    let group_id = GroupId::from_slice(b"downgrade-test-001");

    let result =
        UmbrellaGroup::create_private(&classical_provider, ks.as_ref(), 0, CS_XWING, group_id, T0);

    // Должен fail с GroupOperation (внутренний openmls fail из-за
    // UnsupportedCiphersuite). Конкретный variant — не важен, главное что
    // не panic и не silent ok.
    // Must fail with GroupOperation (inner openmls fails on
    // UnsupportedCiphersuite). The exact variant does not matter; the key
    // property is no panic and no silent ok.
    let err = result.map(|_| ()).err();
    assert!(
        matches!(err, Some(MlsError::GroupOperation { .. })),
        "classical provider must fail on X-Wing ciphersuite: got error {err:?}"
    );
}

/// PQ-aware Alice + classical Bob договариваются на classical ciphersuite.
/// Защита: mixed deployment не падает — fallback на classical наблюдается
/// явно через choice ciphersuite (не silent X-Wing с runtime panic).
/// PQ-aware Alice + classical Bob negotiate on a classical ciphersuite.
/// Protection: mixed deployment does not break — fallback to classical is
/// observable via the chosen ciphersuite (not silent X-Wing with runtime panic).
#[test]
fn pq_alice_classical_bob_communicate_on_classical_ciphersuite() {
    // Alice имеет UmbrellaXWingProvider (поддерживает classical + PQ).
    // Alice has UmbrellaXWingProvider (supports classical + PQ).
    let alice_ks = fresh_keystore_for_device(0);
    let alice_provider = UmbrellaXWingProvider::new_for_kat_tests_only();

    // Bob использует UmbrellaProvider (classical only).
    // Bob uses UmbrellaProvider (classical only).
    let bob_ks = fresh_keystore_for_device(1);
    let bob_provider = UmbrellaProvider::default();

    // Alice создаёт группу на classical CS — works через PQ provider тоже.
    // Alice creates a group on classical CS — works via the PQ provider too.
    let group_id = GroupId::from_slice(b"mixed-classical-grp");
    let mut alice_group = UmbrellaGroup::create_private(
        &alice_provider,
        alice_ks.as_ref(),
        0,
        CS_CLASSICAL,
        group_id,
        T0,
    )
    .expect("Alice classical group creation through PQ provider must work");
    assert_eq!(alice_group.ciphersuite(), CS_CLASSICAL);

    // Bob публикует classical KeyPackage.
    // Bob publishes a classical KeyPackage.
    let bob_kp = build_device_key_package(&bob_provider, bob_ks.as_ref(), 1, CS_CLASSICAL)
        .expect("Bob classical KeyPackage")
        .key_package()
        .clone();

    // Alice добавляет Bob → Welcome.
    // Alice adds Bob → Welcome.
    let outcome = alice_group
        .add_members(
            &alice_provider,
            alice_ks.as_ref(),
            std::slice::from_ref(&bob_kp),
            T0,
        )
        .expect("Alice add classical Bob");
    let welcome_bytes = outcome.welcome.expect("welcome must be Some");

    // Bob join'ит через classical provider — works (CS=0x0003 supported).
    // Bob joins via classical provider — works (CS=0x0003 supported).
    let mut bob_group = UmbrellaGroup::join_from_welcome(
        &bob_provider,
        bob_ks.as_ref(),
        1,
        &welcome_bytes,
        GroupPolicy::Private,
        T0,
    )
    .expect("Bob classical join must work for classical CS");
    assert_eq!(bob_group.ciphersuite(), CS_CLASSICAL);

    // Application message обмен — Alice → Bob.
    // Application message exchange — Alice → Bob.
    let alice_msg = b"mixed deployment hello";
    let ct = alice_group
        .encrypt_application(&alice_provider, alice_ks.as_ref(), alice_msg)
        .expect("Alice encrypt");
    match bob_group
        .process_incoming(&bob_provider, &ct)
        .expect("Bob process")
    {
        IncomingMessage::Application { payload, .. } => assert_eq!(payload, alice_msg),
        other => panic!("expected Application, got {other:?}"),
    }
}

/// Classical peer не может join'ить X-Wing Welcome — openmls_rust_crypto не
/// supports X-Wing HPKE для расшифровки Welcome (`unimplemented!()` в
/// `kem_mode(XWingKemDraft6)` would panic; openmls validates supports() before
/// reaching там, поэтому получаем ordered Welcome rejection вместо panic).
/// A classical peer cannot join an X-Wing Welcome — openmls_rust_crypto does
/// not support X-Wing HPKE for Welcome decryption (`unimplemented!()` in
/// `kem_mode(XWingKemDraft6)` would panic; openmls validates supports() before
/// that path, so we get an ordered Welcome rejection instead of a panic).
#[test]
fn classical_peer_cannot_join_xwing_welcome() {
    // Alice через UmbrellaXWingProvider создаёт X-Wing group.
    // Alice creates an X-Wing group via UmbrellaXWingProvider.
    let alice_ks = fresh_keystore_for_device(0);
    let alice_provider = UmbrellaXWingProvider::new_for_kat_tests_only();

    let group_id = GroupId::from_slice(b"classical-cant-join");
    let mut alice_group = UmbrellaGroup::create_private(
        &alice_provider,
        alice_ks.as_ref(),
        0,
        CS_XWING,
        group_id,
        T0,
    )
    .expect("Alice X-Wing group creation");

    // Bob has X-Wing-capable KeyPackage (через своего PQ provider).
    // Bob has an X-Wing-capable KeyPackage (via his own PQ provider).
    let bob_ks = fresh_keystore_for_device(1);
    let bob_pq_provider = UmbrellaXWingProvider::new_for_kat_tests_only();
    let bob_kp = build_device_key_package(&bob_pq_provider, bob_ks.as_ref(), 1, CS_XWING)
        .expect("Bob X-Wing KeyPackage")
        .key_package()
        .clone();

    let outcome = alice_group
        .add_members(
            &alice_provider,
            alice_ks.as_ref(),
            std::slice::from_ref(&bob_kp),
            T0,
        )
        .expect("Alice add Bob to X-Wing group");
    let welcome_bytes = outcome.welcome.expect("welcome");

    // Bob теперь пытается join Welcome через CLASSICAL provider — должен fail.
    // Bob now tries to join the Welcome via the CLASSICAL provider — must fail.
    let bob_classical_provider = UmbrellaProvider::default();
    let result = UmbrellaGroup::join_from_welcome(
        &bob_classical_provider,
        bob_ks.as_ref(),
        1,
        &welcome_bytes,
        GroupPolicy::Private,
        T0,
    );

    let err = result.map(|_| ()).err();
    assert!(
        err.is_some(),
        "classical provider must NOT join an X-Wing Welcome: got Ok"
    );
}
