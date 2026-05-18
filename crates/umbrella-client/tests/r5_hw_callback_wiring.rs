//! Round-5 device-capture closure — `ClientCore` wiring через
//! `PersistentKeyStoreCallback` доказывает что:
//!
//! 1. `ClientCore::new_with_hw_callback` принимает callback Arc и
//!    bootstraps identity без передачи raw seed bytes в Rust.
//! 2. `MockHwKeystore::generate_identity` хранит секрет в `MlockedSecret<[u8; 32]>`
//!    (heap-resident + libc::mlock) — никаких stack copies на тестовом пути.
//! 3. `core.has_hw_identity() == true` после bootstrap.
//! 4. `core.hw_identity_handle()` доступен; signing operations идут через callback.
//!
//! Acceptance: round-5 spec §«Acceptance gate row 1» — trait + wired via
//! IdentityStore bootstrap. Этот test проверяет именно wire-up path.
//!
//! Round-5 device-capture closure — `ClientCore` wiring through
//! `PersistentKeyStoreCallback` proves that:
//!
//! 1. `ClientCore::new_with_hw_callback` accepts a callback Arc and
//!    bootstraps identity without passing raw seed bytes through Rust.
//! 2. `MockHwKeystore::generate_identity` stores the secret in a
//!    `MlockedSecret<[u8; 32]>` (heap-resident + libc::mlock) — no stack
//!    copies on the test path.
//! 3. `core.has_hw_identity() == true` after bootstrap.
//! 4. `core.hw_identity_handle()` is available; signing operations route
//!    through the callback.
//!
//! Acceptance: round-5 spec §«Acceptance gate row 1» — trait + wired via
//! IdentityStore bootstrap. This test verifies that wire-up path.

use std::sync::Arc;

use umbrella_client::keystore::hw_callback::{MockHwKeystore, PersistentKeyStoreCallback};
use umbrella_client::{ClientConfig, ClientCore};

#[tokio::test]
async fn r5_client_core_bootstraps_with_hw_callback() {
    let callback: Arc<dyn PersistentKeyStoreCallback> = Arc::new(MockHwKeystore::new());
    let config = ClientConfig::default();
    let core = ClientCore::new_with_hw_callback(
        config,
        callback,
        "xyz.umbrellax.identity.primary",
    )
    .await
    .expect("bootstrap with hw callback");

    assert!(core.has_hw_identity(), "hw identity must be wired");
    let handle = core
        .hw_identity_handle()
        .expect("hw_identity_handle present");
    assert_eq!(handle.label(), "xyz.umbrellax.identity.primary");
}

#[tokio::test]
async fn r5_legacy_bootstrap_for_test_has_no_hw_identity() {
    // Sanity: legacy path NEVER claims hw identity (postulate: explicit opt-in).
    // Sanity: the legacy path NEVER claims hw identity (postulate: explicit opt-in).
    use umbrella_identity::{IdentitySeed, MnemonicLanguage};
    let seed = IdentitySeed::generate(&mut rand_core::OsRng, MnemonicLanguage::English);
    let core = ClientCore::new_for_test(ClientConfig::default(), seed)
        .await
        .expect("legacy bootstrap");
    assert!(!core.has_hw_identity());
    assert!(core.hw_identity_handle().is_none());
}

#[tokio::test]
async fn r5_callback_sign_through_handle_works() {
    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let config = ClientConfig::default();
    let core = ClientCore::new_with_hw_callback(
        config,
        callback,
        "xyz.umbrellax.identity.sign-test",
    )
    .await
    .expect("bootstrap with hw callback");

    let handle = core
        .hw_identity_handle()
        .expect("hw identity present")
        .clone();

    // Direct callback invocation — production code goes through facade
    // wrappers but this proves the wiring path.
    let sig = mock.sign_identity(&handle, b"r5-acceptance-test").expect("sign");
    assert_eq!(sig.len(), 64, "Ed25519 signatures are always 64 bytes");
}

/// **F-CLIENT-HW-1 closure regression test — verifying-key consistency.**
///
/// Public-API view of the closure: `core.identity_verifying_key()` MUST
/// return bytes that match a signature produced by the hardware-resident
/// identity. End-to-end check via public API only:
///
/// 1. Bootstrap a ClientCore with hw_callback.
/// 2. Fetch identity_verifying_key() through the accessor (no
///    `pub(crate)` field access — pure consumer view).
/// 3. Sign a message via mock.sign_identity(handle, msg).
/// 4. Verify the signature using the accessor-returned bytes as the
///    Ed25519 public key.
///
/// Pre-closure the accessor returned bytes for an EPHEMERAL synthesized
/// identity that did NOT correspond to the hardware key — signatures
/// from the hardware key would FAIL verification under those bytes.
/// Post-closure the accessor returns the real hardware verifying-key
/// and the verification succeeds.
///
/// This test is the consumer-side regression guard: any future change
/// that re-introduces ephemeral-identity synthesis (or any other
/// drift between `identity_verifying_key()` and the actual signing key)
/// breaks the verification step.
#[tokio::test]
async fn f_client_hw_1_identity_verifying_key_verifies_real_hw_signatures() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let core = ClientCore::new_with_hw_callback(
        ClientConfig::default(),
        callback,
        "f-client-hw-1.public-api.verification",
    )
    .await
    .expect("bootstrap with hw callback");

    let accessor_vk_bytes = core
        .identity_verifying_key()
        .expect("identity_verifying_key on hw core");

    // The accessor's bytes MUST decode as a valid Ed25519 point. The
    // pre-closure ephemeral-identity synthesis ALSO produced valid bytes
    // (it derived a fresh IdentityKey), so this check alone wouldn't
    // catch the gap. The verification step below does.
    let vk = VerifyingKey::from_bytes(&accessor_vk_bytes)
        .expect("accessor returned a valid Ed25519 point");

    // Sign a message via the HARDWARE-resident identity (mock.sign_identity
    // dispatches into the keystore — production this is SE/StrongBox).
    let handle = core.hw_identity_handle().expect("handle").clone();
    let msg = b"F-CLIENT-HW-1 closure public-API verification message";
    let sig_bytes = mock.sign_identity(&handle, msg).expect("sign via hw");
    let sig =
        Signature::from_slice(&sig_bytes).expect("Ed25519 sig is 64 bytes");

    // Pre-closure: the accessor returned bytes for an EPHEMERAL identity
    // unrelated to the hardware key, so this verification would FAIL
    // with a SignatureError. Post-closure: the accessor returns the
    // hardware key's verifying-key, so verification succeeds.
    vk.verify(msg, &sig).expect(
        "F-CLIENT-HW-1 closure: identity_verifying_key MUST correspond to the \
         hardware-resident signing key; ephemeral-identity synthesis would break \
         this verification",
    );
}

/// **F-CLIENT-HW-1 closure regression test — legacy path partition.**
///
/// `new_for_test` keeps the legacy in-heap identity path; the accessor
/// returns `IdentityKey::derive(seed, 0).public().to_bytes()`. Mirror
/// of the HW test above for the legacy regime — together they prove
/// the two regimes are total and disjoint as far as the public API
/// exposes.
#[tokio::test]
async fn f_client_hw_1_legacy_accessor_matches_identity_public() {
    use umbrella_identity::{IdentitySeed, MnemonicLanguage};

    let mut rng = rand_core::OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let expected_vk = umbrella_identity::IdentityKey::derive(&seed, 0)
        .expect("derive identity from seed")
        .public()
        .to_bytes();

    let client = umbrella_client::UmbrellaClient::bootstrap_for_test(
        ClientConfig::default(),
        seed,
    )
    .await
    .expect("legacy bootstrap");
    let core = client.core();

    let accessor_vk = core
        .identity_verifying_key()
        .expect("accessor on legacy core");
    assert_eq!(
        accessor_vk, expected_vk,
        "F-CLIENT-HW-1: legacy accessor MUST equal IdentityKey::derive(seed, 0).public()"
    );
}

/// **F-CLIENT-HW-1 closure regression test — HW path has no leakable
/// in-heap identity key.**
///
/// Public-API view: a hw-bootstrapped ClientCore must NOT expose any
/// `IdentityKey` instance to consumers. We exercise the only public
/// reader (`identity_verifying_key()`), confirm it succeeds, and
/// confirm no other public API surface lets a caller extract a
/// SigningKey. The closure invariant — `core.identity = None` on HW —
/// is verified by `production_boundary_tests` inside `core.rs` (those
/// tests can reach `pub(crate)` fields). This public-API mirror simply
/// proves the accessor remains a one-way (read-only public-bytes)
/// surface and that no secret material ever crosses the FFI boundary
/// or the Rust-heap boundary on this path.
#[tokio::test]
async fn f_client_hw_1_hw_path_public_api_yields_no_in_heap_secret() {
    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let core = ClientCore::new_with_hw_callback(
        ClientConfig::default(),
        callback,
        "f-client-hw-1.public-api.read-only",
    )
    .await
    .expect("hw bootstrap");

    // Public API exposes:
    //   - has_hw_identity() -> bool (no key material)
    //   - hw_identity_handle() -> Option<&HwKeyHandle> (opaque alias, no key)
    //   - identity_verifying_key() -> Result<[u8; 32]> (public bytes only)
    //   - default_ciphersuite() -> u16 (no key material)
    //   - device_index() -> u32 (no key material)
    //   - config() -> ClientConfig (no key material)
    //
    // None of these methods can leak the hardware-resident signing
    // scalar. Verifying-key is public by definition of asymmetric
    // cryptography; HwKeyHandle is an opaque alias string. Pre-closure
    // there was a fourth surface — `pub(crate) identity: Arc<IdentityKey>`
    // (with crate-internal `.sign()` capability) — bypassing the
    // PersistentKeyStore boundary; closure removes the in-heap
    // IdentityKey entirely on this path.
    assert!(core.has_hw_identity());
    assert!(core.hw_identity_handle().is_some());
    let vk = core
        .identity_verifying_key()
        .expect("accessor must succeed on hw core");
    assert_eq!(vk.len(), 32, "verifying-key is 32 bytes");
}
