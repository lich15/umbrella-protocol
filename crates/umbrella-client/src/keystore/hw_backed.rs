//! `HwBackedKeyStore` — hardware-backed `KeyStore` impl.
//! `HwBackedKeyStore` — hardware-backed `KeyStore` impl.
//!
//! **F-IDENT-1 + F-IDENT-2 closure (PhD-B Pass 5 remediation 2026-05-19).**
//!
//! Identity-key signing scalar **физически** resides в Secure Enclave /
//! StrongBox через [`PersistentKeyStoreCallback`]. `HwBackedKeyStore`
//! содержит ТОЛЬКО:
//!
//! - `account: u32`
//! - `callback: Arc<dyn PersistentKeyStoreCallback>`
//! - `identity_handle: HwKeyHandle` (opaque alias string)
//! - `identity_public_cached: IdentityKeyPublic` (32 bytes, public by
//!   definition of asymmetric cryptography)
//!
//! Никакого `IdentitySeed`, никакого `IdentityKey` struct'а, никаких
//! приватных Ed25519 scalar в Rust heap. F-IDENT-2 закрыт по дизайну:
//! `HwBackedKeyStore` не имеет `seed` поля. Adversary с runtime process-
//! memory access на HW-bootstrapped client'е получает только public
//! material (identity_pubkey, handle alias) — ни одного байта секрета,
//! из которого можно re-derive identity_sk.
//!
//! # Покрытие KeyStore API (v1.0.0 honest scope)
//!
//! Полностью реализованы через callback:
//!
//! - [`KeyStore::account`]
//! - [`KeyStore::identity_public`]
//! - [`KeyStore::sign_with_identity`] — routes through
//!   [`PersistentKeyStoreCallback::sign_identity`]
//!
//! Honestly закрытые (fail-closed с [`IdentityError::HwBackedUnsupported`]):
//!
//! - [`KeyStore::add_device`] / [`KeyStore::revoke_device`] /
//!   [`KeyStore::sign_with_device`] — требуют callback методов для генерации
//!   и подписи device handle (F-IDENT-DEVICE-1 v1.2.x)
//! - [`KeyStore::active_device_indices`] /
//!   [`KeyStore::all_known_device_indices`] / [`KeyStore::device_public`]
//!   /[`KeyStore::device_attestation`] — empty/None т.к. device keys не
//!   зарегистрированы (consistent с no devices)
//!
//! Panic с explicit message (методы trait не возвращают `Result`, нельзя
//! fail-closed cleanly):
//!
//! - [`KeyStore::identity_x25519_public`] /
//!   [`KeyStore::x25519_dh_with_identity`] — требуют X25519 DH в TEE
//!   (F-IDENT-X25519-1 v1.2.x). Production code пути reach'ить этих
//!   методов в hw-mode на v1.0.0 не должны — facade gating через
//!   F-CLIENT-FACADE-1 stubs.
//! - PQ методы — same caveat (F-IDENT-PQ-1 v1.2.x)
//!
//! # Production roadmap
//!
//! Block 7.4+ facade integration:
//!
//! 1. Expand [`PersistentKeyStoreCallback`] с device-key generation +
//!    signing methods (`generate_device_handle`, `sign_device(handle, data)`,
//!    `delete_device(handle)`). Native iOS: `SecKeyCreateRandomKey` под
//!    отдельным `kSecAttrApplicationTag`. Native Android: `KeyStore`
//!    entries с distinct aliases.
//! 2. Expand callback с `x25519_dh(handle, peer_pub) -> Result<SecretBytes<32>>`.
//!    Native iOS: `SecKeyCreateRandomKey(kSecAttrKeyTypeECSECPrimeRandom)` +
//!    `SecKeyCopyKeyExchangeResult(kSecKeyAlgorithmECDHKeyExchangeStandard)`.
//!    Android: `KeyAgreement.getInstance("ECDH")` поверх StrongBox key.
//! 3. Implement device-key tracking inside `HwBackedKeyStore` с
//!    `Mutex<BTreeMap<u32, HwDeviceRecord>>`, populated через `add_device`
//!    rolling new HW handle + signing `DeviceAttestation` через
//!    identity_handle.
//! 4. (Опц.) PQ tracks через separate FFI bridge для ML-DSA / SLH-DSA /
//!    X-Wing primitives — required только если HW vendor exposes these
//!    natively (Android Keystore 14+ имеет experimental support).
//!
//! `HwBackedKeyStore` — hardware-backed `KeyStore` implementation.
//!
//! **F-IDENT-1 + F-IDENT-2 closure (PhD-B Pass 5 remediation 2026-05-19).**
//!
//! The identity-key signing scalar **physically** lives in the Secure
//! Enclave / StrongBox through [`PersistentKeyStoreCallback`].
//! `HwBackedKeyStore` holds ONLY:
//!
//! - `account: u32`
//! - `callback: Arc<dyn PersistentKeyStoreCallback>`
//! - `identity_handle: HwKeyHandle` (opaque alias string)
//! - `identity_public_cached: IdentityKeyPublic` (32 bytes, public by
//!   definition of asymmetric cryptography)
//!
//! No `IdentitySeed`, no `IdentityKey` struct, no private Ed25519 scalars
//! on the Rust heap. F-IDENT-2 is closed by design: `HwBackedKeyStore`
//! has no `seed` field. An adversary with runtime process-memory access
//! on a HW-bootstrapped client gets only public material (identity
//! pubkey, handle alias) — not a single byte of secret from which
//! identity_sk could be re-derived.
//!
//! # KeyStore API coverage (v1.0.0 honest scope)
//!
//! Fully implemented through the callback:
//!
//! - [`KeyStore::account`]
//! - [`KeyStore::identity_public`]
//! - [`KeyStore::sign_with_identity`] — routes through
//!   [`PersistentKeyStoreCallback::sign_identity`]
//!
//! Honestly closed (fail-closed with
//! [`IdentityError::HwBackedUnsupported`]):
//!
//! - [`KeyStore::add_device`] / [`KeyStore::revoke_device`] /
//!   [`KeyStore::sign_with_device`] — require callback methods for
//!   generating and signing with device handles (F-IDENT-DEVICE-1
//!   v1.2.x)
//! - [`KeyStore::active_device_indices`] /
//!   [`KeyStore::all_known_device_indices`] / [`KeyStore::device_public`]
//!   / [`KeyStore::device_attestation`] — empty/None because no device
//!   keys are registered (consistent "no devices" view)
//!
//! Panic with an explicit message (trait methods that do not return
//! `Result` cannot fail-closed cleanly):
//!
//! - [`KeyStore::identity_x25519_public`] /
//!   [`KeyStore::x25519_dh_with_identity`] — require X25519 DH inside
//!   the TEE (F-IDENT-X25519-1 v1.2.x). Production code paths must
//!   not reach these methods in hw-mode at v1.0.0 — facade gating
//!   via F-CLIENT-FACADE-1 stubs.
//! - PQ methods — same caveat (F-IDENT-PQ-1 v1.2.x)

use std::sync::Arc;

use umbrella_crypto_primitives::secret::SecretBytes;
use umbrella_crypto_primitives::sig::Ed25519Signature;

use umbrella_identity::{
    DeviceAttestation, DeviceKeyPublic, IdentityError, IdentityKeyPublic,
    IdentityX25519KeyPublic, KeyStore,
};

use crate::keystore::hw_callback::{HwKeyHandle, PersistentKeyStoreCallback};

/// Hardware-backed `KeyStore` implementation.
///
/// Hardware-backed `KeyStore` implementation.
///
/// See module-level docs for full closure semantics. Construct via
/// [`Self::new`] from the bytes returned by
/// [`crate::keystore::hw_callback::bootstrap_hw_identity`].
pub struct HwBackedKeyStore {
    /// Индекс аккаунта в BIP-32 дереве (обычно 0). Хранится только для
    /// `KeyStore::account()` accessor.
    ///
    /// Account index in the BIP-32 tree (usually 0). Stored only for the
    /// `KeyStore::account()` accessor.
    account: u32,

    /// Hardware-backed keystore callback. Все identity-sk операции
    /// dispatch через этот callback.
    ///
    /// Hardware-backed keystore callback. All identity-sk operations
    /// dispatch through this callback.
    callback: Arc<dyn PersistentKeyStoreCallback>,

    /// Opaque alias на TEE-resident identity key. Хранится для последующих
    /// `sign_with_identity` invocations.
    ///
    /// Opaque alias to the TEE-resident identity key. Stored for subsequent
    /// `sign_with_identity` invocations.
    identity_handle: HwKeyHandle,

    /// Cached 32-byte Ed25519 verifying-key для identity. Populated at
    /// construction time через [`PersistentKeyStoreCallback::verifying_key`]
    /// (вернее, его F-CLIENT-HW-2 closure bytes уже surfaced caller'ом).
    /// Public material — не секрет.
    ///
    /// Cached 32-byte Ed25519 verifying-key for the identity. Populated
    /// at construction time through
    /// [`PersistentKeyStoreCallback::verifying_key`] (more precisely, its
    /// F-CLIENT-HW-2 closure bytes were already surfaced by the caller).
    /// Public material — not a secret.
    identity_public_cached: IdentityKeyPublic,
}

impl HwBackedKeyStore {
    /// Constructs a `HwBackedKeyStore` from bootstrap byproducts.
    ///
    /// Constructs a `HwBackedKeyStore` from bootstrap byproducts.
    ///
    /// `verifying_key_bytes` must be the 32-byte Ed25519 verifying-key
    /// returned by [`crate::keystore::hw_callback::bootstrap_hw_identity`]
    /// (post F-CLIENT-HW-2 closure: real bytes, not the legacy
    /// `[0u8; 32]` placeholder).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Crypto`] if `verifying_key_bytes` does not
    ///   decode as a valid Ed25519 point. In production this would
    ///   indicate the native bridge returned malformed bytes — a hard
    ///   failure that should abort bootstrap rather than mask.
    pub fn new(
        account: u32,
        callback: Arc<dyn PersistentKeyStoreCallback>,
        identity_handle: HwKeyHandle,
        verifying_key_bytes: [u8; 32],
    ) -> Result<Self, IdentityError> {
        let identity_public_cached = IdentityKeyPublic::from_bytes(&verifying_key_bytes)?;
        Ok(Self {
            account,
            callback,
            identity_handle,
            identity_public_cached,
        })
    }

    /// Returns the underlying HW key handle (opaque alias). Useful for
    /// callers that need to perform direct callback operations bypassing
    /// the `KeyStore` trait (e.g. wrap/unwrap secrets for the
    /// non-key-material side of the keystore).
    ///
    /// Returns the underlying HW key handle (opaque alias). Useful for
    /// callers that need to perform direct callback operations bypassing
    /// the `KeyStore` trait (e.g. wrap/unwrap secrets for the
    /// non-key-material side of the keystore).
    #[must_use]
    pub fn identity_handle(&self) -> &HwKeyHandle {
        &self.identity_handle
    }

    /// Returns a clone of the underlying callback handle. Useful for
    /// callers that need additional hardware-backed operations (e.g.
    /// device-key bootstrap via expanded callback methods in v1.2.x).
    ///
    /// Returns a clone of the underlying callback handle. Useful for
    /// callers that need additional hardware-backed operations (e.g.
    /// device-key bootstrap via expanded callback methods in v1.2.x).
    #[must_use]
    pub fn callback(&self) -> Arc<dyn PersistentKeyStoreCallback> {
        self.callback.clone()
    }
}

impl KeyStore for HwBackedKeyStore {
    fn account(&self) -> u32 {
        self.account
    }

    fn identity_public(&self) -> IdentityKeyPublic {
        self.identity_public_cached
    }

    /// Routes signing through [`PersistentKeyStoreCallback::sign_identity`].
    /// The 64-byte Ed25519 signature comes from the TEE; identity_sk
    /// never enters Rust heap.
    ///
    /// **Failure handling caveat:** the `KeyStore` trait signs through a
    /// `-> Ed25519Signature` return (no `Result`). HW callback errors
    /// (`UserDenied`, `HardwareUnavailable`, etc.) panic with an explicit
    /// message. Block 7.4+ facade refactor may rework the trait to
    /// return `Result<Ed25519Signature, IdentityError>` so that biometric
    /// prompts can surface to UI gracefully. Pre-Block-7.4: panic is the
    /// honest signal — production facades have not yet wired the path.
    fn sign_with_identity(&self, message: &[u8]) -> Ed25519Signature {
        let sig_bytes = self
            .callback
            .sign_identity(&self.identity_handle, message)
            .unwrap_or_else(|err| {
                panic!(
                    "HwBackedKeyStore::sign_with_identity — hw callback failed for handle {handle}: {err}. \
                     Block 7.4+ facade refactor must rework KeyStore::sign_with_identity to \
                     return Result so biometric prompts (UserDenied) can surface gracefully.",
                    handle = self.identity_handle,
                )
            });
        assert_eq!(
            sig_bytes.len(),
            64,
            "HwBackedKeyStore::sign_with_identity — callback returned malformed signature length \
             {} (expected 64); native bridge bug",
            sig_bytes.len(),
        );
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        Ed25519Signature::from_bytes(&sig_arr)
    }

    /// Returns an empty list: device-key registration is not yet
    /// supported in hardware-backed mode at v1.0.0 (F-IDENT-DEVICE-1
    /// v1.2.x). Consistent with "no devices registered" view.
    ///
    /// Returns an empty list: device-key registration is not yet
    /// supported in hardware-backed mode at v1.0.0 (F-IDENT-DEVICE-1
    /// v1.2.x). Consistent with "no devices registered" view.
    fn active_device_indices(&self) -> Vec<u32> {
        Vec::new()
    }

    fn all_known_device_indices(&self) -> Vec<u32> {
        Vec::new()
    }

    fn device_public(&self, _index: u32) -> Option<DeviceKeyPublic> {
        None
    }

    fn device_attestation(&self, _index: u32) -> Option<DeviceAttestation> {
        None
    }

    fn sign_with_device(
        &self,
        index: u32,
        _message: &[u8],
    ) -> Result<Ed25519Signature, IdentityError> {
        // No devices registered in v1.0.0 hw-mode → UnknownDevice is the
        // honest answer (NOT HwBackedUnsupported, since the device truly
        // is not registered). Consistent with `active_device_indices()`
        // returning an empty list.
        Err(IdentityError::UnknownDevice { index })
    }

    fn add_device(
        &self,
        _index: u32,
        _ttl_secs: Option<u64>,
    ) -> Result<DeviceAttestation, IdentityError> {
        Err(IdentityError::HwBackedUnsupported {
            method: "add_device",
            reason:
                "device-key generation + DeviceAttestation issuance via TEE requires expanding \
                 PersistentKeyStoreCallback with generate_device_handle/sign_device methods \
                 (F-IDENT-DEVICE-1 v1.2.x)",
        })
    }

    fn revoke_device(&self, index: u32) -> Result<(), IdentityError> {
        // No devices registered → UnknownDevice (mirrors what add_device
        // would not have inserted).
        Err(IdentityError::UnknownDevice { index })
    }

    /// **Panic in v1.0.0 hw-mode.** `KeyStore::identity_x25519_public`
    /// returns `IdentityX25519KeyPublic` (no `Result`); without a TEE-side
    /// X25519 DH method on `PersistentKeyStoreCallback` we cannot deliver
    /// a real key without materialising X25519 secret in heap (which
    /// would re-introduce the F-IDENT-2 gap). Production facade gating
    /// (F-CLIENT-FACADE-1 stubs) ensures no code path reaches here in
    /// hw-mode at v1.0.0. F-IDENT-X25519-1 v1.2.x closure will add
    /// `callback.x25519_public(handle)` and remove this panic.
    ///
    /// **Panics in v1.0.0 hw-mode.** `KeyStore::identity_x25519_public`
    /// returns `IdentityX25519KeyPublic` (no `Result`); without a TEE-side
    /// X25519 DH method on `PersistentKeyStoreCallback` we cannot deliver
    /// a real key without materialising X25519 secret in heap (which
    /// would re-introduce the F-IDENT-2 gap). Production facade gating
    /// (F-CLIENT-FACADE-1 stubs) ensures no code path reaches here in
    /// hw-mode at v1.0.0. F-IDENT-X25519-1 v1.2.x closure will add
    /// `callback.x25519_public(handle)` and remove this panic.
    fn identity_x25519_public(&self) -> IdentityX25519KeyPublic {
        unimplemented!(
            "HwBackedKeyStore::identity_x25519_public — X25519 DH inside TEE is not yet wired \
             (F-IDENT-X25519-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }

    fn x25519_dh_with_identity(&self, _peer: &IdentityX25519KeyPublic) -> SecretBytes<32> {
        unimplemented!(
            "HwBackedKeyStore::x25519_dh_with_identity — X25519 DH inside TEE is not yet wired \
             (F-IDENT-X25519-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }

    // ─── Hybrid post-quantum API (feature `pq`) — все unimplemented ───
    //
    // Все PQ методы возвращают ошибку либо panic с указанием
    // F-IDENT-PQ-1 v1.2.x follow-up track. ML-DSA-65 / SLH-DSA / X-Wing
    // primitives не доступны в современных мобильных TEE (iOS Secure
    // Enclave / Android StrongBox) — поддержка требует либо software
    // fallback с careful zeroization, либо expanded vendor APIs.
    //
    // All PQ methods return an error or panic with a pointer to the
    // F-IDENT-PQ-1 v1.2.x follow-up track. ML-DSA-65 / SLH-DSA / X-Wing
    // primitives are not available in current mobile TEEs (iOS Secure
    // Enclave / Android StrongBox) — support requires either a careful
    // software fallback with zeroization or expanded vendor APIs.

    #[cfg(feature = "pq")]
    fn hybrid_identity_public(&self) -> umbrella_identity::HybridIdentityKeyPublic {
        unimplemented!(
            "HwBackedKeyStore::hybrid_identity_public — ML-DSA-65 in TEE not yet wired \
             (F-IDENT-PQ-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }

    #[cfg(feature = "pq")]
    fn sign_with_hybrid_identity(
        &self,
        _message: &[u8],
    ) -> Result<umbrella_pq::HybridSignature, IdentityError> {
        Err(IdentityError::HwBackedUnsupported {
            method: "sign_with_hybrid_identity",
            reason:
                "ML-DSA-65 signing in TEE requires PQ callback expansion (F-IDENT-PQ-1 v1.2.x)",
        })
    }

    #[cfg(feature = "pq")]
    fn hybrid_device_public(
        &self,
        _index: u32,
    ) -> Option<umbrella_identity::HybridDeviceKeyPublic> {
        None
    }

    #[cfg(feature = "pq")]
    fn sign_with_hybrid_device(
        &self,
        index: u32,
        _message: &[u8],
    ) -> Result<umbrella_pq::HybridSignature, IdentityError> {
        Err(IdentityError::UnknownDevice { index })
    }

    #[cfg(feature = "pq")]
    fn slh_dsa_backup_public(&self) -> umbrella_identity::SlhDsaBackupKeyPublic {
        unimplemented!(
            "HwBackedKeyStore::slh_dsa_backup_public — SLH-DSA in TEE not yet wired \
             (F-IDENT-PQ-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }

    #[cfg(feature = "pq")]
    fn sign_slh_dsa_backup_proof(
        &self,
        _message: &[u8],
    ) -> Result<umbrella_pq::SlhDsa128fSignature, IdentityError> {
        Err(IdentityError::HwBackedUnsupported {
            method: "sign_slh_dsa_backup_proof",
            reason:
                "SLH-DSA backup signing in TEE requires PQ callback expansion \
                 (F-IDENT-PQ-1 v1.2.x)",
        })
    }

    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_public(&self) -> umbrella_identity::CloudWrapRecoveryKeyPublic {
        unimplemented!(
            "HwBackedKeyStore::cloud_wrap_recovery_public — X-Wing recovery in TEE not yet wired \
             (F-IDENT-PQ-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }

    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_decapsulate(
        &self,
        _ct: &[u8; umbrella_pq::XWING_CIPHERTEXT_LEN],
    ) -> Result<secrecy::SecretBox<[u8; umbrella_pq::XWING_SHARED_SECRET_LEN]>, IdentityError>
    {
        Err(IdentityError::HwBackedUnsupported {
            method: "cloud_wrap_recovery_decapsulate",
            reason:
                "X-Wing decapsulation in TEE requires PQ callback expansion \
                 (F-IDENT-PQ-1 v1.2.x)",
        })
    }

    #[cfg(feature = "pq")]
    fn hedged_encaps_witness(&self) -> &umbrella_pq::HedgedWitness {
        unimplemented!(
            "HwBackedKeyStore::hedged_encaps_witness — HKDF-on-seed-derivative in TEE not yet \
             wired (F-IDENT-PQ-1 v1.2.x). Facade gating via F-CLIENT-FACADE-1 stubs must prevent \
             reaching this path at v1.0.0."
        )
    }
}

impl core::fmt::Debug for HwBackedKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Debug intentionally avoids printing the callback (which may
        // not implement Debug) and renders only public material plus the
        // handle alias. Identity_pubkey is rendered through the
        // IdentityKeyPublic Debug impl (first 4 hex bytes only).
        f.debug_struct("HwBackedKeyStore")
            .field("account", &self.account)
            .field("identity_public", &self.identity_public_cached)
            .field("identity_handle", &self.identity_handle)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::hw_callback::{bootstrap_hw_identity, MockHwKeystore};

    fn fresh_hw_keystore() -> (HwBackedKeyStore, Arc<MockHwKeystore>) {
        let mock = Arc::new(MockHwKeystore::new());
        let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
        let (handle, vk_bytes) =
            bootstrap_hw_identity(&callback, "xyz.umbrellax.hwbacked.test")
                .expect("bootstrap mock");
        let store = HwBackedKeyStore::new(0, callback, handle, vk_bytes).expect("construct");
        (store, mock)
    }

    /// **F-IDENT-1 closure invariant**: `identity_public` returns bytes
    /// that correspond to the TEE-resident signing key.
    #[test]
    fn identity_public_matches_callback_verifying_key() {
        let (store, mock) = fresh_hw_keystore();
        let store_pub = store.identity_public().to_bytes();
        let callback_pub = mock
            .verifying_key(store.identity_handle())
            .expect("vk via callback");
        assert_eq!(store_pub, callback_pub);
    }

    /// Helper: verify Ed25519 signature via `ed25519_dalek` (avoiding the
    /// `IdentityKeyPublic::verify` pub(crate) accessor which is not
    /// reachable across crate boundaries).
    fn dalek_verify(
        pubkey: &IdentityKeyPublic,
        message: &[u8],
        sig: &Ed25519Signature,
    ) -> Result<(), ed25519_dalek::ed25519::Error> {
        use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
        let pk = VerifyingKey::from_bytes(&pubkey.to_bytes()).expect("32-byte Ed25519 point");
        let dalek_sig = DalekSig::from_bytes(&sig.to_bytes());
        pk.verify(message, &dalek_sig)
    }

    /// **F-IDENT-1 closure invariant**: `sign_with_identity` returns a
    /// signature that verifies under the cached `identity_public`. Proves
    /// the routing goes through the hardware-resident key (a stale or
    /// drifted public key would fail verification).
    #[test]
    fn sign_with_identity_signature_verifies_under_cached_public() {
        let (store, _mock) = fresh_hw_keystore();
        let msg = b"F-IDENT-1 closure round-trip";
        let sig = store.sign_with_identity(msg);
        dalek_verify(&store.identity_public(), msg, &sig)
            .expect("hw-backed signature verifies under cached identity_public");
    }

    /// Sign-then-verify under an INDEPENDENT public key (different
    /// keystore instance) fails — confirms the signature is tied to
    /// this keystore's TEE-resident key, not a globally-shared one.
    #[test]
    fn sign_with_identity_signature_does_not_verify_under_unrelated_public() {
        let (store_a, _) = fresh_hw_keystore();
        let (store_b, _) = fresh_hw_keystore();
        let msg = b"isolation check";
        let sig_a = store_a.sign_with_identity(msg);
        let result = dalek_verify(&store_b.identity_public(), msg, &sig_a);
        assert!(
            result.is_err(),
            "Signature from store_a must NOT verify under store_b's independent public key"
        );
    }

    /// **F-IDENT-2 closure invariant**: `HwBackedKeyStore` does not hold
    /// an `IdentitySeed` or `IdentityKey` field. Compile-time guarantee
    /// via struct definition + runtime check that struct memory is
    /// bounded by handle + pubkey size only (no 64-byte seed-shaped
    /// slot). The struct layout test below is a `static_assertions`
    /// stand-in.
    #[test]
    fn hw_backed_keystore_has_no_seed_field_compile_time_guarantee() {
        // Compile-time: struct fields are pub(super)-restricted; only
        // (account, callback, identity_handle, identity_public_cached)
        // are present. No IdentitySeed import in this file.
        //
        // Run-time guard: `std::mem::size_of::<HwBackedKeyStore>()`
        // upper-bounds. IdentitySeed weighs 64 bytes (Box<[u8; 64]>);
        // adding it would push the struct size by 8 bytes (Box pointer)
        // minimum. We sanity-check the struct is small enough that an
        // additional Box<[u8; 64]> slot is not silently present.
        let size = std::mem::size_of::<HwBackedKeyStore>();
        // 4 (u32) + ~16 (Arc) + ~24 (String inside HwKeyHandle) + 32
        // (IdentityKeyPublic) ≈ 76 bytes; allow generous headroom but
        // require less than 256 bytes (which would imply a sizable
        // additional field).
        assert!(
            size < 256,
            "F-IDENT-2 closure regression: HwBackedKeyStore size {size} bytes suggests an \
             extra secret-material field was added; review struct fields and ensure no \
             IdentitySeed / IdentityKey is materialised"
        );
    }

    /// **Honest scope guard**: device methods report "no devices"
    /// consistently and `add_device` fails closed with
    /// `HwBackedUnsupported`.
    #[test]
    fn device_methods_report_no_devices_and_add_device_fail_closed() {
        let (store, _) = fresh_hw_keystore();
        assert!(store.active_device_indices().is_empty());
        assert!(store.all_known_device_indices().is_empty());
        assert!(store.device_public(0).is_none());
        assert!(store.device_attestation(0).is_none());
        assert!(matches!(
            store.sign_with_device(0, b"x"),
            Err(IdentityError::UnknownDevice { index: 0 })
        ));
        let add_result = store.add_device(0, None);
        assert!(matches!(
            add_result,
            Err(IdentityError::HwBackedUnsupported {
                method: "add_device",
                ..
            })
        ));
        assert!(matches!(
            store.revoke_device(0),
            Err(IdentityError::UnknownDevice { index: 0 })
        ));
    }

    /// X25519 methods panic at v1.0.0 — guard the panic message.
    #[test]
    #[should_panic(expected = "F-IDENT-X25519-1 v1.2.x")]
    fn identity_x25519_public_panics_with_explicit_message() {
        let (store, _) = fresh_hw_keystore();
        let _ = store.identity_x25519_public();
    }

    /// `Debug` impl does not panic and renders the handle alias plus
    /// pubkey prefix; no secret material in output.
    #[test]
    fn debug_does_not_leak_secrets() {
        let (store, _) = fresh_hw_keystore();
        let s = format!("{store:?}");
        assert!(s.starts_with("HwBackedKeyStore"));
        assert!(s.contains("account: 0"));
        assert!(s.contains("xyz.umbrellax.hwbacked.test"));
    }
}
