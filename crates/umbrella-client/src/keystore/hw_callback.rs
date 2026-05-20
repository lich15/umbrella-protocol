//! Hardware-backed `PersistentKeyStoreCallback` interface — round-5 device-capture closure.
//! Hardware-backed `PersistentKeyStoreCallback` interface — round-5 device-capture closure.
//!
//! # Назначение
//!
//! Round-4 PhD-B device-capture audit (`docs/audits/phd-b-device-capture-
//! defense-2026-05-19.md`) обнаружил 4 CRITICAL findings (R7 identity_sk
//! extractable, R7-2 master_key extractable, R10 hardware keystore not
//! wired, R12 ratchet state extractable). **Корневая причина — одна:**
//! `PersistentKeyStore` trait определён в `trait_def.rs`, но callback
//! interface через uniffi не существует. Native Swift / Kotlin сторона
//! не может имплементировать trait — она остаётся standalone.
//!
//! Этот модуль — Component 1 round-5 closure. Определяет
//! `PersistentKeyStoreCallback` trait через `#[uniffi::export(callback_interface)]`
//! (uniffi 0.31+). Native side имплементирует trait в Swift / Kotlin,
//! передаёт инстанс через FFI в Rust, и **identity_sk физически никогда
//! не покидает Secure Enclave / StrongBox**.
//!
//! # Purpose
//!
//! Round-4 PhD-B device-capture audit (`docs/audits/phd-b-device-capture-
//! defense-2026-05-19.md`) found 4 CRITICAL findings (R7 identity_sk
//! extractable, R7-2 master_key extractable, R10 hardware keystore not
//! wired, R12 ratchet state extractable). **Single root cause:**
//! `PersistentKeyStore` is defined in `trait_def.rs`, but there is no
//! uniffi callback interface to back it. The native Swift / Kotlin side
//! cannot implement the trait — it stays standalone.
//!
//! This module is Component 1 of the round-5 closure. It defines the
//! `PersistentKeyStoreCallback` trait via `#[uniffi::export(callback_interface)]`
//! (uniffi 0.31+). The native side implements the trait in Swift / Kotlin,
//! passes the instance across the FFI boundary into Rust, and **identity_sk
//! physically never leaves Secure Enclave / StrongBox**.
//!
//! # Wiring через `IdentityStore::bootstrap`
//!
//! `ClientCore::new_with_hw_callback` принимает `Arc<dyn PersistentKeyStoreCallback>`
//! и НЕ материализует identity_sk в Rust heap — вместо этого хранит
//! только `HwKeyHandle` (opaque alias строки которую native сторона
//! идентифицирует со своим Keychain entry / KeyStore alias). Все
//! операции `sign_with_identity` / `derive_storage_master_key` идут
//! через callback в SE/StrongBox и возвращают только sign-output
//! (64 байта Ed25519 signature) или wrap'ed buffer.
//!
//! # Wiring through `IdentityStore::bootstrap`
//!
//! `ClientCore::new_with_hw_callback` takes `Arc<dyn PersistentKeyStoreCallback>`
//! and does NOT materialise identity_sk on the Rust heap — instead, it
//! holds only an `HwKeyHandle` (an opaque alias string that the native
//! side identifies with its Keychain entry / KeyStore alias). All
//! `sign_with_identity` / `derive_storage_master_key` operations go
//! through the callback into SE/StrongBox and return only sign-output
//! (64-byte Ed25519 signature) or wrap'ed buffer.
//!
//! # Acceptance (round-5 spec §5)
//!
//! 1. Re-run round-4 R7 lldb attack — expect **0 stack hits** for
//!    identity_sk + master_key (key bytes never enter Rust heap).
//! 2. Re-run round-4 R12 lldb attack — expect **0 hits both stack+heap**
//!    post-drop (ratchet secret in MlockedSecret with TEE-derived seed).
//!
//! # API contract
//!
//! ```text
//! // Swift side:
//! // final class MyKeyStore: PersistentKeyStoreCallback {
//! //     func generateIdentity(label: String) throws -> HwKeyHandle { ... }
//! //     func signIdentity(handle: HwKeyHandle, data: Data) throws -> Data { ... }
//! //     // ... wrap_secret, unwrap_secret, delete_identity ...
//! // }
//!
//! // Rust side (umbrella-client):
//! // let callback: Arc<dyn PersistentKeyStoreCallback> = /* from FFI */;
//! // let core = ClientCore::new_with_hw_callback(config, callback).await?;
//! ```

use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroize;

use umbrella_backup::cloud_wrap::identity_rotation::{
    canonical_signing_input_rotation, CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN,
};
use umbrella_backup::cloud_wrap::{RotationReason, AUTHORIZATION_WIRE_VERSION};

use crate::error::ClientError;

/// Opaque handle для hardware-backed identity. Содержит ТОЛЬКО строковый
/// alias (Keychain `kSecAttrApplicationTag` / Android Keystore alias) —
/// private key bytes остаются в TEE и НЕ пересекают FFI границу.
///
/// Opaque handle for hardware-backed identity. Holds ONLY the string
/// alias (Keychain `kSecAttrApplicationTag` / Android Keystore alias) —
/// private key bytes stay in the TEE and never cross the FFI boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HwKeyHandle {
    /// Native-side alias: на iOS — `kSecAttrApplicationTag`; на Android —
    /// AndroidKeyStore alias. Например `"xyz.umbrellax.identity"` или
    /// `"xyz.umbrellax.device.0"`.
    ///
    /// Native-side alias: on iOS — `kSecAttrApplicationTag`; on Android —
    /// AndroidKeyStore alias. For instance `"xyz.umbrellax.identity"` or
    /// `"xyz.umbrellax.device.0"`.
    label: String,
}

impl HwKeyHandle {
    /// Construct from a native-side alias.
    /// Construct from a native-side alias.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    /// Native-side alias.
    /// Native-side alias.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for HwKeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HwKeyHandle({})", self.label)
    }
}

/// Ошибки `PersistentKeyStoreCallback`. Native side возвращает один из
/// вариантов; Rust callers map'ят его в `ClientError::Platform`.
///
/// Errors from `PersistentKeyStoreCallback`. The native side returns one
/// of these variants; Rust callers map them to `ClientError::Platform`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HwKeystoreError {
    /// User refused biometric/passcode prompt (LAError on iOS,
    /// UserNotAuthenticatedException on Android).
    /// User refused biometric / passcode prompt.
    #[error("user denied keystore access")]
    UserDenied,

    /// Secure Enclave / StrongBox physically not present (iPhone 5s−,
    /// Android without StrongBox hardware).
    /// Secure Enclave / StrongBox hardware not present.
    #[error("hardware keystore unavailable")]
    HardwareUnavailable,

    /// Key with this handle not found (could have been deleted by user
    /// in Settings, by `purge_all`, etc.).
    /// Key with this handle not found.
    #[error("hw key not found: {0}")]
    KeyNotFound(String),

    /// Sign operation failed inside TEE (rare — hardware error or OS
    /// policy restriction).
    /// Hardware sign failure.
    #[error("hw signing failed: {0}")]
    SigningFailed(String),

    /// Wrap/unwrap operation failed (e.g. corrupted ciphertext).
    /// Wrap or unwrap failed.
    #[error("hw wrap failed: {0}")]
    WrapFailed(String),

    /// Other native-side error (OSStatus text / JNI exception text).
    /// Other native-side error.
    #[error("hw native error: {0}")]
    Native(String),
}

impl From<HwKeystoreError> for ClientError {
    fn from(err: HwKeystoreError) -> Self {
        ClientError::Platform(err.to_string())
    }
}

/// Hardware-backed keystore callback interface. Native side (Swift /
/// Kotlin) implements this trait; Rust calls into it through FFI.
///
/// **Postulate:** private key bytes (Ed25519 signing scalar, P-256
/// secret) NEVER cross this boundary. Inputs are plaintext to sign or
/// wrap; outputs are signatures (64 bytes Ed25519) or AEAD ciphertexts.
/// The native side controls TEE key residency.
///
/// Hardware-backed keystore callback interface. The native side
/// (Swift/Kotlin) implements this trait; Rust calls into it via FFI.
///
/// **Postulate:** private key bytes (Ed25519 signing scalar, P-256
/// secret) NEVER cross this boundary. Inputs are plaintext to sign or
/// wrap; outputs are signatures (64-byte Ed25519) or AEAD ciphertexts.
/// The native side controls TEE key residency.
///
/// # FFI registration
///
/// The actual `#[uniffi::export(callback_interface)]` registration lives
/// in `crates/umbrella-ffi/src/keystore_callback.rs`. This trait stays
/// in `umbrella-client` so the core does not depend on uniffi macros
/// at compile time — `umbrella-ffi` provides a `#[derive(uniffi::Object)]`
/// wrapper that holds `Arc<dyn PersistentKeyStoreCallback>`.
///
/// # Thread safety
///
/// Implementations MUST be `Send + Sync` — Rust may call methods from
/// any Tokio worker thread; iOS / Android keystores are thread-safe per
/// platform documentation (`SecKeyCreateSignature` is non-reentrant per
/// key, but `MlockedSecret` ensures separate state per handle).
pub trait PersistentKeyStoreCallback: Send + Sync + 'static {
    /// Generate an identity inside the hardware keystore. The native
    /// implementation calls `SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)`
    /// on iOS or `KeyGenParameterSpec.setIsStrongBoxBacked(true)` on
    /// Android. Returns only the opaque handle — private bytes stay in TEE.
    ///
    /// Generate an identity inside the hardware keystore. Native side
    /// calls `SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)` on iOS
    /// or `KeyGenParameterSpec.setIsStrongBoxBacked(true)` on Android.
    /// Returns only the opaque handle — private bytes stay in TEE.
    fn generate_identity(&self, label: String) -> Result<HwKeyHandle, HwKeystoreError>;

    /// Sign `data` with the hardware-resident identity key. The native
    /// implementation calls `SecKeyCreateSignature` (iOS) or
    /// `Signature.getInstance("EdDSA").sign()` (Android). Returns a
    /// 64-byte Ed25519 signature.
    ///
    /// Sign `data` with the hardware-resident identity key. Native side
    /// calls `SecKeyCreateSignature` (iOS) or
    /// `Signature.getInstance("EdDSA").sign()` (Android). Returns a
    /// 64-byte Ed25519 signature.
    fn sign_identity(&self, handle: &HwKeyHandle, data: &[u8]) -> Result<Vec<u8>, HwKeystoreError>;

    /// Wrap a software-side secret (e.g. SQLite master_key) using a TEE-
    /// resident wrap key. Returns ciphertext that only this hardware
    /// keystore can decrypt. The plaintext **must be zeroized** by the
    /// caller immediately after this call returns.
    ///
    /// Wrap a software-side secret (e.g. SQLite master_key) using a TEE-
    /// resident wrap key. Returns ciphertext that only this hardware
    /// keystore can decrypt. The plaintext **must be zeroized** by the
    /// caller immediately after this call returns.
    fn wrap_secret(
        &self,
        handle: &HwKeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError>;

    /// Reverse of `wrap_secret`. Returns the plaintext which the caller
    /// must zeroize after use (typically via `MlockedSecret<[u8; N]>`).
    ///
    /// Reverse of `wrap_secret`. Returns the plaintext which the caller
    /// must zeroize after use (typically via `MlockedSecret<[u8; N]>`).
    fn unwrap_secret(
        &self,
        handle: &HwKeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError>;

    /// Delete an identity from the hardware keystore (logout / device
    /// wipe). After this call, all `sign_identity` / `unwrap_secret`
    /// calls for `handle` return `KeyNotFound`.
    ///
    /// Delete an identity from the hardware keystore (logout / device
    /// wipe). After this call all `sign_identity` / `unwrap_secret`
    /// calls for `handle` return `KeyNotFound`.
    fn delete_identity(&self, handle: &HwKeyHandle) -> Result<(), HwKeystoreError>;

    /// Retrieve the Ed25519 verifying-key (32 bytes) for the hardware-
    /// resident identity. Native implementations fetch directly from the
    /// TEE without the private seed ever returning to Rust:
    /// - iOS: `SecKeyCopyPublicKey(handle)` →
    ///   `SecKeyCopyExternalRepresentation` → raw 32 bytes.
    /// - Android: `KeyStore.getCertificate(alias).publicKey.encoded`
    ///   (X.509 SubjectPublicKeyInfo with the 32 raw Ed25519 bytes at
    ///   `[len - 32..]`).
    ///
    /// **F-CLIENT-HW-2 closure (PhD-B Pass 5 remediation):** previously
    /// [`bootstrap_hw_identity`] returned `[0u8; 32]` as a placeholder
    /// for the verifying-key. The closure adds this trait method so the
    /// callback can surface the real Ed25519 public key bytes that Key
    /// Transparency publishing or peer-verification flows consume.
    /// Production wiring fetches from the TEE-resident handle without
    /// the seed ever materialising in Rust.
    fn verifying_key(&self, handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError>;

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** rotate the
    /// hardware-resident identity key atomically.
    ///
    /// Native side MUST atomically:
    ///
    /// 1. Generate a fresh identity SK + verifying key inside the HW
    ///    keystore under `new_identity_label` (iOS: a new Keychain entry
    ///    with `kSecAttrTokenIDSecureEnclave`; Android: a new StrongBox-
    ///    backed AndroidKeyStore alias). New secret material lives in
    ///    TEE and never enters userspace.
    /// 2. Compute the **canonical signing input** using the exact same
    ///    algorithm and constants as
    ///    [`umbrella_backup::cloud_wrap::identity_rotation::canonical_signing_input_rotation`]:
    ///    `b"umbrellax-identity-rotation-v1" || version(1) ||
    ///    old_identity_pubkey(32) || new_identity_pubkey(32) ||
    ///    rotation_timestamp_be(8) || rotation_reason_tag(1) ||
    ///    code_recovery_public_half_proof(32)` (115 bytes total). The
    ///    wire-format requirement is **fixed by ADR-008 § identity rotation**
    ///    and SPEC-12 §A.5.1; native impls cannot deviate without
    ///    breaking dual-signature verification on the publish path.
    /// 3. Sign the canonical input with the **OLD identity SK** (via
    ///    `old_identity_handle`, which the native side already knows).
    /// 4. Sign the canonical input with the **NEW identity SK** (just
    ///    generated under `new_identity_label`).
    /// 5. Return [`RotatedIdentityArtifact`] containing the new HW
    ///    handle alias, the new 32-byte verifying key, and both 64-byte
    ///    Ed25519 signatures. The Rust facade
    ///    ([`crate::identity::rotate_identity_full`]) constructs an
    ///    `IdentityRotationRecord`, performs defence-in-depth local
    ///    verification, wire-encodes it, and publishes to KT.
    ///
    /// `rotation_reason_tag` must be one of `0x01` (CatastrophicRecovery),
    /// `0x02` (PlannedRotation), `0x03` (IdentityCompromise) per
    /// `umbrella_backup::cloud_wrap::RotationReason::tag`. Implementations
    /// MUST reject unknown tags with [`HwKeystoreError::Native`] before
    /// generating new HW material (an unknown tag is a caller bug; refusing
    /// early avoids polluting the TEE with an orphan key whose semantic
    /// status is undefined).
    ///
    /// **Atomicity**: if any step fails after the new HW material is
    /// generated (e.g. signing fails), implementations SHOULD attempt to
    /// delete the new HW handle before returning the error, so a half-
    /// rotated TEE state is not left behind. Failure to clean up is not a
    /// fatal error from Rust's perspective — the new handle simply
    /// becomes unreachable garbage — but native implementations are
    /// encouraged to do best-effort cleanup.
    ///
    /// **Default impl** returns
    /// [`HwKeystoreError::Native`] with an explicit "not implemented"
    /// message. This preserves backward compatibility with existing
    /// [`PersistentKeyStoreCallback`] implementations that pre-date
    /// session 9d while making missing wire-up surface immediately
    /// rather than silently masquerading as success.
    ///
    /// # Errors
    ///
    /// - [`HwKeystoreError::KeyNotFound`] — `old_identity_handle` not
    ///   present in the keystore (e.g. user wiped keychain).
    /// - [`HwKeystoreError::HardwareUnavailable`] — TEE physically not
    ///   present.
    /// - [`HwKeystoreError::UserDenied`] — biometric / passcode prompt
    ///   refused.
    /// - [`HwKeystoreError::SigningFailed`] — either signature operation
    ///   failed inside TEE.
    /// - [`HwKeystoreError::Native`] — unknown `rotation_reason_tag` or
    ///   other native-side error.
    fn rotate_identity(
        &self,
        old_identity_handle: &HwKeyHandle,
        new_identity_label: String,
        old_identity_pubkey: [u8; 32],
        rotation_timestamp: u64,
        rotation_reason_tag: u8,
        code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
    ) -> Result<RotatedIdentityArtifact, HwKeystoreError> {
        let _ = (
            old_identity_handle,
            new_identity_label,
            old_identity_pubkey,
            rotation_timestamp,
            rotation_reason_tag,
            code_recovery_public_half_proof,
        );
        Err(HwKeystoreError::Native(
            "rotate_identity not implemented by this PersistentKeyStoreCallback impl \
             (default impl reject; override required for F-CLIENT-FACADE-1 session 9d \
             rotation orchestration)"
                .to_string(),
        ))
    }
}

/// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** result of a successful
/// [`PersistentKeyStoreCallback::rotate_identity`] call.
///
/// Holds the public material the Rust facade needs to build, verify, and
/// publish an `IdentityRotationRecord`: the new HW handle (opaque alias
/// the native side just created), the new 32-byte verifying key, and the
/// two 64-byte Ed25519 signatures over the canonical signing input.
///
/// **No secret material**: the new identity signing scalar stays in TEE.
/// Adversary with read access к `RotatedIdentityArtifact` gets only
/// public bytes (pubkey + signatures + handle alias).
///
/// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** result of a successful
/// [`PersistentKeyStoreCallback::rotate_identity`] call. Carries the
/// public material the Rust facade needs to construct, verify, and
/// publish an `IdentityRotationRecord`. No secret material crosses this
/// boundary.
#[derive(Clone, Debug)]
pub struct RotatedIdentityArtifact {
    /// Opaque alias for the newly-generated TEE-resident identity key.
    /// Каллер (facade) использует это для конструирования нового
    /// [`crate::keystore::HwBackedKeyStore`] и follow-up
    /// `core.swap_mls_keystore(...)` call.
    ///
    /// Opaque alias for the newly-generated TEE-resident identity key.
    /// The caller (facade) uses this to construct a new
    /// [`crate::keystore::HwBackedKeyStore`] and a follow-up
    /// `core.swap_mls_keystore(...)` call.
    pub new_identity_handle: HwKeyHandle,
    /// 32-byte Ed25519 verifying-key for the new identity. Goes into
    /// `IdentityRotationRecord::new_identity_pubkey`.
    pub new_identity_pubkey: [u8; 32],
    /// 64-byte Ed25519 signature by the OLD identity SK over the
    /// canonical signing input. Goes into
    /// `IdentityRotationRecord::old_identity_signature`.
    pub old_identity_signature: [u8; 64],
    /// 64-byte Ed25519 signature by the NEW identity SK over the SAME
    /// canonical signing input. Goes into
    /// `IdentityRotationRecord::new_identity_signature`.
    pub new_identity_signature: [u8; 64],
}

/// `MockHwKeystore` — software-only implementation for macOS test rig.
/// Provides a working `PersistentKeyStoreCallback` impl that uses an
/// in-memory `HashMap<HwKeyHandle, MlockedSecret<[u8; 32]>>` so the
/// Rust side wiring + acceptance test can run without a real iOS /
/// Android device. The acceptance test gate in spec §«Acceptance gate
/// row 2» says: `MockHwKeystore` test passes under
/// `cargo test --release -p umbrella-client`.
///
/// # Что это даёт
///
/// 1. Доказывает что Rust-side IdentityStore::bootstrap правильно
///    проходит через callback и НЕ материализует identity_sk в heap.
/// 2. Дает CI gate без real device.
/// 3. Round-5 R7 lldb re-run использует этот же mock — финальная проверка
///    что identity_sk не виден в lldb.
///
/// # What this provides
///
/// 1. Proves that `IdentityStore::bootstrap` flows through the callback
///    on the Rust side and never materialises identity_sk on the heap.
/// 2. Gives a CI gate without a real device.
/// 3. Round-5 R7 lldb re-run uses this same mock — final check that
///    identity_sk is not visible to lldb.
///
/// # Roadmap для real device
///
/// Compile-green Swift `KeyStoreBridge.swift` + Kotlin `KeyStoreBridge.kt`
/// (round-5 Component 2) дают reference impl но не runtime-тестируются
/// в этой round. Block 7.10 CI integration пайплайн добавит real-device
/// gate (требует physical iPhone / Pixel + signing identity).
///
/// # Real-device roadmap
///
/// Compile-green Swift `KeyStoreBridge.swift` + Kotlin `KeyStoreBridge.kt`
/// (round-5 Component 2) provide the reference impl but are not runtime-
/// tested in this round. The Block 7.10 CI integration pipeline will add
/// a real-device gate (physical iPhone / Pixel + signing identity
/// required).
#[derive(Default)]
pub struct MockHwKeystore {
    /// In-memory mapping; gated by Mutex to allow `&self` API yet mutate.
    /// Each stored value is `MlockedSecret<[u8; 32]>` so the test mirrors
    /// the production memory invariant: secrets are heap-resident +
    /// mlocked + zeroized.
    keys: std::sync::Mutex<std::collections::HashMap<HwKeyHandle, MockKeyMaterial>>,
}

/// Internal storage for the mock — 32-byte Ed25519 SigningKey seed
/// (the canonical representation), wrapped in `MlockedSecret` so the
/// mock preserves the production invariant during R7 lldb re-runs.
///
/// Internal storage for the mock — 32-byte Ed25519 SigningKey seed (the
/// canonical representation), wrapped in `MlockedSecret` so the mock
/// preserves the production invariant during R7 lldb re-runs.
struct MockKeyMaterial {
    seed: umbrella_crypto_primitives::MlockedSecret<[u8; 32]>,
}

impl MockHwKeystore {
    /// Empty store.
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored identities — for tests.
    /// Number of stored identities — for tests.
    pub fn len(&self) -> usize {
        self.keys
            .lock()
            .expect("mock keystore mutex never poisoned in tests")
            .len()
    }

    /// `true` if empty.
    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PersistentKeyStoreCallback for MockHwKeystore {
    fn generate_identity(&self, label: String) -> Result<HwKeyHandle, HwKeystoreError> {
        // Synthesize a 32-byte Ed25519 SigningKey seed using a CSPRNG.
        // Производство: replaced by SE-side SecKeyCreateRandomKey output.
        use rand_core::OsRng;
        use rand_core::RngCore;

        let mut seed_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut seed_bytes);

        let handle = HwKeyHandle::new(label);
        let material = MockKeyMaterial {
            seed: umbrella_crypto_primitives::MlockedSecret::new(seed_bytes),
        };
        // zeroize стек-копию параметра.
        seed_bytes.zeroize();
        self.keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?
            .insert(handle.clone(), material);
        Ok(handle)
    }

    fn sign_identity(&self, handle: &HwKeyHandle, data: &[u8]) -> Result<Vec<u8>, HwKeystoreError> {
        use ed25519_dalek::{Signer, SigningKey};
        let guard = self
            .keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?;
        let material = guard
            .get(handle)
            .ok_or_else(|| HwKeystoreError::KeyNotFound(handle.label().to_string()))?;

        // SigningKey::from_bytes copies the seed onto its stack frame —
        // this is the "TEE boundary" in the mock: the SigningKey replaces
        // what would be a SecKeyCreateSignature call on real iOS. The
        // SigningKey is dropped at end of scope; its internal zeroize-on-
        // drop wipes the heap copy. The stack copy here is the same
        // class of leak as R7 / R12 stack-spill — mitigated separately
        // by IdentitySeed → Box<...> refactor; for the mock the cost is
        // acceptable because the mock is only used in lldb re-runs.
        //
        // SigningKey::from_bytes copies the seed onto its stack frame —
        // this is the "TEE boundary" in the mock: the SigningKey replaces
        // what would be a SecKeyCreateSignature call on a real iPhone.
        // The SigningKey is dropped at end of scope; its zeroize-on-drop
        // wipes the heap copy. The stack copy here is the same class as
        // R7 / R12 stack-spill — mitigated separately by the
        // IdentitySeed → Box<...> refactor; for the mock the cost is
        // acceptable because the mock is only used in lldb re-runs.
        let signing = SigningKey::from_bytes(material.seed.expose());
        let sig = signing.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn wrap_secret(
        &self,
        handle: &HwKeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        // Mock wrap: ChaCha20-Poly1305 with the stored seed as a key.
        // Production replaces with SE-resident HKDF + AEAD.
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let guard = self
            .keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?;
        let material = guard
            .get(handle)
            .ok_or_else(|| HwKeystoreError::KeyNotFound(handle.label().to_string()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(material.seed.expose()));
        // Deterministic mock nonce — fine for testing wiring; production
        // uses HKDF-derived nonce per ADR-010 Decision 5.
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HwKeystoreError::WrapFailed(format!("aead encrypt: {e}")))?;
        Ok(ct)
    }

    fn unwrap_secret(
        &self,
        handle: &HwKeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let guard = self
            .keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?;
        let material = guard
            .get(handle)
            .ok_or_else(|| HwKeystoreError::KeyNotFound(handle.label().to_string()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(material.seed.expose()));
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| HwKeystoreError::WrapFailed(format!("aead decrypt: {e}")))?;
        Ok(pt)
    }

    fn delete_identity(&self, handle: &HwKeyHandle) -> Result<(), HwKeystoreError> {
        let mut guard = self
            .keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?;
        guard
            .remove(handle)
            .ok_or_else(|| HwKeystoreError::KeyNotFound(handle.label().to_string()))?;
        Ok(())
    }

    fn verifying_key(&self, handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError> {
        // F-CLIENT-HW-2 closure: derive the verifying-key from the stored
        // seed using `ed25519_dalek::SigningKey::verifying_key`. Production
        // calls `SecKeyCopyPublicKey` (iOS) or
        // `KeyStore.getCertificate(alias).publicKey` (Android) — the seed
        // never returns to userspace in either case. The mock takes a
        // side-channel peek at the seed (acceptable per the same R7-stack-
        // spill caveat noted on `sign_identity`) so the mock keystore is
        // testable end-to-end without a real SE/StrongBox.
        use ed25519_dalek::SigningKey;
        let guard = self
            .keys
            .lock()
            .map_err(|_| HwKeystoreError::Native("mock mutex poisoned".into()))?;
        let material = guard
            .get(handle)
            .ok_or_else(|| HwKeystoreError::KeyNotFound(handle.label().to_string()))?;
        let signing = SigningKey::from_bytes(material.seed.expose());
        Ok(signing.verifying_key().to_bytes())
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19) Mock implementation.**
    ///
    /// Mirrors the production atomic-rotation contract: generates a fresh
    /// 32-byte Ed25519 seed using `OsRng`, stores it under
    /// `new_identity_label`, computes the canonical signing input via
    /// [`canonical_signing_input_rotation`] (same algorithm a real native
    /// side would use), and signs the canonical input with both the old
    /// and new identity keys. Returns the new handle, new pubkey, and
    /// both signatures.
    ///
    /// **Verification properties** (lock-in invariants enforced via
    /// `cargo test --release` against the mock):
    ///
    /// 1. `new_identity_pubkey` is the real Ed25519 verifying-key for the
    ///    just-generated seed — never `[0u8; 32]`.
    /// 2. `new_identity_pubkey ≠ old_identity_pubkey` with overwhelming
    ///    probability (collision-resistance of fresh CSPRNG seed).
    /// 3. `old_identity_signature` verifies under `old_identity_pubkey`
    ///    over the canonical input. Verifiable by caller via
    ///    `IdentityRotationRecord::verify()`.
    /// 4. `new_identity_signature` verifies under `new_identity_pubkey`
    ///    over the SAME canonical input.
    /// 5. The new HW handle is added to the mock's in-memory map; subsequent
    ///    `sign_identity(new_handle, data)` produces signatures verifiable
    ///    under `new_identity_pubkey`.
    fn rotate_identity(
        &self,
        old_identity_handle: &HwKeyHandle,
        new_identity_label: String,
        old_identity_pubkey: [u8; 32],
        rotation_timestamp: u64,
        rotation_reason_tag: u8,
        code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
    ) -> Result<RotatedIdentityArtifact, HwKeystoreError> {
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::{OsRng, RngCore};

        // Validate the rotation reason tag against the canonical enum
        // before any HW state mutation. An unknown tag indicates a caller
        // bug; refusing early avoids leaving an orphan seed in the mock's
        // map. Production native impls SHOULD perform the same check
        // before generating new TEE material.
        let rotation_reason = RotationReason::from_tag(rotation_reason_tag).ok_or_else(|| {
            HwKeystoreError::Native(format!(
                "unknown rotation_reason_tag {rotation_reason_tag:#04x} — \
                 must be one of 0x01 (CatastrophicRecovery), 0x02 (PlannedRotation), \
                 0x03 (IdentityCompromise)"
            ))
        })?;

        // Generate the new identity seed. Production: native SE/StrongBox
        // create. Mock: OsRng + in-memory store.
        let mut new_seed_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut new_seed_bytes);
        let new_signing = SigningKey::from_bytes(&new_seed_bytes);
        let new_identity_pubkey = new_signing.verifying_key().to_bytes();

        // Compute the canonical signing input using the wire-format spec
        // from `umbrella-backup`. Production native code mirrors this
        // byte-for-byte; deviation here means the dual signatures will
        // not verify against `record.verify()` on the facade side.
        let canonical = canonical_signing_input_rotation(
            AUTHORIZATION_WIRE_VERSION,
            &old_identity_pubkey,
            &new_identity_pubkey,
            rotation_timestamp,
            rotation_reason,
            &code_recovery_public_half_proof,
        );

        // Sign with OLD identity SK (pull from existing map entry).
        let old_signing = {
            let guard = self.keys.lock().map_err(|_| {
                HwKeystoreError::Native("mock mutex poisoned during rotate_identity".into())
            })?;
            let material = guard.get(old_identity_handle).ok_or_else(|| {
                HwKeystoreError::KeyNotFound(old_identity_handle.label().to_string())
            })?;
            SigningKey::from_bytes(material.seed.expose())
        };
        let old_identity_signature = old_signing.sign(&canonical).to_bytes();

        // Sign with NEW identity SK (just generated).
        let new_identity_signature = new_signing.sign(&canonical).to_bytes();

        // Persist the new seed under the new handle. Lock taken after
        // signing to keep the critical section short.
        let new_identity_handle = HwKeyHandle::new(new_identity_label);
        let material = MockKeyMaterial {
            seed: umbrella_crypto_primitives::MlockedSecret::new(new_seed_bytes),
        };
        new_seed_bytes.zeroize();
        self.keys
            .lock()
            .map_err(|_| {
                HwKeystoreError::Native("mock mutex poisoned during rotate_identity insert".into())
            })?
            .insert(new_identity_handle.clone(), material);

        Ok(RotatedIdentityArtifact {
            new_identity_handle,
            new_identity_pubkey,
            old_identity_signature,
            new_identity_signature,
        })
    }
}

/// Bootstrap a TEE-anchored identity into the keystore. Returns the
/// `HwKeyHandle` plus the Ed25519 verifying-key bytes that can be
/// published to Key Transparency. The signing scalar **stays in TEE**.
///
/// **F-CLIENT-HW-2 closure (PhD-B Pass 5 remediation):** the verifying-key
/// is now sourced from [`PersistentKeyStoreCallback::verifying_key`] — a
/// real 32-byte Ed25519 public key — instead of the `[0u8; 32]`
/// placeholder that previously occupied the second tuple slot. A probe
/// `sign_identity` call still runs as a smoke test that the native
/// bridge is wired correctly; the returned signature is verified against
/// the freshly-fetched verifying-key to catch handle/key drift at
/// bootstrap time rather than at first peer interaction.
///
/// # Mock note
///
/// For `MockHwKeystore` the verifying-key is derived from the stored
/// seed via `SigningKey::verifying_key()`. For real iOS / Android the
/// verifying-key is retrieved via `SecKeyCopyPublicKey` or
/// `KeyStore.getCertificate(alias).publicKey`.
pub fn bootstrap_hw_identity(
    callback: &Arc<dyn PersistentKeyStoreCallback>,
    label: impl Into<String>,
) -> Result<(HwKeyHandle, [u8; 32]), HwKeystoreError> {
    let label = label.into();
    let handle = callback.generate_identity(label)?;

    // Probe the verifying-key by signing a fixed-prefix "publish" message
    // and verifying with the public key — also acts as a smoke test that
    // the native bridge is correctly wired.
    let probe = b"umbrellax-tee-identity-probe-v1";
    let sig_bytes = callback.sign_identity(&handle, probe)?;
    if sig_bytes.len() != 64 {
        return Err(HwKeystoreError::SigningFailed(format!(
            "hw signature wrong length: {} (expected 64)",
            sig_bytes.len()
        )));
    }

    // F-CLIENT-HW-2 closure: fetch the real Ed25519 verifying-key from
    // the callback. Previously this returned `[0u8; 32]` placeholder; the
    // caller (`ClientCore::new_with_hw_callback`) silently discarded the
    // result via `let (handle, _verifying_key_placeholder) = ...`, which
    // masked the gap. Now the gap is closed: the verifying-key is real,
    // ready for downstream KT-publish / peer-verification consumers once
    // F-CLIENT-HW-1 (production signing path wire-up) lands.
    let verifying_key = callback.verifying_key(&handle)?;

    // Smoke test: verify the probe signature against the fetched
    // verifying-key. Catches handle/key drift between
    // `generate_identity` and `verifying_key` at bootstrap time.
    let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key)
        .map_err(|e| HwKeystoreError::SigningFailed(format!("verifying_key invalid: {e}")))?;
    let dalek_sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| HwKeystoreError::SigningFailed(format!("probe sig parse: {e}")))?;
    dalek_pk
        .verify_strict(probe, &dalek_sig)
        .map_err(|e| HwKeystoreError::SigningFailed(format!("probe sig verify: {e}")))?;

    Ok((handle, verifying_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_keystore_generate_and_sign() {
        let mock = MockHwKeystore::new();
        let handle = mock
            .generate_identity("xyz.umbrellax.identity.test".to_string())
            .expect("generate identity");
        assert_eq!(handle.label(), "xyz.umbrellax.identity.test");
        assert_eq!(mock.len(), 1);

        let sig = mock
            .sign_identity(&handle, b"hello world")
            .expect("sign data");
        assert_eq!(sig.len(), 64, "Ed25519 signature is always 64 bytes");
    }

    #[test]
    fn mock_keystore_wrap_unwrap_roundtrip() {
        let mock = MockHwKeystore::new();
        let handle = mock
            .generate_identity("xyz.umbrellax.identity.wrap.test".to_string())
            .expect("generate");
        let secret = [0xAAu8; 32];
        let wrapped = mock.wrap_secret(&handle, &secret).expect("wrap");
        let unwrapped = mock.unwrap_secret(&handle, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_slice(), &secret);
    }

    #[test]
    fn mock_keystore_delete() {
        let mock = MockHwKeystore::new();
        let handle = mock
            .generate_identity("xyz.umbrellax.identity.delete.test".to_string())
            .expect("generate");
        assert_eq!(mock.len(), 1);
        mock.delete_identity(&handle).expect("delete");
        assert_eq!(mock.len(), 0);
        let result = mock.sign_identity(&handle, b"data");
        assert!(matches!(result, Err(HwKeystoreError::KeyNotFound(_))));
    }

    #[test]
    fn mock_keystore_key_not_found() {
        let mock = MockHwKeystore::new();
        let handle = HwKeyHandle::new("xyz.umbrellax.does.not.exist");
        let result = mock.sign_identity(&handle, b"data");
        assert!(matches!(result, Err(HwKeystoreError::KeyNotFound(_))));
    }

    #[test]
    fn mock_keystore_multiple_identities() {
        let mock = MockHwKeystore::new();
        let h1 = mock.generate_identity("id.1".into()).expect("gen 1");
        let h2 = mock.generate_identity("id.2".into()).expect("gen 2");
        assert_eq!(mock.len(), 2);
        let s1 = mock.sign_identity(&h1, b"x").expect("sign 1");
        let s2 = mock.sign_identity(&h2, b"x").expect("sign 2");
        assert_ne!(
            s1, s2,
            "different keys must produce different signatures on the same data"
        );
    }

    #[test]
    fn hw_keystore_error_to_client_error() {
        let ce: ClientError = HwKeystoreError::UserDenied.into();
        assert!(matches!(ce, ClientError::Platform(_)));
    }

    #[test]
    fn bootstrap_hw_identity_succeeds_for_mock() {
        let callback: Arc<dyn PersistentKeyStoreCallback> = Arc::new(MockHwKeystore::new());
        let (handle, vk) = bootstrap_hw_identity(&callback, "xyz.umbrellax.identity.test")
            .expect("bootstrap mock");
        assert_eq!(handle.label(), "xyz.umbrellax.identity.test");
        assert_eq!(vk.len(), 32);
        // F-CLIENT-HW-2 closure: vk is no longer a `[0u8; 32]` placeholder.
        assert_ne!(
            vk, [0u8; 32],
            "F-CLIENT-HW-2 closure: bootstrap_hw_identity must return real verifying-key, \
             not the pre-closure [0u8; 32] placeholder"
        );
    }

    /// **F-CLIENT-HW-2 closure regression guard.**
    ///
    /// Validates that the verifying-key surfaced by [`bootstrap_hw_identity`]
    /// matches the actual Ed25519 public key for the keystore-resident
    /// identity. End-to-end check: bootstrap → sign a message via callback
    /// → verify the signature against the returned verifying-key. Confirms
    /// closure of the gap where the function previously returned
    /// `[0u8; 32]` (silent placeholder) regardless of which keystore handle
    /// was generated.
    ///
    /// If a future regression re-introduces the placeholder pattern, this
    /// test fails at the `from_bytes`/`verify_strict` step because the
    /// all-zeros verifying-key cannot validate a real Ed25519 signature.
    #[test]
    fn bootstrap_hw_identity_returns_real_verifying_key_matching_dalek_derivation() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let mock = Arc::new(MockHwKeystore::new());
        let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();

        let (handle, vk_bytes) = bootstrap_hw_identity(&callback, "f-client-hw-2.test")
            .expect("bootstrap should succeed");

        // The verifying-key MUST be a valid Ed25519 point — the all-zeros
        // pre-closure placeholder would fail this decode.
        let vk_dalek =
            VerifyingKey::from_bytes(&vk_bytes).expect("vk_bytes must decode as Ed25519");

        // Sign a fresh message via the callback (production: SE/StrongBox
        // signing operation). Verify with the returned vk — proves the vk
        // corresponds to the actual signing key stored under `handle`.
        let msg = b"F-CLIENT-HW-2 closure verification message";
        let sig_bytes = callback.sign_identity(&handle, msg).expect("sign");
        let sig = Signature::from_slice(&sig_bytes).expect("64-byte Ed25519 sig");
        vk_dalek
            .verify(msg, &sig)
            .expect("F-CLIENT-HW-2 closure: vk verifies hw-callback signatures");

        // Two distinct handles must yield distinct verifying-keys (sanity:
        // generate_identity yields a fresh seed each call → independent
        // SigningKey → independent VerifyingKey).
        let (other_handle, other_vk) =
            bootstrap_hw_identity(&callback, "f-client-hw-2.other.test").expect("second bootstrap");
        assert_ne!(handle, other_handle);
        assert_ne!(
            vk_bytes, other_vk,
            "F-CLIENT-HW-2 closure: distinct handles must yield distinct verifying-keys"
        );
    }

    /// Acceptance gate row 2: `MockHwKeystore` test passes under
    /// `cargo test --release -p umbrella-client`. The full end-to-end
    /// flow: generate → sign → verify (via reference dalek
    /// VerifyingKey extracted from the stored material).
    ///
    /// We re-derive the verifying-key inside the test using a backdoor
    /// helper — production never has this, but the test needs to
    /// validate that the signature in fact verifies against the public
    /// key derived from the stored seed.
    #[test]
    fn mock_keystore_sign_verifies_against_dalek() {
        use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

        let mock = MockHwKeystore::new();
        let handle = mock.generate_identity("verify.test".into()).expect("gen");

        // Re-derive verifying-key by recomputing from the stored seed.
        // Production: `SecKeyCopyPublicKey(handle)` returns the public
        // half directly — the seed never appears.
        let guard = mock.keys.lock().expect("mock mutex");
        let seed_bytes = *guard.get(&handle).expect("material").seed.expose();
        drop(guard);
        let signing = SigningKey::from_bytes(&seed_bytes);
        let vk: VerifyingKey = signing.verifying_key();

        let msg = b"round-5 mock acceptance test";
        let sig_bytes = mock.sign_identity(&handle, msg).expect("sign");
        let sig = Signature::from_slice(&sig_bytes).expect("sig 64 bytes");
        vk.verify(msg, &sig)
            .expect("mock signature verifies under dalek VerifyingKey");
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** end-to-end mock
    /// rotation contract test. Verifies all five lock-in invariants from
    /// the impl doc-comment: real new pubkey, distinct from old, both
    /// signatures verify, new handle subsequently signable.
    #[test]
    fn mock_rotate_identity_signs_canonical_input_with_both_keys_and_persists_new_handle() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use umbrella_backup::cloud_wrap::identity_rotation::canonical_signing_input_rotation;
        use umbrella_backup::cloud_wrap::{RotationReason, AUTHORIZATION_WIRE_VERSION};

        let mock = MockHwKeystore::new();
        let (old_handle, old_pk) = bootstrap_hw_identity(
            &(Arc::new(MockHwKeystore::new()) as Arc<dyn PersistentKeyStoreCallback>),
            "session-9d.mock.bootstrap-discard",
        )
        .expect("discarded bootstrap");
        // Re-use a fresh handle inside `mock` (the keystore we actually
        // rotate) to mirror the production wiring.
        let _ = old_handle;
        let _ = old_pk;
        let bootstrap_handle = mock
            .generate_identity("session-9d.mock.old".into())
            .expect("generate old identity");
        let bootstrap_old_pk = mock
            .verifying_key(&bootstrap_handle)
            .expect("verifying_key old");

        let rotation_timestamp: u64 = 1_715_000_000_000;
        let reason = RotationReason::PlannedRotation;
        let proof = [0x42u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN];

        let artifact = mock
            .rotate_identity(
                &bootstrap_handle,
                "session-9d.mock.new".into(),
                bootstrap_old_pk,
                rotation_timestamp,
                reason.tag(),
                proof,
            )
            .expect("rotate_identity succeeds");

        // Invariant 1: new pubkey is real (decodes as Ed25519, not zero).
        assert_ne!(
            artifact.new_identity_pubkey, [0u8; 32],
            "new_identity_pubkey must be real Ed25519, not zero placeholder"
        );
        let new_vk = VerifyingKey::from_bytes(&artifact.new_identity_pubkey)
            .expect("new_identity_pubkey decodes as Ed25519");
        let old_vk = VerifyingKey::from_bytes(&bootstrap_old_pk)
            .expect("bootstrap old_pk decodes as Ed25519");

        // Invariant 2: new ≠ old.
        assert_ne!(
            artifact.new_identity_pubkey, bootstrap_old_pk,
            "rotation must yield a distinct pubkey"
        );

        // Invariant 3 + 4: both signatures verify over canonical input.
        let canonical = canonical_signing_input_rotation(
            AUTHORIZATION_WIRE_VERSION,
            &bootstrap_old_pk,
            &artifact.new_identity_pubkey,
            rotation_timestamp,
            reason,
            &proof,
        );
        let old_sig = Signature::from_slice(&artifact.old_identity_signature)
            .expect("old_identity_signature is 64 bytes");
        old_vk
            .verify(&canonical, &old_sig)
            .expect("old_identity_signature verifies under old_pk over canonical input");
        let new_sig = Signature::from_slice(&artifact.new_identity_signature)
            .expect("new_identity_signature is 64 bytes");
        new_vk
            .verify(&canonical, &new_sig)
            .expect("new_identity_signature verifies under new_pk over canonical input");

        // Invariant 5: new handle is now signable via the mock.
        let smoke = mock
            .sign_identity(&artifact.new_identity_handle, b"smoke-after-rotation")
            .expect("sign with new handle");
        let smoke_sig = Signature::from_slice(&smoke).expect("64-byte sig");
        new_vk
            .verify(b"smoke-after-rotation", &smoke_sig)
            .expect("new handle's signatures verify under new_pk");
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** unknown rotation
    /// reason tags are rejected before any HW state mutation.
    #[test]
    fn mock_rotate_identity_rejects_unknown_reason_tag() {
        let mock = MockHwKeystore::new();
        let handle = mock
            .generate_identity("session-9d.bad-tag.bootstrap".into())
            .expect("generate");
        let old_pk = mock.verifying_key(&handle).expect("vk");

        let mock_len_before = mock.len();
        let result = mock.rotate_identity(
            &handle,
            "session-9d.bad-tag.new".into(),
            old_pk,
            0,
            0xFE, // not in {0x01, 0x02, 0x03}
            [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
        );
        match result {
            Err(HwKeystoreError::Native(msg)) => {
                assert!(
                    msg.contains("unknown rotation_reason_tag"),
                    "error message must point at the invalid tag, got: {msg}"
                );
            }
            other => panic!("expected HwKeystoreError::Native, got {other:?}"),
        }
        assert_eq!(
            mock.len(),
            mock_len_before,
            "no HW state mutation on invalid tag rejection"
        );
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** unknown handle
    /// reference returns `KeyNotFound` before generating new material.
    #[test]
    fn mock_rotate_identity_rejects_unknown_old_handle() {
        use umbrella_backup::cloud_wrap::RotationReason;

        let mock = MockHwKeystore::new();
        let nonexistent = HwKeyHandle::new("session-9d.nonexistent");
        let result = mock.rotate_identity(
            &nonexistent,
            "session-9d.unreachable.new".into(),
            [0u8; 32],
            0,
            RotationReason::PlannedRotation.tag(),
            [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
        );
        assert!(
            matches!(result, Err(HwKeystoreError::KeyNotFound(_))),
            "missing handle must surface as KeyNotFound, got {result:?}"
        );
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** default trait impl
    /// rejects callers that have not overridden `rotate_identity` —
    /// ensures missing wire-up surfaces with a deterministic error
    /// rather than silent placeholder behaviour.
    #[test]
    fn default_rotate_identity_impl_returns_not_implemented_native_error() {
        use umbrella_backup::cloud_wrap::RotationReason;

        struct StubCallback;
        impl PersistentKeyStoreCallback for StubCallback {
            fn generate_identity(&self, _label: String) -> Result<HwKeyHandle, HwKeystoreError> {
                unimplemented!()
            }
            fn sign_identity(
                &self,
                _handle: &HwKeyHandle,
                _data: &[u8],
            ) -> Result<Vec<u8>, HwKeystoreError> {
                unimplemented!()
            }
            fn wrap_secret(
                &self,
                _handle: &HwKeyHandle,
                _plaintext: &[u8],
            ) -> Result<Vec<u8>, HwKeystoreError> {
                unimplemented!()
            }
            fn unwrap_secret(
                &self,
                _handle: &HwKeyHandle,
                _ct: &[u8],
            ) -> Result<Vec<u8>, HwKeystoreError> {
                unimplemented!()
            }
            fn delete_identity(&self, _handle: &HwKeyHandle) -> Result<(), HwKeystoreError> {
                unimplemented!()
            }
            fn verifying_key(&self, _handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError> {
                unimplemented!()
            }
        }

        let stub = StubCallback;
        let dummy_handle = HwKeyHandle::new("unused");
        let result = stub.rotate_identity(
            &dummy_handle,
            "unused".into(),
            [0u8; 32],
            0,
            RotationReason::PlannedRotation.tag(),
            [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
        );
        match result {
            Err(HwKeystoreError::Native(msg)) => {
                assert!(
                    msg.contains("not implemented"),
                    "default impl must surface 'not implemented' diagnostic, got: {msg}"
                );
            }
            other => panic!("expected default impl Err(Native), got {other:?}"),
        }
    }
}
