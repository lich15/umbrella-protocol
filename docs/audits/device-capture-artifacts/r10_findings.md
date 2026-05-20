# R10 — Hardware Keystore Integration Audit

> **CLOSURE BANNER (2026-05-20 reconciliation):** F-PHD-DC-R10-1 (HW Keystore not wired) documented в этом artifact is **CLOSED** as of Round 5 closure + Pass 5 remediation: `PersistentKeyStoreCallback` trait wired через `ClientCore::new_with_hw_callback`; `HwBackedKeyStore` eliminates in-heap seed + identity_sk (commit `46784d1a`); `core.identity` is `Option<Arc<IdentityKey>>` and `None` on hw bootstrap path (commit `e7b034ff` F-CLIENT-HW-1 closes M-FINAL-1). This file remains as an archive of the round-4 audit findings at the time of writing.

## File enumeration

iOS bridge (`examples/ios-harness/`):

- `Package.swift`
- `Sources/UmbrellaTestHarness/UmbrellaTestHarnessApp.swift`
- `Sources/UmbrellaTestHarness/ContentView.swift`
- `Sources/UmbrellaTestHarness/TestScenarios.swift`
- `Sources/UmbrellaTestHarness/NativeBridges/KeyStoreBridge.swift`   ← **R10 focus**
- `Sources/UmbrellaTestHarness/NativeBridges/AttestationBridge.swift`
- `Sources/UmbrellaTestHarness/NativeBridges/CallKitBridge.swift`
- `Tests/UmbrellaTestHarnessTests/SmokeTests.swift`

Android bridge (`examples/android-harness/`):

- `app/build.gradle.kts`
- `app/src/main/AndroidManifest.xml`
- `app/src/main/java/xyz/umbrellax/testharness/MainActivity.kt`
- `app/src/main/java/xyz/umbrellax/testharness/TestScenarios.kt`
- `app/src/main/java/xyz/umbrellax/testharness/nativebridges/KeyStoreBridge.kt`   ← **R10 focus**
- `app/src/main/java/xyz/umbrellax/testharness/nativebridges/AttestationBridge.kt`
- `app/src/main/java/xyz/umbrellax/testharness/nativebridges/ConnectionServiceBridge.kt`
- `app/src/androidTest/java/xyz/umbrellax/testharness/SmokeTest.kt`

FFI binding crates:

- `crates/umbrella-ffi-swift/src/lib.rs` (49 LoC — re-exports only)
- `crates/umbrella-ffi-kotlin/src/lib.rs` (54 LoC — re-exports only)
- `crates/umbrella-ffi/src/lib.rs` — production FFI surface (Rust side)

## iOS KeyStoreBridge.swift — code excerpt with line citations

`examples/ios-harness/Sources/UmbrellaTestHarness/NativeBridges/KeyStoreBridge.swift`:

```swift
// Line 5-37: doc comment EXPLICITLY states skeleton scope
/// `KeyStoreBridge` — iOS Keychain + Secure Enclave facade для identity-seed
/// и device-keys.
///
/// # Скоуп Блока 7.8
///
/// Блок 7.8 ограничен skeleton-реализацией. `PersistentKeyStore` Rust trait
/// (см. `crates/umbrella-client/src/keystore/trait_def.rs`) **не экспонирован**
/// через uniffi как `callback_interface` в этом блоке — соответственно
/// `KeyStoreBridge` **не** наследует Rust trait и не передаётся в
/// `UmbrellaClientHandle` через FFI. Реальный two-way wiring через uniffi
/// callback interface появляется в Блоке 7.10 integration milestone.

// Line 38: only 3 methods implemented
final class KeyStoreBridge {
    enum BridgeError: Error {
        case native(String)
    }

    private let identityAccount = "umbrellax.identity.seed"
    private let service = "xyz.umbrellax.testharness.keystore"

    init() throws { /* pre-checks; SE available on iPhone 5s+ */ }

    func hasIdentity() async throws -> Bool { /* SecItemCopyMatching */ }
    func storeSeed(_ seed: Data) async throws { /* SecItemAdd */ }
    func purgeAll() async throws { /* SecItemDelete */ }
}
```

### What is actually wired

- `hasIdentity()` — Keychain `SecItemCopyMatching` against
  `kSecClassGenericPassword` with service "xyz.umbrellax.testharness.keystore".
- `storeSeed(_:)` — Keychain `SecItemAdd` with
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Note: seed bytes are
  stored as **value data** of a generic password Keychain item. **Not** in
  Secure Enclave. SE is only mentioned in doc-comments.
- `purgeAll()` — Keychain `SecItemDelete`.

### What is NOT wired

- **No** `SecKeyCreateRandomKey(..., kSecAttrTokenIDSecureEnclave)` call
  anywhere — the SE never creates a key. The doc-comment says "Ed25519 →
  P-256 mapping inside SE — ADR-010 Решение 5" but **no Swift code
  performs that mapping**.
- **No** `LAContext` biometric protection on retrieval.
- **No** uniffi `callback_interface` registration. The Rust
  `PersistentKeyStore` trait is **not** implemented by this Swift class.
- **No** `signWithIdentity`, `addDevice`, `signWithDevice`, or any
  TEE-cross signing primitive.

## Android KeyStoreBridge.kt — code excerpt with line citations

`examples/android-harness/app/src/main/java/xyz/umbrellax/testharness/nativebridges/KeyStoreBridge.kt`:

```kotlin
// Line 14-19: doc comment EXPLICITLY states skeleton scope
 * Skeleton: Rust `PersistentKeyStore` trait (см.
 * `crates/umbrella-client/src/keystore/trait_def.rs`) **не экспонирован**
 * через uniffi как `callback_interface`. `KeyStoreBridge` — standalone
 * Kotlin класс; real two-way wiring Rust ↔ Kotlin через uniffi callback
 * interface приходит в Блоке 7.10 integration milestone.

// Line 40-91: 3 methods only
class KeyStoreBridge(private val ctx: Context) {
    private val encPrefsName = "umbrellax_identity_seed"
    private val keystoreAlias = "umbrellax.identity"

    fun hasIdentity(): Boolean { ... }
    fun storeSeed(seed: ByteArray) { ... EncryptedSharedPreferences ... }
    fun purgeAll() { ... }
}
```

### What is actually wired

- `storeSeed` uses `androidx.security.crypto.EncryptedSharedPreferences`
  with a `MasterKey.Builder` that calls `setRequestStrongBoxBacked(true)`
  on API 28+. The MasterKey itself is StrongBox-backed when available.
- `hasIdentity` checks `KeyStore.getInstance("AndroidKeyStore")` for the
  alias.

### What is NOT wired

- **No** `KeyGenParameterSpec.Builder(alias, KEY_USAGE).setIsStrongBoxBacked(true)`
  for device-keys. Only the MasterKey wrapping EncryptedSharedPreferences
  uses StrongBox. The actual seed bytes are inside EncryptedSharedPreferences,
  which is **on disk** (encrypted) — not inside StrongBox at rest.
- **No** signing operations. No `Signature.getInstance("Ed25519").initSign(...)`
  with a StrongBox-backed private key reference.
- **No** uniffi `callback_interface` registration.

## umbrella-ffi-swift / umbrella-ffi-kotlin Rust side

`crates/umbrella-ffi-swift/src/lib.rs` (49 LoC total):

```rust
pub use umbrella_ffi::*;
pub const BUILD_MARKER: &str = "umbrella-ffi-swift stage-7.8 xcframework";
umbrella_ffi::uniffi_reexport_scaffolding!();
```

`crates/umbrella-ffi-kotlin/src/lib.rs` (54 LoC total):

```rust
pub use umbrella_ffi::*;
pub const BUILD_MARKER: &str = "umbrella-ffi-kotlin stage-7.9 aar";
umbrella_ffi::uniffi_reexport_scaffolding!();
```

Both crates are pure re-export shims. There is **no** uniffi
`#[callback_interface]` definition for `PersistentKeyStore` in the
entire workspace (verified by `rg "callback_interface"` → 0 hits).

## Production code path: ClientCore.identity

`crates/umbrella-client/src/core.rs:217-227`:

```rust
#[allow(dead_code)]
pub struct ClientCore {
    /// Identity-key Ed25519 — корень доверия. В Блоке 7.2 хранится в памяти
    /// (`Arc<IdentityKey>`); в Блоке 7.3 заменяется на non-exportable ключ
    /// внутри Secure Enclave / StrongBox через `PersistentKeyStore` callback.
    pub(crate) identity: Arc<IdentityKey>,
```

The doc-comment is **future-tense aspiration**. As of audit date
2026-05-19, `identity` is an `Arc<IdentityKey>` — `IdentityKey` holds a
plain `PrivateSigningKey(SigningKey)` from `ed25519_dalek` 2.2. The
Ed25519 signing scalar lives in process heap.

## Findings

### F-PHD-DC-R10-1 — Hardware-backed identity NOT wired (CRITICAL)

The architectural intent (ADR-010 Decision 5 — non-exportable P-256
inside SE/StrongBox + Ed25519 → P-256 mapping) exists **only in
documentation**. The current production code path stores identity_sk
and device-keys in regular Rust heap memory. R7 lldb scan empirically
confirms entropy + master_key extractability.

Required to close:

1. Define `#[uniffi::export(callback_interface)]` trait
   `PersistentKeyStore` in `crates/umbrella-ffi/src/keystore_callback.rs`.
2. Swift implementation: `class KeyStoreBridgeImpl: PersistentKeyStore`
   that calls `SecKeyCreateRandomKey` with
   `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` for device-keys.
3. iOS doesn't support Ed25519 in SE (P-256 only); implement
   Ed25519-on-P-256 wrapping per ADR-010 §5 by deriving an Ed25519
   identity outside SE but using SE-backed P-256 as a **wrap key** for
   identity_sk at rest, then decrypting per-session into mlock'd memory.
4. Android: `KeyGenParameterSpec.Builder("umbrellax.device.0", ...)
   .setKeySize(256).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
   .setIsStrongBoxBacked(true).build()` for non-exportable device-keys.
5. `bootstrap_identity` flow on first launch: native side generates
   non-exportable device-key + identity wrap-key, returns only public
   parts + attestation to Rust; Rust never sees private bytes.

### F-PHD-DC-R10-2 — Skeleton bridges are explicitly admitted (INFO)

The doc-comments in both Swift and Kotlin KeyStoreBridge files
explicitly state "Block 7.10 integration milestone" as the wiring date.
This is honest disclosure. However: the workspace contains no
`crates/umbrella-ffi/src/keystore_callback.rs` and no
`#[uniffi::export(callback_interface)]` macro invocation for
`PersistentKeyStore`. The work is not in progress on this branch.

### F-PHD-DC-R10-3 — Attestation bridges separate from key storage (LOW)

`AttestationBridge.swift` and `AttestationBridge.kt` exist; they handle
App Attest / Play Integrity wire bytes. These DO appear wired through
the FFI (see `crates/umbrella-ffi/src/export/client.rs` calls into
`umbrella_client::keystore::trait_def::BootstrappedIdentity::
primary_device_attestation`). Attestation is wired; **key storage is
not**. The asymmetry means a passing attestation says "we're on a real
device" but doesn't say "we have hardware-backed keys".

## Severity

**F-PHD-DC-R10-1**: **CRITICAL** — fundamental device-capture defense
gap. All R7 / R12 findings are downstream of this single architecture
gap.

## Reference

Apple Platform Security Guide May 2024:
- Secure Enclave Boot ROM key wrapping — pages 16-19.
- Keychain Services API — `SecKeyCreateRandomKey` with
  `kSecAttrTokenIDSecureEnclave` for non-exportable P-256 keys.
- Data Protection class `NSFileProtectionComplete` /
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — passcode-locked.

Android Keystore System (developer.android.com/training/articles/keystore):
- `KeyGenParameterSpec.Builder.setIsStrongBoxBacked(true)` — StrongBox-
  backed for hardware key isolation (Pixel 3+, Samsung S10+).
- `setUserAuthenticationRequired(true)` — biometric/PIN required for
  signing operations.

NIST SP 800-57 Part 1 Rev. 5 §6.2.1 — long-term identity keys
should be hardware-protected; ephemeral session keys may live in
software-only memory.
