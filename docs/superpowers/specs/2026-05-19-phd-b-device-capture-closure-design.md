# PhD-B Device-Capture Closure — Design Spec (Round 5)

**Date:** 2026-05-19 (fifth round)
**Predecessor:** Round 4 device-capture audit found 4 CRITICAL + 3 HIGH + 1 MEDIUM. This round closes them.

**Goal:** Real implementation, not paperwork. Every CRITICAL/HIGH from round 4 either closed in code OR has explicit hard reason why this round can't fully close (real-device requirement) + production-quality scaffolding plus closed-in-code parts.

## Findings to close

From `docs/audits/phd-b-device-capture-defense-2026-05-19.md` and per-R findings:

| ID | Severity | Closure path |
|----|----------|--------------|
| F-PHD-DC-R7-1 | CRITICAL | HW keystore (Rust trait + native bridges + mock for macOS test) |
| F-PHD-DC-R7-2 | CRITICAL | master_key sourced from HW-derived material when callback present |
| F-PHD-DC-R7-3 | HIGH | Stack-spill closure: `IdentitySeed` → `Box<[u8; N]>` fields |
| F-PHD-DC-R9-1 | HIGH | mlock + document VM compressor as residual (cannot fix from userland) |
| F-PHD-DC-R10-1 | CRITICAL | Real `PersistentKeyStoreCallback` trait + iOS Swift + Android Kotlin bindings |
| F-PHD-DC-R11-1 | MEDIUM | `MlockedSecret<T>` type + 5 sites migration |
| F-PHD-DC-R12-1 | CRITICAL | Ratchet state in MlockedSecret + zeroize-on-drop verified by re-run lldb |
| F-PHD-DC-R12-2 | HIGH | `Key::from_slice` audit + stack-spill closure inheritance |

## Architecture — 5 components

### Component 1 — `PersistentKeyStoreCallback` trait

`crates/umbrella-client/src/keystore/hw_callback.rs` (new file):

```rust
#[uniffi::export(callback_interface)]
pub trait PersistentKeyStoreCallback: Send + Sync + 'static {
    /// Generate identity inside HW keystore. Returns opaque key handle —
    /// **private key bytes never cross this boundary**.
    fn generate_identity(&self, label: String) -> Result<HwKeyHandle, HwKeystoreError>;
    
    /// Sign data with HW-resident identity key. Bytes signed inside chip.
    fn sign_identity(&self, handle: HwKeyHandle, data: Vec<u8>) -> Result<Vec<u8>, HwKeystoreError>;
    
    /// Wrap a software-side secret for storage. Returns ciphertext that
    /// only this HW keystore can unwrap (uses HW-side key).
    fn wrap_secret(&self, handle: HwKeyHandle, plaintext: Vec<u8>) -> Result<Vec<u8>, HwKeystoreError>;
    
    fn unwrap_secret(&self, handle: HwKeyHandle, ciphertext: Vec<u8>) -> Result<Vec<u8>, HwKeystoreError>;
    
    /// Delete identity (logout / device wipe).
    fn delete_identity(&self, handle: HwKeyHandle) -> Result<(), HwKeystoreError>;
}

pub struct HwKeyHandle(String); // opaque alias / Keychain label / Keystore alias
```

### Component 2 — Native bridges (Swift + Kotlin)

`crates/umbrella-ffi-swift/swift-package/UmbrellaProtocol/Sources/UmbrellaProtocol/KeyStoreBridge.swift`:

Real implementation with `SecKeyCreateRandomKey(attributes, &error)` using:
```swift
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: label.data(using: .utf8)!,
        kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], nil)!
    ]
]
```

`crates/umbrella-ffi-kotlin/kotlin-package/.../KeyStoreBridge.kt`:

Real implementation with `KeyGenParameterSpec.Builder` using:
```kotlin
val spec = KeyGenParameterSpec.Builder(
    label,
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)   // CRITICAL: hardware-backed
    .setUserAuthenticationRequired(true)
    .setUnlockedDeviceRequired(true)
    .build()
```

**Acceptance for bridges:** compile to target platform (`cargo ndk build` for Android, `xcrun swiftc` for iOS Simulator at minimum). Runtime test requires real device — documented as CI-gate addition.

### Component 3 — `MlockedSecret<T>` wrapper

`crates/umbrella-core/src/mlocked.rs` (new):

```rust
pub struct MlockedSecret<T: Zeroize> {
    inner: Box<T>, // heap-allocated
    locked: bool,
}

impl<T: Zeroize> MlockedSecret<T> {
    pub fn new(value: T) -> Self {
        let mut inner = Box::new(value);
        let ptr = &*inner as *const T as *const libc::c_void;
        let size = std::mem::size_of::<T>();
        let locked = unsafe { libc::mlock(ptr, size) } == 0;
        Self { inner, locked }
    }
    
    pub fn expose(&self) -> &T { &*self.inner }
}

impl<T: Zeroize> Drop for MlockedSecret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        if self.locked {
            let ptr = &*self.inner as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe { libc::munlock(ptr, size) };
        }
    }
}
```

**5 sites to migrate** (identified by round 4 R11):
1. `crates/umbrella-client/src/keystore/row_cipher.rs:113` — master_key
2. `crates/umbrella-client/src/core.rs:227` — identity (or replace with HW handle)
3. `crates/umbrella-mls/src/...` — session secrets (ratchet state)
4. `crates/umbrella-identity/src/seed.rs` — IdentitySeed
5. `crates/umbrella-pq/src/hedged.rs` — HedgedWitness

### Component 4 — Stack-spill closure

Audit `Key::from_slice` workspace-wide via `rg "from_slice|copy_from_slice" --type rust` in crypto-touching files. For each: ensure either:
- Source is already `Box<...>` (heap) and method returns `&Key`, no copy.
- OR refactor to receive heap pointer.

Specific refactor: `crates/umbrella-identity/src/seed.rs:113-120` — change struct layout so `[u8; N]` fields are `Box<[u8; N]>` (heap-allocated, droppable, zeroized).

### Component 5 — R7/R12 re-verification

After closure, **re-run** round 4 R7 and R12 lldb attacks. Acceptance:
- `attack_r7_identity_sk_not_in_stack_after_keygen` — 0 hits on stack scan
- `attack_r7_master_key_in_mlocked_region` — pointer falls within mlock'd page (verified via mincore syscall)
- `attack_r12_ratchet_zeroized_post_drop_stack_and_heap` — 0 hits both regions

## What does NOT count

- Adding `PersistentKeyStoreCallback` trait without wiring it through `IdentityStore` bootstrap path.
- Swift/Kotlin "skeleton" implementation that doesn't compile.
- `MlockedSecret` defined but not migrated to the 5 sites.
- R7 lldb re-run that uses old (pre-closure) binary.
- Mark anything as "carry-over to v1.2.0" without explicit hard reason (e.g., real device required).
- Tamarin lemma for HW keystore (wrong layer — this is OS/HW integration, not protocol).

## Real device caveat

iOS Secure Enclave / Android StrongBox actual runtime testing requires physical device or simulator. This round's acceptance for native bridges is:
- **Compile-green** under target toolchain (cargo ndk for Android, Swift Package Manager for iOS).
- **API contract** matches platform documentation.
- **Mock implementation** for macOS test path (`MockHwKeystore` simulating expected HW behavior).
- **CI workflow** stub added (with comment `# real device run TBD`) for Block 7.10 wiring.

Subagent should NOT claim runtime closure for Swift/Kotlin — only compile-green + mock-test pass + CI scaffold.

## Acceptance gate (all 6 must PASS)

1. `PersistentKeyStoreCallback` trait exists + wired through `IdentityStore::bootstrap` (callback-present path).
2. `MockHwKeystore` test passes under `cargo test --release -p umbrella-client`.
3. `MlockedSecret<T>` exists + 5 sites migrated + workspace tests green.
4. `IdentitySeed` + `RowCipher` use heap-allocated buffers; round 4 stack-spill patterns documented closed.
5. R7 re-run: 0 stack hits for identity_sk + master_key in mlock'd region.
6. R12 re-run: 0 stack+heap hits for ratchet application_secret post-drop.

Bridge layer (Swift+Kotlin):
- Compile-green (acceptance ≠ runtime-tested).
- API matches platform docs.
- Real-device runtime test documented as CI-gate for separate round.

## Workflow

1. Read round 4 report + per-R findings.
2. Build TodoWrite plan ~15 items.
3. Component 1: trait + error type + HwKeyHandle.
4. Component 2: Swift bridge + Kotlin bridge (compile-green, not runtime).
5. Component 3: MlockedSecret in umbrella-core.
6. Component 3 cont: migrate 5 sites.
7. Component 4: IdentitySeed refactor + Key::from_slice audit.
8. Wire HW callback through IdentityStore bootstrap.
9. MockHwKeystore + tests.
10. R7 re-run via updated `examples/r7_identity_lldb_target.rs` after closure.
11. R12 re-run via updated `examples/r12_ratchet_lldb_target.rs` after closure.
12. Final closure report `docs/audits/phd-b-device-capture-closure-2026-05-19.md`.
13. Ledger update — findings status from OPEN → CLOSED/PARTIAL.
14. Commits per phase.

## Branch

Continue on `audit/phd-b-hybrid-pq-2026-05-19`. Round 5 commits on top. Single big PR at end.

## Stop / handoff

Memory `feedback_phd_no_partial`. Context budget runs short → partial state with explicit "closed N of 6, remaining M" — NOT partial PhD claim.

## Literature for citations

- Apple Platform Security Guide May 2024 — SecKeyCreateRandomKey + kSecAttrTokenIDSecureEnclave
- Android Keystore developer docs — KeyGenParameterSpec.setIsStrongBoxBacked
- Linux mlock(2), Darwin mlock(2) man pages
- Halderman et al 2009 USENIX — "Lest We Remember: Cold-Boot Attacks on Encryption Keys"
- Aumasson 2018 "Serious Cryptography" §13 — implementation security
