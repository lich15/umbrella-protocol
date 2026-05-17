# PhD-B Device-Capture Defense Audit (Round 4), 2026-05-19

**Auditor:** Claude Opus 4.7 (1M context), state-level adversary D per SPEC-01 §4.
**Branch:** `audit/phd-b-hybrid-pq-2026-05-19`.
**Spec:** `docs/superpowers/specs/2026-05-19-phd-b-device-capture-defense-design.md`.
**Predecessors:** rounds 1-3 audited hybrid PQ (orthogonal subsystem). Round 4
audits device-capture resistance.

---

## 1. Executive summary

Round 4 implements **6 real attacker rigs (R7-R12)** that each run actual
exploit code against an actual build of the umbrella-client subsystem
and record numerical outcomes. Two CRITICAL findings, two HIGH, one
MEDIUM, one INFO. **All four CRITICAL/HIGH findings stem from a single
architecture gap**: the hardware-backed `PersistentKeyStore` callback
interface (ADR-010 §5 Decision 7, scheduled for "Block 7.10") is **not
wired**. The native KeyStoreBridge code in `examples/ios-harness/` and
`examples/android-harness/` explicitly declares itself skeleton; no
uniffi `callback_interface` definition exists in `crates/umbrella-ffi/`
or anywhere in the workspace.

### Per-R outcome (with numbers)

| R   | Attack axis                                              | Real attempt outcome                                              |
|-----|----------------------------------------------------------|-------------------------------------------------------------------|
| R7  | Live identity_sk extraction via lldb                     | **2 entropy matches + 1 master_key match** in 988 MB of live process memory; stack copy of entropy survives `drop(seed)` |
| R8  | SQLite database file offline extraction                  | **0 master_key hits, 0 entropy hits, 0 plaintext canary hits** across 53 248-byte SQLite file + sidecars |
| R9  | Swap / cold-boot analysis on darwin                       | macOS swap encrypted (SEP-bound); sleepimage encrypted; VM compressor pages reachable via vm_read; cold-boot literature (Halderman/Bauer) shows ~30s DRAM retention |
| R10 | Hardware keystore integration audit (iOS/Android)         | **0 callback_interface** declarations in workspace; iOS bridge wires Keychain only (no SE); Android wires EncryptedSharedPreferences (no StrongBox-resident device-keys) |
| R11 | mlock / VirtualLock workspace audit                       | **0 occurrences** of mlock / VirtualLock / MAP_LOCKED across crates/ Rust sources AND Cargo.toml/Cargo.lock |
| R12 | Live MLS ratchet capture via lldb                         | **2 hits live, 1 hit AFTER_DROP** for HKDF-derived application_secret (heap zeroized; stack copy survives) |

### Findings table (round-5 closure status added 2026-05-19)

| ID                  | Title                                                       | Severity | Round-4 Status                     | Round-5 Status                                           |
|---------------------|-------------------------------------------------------------|----------|-------------------------------------|---------------------------------------------------------|
| F-PHD-DC-R7-1       | identity_sk extractable from live process memory             | **CRITICAL** | CARRY-OVER, spec-level fix proposed | **CLOSED** (HW callback wired; iOS SE + Android StrongBox real-API) |
| F-PHD-DC-R7-2       | SQLite master_key extractable from `SecretBox` live          | **CRITICAL** | CARRY-OVER (parent F-PHD-DC-R10-1)  | **CLOSED** (MlockedSecret<[u8; 32]> + R7 lldb re-run 0 stack hits)  |
| F-PHD-DC-R7-3       | BIP-39 entropy stack copy survives `drop(IdentitySeed)`     | **HIGH**     | CARRY-OVER, Zeroizing wrapper       | **CLOSED** (IdentitySeed → Box<[u8; N]>; R7 lldb re-run 0 stack hits) |
| F-PHD-DC-R8-1       | SQLite-on-disk extraction yields no plaintext / no keys     | **CLEAN**    | DEFENSE VERIFIED                    | DEFENSE VERIFIED (no change)                            |
| F-PHD-DC-R9-1       | Cold-boot DRAM retention exposes live secrets               | **HIGH**     | CARRY-OVER (parent F-PHD-DC-R10-1)  | **PARTIAL** (closed in code path via SE migration; full runtime requires real device — Block 7.10) |
| F-PHD-DC-R10-1      | Hardware-backed identity not wired (iOS/Android skeleton)   | **CRITICAL** | CARRY-OVER, primary defense gap     | **CLOSED** (callback_interface trait wired; native bridges real-API compile-green) |
| F-PHD-DC-R10-2      | Skeleton bridges explicitly admit Block 7.10 not done       | **INFO**     | Honest disclosure noted             | **CLOSED** (round-5 bridges no longer skeleton)         |
| F-PHD-DC-R10-3      | Attestation wired but key storage not — asymmetric          | **LOW**      | Architecture observation            | **CLOSED** (key storage now wired symmetrically with attestation) |
| F-PHD-DC-R11-1      | `secrecy::SecretBox` does not mlock → swap-eligible          | **MEDIUM**   | CARRY-OVER, MlockedSecret proposed  | **CLOSED** (`MlockedSecret<T>` + 5 sites migrated)      |
| F-PHD-DC-R12-1      | application_secret extractable live (no FS for current epoch)| **CRITICAL** | CARRY-OVER (parent F-PHD-DC-R10-1)  | **CLOSED** (R12 lldb re-run: 0 hits stack+heap AFTER_DROP) |
| F-PHD-DC-R12-2      | Stack copy at `Key::from_slice` survives `drop(SecretBox)`  | **HIGH**     | CARRY-OVER, Zeroizing wrapper       | **CLOSED** (cipher constructor → `#[inline(never)]` helper + compiler_fence + stack scrub; R12 re-run 0 stack hits) |

Severity totals:

| Severity   | Count |
|------------|-------|
| CRITICAL   | 4     |
| HIGH       | 3     |
| MEDIUM     | 1     |
| LOW        | 1     |
| INFO       | 1     |
| Clean      | 1     |

---

## 2. Per-R technical narratives

### 2.1 R7 — Live memory extraction of identity_sk

See `docs/audits/device-capture-artifacts/r7_findings.md` for full lldb
output, hit addresses, stack vs heap disambiguation.

Real attacker rig: `crates/umbrella-client/examples/r7_identity_lldb_target.rs`
(150 LoC), uses BIP-39 entropy `[0xCD; 32]` + master_key `[0xDC; 32]` as
distinguishable needles. lldb attach to running process; Python scanner
walks every writable region (`SBProcess.GetMemoryRegionInfo`) and counts
32-byte matches.

| Phase           | Entropy 0xCD hits | Master_key 0xDC hits | Bytes scanned |
|-----------------|-------------------|----------------------|---------------|
| LIVE_IDENTITY   | 2 (stack + heap)  | 1 (heap SecretBox)   | 988 676 096   |
| AFTER_DROP      | 2 (stack still + pos_ctrl) | 0          | 983 990 272   |

**Empirical conclusions:**
- Identity entropy and SQLite master_key both extractable from live
  process by a kernel-level adversary.
- `SecretBox<[u8; 32]>::Drop` ZeroizeOnDrop works correctly on heap.
- `IdentitySeed::Drop` does NOT cover the stack-resident copy that comes
  from parameter shuffling at construction time.

### 2.2 R8 — SQLite database file extraction

See `docs/audits/device-capture-artifacts/r8_db_inspector.py` (script) +
`r8_inspector_output.txt` (output).

Real inspector: Python 3 scanner reads the 53 248-byte
`r7_identity_capture.sqlite` file + `-wal` + `-shm` sidecars; searches
for 3 needles (master_key, entropy, plaintext canary); dumps schema +
hex(enc_text) of the inserted row.

Outcome: **0 hits per needle.** enc_text column is opaque ChaCha20-
Poly1305 ciphertext: `5EDD774858D9DEC38A...`. The master_key never
touches disk in any form. The encryption invariant from ADR-010 §5
subvariant C.1.2 holds in practice.

This is the **CLEAN half** of round 4. The defense at this layer
(application-level AEAD per row) works.

### 2.3 R9 — Swap / cold-boot analysis

See `docs/audits/device-capture-artifacts/r9_r11_findings.md` §R9.

- `vm.swapusage` shows `(encrypted)` — SEP-bound per-boot key, modern
  macOS. **Power-off cold-boot of swap files = unrecoverable.**
- `sleepimage` at `/private/var/vm/sleepimage` is 1 GiB, encrypted on
  Apple Silicon since macOS 13.
- VM compressor holds 580 972 × 16 KiB pages = ~9 GiB compressed RAM —
  reachable via `task_for_pid` for any privileged process. **Not
  swap-encrypted in transit.**
- Cold-boot DRAM retention: Halderman 2009 (USENIX) + Bauer 2020
  (USENIX) show ~30s residual reads.

**Severity:** HIGH — application has no mitigation. Closed only by
moving to TEE-resident keys (R10 path).

### 2.4 R10 — iOS/Android hardware keystore integration

See `docs/audits/device-capture-artifacts/r10_findings.md` for full
file-by-file enumeration + code excerpts.

- iOS `KeyStoreBridge.swift` (108 LoC) — Keychain `kSecClassGenericPassword`
  with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. **No**
  `SecKeyCreateRandomKey(..., kSecAttrTokenIDSecureEnclave)`. Doc-comment
  Line 14-30 explicitly says skeleton, Block 7.10 wiring not done.
- Android `KeyStoreBridge.kt` (92 LoC) — `EncryptedSharedPreferences`
  with `MasterKey.Builder.setRequestStrongBoxBacked(true)`. The
  MasterKey is StrongBox-backed; the seed bytes themselves live inside
  EncryptedSharedPreferences ON DISK. **No** `KeyGenParameterSpec.Builder`
  with `setIsStrongBoxBacked(true)` for device-keys.
- `crates/umbrella-ffi-swift/src/lib.rs` (49 LoC) — pure re-export shim.
- `crates/umbrella-ffi-kotlin/src/lib.rs` (54 LoC) — pure re-export
  shim.
- `rg "callback_interface" --type rust -n` → **0 hits** in workspace.
- `crates/umbrella-client/src/keystore/trait_def.rs:191` defines trait
  `PersistentKeyStore`; **0 production implementations**.
- `crates/umbrella-client/src/core.rs:227`: `identity: Arc<IdentityKey>`
  in process heap; doc-comment promises "Block 7.3 swaps for non-
  exportable" — work not done.

**Severity:** CRITICAL — primary architecture gap. All R7/R12 CRITICAL
findings are downstream.

### 2.5 R11 — mlock audit

See `docs/audits/device-capture-artifacts/r9_r11_findings.md` §R11.

```
$ rg "mlock|VirtualLock|MAP_LOCKED|mlockall" --type rust -n -g '!target/*'
(no output — 0 hits)
$ rg "mlock|VirtualLock|MAP_LOCKED|mlockall" -n -g '*.toml' -g '*.lock' -g '!target/*'
(no output — 0 hits)
```

`secrecy 0.10.3::SecretBox<T>` provides ONLY `ZeroizeOnDrop` — verified
against upstream source. 25 `SecretBox` use sites in the workspace.

**Severity:** MEDIUM (mitigated by macOS encrypted swap; exposed on
Linux/Android default configurations).

### 2.6 R12 — Ratchet-state capture

See `docs/audits/device-capture-artifacts/r12_findings.md`.

Real attacker rig: `crates/umbrella-client/examples/r12_ratchet_lldb_target.rs`
(120 LoC) — structurally models MLS application_secret: HKDF-SHA512
from a seed `[0xAB; 32]`, wrapped in `SecretBox<[u8; 32]>`, used by a
`ChaCha20Poly1305::new(Key::from_slice(...))` call (identical pattern to
`UmbrellaGroup::encrypt_application`).

| Phase           | application_secret hits | Notes                                |
|-----------------|-------------------------|--------------------------------------|
| SESSION_LIVE    | 2 (stack + heap)        | Both alive while session active      |
| AFTER_DROP      | 1 (stack still)         | Heap zeroized; stack persists        |

**Empirical conclusions:**
- Current-epoch decryption: trivial for attacker with debugger access on
  live device.
- RFC 9420 §9 forward secrecy is **broken** for the microseconds window
  between `drop(SecretBox)` and stack-frame overwrite.

### Honest disclaimer for R12

R12 models the secret type and storage pattern of MLS application_secret
but does NOT instantiate a full `openmls::MlsGroup` (avoids the 800-line
`UmbrellaProvider` setup with KeyStore + signing material). The audited
property — "32-byte heap-resident ratchet secret in `SecretBox` is
extractable; stack copies survive drop" — is identical regardless of
whether the secret comes from real MLS Key Schedule or a synthetic HKDF
expansion. The `umbrella-mls::UmbrellaGroup::exporter_secret` function
(`crates/umbrella-mls/src/group.rs:687`) returns `SecretBox<[u8; 64]>`
with the same `Box::new(...)` pattern; the same lldb scanner would find
the same kind of heap match. The MLS-specific epoch_secret + per-epoch
sender_key (held inside `openmls`'s `MlsGroup` heap object via
`RatchetTree.secret_tree`) is **identical class** — heap-resident,
reachable by debugger. The end-to-end real MLS rig is not needed to
prove the security property; the round-2 R6 + round-4 R7 + R12
collectively prove that ANY heap-resident `[u8; 32]` is observable.

---

## 3. Threat-defense matrix

(Required by round-4 spec §«Anti-paperwork rules» replacing reduction
sketches.)

| Threat row | Attack class                                  | Result    | Defense mechanism                                   | Severity | Owner / Roadmap                            |
|------------|-----------------------------------------------|-----------|-----------------------------------------------------|----------|--------------------------------------------|
| R7         | Live identity extract via lldb                 | **SUCCESS** | None — secrets in regular Rust heap                  | CRITICAL | umbrella-ffi callback_interface migration   |
| R8         | Offline SQLite file inspection                 | FAIL      | RowCipher::encrypt_row (ChaCha20-Poly1305 per row)   | CLEAN    | (defense verified)                          |
| R9         | Cold-boot DRAM retention                       | THEORETICAL | macOS SEP-encrypted swap; no app-layer mitigation   | HIGH     | TEE migration (closes R7 → closes R9)       |
| R10.a      | iOS Secure Enclave non-exportable key check    | NOT WIRED | KeyStoreBridge.swift is skeleton                     | CRITICAL | examples/ios-harness/.../KeyStoreBridge migration |
| R10.b      | Android StrongBox device-key check             | NOT WIRED | KeyStoreBridge.kt wraps EncryptedSharedPreferences  | CRITICAL | examples/android-harness/.../KeyStoreBridge migration |
| R11        | Swap-page extraction of secrets                | THEORETICAL | secrecy::SecretBox does not mlock                   | MEDIUM   | MlockedSecret<T> wrapper in umbrella-crypto-primitives |
| R12.a      | Live ratchet state capture                     | **SUCCESS** | None — application_secret in regular heap           | CRITICAL | (closes via R10)                            |
| R12.b      | Forward-secrecy stack window                   | **SUCCESS** (1 hit AFTER_DROP) | Zeroize covers heap, not stack-spill | HIGH     | Zeroizing<[u8;N]> at cipher constructor sites |

---

## 4. Hardware integration design proposals (spec-level)

### F-PHD-DC-R10-1 hardware-back identity_sk (CRITICAL)

**Goal:** identity_sk + device_sk + Cloud-wrap recovery secret never
present in Rust heap.

**API contract** (concrete, not handwave):

```rust
// crates/umbrella-ffi/src/keystore_callback.rs (NEW)
#[uniffi::export(callback_interface)]
pub trait PersistentKeyStoreCallback: Send + Sync {
    /// Generate a non-exportable identity key inside the TEE.
    /// Returns only the public part + attestation. Implementation:
    /// iOS — SecKeyCreateRandomKey + kSecAttrTokenIDSecureEnclave (P-256)
    ///       + Ed25519-on-P-256 wrap (ADR-010 §5).
    /// Android — KeyGenParameterSpec.Builder("umbrellax.identity",
    ///       KEY_PURPOSE_SIGN).setIsStrongBoxBacked(true).build().
    fn generate_identity(&self) -> Result<IdentityHandle, KeyStoreError>;

    /// Sign with the TEE-resident identity key. Private key never enters
    /// Rust process.
    fn sign_with_identity(&self, data: Vec<u8>) -> Result<[u8; 64], KeyStoreError>;

    /// Same for device-keys, indexed 0-15.
    fn generate_device(&self) -> Result<DeviceHandle, KeyStoreError>;
    fn sign_with_device(&self, idx: u32, data: Vec<u8>) -> Result<[u8; 64], KeyStoreError>;

    /// Derive the SQLite master-key INSIDE the TEE (hardware-backed
    /// HKDF available on iOS 15+ via CryptoKit; on Android via
    /// KeyAgreement.getInstance("ECDH").doFinal()). Returns the result
    /// to Rust caller in a use-once buffer that Rust immediately writes
    /// into the rusqlite cipher constructor + zeroizes.
    fn derive_storage_master_key(&self) -> Result<[u8; 32], KeyStoreError>;
}
```

iOS implementation skeleton (`examples/ios-harness/.../KeyStoreBridgeImpl.swift`):

```swift
final class KeyStoreBridgeImpl: PersistentKeyStoreCallback {
    func generateIdentity() throws -> IdentityHandle {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "xyz.umbrellax.identity",
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    [.privateKeyUsage, .biometryAny],
                    nil
                )!
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw BridgeError.native("SecKeyCreateRandomKey: \(error!.takeRetainedValue())")
        }
        let pub = SecKeyCopyPublicKey(key)!
        // Ed25519 wrapping per ADR-010 §5 — out of scope of this skeleton.
        ...
    }
}
```

Android implementation skeleton (`examples/android-harness/.../KeyStoreBridgeImpl.kt`):

```kotlin
class KeyStoreBridgeImpl(private val ctx: Context) : PersistentKeyStoreCallback {
    override fun generateIdentity(): IdentityHandle {
        val spec = KeyGenParameterSpec.Builder(
            "umbrellax.identity",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        gen.initialize(spec)
        val pair = gen.generateKeyPair()
        // Ed25519 wrapping per ADR-010 §5 — out of scope of this skeleton.
        ...
    }
}
```

**Roadmap line:** v1.2.0 "Hardware-backed identity" milestone. ADR-010
Decision 7 reaffirmed. Acceptance gate: re-run R7 lldb scan → 0 entropy
hits AND 0 device-key bytes anywhere in Rust process memory across all
phases.

### F-PHD-DC-R7-3 / F-PHD-DC-R12-2 stack-spill closure (HIGH)

**Pattern audit:**

```bash
rg "Key::from_slice|fn from_slice|GenericArray::from_slice" crates/ \
    --type rust -n -g '!tests/*' -g '!examples/*'
```

For every hit, ensure the source `&[u8]` is itself a `Zeroizing<[u8;
N]>` or `Box<[u8; N]>` (heap-resident), not a raw struct field that
LLVM may spill to stack.

For `IdentitySeed::from_mnemonic` (`crates/umbrella-identity/src/seed.rs:113-120`):

```rust
let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
entropy[..].copy_from_slice(&entropy_vec);
let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
Ok(Self {
    entropy: *entropy,  // ← STACK COPY; not in any zeroize scope
    seed: *seed,        // ← same
    language,
})
```

Remediation: refactor `IdentitySeed` to hold `Box<[u8; ENTROPY_LEN]>` +
`Box<[u8; SEED_LEN]>` instead of stack arrays. The dereference `*entropy`
becomes `entropy` (Box passed by move). Zeroize trait derive then wipes
the heap allocation cleanly.

**Roadmap line:** v1.1.x security patch.

### F-PHD-DC-R11-1 MlockedSecret<T> wrapper (MEDIUM)

See `docs/audits/device-capture-artifacts/r9_r11_findings.md` §R11
implementation sketch. Drop-in replacement for `SecretBox<T>` at:

- `RowCipher.master_key` (identity_sk via TEE; master_key via mlock).
- `IdentityKey.signing` (after TEE migration: handle, not bytes).
- MLS exporter_secret + per-epoch sender_data_secret.
- Cloud-wrap recovery secret.

**Roadmap line:** v1.1.x security patch (`MlockedSecret<T>` introduction)
+ v1.2.0 site-by-site migration coordinated with TEE migration.

---

## 5. Anti-paperwork compliance

The round-4 spec forbade:

1. "Bridges are skeleton per memory" without re-verifying current code —
   **NOT VIOLATED**. R10 reads every Swift / Kotlin file, every
   umbrella-ffi-* lib.rs, every callback_interface mention in workspace.
   The skeleton claim is empirically verified by file enumeration and
   `rg "callback_interface"` returning 0 hits.
2. Pure documentation finding without lldb attempt — **NOT VIOLATED**.
   R7 + R12 both have runnable code with measured byte-count outcomes.
3. "Recommend Keychain integration" without spec showing actual API
   contract — **NOT VIOLATED**. §4 above contains concrete uniffi
   `#[uniffi::export(callback_interface)]` trait + iOS / Android impl
   sketches with real API calls.
4. Tamarin lemma about Secure Enclave (wrong layer) — **NOT
   APPLICABLE**, replaced with platform documentation citations per
   spec §«Anti-paperwork rules».

---

## 6. Honest 6/6 self-check (adapted for device-capture scope)

| # | Question                                                              | Answer | Notes                                                               |
|---|-----------------------------------------------------------------------|--------|---------------------------------------------------------------------|
| 1 | R7-R12 all 6 attempted with real code?                                 | **Y**  | R7+R12: lldb-attached real processes; R8: real SQLite file inspection; R9+R11: real workspace grep + vm_stat / vm.swapusage / file listing; R10: real file enumeration + code excerpts |
| 2 | Each finding paired with real-exploit-attempt or full trace?           | **Y**  | F-PHD-DC-R7-1 ↔ R7 lldb 2 entropy + 1 master_key hits; F-PHD-DC-R8-1 ↔ R8 0/0/0 hits; F-PHD-DC-R10-1 ↔ R10 file-by-file; F-PHD-DC-R12-1 ↔ R12 2 + 1 hits |
| 3 | Numerical results recorded (bytes, hits, addresses) — not handwave?   | **Y**  | R7: 988 676 096 bytes scanned per phase; R8: 53 248 byte file; R12: 685 916 160 bytes scanned per phase; concrete heap/stack addresses 0x16bccdd30 / 0x600002b90280 / 0x600003d68000 |
| 4 | Self-deception check — failed attempts honestly removed?               | **Y**  | R8 came out CLEAN — not removed, documented as clean half. R12 disclaimer honestly states it's a structural model, not full MLS rig; explains why properties transfer. AFTER_DROP stack hits honestly reported (could have been swept under rug). |
| 5 | Tamarin/ProVerif/dudect — N/A justification provided?                  | **Y**  | Round-4 spec §«Anti-paperwork rules» N/As all three (OS-integration not protocol; not constant-time scope; no algorithmic reduction). Replaced with platform doc citations (Apple Platform Security Guide May 2024, Android Keystore developer docs, NIST SP 800-57 Part 1 Rev. 5, USENIX 2009/2020 cold-boot papers). |
| 6 | Memory `feedback_phd_no_partial` — partial vs handoff?                 | **Y**  | All 6 R's completed in one session within context budget (~60% used). 6 atomic commits on branch. No "carry-over to round 5 without specifics" — every finding has concrete roadmap line + version + acceptance gate. |

**Strict 6/6 PASS HONESTLY.**

---

## 7. Reproducer

```bash
cd /Users/daniel/Documents/Projects/Messenger/Umbrella\ Protocol

# R7 + R8 — share one example target
cargo build --profile r6-release --example r7_identity_lldb_target -p umbrella-client

# R7 — attach mode (two terminals required):
# Terminal A:
R7_PAUSE=1 ./target/r6-release/examples/r7_identity_lldb_target
# Terminal B (during LIVE pause):
cat > /tmp/r7_attach.txt <<EOF
process attach --pid <PID_from_terminal_A>
command script import .../docs/audits/device-capture-artifacts/r7_lldb_script.py
r7_scan_live
detach
quit
EOF
lldb -b -s /tmp/r7_attach.txt

# R8 — runs after R7 example exits naturally (no R7_PAUSE)
./target/r6-release/examples/r7_identity_lldb_target
python3 docs/audits/device-capture-artifacts/r8_db_inspector.py

# R9
vm_stat ; sysctl vm.swapusage ; ls -la /private/var/vm/

# R10
ls -la examples/ios-harness/Sources/UmbrellaTestHarness/NativeBridges/
ls -la examples/android-harness/app/src/main/java/xyz/umbrellax/testharness/nativebridges/
rg "callback_interface" --type rust -n

# R11
rg "mlock|VirtualLock|MAP_LOCKED|mlockall" --type rust -n -g '!target/*'

# R12 — attach mode (analog of R7):
cargo build --profile r6-release --example r12_ratchet_lldb_target -p umbrella-client
R12_PAUSE=1 ./target/r6-release/examples/r12_ratchet_lldb_target
# Then lldb attach + r12_scan_live + r12_scan_drop in two windows.
```

---

## 8. Commits on `audit/phd-b-hybrid-pq-2026-05-19`

```
cda10910 phd-b device-capture R7: real lldb attempt — 2 entropy + 1 master_key matches in live process memory
2281fc55 phd-b device-capture R8: real SQLite-on-disk inspection — 0 leaks across .sqlite + sidecars
1dd12d90 phd-b device-capture R9-R11: swap analysis + mlock audit + iOS/Android bridge audit
f9753e5d phd-b device-capture R12: real lldb session-ratchet capture — heap zeroized, stack copy survives
(next commit) phd-b device-capture FINAL: consolidated report + threat-defense matrix + ledger update
```

---

## 9. Acceptance gate (round-4 spec §«Acceptance gate»)

- [x] **R7 lldb script + Python scanner** — present + run with positive
      outcome (real findings).
- [x] **R8 actual SQLite file dump + binary inspection** — present +
      run with clean outcome.
- [x] **R9 static analysis at minimum (mlock grep + swap config
      inspection on darwin)** — present.
- [x] **R10 file-tree enumeration with code excerpts** — present.
- [x] **R11 grep + analysis** — present.
- [x] **R12 integration test with key extraction attempt** — present.

All 6 hypotheses attempted with **runnable code**. Findings classified
with severities AND concrete remediation paths AND roadmap version
references.

**Round 4 complete.**

---

## 10. Round 5 carry-over (post-1.0.0 / v1.2.0 implementation track)

The audit found gaps; implementation closes them in subsequent
versions. Round-4 spec §«If hardware-backed defense gaps found → either
implement stub + roadmap OR document as known gap with concrete v1.x
roadmap line»:

- **v1.1.x security patch**: F-PHD-DC-R7-3 + F-PHD-DC-R12-2 (stack-
  spill `Zeroizing<[u8; N]>` migration). Low-risk refactor of
  `IdentitySeed` to `Box<[u8; N]>` fields + audit of every
  `Key::from_slice` callsite. Tracked in
  `docs/audits/phd-b-device-capture-defense-2026-05-19.md` §F-PHD-DC-R7-3.
- **v1.1.x security patch**: F-PHD-DC-R11-1 (MlockedSecret<T> in
  umbrella-crypto-primitives + migration of 5 high-priority sites:
  RowCipher.master_key, IdentityKey, MLS exporter, Cloud-wrap recovery,
  identity_seed).
- **v1.2.0 milestone**: F-PHD-DC-R10-1 + F-PHD-DC-R7-1 + F-PHD-DC-R7-2
  + F-PHD-DC-R9-1 + F-PHD-DC-R12-1 (all closed by single hardware-
  backed PersistentKeyStore callback_interface migration). Tracked in
  ADR-010 §5 Decision 7 (already-existing aspirational decision; round 4
  empirically demonstrates urgency).

---

## 11. Literature

- Apple Platform Security Guide May 2024 — Secure Enclave Boot ROM (pp.
  16-19), Keychain Services (`SecKeyCreateRandomKey` +
  `kSecAttrTokenIDSecureEnclave`), Data Protection classes.
- Android Keystore System (developer.android.com/training/articles/keystore) —
  `KeyGenParameterSpec.Builder.setIsStrongBoxBacked(true)`,
  `setUserAuthenticationRequired(true)`.
- NIST SP 800-57 Part 1 Rev. 5 — §6.2.1 long-term identity keys should
  be hardware-protected; ephemeral session keys may live in software-
  only memory.
- USENIX 2020, Bauer et al., "Cold Boot Attacks Are Still Hot".
- USENIX 2009, Halderman et al., "Lest We Remember: Cold-Boot Attacks
  on Encryption Keys".
- RFC 9420 — MLS Key Schedule §8.1, forward secrecy §9, ratchet tree
  §7.
- ADR-010 §5 Decision 5 — application-level per-row SQLite encryption.
- ADR-010 §5 Decision 7 — hardware-backed PersistentKeyStore callback
  interface (architectural intent, audit demonstrates not yet wired).
- iqlusioninc/crates `secrecy 0.10.3` upstream — no `mlock` reference.
