# R7 — Live Memory Extraction of identity_sk

> **CLOSURE BANNER (2026-05-20 reconciliation):** The CRITICAL findings F-PHD-DC-R7-1 / R7-2 / R7-3 documented в этом artifact are **CLOSED** as of:
> - Round 5 closure (`docs/audits/phd-b-device-capture-closure-2026-05-19.md`): R7-1, R7-2, R7-3 защищены через `HwBackedKeyStore` + `MlockedSecret<T>` + `IdentitySeed::Box<[u8; N]>` heap refactor;
> - Pass 5 remediation (`docs/audits/phd-b-pass5-remediation-2026-05-19.md`): F-IDENT-1 + F-IDENT-2 commit `46784d1a`; F-CLIENT-HW-1 commit `e7b034ff` closes M-FINAL-1.
>
> This file remains as an archive of the round-4 audit findings at the time of writing.

**Date:** 2026-05-19 (round-4 PhD-B device-capture audit)
**Status:** CRITICAL — entropy + master_key extractable from live process memory.

## Method

Binary: `crates/umbrella-client/examples/r7_identity_lldb_target.rs`
(builds under `r6-release` profile = `release + strip="none" + debug="full"`).

Two phases captured by `lldb -p <pid>` attach to a paused real process
running on macOS 15.7.4 arm64:

1. **LIVE_IDENTITY** phase: after `IdentitySeed::from_mnemonic` + `IdentityKey::
   derive(&seed, 0)` + `SqliteMetadataStore::open(_, master_key)`. All three
   secrets in scope: `seed`, `identity`, `store`.
2. **AFTER_DROP** phase: after `drop(seed); drop(identity); drop(store);`.
   Zeroize-on-drop expected to wipe `SecretBox` and `IdentitySeed` heap
   bytes.

Needles (32-byte patterns):

- 0xCD × 32 — BIP-39 entropy used to derive the identity_sk lineage.
- 0xDC × 32 — explicit master_key passed to `SqliteMetadataStore::open`,
  stored in `RowCipher.master_key: SecretBox<[u8; 32]>`.

Scanner: `docs/audits/device-capture-artifacts/r7_lldb_script.py`
(round-2 R6 methodology, single-pass per phase).

## Outcomes (numerical)

| Phase           | Entropy 0xCD hits | Master_key 0xDC hits | Bytes scanned |
|-----------------|-------------------|----------------------|---------------|
| LIVE_IDENTITY   | **2** (stack + heap pos_ctrl) | **1** (heap SecretBox) | 988 676 096 |
| AFTER_DROP      | **2** (stack + heap pos_ctrl unchanged) | **0** (SecretBox zeroized) | 983 990 272 |

### LIVE_IDENTITY hit detail (raw lldb output)

```
[R7 lldb] MATCH LIVE_IDENTITY/ENTROPY base=0x16b4d8000 abs=0x16bccdd30 name=
[R7 lldb]   prev16=c46aeb690cb837d988feac749b4b8d55  match+next=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c
[R7 lldb] MATCH LIVE_IDENTITY/ENTROPY base=0x600000000000 abs=0x600002b97600 name=
[R7 lldb]   prev16=0000000000000000d0928e0602000000  match+next=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000000000000000000000000000000
[R7 lldb] MATCH LIVE_IDENTITY/MASTER_KEY base=0x600000000000 abs=0x600002b90280 name=
[R7 lldb]   prev16=6f6e7300000000000000000000000000  match+next=dcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdca002f4c5c8300000fb07000000000000
[R7 lldb] SUMMARY LIVE_IDENTITY: regions=102 chunks=960 bytes=988676096 entropy_hits=2 master_key_hits=1
```

- `0x16b4d8000…16bccdd30` — stack region. The prev-16 prefix is non-zero,
  match is followed by 16 bytes of 0x5C — this is the BIP-39 entropy on the
  call-stack from `IdentitySeed::from_mnemonic` (parameter copy or local
  temporary). NOT covered by `IdentitySeed::Drop` because the `Zeroize`
  derive only wipes the field-resident `entropy: [u8; 32]`, not stack
  spill slots from preceding parameter shuffles.
- `0x600002b97600` — heap. This is the `pos_ctrl: Vec<u8>` positive control
  in main(). It stays alive in scope through both phases (legitimate).
- `0x600002b90280` — heap. Prev-16 contains b"ons\x00" pattern + zeros (heap
  block header). This is the `SecretBox<[u8; 32]>::new(Box::new(...))`
  allocation — exactly `RowCipher.master_key` storage.

### AFTER_DROP hit detail

```
[R7 lldb] MATCH AFTER_DROP/ENTROPY base=0x16b4d8000 abs=0x16bccdd30 name=
[R7 lldb] MATCH AFTER_DROP/ENTROPY base=0x600000000000 abs=0x600002b97600 name=
[R7 lldb] SUMMARY AFTER_DROP: regions=91 chunks=950 bytes=983990272 entropy_hits=2 master_key_hits=0
```

- Heap master_key (0x600002b90280) gone — **`SecretBox<[u8;32]>`
  zeroize-on-drop works correctly.**
- Stack entropy at `0x16bccdd30` **STILL PRESENT** — `IdentitySeed::Drop`
  did not cover this stack slot. This is the live finding: 32-byte BIP-39
  entropy survives `drop(seed)` on the stack.
- Heap pos_ctrl unchanged — legitimate (still in scope).

## Severity classification

**CRITICAL** per round-4 spec §«Severity classification rule»:

- Adversary with kernel debugger access to a captured running unlocked
  device extracts 32-byte BIP-39 entropy → reconstructs entire identity
  tree (BIP-32-Ed25519 → identity_sk + every device key + every
  HKDF-derived per-chat secret + `derive_storage_master_key` output).
- Adversary extracts 32-byte SQLite master_key directly from
  `SecretBox<[u8; 32]>` → decrypt every `messages`, `mls_groups`,
  `contacts`, `kt_log_mirror` row in the local DB.
- Extraction is **trivial** for a state-level adversary because:
  1. **No hardware backing** — `crates/umbrella-client/src/core.rs:227`
     comment "Block 7.2 held in memory ... Block 7.3 swaps it for non-
     exportable" is **not yet implemented**. Trait `PersistentKeyStore`
     has zero production impls; bridges in
     `examples/{ios-,android-}harness/.../KeyStoreBridge.{swift,kt}` are
     explicitly documented as "Block 7.10 wiring not done".
  2. **No mlock** — R11 grep finds 0 occurrences of mlock/VirtualLock
     across the entire workspace. `secrecy 0.10.3::SecretBox` does NOT
     lock pages — only `ZeroizeOnDrop` on heap.
  3. **No stack-spill coverage** — R7 demonstrates entropy on stack
     survives drop. Compiler stack frame spills are not in any zeroize
     scope.

## Remediation roadmap (spec-level, not implementation)

1. **F-PHD-DC-R7-1 — Hardware-back identity_sk**.
   Implement `crates/umbrella-ffi/src/keystore_callback.rs` uniffi
   `callback_interface` per ADR-010 §5 Decision 7. Move
   `ClientCore.identity: Arc<IdentityKey>` to
   `ClientCore.identity_handle: PersistentKeyStoreHandle` (Rust holds
   only an opaque handle; signing crosses FFI into Secure Enclave /
   StrongBox; private key never enters Rust heap). Acceptance: R7
   lldb scan after re-attempt finds 0 matches for entropy AND 0 matches
   for identity_sk material.

2. **F-PHD-DC-R7-2 — Hardware-back SQLite master_key**.
   `derive_storage_master_key` returns 32 bytes today; replace with
   "encrypt-this-buffer" callback whose key never leaves the TEE.
   Per-row AEAD becomes hardware-bound. Alternative (lower cost):
   master_key derived from passphrase + Argon2id (knowledge factor) +
   hardware-bound HKDF — cost: requires user passphrase entry per
   session.

3. **F-PHD-DC-R7-3 — Stack spill coverage**.
   The `entropy: *entropy` deref in `IdentitySeed::from_mnemonic`
   (`seed.rs:117`) copies bytes from `Zeroizing<[u8;32]>` into a stack
   slot during struct construction. LLVM stack-spill of these bytes is
   not in any zeroize scope. Remediation: refactor to write directly
   into a `Box<[u8; 32]>` (heap-resident from creation), OR add
   explicit `zeroize::zeroize_flat_type_on_drop_function()` against
   the stack window via a `compiler_fence + write_volatile` wrap.

4. **F-PHD-DC-R7-4 — mlock-or-VirtualLock for all SecretBox sites**.
   `secrecy::SecretBox` does not lock pages. Add a wrapper
   `MlockedSecret<T>` that calls `libc::mlock(ptr, size)` on construct
   and `libc::munlock` on drop. Trades RSS pressure for swap immunity.
   See R9 for context — current macOS swap is encrypted (per-boot SEP
   key) but VM compressor pages are not.

## Verification reproduce

```bash
cd /Users/daniel/Documents/Projects/Messenger/Umbrella\ Protocol
cargo build --profile r6-release --example r7_identity_lldb_target -p umbrella-client

# Terminal 1:
R7_PAUSE=1 ./target/r6-release/examples/r7_identity_lldb_target

# Terminal 2 (during the LIVE pause window):
cat > /tmp/r7_attach.txt <<EOF
process attach --pid <PID>
command script import /full/path/to/r7_lldb_script.py
r7_scan_live
detach
quit
EOF
lldb -b -s /tmp/r7_attach.txt
```
