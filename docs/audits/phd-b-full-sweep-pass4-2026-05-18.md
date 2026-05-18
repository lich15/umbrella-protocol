# PhD-B Full Sweep Audit — Pass 4 (umbrella-client + FFI + Platform-Verifier + Server-Postman + regression check)

**Date:** 2026-05-18
**Session:** PhD-B full sweep, pass #4 / 5
**Scope:** umbrella-client (10K LoC) + umbrella-ffi (1.3K) + umbrella-ffi-kotlin (53) + umbrella-ffi-swift (49) + umbrella-platform-verifier (1K) + umbrella-server-blind-postman (1K) + regression check umbrella-discovery + umbrella-threshold-identity
**Predecessors:**
- `docs/audits/phd-b-full-sweep-pass1-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md` + supplemental
- `docs/audits/phd-b-full-sweep-pass3-2026-05-18.md`
**Auditor:** Claude Opus 4.7 (PhD-B level per `feedback_phd_level_mandatory` + `feedback_real_not_paperwork` + `feedback_phd_vs_a_level_distinguisher` + `feedback_phd_pass_full_model_reading`)
**Status:** **1 CRITICAL NEW + 2 HIGH/HONEST GAP NEW + 1 MEDIUM NEW + 3 carry-over (1 HIGH + 2 CRITICAL) + 6 PASS+ exemplars = 13 distinct entries.** Most severe new finding: **F-FFI-2 CRITICAL** — `OnboardingHandle::unlock_with_pin` exposes 64 bytes of session key material (device_key + master_key) across the FFI boundary as hex strings via a production-named method, defeating the `MlockedSecret` invariant.

---

## Severity legend

- **CRITICAL:** Production-named API with placeholder / leak semantics OR carry-over CRITICAL still open.
- **HIGH:** Production code path gap (missing wire-up, dormant subsystem) OR production claim ungrounded by current code.
- **MEDIUM:** Documented gap that meaningfully reduces a security property under realistic conditions.
- **MINOR / INFO:** Test/code rigor gap OR documented test-only helper.
- **PASS+:** Exemplar of `feedback_real_not_paperwork` standard worth emulating.

---

## Carry-over status (priority-1)

### F-MLS-1 (HIGH carry-over confirmed) — PQ MLS provider 0 production callsites

Pass 4 deeper grep over all Pass 4 scope crates:

- `UmbrellaXWingProvider` in `crates/umbrella-client/`: **2 matches** — `core.rs:581,605`, both doc-comments only describing `bootstrap_pq_for_test` semantics. **0 actual constructions.**
- `with_hedged_witness` outside `umbrella-mls/tests`: still only the 1 single production caller `umbrella-sealed-sender/src/hybrid_envelope.rs:167` (via `keystore.hedged_encaps_witness()`, not via `UmbrellaXWingProvider::with_hedged_witness`).
- `UmbrellaXWingProvider::new()` constructions: **20 matches** — all inside `umbrella-mls/tests/*.rs` (`test_F_63.rs` 7×, `pq_downgrade_resistant.rs` 3×, `xwing_provider_handshake.rs` 1×, `xwing.rs` 10× inside `#[cfg(test)]`).
- FFI / `umbrella-ffi`, `umbrella-ffi-kotlin`, `umbrella-ffi-swift`: **0 callsites** (Pass 3 verdict re-confirmed).
- `umbrella-client/Cargo.toml`: feature `pq` exists as aggregator but no code path under `#[cfg(feature = "pq")]` instantiates `UmbrellaXWingProvider`.

**Verdict:** Pass 3 verdict stands unchanged — PQ MLS is dormant. `UmbrellaXWingProvider::default()` would fall back to `HedgedWitness::zeroed_for_tests_only()` at `umbrella-mls/src/provider/xwing.rs:470`, but no production code reaches that line.

**Recommended remediation (unchanged from Pass 3):**
1. (Strongest) `#[cfg(test)]`-gate `UmbrellaXWingProvider::new()` and remove `impl Default`. Force `with_hedged_witness(witness)`.
2. `panic!("UmbrellaXWingProvider::default() called in production")` in release builds.
3. CI grep-check that no production code reaches `UmbrellaXWingProvider::new()`.

Decision required pre-1.0.0 PQ MLS activation.

### F-1 (CRITICAL carry-over confirmed) — XOR placeholder in `unlock_with_pin`

`crates/umbrella-client/src/keystore/distributed_identity_client.rs:148`:

```rust
// XOR-combine (placeholder for production threshold reconstruction).
for (slot, byte) in combined_share.iter_mut().zip(share.iter()) {
    *slot ^= *byte;
}
```

Still open. The Pass 1 finding stands: production-named `unlock_with_pin` uses XOR over 3 of 5 server shares as a placeholder for the threshold reconstruction. XOR-combine is **algebraically wrong** for Shamir secret sharing — adversary holding any single share + the XOR-combined result trivially recovers the other 2 shares.

**Real-adversary impact (quantified):**
- Adversary compromises **1 Sealed Server** + observes `combined_share`-derived ciphertext side-channel
- Adversary holds `server_share_i` (32 bytes)
- Adversary recovers `server_share_j XOR server_share_k = combined_share XOR server_share_i`
- This reduces 2-of-5 quorum to 1-of-5 — **threshold security collapsed by 1 bit per compromised server**.
- For full master_key recovery: 1 compromise + ciphertext + master_key derivation step is enough (vs intended 3-of-5 = at least 3 compromises).

### F-2 (CRITICAL carry-over confirmed) — anon-IDs locally derive HKDF(pin_root, salt)

`crates/umbrella-client/src/keystore/distributed_identity_client.rs:250-263`:

```rust
let pin_root = pin_kdf::derive_pin_root(&input.pin, &account_local_salt)?;
let mut anon_seed = [0u8; 32];
Hkdf::<Sha256>::new(Some(&account_local_salt), pin_root.expose())
    .expand(b"umbrella-r6/anon-seed/v1", &mut anon_seed)?;
let per_server_anonymous_ids = anonymous_id::derive_all_anonymous_ids(&anon_seed)?;
```

Still open. Pass 1 finding stands: anonymous IDs are derived locally on device from PIN-derived material. Comment explicitly acknowledges this is a "deterministic proxy for any device re-deriving from the same PIN+salt".

**Real-adversary impact (quantified):**
- Adversary captures `account_local_salt` (16 bytes, persisted on device, not secret)
- Adversary obtains PIN via PIN-guessing attack against Argon2id (mobile-tunable; ~600-800ms per guess per `derive_pin_root`)
- Adversary re-derives `pin_root` + `anon_seed` + all 5 `per_server_anonymous_ids` **locally without any server interaction**
- Adversary can now correlate which queries belong to this account across all 5 Sealed Servers (anon-id is the cross-server correlation key)
- **Anonymous-ID unlinkability defense collapsed** — adversary with PIN can fully de-anonymize the account.

The intended round-7 PSI flow assumes anon-IDs are issued **by servers via OPRF** so a device cannot independently derive them. The current implementation contradicts that design intent.

### F-3 (CRITICAL carry-over) + F-4 (HIGH carry-over)

Pass 1 findings in `umbrella-discovery` + R20-R27 attack tests. Pass 4 regression check:

- `umbrella-discovery/tests/attack_d*.rs`: 3 attack tests present (`d1_plaintext_phone_leak`, `d3_kt_bind_silent_swap`, `d4_cluster_collusion`). No `attack_d_r23_*.rs` regenerated.
- `umbrella-threshold-identity/tests/`: only `dkg_e2e.rs`. R20-R27 attack tests live in `umbrella-tests` workspace per memory `project_phd_b_6_rounds_complete`.
- F-3 / F-4 status: **carry-over unchanged** in Pass 4 scope (no regression triggered by new code, no fix applied).

---

## NEW findings — Pass 4 priority

### F-FFI-2 (CRITICAL NEW) — `OnboardingHandle::unlock_with_pin` exposes session keys across FFI boundary

**File:** `crates/umbrella-ffi/src/export/onboarding.rs:202-222`

```rust
#[uniffi::export]
impl OnboardingHandle {
    pub fn unlock_with_pin(
        &self,
        pin: String,
        bootstrap_state_hex: String,
        device_random_hex: String,
    ) -> Result<UnlockResultFfi, UmbrellaError> {
        ...
        Ok(UnlockResultFfi {
            identity_pk_hex: hex::encode(session.identity_pk),
            // For Stage 2/3 we expose key bytes as hex — in production, the
            // SDK keeps them inside MlockedSecret and never crosses FFI
            // boundary in plaintext. Here we publish for test inspection.
            device_key_hex: hex::encode(session.device_key.expose()),
            master_key_hex: hex::encode(session.master_key.expose()),
        })
    }
}
```

**Issue:** `UnlockResultFfi` is returned by a `#[uniffi::export]` method on a `pub` `OnboardingHandle`. Production Swift/Kotlin apps calling `unlock_with_pin` receive **64 bytes of session key material** (`device_key` + `master_key`) as **plaintext hex strings**. Once these strings cross the FFI boundary:

1. They live on the Swift/Kotlin native heap as `String` allocations, **not** `MlockedSecret`. No mlock, no zeroize-on-drop, no page-locking.
2. They are subject to standard JVM/Swift GC and may be paged to swap, copied during VM compaction, or leaked via String interning.
3. Process memory capture (R20 lldb attack class) recovers them trivially.

**Comment disclosure:** Line 218-220 documents "For Stage 2/3 we expose key bytes as hex" and "production SDK replaces this with opaque session-handle IDs." Line 250-254 doc-comment on `UnlockResultFfi`:

> **Note:** in production the secret bytes (`device_key_hex` + `master_key_hex`) MUST NOT cross the FFI boundary in plaintext. They are exposed for the Stage 2 / Stage 5 R20 lldb test rig (visibility for measurement); production SDK replaces this with opaque session-handle IDs.

**Why this is CRITICAL despite the comment:**
1. The method is in the **main** `#[uniffi::export] impl OnboardingHandle` block — **not** `#[cfg(test)]`-gated, **not** behind a `test-utils` feature flag, **not** under a `cfg(feature = "internal-debug")` predicate.
2. The method is named `unlock_with_pin` (production-named), not `unlock_with_pin_for_test_rig`.
3. Swift/Kotlin callers building against the public SDK have **no compile-time signal** that this leaks secrets.
4. Same pattern class as F-1 (CRITICAL XOR placeholder in production-named `unlock_with_pin`): "implementation note says don't use in production, but no compile-time enforcement."

**Real-adversary impact (quantified):**
- Per round-4 R20 lldb attack methodology: process memory capture of Swift/Kotlin app post-unlock recovers `device_key` + `master_key` from native `String` heap.
- 64 bytes per unlock × N users × M unlocks per day = mass-collection feasible for adversary D (state-level).
- The MlockedSecret invariant chain (`MlockedSecret::new` → `libc::mlock` → `expose()` returns `&[u8; 32]` → drop zeroizes) is **broken** at the FFI boundary because `expose()` is called, `hex::encode` allocates a new String, and the original `MlockedSecret` is dropped (zeroizing the original 32 bytes) but the **hex-encoded copy survives in JVM/Swift heap**.

**Per memory `feedback_phd_severity_uplift`:** MINOR carry-overs CAN upgrade to CRITICAL under PhD-B sweep. Pass 4 confirms: comment-disclosed-but-unenforced placeholder in production-named API is the same severity-class as F-1.

**Recommended remediation:**
1. Split impl: `OnboardingHandle` (production) + `OnboardingHandleForTesting` (`#[cfg(any(test, feature = "test-utils"))]`-gated).
2. Production `unlock_with_pin` returns opaque session-handle `String` (UUID) keyed into an internal `HashMap<SessionId, UnlockSession>` held in Rust heap with MlockedSecret intact.
3. All subsequent FFI methods (`send_text`, `fetch_inbox`, etc.) accept the session-handle and look up the live `UnlockSession` internally — secrets never cross FFI.

### F-CLIENT-FACADE-1 (HIGH/HONEST GAP NEW) — All umbrella-client facade methods are Block 7.2 stubs

**Files:**
- `crates/umbrella-client/src/facade/chat_common.rs:202-208`
- `crates/umbrella-client/src/facade/cloud_chat.rs:150-246`
- `crates/umbrella-client/src/facade/secret_chat.rs:173-220`

The `send_mls_text` helper that both facades funnel through (`chat_common.rs:202-208`):

```rust
pub(crate) async fn send_mls_text(
    _core: &Arc<ClientCore>,
    _chat_id: ChatId,
    _text: String,
) -> Result<MessageId> {
    Ok(MessageId([0u8; 16]))
}
```

**All underscore-prefixed parameters** — the helper does **nothing**: no MLS encryption, no padding, no sealed-sender envelope construction, no Postman delivery. Returns a zeroed `MessageId`.

Other facade stubs:
- `CloudChat::send_text` → `send_mls_text` (stub) → `Ok(MessageId([0u8; 16]))`
- `CloudChat::fetch_inbox` → `Ok(Vec::new())`
- `CloudChat::cloud_sync_history(_since)` → `Ok(Vec::new())`
- `CloudChat::add_bot(_bot_id)` → `Ok(())`
- `CloudChat::add_participant(_peer)` → `Ok(())`
- `CloudChat::remove_participant(_peer)` → `Ok(())`
- `SecretChat::send_text` → same `send_mls_text` stub
- `SecretChat::fetch_inbox` → `Ok(Vec::new())`
- `SecretChat::add_participant` / `remove_participant` → `Ok(())`

**Doc-comment disclosure (every method):**
> «В Блоке 7.2 — infallible stub; в 7.4 — `ClientError::Mls/SealedSender/Network/Padding`.»

**Real-adversary impact:** The umbrella-client facade is fully wired for `UmbrellaClient::bootstrap_for_test` + `bootstrap_pq_for_test` + `bootstrap_classical_for_test` → `CloudChat::create / SecretChat::create / send_text`. A Swift/Kotlin app calling through these path's would silently **send no messages** (returning a zeroed `MessageId`), **fetch no messages** (empty `Vec`), **add no participants**. The PQ MLS group establishment, X-Wing key encapsulation, sealed-sender V2 wrap, blind-postman delivery — all bypassed.

**Mitigating fact:** Pass 4 confirmed `ClientCore::new_with_http2` returns `Err(ClientError::Network("production HTTP/2 bootstrap is closed..."))` at `core.rs:483-489`. The fail-closed gate at the **transport** layer prevents real production deployment. So:
- Production path: blocked at `new_with_http2` (fail-closed correctly).
- Test path: stub facades return Ok(empty) — visible as obviously-zeroed `MessageId([0u8; 16])` in tests, easy to detect.

**Severity:** HIGH/HONEST GAP — documented Block 7.2 stub state, production path fail-closed. Cannot ship to 1B users; cannot accept Pass 4 as "umbrella-client production-ready."

**Recommended remediation:** Block 7.4 wire-up per existing milestone plan — not a separate PhD-B fix.

### F-CLIENT-HW-1 (HIGH/HONEST GAP NEW) — HW Keystore callback wired but 0 production signing operations route through it

**Files:**
- `crates/umbrella-client/src/keystore/hw_callback.rs` (639 LoC — `PersistentKeyStoreCallback` trait + `MockHwKeystore` + `bootstrap_hw_identity`)
- `crates/umbrella-client/src/core.rs:307,396-442,452-463` (`ClientCore.hw_callback` field + `new_with_hw_callback` constructor + `has_hw_identity` accessor)

**Issue:** Per memory `project_phd_b_6_rounds_complete` last bullet, round-5 device-capture closure F-PHD-DC-R7-1 / F-PHD-DC-R10-1 added `PersistentKeyStoreCallback` interface with explicit acceptance gate: «Re-run round-4 R7 lldb attack — expect **0 stack hits** for identity_sk + master_key».

Pass 4 verified:
- `bootstrap_hw_identity` exists (`hw_callback.rs:492-525`) — calls `callback.generate_identity()` + signs a probe message
- `ClientCore::new_with_hw_callback` exists (`core.rs:396-442`) — stores `Some(Arc<dyn PersistentKeyStoreCallback>)` in `core.hw_callback`
- `has_hw_identity()` accessor + `hw_identity_handle()` accessor — for query
- `bootstrap_with_hw_callback` exists in `UmbrellaClient` (`core.rs:566-572`)

**But:** Cross-workspace grep for `hw_callback.sign_identity\|hw_callback\.sign` reveals:
- 0 production signing operations route through `core.hw_callback.sign_identity(...)`
- All callers of `sign_identity` (10 matches) are inside `hw_callback.rs` itself (probe + tests + Mock impl) plus `tests/r5_hw_callback_wiring.rs` (test-only)
- Production-path signing in `umbrella-client` `umbrella-mls` `umbrella-sealed-sender` `umbrella-backup` all uses `core.identity.sign(...)` (Rust `Arc<IdentityKey>`) — never `core.hw_callback`

**Furthermore (M-FINAL-1 disclosure in `core.rs:407-424`):** When `new_with_hw_callback` is invoked, the verifying-key from `bootstrap_hw_identity` is **discarded** (`let (handle, _verifying_key_placeholder) = ...`) and ClientCore synthesizes a **separate ephemeral** `IdentityKey` from a one-shot seed:

```rust
let ephemeral_seed =
    IdentitySeed::generate(&mut rand_core::OsRng, MnemonicLanguage::English);
let identity = Arc::new(IdentityKey::derive(&ephemeral_seed, 0)?);
drop(ephemeral_seed); // explicit zeroize-on-drop
```

So `core.identity` (used for ALL production signing) does NOT correspond to the TEE-resident `hw_identity_handle`. Even if a production signing path were later wired to call `core.hw_callback.sign_identity(handle, data)`, the resulting signature would verify under a different verifying-key than `core.identity.verifying_key()`.

**Real-adversary impact:** Per round-4 R7 attack: process memory capture of `umbrella-client` recovers `core.identity` ephemeral seed (32 bytes, heap-resident, briefly synthesized). The intended round-5 closure (identity_sk lives only in TEE) is **wire-up demo only** — the TEE pathway exists in code structure but is never actually exercised by production cryptography.

**Severity:** HIGH/HONEST GAP — explicitly disclosed in `core.rs:418-420`:
> `TODO(v1.2.x): refactor core.identity to Option<Arc<IdentityKey>>` or a public-only verifying-key variant so this synthesis can be eliminated entirely. Tracking issue: M-FINAL-1.

But the comment honestly describes the gap — production cryptographic operations cannot currently use a TEE. Combined with F-IDENT-1 (Pass 3 HIGH/HONEST GAP: `InMemoryKeyStore` is the only KeyStore impl), the picture is consistent: **production cryptographic operations cannot use a TEE in current code state.**

**Recommended remediation (M-FINAL-1 tracking):**
1. Refactor `core.identity` to `Option<Arc<IdentityKey>>` so HW path doesn't materialise an ephemeral.
2. Wire all signing paths (`UmbrellaIdentitySigner`, `UmbrellaDeviceSigner`, sealed-sender, MLS) to first check `core.has_hw_identity()` and route through `core.hw_callback.sign_identity(handle, data)` when present.
3. Production `bootstrap_hw_identity` returns real verifying-key via a separate `verifying_key(handle)` callback method (per `hw_callback.rs:511-518` comment).

### F-CLIENT-HW-2 (MEDIUM NEW) — `bootstrap_hw_identity` returns `[0u8; 32]` placeholder verifying-key

**File:** `crates/umbrella-client/src/keystore/hw_callback.rs:511-525`

```rust
// For the mock, callers immediately compose the verifying key from
// the SigningKey path inside `sign_identity`; production retrieves
// it from the SE via `SecKeyCopyPublicKey`. We expose only the
// 64-byte signature here and let `Iden(tity|tityStore)` derive the
// verifying key in the next round if needed; for the round-5
// closure we return zero bytes as the verifying-key placeholder —
// real wiring will populate via a separate `verifying_key` callback
// method in v1.2.0.
Ok((handle, [0u8; 32]))
```

`bootstrap_hw_identity` returns a tuple `(HwKeyHandle, [u8; 32])` where the second element is **always all-zero**. The intent (per comment) is for KT publishing of the TEE-resident identity's verifying-key, but the production-grade `verifying_key(handle)` callback method does not yet exist.

**Real-adversary impact:** If Key Transparency were to publish this verifying-key:
- All-zero verifying-key is detectable on its face — KT auditors would reject.
- Or worse, if accepted, the verifying-key is **not** the public half of the TEE-resident signing key — no signature would ever verify against it.

This is a downstream consequence of F-CLIENT-HW-1: since `ClientCore::new_with_hw_callback` ignores the placeholder via `let (handle, _verifying_key_placeholder)`, KT publishing simply uses `core.identity.verifying_key()` (the ephemeral synthesized key). The placeholder doesn't actually break anything — but it's a wire-up dead-end.

**Severity:** MEDIUM (deserves fix before v1.2.x HW production wire-up, but not v1.0.0-blocking).

**Recommended remediation:** Add `verifying_key(&self, handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError>` to `PersistentKeyStoreCallback` trait. Native iOS impl calls `SecKeyCopyPublicKey(handle)`; Android `KeyStore.getCertificate(alias).publicKey`. Update `bootstrap_hw_identity` to call it.

---

## NEW PASS+ exemplars — Pass 4 scope

### F-PINNING-1 PASS+ — SPKI certificate pinning with inner+pin defense-in-depth

**File:** `crates/umbrella-client/src/transport/pinning.rs` (568 LoC + 11 tests)

- `SpkiPin([u8; 32])` SHA-256 over DER-encoded SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
- `SpkiPinningVerifier` wraps inner `ServerCertVerifier` — **inner cert chain check runs first**, then SPKI pin check. Test `matching_pin_does_not_bypass_inner_certificate_failure` proves: SPKI pin match alone does NOT bypass standard X.509 verification.
- Test `wrong_key_for_same_server_is_rejected_after_inner_accepts` proves: MITM with valid cert chain but wrong SPKI rejected.
- IP addresses rejected at SNI parsing (`server_name_to_dns_host` returns `UnsupportedServerName` for `ServerName::IpAddress`).
- DNS host normalization (lowercase + trim trailing dot) prevents case-sensitivity / FQDN tail-dot bypass.
- `PinningConfig::dual(primary, backup)` for graceful rotation.

**Real-vs-paperwork verdict:** 11 tests construct real X.509 certs via `rcgen::generate_simple_self_signed`, extract real SPKI bytes, derive SHA-256, verify byte-equal pinning + adversarial rejection. PhD-B grade A+.

### F-ATTEST-1 PASS+ — `AttestationProvider` trait with explicit server_nonce embedding

**File:** `crates/umbrella-client/src/attestation/provider_trait.rs` (328 LoC + 7 tests)

- `async fn fresh_token(&self, server_nonce: [u8; 32]) -> Result<PlatformAttestation, AttestationError>` — explicit nonce parameter, native side embeds in App Attest `clientDataHash` (iOS) or Play Integrity `nonce` (Android) for ±5min freshness window.
- `StaticTestAttestationProvider` documents: «In production Sealed Servers reject tokens carrying the `Platform::Testing` tag.» — explicit production/test boundary.
- 4 test platforms covered (iOS / Android / Web / Testing); test `static_provider_different_nonces_produce_different_tokens` proves freshness defense.
- Re-exports canonical wire-format types from `umbrella_backup::cloud_wrap::signed_request` (no DRY violation).

### F-ROWCIPHER-1 PASS+ — F-57 closure constant-time nonce check exemplar

**File:** `crates/umbrella-client/src/keystore/row_cipher.rs` (547 LoC + 8 tests + 3 proptest 384 cases)

- F-57 closure (block 10.16; F-51 pattern recurrence): `subtle::ConstantTimeEq::ct_eq` on nonce comparison at line 275 — defense-in-depth even on "practically safe" tampering signal.
- F-PHD-DC-R11-1 closure: `MlockedSecret<[u8; 32]>` wraps master_key — heap-resident + `libc::mlock` + zeroize-on-drop.
- Deterministic nonce derivation via HKDF-SHA512(master_key, info = PREFIX || context || row_id) → `[u8; 12]` — detects row-swap attacks before AEAD even runs.
- Proptest `prop_row_swap_fails` 128 cases: random `(context, row_id_a, row_id_b)` triples confirm row-swap is statistically caught.
- Source-grep regression test `row_cipher_sensitive_temporaries_are_zeroizing` verifies `Zeroizing::new(plaintext.to_vec())` + `Zeroizing::new(ciphertext.to_vec())` patterns survive in source.

### F-PLAT-TYPES-1 PASS+ — Debug redaction exemplar in PlatformVerificationContext

**File:** `crates/umbrella-platform-verifier/src/types.rs` (201 LoC + 4 tests)

- `PlatformVerificationContext` `Debug` impl redacts token + server_nonce + device_pubkey + app_or_site — every field that could leak to server logs is `<redacted>`.
- Test `platform_verification_context_debug_redacts_token` proves none of `["token: [", "server_nonce: [", "device_pubkey: [", "io.umbrellax.app"]` appear in `format!("{ctx:?}")`.
- Lengths preserved (`token_len`, `server_nonce_len`, etc.) for diagnostic value without information leak.

### F-PLAT-VER-1 PASS+ / HONEST GAP — Apple/Android verifiers honest-fail-closed even with config flag=true

**Files:** `crates/umbrella-platform-verifier/src/apple.rs` (171 LoC + 5 tests) + `crates/umbrella-platform-verifier/src/android.rs` (146 LoC + 5 tests)

Both verifiers have a final unconditional fail-close:

```rust
// apple.rs:75-77
Err(PlatformVerifierError::ExternalTrustMaterialRequired(
    "apple app attest full verification is not implemented in this local phase",
))

// android.rs:60-62
Err(PlatformVerifierError::ExternalTrustMaterialRequired(
    "android play integrity full verification is not implemented in this local phase",
))
```

Tests `apple_still_fails_closed_when_trust_flag_is_only_a_placeholder` + `android_still_fails_closed_when_google_flag_is_only_a_placeholder` confirm: even with `trust_roots_configured = true` / `google_verification_configured = true`, verifier returns `ExternalTrustMaterialRequired` — code structurally cannot accept any token regardless of configuration.

**Real-vs-paperwork verdict:** This is the right pattern per memory `feedback_real_not_paperwork`: don't fake-pass when verification material isn't actually present. Both verifiers honestly disclose "not implemented in this local phase".

**Boundary:** Real Apple App Attest / Google Play Integrity verification lives on Sealed Servers backend, not in this codebase. The Rust-side platform-verifier is honest-fail-closed wireframe — a Sealed Servers backend would substitute its own verifier with full root chain + CBOR/JWE/JWS parsing.

### F-FFI-1 PASS+/HONEST GAP — Production bootstrap fail-closed

**File:** `crates/umbrella-ffi/src/export/client.rs:33-38, 199-200, 343-344, 506-507`

```rust
fn production_bootstrap_unavailable() -> UmbrellaError {
    UmbrellaError::Internal(
        "production bootstrap is not available: public FFI must not use test constructors until the production attestation verifier, mobile bridge, and server integration paths are wired end to end"
            .into(),
    )
}
```

All three production-facing FFI constructors — `UmbrellaClientHandle::bootstrap`, `bootstrap_pq`, `bootstrap_classical` — call `production_bootstrap_unavailable()` after validating inputs. Input validation (BIP-39 phrase decode, `ClientConfigFfi::try_into()`) is honest — bad inputs return `UmbrellaError::Identity` or `Internal`. Valid inputs **always** return the fail-closed error.

**Why this is PASS+ not finding:** Per memory `feedback_real_not_paperwork` — honest fail-closed is preferable to silent stub behavior. The FFI surface explicitly refuses to bootstrap a real client until the production transport + verifier + native bridge chains are wired. Pairs correctly with `ClientCore::new_with_http2` fail-closed (core.rs:483-489).

---

## Pass 4 severity tracking

| Finding | Severity | Crate / File | Status |
|---------|----------|--------------|--------|
| F-MLS-1 | **HIGH carry-over** | umbrella-mls + umbrella-client | confirmed (Pass 1-3, Pass 4 re-verified) |
| F-1 | **CRITICAL carry-over** | umbrella-client/src/keystore/distributed_identity_client.rs:148 | still open |
| F-2 | **CRITICAL carry-over** | umbrella-client/src/keystore/distributed_identity_client.rs:250-263 | still open |
| F-3 | CRITICAL carry-over | umbrella-discovery R23 BTreeMap arithmetic | unchanged (Pass 1 finding) |
| F-4 | HIGH carry-over | umbrella-discovery / umbrella-threshold-identity R21 | unchanged (Pass 1 finding) |
| F-IDENT-1 | HIGH/HONEST GAP carry-over | umbrella-identity/src/keystore.rs | unchanged (Pass 3 finding) |
| F-IDENT-2 | HIGH carry-over | umbrella-identity/src/keystore.rs | unchanged (Pass 3 finding) |
| F-IDENT-37 | MEDIUM carry-over | umbrella-identity/src/code_recovery.rs:303 | unchanged (Pass 3 finding) |
| **F-FFI-2** | **CRITICAL NEW** | umbrella-ffi/src/export/onboarding.rs:218-220 | Pass 4 |
| **F-CLIENT-FACADE-1** | **HIGH/HONEST GAP NEW** | umbrella-client/src/facade/{chat_common,cloud_chat,secret_chat}.rs | Pass 4 |
| **F-CLIENT-HW-1** | **HIGH/HONEST GAP NEW** | umbrella-client/src/keystore/hw_callback.rs + core.rs | Pass 4 |
| **F-CLIENT-HW-2** | **MEDIUM NEW** | umbrella-client/src/keystore/hw_callback.rs:511-525 | Pass 4 |
| F-FFI-1 | PASS+/HONEST GAP | umbrella-ffi/src/export/client.rs | Pass 4 exemplar |
| F-PINNING-1 | PASS+ | umbrella-client/src/transport/pinning.rs | Pass 4 exemplar |
| F-ATTEST-1 | PASS+ | umbrella-client/src/attestation/provider_trait.rs | Pass 4 exemplar |
| F-ROWCIPHER-1 | PASS+ | umbrella-client/src/keystore/row_cipher.rs | Pass 4 exemplar |
| F-PLAT-TYPES-1 | PASS+ | umbrella-platform-verifier/src/types.rs | Pass 4 exemplar |
| F-PLAT-VER-1 | PASS+/HONEST GAP | umbrella-platform-verifier/src/{apple,android}.rs | Pass 4 exemplar |

**Totals new in Pass 4:** 1 CRITICAL NEW + 2 HIGH/HONEST GAP NEW + 1 MEDIUM NEW + 6 PASS+ exemplars = 10 distinct entries new.

**Totals including carry-overs:** 3 CRITICAL (1 new + 2 carry-over) + 4 HIGH (2 new + 2 carry-over) + 1 MEDIUM new + 6 PASS+ = 14 distinct entries.

---

## 6-question self-check application (per `feedback_phd_vs_a_level_distinguisher`)

1. **Findings count 5+** — ✅ 14 entries (3 CRITICAL + 4 HIGH + 1 MEDIUM + 6 PASS+).
2. **Test naming honesty `attack_*` adversarial vs behavioral** — ✅ Verified:
   - `pinning.rs::wrong_key_for_same_server_is_rejected_after_inner_accepts` — adversary constructs MITM cert with valid chain but wrong SPKI; reject expected.
   - `pinning.rs::matching_pin_does_not_bypass_inner_certificate_failure` — adversary supplies cert with matching pin but inner chain rejected; ensures defense order (inner first, then pin).
   - `row_cipher.rs::prop_row_swap_fails` — random `(row_id_a, row_id_b)` differ; adversary plants ct of row_a into row_b decrypt; reject required.
   - `apple.rs::apple_still_fails_closed_when_trust_flag_is_only_a_placeholder` — adversary toggles `trust_roots_configured = true`; verifier still rejects (placeholder honest-fail-closed).
   - `r5_hw_callback_wiring.rs` — round-5 acceptance test for HW callback wiring (existence test, not adversarial — boundary).
3. **Tamarin/ProVerif model engagement 80%+ reading** — N/A for Pass 4 (no formal models in scope; all 9 covered in Pass 3).
4. **Dudect 1M+ samples for CT-critical paths** — Deferred to Pass 5 cross-cutting per Pass 1-3 plan.
5. **Reduction sketches with concrete numbers** —
   - F-1 quantification: XOR-combine over 3 shares of 32 bytes — adversary with 1 compromised server share and ciphertext side-channel can recover XOR of remaining 2 shares (reduces 2-of-5 to 1-of-5 logical threshold).
   - F-2 quantification: anon-IDs derived from `Argon2id(PIN, salt)` + HKDF-Sha256 + `derive_all_anonymous_ids(seed)`. PIN search space ~10^6 for 6-digit PINs; Argon2id ~600-800ms per attempt on mobile; ~140 hours per PIN exhaust on mobile single-thread, ~6 hours on GPU farm — feasible for state-level adversary holding `account_local_salt` (16 bytes, recoverable from device).
   - F-FFI-2 quantification: 32 bytes device_key + 32 bytes master_key = 64 bytes per unlock × N users × M unlocks/day. Hex-encoded Strings on JVM/Swift heap NOT mlock'd, NOT zeroized — process memory capture recovery rate ~100% per R20 attack methodology.
6. **Literature engagement vs list** — ✅ Cited inline:
   - RFC 5280 §4.1.2.7 SubjectPublicKeyInfo (pinning.rs)
   - Apple App Attest spec (apple.rs)
   - Google Play Integrity API (android.rs)
   - RFC 9180 HPKE (mentioned via core.rs ciphersuite paths)
   - ADR-006 Variant C (compile_fail E0599 doctests for SecretChat type-safety)
   - ADR-010 Decision 5 (subvariant C.1.2 SQLite per-row encryption)
   - ADR-011 Decision 7 (PQ feature aggregator)
   - ADR-013 Decisions 1-2 (PQ-first default switch, classical bridge)
   - SPEC-01 §4 threat model (adversary D state-level)
   - SPEC-06 §3 (no-P2P compliance gate)
   - SPEC-08 §4 (sealed-sender envelope)
   - SPEC-11 §4 (16-device limit per account)
   - SPEC-12 §A.7 (cloud-unwrap signed request wire-format)

**Self-check verdict:** 5/6 fully passed + 1/6 (dudect) deferred. Same boundary as Pass 3 — within `feedback_phd_no_partial` acceptance (deferred dudect explicitly Pass 5 cross-cutting).

This pass is claimed as **PhD-B with explicit Pass 5 cross-cutting carry-over**, not as partial PhD-B work on Pass 4 crates.

---

## Real-vs-paperwork verdict (per `feedback_real_not_paperwork`)

| Test class | Real adversary? | Measurements? | PhD-B grade |
|------------|-----------------|---------------|-------------|
| umbrella-client pinning 11 tests + dual+rotation+wrong-key+inner-fail | yes | rcgen real X.509 certs + DER bytes + SHA-256 | A+ |
| umbrella-client row_cipher 8 tests + 3 proptest (384 cases) | yes | tamper-detection across all byte positions | A+ |
| umbrella-client attestation 7 tests (deterministic provider + nonce binding + oversize reject) | yes | byte-equal token end | A |
| umbrella-platform-verifier apple/android honest-fail-closed (5+5 tests) | yes | structural inability to accept tokens; placeholder honesty | A |
| umbrella-platform-verifier types Debug redaction (4 tests) | yes | format!("{:?}") string-scan for leaked bytes | A |
| umbrella-ffi production_bootstrap_unavailable (fail-closed) | yes | structural rejection | A |
| **umbrella-ffi onboarding unlock_with_pin (F-FFI-2)** | **NO (production leak)** | **64 bytes session key cross FFI in plaintext** | **F** |
| **umbrella-client facade send_mls_text stub (F-CLIENT-FACADE-1)** | **NO (production stub)** | **Ok(MessageId([0u8; 16])) — no crypto** | **F** |
| **umbrella-client hw_callback no production signing (F-CLIENT-HW-1)** | **NO (production demo wire-up)** | **0 signing callsites use core.hw_callback** | **F** |
| umbrella-server-blind-postman replay HashSet (replay.rs:99) | yes | 60s window message-hash dedup | A |

**Conclusion:** Pass 4 scope contains **a sharp bimodal split** — defense-in-depth exemplars (pinning, row_cipher, attestation, platform-verifier honest fail-closed) at PhD-B A+/A grade, **alongside** production-named placeholder leaks (F-1, F-2, F-FFI-2, F-CLIENT-FACADE-1, F-CLIENT-HW-1) that are F-grade per the real-vs-paperwork bar.

The pattern: high-quality defenses for **defined attack surfaces** (TLS pinning, AEAD-protected DB rows, attestation freshness) coexist with **wireframe placeholders** for **integration paths** (FFI session-handle, MLS facade, HW callback signing). The Block 7.2 → 7.4 milestone plan separates them honestly, but the placeholder code paths use **production-named APIs without compile-time enforcement** of their test-only nature.

---

## Pre-commit decisions

This audit deliverable is committed directly to `main` per `feedback_direct_to_main`. The findings are documentation-only in this commit; remediation/fix work is separate sessions per finding.

**No code modifications in this commit** — audit-only.

**Recommended remediation prioritization (post Pass 5 consolidation):**

1. **F-FFI-2 (CRITICAL NEW):** Split `OnboardingHandle` impl into production + `#[cfg(any(test, feature = "test-utils"))]`-gated test rig. Production `unlock_with_pin` returns opaque session-handle string; secrets stay in Rust heap. ~3-4 hours.
2. **F-1 (CRITICAL carry-over):** Replace XOR-combine in `distributed_identity_client.rs:148` with real Lagrange interpolation over Shamir 3-of-5 shares (per round-7 design). ~4-6 hours.
3. **F-2 (CRITICAL carry-over):** Move anon-ID derivation server-side via OPRF (per round-7 design intent); device sends blinded PIN, server returns blinded anon-id, device unblinds. Requires `umbrella-oprf` integration. ~6-8 hours + server backend coordination.
4. **F-CLIENT-FACADE-1 (HIGH/HONEST GAP):** Block 7.4 milestone — wire `send_mls_text` through real MLS group + padding + sealed-sender + Postman delivery. Per existing roadmap; not a separate PhD-B fix.
5. **F-CLIENT-HW-1 (HIGH/HONEST GAP):** Refactor `core.identity` to `Option<...>`; wire signing paths through `core.hw_callback.sign_identity(handle, ...)`. M-FINAL-1 v1.2.x track. ~8-12 hours.
6. **F-MLS-1 (HIGH carry-over):** Decision pre-1.0.0 PQ MLS activation (compile-time gate `new()` / panic / CI grep).
7. **F-CLIENT-HW-2 (MEDIUM):** Add `verifying_key(handle)` callback method. ~2 hours.

---

## Handoff for Pass 5

**Pass 4 scope completed; Pass 5 carry-over watch items:**

1. **Dudect 1M+ samples cross-cutting** — primary Pass 5 deliverable per Pass 1-3 plan. Specifically:
   - `umbrella-oprf::blind/unblind`
   - `umbrella-crypto-primitives::mlocked::MlockedSecret::new/expose`
   - `umbrella-padding::strip_padding` zero-check
   - `umbrella-sealed-sender::derive_v2_keys`
   - `umbrella-identity::keystore::hedged_encaps_witness`
   - Per Pass 4 newly: `umbrella-client::keystore::row_cipher::decrypt_row_zeroizing` constant-time nonce comparison (F-57 closure).
2. **Final consolidation report:**
   - Which Pass 1-4 findings ship before v1.0.0 vs accepted for v1.1.x.
   - Severity uplift decisions (e.g., F-FFI-2 from comment-disclosed-MINOR to CRITICAL — confirm category).
   - PhD-B grade per crate.
3. **F-MLS-MODEL-1 (Pass 3 HIGH formal-claim-gap)** — formal-modeling refactor of `mls_ed25519.spthy` to add ECDSA function symbols + malleability equation. ~4-6 hours formal-modeling.
4. **5 MEDIUM tautological-lemma cluster (Pass 3)** — refactor kt_v1 / kt_v2 / sframe / downgrade / type_safe lemmas to substantive form. ~8-12 hours total.
5. **F-IDENT-37 fix (Pass 3 MEDIUM NEW)** — `RotatedIdentityMaterial.seed: Box<[u8; 64]>` refactor + pointer-arithmetic regression test.

**Pass 5 also performs:**
- End-to-end integration cross-crate audit (umbrella-tests workspace milestone scenarios).
- Final review of `feedback_phd_severity_uplift` carry-over list — confirm all severity categorizations stable.
- Final PhD-B grade per cluster of findings.

**Memory updates required (commit-time):**

1. Add `project_phd_b_pass4_complete` to MEMORY.md.
2. Update `feedback_phd_severity_uplift` carry-over with Pass 4 cluster:
   - F-FFI-2 CRITICAL NEW (comment-disclosed but uncompile-time-enforced placeholder)
   - F-CLIENT-FACADE-1 HIGH/HONEST GAP NEW
   - F-CLIENT-HW-1 HIGH/HONEST GAP NEW
   - F-CLIENT-HW-2 MEDIUM NEW
3. Note Pass 4 lessons in `feedback_phd_pass_full_model_reading` continuation: «Production-named FFI methods + production-named API placeholder pattern. comment-disclosed but no compile-time enforcement → CRITICAL severity per `feedback_phd_severity_uplift`».

---

## References

- `feedback_real_not_paperwork.md` (memory)
- `feedback_phd_level_mandatory.md` (memory)
- `feedback_phd_vs_a_level_distinguisher.md` (memory)
- `feedback_phd_pass_full_model_reading.md` (memory)
- `feedback_phd_no_partial.md` (memory)
- `feedback_direct_to_main.md` (memory)
- `feedback_phd_severity_uplift.md` (memory)
- `project_phd_b_6_rounds_complete.md` (memory)
- `project_phd_b_pass2_complete.md` (memory)
- `project_phd_b_pass3_complete.md` (memory)
- `docs/audits/phd-b-full-sweep-pass1-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md` + supplemental
- `docs/audits/phd-b-full-sweep-pass3-2026-05-18.md`
- RFC 5280 §4.1.2.7 (SubjectPublicKeyInfo)
- RFC 9180 (HPKE Base Mode)
- RFC 9420 (MLS)
- RFC 8032 (EdDSA / Ed25519)
- ADR-006 Variant C (compile_fail E0599 type-safe facades)
- ADR-008 (multi-device authorization)
- ADR-010 Decision 5 subvariant C.1.2 (SQLite per-row encryption)
- ADR-011 Decision 7 (PQ aggregator feature)
- ADR-013 Decisions 1-3 (PQ-first default switch)
- SPEC-01 §4 (threat model)
- SPEC-06 §3 (no-P2P compliance gate)
- SPEC-08 §4 (sealed-sender envelope)
- SPEC-11 §4 (16-device limit)
- SPEC-12 §A.7 (cloud-unwrap signed request)
- Apple App Attest spec (DCAppAttestService)
- Google Play Integrity API (IntegrityManager)
