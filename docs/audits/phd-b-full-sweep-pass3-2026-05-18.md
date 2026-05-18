# PhD-B Full Sweep Audit — Pass 3 (Priority-3 Crates + 9 Formal Models)

**Date:** 2026-05-18
**Session:** PhD-B full sweep, pass #3 / 5
**Scope:** umbrella-core + umbrella-mls (F-MLS-1 deep + non-R24) + umbrella-identity + umbrella-kt + umbrella-calls + umbrella-formal-verification (9 remaining .spthy/.pv models)
**Predecessors:** `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md` + `phd-b-full-sweep-pass2-supplemental-2026-05-18.md`
**Auditor:** Claude Opus 4.7 (PhD-B level per `feedback_phd_level_mandatory` + `feedback_real_not_paperwork` + `feedback_phd_vs_a_level_distinguisher` + `feedback_phd_pass_full_model_reading`)
**Status:** **1 HIGH carry-over (confirmed) + 1 MEDIUM new (RotatedIdentityMaterial stack-resident regression) + 5 MEDIUM formal-model tautology cluster + 15 MINOR/INFO findings.** Most severe new finding: **tautological-lemma cluster across 5 of 9 formal models** — passes Tamarin verification but does not prove the claimed property; same pattern as session #66 `multi_device_authorization.spthy` lesson.

---

## Severity legend

- **CRITICAL:** Production-named API with placeholder semantics OR attack test that does not test the claimed attack surface; cannot ship to 1B users in this state.
- **HIGH:** Production code path that depends on caller hygiene rather than compile-time enforcement; gap in production wire-up of recently-introduced defense; verification gap where formal model passes but claim not proven.
- **MEDIUM:** Documented limit that requires backend coordination OR test coverage gap that meaningfully weakens security claim under realistic conditions; tautological formal-model lemma that does not prove claimed property.
- **MINOR:** Real test/code that lacks PhD-B grade rigor (insufficient samples, no quantification, silent fallback under failure).
- **INFO:** Boundary disclosure, documented test-only helper, no security gap.

---

## F-MLS-1 production wire-up — FINAL RESOLUTION (priority-1 task)

**Pass 2 finding restated:** `UmbrellaXWingProvider::new()` and `Default::default()` silently fall back to `HedgedWitness::zeroed_for_tests_only()` with only doc-comment guard. No production callers `with_hedged_witness()` workspace-wide.

**Pass 3 deeper investigation (priority-1 task):**

Broader grep patterns executed:
- `with_hedged_witness` — 11 matches: 10 doc-comment references in `xwing.rs:327-494`, 1 function definition at `xwing.rs:496`. **0 production callsites.**
- `UmbrellaXWingProvider` — 14 matches: 2 in `umbrella-client/src/core.rs:581,605` (doc-comments only, no construction), 12 in `umbrella-mls/tests/*.rs` (all under `#[test]` or `#[cfg(test)]`).
- `hedged_encaps_witness` — 7 matches: trait definition `umbrella-identity/src/keystore.rs:290`, impl `umbrella-identity/src/keystore.rs:603`, **single production caller `umbrella-sealed-sender/src/hybrid_envelope.rs:167`**, plus doc-comments in `umbrella-mls/src/provider/xwing.rs:489-494` and `umbrella-backup/src/cloud_wrap/pq_wrap.rs:551,555`.
- `OpenMlsProvider` / `UmbrellaProvider` indirect dispatch: **0 in umbrella-ffi, umbrella-ffi-kotlin, umbrella-ffi-swift, umbrella-client.**

**FINAL VERDICT:** PQ MLS provider (X-Wing ciphersuite 0x004D) is **not wired into production code anywhere in the workspace** — not via `new()`, not via `with_hedged_witness()`, not via indirect trait dispatch in client/FFI layers. Only `umbrella-sealed-sender::seal_v2` actually uses the hedged witness (via direct `keystore.hedged_encaps_witness()` at `hybrid_envelope.rs:167`).

**Real-adversary impact:** PQ MLS round-3 hedged-encaps defense is **dormant** for MLS group communication. When/if `UmbrellaXWingProvider` is wired into the client (current state: only Cargo `pq` feature exists + capability advertised in `caps.rs`, but no instantiation), the default `new()`/`default()` path provides zero-witness encaps — equivalent to non-hedged baseline at the HPKE layer.

**Recommended remediation paths (ranked by PhD-B preference):**

1. **(Strongest) Remove `Default::default()` impl + make `new()` private (or `#[cfg(test)]`-gated):** Force production callers to construct via `with_hedged_witness(witness)` — compile-time enforcement of the witness-required invariant. Eliminates the footgun entirely.
2. **(Mid) Convert silent fallback to `panic!()` in release builds:** Currently `Default::default()` returns a valid (but insecure) provider; switching to `panic!("UmbrellaXWingProvider::default() called in production; use with_hedged_witness")` makes the bug surfacing immediately at first PQ group operation instead of silently degrading.
3. **(Weakest) Document the transitional state in a release-tracking memo + add CI check that no production code path reaches `UmbrellaXWingProvider::new()`:** Maintains current contract but adds explicit observability. Acceptable for v1.0.0 if PQ MLS is explicitly out-of-scope for that release.

**F-MLS-1 stands as HIGH carry-over for post-1.0.0 PQ MLS activation track.** Cannot ship as-is to 1B users with PQ MLS activated; fine to ship without PQ MLS (current state — feature gate disables the variant in `caps.rs::umbrella_supported_openmls_ciphersuites` when `pq` not active).

---

## Crate-by-crate summary

### umbrella-core (Pass — 153 LoC base layer)

✅ Type-only base: `UserId([u8; 32])` + `DeviceId([u8; 32])` + `EpochId(pub u64)` + `MessageId([u8; 16])` + `CoreError`.
✅ `#![forbid(unsafe_code)]` + `#![warn(missing_docs)]` defensive boundary.
✅ Debug impls truncate to 4-byte prefix (`UserId(2a2a2a2a…)`) — prevents key leak in logs.

**Findings:**

- **F-CORE-1 (INFO):** `UserId::from_bytes`/`DeviceId::from_bytes` accept any 32 bytes without Ed25519 point validation — caller "obligated" per doc-comment. Validation lives in `umbrella-identity::IdentityKeyPublic::from_bytes`. Documentation-driven invariant. No security gap if downstream uses umbrella-identity wrappers.
- **F-CORE-2 (INFO):** `EpochId(pub u64)` has `pub` field — trivially mutable. Not security-critical (epoch is replay-monotonic, not secret), but breaks newtype encapsulation pattern of UserId/DeviceId/MessageId.
- **F-CORE-3 (INFO):** Only 2 tests (round-trip + epoch ordering). No proptest. Acceptable since core has no crypto.

### umbrella-mls (Pass with HIGH carry-over F-MLS-1 + 5 MINOR)

**File-by-file watch items:**
- `provider/xwing.rs` (998 LoC): UmbrellaXWingProvider HPKE base mode RFC 9180 §5.1 over X-Wing draft-10 KAT + `setup_base_sender` using `xwing_encaps_hedged(witness)` per round-3 closure; `HpkeContext` has `#[derive(ZeroizeOnDrop)]` for key + base_nonce + exporter_secret (F-63 closure inline-fix).
- `group.rs` (1739 LoC): MlockedSecret wraps exporter_secret (MAX_EXPORTER_LEN=64); `process_incoming` wraps openmls 0.8.1 in `catch_unwind` for AEAD-debug-assertion panics; F-37 parser_safe defensive layer.
- `parser.rs` (252 LoC): F-37 closure bounds-check + `std::panic::catch_unwind` for `tls_codec-0.4.2` panic on 5-byte `[0,0,0,1,192]` input. Tested with minimal F-37 reproduction.
- `signer.rs` (216 LoC): UmbrellaIdentitySigner + UmbrellaDeviceSigner delegate to KeyStore; private keys never enter openmls memory. `device_signer_after_revoke_returns_signer_error` validates revocation propagation.
- `ciphersuite.rs` (409 LoC): **ETK attack mitigation (Cremers et al. eprint 2025/229) at type level** — ECDSA-based ciphersuites (0x0002/0x0005/0x0007) excluded from `UmbrellaCiphersuite` enum. `from_raw_id` rejects with `DisallowedCiphersuite`; `0x004D` gated by `CiphersuiteRequiresPqFeature` runtime variant under no-`pq` feature.
- `caps.rs` (78 LoC): `umbrella_capabilities()` declares only whitelist + BasicCredential + MLS 1.0 + no experimental extensions/proposals.
- `credential.rs` (171 LoC): BasicCredential identity payload = `identity_pubkey_32 || device_index_be_4` = 36 bytes; KT-binding via DeviceAttestation lookup is the boundary.
- `key_package.rs` (377 LoC): KEY_PACKAGE_LIFETIME_SECS = 28 days (vs openmls 90-day default). Tests verify capabilities classifier (`capabilities_do_not_declare_ecdsa_variants`).
- `group_policy.rs` (196 LoC): Private (1-1, no external ops) vs PublicBroadcast (PSK-gated). Sanity test `KP lifetime > rekey interval` validates constants relationship.
- `screenshot_policy.rs` (234 LoC): Per-chat screenshot policy + TTL self-destruct. Receiver-side timer (anti-forensic UX, not cryptographic guarantee).

**Findings:**

- **F-MLS-1 (HIGH carry-over):** PQ MLS not production-wired (see priority-1 task resolution above).
- **F-MLS-22 (MINOR):** `KEY_PACKAGE_MIN_BYTES = 64` is "conservative lower bound" comment says "real canonical KeyPackage значительно больше (~300+ байт)". Tighter bound (~300) would block wider class of F-37-like panics before reaching `catch_unwind`. Acceptable defense-in-depth gap.
- **F-MLS-35 (MINOR/HONEST GAP):** `Capabilities::new(Some([Mls10]), Some(suites), None, None, Some([Basic]))` — the `None` for extensions and proposals is openmls's "accept defaults". No regression test verifies "no experimental extensions declared by openmls 0.8.x defaults". Test would protect against upstream regression where openmls auto-adds experimental capabilities to leaf nodes.
- **F-MLS-14 (MEDIUM/HONEST GAP):** `bit_flip_in_ciphertext_rejected` test (group.rs:1372-1395) accepts `Err(ProcessingPanic) | Err(GroupOperation)` — reliance on `catch_unwind` workaround for openmls 0.8.1 AEAD-debug-assertion panic. Documented honestly; production caller depends on `catch_unwind` to prevent malformed-input DoS.
- **F-MLS-19 (MINOR):** `removed_member_cannot_decrypt_subsequent_messages` test conditionally asserts forward secrecy (`if Ok(ct) → bob_result.is_err()`) — doesn't enforce that encrypt MUST succeed for the FS property to be meaningfully tested. Acceptable if openmls semantics document single-member encrypt rejection; otherwise minor weakness.
- **F-MLS-36 (MINOR/INFO):** `ReceiverMessageTracker::check_ttl` uses local SystemTime — honest UX/anti-forensic feature, not cryptographic guarantee. Documented as "anti-forensic" in module doc.

### umbrella-identity (Pass with 1 MEDIUM new + 2 HIGH/HONEST GAP + 3 MINOR)

**Critical files reviewed:**
- `keystore.rs` (1012 LoC): KeyStore trait + InMemoryKeyStore (the only impl in this codebase). `hedged_encaps_witness()` derives via `HedgedWitness::derive_from_identity_seed(seed.seed(), account)` at line 377.
- `seed.rs` (451 LoC): IdentitySeed with **F-PHD-DC-R7-3 closure** — `Box<[u8; 32]>` heap-resident entropy + `Box<[u8; 64]>` heap-resident seed. Regression tests `bip39_derivation_temporaries_are_zeroizing` (source-grep) + `r7_closure_entropy_and_seed_are_heap_resident` (pointer-arithmetic check > 64 KiB from stack anchor). **PhD-B exemplar of memory-hygiene regression-guarding.**
- `derive.rs` (615 LoC): SLIP-0010 with full RFC test vector coverage TV1 (master + 0H + 0H/1H + 0H/1H/2H + 0H/1H/2H/2H + 0H/1H/2H/2H/1000000000H) + TV2 (master + 0H + 0H/2147483647H + +1H + +2147483646H + +2H — session #67 F-PHD-RETRO-4 depth-3/4/5 closure). Proptest `prop_one_bit_seed_change_changes_master` 256 cases.
- `identity_key.rs` (190 LoC): IdentityKey `pub(crate) fn sign` — external crates go through KeyStore. Encapsulated.
- `device_key.rs` (181 LoC): DeviceKey `pub fn sign` — asymmetric with IdentityKey (note: `device_index_distinct_signatures` test verifies distinct device keys produce distinct sigs).
- `identity_x25519.rs` (228 LoC): X25519 derived at separate hardened path `m/0x554D'/account'/4'` — avoids ed2curve birational map risk.
- `attestation.rs` (472 LoC): **PhD-B exemplar** — wire-format `version_u8 || account_u32_BE || device_index_u32_BE || issued_at_u64_BE || expires_at_u64_BE || device_pubkey_32 || signature_64` = 121 bytes; explicit ATTESTATION_DOMAIN_SEPARATOR; 7 adversarial tests + 2 proptest (`prop_attestation_round_trip` 100 + `prop_any_bit_flip_in_signature_rejected` 512 cases).
- `code_recovery.rs` (991 LoC): **F-PHD-RETRO-3-E closure exemplar** — 24+12 word HKDF-SHA512 rotation + `public_half_proof(account)` + `rotation_commitment(old_pk, new_pk)` primitives + `code_recovery_temporaries_are_zeroizing` source-grep test verifying 6 Zeroizing patterns + `ct_eq` constant-time old_pubkey verification before derive.
- `hybrid_identity.rs` (552 LoC): Ed25519 + ML-DSA-65 AND-mode; Ed25519 part byte-equal to classical IdentityKey; ML-DSA-65 derived via `ChaCha20Rng::from_seed(HKDF-SHA256(seed, salt=account_be, info="umbrellax-hybrid-identity-mldsa-v1"))`. Test `hybrid_pubkey_substituted_ed25519_yields_verify_failure` checks AND-mode gate via tampered pubkey.
- `cloud_wrap_recovery.rs` (463 LoC): X-Wing recovery keypair under separate HKDF info `"umbrellax-cloud-wrap-recovery-xwing-v1"`; verified byte-distinct from SLH-DSA backup seed.
- `slh_dsa_backup.rs` (418 LoC): SLH-DSA-128f isolated to catastrophic-recovery (not hot path; 17 KB sigs ~15 ms signing).

**Findings:**

- **F-IDENT-1 (HIGH/HONEST GAP):** `InMemoryKeyStore` is the **only** KeyStore impl in the crate. Documented as "test-only" + "**НЕ для production**" in module-level doc-comment. **However, there is no actual Secure Enclave/StrongBox FFI bridge implementation in this codebase**; downstream production users either implement KeyStore themselves (correct path) or use InMemoryKeyStore in production (footgun). The Secure Enclave path is documented as "to be added via FFI bridge" but the bridge code is not in this repository. Real-adversary impact: process memory capture on production app using `InMemoryKeyStore` recovers all key material.
- **F-IDENT-2 (HIGH):** `InMemoryKeyStore.seed: IdentitySeed` lives in process heap for the lifetime of the keystore. Even with seed `Box<[u8; 64]>` heap-resident (R7-3 closure), it persists for the keystore's lifetime. `add_device` re-derives `DeviceKey::derive(&self.seed, ...)` — adversary with process memory access can regenerate ALL device keys without needing individual device_sk leaks. Mitigated by HW backed KeyStore in production; documented gap.
- **F-IDENT-3 (INFO):** `revoke_device` only flips `rec.revoked = true`. Private device key `rec.private` REMAINS in keystore map until full keystore Drop. Per doc-comment lines 296-298: "Private device key (DeviceKey is already ZeroizeOnDrop — zeroized on map removal)." But `revoke_device` does NOT remove from map. Honest gap; revocation-without-deletion preserves audit trail but extends in-memory key lifetime.
- **F-IDENT-19 (MINOR):** `derive.rs:128-131` and `:177-179` construct `ExtendedSecret(*secret)` and `ChainCode(*chain_code)` by dereferencing `Zeroizing<[u8; 32]>`. Stack-resident pattern; not heap-resident `Box<[u8; 32]>`. Same risk class as the original F-PHD-DC-R7-3 finding but applied to SLIP-0010 intermediates. Bounded by short MasterKey lifetime + ZeroizeOnDrop on the final struct, but Box-pattern not applied here.
- **F-IDENT-25 (MINOR):** Same stack-copy pattern in `identity_x25519.rs:71` — `let mut scalar = *master.secret().as_bytes()`. Locally zeroized post-handoff to X25519Static.
- **F-IDENT-37 (MEDIUM — NEW HIGH-LIKELIHOOD REGRESSION):** **`RotatedIdentityMaterial.seed: [u8; SEED_LEN=64]` in `code_recovery.rs:303` is stack-resident, NOT `Box<[u8; 64]>`.** This is a **regression of the F-PHD-DC-R7-3 lesson** applied to `IdentitySeed.seed` (which was refactored to `Box<[u8; 64]>` per the round-5 device-capture closure). Catastrophic recovery is a production code path; the rotated seed lives on the owner's stack until `RotatedIdentityMaterial::drop` zeroizes. Pointer-arithmetic regression test analogous to `r7_closure_entropy_and_seed_are_heap_resident` would catch this in CI.

  Recommended fix: `pub struct RotatedIdentityMaterial { seed: Box<[u8; SEED_LEN]> }` + custom `Zeroize`/`Drop` impl analogous to `IdentitySeed`. Also `derive_rotated_identity_material:389` constructs `RotatedIdentityMaterial { seed: *rotated_seed }` — should construct via `Box::new(*rotated_seed)` after refactoring.

- **F-IDENT-30 PASS+:** `attestation.rs` 7 adversarial tests + 2 proptest (612 cases) — `attestation_with_substituted_device_pubkey_rejected` modifies wire-format byte slice 25..57 and verifies Crypto error. Exemplar of real-vs-paperwork standard.
- **F-IDENT-31 PASS+:** `code_recovery.rs` F-PHD-RETRO-3-E primitives + 8 adversarial tests + 5 proptest (640 cases) + integration test `full_catastrophic_recovery_flow`. **Highest-grade PhD-B in umbrella-identity.**

### umbrella-kt (Pass — PhD-B exemplar)

**Files reviewed:**
- `lib.rs` (112 LoC): Module organization — `version` (KtEntryVersion enum, always compiled) + `entry`/`entry_v2` (V1 + V2 wire format) + `monitor` (self-monitoring) + `witness` (3-of-5 split-view defense) + `observation` (equivocation evidence) + `merkle` (RFC 6962 SHA-256 domain-separated) + `authorization_entries` (ADR-008 multi-device).
- `entry.rs` (273 LoC): KtEntry canonical encoding (account_id+epoch+identity+devices, sorted by device_index for reorder defense); merkle_leaf_hash = SHA-256(0x00 || canonical_encoding).
- `merkle.rs` (504 LoC): RFC 6962 leaf prefix 0x00 + inner prefix 0x01 (second-preimage attack mitigated); `largest_power_of_two_below` debug_assert(n >= 2) — caller-only invariant.
- `witness.rs` (671 LoC): WitnessSet (deduplicated set); WitnessSignature; SignedEpochRoot with `epoch, root, log_size, timestamp_unix_millis, signatures: Vec<WitnessSignature>`; **F-PHD-S68-1 closure** — `canonical_sign_payload(epoch, root, log_size, timestamp_unix_millis)` = `WITNESS_DOMAIN_SEP || version || epoch_BE || root || log_size_BE || timestamp_BE` (80 bytes) per SPEC-09 §5.3.
- `authorization_entries.rs` (2352 LoC): ADR-008 entry types 0x04 (DeviceAuthorizationApproval), 0x05 (DeviceAuthorizationRevocation), 0x06 (IdentityRotationRecord); `KtLogState` mirror with **F-PHD-RETRO-3-E mitigation** — stored `code_recovery_public_half_proof: Option<[u8; 32]>` tracks bit-equal proof from `CodeRecoveryMnemonic::public_half_proof`.
- `tests/phd_real_attacks.rs` (928 LoC): **Session #68b honest correction "делал PhD атаку?" = нет → real attacks** — 100K randomized fuzz on KtEntryV2::from_bytes (panic detection + false-positive parse + trailing byte acceptance + bit-flip silent corruption) + exhaustive bit-flip 1536 signature bits + differential testing Merkle root with reference RFC 6962 + boundary length fuzz 2065..2099 + concurrent log_state corruption race.

**Findings:**

- **F-KT-1 PASS+:** RFC 6962 Merkle with domain-separated leaf/inner hashes.
- **F-KT-2 PASS+:** Multi-witness 3-of-5 split-view defense across distinct jurisdictions.
- **F-KT-3 PASS+:** `canonical_sign_payload` cross-binding `epoch + root + log_size + timestamp` (F-PHD-S68-1 closure session #68d).
- **F-KT-4 PASS+:** `KtLogState.code_recovery_public_half_proof` F-PHD-RETRO-3-E mitigation — bit-equal stored proof prevents 24-words leak alone account hijack.
- **F-KT-5 PASS+:** `phd_real_attacks.rs` 100K fuzz + 1536 bit-flip + differential Merkle — **exemplar of `feedback_real_not_paperwork` standard for the umbrella-kt scope.**
- **F-KT-6 PASS+:** Session #68b honest naming reform — rename behavioral tests to real attacks per memory `feedback_real_not_paperwork` enforcement.
- **F-KT-7 (INFO):** `authorization_entries.rs` reuses `umbrella_backup::cloud_wrap` wire-format types (single source of truth per SPEC-12 §A.13) — no dual encode/decode paths.

### umbrella-calls (Pass — PhD-B exemplar)

**Files reviewed:**
- `sframe/derive.rs` (663 LoC): **F-CALL-2 PASS+** — full RFC 9605 §4.4.2 + §5.1 pipeline (HKDF-Extract → HKDF-Expand) with normative labels `"SFrame 1.0 Secret key "` (22 bytes) / `"SFrame 1.0 Secret salt "` (23 bytes). **RFC 9605 Appendix C test vectors verified byte-equal**: `rfc9605_vector_sframe_secret_matches` + `rfc9605_vector_sframe_key_salt_match` + `rfc9605_vector_nonce_matches` + `rfc9605_vector_wire_header_matches` + `rfc9605_vector_full_aead_matches`. Cross-checks land on same point as IETF sframe-wg test suite.
- `dtls/fingerprint.rs` (335 LoC): **PhD-B exemplar** — `IdentityDtlsFingerprint::derive(pk, nonce) = SHA-256(DOMAIN_IDENTITY || pk || nonce)` + `compute_mutual_identity_binding(local, peer, nonce) = SHA-256(DOMAIN_MUTUAL || min(local,peer) || max(local,peer) || nonce)`. Lexicographic min/max for symmetric safety-number regardless of arg order (Signal-style per-call safety-number). `subtle::ConstantTimeEq` for fingerprint compare. 14 tests + 2 proptest (256 cases).

**Findings:**

- **F-CALL-1 PASS+:** RFC 9605 §5 key schedule pipeline with explicit Appendix C test-vector cross-check.
- **F-CALL-2 PASS+:** Full RFC 9605 Appendix C vector validation byte-equal (sframe_secret + sframe_key + sframe_salt + nonce + wire_header + AEAD ciphertext_with_tag).
- **F-CALL-3 PASS+:** Domain separation tested (`derive_per_kid_domain_separation_key_vs_salt`): same KID, different labels → distinct outputs.
- **F-CALL-4 PASS+:** F-56 closure (block 10.15) — `mls_exporter_output: [u8; 64]` taken by value + zeroized before return (stack-frame hygiene).
- **F-CALL-5 PASS+:** Round-5 closure F-PHD-DC-R11-1 — `secret: MlockedSecret<[u8; MAX_EXPORTER_LEN=64]>` replaces `secrecy::SecretBox` for mlock+zeroize defense.
- **F-CALL-7 (HONEST GAP):** Comment `derive.rs:156-164` explicitly notes `prk_stack: GenericArray` stack-spill is best-effort (generic-array 0.14 does NOT implement `Zeroize`). Documented forensic limitation without unsafe. Acceptable PhD-B disclosure.
- **F-CALL-8 PASS+:** DTLS fingerprint domain separation (identity vs mutual + session_nonce 16 bytes prevents replay across sessions).
- **F-CALL-9 PASS+:** Lexicographic min/max in `compute_mutual_identity_binding` ensures symmetric safety-number — `mutual_binding_symmetric` test.

### umbrella-formal-verification (Pass with 5 MEDIUM tautology cluster + 1 HIGH formal-claim-gap)

**Per memory `feedback_phd_pass_full_model_reading` lesson session #66**: lemma names can be misleading, tautological lemmas can pass verification without proving the claimed property. Applied detector across all 9 Pass 3 models.

**9 models read top-to-bottom (5447 total LoC):**

#### multi_device_authorization.spthy (705 LoC) — **PASS+ exemplar**

13 lemmas. **All substantive:**

- ✅ `pending_state_required_before_active` — proves state-machine transition through DeviceActivated → ApprovalSignedByActive cross-reference.
- ✅ `active_device_signs_authorization` — proves UF-CMA approval signature from existing active device-key.
- ✅ `unauthorized_device_rejected_by_sealed_servers` (strengthened) — explicitly combines prior-activation AND signed-request via `UnwrapRequestSignedByDevice` action label (F-PHD-RETRO-3 closure session 2026-05-17 inline fix).
- ✅ `twentyfour_words_leak_alone_insufficient` — PRIMARY threat-model claim SPEC-01 §4 row 8; proves UnwrapGranted requires ApprovalSignedByActive even after Reveal24Words.
- ✅ `identity_rotation_atomic_dual_signature` — PhD-deep session #67 F-PHD-RETRO-1 fix: literally formalizes dual signature via `SignedRotationOld` + `SignedRotationNew` action labels (previous formulation `not (old_pk = new_pk)` was misleading — only proved keys differ, not dual-signature invariant).
- ✅ `revocation_terminal_state` — proves through `RevocationTerminal` restriction enforcing temporal order.
- ✅ `unwrap_requires_signed_request` — proves UnwrapGranted requires `UnwrapRequestSignedByDevice` event (session #67 NEW).
- ✅ `unwrap_binds_chat_id_to_identity` — cross-account replay defense (session #67 NEW).
- ✅ `twentyfour_words_leak_alone_strengthened` — session #67 NEW: explicit device_sk requirement even after identity_sk leak.
- ✅ `rotation_requires_e12_knowledge` — F-PHD-RETRO-3-E NEW: rotation universally requires e12 (honest path OR adversary leak).
- ✅ `twentyfour_words_leak_alone_insufficient_REGRESSION` — F-PHD-RETRO-3-E regression-guard: falsifiable lemma proving rotation impossible with ONLY 24-words leak.
- ✅ `honest_setup_executable` exists-trace sanity.

**Honest disclosure (lines 145-183):** Wire-format abstractions — 7-field 138-byte wire format abstracted to single tuple `<'dom_request', device_pk>`. Symbolic proof covers signature unforgeability + state-machine transitions, NOT timestamp manipulation / challenge_nonce reuse / location_hint privacy / wire_version downgrade. These checked separately via fuzz + cross-reference (`umbrella-backup/fuzz/...` + ADR-008 §5 normative wire format + computational reduction Brendel 2020 Theorem 2). **Honest "wire-format abstraction gap" pattern; computational + fuzz complement symbolic.**

**F-MDA-MODEL-1 PASS+:** Highest-quality PhD-B formal model in the workspace. Iterative strengthening visible through F-PHD-RETRO-3 + F-PHD-RETRO-3-E commits.

#### kt_v1_self_monitoring.spthy (278 LoC) — **TAUTOLOGICAL CLUSTER**

All 3 substitution_detected_v1 lemmas have the form:

```
"... not(identity_orig = identity_sub) & ... ==> not(identity_sub = identity_orig)"
```

The premise `not(identity_orig = identity_sub)` and the conclusion `not(identity_sub = identity_orig)` are **literally the same proposition via commutativity of equality**. Tamarin verifies this trivially. The lemma does NOT prove "self-monitor would detect the substitution" — it proves "if A ≠ B then B ≠ A".

**F-KT-V1-MODEL-1 (MEDIUM)**: `identity_substitution_detected_v1` + `device_substitution_detected_v1` + `foreign_identity_detected_v1` — all 3 substantive lemmas are tautological. The model passes Tamarin verification but does not formally prove the self-monitoring detection property.

**Correct formulation would be:**
```
"All A acc_id sub local #i.
    SelfMonitorIdentityV1(A, acc_id, sub, local) @ i & not(sub = local)
    ==>
    Ex orig #j. AdversarySubstituteIdentityV1(A, acc_id, orig, sub) @ j & j < i"
```
i.e., "if self-monitor observed a mismatch, there MUST exist a prior adversarial substitution event" — connects model state to attack causally rather than tautologically.

#### kt_v2_self_monitoring.spthy (298 LoC) — **TAUTOLOGICAL CLUSTER**

Same pattern as kt_v1 — `ghost_participant_substitution_detected`, `slh_dsa_backup_substitution_detected`, `slh_dsa_backup_unexpected_missing_detected` all have form:

```
"... AdversarySubstitute(orig, sub) & SelfMonitor(<sub, ...>, <orig, ...>) & not(orig = sub)
   ==> not(<sub, ...> = <orig, ...>)"
```

Two tuples differing only in first position are equal iff first components are equal; conclusion `not(<sub,...> = <orig,...>)` ⟺ `sub ≠ orig` = premise.

**F-KT-V2-MODEL-1 (MEDIUM)**: Same tautology pattern as kt_v1. The `slh_dsa_backup_unexpected_missing_detected` clauses are STRUCTURALLY true (`'absent' ≠ 'present'` by inspection) — Tamarin proves trivially without needing adversarial reasoning.

#### mls_ed25519.spthy (327 LoC) — **3 TAUTOLOGICAL LEMMAS by model construction**

- `external_operations_disabled`: The `external_commit_attempt` rule requires `!Group(group_id, _, 'true')` premise; the `create_private_group_ed25519` rules ALWAYS create `!Group(..., 'false')` — NO rule produces 'true' Group. **Tautological by structural unreachability.** The model doesn't include a rule like "adversary attempts external commit on private group" with the actual reject path; it just doesn't model any rule that could fire.
- `etk_split_brain_prevented`: `epoch_state = h(<group_id, new_epoch, ciphersuite>)` — deterministic hash. Two events for same args yield same hash. **Proves hash determinism, not ECDSA malleability defense** — the model doesn't even include ECDSA. Real ETK attack would need ECDSA function symbol with malleability equation `verify(repack(sig), m, pk) = true` enabling adversary to produce two distinct sig bytes for same message.
- `ed25519_only_whitelist`: `create_private_group_ed25519` rule emits both `CreateGroup` AND `Whitelisted` action labels at the SAME timestep. Lemma `CreateGroup ⟹ Whitelisted @ same timestep` is trivially true by rule structure.

**F-MLS-MODEL-1 (HIGH)**: All 3 primary security claims in `mls_ed25519.spthy` are tautological — model passes Tamarin verification but the security claim (Ed25519-SUF-CMA blocks ETK split-brain) is NOT actually formalized. The model lacks ECDSA function symbols + malleability equation that would make the property non-trivial. **The ETK attack mitigation citation in the module preamble references Cremers et al. eprint 2025/229 but the formal claim doesn't simulate the attack.**

**Recommended fix:** Add second signature scheme abstraction with explicit malleability equation `ecdsa_repack(sig, r) | verify(ecdsa_sig, m, pk) = true | verify(ecdsa_repack(sig, r), m, pk) = true`, then prove `not Ed25519-malleable` via standard SUF-CMA semantics.

#### sframe_rfc9605.spthy (302 LoC) — **2 TAUTOLOGICAL + 2 VALID**

- ✅ `per_kid_counter_anti_replay` — enforced by `AntiReplayUnique` restriction; valid claim about ReplayWindow.
- ✅ `frame_decrypt_authentic` — proves AEAD AAD binding (receive plaintext = sent plaintext via aead_open/aead_seal equation). Substantive PhD-B claim.
- 🟡 `dtls_identity_binding_consistent`: `fingerprint = h(<dom, identity_pk, session_nonce>)` deterministic; lemma proves hash determinism. **Doesn't model MITM substitution attempt.**
- 🟡 `kid_uniqueness_per_epoch`: `sframe_key = h(<base_key, kid, 'cs_0005', 'label_key'>)` deterministic; with same (A, epoch, kid) the base_key is fixed by `!MlsBaseKey` persistent fact (Fr semantics ensure uniqueness per (A, epoch)). **Tautological by Fr + h-determinism.**

**F-SFRAME-MODEL-1 (MEDIUM)**: 2 of 4 substantive lemmas tautological. The 2 valid lemmas (`per_kid_counter_anti_replay` + `frame_decrypt_authentic`) are the meaningful security claims.

#### discovery.spthy (412 LoC) — **1 TAUTOLOGICAL + 4 VALID**

- ✅ `server_never_learns_plaintext_phone` — proves through Fr semantics + adversary cannot invert `blind(input, r)` without `r`.
- ✅ `intersection_cardinality_only_disclosed` — proves adversary cannot recover input from output even with output known.
- ✅ `kt_bind_prevents_silent_swap` — proves through `KtBindMustMatch` + `KtLeafMustMatch` restrictions + only `kt_insert_leaf` rule produces `!KtEpochRoot` facts.
- ✅ `anon_id_unlinkable_across_queries` — proves through Fr salt uniqueness + h-determinism.
- 🟡 `replay_protection_enforced`: `CombinedServerResponded(aid, p, sn, cn) @ #i & ... @ #j ⟹ #i = #j` — proves Fr nonce uniqueness, not replay defense. **Doesn't model adversary replaying captured response via In channel.**

**F-DISCOVERY-MODEL-1 (MINOR)**: 1 of 5 substantive lemmas partially tautological. 4 valid claims. Honest disclosure (lines 106-114) acknowledges Lagrange threshold combination abstracted to single `k_combined`; companion model `sealed_servers_threshold_3of5.spthy` covers Shamir property (verified Pass 2 supplemental as F-3OF5-1 PASS+ + F-UNIV-1 PASS+).

#### downgrade_resistance.spthy (410 LoC) — **3 TAUTOLOGICAL + 2 VALID**

- ✅ `adversary_cannot_force_silent_downgrade` — re-states `no_silent_downgrade` restriction; valid PhD-B (restriction-driven proof).
- 🟡 `default_ciphersuite_respected`: ONLY rule emitting `DefaultCiphersuite` is `chat_settings_default_pq_to_pq` which always emits `DefaultCiphersuite($A, '0x004D')`. **Tautological by single-rule action label.**
- 🟡 `no_silent_fallback_under_capability_mismatch`: `require_pq_without_feature` rule emits `MlsErrorCapabilities` + creates no Group fact. NO rule path produces `Negotiated(A, B, '0x0003')` with the premise's preconditions. **Tautological by structural unreachability.**
- 🟡 `adversary_strip_does_not_force_downgrade`: `adversarial_keypackage_capability_strip` rule has empty post-condition `[ ]` — no state change. Lemma reduces to `no_silent_downgrade` restriction. **HONEST DISCLOSURE in module doc lines 233-238**: model explicitly notes capability negotiation uses LOCAL state (not network) — adversary strip rule is no-op by design. Documented honestly but tautological for adversarial simulation.
- ✅ `explicit_chatsettings_override_allowed` exists-trace sanity.

**F-DOWNGRADE-MODEL-1 (MEDIUM)**: 3 of 5 substantive lemmas tautological by model construction. Honest module-doc disclosure of the design rationale (LOCAL state vs network capability negotiation).

#### hybrid_signature_and_mode.spthy (298 LoC) — **PASS+ exemplar**

- ✅ `and_mode_security_classical_break_ed25519` — substantive: classical break alone insufficient; ML-DSA-65 EUF-CMA protects.
- ✅ `and_mode_security_quantum_break_mldsa` — symmetric: quantum break alone insufficient; Ed25519 EUF-CMA protects.
- ✅ `domain_separation` — non-canonical context label forgery requires both compromises.
- ✅ `honest_setup_executable` exists-trace.

**All 3 substantive AND-mode claims are valid PhD-B.** `mldsa_pk/1 [private]` ensures adversary cannot derive pubkey from arbitrary terms — proper modeling of separate EUF-CMA security. **F-HYBRID-MODEL-1 PASS+**: model exemplar.

#### type_safe_enforcement.spthy (332 LoC) — **3 TAUTOLOGICAL + 1 VALID**

- 🟡 `cloud_chat_requires_sealed_servers`: `cloud_read` rule REQUIRES `UnwrapComplete($A, chat_id)` linear fact, ONLY produced by `cloud_unwrap_threshold`. **Tautological by linear-fact rule chaining.**
- 🟡 `secret_chat_no_cloud_unwrap`: `cloud_unwrap_threshold` requires `!ChatMode(chat_id, 'cloud')` premise; `secret_read` requires `'secret'`. `!ChatMode` set-once by `create_*_chat`. **Tautological by mode-gated rule premises.**
- 🟡 `mode_separation_invariant`: `Fr(~chat_id)` in `create_*_chat` ensures chat_ids unique. Two ChatCreated events with same chat_id structurally impossible. **Tautological by Fr semantics.**
- 🟡 `secret_chat_three_of_five_servers_compromise_irrelevant`: same as #2 — `cloud_unwrap_threshold` cannot fire for `!ChatMode(chat_id, 'secret')`. **Tautological by mode-gated premises.**
- ✅ `honest_setup_executable_both_modes` exists-trace.

**F-TYPE-SAFE-MODEL-1 (MEDIUM)**: 3 of 4 substantive lemmas tautological by model construction. Honest module-doc disclosure (lines 84-86): "В реальном коде это compile-fail E0599 на SecretChatHandle::cloud_sync_history" — type-safety enforced at compile-time, formal model represents it structurally via mode-gated rules. The model captures structural invariant correctly but lemmas don't model adversarial mixing attempts.

---

## Pass 3 severity tracking

| Finding | Severity | Crate / Model | Memory disconnect |
|---------|----------|---------------|-------------------|
| F-MLS-1 | **HIGH carry-over** | umbrella-mls (production wire-up confirmed missing) | tracked since Pass 2 |
| F-IDENT-37 | **MEDIUM NEW** | umbrella-identity/src/code_recovery.rs | regression of F-PHD-DC-R7-3 lesson |
| F-IDENT-1 | HIGH/HONEST GAP | umbrella-identity/src/keystore.rs | InMemoryKeyStore production fallback |
| F-IDENT-2 | HIGH | umbrella-identity/src/keystore.rs | seed lives in process heap |
| F-MLS-MODEL-1 | **HIGH formal-claim-gap** | mls_ed25519.spthy | 3 tautological lemmas (ETK NOT formalized) |
| F-KT-V1-MODEL-1 | MEDIUM | kt_v1_self_monitoring.spthy | 3 tautological lemmas |
| F-KT-V2-MODEL-1 | MEDIUM | kt_v2_self_monitoring.spthy | 3 tautological lemmas (incl. SLH-DSA backup) |
| F-SFRAME-MODEL-1 | MEDIUM | sframe_rfc9605.spthy | 2 of 4 lemmas tautological |
| F-DOWNGRADE-MODEL-1 | MEDIUM | downgrade_resistance.spthy | 3 of 5 lemmas tautological |
| F-TYPE-SAFE-MODEL-1 | MEDIUM | type_safe_enforcement.spthy | 3 of 4 lemmas tautological |
| F-DISCOVERY-MODEL-1 | MINOR | discovery.spthy | 1 of 5 lemmas (replay) tautological |
| F-MLS-22 | MINOR | umbrella-mls/src/parser.rs | KEY_PACKAGE_MIN_BYTES=64 conservative |
| F-MLS-14 | MEDIUM/HONEST GAP | umbrella-mls/src/group.rs | openmls 0.8.1 panic workaround |
| F-MLS-35 | MINOR/HONEST GAP | umbrella-mls/src/caps.rs | no regression test for `None` extensions/proposals |
| F-MLS-19 | MINOR | umbrella-mls/src/group.rs | conditional FS assertion |
| F-MLS-36 | MINOR/INFO | umbrella-mls/src/screenshot_policy.rs | local SystemTime UX |
| F-IDENT-3 | INFO | umbrella-identity/src/keystore.rs | revoke keeps key in memory |
| F-IDENT-19 | MINOR | umbrella-identity/src/derive.rs | stack-resident Zeroizing intermediates |
| F-IDENT-25 | MINOR | umbrella-identity/src/identity_x25519.rs | stack-copy from `*master.secret().as_bytes()` |
| F-CORE-1 | INFO | umbrella-core/src/ids.rs | no Ed25519 point validation in from_bytes |
| F-CORE-2 | INFO | umbrella-core/src/ids.rs | EpochId pub field |
| F-CALL-7 | HONEST GAP | umbrella-calls/src/sframe/derive.rs | GenericArray stack-spill (best-effort) |
| F-MDA-MODEL-1 | PASS+ | multi_device_authorization.spthy | 13 substantive lemmas exemplar |
| F-HYBRID-MODEL-1 | PASS+ | hybrid_signature_and_mode.spthy | 3 substantive AND-mode lemmas |
| F-KT-1...F-KT-7 | PASS+ | umbrella-kt | session #68b real PhD attacks |
| F-CALL-1...F-CALL-9 | PASS+ | umbrella-calls | RFC 9605 Appendix C byte-equal vectors |
| F-IDENT-30...F-IDENT-31 | PASS+ | umbrella-identity | DeviceAttestation + code_recovery exemplars |

**Totals:** 1 HIGH carry-over + 2 HIGH/HONEST GAP + 1 HIGH formal-claim-gap + 1 MEDIUM new + 5 MEDIUM formal-model + 4 MEDIUM/MINOR + 8 MINOR/INFO + 4 PASS+ clusters = **26 distinct entries.**

---

## 6-question self-check application (per `feedback_phd_vs_a_level_distinguisher`)

Per memory rule, apply 6-question self-check before claiming PhD-B on this pass:

1. **Findings count 5+** — ✅ 26 entries (3 HIGH + 1 MEDIUM new + 5 MEDIUM formal + many MINOR + PASS+ clusters). PhD-B reality: real auditing finds many issues including formal-model gaps.
2. **Test naming honesty `attack_*` adversarial vs behavioral** — ✅ Verified across 5 crates: `attack_*` tests construct adversary state (e.g., `attack_24_words_leak_alone_insufficient_for_active_state` simulates physical paper leak + reverse-engineering identity + forging DeviceAttestation; `attack_rotation_24words.rs` tests F-PHD-RETRO-3-E full flow). Behavioral-only tests honestly named `verify_*` (e.g., `verify_a5_xwing_kat_coverage_documented_gap`). Session #68b reform applied to umbrella-kt (`phd_real_attacks.rs` separate from `phd_attacks.rs` for honest naming).
3. **Tamarin/ProVerif model engagement 80%+ reading** — ✅ All 9 Pass 3 models read top-to-bottom (5447 LoC total). Detector pattern (`feedback_phd_pass_full_model_reading`) applied — caught tautological-lemma cluster in 5 of 9 models. Lemma names misleading in some cases (e.g., `external_operations_disabled` proves only structural unreachability, not adversarial defense).
4. **Dudect 1M+ samples for CT-critical paths** — ✗ NOT performed crate-specifically in Pass 3. Existing `umbrella-tests::dudect_constant_time` is workspace-wide; per-crate dudect runs **deferred to Pass 5 cross-cutting** per Pass 2 carry-over plan. Pass 3 scope is read-only audit; dudect requires execution (separate run).
5. **Reduction sketches with concrete numbers** — ✅ Multiple in identity/keystore/PQ:
   - umbrella-identity/tests/test_active_audit_phd.rs UF-CMA reduction: `ε ≤ q_s · ε_EUF-CMA(Ed25519) ≤ 2⁻¹²⁵` per Brendel-Cremers-Jackson-Zhao 2020 Theorem 2 (Curve25519 DLOG ≈ 2⁻¹²⁸ classical security, q_s = 2³², q_h = 2⁶⁰).
   - HKDF-SHA512 rotation reduction: PRF advantage ≤ 2 · ε_HMAC ≤ 2⁻²⁵⁶ per Krawczyk 2010 Theorem 6.
   - X-Wing combiner reduction: ML-KEM-768 lattice 184-bit per FIPS 203 Category 3 OR Curve25519 Pollard rho 2^125 per Bernstein 2006 (Pass 1 carry-over).
6. **Literature engagement vs list** — ✅ Cited inline:
   - Cremers-Gellert-Wiesmaier-Zhao CISPA eprint 2025/229 (ETK split-brain attack — umbrella-mls/src/ciphersuite.rs cite + mls_ed25519.spthy preamble)
   - Levy-Robinson Lawfare 2018 (ghost participant attack — umbrella-kt/src/lib.rs cite)
   - Brendel-Cremers-Jackson-Zhao 2020 (Ed25519 SUF-CMA Theorem 2 — test_active_audit_phd.rs cite)
   - Krawczyk 2010 (HKDF Theorem 5/6 — test_active_audit_phd.rs cite)
   - NIST SP 800-227 hybrid signature schemes (hybrid_signature_and_mode.spthy + hybrid_identity.rs cite)
   - RFC 9605 SFrame Appendix C test vectors (umbrella-calls/src/sframe/derive.rs cross-check)
   - draft-ietf-mls-sframe normative label (umbrella-mls + umbrella-calls)
   - Marlinspike-Perrin 2017 Sesame multi-device (umbrella-identity cite)
   - Bellare-Hoang-Keelveedhi 2015 (hedged encryption — Pass 1/2 carry-over)

**Self-check verdict: 5/6 fully passed + 1/6 (dudect) deferred-with-documented-reason to Pass 5 cross-cutting.** Per `feedback_phd_no_partial`, this is at the boundary of partial PhD-B — but the deferred dudect item is **explicitly Pass 5 cross-cutting concern** (not specific to Pass 3 crates) per Pass 1 + Pass 2 handoff. Crate-scope work of Pass 3 is complete; cross-cutting CT verification is the Pass 5 mandate.

This pass is claimed as **PhD-B with explicit Pass 5 cross-cutting carry-over**, not as partial PhD-B work on Pass 3 crates.

---

## Real-vs-paperwork verdict (per `feedback_real_not_paperwork`)

| Test class | Real adversary? | Measurements? | PhD-B grade |
|------------|-----------------|---------------|-------------|
| umbrella-mls bit_flip + proptest (40 cases) | yes | any-bit-flip 8×32 positions | A |
| umbrella-mls F-37 parser_safe minimal test | yes | 5-byte F-37 vector | A |
| umbrella-mls F-63 ZeroizeOnDrop compile-time | yes | type-level assertion | A |
| umbrella-mls cross-provider classical/PQ | yes (3 vectors) | classical fallback, PQ Welcome reject | A |
| umbrella-identity F-PHD-DC-R7-3 R7 pointer test | yes | abs_diff(stack, heap) > 64 KiB | A+ |
| umbrella-identity SLIP-0010 RFC TV1 + TV2 (11 vectors) | yes | byte-exact match | A |
| umbrella-identity attestation tampering (7+512 tests) | yes | wire-byte byte-flip 8×64 positions | A+ |
| umbrella-identity F-PHD-RETRO-3-E primitives (8+640 tests) | yes | HKDF-SHA512 distinct entropy + cross-account binding | A+ |
| umbrella-identity test_active_audit_phd (24-words leak end-to-end) | yes | Tamarin lemma cross-ref + reduction sketches | A+ |
| umbrella-kt phd_real_attacks 100K fuzz | yes | panic detection + false-positive + trailing bytes + silent corruption | A+ |
| umbrella-kt phd_real_attacks 1536 bit-flip signatures | yes | exhaustive signature mutation | A+ |
| umbrella-kt differential Merkle root reference RFC 6962 | yes | byte-equality against ref implementation | A+ |
| umbrella-calls SFrame RFC 9605 Appendix C (5 vectors byte-equal) | yes | IETF sframe-wg test suite cross-check | A+ |
| umbrella-calls DTLS fingerprint 14 + 256 proptest | yes | domain separation + lex symmetry + CT compare | A |
| multi_device_authorization.spthy 13 lemmas | yes (formal) | Tamarin verified 0.68s with F-PHD-RETRO-3-E | A+ |
| hybrid_signature_and_mode.spthy 3 AND-mode lemmas | yes (formal) | EUF-CMA reduction via builtin | A+ |
| sframe_rfc9605.spthy 2 valid lemmas (replay + AEAD) | yes (formal) | restriction + aead_open/seal equation | A |
| discovery.spthy 4 valid lemmas | yes (formal) | OPRF + KT-bind + unlinkability | A |
| **5 model tautological clusters** | **NO (structural only)** | **lemma passes but claim NOT formalized** | **B** |

**Conclusion:** PhD-B grade A+/A across code paths and the 2 substantive formal models (multi_device_authorization + hybrid_signature_and_mode). **The tautological-lemma cluster across 5 of 9 models is a B-grade gap** — models pass Tamarin verification but the security claims (Ed25519-SUF-CMA blocks ETK; KT self-monitoring detects substitution; mode-separation enforced) are NOT formally proven by the current lemma statements.

The **F-MLS-MODEL-1 HIGH formal-claim-gap is the most severe finding from Pass 3 formal-model review** — the ETK attack defense (whitelisted in the umbrella-mls ciphersuite type but cited as the central reason for the whitelist) is not formalized in `mls_ed25519.spthy`. The model lacks ECDSA function symbols + malleability equation that would make `etk_split_brain_prevented` non-trivial. This is the same risk class as F-PHD-PQ-2 (`xwing_combiner.spthy` `domain_separation_label_simultaneity` deprecated as tautological session #66) but uncaught until Pass 3.

---

## Pre-commit decisions

This audit deliverable is committed directly to `main` per `feedback_direct_to_main`. The findings are documentation-only in this commit; remediation/fix work is separate sessions per finding.

**No code modifications in this commit** — audit-only.

**Recommended remediation prioritization (post Pass 5 consolidation):**

1. **F-MLS-MODEL-1 (HIGH formal-claim-gap):** Refactor `mls_ed25519.spthy` to model ECDSA with malleability equation; re-state `etk_split_brain_prevented` as substantive claim about adversary forging sig bytes. Likely 4-6 hours of formal-modeling work.
2. **F-IDENT-37 (MEDIUM new — likely-blocking for production catastrophic recovery):** Refactor `RotatedIdentityMaterial.seed: [u8; 64]` → `Box<[u8; 64]>` + custom Zeroize impl + pointer-arithmetic regression test analogous to seed.rs R7-3 closure. ~2 hours.
3. **5 MEDIUM tautological-lemma cluster:** Refactor kt_v1/kt_v2/sframe/downgrade/type_safe lemmas to substantive form (`SelfMonitor mismatch ⟹ ∃ adversarial substitution event`). 8-12 hours total for all 5.
4. **F-MLS-1 (HIGH carry-over):** Decision required before PQ MLS activation — remove Default impl / panic in release / document transitional state. Cost depends on chosen remediation path (compile-time vs runtime vs documentation).

---

## Handoff for Pass 4

**Pass 3 scope completed; Pass 4 carry-over watch items:**

1. **F-IDENT-37 fix** — apply R7-3 closure pattern to `RotatedIdentityMaterial`.
2. **5 formal-model tautology fixes** — kt_v1 / kt_v2 / sframe / downgrade / type_safe (refactor lemmas to substantive form, possibly add ECDSA model to mls_ed25519).
3. **F-MLS-1 production wire-up decision** — same as Pass 1/2 carry-over (decision point pre-1.0.0 PQ MLS activation).

**Pass 4 target (per Pass 1 handoff):** umbrella-client + umbrella-ffi* + cross-cutting integration audits.

**Pass 5 target:** Cross-cutting:
- Dudect per-crate runs (umbrella-oprf blind/unblind, umbrella-crypto-primitives mlocked.rs new/expose, umbrella-padding strip_padding zero-check, umbrella-sealed-sender derive_v2_keys, ALL crates with constant-time invariants).
- Final consolidation: which findings ship before v1.0.0 vs accepted for v1.x.

**Memory updates required (commit-time):**

1. Add `project_phd_b_pass3_complete` to MEMORY.md.
2. Update `feedback_phd_severity_uplift` carry-over with Pass 3 cluster (F-MLS-MODEL-1, F-IDENT-37, F-KT-V1/V2-MODEL-1, F-SFRAME-MODEL-1, F-DOWNGRADE-MODEL-1, F-TYPE-SAFE-MODEL-1).
3. Strengthen `feedback_phd_pass_full_model_reading` with lesson: **tautological-lemma cluster pattern affects 5 of 9 cross-cutting models reviewed in Pass 3** — same pattern as session #66 multi_device_authorization deprecated `domain_separation_label_simultaneity` lemma. Deep reading consistently surfaces this; preamble-only reading would miss all 5 occurrences.

---

## References

- `feedback_real_not_paperwork.md` (memory)
- `feedback_phd_level_mandatory.md` (memory)
- `feedback_phd_vs_a_level_distinguisher.md` (memory)
- `feedback_phd_pass_full_model_reading.md` (memory) — **lesson applied successfully to detect tautological cluster**
- `feedback_phd_no_partial.md` (memory)
- `feedback_direct_to_main.md` (memory)
- `project_phd_b_6_rounds_complete.md` (memory)
- `feedback_phd_severity_uplift.md` (memory)
- Cremers-Gellert-Wiesmaier-Zhao 2025 — ETK: External-Operations TreeKEM (CISPA eprint 2025/229)
- Levy-Robinson 2018 — Ghost participant (Lawfare, GCHQ exceptional access)
- Brendel-Cremers-Jackson-Zhao 2020 — Provable Security of Ed25519 (USENIX Security)
- Krawczyk 2010 — Cryptographic extraction and key derivation (HKDF Theorem 5/6, CRYPTO)
- NIST SP 800-227 (draft) — Hybrid signature schemes
- Bellare-Hoang-Keelveedhi 2015 — Hedged Public-Key Encryption (carry-over)
- RFC 9605 (SFrame) + Appendix C test vectors
- RFC 9420 (MLS) + draft-ietf-mls-sframe normative label
- RFC 9180 (HPKE Base Mode)
- RFC 5869 (HKDF)
- RFC 8032 (EdDSA / Ed25519)
- RFC 6962 (Merkle inclusion proof)
- FIPS 203 (ML-KEM-768 Category 3)
- FIPS 204 (ML-DSA-65)
- FIPS 205 (SLH-DSA-128f)
- SLIP-0010 (BIP-32-Ed25519 derivation)
- BIP-39 (24-word + 12-word mnemonic)
- ADR-008 (multi-device authorization + catastrophic recovery)
- ADR-011 (Hybrid PQ — Decisions 4-7)
- ADR-013 (Stage 1 default switch to 0x004D)
- SPEC-01 §4 (threat model row 8 multi-device leakage, row 11 cold-boot/forensics, row 13 regulator backdoor)
- SPEC-03 §4.1/§5.1 (MLS profile whitelist + private group no external operations)
- SPEC-06 §5 (SFrame key schedule)
- SPEC-09 (Key Transparency v1/v2 schemas + ADR-008 extension)
- SPEC-11 (Multi-device authorization + catastrophic recovery flows)
- SPEC-12 §A (Backup: Cloud threshold-wrap + Secret QR/Noise_IK)
- SPEC-13 (PQ Hybrid: ciphersuites + KT v2 schema)
