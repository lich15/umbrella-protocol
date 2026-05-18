# PhD-B 5-pass cycle closed — Remediation handoff

**Date:** 2026-05-18
**Predecessor:** `docs/audits/phd-b-final-consolidation-2026-05-18.md` (Pass 5 final consolidation report)
**Status:** 5-pass PhD-B full sweep audit cycle complete. Next sessions = remediation work per finding cluster.

## 18 open findings — remediation priority order

Per `docs/audits/phd-b-final-consolidation-2026-05-18.md` §3 (v1.0.0 ship/no-ship decision matrix), the recommended order for next sessions is:

### Track A — v1.0.0 ship-blockers (4 CRITICAL — ~14-20h total, can split per finding)

1. **F-FFI-2 fix session (~3-4h)** — recommended first because the cleanest scope:
   - File: `crates/umbrella-ffi/src/export/onboarding.rs:202-222`
   - Split `OnboardingHandle::unlock_with_pin` into production (returns `UnlockResultFfi { identity_pk_hex, session_handle: String }` UUID) + `#[cfg(any(test, feature = "test-utils"))]`-gated `unlock_with_pin_for_test_rig`
   - Internal `HashMap<SessionId, UnlockSession>` in `OnboardingHandle` keeps live MlockedSecret-wrapped session keys
   - Update all subsequent FFI methods (if any) to accept `session_handle` lookup
   - Existing `attack_phd4_f_ffi2_hex_copy_survives_mlocked_secret_zeroize` + `attack_phd4_f_ffi2_utf8_bytes_persist_independently_of_source_string` should START FAILING — signal exploit closed
   - Add new positive regression tests for production session-handle round-trip + UTF-8 byte non-exposure invariant

2. **F-1 fix session (~4-6h)** — XOR-combine to Lagrange interpolation:
   - File: `crates/umbrella-client/src/keystore/distributed_identity_client.rs:148`
   - Read round-7 design spec at `docs/specifications/SPEC-11-*.md` for exact interpolation parameters
   - Replace XOR loop with proper Shamir Lagrange over GF(p) (use `umbrella-oprf` Scalar arithmetic if applicable, OR pull existing `umbrella-threshold-identity::signing::aggregate` for share aggregation)
   - Existing `attack_phd4_f1_xor_linearity_breaks_shamir_threshold_property` should START FAILING
   - Add new positive test: 3-of-5 with different quora yield identical secret (combined_a == combined_b)

3. **F-2 fix session (~6-8h + backend coordination)** — anon-IDs server-side OPRF:
   - File: `crates/umbrella-client/src/keystore/distributed_identity_client.rs:250-263`
   - Replace local `Hkdf::<Sha256>::new(...).expand(...)` with OPRF client call via `umbrella-oprf::client`
   - Device sends `BlindedRequest(PIN)` → server returns `ServerEvaluation` → device unblinds via `client.finalize` → result IS the anon-id
   - Server backend coordination required for OPRF endpoint provisioning (Sealed Servers infrastructure)
   - Existing `attack_phd4_f2_anon_ids_independently_derivable_from_pin_plus_salt` should START FAILING

4. **F-3 decision session (~30min OR ~40-80h)**:
   - Option A (light): Remove `crates/umbrella-discovery/tests/attack_r23_5_registry_detects_fake_version.rs` until real integration. Update test inventory in Cargo.toml + remove related fixtures. ~30 min cleanup.
   - Option B (heavy): Implement real Sigstore Rekor (cosign verify-blob via rekor.sigstore.dev) + Certificate Transparency log lookup + alternative jurisdiction mirror probing + p2p attestation network. ~40-80h engineering + backend services.
   - Recommendation: Option A for v1.0.0 ship; Option B to v1.1.x supply-chain hardening track.

### Track B — v1.0.0 quick fixes (recommended pre-ship, ~6-10h total)

5. **F-MLS-1 decision + fix (~2-4h)**:
   - File: `crates/umbrella-mls/src/provider/xwing.rs:459-485`
   - Choose: (a) remove `Default::default()` impl + make `new()` `#[cfg(test)]`-gated; (b) `panic!()` in release builds; (c) CI grep check
   - Recommendation: Option (a) compile-time enforcement is strongest — Force production callers through `with_hedged_witness(witness)`

6. **F-IDENT-37 quick fix (~2h)** — `RotatedIdentityMaterial.seed: [u8; 64]` → `Box<[u8; 64]>`:
   - File: `crates/umbrella-identity/src/code_recovery.rs:303`
   - Apply F-PHD-DC-R7-3 pattern from `IdentitySeed.seed`
   - Add `Box<[u8; 64]>` field + custom `Zeroize`/`Drop` impl
   - Construct via `Box::new(...)` in `derive_rotated_identity_material:389`
   - Add pointer-arithmetic regression test analogous to `r7_closure_entropy_and_seed_are_heap_resident` (abs_diff(stack_anchor, seed.as_ptr()) > 64 KiB)

### Track C — v1.0.x investigation cluster (~2-4h)

7. **F-DUDECT-HKDF-BORDERLINE-1 + F-DUDECT-METHODOLOGY-1 + F-DUDECT-PADDING-OBSERVATION-1 investigation**:
   - Apply Site 6 RowCipher cache-bounded-pool pattern (32 fixtures L1d-resident) to Site 2 HKDF + Site 3 baseline + Site 4 padding_strip
   - Re-run 1M samples on macOS arm64
   - If |t| > 4.5 persists after pool bounding → upstream RustCrypto investigation (hmac/subtle)
   - If |t| drops below 4.5 → close as measurement methodology artifact, calibrate in-block guard threshold per operation timing scale

### Track D — v1.1.x Block 7.4 facade wire-up (HIGH F-CLIENT-FACADE-1, ~outside PhD-B scope)

8. **Block 7.4 milestone** — Wire `send_mls_text` / `fetch_inbox` / `add_participant` / `remove_participant` / `cloud_sync_history` through real implementations. ClientCore::new_with_http2 wire-up to `build_production_http2_client(config, &production)` already fully functional per F-HTTP2-1 PASS+ in Pass 4 supplemental.

### Track E — v1.2.x HW Keystore cluster (5 findings, ~20-30h)

9. **M-FINAL-1 tracking — F-IDENT-1 + F-IDENT-2 + F-CLIENT-HW-1 + F-CLIENT-HW-2 + F-IDENT-37**:
   - Refactor `core.identity: Arc<IdentityKey>` to `Option<Arc<IdentityKey>>` — eliminate ephemeral seed synthesis at `core.rs:421-424`
   - Wire signing paths (`UmbrellaIdentitySigner`, `UmbrellaDeviceSigner`, sealed-sender, MLS) through `core.hw_callback.sign_identity(handle, data)` if `core.has_hw_identity()`
   - Add `verifying_key(handle)` method to `PersistentKeyStoreCallback` trait. iOS: `SecKeyCopyPublicKey(handle)`. Android: `KeyStore.getCertificate(alias).publicKey`
   - Update `bootstrap_hw_identity` returns real verifying-key
   - Implement `HwBackedKeyStore: KeyStore` to replace `InMemoryKeyStore` in production paths

### Track F — Post-1.0.0 formal-modeling cluster (6 findings, ~16-24h)

10. **F-MLS-MODEL-1 + 5 tautology cluster** — Refactor lemmas to substantive form:
    - `mls_ed25519.spthy`: add ECDSA function symbol with malleability equation; re-state `etk_split_brain_prevented`
    - `kt_v1/v2_self_monitoring.spthy`: replace tautological `not(A=B) ⟹ not(B=A)` with causal `SelfMonitor mismatch ⟹ ∃ AdversarySubstitute event before`
    - `sframe_rfc9605.spthy`: replace 2 hash-determinism lemmas with MITM substitution attempts
    - `downgrade_resistance.spthy`: add adversary capability-strip rule with substantive post-condition
    - `type_safe_enforcement.spthy`: add adversary cross-mode access attempt rule

### Track G — Post-1.0.0 test rebuild (1 HIGH, ~4-6h)

11. **F-4 R21 attack test rebuild** — Build real client-server test rig with 5 separate `AccountState` + mocked transport requiring FROST signature on UNRECOVERABLE_DELETE.

## Memory updates required

Memory `project_phd_b_pass5_complete.md` already records Pass 5 completion. After each remediation session, update relevant memory entries:

- Track A session 1 (F-FFI-2 fix): update `project_phd_b_pass5_complete.md` F-FFI-2 status to «closed in commit XX, attack_phd4_f_ffi2_* now fails (exploit closed)»
- Track A session 2 (F-1 fix): same pattern for F-1
- Track A session 3 (F-2 fix): same pattern for F-2 + backend coordination note
- Track A session 4 (F-3 decision): record decision Option A vs Option B + cleanup commit OR roadmap entry
- Track B sessions: same pattern for F-MLS-1 + F-IDENT-37
- Tracks C-G similarly per finding

## Stop conditions per memory chain

- Per `feedback_context_60pct`: work to 60% context, then handoff
- Per `feedback_phd_no_partial`: full PhD-B 6/6 self-check claim on each remediation OR honest «remediation not PhD-grade test rebuild» disclosure
- Per `feedback_real_not_paperwork`: each fix must include working regression test demonstrating exploit closure (existing attack_phd4_* tests transition from PASS to FAIL after fix)
- Per `feedback_direct_to_main`: one fix = one commit in main; author Kirill Abramov; no Co-Authored-By: Claude

## How to start a remediation session

1. Choose track (A/B/C/D/E/F/G) and specific finding ID
2. Read this handoff + `docs/audits/phd-b-final-consolidation-2026-05-18.md` §6 remediation roadmap for that finding
3. Read affected source files + existing tests
4. Apply fix
5. Run affected test suite + verify attack_phd4_* transitions if applicable
6. Apply 6-question self-check before commit
7. Single commit to main with descriptive message
8. Update memory entry for the finding

End of Pass 5 handoff. The 5-pass PhD-B full sweep cycle 2026-05-18 is formally complete; next work begins from remediation tracks above.
