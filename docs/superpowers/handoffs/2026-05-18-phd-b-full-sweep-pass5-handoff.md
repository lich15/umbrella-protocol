# PhD-B Full Sweep — Pass 5 Handoff (Cross-cutting + Consolidation)

**Date:** 2026-05-18
**Predecessors:**
- `docs/audits/phd-b-full-sweep-pass1-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md` + supplemental
- `docs/audits/phd-b-full-sweep-pass3-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass4-2026-05-18.md`
**Next session:** Pass 5 = final consolidation + cross-cutting CT verification + remediation prioritization.

## Pass 4 result summary

**1 CRITICAL NEW + 2 HIGH/HONEST GAP NEW + 1 MEDIUM NEW + 3 carry-over (1 HIGH + 2 CRITICAL) + 6 PASS+ exemplars = 14 distinct entries.**

Most severe new finding: **F-FFI-2 CRITICAL** — `OnboardingHandle::unlock_with_pin` exposes 64 bytes of session key material (device_key + master_key) across the FFI boundary as hex strings via a production-named method.

## Aggregate finding catalogue (Pass 1 → Pass 4)

| Finding ID | Severity | Crate | Status |
|------------|----------|-------|--------|
| F-1 | CRITICAL | umbrella-client/src/keystore/distributed_identity_client.rs:148 | open |
| F-2 | CRITICAL | umbrella-client/src/keystore/distributed_identity_client.rs:250-263 | open |
| F-3 | CRITICAL | umbrella-discovery R23 BTreeMap arithmetic | open (Pass 1 finding, untouched in Passes 2-4) |
| F-4 | HIGH | umbrella-discovery / umbrella-threshold-identity R21 | open |
| F-MLS-1 | HIGH | umbrella-mls/src/provider/xwing.rs + 0 production callsites | open (Pass 1-4 carry-over) |
| F-IDENT-1 | HIGH/HONEST GAP | umbrella-identity/src/keystore.rs (InMemoryKeyStore only KeyStore impl) | open (Pass 3 finding) |
| F-IDENT-2 | HIGH | umbrella-identity/src/keystore.rs (seed lives in heap) | open |
| F-IDENT-37 | MEDIUM | umbrella-identity/src/code_recovery.rs:303 (RotatedIdentityMaterial stack-resident) | open (Pass 3 NEW) |
| F-MLS-MODEL-1 | HIGH formal-claim-gap | mls_ed25519.spthy (3 tautological lemmas) | open (Pass 3 NEW) |
| F-KT-V1-MODEL-1 | MEDIUM | kt_v1_self_monitoring.spthy (3 tautological) | open (Pass 3 NEW) |
| F-KT-V2-MODEL-1 | MEDIUM | kt_v2_self_monitoring.spthy (3 tautological) | open (Pass 3 NEW) |
| F-SFRAME-MODEL-1 | MEDIUM | sframe_rfc9605.spthy (2 of 4 tautological) | open (Pass 3 NEW) |
| F-DOWNGRADE-MODEL-1 | MEDIUM | downgrade_resistance.spthy (3 of 5 tautological) | open (Pass 3 NEW) |
| F-TYPE-SAFE-MODEL-1 | MEDIUM | type_safe_enforcement.spthy (3 of 4 tautological) | open (Pass 3 NEW) |
| F-FFI-2 | **CRITICAL** | umbrella-ffi/src/export/onboarding.rs:218-220 | open (Pass 4 NEW) |
| F-CLIENT-FACADE-1 | HIGH/HONEST GAP | umbrella-client/src/facade/{chat_common,cloud_chat,secret_chat}.rs | open (Pass 4 NEW) |
| F-CLIENT-HW-1 | HIGH/HONEST GAP | umbrella-client/src/keystore/hw_callback.rs + core.rs | open (Pass 4 NEW) |
| F-CLIENT-HW-2 | MEDIUM | umbrella-client/src/keystore/hw_callback.rs:511-525 | open (Pass 4 NEW) |
| F-SS-2 | HONEST GAP closure-pending | umbrella-sealed-sender + umbrella-server-blind-postman | partial closure on Postman replay HashSet (Pass 2 → Pass 4) |

**Open severity totals:** **3 CRITICAL** (F-1, F-2, F-FFI-2) + **5 HIGH** (F-MLS-1, F-IDENT-1, F-IDENT-2, F-CLIENT-FACADE-1, F-CLIENT-HW-1) + **1 HIGH formal-claim-gap** (F-MLS-MODEL-1) + **8 MEDIUM** (F-IDENT-37, F-CLIENT-HW-2, F-KT-V1/V2/SFRAME/DOWNGRADE/TYPE-SAFE-MODEL-1) = **17 open findings before v1.0.0 ship.**

## Pass 5 scope

### Primary deliverable: Dudect 1M+ samples cross-cutting

Per Pass 1-3 plan, Pass 5 is the cross-cutting CT verification round. Run per-crate dudect against:

1. **umbrella-oprf::blind / unblind** — Ristretto scalar mul over secret blinding factor; CT of group operation.
2. **umbrella-crypto-primitives::mlocked::MlockedSecret::new / expose** — Box allocation + libc::mlock invocation timing.
3. **umbrella-padding::strip_padding** — Postel-style zero-check over variable-length input (F-51 closure context, F-57 pattern recurrence).
4. **umbrella-sealed-sender::derive_v2_keys** — HKDF-SHA256 over secret IKM.
5. **umbrella-identity::keystore::hedged_encaps_witness** — derive_from_identity_seed over IdentitySeed::seed (heap-resident).
6. **umbrella-client::keystore::row_cipher::decrypt_row_zeroizing** — `subtle::ConstantTimeEq::ct_eq` on nonce (F-57 closure verification).
7. **umbrella-kt::merkle** — RFC 6962 inner+leaf prefix hashing under secret leaf inputs.
8. **umbrella-mls::group::AEAD decrypt** — openmls 0.8.1 path with `catch_unwind` workaround.

Each run: 1,000,000+ samples per primitive; t-statistic with confidence interval; comparison against constant baseline; t-value < 4.5 (Welch's threshold) for PhD-B pass.

### Secondary deliverable: Final consolidation report

`docs/audits/phd-b-final-consolidation-2026-05-19.md` (or current date):

1. **All-passes findings list** with severity / status / file paths.
2. **v1.0.0 ship/no-ship decision per finding:**
   - F-1, F-2, F-FFI-2 — CRITICAL, must fix before v1.0.0.
   - F-MLS-1 — HIGH, decision (compile-time gate / panic / CI grep / defer PQ MLS).
   - F-CLIENT-FACADE-1 — HIGH, Block 7.4 milestone (per existing roadmap).
   - F-CLIENT-HW-1, F-CLIENT-HW-2, F-IDENT-1, F-IDENT-2, F-IDENT-37 — HW Keystore production wire-up cluster (M-FINAL-1 v1.2.x track).
   - F-MLS-MODEL-1 + 5 MEDIUM formal-model tautology cluster — formal-modeling refactor cluster (~24-36 hours total).
3. **Severity uplift retrospective** — confirm Pass 1-4 severity categorizations stable:
   - F-FFI-2 was MINOR-pattern (comment-disclosed) → CRITICAL per `feedback_phd_severity_uplift` rule
   - F-3 was Pass 1 MINOR → CRITICAL per Pass 1 audit
   - F-1, F-2 were Pass 1 MINOR → CRITICAL per Pass 1 audit
   - Same pattern: comment-disclosed-but-uncompile-time-enforced placeholder = CRITICAL
4. **PhD-B grade per crate cluster:**
   - umbrella-mls: A (with HIGH carry-over F-MLS-1)
   - umbrella-identity: A+ (with HIGH/MEDIUM carry-overs F-IDENT-1/2/37)
   - umbrella-kt: A+
   - umbrella-calls: A+
   - umbrella-client: B (HIGH/HONEST GAP cluster F-CLIENT-FACADE-1 + F-CLIENT-HW-1)
   - umbrella-ffi: B (CRITICAL F-FFI-2)
   - umbrella-platform-verifier: A (honest-fail-closed placeholder)
   - umbrella-server-blind-postman: A
   - umbrella-discovery: B (CRITICAL F-3 carry-over)
   - umbrella-threshold-identity: A
   - umbrella-formal-verification: B (HIGH formal-claim-gap F-MLS-MODEL-1 + 5 MEDIUM tautological)

### Tertiary deliverables (optional, time-permitting)

1. **F-MLS-MODEL-1 formal-modeling fix** — refactor `mls_ed25519.spthy` to add ECDSA function symbols with malleability equation. Substantive `etk_split_brain_prevented` claim. ~4-6 hours formal-modeling.
2. **5 tautology-cluster fix** — kt_v1 / kt_v2 / sframe / downgrade / type_safe substantive lemma rewrites. ~8-12 hours total.
3. **F-IDENT-37 fix** — `RotatedIdentityMaterial.seed: Box<[u8; 64]>` refactor + pointer-arithmetic regression test analogous to `r7_closure_entropy_and_seed_are_heap_resident`. ~2 hours.

## Cross-cutting watch items for Pass 5

1. **F-FFI-2 CRITICAL severity confirmation** — verify Pass 5 reviewer agrees that comment-disclosed `unlock_with_pin` test rig leak is CRITICAL (same class as F-1). Memory `feedback_phd_severity_uplift` precedent supports.
2. **F-CLIENT-HW-1 vs F-IDENT-1 relationship** — both findings describe related gap: production cryptographic operations cannot use TEE. Pass 5 may consolidate into single finding cluster.
3. **F-1 / F-2 / F-FFI-2 round-7 design intent vs implementation reality** — confirm with design docs (SPEC-11 round-7 spec) that:
   - F-1: production threshold reconstruction should be Lagrange interpolation over Shamir 3-of-5 shares (not XOR).
   - F-2: anon-IDs should be issued server-side via OPRF (not derived locally on device from PIN).
   - F-FFI-2: production unlock_with_pin should return opaque session-handle (not device_key + master_key plaintext).
4. **Pass 5 dudect cross-check Pass 1-3 findings:** does any finding gain or lose severity under per-crate dudect measurements? (E.g., F-CALL-7 honest-gap about `prk_stack: GenericArray` stack-spill — under dudect on full pipeline, is timing observable?)

## Stop / handoff conditions for Pass 5

- Achieves 60% context — commit state and handoff to Pass 5b (consolidation).
- If formal-model refactoring (tertiary deliverable) exceeds context budget — defer to separate session, commit dudect + consolidation as Pass 5 primary deliverable.
- If dudect uncovers new HIGH/CRITICAL severity finding — commit immediately as stop-the-world and handoff (don't continue with other dudect runs).

## Memory directives

- Pass 5 must read all 4 prior pass reports + this handoff before starting.
- Pass 5 must run dudect with PhD-B sample count (1M+ per primitive), not A-level (10k-100k).
- Per memory `feedback_real_not_paperwork`: dudect t-statistic must be real measurement, not synthetic — measure actual library code paths, not isolated micro-benchmarks.
- Per memory `feedback_phd_severity_uplift`: continue applying severity uplift rule; any MINOR carry-over can upgrade to MEDIUM/HIGH/CRITICAL.
- Per memory `feedback_phd_no_partial`: only full PhD-B 6/6 self-check or handoff. Dudect partial (e.g. 3 of 8 primitives measured) is acceptable Pass 5a → Pass 5b split.

## Stop / handoff

Pass 4 complete in this session. Commit Pass 4 audit report + Pass 5 handoff + MEMORY.md update directly to `main` per `feedback_direct_to_main` (one block = one commit, author Kirill Abramov, no Co-Authored-By: Claude per user rule).

Next session: open fresh context, read all 4 prior pass reports + this handoff, execute Pass 5 — start with dudect cross-cutting runs + final consolidation report.
