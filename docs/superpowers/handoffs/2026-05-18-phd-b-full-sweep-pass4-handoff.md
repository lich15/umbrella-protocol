# PhD-B Full Sweep — Pass 4 Handoff

**Date:** 2026-05-18
**Predecessors:**
- `docs/audits/phd-b-full-sweep-pass1-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md` + `phd-b-full-sweep-pass2-supplemental-2026-05-18.md`
- `docs/audits/phd-b-full-sweep-pass3-2026-05-18.md`
**Next session:** Pass 4 PhD-B audit of remaining crates + cross-cutting integration.

## Pass 3 result summary

**3 HIGH + 1 MEDIUM new + 5 MEDIUM formal-model + 11 MINOR/INFO + 4 PASS+ clusters = 26 distinct entries.**

Most severe:
- **F-MLS-1 (HIGH carry-over confirmed)** — 0 production callsites of `UmbrellaXWingProvider::new()` / `with_hedged_witness()` anywhere in umbrella-client / umbrella-ffi*. PQ MLS in transitional state.
- **F-IDENT-1 (HIGH/HONEST GAP)** — `InMemoryKeyStore` is the ONLY KeyStore impl in this codebase; no Secure Enclave/StrongBox FFI bridge exists yet. Documented as test-only but production users get this by default.
- **F-IDENT-2 (HIGH)** — `InMemoryKeyStore.seed: IdentitySeed` lives in process heap for keystore lifetime; capture allows derive of all device keys.
- **F-IDENT-37 (MEDIUM NEW)** — `RotatedIdentityMaterial.seed: [u8; 64]` is stack-resident, NOT `Box<[u8; 64]>` — regression of F-PHD-DC-R7-3 lesson from `IdentitySeed`. Catastrophic-recovery path stack-spills the rotated seed.
- **F-MLS-MODEL-1 (HIGH formal-claim-gap)** — `mls_ed25519.spthy` 3 lemmas tautological; ETK attack mitigation (citing Cremers eprint 2025/229) NOT formally proven.
- **5 MEDIUM tautological-lemma cluster** in kt_v1/kt_v2/sframe/downgrade/type_safe models — pass Tamarin verification but lemma is premise-restated-as-conclusion or model-structural unreachability.

Memory previously tracked F-MLS-1 (Pass 2 finding); newly surfaced in Pass 3: F-IDENT-37 + 5 MEDIUM formal-model cluster.

## Pass 4 scope

**Crates to PhD-B audit:**
- `crates/umbrella-client` (largest production-facing crate — facades over MLS + identity + KT + sealed-sender + backup + calls; contains DistributedIdentityClient per Round 6/7)
- `crates/umbrella-ffi` (FFI ABI 0.0.11 invariant per ADR-010)
- `crates/umbrella-ffi-kotlin` (Android JNI bridge)
- `crates/umbrella-ffi-swift` (iOS Swift bridge)
- `crates/umbrella-platform-verifier` (Play Integrity / DeviceCheck verifier)
- `crates/umbrella-server-blind-postman` (Postman idempotency server logic)
- `crates/umbrella-discovery` (Round 7 — Pass 1 covered, may have new code post-Pass 1)
- `crates/umbrella-threshold-identity` (Round 6 FROST DKG — Pass 1 covered, verify no regressions)

**Cross-cutting watch items:**

1. **F-MLS-1 production wire-up resolution decision** — same as Pass 2/3 carry-over. Decision point before any PQ MLS activation.
2. **Tautological formal-model cluster** — 5 MEDIUM findings in kt_v1/kt_v2/sframe/downgrade/type_safe models. Refactor lemmas to substantive form OR document model honestly as structural (not adversarial).
3. **F-MLS-MODEL-1 ETK formalization gap** — refactor `mls_ed25519.spthy` to add ECDSA function symbols with malleability equation; re-state `etk_split_brain_prevented` as substantive claim.
4. **F-IDENT-37 fix** — apply R7-3 closure pattern to `RotatedIdentityMaterial.seed: Box<[u8; 64]>` + Zeroize impl + pointer-arithmetic regression test.
5. **F-IDENT-1/2 production keystore decision** — InMemoryKeyStore is documented test-only but no production-grade KeyStore exists in this repo. Decide:
   - (a) Add Secure Enclave / StrongBox FFI bridge crate in this repo
   - (b) Document that downstream apps MUST implement KeyStore themselves (current state)
   - (c) Make `InMemoryKeyStore::open` `#[cfg(any(test, feature = "test-utils"))]`-gated with `test-utils` defaulting off

**Memory updates needed before Pass 4:**

1. Add `project_phd_b_pass3_complete` entry to MEMORY.md (one-line under 200 chars).
2. Update `feedback_phd_severity_uplift.md` to include Pass 3 findings cluster (F-MLS-MODEL-1 HIGH, F-IDENT-37 MEDIUM new, 5 MEDIUM tautology cluster).
3. Update `feedback_phd_pass_full_model_reading.md` with Pass 3 lesson:
   > Tautological-lemma cluster pattern affects 5 of 9 cross-cutting Tamarin/ProVerif models. Same pattern as session #66 `multi_device_authorization.spthy` deprecated `domain_separation_label_simultaneity` — lemma passes verification but premise restated as conclusion (commutativity of equality) OR proves structural unreachability rather than adversarial defense. Deep reading consistently surfaces; preamble-only reading misses.

## Key real-vs-paperwork bar (memory `feedback_real_not_paperwork`)

For each attack/phd test in Pass 4 crates, verify:

1. **Adversary really modelled?** Test should construct attacker state explicitly (e.g., compromised servers, captured wire bytes, lldb attached process, observable network state) — NOT just call public APIs and assert `Err(...)`.
2. **Real measurements?** queries-per-bit, seconds-per-evaluation, hits in N-byte memory scan, t-statistic, ops-to-exhaust — not just `.is_ok()` / `.is_err()`.
3. **Attack outcome quantified?** Either recovered material (bits / bytes) OR documented bound (computational complexity, queries needed). NOT silent passing.
4. **Formal-model lemma substantive?** Lemma premise must not be restated as conclusion through equality commutativity or tuple-position inspection. Test detector: does the lemma require Tamarin to do any non-trivial reasoning, or is the conclusion structurally derivable from the premise?

Exemplars from Pass 3 to emulate:
- multi_device_authorization.spthy 13 substantive lemmas with F-PHD-RETRO-3-E regression-guard
- hybrid_signature_and_mode.spthy 3 AND-mode lemmas with proper EUF-CMA reductions
- umbrella-kt/tests/phd_real_attacks.rs 100K fuzz + 1536 bit-flip + differential
- umbrella-calls SFrame RFC 9605 Appendix C byte-equal cross-check

## Crate-specific watch items for Pass 4

### umbrella-client (likely largest Pass 4 crate)
- DistributedIdentityClient (Round 6/7 — 24+12 words NEVER on device)
- core.rs facades over MLS + Identity + KT + SealedSender + Backup + Calls
- F-MLS-1 production wire-up — Pass 3 confirmed 0 callsites, verify Pass 4 deeper if new code added.
- compile_fail_secret_chat_no_cloud_sync.rs test (ADR-006 Variant C type-safety enforcement)
- ChatSettings + Negotiated ciphersuite selection (downgrade_resistance.spthy real impl)

### umbrella-ffi / umbrella-ffi-kotlin / umbrella-ffi-swift
- ABI 0.0.11 invariant per ADR-010 — backward compatibility
- HW Keystore callback path (per memory `project_phd_b_6_rounds_complete` last bullet about M-FINAL-1 legacy ephemeral seed disclosure)
- Verify FFI does NOT expose `IdentitySeed::generate` (Pass 3 finding F-IDENT-14: deprecated since 1.1.0 but pub fn — accessible from FFI?)
- Verify FFI does NOT instantiate `InMemoryKeyStore` directly in production paths (Pass 3 finding F-IDENT-1)

### umbrella-platform-verifier
- Play Integrity / DeviceCheck verification (Pass 2 supplemental covered umbrella-oprf attestation.rs)
- Real verifier vs test verifier separation

### umbrella-server-blind-postman
- Sealed Sender V2 Postman idempotency (closure for F-SS-2 Pass 2 HONEST GAP — same-recipient replay defense at backend layer)

### umbrella-discovery (Pass 1 covered; verify no regressions)
- 5 anon_ids per query (Pass 1 F-2 fix verification)
- PSI flow with 3-of-5 Sealed Servers
- KT-bind in discovery answer (Pass 1 D-3 closure)

### umbrella-threshold-identity (Pass 1 covered; verify no regressions)
- FROST DKG 3-of-5 (Pass 1 R20-R27 attack tests verified)
- HW Keystore integration (M-FINAL-1 disclosure)

## Context budget

Pass 3 session reached ~75% context after reading all 9 formal models + crates + writing report. Pass 4 likely needs separate session with fresh context per memory `feedback_context_60pct`.

**Pass 4 estimated scope:** 8 crates (umbrella-client + 3 FFI + platform-verifier + server-postman + discovery + threshold-identity). Likely 30-50k LoC across these crates. **May require split into Pass 4a + Pass 4b** depending on actual crate sizes.

## Stop / handoff conditions for Pass 4

- Achieves 60% context — commit state and handoff to Pass 4b.
- If PhD-B 6/6 not achievable per crate — close meaningful subset, remainder to handoff (per `feedback_phd_no_partial`: only full PhD-B or handoff).
- If another CRITICAL F-1/F-2/F-3-class finding OR HIGH F-MLS-1-class production-wire-up gap surfaces — commit immediately as stop-the-world and handoff (don't continue auditing other crates).

## Memory directives

- Pass 4 must read existing F-IDENT-37 + 5 tautology cluster reports before starting (Pass 3 main + this handoff).
- Pass 4 must apply tautological-lemma detector to any formal models added in Pass 4 scope (if any).
- Per `feedback_real_not_paperwork`: continue session #68b honest naming reform — split behavioral tests (rename to `verify_*`) from real attack tests (`attack_*` / `phd_real_attacks_*`).
- Per `feedback_phd_severity_uplift`: MINOR carry-overs may upgrade to MEDIUM/HIGH; tautology cluster is the new severity-uplift exemplar (lemma passes but doesn't prove claim).

## Stop / handoff

Pass 3 complete in this session. Commit Pass 3 audit report + Pass 4 handoff + MEMORY.md update directly to `main` per `feedback_direct_to_main` (one block = one commit, author Kirill Abramov, no Co-Authored-By: Claude per user rule).

Next session: open fresh context, read Pass 3 main + this handoff, execute Pass 4 — start with F-MLS-1 production wire-up final decision + F-IDENT-37 fix design + 5 tautology cluster refactoring plan.
