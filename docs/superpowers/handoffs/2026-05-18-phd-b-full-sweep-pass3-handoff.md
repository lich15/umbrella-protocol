# PhD-B Full Sweep — Pass 3 Handoff

**Date:** 2026-05-18
**Predecessor:** `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md`
**Next session task:** Pass 3 PhD-B audit of priority-3 crates + Tamarin model reading + cross-cutting carry-overs

## Pass 2 result summary

**1 HIGH + 7 MINOR + 9 INFO + 4 DEFER = 21 distinct entries.**

Most severe: **F-MLS-1 (HIGH)** — `UmbrellaXWingProvider::new()` / `Default::default()` (umbrella-mls/src/provider/xwing.rs:459-485) silently fall back to `HedgedWitness::zeroed_for_tests_only()` with only doc-comment guard. **No production code anywhere in the workspace calls `with_hedged_witness()`** (grep returned only test-file callsites). PQ MLS provider is effectively not wired into production; if/when wired via `new()`, round-3 hedged-encaps closure is void at the MLS HPKE layer.

Other notable:
- F-OPRF-1 (MINOR): `BlindingState::zeroize()` is no-op by design; API contract violated for callers calling `.zeroize()` explicitly.
- F-OPRF-3 (MINOR): Strong Unlinkability claim has no explicit regression test.
- F-SS-3 (PASS+): R4 series in umbrella-sealed-sender is the exemplar of `feedback_real_not_paperwork` standard.
- F-CP-2/3 (MINOR): mlock failure silent in release; no `setrlimit(RLIMIT_MEMLOCK)` workspace-wide.
- F-PAD-1 (MINOR/INFO): dudect for padding strip explicitly deferred to block 10.24.

Memory previously tracked **none** of these findings — Pass 2 newly surfaces them.

## Pass 3 scope

**Crates to PhD-B audit:**
- `crates/umbrella-core`
- `crates/umbrella-mls` (non-R24 paths, plus deep production-wire-up investigation for F-MLS-1)
- `crates/umbrella-identity` (KeyStore, IdentitySeed, hw_callback)
- `crates/umbrella-kt` (Key Transparency)
- `crates/umbrella-calls`
- `crates/umbrella-formal-verification` (read all `.spthy` models in `models/`)

**Pass-2 deferred large reads:** **CLOSED via Pass-2 supplemental** (`docs/audits/phd-b-full-sweep-pass2-supplemental-2026-05-18.md`):
1. ~~`crates/umbrella-oprf/src/attestation.rs`~~ — closed, F-ATT-1/2/3 (PASS strong)
2. ~~`crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs`~~ — closed, F-SS-PHD-1/2/3 (PASS+ KCI + DS statistical exemplars)
3. ~~`crates/umbrella-backup/tests/phd_attacks_v2_wrapping.rs`~~ — closed, F-BACKUP-PHD-1/2/3 (PASS+ exhaustive bit-flip + AAD substitution)

**Pass-2 relevant Tamarin/ProVerif models:** **CLOSED via Pass-2 supplemental** — 7 models read top-to-bottom (xwing_combiner.spthy + sealed_sender_v1.pv + sealed_sender_v2.pv + oprf_ristretto255.pv + sealed_servers_threshold_3of5.spthy + sealed_servers_threshold_universal.spthy + backup_wrap_v2.pv). Notable findings:
- F-XWING-MODEL-1 (MINOR): hedged eseed abstracted as single value
- F-OPRF-PV-2 (MODEL GAP): combine_3 equation uses k_master ×3; real Shamir math covered in companion sealed_servers_threshold_3of5.spthy
- F-3OF5-1 + F-UNIV-1 (PASS+): real threshold property formally proved (universal pigeonhole)
- Multiple HONEST GAPs про model invariants, key-compromise epochs, replay defense layer separation — all documented honestly in model comments

**Cross-cutting Pass 3 mandates:**
1. **F-MLS-1 production wire-up resolution:** grep `umbrella-client`, `umbrella-ffi`, `umbrella-mls`, and `crates/umbrella-*/src/**` with broader patterns:
   - `with_hedged_witness`
   - `UmbrellaXWingProvider`
   - `hedged_encaps_witness`
   - Look for any indirect/dynamic dispatch via traits.
   If no production callsite exists, document the state as "PQ MLS not yet production-wired" and assign HIGH carry-over to a future stage. If callsites exist that Pass 2 missed, re-audit them for `with_hedged_witness` usage.

2. **Tamarin/ProVerif model reading** per memory `feedback_phd_pass_full_model_reading`:
   - Pass-2 supplemental covered 7 Pass-2-relevant models. **Pass 3 must read the remaining 9 models:**
     - `discovery.spthy` (umbrella-discovery — Pass 1 follow-up)
     - `downgrade_resistance.spthy` (cross-cutting)
     - `hybrid_signature_and_mode.spthy` (umbrella-pq hybrid sigs)
     - `kt_v1_self_monitoring.spthy` + `kt_v2_self_monitoring.spthy` (umbrella-kt)
     - `mls_ed25519.spthy` (umbrella-mls)
     - `multi_device_authorization.spthy` (umbrella-identity — 35 KB largest)
     - `sframe_rfc9605.spthy` (umbrella-calls)
     - `type_safe_enforcement.spthy` (umbrella-client + cross-cutting)
   - Cross-check lemma claims match what is actually proved. Apply same tautological-lemma detector as in supplemental (xwing_combiner.spthy historical lesson).

3. **Dudect per-crate runs:** add per-crate constant-time measurements for:
   - umbrella-oprf blind/unblind path (1M+ samples)
   - umbrella-crypto-primitives mlocked.rs `new` / `expose` allocation+lock path
   - umbrella-padding strip_padding zero-check (F-PAD-1 closure)
   - umbrella-sealed-sender derive_v2_keys path

4. **`feedback_phd_severity_uplift` cross-reference:** memory MINOR carry-overs may be CRITICAL under PhD-B sweep. Re-audit `project_phd_b_6_rounds_complete.md` carry-over list against Pass 3 crate code state.

## Key real-vs-paperwork bar (memory `feedback_real_not_paperwork`)

For each attack/phd test, verify:

1. **Adversary really modelled?** Test should construct attacker state explicitly (e.g., compromised servers, captured wire bytes, lldb attached process, observable network state) — NOT just call public APIs and assert `Err(...)`.
2. **Real measurements?** queries-per-bit, seconds-per-evaluation, hits in N-byte memory scan, t-statistic, ops-to-exhaust — not just `.is_ok()` / `.is_err()`. R4 series in umbrella-sealed-sender is the model to emulate.
3. **Attack outcome quantified?** Either recovered material (bits / bytes) OR documented bound (computational complexity, queries needed). NOT silent passing.

## Crate-specific watch items for Pass 3

### umbrella-core
- First standalone PhD-B audit. Identify entry-point traits (Client, MessageBus, etc.).
- Verify any cryptographic dispatch uses hardened paths.

### umbrella-mls (non-R24 + F-MLS-1)
- **Critical:** resolve F-MLS-1 production wire-up gap.
- Audit `OpenMlsProvider` integration, group key schedule, exporter secrets.
- Pass 2 noted `umbrella-mls/src/group.rs:709` uses `MlockedSecret` for group exporter — verify usage path.
- Read `tests/pq_downgrade_resistant.rs` for downgrade attack resilience.

### umbrella-identity
- KeyStore trait + InMemoryKeyStore + hw_callback path.
- `HedgedWitness::derive_from_identity_seed` call at `umbrella-identity/src/keystore.rs:377`.
- M-FINAL-1 ephemeral seed disclosure (memory `project_phd_b_6_rounds_complete.md` last bullet).
- IdentitySeed::generate deprecation since 1.1.0.

### umbrella-kt
- Key Transparency tree, pinned-pk swap defense, epoch root verification.
- Pass 1 covered D-3 KT-bind silent swap (umbrella-discovery side); Pass 3 covers KT primary implementation.

### umbrella-calls
- Voice/video calls SRTP + DTLS path.
- Verify post-quantum integration if applicable (or document as v1.2.0+ scope).

### umbrella-formal-verification
- **Read every .spthy from top to bottom** (memory `feedback_phd_pass_full_model_reading`).
- Existing models inventory should include `discovery.spthy` (412 LoC per Pass 1 handoff) + others.
- Check: rule definitions, lemma definitions, lemma proofs (or oracle/proof tactics), restrictions.
- Cross-check claimed properties against actual lemma statements.

## Pre-fix audit, post-fix audit ordering

**This audit (Pass 2) is read-only.** F-MLS-1 (HIGH) requires production wire-up decision — either intentional transition state (document) or production wire-up fix. F-OPRF-1 etc. (MINOR) require small code edits.

Recommended fix sequencing (after Pass 5 complete):
- Pass 5 final consolidation determines which findings ship before v1.0.0 vs accepted for v1.x.
- F-MLS-1 (HIGH) is **stop-the-world for PQ MLS activation** but NOT for current sealed-sender-only flow.
- F-OPRF-1 / F-OPRF-3 are 1-line fixes (one zeroize call + one regression test).
- F-CP-2 / F-CP-3 require systemic decision: enforce `setrlimit` at app init OR accept silent degradation OR add caller-side `is_locked()` checks at critical sites.
- F-PAD-1 closes when block 10.24 runs dudect for padding.

Pass 3 audit may proceed in parallel with F-* fix work, since Pass-3 crates don't share files with F-* findings.

## Context budget

Pass 2 session at handoff time: 60% of context used (Pass 1 reading + Pass 2 reading of 6 crates + report writing). Pass 3 should run in fresh session per memory `feedback_context_60pct` + `feedback_phd_no_partial` (no partial PhD-B).

Pass 3 estimated scope: 6 crates + 3 deferred large reads + Tamarin model reading + per-crate dudect runs. **This may exceed single-session context budget** — consider splitting Pass 3 into Pass 3a (umbrella-core/mls/identity/kt) + Pass 3b (umbrella-calls/formal-verification + 3 deferred large reads + dudect).

## Memory updates required

1. Add `project_phd_b_pass2_complete` — Pass 2 result summary entry in MEMORY.md
2. Update `feedback_phd_severity_uplift` carry-over (added F-MLS-1 HIGH).
3. Update `project_phd_b_6_rounds_complete.md` to note F-MLS-1 as new HIGH carry-over.

## Stop / handoff

Pass 2 complete in this session. Commit Pass 2 audit report + Pass 3 handoff + MEMORY.md update directly to `main` per `feedback_direct_to_main` (one block = one commit, author Kirill Abramov, no Co-Authored-By: Claude per user rule).

Next session: open fresh context, read this handoff + Pass 2 report, execute Pass 3 — start with F-MLS-1 production wire-up resolution as priority-1 task.
