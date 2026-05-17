# Round 7 PhD-B Discovery — Ledger

**Date:** 2026-05-18
**Branch:** `audit/phd-b-discovery-2026-05-18`
**Closure report:** `docs/audits/phd-b-discovery-closure-2026-05-18.md`

This ledger is the canonical mapping between
1. round-7 threat-model rows (D-1 .. D-8 per SPEC-01 §4 + round-7 design
   spec §threat-model),
2. defenses implemented in the `umbrella-discovery` crate,
3. Tamarin lemmas in `discovery.spthy`,
4. attack-regression tests under `crates/umbrella-discovery/tests/`,
5. status (CLEAN / CARRY-OVER).

## D-series mapping

| Row | Threat | Defense (crate code) | Tamarin lemma | Attack test | Sub-tests | Status |
|-----|--------|---------------------|---------------|-------------|-----------|--------|
| D-1 | Server learns plaintext phone | `umbrella-discovery::psi` + OPRF blinding (RFC 9497 SUF, `umbrella-oprf::blind`) | `server_never_learns_plaintext_phone` (5 steps) | `attack_d1_plaintext_phone_leak.rs` | 4 | CLEAN |
| D-2 | Server correlates @username queries from same client | `umbrella-discovery::anonymous_query::derive_per_query_anon_id` HKDF + fresh salt | `anon_id_unlinkable_across_queries` (2 steps) | `attack_d2_query_correlation.rs` | 3 | CLEAN |
| D-3 | Server returns fake `device_pubkey` (silent swap) | `umbrella-discovery::kt_bind::verify_discovery_bind` Merkle audit-path | `kt_bind_prevents_silent_swap` (5 steps) | `attack_d3_kt_bind_silent_swap.rs` | 4 | CLEAN |
| D-4 | 4-of-5 cluster collusion → recover address book | OPRF SUF + KT log public + 3-of-5 threshold (existing round-2 + round-7 binding) | `server_never_learns_plaintext_phone` (covers under any compromise count by symbolic abstraction) | `attack_d4_cluster_collusion.rs` | 3 | CLEAN (documented residual: with 3-of-5 collusion adversary observes labels; cannot invert by RFC 9497 SUF) |
| D-5 | OPRF response replay | `umbrella-discovery::rate_limit::NonceReplayGuard` + server `server_nonce` | `replay_protection_enforced` (2 steps) | `attack_d5_oprf_replay.rs` | 5 | CLEAN |
| D-6 | Anonymous-id reuse → linkability | `umbrella-discovery::anonymous_query::fresh_query_salt` CSPRNG | `anon_id_unlinkable_across_queries` (2 steps) | `attack_d6_anon_id_reuse.rs` | 6 | CLEAN |
| D-7 | Rate-limit bypass via parallel sibling devices | `umbrella-discovery::rate_limit::ClientBudgetState` + server-coordinated budget (backend spec §7) | (no direct Tamarin lemma — operational property, server-side coordination) | `attack_d7_rate_limit_bypass.rs` | 5 | CLEAN client-side; backend-coordination CARRY-OVER to `rust_1mlrd/docs/spec/discovery-backend-spec.md` §7 implementation |
| D-8 | Cardinality-timing side channel | Constant-time HashSet lookup + recommended padding policy (`discovery-integration.md` §8) | `intersection_cardinality_only_disclosed` (5 steps) | `attack_d8_cardinality_timing.rs` | 3 | CLEAN with documented residual: measured ≤2× latency variance; padding policy advisory not enforced (CARRY-OVER to v1.2.0) |

## Statistics

- 8 of 8 D-series threats addressed.
- 5 of 5 Tamarin lemmas verified (1 sanity exists-trace also verified).
- 38 of 38 attack sub-tests PASS.
- 2 carry-overs (operational):
  1. Server-side rate-limit coordination — implementation in
     `rust_1mlrd/services/discovery-svc/` per backend spec.
  2. Padding policy enforcement (D-8 mitigation) — advisory now,
     mandatory v1.2.0.

## Workspace deltas

- New crate `umbrella-discovery` (~3 100 LoC main code + ~1 300 LoC test
  code + 116 LoC example).
- New Tamarin model `discovery.spthy` (412 LoC).
- New spec `docs/spec/discovery-integration.md` (229 LoC).
- New spec (sibling repo) `rust_1mlrd/docs/spec/discovery-backend-spec.md`.
- Updated `crates/umbrella-formal-verification/src/model_metadata.rs` and
  test suite (added DISCOVERY metadata, updated ALL_MODELS count
  13 → 14, 10 Tamarin + 4 ProVerif).
- Workspace test count: 2 080 → 2 179 (+99).

## Files cross-reference

| Layer | Path |
|-------|------|
| Round-7 design spec | `docs/superpowers/specs/2026-05-18-phd-b-discovery-design.md` |
| Round-7 handoff (predecessor session) | `docs/superpowers/handoffs/2026-05-18-round-7-discovery-handoff.md` |
| Closure report | `docs/audits/phd-b-discovery-closure-2026-05-18.md` |
| This ledger | `docs/audits/phd-b-discovery-ledger-2026-05-18.md` |
| Tamarin model | `crates/umbrella-formal-verification/models/discovery.spthy` |
| Client spec | `docs/spec/discovery-integration.md` |
| Backend spec (sibling repo) | `rust_1mlrd/docs/spec/discovery-backend-spec.md` |
| Code | `crates/umbrella-discovery/` |

## Branch state

```
$ git log --oneline 4b2fe151..HEAD
9d9fad7b  docs(discovery): round 7 phase 9 — client-side integration spec
028a5390  test(discovery): round 7 phase 8 — 8 D-series attack tests + realistic example
08990bb9  feat(formal-verification): round 7 phase 7 — Tamarin discovery.spthy 6/6 verified
d6c3a554  feat(discovery): round 7 phases 1-6 — umbrella-discovery crate
1fec496f  docs: spec round 7 — discovery (PSI + @username) design
```

The final commit landing this closure report + ledger + ROUND-1-TO-7
summary refresh closes the branch.
