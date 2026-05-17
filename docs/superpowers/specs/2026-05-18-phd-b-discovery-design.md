# Round 7 — Discovery (PSI + @username) Design Spec

**Date:** 2026-05-18
**Predecessors:** rounds 1-6 (merged PR #6, commit `84b4d576` + docs refresh `4b2fe151`)
**Handoff source:** `docs/superpowers/handoffs/2026-05-18-round-7-discovery-handoff.md`

**Goal:** Add private contact discovery to Umbrella Protocol such that:
- Server **never learns** a user's address book in plaintext
- Client learns **only** intersection (who in their contacts is already on Umbrella)
- Username lookup (`@handle → device_pubkey`) is unlinkable across queries
- KT (Key Transparency) binds discovery answer — server cannot silently swap mapping
- 1-2 of 5 servers compromised → discovery still private

## Scope split (per user instruction)

- **Code:** only in `Umbrella Protocol` repo
- **Spec for backend:** in `Umbrella Protocol/docs/spec/discovery-integration.md` + sibling `rust_1mlrd/docs/spec/discovery-backend-spec.md`
- **NO code in `rust_1mlrd/services/`** — backend team implements per spec

## Threat model

Adversary D from SPEC-01 §4 + new D-discovery rows:

| Row | Threat |
|-----|--------|
| D-1 | Server learns plaintext phone numbers from blinded queries |
| D-2 | Server correlates @username queries from same client across time |
| D-3 | Server returns fake `device_pubkey` for queried handle (silent swap) |
| D-4 | 4-of-5 server cluster collusion still cannot recover address book |
| D-5 | Replay of OPRF response to a different query |
| D-6 | Anonymous-id reuse across queries → linkability |
| D-7 | Rate-limit bypass via parallel queries from sibling devices |
| D-8 | Timing side-channel from intersection-cardinality leak |

## Architecture

### Component 1 — PSI protocol choice

**Decision: RFC-style OPRF-PSI** (Pinkas-Rosulek-Trieu-Yanai 2018) using existing `umbrella-oprf` crate.

**Rationale:**
- Reuses already-attack-tested OPRF primitive (Ristretto255, RFC 9497)
- Linear in set size — acceptable for typical address book (200-500 contacts)
- Avoids cuckoo-filter + garbled-circuit complexity (Kales-Rindal-Rosulek-Trieu-Yanai 2019 — 100MB+ bandwidth for 500 contacts)
- Compatible with our existing 5-Sealed-Servers threshold model
- Easier formal verification

**Alternative considered & rejected:** Apple-style PSI-CA (Cuckoo + Garbled Circuit). Faster query latency but 50× bandwidth and harder threshold-distributed.

### Component 2 — Username lookup

Separate from PSI; uses **OPRF anonymous query**:

1. Client hashes `@handle` → blinds via OPRF
2. Sends blinded query to 3 of 5 Sealed Servers (threshold)
3. Servers respond with OPRF evaluation
4. Client unblinds → derives query key
5. Servers look up `(query_key → encrypted_record)` table
6. Client decrypts with OPRF-derived key

Servers never see plaintext `@handle`. Anonymous-id derivation from round 6 (`umbrella-threshold-identity::anonymous_id`) provides per-query unlinkability.

### Component 3 — KT bind for discovery answer

Discovery response must include KT inclusion proof. Server cannot silently swap `(handle → device_pubkey)` because:
1. KT log is append-only, public
2. Inclusion proof = Merkle path in KT log
3. Client verifies path → if forged, doesn't match KT root → reject

Reuses `umbrella-kt` existing KT-witness infrastructure.

### Component 4 — Rate-limit + replay

OPRF context already has server-nonce replay rejection (`umbrella-oprf`). Discovery extends with:
- Per-client request budget (e.g., 100 lookups / hour)
- Threshold-coordinated rate state across 5 servers (avoid bypass via sibling devices)
- Exponential backoff after burst

### Component 5 — Sealed-Sender compatibility

First-contact via discovery returns **minimum** needed for Sealed Sender V2 envelope:
- `device_pubkey` (X-Wing + Ed25519 pair)
- `kt_inclusion_proof`
- Anonymous account ID for routing

Does NOT return full device list — that comes after first envelope succeeds.

## Acceptance gate

All 7 must PASS:

1. **PSI implementation:** `umbrella-discovery::psi` works end-to-end with 5 mock Sealed Servers. Test: client with 500 contacts, server with 1M registered users → intersection cardinality correct, no plaintext leak measured.

2. **Username lookup:** `umbrella-discovery::username_lookup` works end-to-end. Test: 1000 lookups from same client → no two queries produce identical anonymous_id (unlinkability).

3. **KT bind:** discovery response without valid KT inclusion proof → client rejects. Test: forged response → `DiscoveryError::KtBindFailed`.

4. **Threshold model:** discovery query with only 3 of 5 servers responding → success. Test: 2 of 5 timeout / fail → 3 honest succeed.

5. **`cargo test --release --workspace --all-features` green.** Test delta from 2080 → expected ~2120+ (40 new discovery tests).

6. **8 D-series attack tests** in `crates/umbrella-discovery/tests/attack_d{1..8}.rs` all PASS (regression tests that attack is blocked).

7. **Tamarin model** `crates/umbrella-formal-verification/models/discovery.spthy` verifies 5 lemmas:
   - `server_never_learns_plaintext_phone`
   - `intersection_cardinality_only_disclosed`
   - `kt_bind_prevents_silent_swap`
   - `anon_id_unlinkable_across_queries`
   - `replay_protection_enforced`

## File map

### Code in `Umbrella Protocol/`

```
crates/umbrella-discovery/                  ← NEW crate
├── Cargo.toml
├── src/
│   ├── lib.rs                              — public API
│   ├── psi.rs                              — OPRF-PSI protocol
│   ├── username_lookup.rs                  — @handle → device_pubkey
│   ├── anonymous_query.rs                  — per-query anon-id derivation
│   ├── kt_bind.rs                          — KT inclusion proof verify
│   ├── rate_limit.rs                       — per-query budget tracking (client-side)
│   ├── error.rs                            — DiscoveryError enum
│   └── wire.rs                             — wire formats (request/response)
├── tests/
│   ├── attack_d1_plaintext_phone_leak.rs
│   ├── attack_d2_query_correlation.rs
│   ├── attack_d3_kt_bind_silent_swap.rs
│   ├── attack_d4_cluster_collusion.rs
│   ├── attack_d5_oprf_replay.rs
│   ├── attack_d6_anon_id_reuse.rs
│   ├── attack_d7_rate_limit_bypass.rs
│   ├── attack_d8_cardinality_timing.rs
│   └── psi_correctness.rs                  — happy-path correctness
└── examples/
    └── psi_realistic_scenario.rs           — 500 contacts vs 1M registered

crates/umbrella-formal-verification/models/
└── discovery.spthy                         ← NEW Tamarin model

docs/spec/
└── discovery-integration.md                ← NEW — backend integration contract
```

### Spec in `rust_1mlrd/`

```
rust_1mlrd/docs/spec/
└── discovery-backend-spec.md               ← NEW — what backend must implement
```

**Note:** the file in `rust_1mlrd/docs/spec/discovery-backend-spec.md` is a spec document only. NO code in `rust_1mlrd/services/`.

## Anti-paperwork enforcement

Per memory `feedback_real_not_paperwork`:

- Tamarin lemma alone ≠ closed. Must be paired with `attack_d*` test that exercises the property end-to-end.
- 8 `attack_d*` tests MUST attempt the real attack and assert the protocol blocks it. NO behavioral boundary tests with adversarial naming.
- Wire formats must be real bytes serializable to Vec<u8>, not abstract types.
- PSI correctness verified with realistic numbers (500 contacts, 1M registered) not toy 5 vs 10.
- Bandwidth + latency measured: should be ≤1 MB and ≤2 seconds for typical query on macOS dev host.

## 6-question PhD-B self-check (must apply before claiming closure)

1. **Findings count ≥ 5:** at least 5 closed findings in `attack_d*` regression tests
2. **`attack_*` adversarial naming:** all D-series tests in `attack_d{1..8}.rs` with end-to-end real-attack scenarios
3. **Tamarin engagement ≥ 80%:** read full `discovery.spthy` line-by-line, verify lemma names match what they prove (not tautological)
4. **dudect 1M samples for CT-critical:** OPRF blind / unblind operations measured if not already covered by round 2
5. **Reduction sketches with concrete numbers:** IND-CPA reduction for OPRF-PSI under DDH, bandwidth bound, time bound, intersection-cardinality leak quantified
6. **Literature 5+ citations:** Pinkas-Rosulek-Trieu-Yanai 2018, Kales-Rindal-Rosulek-Trieu-Yanai 2019, Lindell 2017 PSI survey, Hazay-Lindell 2010, Kissner-Song 2005, RFC 9497, plus comparison to Apple PSI-CA and Signal SGX-based discovery

## Implementation phases (single subagent, ~24-30 hours estimated)

**Phase 1 — Crate scaffolding + protocol design (~3h):**
- Create `umbrella-discovery` crate with Cargo.toml
- Define wire formats (PSI request/response, username lookup, KT bind)
- Define error enum
- Add to workspace members + workspace dependencies

**Phase 2 — Anonymous query primitive (~4h):**
- Per-query anon-id derivation (reuse round-6 HKDF pattern)
- Blinded query construction
- Server response unblinding

**Phase 3 — OPRF-PSI protocol (~6h):**
- Client: hash contacts → blind via OPRF → batch request
- Server-side simulator: OPRF evaluation → response
- Client: unblind → derive query keys → match against server table → extract intersection
- Realistic scenario test: 500 vs 1M

**Phase 4 — Username lookup (~3h):**
- Client: blind @handle → query → unblind → derive key → decrypt record
- Server-side simulator: encrypted record table
- Unlinkability test (1000 queries → distinct anon-ids)

**Phase 5 — KT bind (~3h):**
- Discovery response includes KT inclusion proof
- Client verifies path against current KT root
- Mismatched proof → reject

**Phase 6 — Rate limit + replay (~2h):**
- Client-side budget tracking
- Server-coordinated threshold state (simulator)
- Exponential backoff

**Phase 7 — Tamarin model (~3h):**
- Write `discovery.spthy` with 5 lemmas
- Run prover with sufficient budget
- Read full model line-by-line (memory rule `feedback_phd_pass_full_model_reading`)

**Phase 8 — 8 D-series attack tests (~4h):**
- D-1 plaintext leak: server-side simulator records all queries → verify no plaintext
- D-2 correlation: 100 queries → distinct anon-ids verified
- D-3 KT swap: forged response → KtBindFailed
- D-4 4-of-5 collusion: 4 corrupt servers → still no plaintext
- D-5 OPRF replay: capture response, replay → server rejects
- D-6 anon-id reuse: two queries with same anon-id → verify cannot happen by construction
- D-7 rate-limit bypass: parallel queries from 5 sibling devices → server-coordinated rate limit triggers
- D-8 cardinality timing: 0 vs 1 vs 500 intersection size → measure latency variance, document leak

**Phase 9 — Integration spec (~2h):**
- `docs/spec/discovery-integration.md` in `Umbrella Protocol`
- `rust_1mlrd/docs/spec/discovery-backend-spec.md` in `rust_1mlrd`
- API contract: RPC names, request/response formats, error semantics, rate limit policy

**Phase 10 — Closure report + ledger (~2h):**
- `docs/audits/phd-b-discovery-closure-2026-05-XX.md`
- `docs/audits/phd-b-discovery-ledger-2026-05-XX.md`
- 6/6 PhD self-check honest
- Update `docs/audits/ROUND-1-TO-6-SUMMARY.md` → ROUND-1-TO-7

## Stop / handoff

Per memory `feedback_phd_no_partial` + `feedback_context_60pct`:
- If context budget approaches 60% own 1M → document partial state, handoff, NOT partial-PhD claim
- Each phase atomic — partial commits acceptable if phase boundary
- Phase 7 (Tamarin) is the highest risk for non-termination — set 1h wall-clock budget per lemma, then mark as carry-over with explicit numerical result

## Branch + PR strategy

Per memory `feedback_direct_to_main`:
- One block = one commit to main
- For round 7 size (~30h work, ~50+ files), use feature branch `audit/phd-b-discovery-2026-05-18` + PR + admin-bypass merge
- Mirror round-6 pattern (PR #6)

## What does NOT count

- Tamarin lemma without paired `attack_d*` test
- PSI implementation that only handles 5 vs 10 contacts (toy)
- KT bind that returns `Ok(())` always (mock placeholder)
- Anonymous-id reuse tolerated (must be unlinkable by construction)
- Skipping cardinality-leak measurement (D-8) just because it's hard to bound

## What is OUT of scope

- Real production deployment to 5 servers in different jurisdictions (operational)
- Real SMS-provider integration (operational)
- @username squatting policy (operational, business)
- Federation with non-Umbrella discovery servers (future round 8+)
- Group discovery (find a group by name) — different threat model, separate round

## Literature for citations in closure report

- Pinkas, Rosulek, Trieu, Yanai 2018 — "SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension" (Crypto 2018)
- Kales, Rindal, Rosulek, Trieu, Yanai 2019 — "Mobile Private Contact Discovery at Scale" (USENIX Security 2019) — Apple's PSI-CA
- Lindell 2017 — "How to Simulate It — A Tutorial on the Simulation Proof Technique" (foundational for PSI proofs)
- Hazay, Lindell 2010 — "Efficient Protocols for Set Intersection and Pattern Matching with Security Against Malicious and Covert Adversaries"
- Kissner, Song 2005 — "Privacy-Preserving Set Operations" (foundational)
- RFC 9497 — "Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups"
- Signal Blog 2017 — "Private Contact Discovery for Signal" (SGX-based, what we DON'T use)
- Apple Engineering 2021 — "Apple PSI System" (CSAM detection PSI, similar primitives)
