# PhD-B Hybrid PQ Hedged Encaps — Design Spec

**Date:** 2026-05-19 (third round)
**Predecessors:**
- Round 1: `2026-05-19-phd-b-hybrid-pq-audit-design.md` (paperwork findings)
- Round 2: `2026-05-19-phd-b-hybrid-pq-reality-pass-design.md` (real exploits)

**Goal:** Close R5.A / R5.B / R5.C from round 2 by implementing defense-in-depth against compromised CSPRNG.

## Why this round

Round 2 R5 demonstrated that compromised RNG = total break under current architecture (5/5 attacks succeed under that adversary model). Defense relied on (a) OsRng mandate and (b) grep-verified zero production callers of `xwing_encaps_derand`. Both are policy-level defenses, not algorithmic. User: "можем закрыть и эти дыры как то 5 из 5 ? даже если алгоритм как ты говоришь взломали". Answer: yes — partial closure via **hedged encryption** pattern (Bellare-Hoang-Keelveedhi 2015 "Cryptography from Compromised Randomness", Aranha-Orlandi-Takahashi-Zaverucha 2020 "Security of Hedged Fiat-Shamir Signatures"). This round implements it.

## Threat model upgrade

**Before this round:**
- Single compromise of OsRng → full break of all encaps operations on the device.

**After this round:**
- Single compromise of OsRng → **NO break** if long-term witness uncompromised.
- Single compromise of long-term witness → **NO break of past sessions** (forward secrecy via OsRng-derived material in past transcripts).
- Double simultaneous compromise (OsRng + long-term witness) → unavoidable break (fundamental limit).

Attacker now needs **two independent compromises** for a single-session break instead of one.

## Architecture

### Component 1 — Hedged seed derivation

Replace direct `rng.fill_bytes(&mut seed)` in production X-Wing encaps with:

```
seed = HKDF-SHA512(
    salt   = "umbrellax-xwing-hedged-encaps-v1",
    ikm    = rng_bytes (64) || hedged_witness (32),
    info   = transcript_hash (32) || recipient_pk_hash (32)
).expand_into([u8; 64])
```

Where:
- `rng_bytes` — output of CSPRNG (OsRng in production); preserves current behavior if witness ever zero.
- `hedged_witness` — 32-byte deterministic function of long-term identity secret, derived once at client bootstrap via HKDF(identity_sk, salt="umbrellax-hedged-witness-v1"). Stored in `SecretBox`. Never serialized.
- `transcript_hash` — SHA-256 of canonical AAD bytes for this operation (sender_identity || recipient_device || chat_id || msg_seq || version).
- `recipient_pk_hash` — SHA-256(recipient_xwing_pubkey).

Security claim: if any one of {rng_bytes, hedged_witness} is uncompromised (32 bytes uniform random), output seed is computationally indistinguishable from uniform per HKDF-SHA512 random oracle assumption.

### Component 2 — Physical isolation of derand API

`xwing_encaps_derand` is currently `pub` in `crates/umbrella-pq/src/xwing.rs`. Change to `pub(crate)`:
- Test access preserved via `#[cfg(test)]` re-export to integration test crate boundary.
- KAT test file (`tests/xwing_draft10_kat.rs`) needs explicit `#[cfg(feature = "kat-test-only")]` gate or in-tree re-export module.
- Result: downstream production crates physically cannot call derand path. R5.B closes by construction, not by grep policy.

### Component 3 — Hedged production API

New public function in `crates/umbrella-pq/src/xwing.rs`:

```rust
pub fn xwing_encaps_hedged<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &XWingPublicKey,
    hedged_witness: &HedgedWitness,
    transcript: &[u8],
) -> Result<(...)>;
```

Where `HedgedWitness` is a new type in `umbrella-pq/src/hedged.rs`:

```rust
pub struct HedgedWitness {
    bytes: SecretBox<[u8; 32]>,
}

impl HedgedWitness {
    pub fn derive_from_identity_secret(identity_sk: &[u8; 32]) -> Self { ... }
    pub fn zeroed_for_tests_only() -> Self { ... } // explicit testing API
}
```

### Component 4 — Production callsite migration

Search and replace direct `xwing_encaps` callsites in production code:
- `crates/umbrella-backup/src/cloud_wrap/pq_wrap.rs:wrap_v1_into_v2`
- `crates/umbrella-sealed-sender/src/hybrid_envelope.rs:seal_v2`
- Any MLS X-Wing provider callsites that aren't pure test code

Each callsite needs:
- Threaded `&HedgedWitness` parameter from KeyStore (loaded at bootstrap)
- Threaded transcript bytes (already have CanonicalAad — reuse it)

Old `xwing_encaps` stays in API as deprecated test-helper marker `#[deprecated(note = "use xwing_encaps_hedged in production")]` plus `#[allow(deprecated)]` only in test cfg.

### Component 5 — Storage for hedged_witness

`HedgedWitness` material lives in KeyStore alongside identity_sk:
- Derived once at bootstrap from identity_sk via HKDF (deterministic — survives restart, doesn't need persistence beyond identity_sk).
- Loaded at startup, held in memory in SecretBox.
- Zeroized on logout/rotation.
- Identity rotation (existing F-PHD-RETRO-3-E flow) regenerates hedged_witness automatically because it's a deterministic derivative of identity_sk.

## Real attack regression tests (mandatory)

For each R5 sub-attack, add `attack_*` test that:

1. **`attack_r5a_compromised_rng_alone_does_not_break_hedged_encaps`**
   - Inject deterministic RNG with attacker-known seed.
   - Honest hedged_witness still secret (fresh OsRng-derived for test setup).
   - Run `xwing_encaps_hedged` twice with same RNG seed but different transcripts.
   - Assert: outputs differ (transcript domain separation works).
   - Run with same seed AND same transcript.
   - Assert: outputs still pseudo-random under HKDF (cannot be predicted by attacker without hedged_witness).

2. **`attack_r5b_derand_api_inaccessible_from_downstream`** — compile-fail test:
   - Place test in `crates/umbrella-backup` (downstream of umbrella-pq).
   - Attempt to call `umbrella_pq::xwing_encaps_derand(...)`.
   - Assert: compilation fails (private function).

3. **`attack_r5c_multi_session_replay_blocked_by_transcript`**
   - Inject deterministic RNG.
   - Hedged_witness honest.
   - Run encaps for two different sessions (different chat_id in transcript).
   - Assert: shared_secrets differ.

4. **`attack_r5_double_compromise_unavoidable_break`** — explicit documented limit:
   - Inject deterministic RNG.
   - Pass attacker-known hedged_witness.
   - Assert: attacker recovers shared_secret (this is the fundamental limit; test exists to document it explicitly).

## Tamarin model update

Extend `crates/umbrella-formal-verification/models/xwing_combiner.spthy` with:

```
lemma hedged_encaps_unbreakable_with_partial_compromise:
    "All session_id ss #i.
        SharedSecret(session_id, ss) @ #i
      & (not Ex #c. RngCompromise() @ #c & #c < #i 
         & Ex #w. WitnessCompromise() @ #w & #w < #i)
      ==>
        not (Ex #k. K(ss) @ #k)"
```

i.e., adversary knows shared_secret only if BOTH rng and witness compromised before session. Verify with `tamarin-prover --prove`.

## Wire format compatibility

**No change to wire bytes.** Output of `xwing_encaps_hedged` is byte-identical structure to `xwing_encaps` (same ciphertext, same shared secret length). Only the *generation* of the inner seed changes. Receivers don't need any update — decapsulation path unchanged.

This is critical: live deployments don't see a protocol break.

## Acceptance gate

This round passes only when **all four** are true:

1. `xwing_encaps_hedged` exists and is the only production-callable encaps. `xwing_encaps_derand` is `pub(crate)`.
2. All production callsites migrated. `cargo build --release --all-features` green.
3. Four new `attack_r5*` tests pass:
   - r5a (single RNG compromise — protocol survives)
   - r5b (compile-fail downstream call to derand)
   - r5c (multi-session replay — transcript blocks)
   - r5_double_compromise (documented unavoidable break)
4. Tamarin lemma `hedged_encaps_unbreakable_with_partial_compromise` verifies.

## Workflow

1. Read round 2 report + R5 findings markdown.
2. Add `crates/umbrella-pq/src/hedged.rs` with `HedgedWitness` type.
3. Add `xwing_encaps_hedged` to `xwing.rs`. Change `xwing_encaps_derand` to `pub(crate)`.
4. Add HedgedWitness storage to KeyStore (KeyStore reads identity_sk → derives witness at bootstrap).
5. Migrate production callsites one-by-one with regression test after each.
6. Write four `attack_r5*` tests.
7. Extend Tamarin model + run prover.
8. Update report `docs/audits/phd-b-hybrid-pq-hedged-encaps-2026-05-19.md`.
9. Update ledger.
10. Commit per phase.

## Stop / handoff

Same rule as round 1 and 2 (memory `feedback_phd_no_partial`). Partial implementation = invalid. If subagent's context budget runs low before all 4 acceptance criteria met, write partial-state report, commit, hand off — do NOT claim complete.

## What does NOT count

- Adding hedged_witness parameter without changing `rng.fill_bytes` mixing into HKDF.
- Tamarin lemma that proves trivially.
- `attack_r5*` test that passes without actually testing the compromise scenario.
- Skipping the compile-fail test for `derand` API (R5.B physical closure is the whole point).
- Keeping `xwing_encaps_derand` as `pub` "for backward compatibility" (no users yet — this is the moment).

## Out of scope

- Hardware RNG composition (separate concern; can be future round if device-attestation track wants it).
- Forward-secret ephemeral identity rotation per-message (already covered by MLS ratchet + F-PHD-RETRO-3-E rotation).
- ML-KEM-768 standalone encaps (umbrella-pq exposes it but no production caller; only used inside X-Wing combiner via libcrux internals).

## Literature

- Bellare, Hoang, Keelveedhi 2015 — "Cryptography from Compromised Randomness" (Crypto 2015)
- Aranha, Orlandi, Takahashi, Zaverucha 2020 — "Security of Hedged Fiat-Shamir Signatures under Fault Attacks" (EUROCRYPT 2020)
- Krawczyk 2010 — "Cryptographic Extraction and Key Derivation: The HKDF Scheme" (Crypto 2010)
- draft-connolly-cfrg-xwing-kem-10 — X-Wing combiner spec
- RFC 5869 — HKDF
