# R2 — Real MITM exploit findings

**Date:** 2026-05-19 (round 2 reality pass)
**Test:** `crates/umbrella-sealed-sender/tests/r2_mitm_real_exploit.rs`
**Reproducer:**
```
cargo test --release -p umbrella-sealed-sender --features pq \
    --test r2_mitm_real_exploit -- --nocapture
```

## Outcome

**0 successful MITM downgrades.** 5 of 5 attack vectors blocked by AEAD-MAC
or explicit version dispatch. 1 documented design carry-over (intra-recipient
replay defense is at the SealedServer Postman idempotency layer, not the
envelope layer).

## Per-vector trace

| ID    | Attack vector                                       | Outcome                              | Defending site                                              |
|-------|-----------------------------------------------------|--------------------------------------|-------------------------------------------------------------|
| R2.A  | Strip V2 byte → V1 byte, route to V1 unseal         | BLOCKED — `Crypto(AeadAuthFailure)`  | `aead_key.decrypt` in `lib.rs::unseal` — V1 keys derived from X25519 ECDH; V2-encrypted inner uses V2-derived key; MAC fails deterministically. |
| R2.B  | Strip V2 byte → V1 byte, route to V2 unseal_v2      | BLOCKED — `UnsupportedVersion{got:0x01}` | `SealedSenderVersion::try_from(wire[0])` in `hybrid_envelope.rs::unseal_v2` line 235 — strict dispatch. |
| R2.C  | Frankenwire: V2 prefix + Eve's V1 inner ct          | BLOCKED — `Crypto(AeadAuthFailure)`  | `aead_key.decrypt` in `hybrid_envelope.rs::unseal_v2` line 268 — Eve's inner ct was encrypted under V1-derived AEAD key from Eve↔Bob ECDH; V2 path derives DIFFERENT AEAD key from X-Wing decaps of Alice's xwing_ct prefix. |
| R2.D  | X-Wing pubkey substitution by MITM (AAD mismatch)   | BLOCKED — `Crypto(AeadAuthFailure)`  | AAD = `version‖xwing_ct‖own_xwing_pubkey` includes recipient pubkey; Bob recomputes with his pubkey while envelope was AEAD-authenticated under attacker's pubkey → MAC mismatch in `aead_key.decrypt`. |
| R2.E  | Cross-recipient replay (Alice→Bob wire → Carol)     | BLOCKED — `Crypto(AeadAuthFailure)`  | Carol's `xwing_decaps(carol_seed, alice_ct)` yields pseudo-random ss; derived AEAD key ≠ Alice-sealed key → MAC fails. |
| R2.F  | Intra-recipient replay (same wire twice to Bob)     | DESIGN — both succeed                | Documented: replay defense lives in Postman idempotency layer (SPEC-11 §4.3), not envelope layer. F-PHD-PQ-3 round-1 closure is correct. |

## Why this is more conclusive than round 1

Round 1 (F-PHD-PQ-3) closed active-MITM as "documented Tamarin model
abstraction gap" + "real-code defense is local-state architecture, not
formally-modelled property". Round 2 **actually runs the active MITM** on
running pair of `KeyStore` instances and traces which line in the live
codebase rejects each attack:

- `unseal_v2` line 235 — strict version peek
- `aead_key.decrypt` for AAD-bound rejection in lines 268+ (the `?` propagation
  of `AeadError`)
- AEAD AAD coverage (`version || xwing_ct || own_xwing_pubkey`) is the
  universal defense for cross-recipient + pubkey-substitution + frankenwire

The Tamarin model gap remains documented (forked-transcript active-MITM
modelling is a Stage-11 enhancement). However the **real-code defense is
now positively verified by running attacks** rather than argued from local-
state architecture.

## Severity classification (R2)

**F-PHD-PQ-3** (round 1, LOW carry-over documented): unchanged — still
LOW carry-over for Stage 11 Tamarin enhancement. **Reality-pass status**:
real defense **verified positively** by running attacks across 5 vectors.
No new finding; round 1 documented carry-over is now confirmed.

## Findings table delta

| Finding     | Round 1 status                | Round 2 status                                    |
|-------------|-------------------------------|---------------------------------------------------|
| F-PHD-PQ-3  | LOW (carry-over, Tamarin gap) | LOW (carry-over) + **defense verified** by 5 live attack vectors all returning `Crypto(AeadAuthFailure)` or explicit `UnsupportedVersion`. |
| F-PHD-PQ-4  | INFO (verified clean dispatch)| INFO — verified again via R2.B vector explicitly. |

## MITM goal-state outcomes

| Goal                              | Achieved? | Why not                                         |
|-----------------------------------|-----------|-------------------------------------------------|
| Recover Alice's plaintext         | NO        | AEAD MAC binds plaintext to (key, AAD).         |
| Forge envelope as if from Alice   | NO        | Inner ed25519 signature still requires Alice's identity_sk. |
| Downgrade V2→V1 silently           | NO        | `SealedSenderVersion::try_from(0x01)` produces V1Classical, but routing to V1 unseal requires re-deriving X25519 ECDH which fails the AEAD MAC. |
| Authenticate as attacker          | NO        | R2.C tested this; AEAD MAC mismatch since attacker can't compute the X-Wing ss without Bob's seed. |
| Replay across recipients          | NO        | R2.E — distinct sk → distinct ss → MAC fails.   |
| Replay to same recipient          | YES (design) | Postman idempotency layer is the defense; documented design choice. |
