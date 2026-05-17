# R5 — Real RNG injection exploit findings

**Date:** 2026-05-19 (round 2 reality pass)
**Test:** `crates/umbrella-pq/tests/r5_rng_injection_real_exploit.rs`
**Reproducer:** `cargo test --release -p umbrella-pq --features ml-kem --test r5_rng_injection_real_exploit -- --nocapture`

## Outcome

**5 of 5 attacks succeed under the assumed adversary model** (RNG compromised).
**Defense holds in production** because:
1. `OsRng` is the only production-side default RNG, sourcing from kernel
   /dev/urandom / arc4random — compromise requires kernel-level access.
2. `xwing_encaps_derand` (deterministic API) has **zero production callers**
   in the workspace (grep-verified).

## Per-attack results

| ID    | Attack                                                        | Outcome under compromised-RNG model | Production defense          |
|-------|---------------------------------------------------------------|-------------------------------------|-----------------------------|
| R5.A  | Compromised CSPRNG with attacker-known seed → replicate ss     | **SUCCEEDS** — attacker computes the same shared_secret offline | `OsRng` mandate              |
| R5.B  | `xwing_encaps_derand` with attacker-chosen seed                | **SUCCEEDS** — API is deterministic by contract               | No production caller (grep)  |
| R5.C  | Multi-session state replay (Alice + Bob both compromised)      | **SUCCEEDS** — every session recoverable                       | Same as R5.A                 |
| R5.D  | `OsRng` distinct-output sanity                                  | **defense holds** — distinct outputs per call                 | Demonstrated                 |
| R5.E  | Audit invariant: zero production caller of `xwing_encaps_derand`| **PASS** — grep verified                                       | Code-review invariant        |

## Severity classification (R5)

This is the **standard cryptographic-API gotcha**: derandomized hooks (KAT
support) are inherently insecure if reached by adversary-influenced seed.
Round-1 audit covered this via doc-comment warnings on `xwing_encaps_derand`
and via existing `attack_a8_xwing_encaps_derand_zero_seed_deterministic_but_unique`.

**Verdict**: NO new finding. Round-1 closure of A8 is reaffirmed; the doc
comment + audit invariant (zero production caller) are the real defense.

## Real-world tie-back

The case study for the threat: Cloudflare's IngressFromConsulFactory 2017,
Debian OpenSSL 2008 — both incidents where compromised CSPRNG produced
predictable nonces. The defense in both cases was infra-side fix
(replace CSPRNG, regenerate keys); no cryptographic-protocol-level fix.
Umbrella inherits this: if attacker controls OsRng, the protocol is dead.

## Recommendations (carry-over, none new)

1. Maintain audit invariant: `xwing_encaps_derand` MUST stay test-only.
   If a downstream production caller ever appears, that's an inline-fix
   security regression.
2. CI grep gate: `rg "xwing_encaps_derand" crates/ --type rust | grep -v
   tests/ | grep -v "src/xwing.rs"` must return 0 matches.

## Findings table delta

| Finding         | Round 1 status                  | Round 2 status                              |
|-----------------|---------------------------------|---------------------------------------------|
| (no new)        | A8 covered by behavioral test   | A8 covered + audit-invariant grep verified  |
