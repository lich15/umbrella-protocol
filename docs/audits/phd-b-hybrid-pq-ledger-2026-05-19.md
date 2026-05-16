# PhD-B Hybrid PQ Audit Ledger Entry — 2026-05-19

**Branch:** `audit/phd-b-hybrid-pq-2026-05-19`
**Spec:** `docs/superpowers/specs/2026-05-19-phd-b-hybrid-pq-audit-design.md`
**Report:** `docs/audits/phd-b-hybrid-pq-audit-2026-05-19.md`
**Auditor:** Claude Opus 4.7 (1M context) PhD-B level (state-level adversary D per SPEC-01 §4)

## Scope traveled

| Crate | Module / file | LoC read | Outcome |
|---|---|---|---|
| umbrella-pq | lib.rs, constants.rs, error.rs, ml_kem.rs, xwing.rs | 1273 | F-PHD-PQ-7 inline-fix (doc drift), F-PHD-PQ-8 INFO observation |
| umbrella-backup | cloud_wrap/pq_wrap.rs | 973 | F-PHD-PQ-4 verified-clean version dispatch |
| umbrella-sealed-sender | hybrid_envelope.rs | 627 | Existing phd_real_attacks_sealed_sender.rs (session #69) provides V2 coverage; cross-validated |
| umbrella-formal-verification | xwing_combiner.spthy + downgrade_resistance.spthy + hybrid_signature_and_mode.spthy | 864 (100%) | F-PHD-PQ-1/2/3 documented; 2 new lemmas added |

## Findings ledger

| ID | Severity | Title | Status | Closed by |
|---|---|---|---|---|
| F-PHD-PQ-1 | LOW | xwing_combiner adversarial encaps modeling abstraction | CLOSED in-block | New lemma `adversarial_encaps_quantum_break_cannot_recover_K` (verified 11 steps) |
| F-PHD-PQ-2 | LOW | Tautological `domain_separation` lemma renamed + substantive replacement | CLOSED in-block | New lemma `kdf_transcript_binding` (verified 2 steps under RO assumption) |
| F-PHD-PQ-3 | LOW | downgrade_resistance active-MITM rule structurally non-substantive | DOCUMENTED CARRY-OVER (Stage 11 Tamarin enhancement) | Lemma `adversary_strip_does_not_force_downgrade` added; model gap noted |
| F-PHD-PQ-4 | INFO | V2 wire-version dispatch strict, no silent fallback | VERIFIED CLEAN | `attack_a1_forged_v1_byte_on_v2_wire_rejected_by_both_parsers` + `attack_a1_forged_v2_byte_on_v1_wire_rejected_by_v2_parser` |
| F-PHD-PQ-5 | LOW | X-Wing KAT coverage 1 of N draft-10 Appendix C vectors | CARRY-OVER to v1.2.0 | `attack_a5_xwing_kat_coverage_documented_gap` regression-guard asserts current count = 1 |
| F-PHD-PQ-6 | INFO | FIPS 203 ACVP KAT placeholder for ML-KEM-768 | CARRY-OVER to v1.2.0 | Stability KAT exists as baseline (`stability_kat_ml_kem_768_roundtrip`) |
| F-PHD-PQ-7 | LOW | `xwing_decaps` doc claimed explicit rejection; reality is implicit | CLOSED in-block (commit `e6809674`) | xwing.rs:281-308 doc rewritten + `attack_a7_xwing_decaps_actually_implicit_rejection_doc_drift` |
| F-PHD-PQ-8 | INFO | ml_kem_768_decaps borderline-LEAK t-statistic at 1M dudect on arm64 macOS | DOCUMENTED (upstream libcrux opportunity); not exploitable in production tree | dudect arm `ml_kem_768_decaps_valid_vs_invalid` 1M samples reproducible |

## Commits

| Hash | Title |
|---|---|
| `cf9a44cc` | phd-b: F-PHD-PQ-2 + F-PHD-PQ-3 — Tamarin model gaps in domain_separation and downgrade resistance |
| `e6809674` | phd-b: real adversarial attacks + F-PHD-PQ-7 doc drift inline-fix |
| (this commit) | phd-b: dudect Site 11 unwrap_v2_to_v1 + audit report + ledger |

## Outstanding carry-overs

1. **F-PHD-PQ-3 model enhancement** — extend `downgrade_resistance.spthy` with forked-transcript active-MITM modelling (parallel processes, adversary-controlled message passing) to make `adversary_strip_does_not_force_downgrade` substantive at the proof-step level. Target: Stage 11 formal-verification enhancement round.
2. **F-PHD-PQ-5 KAT extension** — import draft-connolly-cfrg-xwing-kem-10 Appendix C vectors 2..n via `umbrella-vectors` data harness. Target: v1.2.0.
3. **F-PHD-PQ-6 ACVP integration** — pull NIST CSRC ACVP test vector set for ML-KEM-768. Target: v1.2.0.
4. **F-PHD-PQ-8 upstream** — file libcrux-ml-kem improvement issue documenting 1-2 ns valid-vs-invalid ct timing signal observable on arm64 Darwin at 1M dudect samples. Note: not a secret-key-bit channel, so not blocking for production; track as quality improvement.

## 6/6 self-check honest evaluation

| # | Criterion | Status | Notes |
|---|---|---|---|
| 1 | Findings count ≥ 5 | PASS | 8 findings (F-PHD-PQ-1..8) |
| 2 | `attack_*` adversarial test naming, end-to-end real scenarios | PASS | 38 of 46 (82.6%) real attacks across 2 new files; 8 verify_* property tests renamed honestly per memory rule |
| 3 | Tamarin engagement ≥ 80% line-by-line | PASS | 864 LoC, 100% read |
| 4 | dudect ≥ 1M samples on CT-critical operations | PASS | 4×1M ml_kem + 3×1M xwing + 1×1M unwrap_v2 |
| 5 | Reduction sketches with concrete numbers | PASS | X-Wing IND-CCA2 (2^-125), V2 AE (2^-69), downgrade (0 deterministic) |
| 6 | Literature ≥ 5 citations with specific insights | PASS | 7 citations, each mapped to code site + decision |

**Strict 6/6 PASS HONESTLY.** No partial criterion.
