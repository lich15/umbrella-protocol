# Audits Index

This directory holds local audit notes, tool-policy documents, and the
closure reports for the PhD-B audit chain.

## Top-level entry points

- [`ROUND-1-TO-7-SUMMARY.md`](ROUND-1-TO-7-SUMMARY.md) — consolidated
  summary of PhD-B rounds 1-7 (rounds 1-6 merged 2026-05-18 via PR #6;
  round 7 discovery merged subsequently).
- [`phd-b-pass5-remediation-2026-05-19.md`](phd-b-pass5-remediation-2026-05-19.md)
  — Pass 5 remediation closure (20 commits resolving 18 findings; closes
  M-FINAL-1 from the independent reviewer verdict).
- [`phd-b-final-independent-review-2026-05-19.md`](phd-b-final-independent-review-2026-05-19.md)
  — fresh-session independent reviewer verdict on rounds 1-6.
- [`phd-b-hybrid-pq-ledger-2026-05-19.md`](phd-b-hybrid-pq-ledger-2026-05-19.md)
  — consolidated findings ledger for rounds 1-6.
- [`phd-b-discovery-closure-2026-05-18.md`](phd-b-discovery-closure-2026-05-18.md)
  + [`phd-b-discovery-ledger-2026-05-18.md`](phd-b-discovery-ledger-2026-05-18.md)
  — round 7 closure + ledger.
- [`max-ratchet-deniability-spec-2026-05-20.md`](max-ratchet-deniability-spec-2026-05-20.md)
  + [`max-ratchet-v3-security-evidence-2026-05-20.md`](max-ratchet-v3-security-evidence-2026-05-20.md)
  — Max Ratchet v3 specification + measured evidence matrix.
- [`dudect-saturation-methodology-2026-05-19.md`](dudect-saturation-methodology-2026-05-19.md)
  — methodology decision document for the F-DUDECT-HKDF-BORDERLINE-1
  saturation question (Pass 5 carry-over closed).

## PhD-B audit chain (rounds 1-6, 2026-05-19)

| Round | Type                       | Report                                                                         |
|-------|----------------------------|---------------------------------------------------------------------------------|
| 1     | Hybrid PQ PhD audit        | [`phd-b-hybrid-pq-audit-2026-05-19.md`](phd-b-hybrid-pq-audit-2026-05-19.md)   |
| 2     | Reality pass R1-R6         | [`phd-b-hybrid-pq-reality-pass-2026-05-19.md`](phd-b-hybrid-pq-reality-pass-2026-05-19.md) |
| 3     | Hedged-encaps closure      | [`phd-b-hybrid-pq-hedged-encaps-2026-05-19.md`](phd-b-hybrid-pq-hedged-encaps-2026-05-19.md) |
| 4     | Device-capture audit       | [`phd-b-device-capture-defense-2026-05-19.md`](phd-b-device-capture-defense-2026-05-19.md) |
| 5     | Device-capture closure     | [`phd-b-device-capture-closure-2026-05-19.md`](phd-b-device-capture-closure-2026-05-19.md) |
| 6     | Distributed identity       | [`phd-b-distributed-identity-closure-2026-05-19.md`](phd-b-distributed-identity-closure-2026-05-19.md) |
| 7     | Discovery (PSI + @username) | [`phd-b-discovery-closure-2026-05-18.md`](phd-b-discovery-closure-2026-05-18.md) |

## Attack artifacts

- [`device-capture-artifacts/`](device-capture-artifacts/) — lldb scan
  scripts, output, and per-finding notes for R7 / R8 / R9-R11 / R10 /
  R12 / R20.
- [`reality-pass-artifacts/`](reality-pass-artifacts/) — per-finding
  notes for R1 (KyberSlash) / R2 (MITM) / R3 (supply chain) / R4
  (offline decrypt) / R5 (RNG injection) / R6 (lldb zeroize).

## Historical security audits

- [`security-hardening-audit-2026-05-15.md`](security-hardening-audit-2026-05-15.md)
- [`security-hardening-audit-2026-05-16.md`](security-hardening-audit-2026-05-16.md)
- [`security-hardening-audit-2026-05-17.md`](security-hardening-audit-2026-05-17.md)
- [`full-fuzz-and-miri-run-2026-05-14.md`](full-fuzz-and-miri-run-2026-05-14.md)
- [`local-release-hardening-status-2026-05-14.md`](local-release-hardening-status-2026-05-14.md)
- [`external-crypto-release-audit-status-2026-05-14.md`](external-crypto-release-audit-status-2026-05-14.md)
- [`formal-lint-status-2026-05-13.md`](formal-lint-status-2026-05-13.md)

## Tool policy

- [`cargo-deny-policy.md`](cargo-deny-policy.md) — cargo-deny ban
  policy and rationale.
- [`dylint-rules.md`](dylint-rules.md) — local dylint rules.
- [`fuzz-runbook.md`](fuzz-runbook.md) — fuzz target runbook.
- [`miri-runbook.md`](miri-runbook.md) — Miri runbook.
- [`reproducible-builds.md`](reproducible-builds.md) — reproducible
  build notes.
