# PhD-B Full Sweep — Pass 2 Handoff

**Date:** 2026-05-18
**Predecessor:** `docs/audits/phd-b-full-sweep-pass1-2026-05-18.md`
**Next session task:** Pass 2 PhD-B audit of remaining priority-2 crates

## Pass 1 result summary

3 CRITICAL + 1 HIGH + 5 MINOR/INFO findings on **umbrella-discovery + umbrella-threshold-identity + umbrella-client R20-R27 wrappers**.

Most severe: `unlock_with_pin` XOR placeholder (F-1), locally derivable anon IDs (F-2), R23 BTreeMap-arithmetic test (F-3).

These three findings invalidate the round-6 distributed identity security claim **until remediation**. Memory previously tracked all 3 as MINOR carry-overs.

## Pass 2 scope

**Crates to PhD-B audit:** umbrella-pq, umbrella-crypto-primitives, umbrella-oprf, umbrella-padding, umbrella-sealed-sender, umbrella-backup.

Each crate gets:
1. Read all `src/*.rs` for `placeholder` / `XOR` / `mock` / `TODO` / `FIXME` markers
2. Read all attack/phd_attacks tests + apply 6-question self-check
3. Cross-check against `docs/audits/` reports for that crate's previous PhD-B passes
4. Document findings in `docs/audits/phd-b-full-sweep-pass2-2026-05-18.md`

## Key real-vs-paperwork bar (memory `feedback_real_not_paperwork`)

For each attack/phd test, verify:

1. **Adversary really modelled?** Test should construct attacker state explicitly (e.g., 2-of-5 compromised servers, captured wire bytes, lldb attached process) — NOT just call public APIs and assert `Err(...)`.
2. **Real measurements?** queries-per-bit, seconds-per-evaluation, hits in N-byte memory scan, t-statistic — not just `.is_ok()` / `.is_err()`.
3. **Attack outcome quantified?** Either recovered material (bits / bytes) OR documented bound (computational complexity, queries needed). NOT silent passing.

## Crate-specific watch items for Pass 2

### umbrella-pq (Round 1-3 hedged closure)
- Confirm `xwing_encaps_derand` is `pub(crate)` (R5.B closure check).
- Confirm `HedgedWitness` derived from real identity_sk in production callsites (NOT zero/test stub).
- Check that R5 attack_* tests in `attack_r5_hedged_encaps_regression.rs` actually inject deterministic RNG + assert pseudo-random output WITH hedged_witness vs WITHOUT.

### umbrella-crypto-primitives (Round 5 MlockedSecret)
- Confirm `MlockedSecret` actually calls `libc::mlock` (not no-op stub on macOS).
- Check 7 production sites memory mentions — grep actual usage count.
- R7/R12 lldb tests still run? — check `tests/test_active_audit.rs`.

### umbrella-oprf
- Never PhD-B'd standalone. Apply full PhD-B audit.
- Critical: OPRF correctness invariants (RFC 9497), constant-time blind/unblind, Strong Unlinkability claim.

### umbrella-padding
- Never PhD-B'd standalone. Padding scheme must defend against length-leak side channel.
- Check if length-padded ciphertext output has constant length per category (TLS record fingerprint resistance).

### umbrella-sealed-sender
- Round 4 indirect target (R3 active MITM downgrade). Confirm V2 envelope path enforces hybrid PQ at every callsite.
- Check `seal_v2` callers use `xwing_encaps_hedged` not `xwing_encaps`.

### umbrella-backup
- attack_rotation_24words.rs — read for real-vs-paperwork.
- phd_attacks_v2_wrapping.rs — read.
- r5b_derand_compile_fail.rs — verify compile-fail test actually expects error.

## Pre-fix audit, post-fix audit ordering

**This audit (Pass 1) is read-only.** Findings F-1/F-2/F-3/F-4 require code changes; those changes should come from:

- Either: separate fix-design + fix-implementation sessions per finding (recommended PhD-B path)
- Or: user-driven prioritization (e.g., "F-1 first, then F-2 and F-3 together, then F-4")

Pass 2 audit may proceed in parallel with F-* fix work, since pass-2 crates don't share files with F-1/F-2/F-3/F-4.

## Context budget

This session at handoff time: ~55% of context used (Pass 1 read 13 files + wrote 1 report). Pass 2 should run in fresh session.

## Memory updates required

1. Add `feedback_phd_full_sweep_severity_uplift` — observation that 3 MINOR carry-overs upgraded to CRITICAL under full PhD-B sweep.
2. Update `project_phd_b_6_rounds_complete.md` carry-over list to reflect new severities.

## Stop / handoff

Pass 1 complete in this session. Commit Pass 1 report directly to main per `feedback_direct_to_main`. Next session: open fresh context, read this handoff + Pass 1 report, execute Pass 2.
