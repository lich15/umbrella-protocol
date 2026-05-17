# PhD-B Hybrid PQ Reality Pass — Design Spec

**Date:** 2026-05-19 (same day, second round)
**Predecessor:** `2026-05-19-phd-b-hybrid-pq-audit-design.md` (round 1, 8 findings, 0 HIGH/CRIT — too paperwork-heavy)
**Auditor:** Claude Opus 4.7 (1M context), state-level adversary D per SPEC-01 §4.

## Why this round exists

User feedback after round 1: "нужны не формальные а реальные". Round 1 produced Tamarin lemmas, t-statistic numbers, doc-drift fixes — academically sound but lacking real exploit attempts against running programs. Memory `feedback_active_audit_mode` (session #47): "НЕ выдуманные unit-test boundary scenarios а РЕАЛЬНЫЕ попытки взлома end-to-end". This pass corrects round 1's miss.

## Mandate

For each of round 1's 8 findings AND for each newly hypothesized attack vector, deliver **at least one of:**
- **Working exploit binary/script** that demonstrates secret recovery, message decryption, downgrade success, or other goal-state achievement on a running build.
- **Real end-to-end attempt with full trace** demonstrating why exploit fails (not "theoretical gap closed by AEAD-MAC" without showing the AEAD-MAC actually wraps it in the live call path).

Paperwork-only outcomes (Tamarin lemma rename, doc-drift comment fix) DO NOT count toward this pass's deliverables. They counted in round 1; round 2 raises the bar.

## Acceptance gate

Pass considered complete only when **all four** of these are true:
1. **At least one real working exploit attempt** against KyberSlash-class timing (F-PHD-PQ-8 from round 1) — running attacker code, measuring timing on victim binary, attempting to recover secret key bit(s) or distinguishing secret-dependent state. Outcome: either recovered key material (CRITICAL finding) or full trace of why the leak cannot be amplified into key recovery (with concrete numbers: bits of info per query, queries needed to exhaust 256-bit key, defense-in-depth latency added by callers).
2. **At least one real MITM attempt** on a running pair of test clients (or simulated network endpoints) — actively modifying wire bytes, attempting downgrade (V2 → V1), replay across chats, public key substitution. Outcome: either successful downgrade/decryption (CRITICAL) or full trace of policy enforcement at every call site.
3. **At least one real supply-chain attempt** — substitute libcrux library file on disk or via Cargo registry mirror, observe whether KATs catch it, whether reproducible builds catch it, whether code signing catches it. Outcome: substitution detected at some layer (LOW/INFO) or undetected (HIGH/CRITICAL).
4. **At least one real live message-exchange attempt** — build two minimal clients (or use existing integration test rig), exchange one hybrid PQ message, intercept on the wire, attempt offline decryption with attacker-known data. Outcome: plaintext recovered (CRITICAL) or full trace.

## Anti-paperwork rules

- **No new Tamarin lemmas count** unless paired with concrete real-program attack attempt.
- **No new `attack_*` tests count** unless test exercises actual untrusted-input parsing or network-bytes-on-wire surface (not just mocked roundtrip with toggled flag).
- **F-PHD-PQ-8 cannot be re-closed as INFO** unless the report contains a real exploit attempt section showing the timing leak's exploitability bound (queries × bits-per-query analysis with measured numbers, not theoretical).
- **F-PHD-PQ-3 active-MITM cannot be re-closed as "carry-over"** unless this round shows a real network-MITM attempt and documents what defense actually blocks it.

## Hypotheses (real-exploit framing)

### R1 — KyberSlash key recovery attempt
Round 1 measured t = +13.24 on ml_kem_768_decaps timing. This is a CT violation; whether key bits leak depends on whether timing function is correlated with secret bits OR only with ciphertext validity classification.

**Real attempt:** Build attacker program that:
1. Generates fixed (sk, pk).
2. Crafts 10,000 ciphertexts with structured perturbations chosen to align with KyberSlash-1 (division-by-secret) and KyberSlash-2 (rejection-sampling-by-secret) attack surfaces.
3. Calls `ml_kem_768_decaps(sk, ct)` under high-resolution clock (rdtsc / mach_absolute_time on arm64), records nanosecond timing.
4. Performs statistical key-bit recovery: for each suspected sk bit, attempt distinguishing via timing.
5. Reports: bits recovered, queries needed, comparison vs theoretical 256-bit key strength.

If recovered ≥1 bit → CRITICAL. If 0 bits → INFO with documented bound.

### R2 — Real MITM downgrade attempt
**Real attempt:** Build network proxy program that sits between two simulated clients exchanging V2 hybrid envelopes. Attempt:
1. Strip V2 wrapper, forward only V1 inner — observe whether receiver downgrades.
2. Substitute V2 envelope with attacker-constructed V1 envelope under sniffed Y point.
3. Replay V2 envelope across different chats (different `chat_id` in AAD).
4. Substitute recipient's X-Wing pubkey in handshake; observe whether receiver detects.

If any succeeds → CRITICAL. If all fail → trace exact policy enforcement code paths.

### R3 — Supply-chain real substitution
**Real attempt:**
1. Copy `~/.cargo/registry/src/.../libcrux-ml-kem-0.0.9` to a writable workspace, modify `decapsulate` to return constant ss=`[0xAA; 32]`, rebuild workspace.
2. Run `cargo test --release` including `xwing_draft10_kat`.
3. Document which test catches substitution.
4. Repeat with subtler change (return correct value but log timing — backdoor for telemetry).

If `xwing_draft10_kat` doesn't catch → HIGH (KAT coverage gap = F-PHD-PQ-5 re-opens).

### R4 — Live message exchange interception
**Real attempt:**
1. Use existing integration test rig (or build one if missing) to perform actual hybrid PQ message wrap/send/unwrap between two `umbrella-sealed-sender` instances.
2. Capture wire bytes at sender output, attacker holds them offline.
3. Attempt decryption with: (a) known V1 ciphersuite weakness assumption + future quantum, (b) X25519 secret recovery via DLog assumption, (c) AEAD key brute via known plaintext.
4. Measure: bits of plaintext recovered (should be 0 under hybrid PQ assumption).

If >0 → CRITICAL. If 0 → report concrete computational bound (e.g. "2^125 ops infeasible per Connolly 2024").

### R5 — RNG injection real test
Round 1 had `rng_injection.rs` but did not test deterministic RNG with adversary-chosen seed leading to predictable shared secret. **Real attempt:** Inject deterministic RNG into `xwing_encaps`, derive predictable ss, demonstrate that AEAD key derived from ss is predictable, attempt to decrypt without recipient sk.

### R6 — Zeroize real test via debugger / memory dump
Round 1 trusted `zeroize::Zeroize` to emit memset (vol-write semantics). **Real attempt:** Compile release binary, attach lldb, set breakpoint after `xwing_keygen` returns, dump stack frame, search for seed bytes. If found → HIGH (Rust zeroize broken on this target). If not found → confirmed.

## Workflow

1. Read round 1 report `docs/audits/phd-b-hybrid-pq-audit-2026-05-19.md` and ledger.
2. Plan R1-R6 with TodoWrite.
3. For each R, build the real attacker code (binary, integration test, or script) and run it against real build.
4. Record numerical outcomes (bits recovered, queries, latency, etc).
5. Update findings:
   - If real exploit succeeded → upgrade severity (LOW→HIGH/CRITICAL).
   - If real attempt confirmed unexploitable → downgrade severity is fine, but only with measured numbers, not theoretical hand-waving.
   - If round 1 finding withstands real test → keep as-is with reality-pass annotation.
6. Write reality-pass report `docs/audits/phd-b-hybrid-pq-reality-pass-2026-05-19.md` appending to round 1's audit narrative.
7. Update ledger.
8. Commit per finding/phase.

## Stop / handoff

Same rule as round 1 (memory `feedback_phd_no_partial`): partial = invalid. If R1-R4 can't all be attempted within context budget, hand off with partial state documented, DO NOT claim pass.

## Branch

Continue on `audit/phd-b-hybrid-pq-2026-05-19` (round 1 commits already there). Add reality-pass commits on top.

## What does NOT count

- Re-running existing dudect harness with different sample size (already done in round 1).
- Adding more Tamarin lemmas without real exploit attempt paired.
- Renaming tests from `verify_*` back to `attack_*` without rewriting logic.
- Documenting "exploitability bounded by AEAD-MAC" without showing AEAD-MAC actually wraps the timing surface in live binary trace.
