# PhD-B Hybrid Post-Quantum Audit — Design Spec

**Date:** 2026-05-19
**Auditor:** Claude Opus 4.7 (1M context) PhD-B level, role of state-level adversary D per SPEC-01 §4.
**Scope (Variant B):**
- `crates/umbrella-pq/src/` — full crate (lib.rs, constants.rs, error.rs, ml_kem.rs, xwing.rs)
- `crates/umbrella-backup/src/cloud_wrap/pq_wrap.rs` — Hybrid V2 wrapping layer
- `crates/umbrella-sealed-sender/src/hybrid_envelope.rs` — message-level hybrid envelope (consumer)
- Tamarin: `xwing_combiner.spthy`, `downgrade_resistance.spthy`, `hybrid_signature_and_mode.spthy`

**Out of scope this round:**
- `hybrid_signature.rs`, `ml_dsa.rs`, `slh_dsa.rs` (signature path — Variant C separate)
- `umbrella-mls` X-Wing ciphersuite integration (block 8.6 already covered, cross-reference only)
- V1 ElGamal classical layer (already retroactive-pass complete)

## Adversary model

State-level adversary with capabilities:
1. **Network MitM** — full active control of wire bytes between client and recovery infrastructure.
2. **Quantum-capable in future** — "harvest now, decrypt later" with future CRQC.
3. **Side-channel measurement** — KyberSlash-class timing on victim device.
4. **Backend swap** — supply-chain attempt to substitute libcrux with weaker / backdoored implementation.
5. **Spec-level downgrade** — protocol-level attempt to force pure-classical (X25519-only) when hybrid is mandated.
6. **Memory inspection** — cold-boot, RAM-dump, swap-out of process memory.

Adversary goal: recover plaintext content of any user's messages and/or recovery key, OR force the system into a state where future plaintext is recoverable with only classical capabilities.

## PhD-B mandatory deliverables (6/6 self-check)

Per memory `feedback_phd_no_partial`, partial PhD = violation. Audit either delivers all 6 or hands off to fresh session.

1. **5+ real findings** in scope. Findings tracked F-PHD-PQ-{N}-{severity}. Severity: INFO / LOW / MED / HIGH / CRITICAL. Each finding has: title, evidence (file:line), exploit sketch, impact, fix recommendation.
2. **`attack_*` adversarial test naming**, end-to-end real attack scenarios — NOT behavioral boundary tests. Each finding paired with at least one `attack_*` regression test that asserts the attack is BLOCKED post-fix.
3. **Tamarin/ProVerif engagement ≥ 80%** — read full bodies of `xwing_combiner.spthy`, `downgrade_resistance.spthy`. If lemma names misleading vs claimed property, document. Extend at least one model with concrete adversary rule from this audit and verify lemma stays / fails.
4. **dudect 1M+ samples per CT-critical operation:**
   - `xwing_decaps` (valid vs invalid ciphertext)
   - `ml_kem_768_decaps` (valid vs invalid ciphertext — KyberSlash class)
   - `unwrap_v2_to_v1` end-to-end (valid envelope vs tampered)
   - HKDF-SHA256 input-length variance
   Existing `dudect_constant_time.rs` extended; results recorded in finding text.
5. **IND-CPA / IND-CCA2 reduction sketches** with concrete numbers (security level bits, distinguishing advantage bound). At least:
   - X-Wing combiner: hybrid IND-CCA2 inherited from ML-KEM-768 IND-CCA2 + X25519 GAP-CDH (Connolly et al 2024).
   - V2 wrapping: AEAD AE security under HKDF-SHA256 random-oracle assumption.
   - Downgrade resistance: distinguishing advantage between hybrid and classical-only.
6. **5+ literature citations** by exact title + year + venue:
   - KyberSlash papers (Bernstein et al 2024).
   - FIPS 203 (final, Aug 2024).
   - draft-connolly-cfrg-xwing-kem-10.
   - Connolly-Hülsing-Kannwischer-Sotirakis 2024 X-Wing original.
   - HACL*/libcrux verification claims (specific papers).

## Attack hypotheses to test

The audit MUST attempt the following attacks. Subagent has autonomy to add more.

### A1 — Hybrid downgrade enforcement
**Claim under test:** Adversary cannot force pure-classical mode by sending V1 envelope to a recipient who must accept hybrid only.
**Test:** Encrypt with V1 (`wrap_message_key`), send to recipient who has V2 mandatory policy. Recipient must reject.
**Current state:** No explicit policy gate seen — `WrappingCiphersuite::try_from` accepts both 0x01 and 0x02. Verify whether call sites enforce min-version.

### A2 — KyberSlash timing on ML-KEM-768 decaps
**Claim under test:** `ml_kem_768_decaps` is constant-time wrt secret key bits and ciphertext validity.
**Test:** dudect 1M+ samples, valid ct vs targeted-invalid ct (KyberSlash-1, KyberSlash-2 patterns from Bernstein 2024). Compare t-statistic > 4.5 threshold.

### A3 — X-Wing combiner: ML-KEM half bypass
**Claim under test:** Cannot derive shared secret from only X25519 half — both halves required per draft-connolly-cfrg-xwing-kem-10 combiner.
**Test:** Construct synthetic xwing_ct where ML-KEM portion zeroed but X25519 portion valid. Verify decaps either fails or yields ss uncorrelated with sender's.

### A4 — V2 envelope domain separation
**Claim under test:** V2 AEAD key derived from same shared_secret cannot decrypt V1 ciphertext and vice versa.
**Test:** Construct cross-protocol replay: V2 wire with V1 KDF salt swap. Verify reject.

### A5 — Backend swap / libcrux substitution
**Claim under test:** Replacing libcrux-ml-kem with a backdoored variant detected by KAT (`xwing_draft10_kat.rs`, FIPS 203 ACVP).
**Test:** Read KAT file, verify coverage of all FIPS 203 ACVP test vectors and X-Wing draft-10 vectors. Document gaps.

### A6 — ML-KEM secret key from_bytes no structural validation
**Claim under test:** `MlKem768SecretKey::from_bytes` rejects malformed secret keys.
**Evidence:** Lines 60-78 of ml_kem.rs explicitly say "structural validation happens only in decapsulate". If untrusted source ever passes sk bytes, downstream decap behavior may leak.

### A7 — Implicit rejection no signal — caller binding
**Claim under test:** ML-KEM-768 returns pseudo-random ss on corrupted ct (FIPS 203 design). Caller (AEAD layer) detects mismatch via Poly1305 tag. Verify no error path before AEAD.

### A8 — `xwing_encaps_derand` low-entropy seed
**Claim under test:** Exposed `xwing_encaps_derand` with adversary-chosen 64-byte seed leads to deterministic predictable encaps. Comment says "primarily KAT" but type system doesn't prevent production misuse.
**Test:** Construct attacker-replayed encaps via low-entropy seed; check if any production path could invoke this.

### A9 — Backend error message leak
**Claim under test:** `PqError::BackendError { message: format!("xwing pk decode: {e:?}") }` may include sensitive byte ranges or pointer fragments from libcrux Debug impls.
**Test:** Trigger known error paths and inspect message content.

### A10 — Memory hygiene: seed buffer zeroize timing
**Claim under test:** `seed.zeroize()` after `xwing_keygen_from_seed` and after `ml_kem_768_keygen` happens AFTER backend consumed bytes. LLVM dead-store elimination cannot remove `zeroize::Zeroize` (volatile-write semantics) — verify via release-build disassembly that `memset` is emitted.

## Required infrastructure leverage

**Existing tests / models to extend:**
- `crates/umbrella-tests/tests/dudect_constant_time.rs` — extend with new test arms if absent.
- `crates/umbrella-pq/tests/adversarial.rs` — extend with new attack_* arms.
- `crates/umbrella-pq/tests/test_active_audit.rs` — extend.
- `crates/umbrella-pq/tests/xwing_draft10_kat.rs` — verify coverage; document gaps.
- `crates/umbrella-formal-verification/models/xwing_combiner.spthy` — read full; extend with downgrade adversary rule if missing.
- `crates/umbrella-formal-verification/models/downgrade_resistance.spthy` — read full; verify universal vs scenario-based.

**Tamarin engagement requirement (memory `feedback_phd_pass_full_model_reading`):**
Subagent MUST read full body of xwing_combiner.spthy and downgrade_resistance.spthy line-by-line, not only preamble. Confirm lemma names match what they prove. Tautological / vacuous lemmas count as PhD findings.

## Report structure

Final report: `docs/audits/phd-b-hybrid-pq-audit-2026-05-19.md`. Sections:
1. Executive summary
2. Findings table (10 columns: ID, severity, title, file:line, attack vector, evidence, exploit sketch, fix, status, regression test)
3. Tamarin model engagement summary (lemma-by-lemma)
4. dudect results (t-statistic per measurement arm, 1M+ samples confirmed)
5. Reduction sketches (with concrete numbers)
6. Literature engagement (5+ citations, what each contributed)
7. 6-question PhD-B self-check (must show 6/6 pass)
8. Ledger update entries for `docs/ledgers/postulate-status.md` / `phd-active-retro-ledger.md`

## Commit policy

- **One block = one commit to main** per memory `feedback_direct_to_main`. Branch protection requires PR, but admin bypass list configured (per session #67 admin merge experience).
- Each finding fix is its own commit referencing F-PHD-PQ-{N}-{severity}.
- Spec commits first → finding commits second → final report commit → ledger commit.
- Each commit message terse, why-focused.

## Stop condition

If subagent's own context approaches its budget limit OR if Tamarin proof requires >2h wall-clock on universal lemma:
1. Document partial findings to `docs/audits/phd-b-hybrid-pq-audit-2026-05-19.md` as "in-progress".
2. Hand off via spec note: what was completed, what remains.
3. Do NOT claim PhD-B pass with partial deliverables (memory `feedback_phd_no_partial`).

## Acceptance gate

PhD-B audit considered complete only when:
- 6/6 self-check honest pass.
- All 10 attack hypotheses tested (some may turn out unexploitable — that's a valid outcome with documented analysis).
- Report committed.
- Ledger updated.

If <6/6, audit closed as A-level (not PhD-B) with explicit downgrade note in commit message.
