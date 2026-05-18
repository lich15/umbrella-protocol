# PhD-B Full Sweep Audit — Pass 1 (Priority-1 Crates)

**Date:** 2026-05-18
**Session:** PhD-B full sweep, pass #1 / 5 (handoff after this pass)
**Scope:** umbrella-discovery (Round 7) + umbrella-threshold-identity (Round 6) + R20-R27 attack tests in umbrella-client/umbrella-mls
**Auditor:** Claude Opus 4.7 (PhD-B level per `feedback_phd_level_mandatory` + `feedback_real_not_paperwork`)
**Status:** **3 CRITICAL + 1 HIGH + 5 MINOR/INFO findings**. **Round 6 distributed identity contains placeholder code that is production-named.** Memory tracking previously rated all 3 CRITICAL as MINOR carry-overs — PhD-B audit upgrades severity based on test reliance + production-name + adversary impact.

---

## Severity legend

- **CRITICAL:** Production-named API with placeholder semantics OR attack test that does not test the claimed attack surface; cannot ship to 1B users in this state.
- **HIGH:** Attack test that bypasses real protocol path and tests only a struct manipulation.
- **MAJOR / honest gap:** Documented architectural limit; downstream component required.
- **MINOR:** Real test that lacks PhD-B grade rigor (insufficient samples, missing quantification).
- **INFO:** Boundary disclosure, no security gap.

---

## CRITICAL findings

### F-1 — `unlock_with_pin` uses XOR-combine, not FROST threshold reconstruction

**File:** `crates/umbrella-client/src/keystore/distributed_identity_client.rs:139-152`

**Evidence:**
```rust
// Step 3: request server_share from servers 1..=3
let mut combined_share = [0u8; 32];
for server_id in 1..=5u16 {
    if got_shares >= 3 { break; }
    match server_client.unwrap_share(...) {
        Ok(share) => {
            // XOR-combine (placeholder for production threshold reconstruction).
            for (slot, byte) in combined_share.iter_mut().zip(share.iter()) {
                *slot ^= *byte;
            }
            got_shares += 1;
        }
        ...
    }
}
```

**Comment context (line 114):**
> "XOR-combine shares (informational only — production combines via threshold reconstruction; in this Stage 2 minimum we use any one share as the input)."

**Real-adversary impact:**
- FROST-Ed25519 (per `umbrella-threshold-identity::signing`) uses **Lagrange interpolation** for share aggregation, not XOR.
- With XOR-combine: if adversary captures share_1 and share_2 (e.g. via 2 compromised servers), and adversary knows the third share (e.g. through online dictionary brute-force of weak PIN), `share_3 = combined ⊕ share_1 ⊕ share_2`. Trivial recovery.
- With FROST Lagrange: adversary needs full 3 shares AND the Lagrange coefficient set; partial knowledge doesn't compose linearly.

**Test reliance:**
- R21 (duress) tests bypass this path (Finding F-4 below).
- The unit tests in `distributed_identity_client.rs:299-413` test the XOR-combine, not FROST. They pass — but they validate placeholder behavior.

**Memory disconnect:**
Memory `project_phd_b_6_rounds_complete.md` line 57 marks this as "MINOR carry-over". PhD-B reclassifies **CRITICAL** because:
1. Function is named `unlock_with_pin` — production-grade naming.
2. R20-R27 attack tests' security claims rest on its correctness.
3. The 1B-user shipping decision cannot ship XOR-combine.

**Remediation required (handoff):**
1. Replace XOR-combine with `umbrella_threshold_identity::signing::aggregate` against the cluster's `PublicKeyPackage`.
2. Add real-attack regression test: 2 colluding servers cannot recover combined material; only ≥3 quorum can.
3. Rerun R20-R27 against new path.

---

### F-2 — Anonymous IDs are locally re-derivable from PIN + salt; server is not the root of trust

**File:** `crates/umbrella-client/src/keystore/distributed_identity_client.rs:247-263`

**Evidence:**
```rust
// Anonymous ID seeder = HKDF(pin_root, salt, "anon-seed").
let mut anon_seed = [0u8; 32];
Hkdf::<Sha256>::new(Some(&account_local_salt), pin_root.expose())
    .expand(b"umbrella-r6/anon-seed/v1", &mut anon_seed)?;
let per_server_anonymous_ids = anonymous_id::derive_all_anonymous_ids(&anon_seed)?;
```

**Comment context (lines 248-252):**
> "In production the master_key is HKDF-re-derived from PIN+salt+server_share — but we don't have server_share at registration; we use HKDF(pin_root, salt) as a deterministic proxy that any device re-deriving from the same PIN+salt will obtain identical IDs."

**Real-adversary impact:**
- An adversary who knows (PIN, account_local_salt) can compute **all 5 server-side anonymous IDs locally** without any server interaction.
- `account_local_salt` is stored on-device (not a secret).
- PIN is a 6-digit number = 10^6 entropy space.
- Combined: adversary with phone access can brute-force PIN via local Argon2id (~800 ms/guess) → 10^6 × 0.8s ≈ 9 days single-thread. Or 6h on 64-thread GPU rig (Argon2id resists GPU partially, factor ~10× → ~22h).
- Result: adversary learns all server anon_ids without ever contacting a server → can issue valid unwrap requests + correlate cross-server queries from a stolen-phone scenario.

**Test reliance:**
- D-6 `d6_attack_master_key_recovery_from_anon_ids_infeasible` measures HKDF avalanche but does not model adversary-knows-PIN scenario.

**Memory disconnect:**
Not previously tracked in memory. **CRITICAL** because anonymity claim of round-6 design is voided.

**Remediation required (handoff):**
1. Anonymous IDs MUST be derived from `(server_share_i || account_id)`, NOT from `(pin_root || account_local_salt)`. Server delivers anon_id_i during bootstrap.
2. Document threat model honestly: PIN brute-force on stolen device IS feasible in round-6 (10^6 space + Argon2id ~800ms ≈ 9 days). Mitigation: 5-attempt-then-time-lock counter (already implemented).
3. Add real-attack test: simulate stolen-phone adversary with known salt + PIN brute-force; show they can/cannot recover anon_ids.

---

### F-3 — R23 5-registry attack test is pure in-memory `BTreeMap` arithmetic

**File:** `crates/umbrella-client/tests/attack_r23_5_registry_detects_fake_version.rs`

**Evidence:**
```rust
struct IntegrityCheck {
    local_binary_hash: [u8; 32],
    registries: BTreeMap<&'static str, [u8; 32]>,
}
```

The "5 registries" are entries in a local `BTreeMap` constructed by the test itself. There is:
- **No Sigstore Rekor API call** (real URL: rekor.sigstore.dev).
- **No Certificate Transparency log lookup.**
- **No P2P attestation network.**
- **No alternative jurisdiction mirror probe.**
- **No actual binary signing/verifying** (e.g. via cosign).

The test asserts `mismatch_count == 4` on a map the test populated with `(name, hash)` pairs.

**Real-adversary impact:**
- A real supply-chain attack (modified binary on App Store / Play Store mirror) is NOT exercised by this test.
- The "4-of-5 gate" decision logic might be correct, but the test does not validate any of the 5 sources of truth.
- Production code (search `crates/`) shows NO integration with rekor, CT, cosign, or any real attestation backend.

**Memory disconnect:**
Memory `project_phd_b_6_rounds_complete.md` line 57: "R23 5-registry — decision-logic model (не real Sigstore/CT)" — marked MINOR. PhD-B reclassifies **CRITICAL** because:
1. Test name `attack_r23_5_registry_detects_fake_version` claims attack regression.
2. Memory `feedback_real_not_paperwork`: "findings ОБЯЗАНЫ pair с real working exploit attempts на real builds, не Tamarin леммы / t-statistic / doc-drift в одиночку".
3. R23 closure claims supply-chain attack defense — but no defense exists in production code.

**Remediation required (handoff):**
1. Either implement real 5-registry integration (cosign + rekor + CT + mirror + p2p) OR remove R23 attack test until backend exists.
2. Replace with attack_supply_chain_libcrux_substitution-style real test that modifies a `~/.cargo/registry/src/...` file and observes whether build/KAT/sig catches it (the test in round-2 reality pass).

---

## HIGH findings

### F-4 — R21 attack test bypasses distributed protocol, manipulates AccountState struct directly

**File:** `crates/umbrella-client/tests/attack_r21_duress_pin_deletes_account.rs:28-115`

**Evidence:**
```rust
fn build_5_server_cluster() -> Vec<AccountState> {
    (0..5).map(|i| {
        AccountState::new(
            [i as u8; 32],
            b"123456",
            [i as u8; 16],
            b"share-encrypted-bytes".to_vec(), // literal placeholder
            ...
        )
    }).collect()
}

// ...

for server in cluster.iter_mut() {
    let _cmd = UnrecoverableDelete {...};
    server.unrecoverable_delete();  // calls local mutator
}
```

**Issues:**
1. `encrypted_share = b"share-encrypted-bytes".to_vec()` — literal placeholder bytes, not real encrypted FROST share.
2. No transport/network layer exercised — test directly calls `server.unrecoverable_delete()`.
3. No threshold-sign verification for the delete command. Real adversary impersonating client could send fake delete without 3-of-5 cluster signature, but this test does not regress that surface.
4. `is_duress_reverse` test is just a string-reverse `ConstantTimeEq` — not an attack scenario.

**PhD-B 6-question self-check:**
- ✗ findings count 5+ from this single test: 0 (it's a happy-path simulation)
- ✗ test naming: `attack_*` adversarial — naming is right, content is behavioral assertion
- ✗ Tamarin engagement: not applicable but expected
- ✗ dudect samples: not applicable
- ✗ reduction sketches: `eprintln` traces share bytes but no security proof
- ✗ literature: none

**Memory disconnect:**
Memory tracks R21 as closed; PhD-B reopens.

**Remediation required (handoff):**
1. Build real client-server test rig with 5 separate `AccountState` instances + mocked transport that requires FROST signature on UNRECOVERABLE_DELETE.
2. Add adversary-impersonation negative test: attacker sends UNRECOVERABLE_DELETE without 3-of-5 signature → cluster rejects.

---

## MAJOR / honest-gap

### F-5 — D-7 rate limit: client-side budget × 5 sibling devices = 500 req/h without backend coordination

**File:** `crates/umbrella-discovery/tests/attack_d7_rate_limit_bypass.rs:50-72`

`d7_attack_five_sibling_devices_independent_budgets_documented` explicitly documents that combined throughput is 5× per-device cap (500/h vs 100/h). Backend `services` must coordinate via privacy-preserving counter.

**Status:** Honest gap, **not** a hidden flaw. Tracked in `docs/spec/discovery-backend-spec.md`. Acceptable PhD-B disclosure if backend ships before 1B-user release.

---

## MINOR findings

### F-6 — D-8 timing test uses 100 iterations, dudect requires 1M+
File `attack_d8_cardinality_timing.rs:87-91` — `let iters = 100u32;`. Memory `feedback_phd_level_mandatory` mandates 1M samples for timing-sensitive paths.

### F-7 — D-1 final test (`d1_attack_compromise_two_servers_no_plaintext_recovery`) is substring scan, not threshold combine attempt
File `attack_d1_plaintext_phone_leak.rs:124-150` — `assert!(!v.windows(11).any(...))`. Should attempt real OPRF reconstruction with 2 sk_shares + observed evaluations and measure bits-recovered.

### F-8 — D-4 does not quantify offline brute-force under 4-of-5 collusion
File `attack_d4_cluster_collusion.rs` — adversary with combined OPRF key can build offline label-table; no measurement of queries × bits.

### F-9 — R22 does not model compromise-primary-device adversary path
File `attack_r22_time_lock_recovery.rs` — tests cover cancel/no-cancel by honest primary; missing: adversary holds both new and primary devices → cancel won't fire → 24h passes → adversary completes recovery.

### F-10 — FFI `OnboardingHandle::mock_with_pin_root` is production-named mock
File `crates/umbrella-ffi/src/export/onboarding.rs:70` — `pub fn mock_with_pin_root(pin_root_hex: String)`. Memory mentions; PhD-B notes the `mock_*` prefix is honest, but visible across FFI boundary. Either gate behind `#[cfg(any(test, feature = "uniffi-test"))]` or add runtime panic in non-test builds.

---

## INFO

### F-11 — D-5 client-side replay window evicts after N nonces; backend filter required
File `attack_d5_oprf_replay.rs:57-79` — `d5_attack_replay_after_window_eviction_passes_but_protocol_still_safe`. Honest disclosure. Documented in spec.

---

## Items confirmed clean (PASS)

- `umbrella-threshold-identity/src/dkg.rs` — real frost-ed25519 v3.0.0 (NCC audited), Pedersen-VSS 3-round, defensive self-inclusion rejection, real test against ed25519_dalek verify_strict.
- `umbrella-threshold-identity/src/signing.rs` — real FROST aggregate, cheater detection, multi-subset quorum tests.
- `umbrella-threshold-identity/src/pin_kdf.rs` — Argon2id with documented mobile params (64 MiB / 3 iter / 4 par), MlockedSecret-backed output, constant-time verify via subtle::ConstantTimeEq, RFC 9106 + Biryukov-Khovratovich 2016 literature.
- `umbrella-threshold-identity/src/key_derivation.rs` — HKDF-SHA256, label-based domain separation, epoch binding, MlockedSecret output, zeroize transient IKM.
- `umbrella-threshold-identity/src/duress.rs` — `is_duress_reverse` is constant-time, palindrome rejection, length-mismatch rejection.
- `umbrella-threshold-identity/src/transport.rs` — fallback chain with monotonic RTT ordering and probe trait; testable.
- `attack_d2_query_correlation` — 1000-query distinctness + cross-server independence.
- `attack_d3_kt_bind_silent_swap` — forged pubkey + forged epoch root + pinned-pk swap + baseline; realistic 8-leaf KT tree.
- `attack_d6_anon_id_reuse` — 10000-salt distinctness + master-key avalanche bound (≤75% common bits).

---

## Inventory data

- **24 crates** in workspace
- **9 unique attack/phd test files** found via grep (R21/R22/R23/R24/R25/R26/R27 + D1-D8 + R5 + various)
- **23 audit reports** in `docs/audits/`
- **3 `#[deprecated]` entries**: vendored openmls crate (2 entries, vendored code — out of scope); `umbrella-identity/src/seed.rs:164 IdentitySeed::generate` (since 1.1.0, M-FINAL-1)

---

## Severity tracking vs. memory

| Item | Memory (project_phd_b_6_rounds_complete) | PhD-B Pass 1 |
|------|-----------------------------------------|--------------|
| `unlock_with_pin` XOR placeholder | MINOR carry-over | **CRITICAL (F-1)** |
| Anon IDs from PIN+salt | not tracked | **CRITICAL (F-2)** |
| R23 5-registry decision-logic | MINOR carry-over | **CRITICAL (F-3)** |
| R21 closure | "shipped" | HIGH reopen (F-4) |
| FFI `mock_with_pin_root` | MINOR carry-over | MINOR (F-10) |
| M-FINAL-1 hw_callback ephemeral seed | MAJOR (independent review) | unchanged |
| R8 SQLite not re-runnable | MINOR carry-over | not re-tested this pass |
| R6 example needs `--features ml-kem` | MINOR carry-over | not re-tested this pass |

---

## Handoff for Pass 2+

**Out of scope this pass (deferred to subsequent passes):**

- Pass 2 target: `umbrella-pq`, `umbrella-crypto-primitives`, `umbrella-oprf`, `umbrella-padding`, `umbrella-sealed-sender`, `umbrella-backup` — re-audit existing PhD-B closures + audit unpassed crates.
- Pass 3 target: `umbrella-core`, `umbrella-mls` (non-R24), `umbrella-identity`, `umbrella-kt`, `umbrella-calls`, `umbrella-formal-verification` (read all .spthy models).
- Pass 4 target: `umbrella-ffi`, `umbrella-ffi-kotlin`, `umbrella-ffi-swift`, `umbrella-platform-verifier`, `umbrella-server-blind-postman`.
- Pass 5 target: `umbrella-fuzz`, `umbrella-lints`, `umbrella-tests`, `umbrella-vectors` + cross-cutting consistency check (memory + docs + code).

**Tamarin model reading (Pass 1 target deferred):** `discovery.spthy` read postponed — Pass 2 should cover all `.spthy` files in `umbrella-formal-verification/models/` together (cross-model consistency check).

**Cross-cutting consistency check (Pass 5):**
- Verify test count: memory says 2179 (post-merge), Read merged commit recent baseline.
- Verify MlockedSecret site count: memory says 7 production sites; grep needs to confirm.
- Cross-check phd-b-distributed-identity-closure-2026-05-19.md against actual code state post-F-1 fix.

---

## Pre-commit decisions

This audit deliverable is committed. Findings F-1 / F-2 / F-3 require code remediation work that exceeds Pass 1 context budget. Per memory `feedback_direct_to_main`: one block = one commit in main. This commit is the Pass 1 audit report; remediation commits in subsequent passes after fix design + implementation per finding.

**No code modifications in this commit** — audit-only.

---

## Real-vs-paperwork verdict (per `feedback_real_not_paperwork`)

| Test | Real adversary modelled? | Measurements? | PhD-B grade |
|------|--------------------------|---------------|-------------|
| D-1 | yes (most sub-tests) | 500 contacts, 16K bytes, 200+ distinct values | B+ |
| D-2 | yes | 1000 queries × 500 cross-server | A- |
| D-3 | yes | 8-leaf KT, 4 attack vectors | A |
| D-4 | yes (partial) | 4-of-5 collusion, KT forge | B |
| D-5 | yes | nonce window 1000+ size | A- |
| D-6 | yes | 10000 salts, avalanche ≤75% | A |
| D-7 | yes (honest gap) | 100/h, 500/h, 23h/25h windows | B+ honest |
| D-8 | partial | 4×100 iters (need 1M) | C+ |
| R21 | **no** | counters/flags only | **D** |
| R22 | yes (partial) | 24h, 1h, +1s windows | B- |
| R23 | **no** (BTreeMap arithmetic) | 5/5, 4/5, 3/5 counts | **D-** |
| R24 (not read this pass) | tbd | tbd | tbd |
| R25 (not read this pass) | tbd | tbd | tbd |
| R26 (not read this pass) | tbd | tbd | tbd |
| R27 (not read this pass) | tbd | tbd | tbd |

**Conclusion:** Discovery (D-series) PhD-B grade B+/A-. Distributed identity client wrapper + R21/R23 attack tests fail real-vs-paperwork bar.

---

## References

- `feedback_real_not_paperwork.md` (memory)
- `feedback_phd_level_mandatory.md` (memory)
- `feedback_phd_vs_a_level_distinguisher.md` (memory)
- `feedback_phd_pass_full_model_reading.md` (memory)
- `project_phd_b_6_rounds_complete.md` (memory)
- Komlo-Goldberg 2020 — FROST: Flexible Round-Optimized Schnorr Threshold Signatures
- Pedersen 1991 — Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing
- Biryukov-Khovratovich 2016 — Argon2 memory-hard hash family
- RFC 9106 — Argon2 parameter recommendations
- RFC 9497 — OPRF Strong Unlinkability
