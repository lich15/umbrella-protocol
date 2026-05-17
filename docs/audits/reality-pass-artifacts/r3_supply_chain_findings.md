# R3 — Real supply-chain substitution exploit findings

**Date:** 2026-05-19 (round 2 reality pass)
**Procedure:** Modified `libcrux-ml-kem 0.0.9` on disk + Cargo `[patch.crates-io]` override + cargo test.
**Two backdoor variants tested.**

## Reproducer (caution — modifies workspace Cargo.toml temporarily)

```bash
# 1) Clone libcrux registry copy:
cp -r ~/.cargo/registry/src/index.crates.io-*/libcrux-ml-kem-0.0.9 /tmp/libcrux-ml-kem-0.0.9-substituted
chmod -R u+w /tmp/libcrux-ml-kem-0.0.9-substituted
# 2) Patch src/mlkem768.rs::decapsulate (see two variants below).
# 3) Add to workspace Cargo.toml [patch.crates-io]:
#    libcrux-ml-kem = { path = "/tmp/libcrux-ml-kem-0.0.9-substituted" }
# 4) cargo test --release -p umbrella-pq --features full
# 5) Restore workspace Cargo.toml after experiment.
```

## Stage 1 — Constant-output backdoor

```rust
pub fn decapsulate(
    _private_key: &MlKem768PrivateKey,
    _ciphertext: &MlKem768Ciphertext,
) -> MlKemSharedSecret {
    [0xAAu8; 32]
}
```

### What caught it

| Layer                 | Test name                                         | Caught? | Mode                                  |
|-----------------------|---------------------------------------------------|---------|---------------------------------------|
| umbrella-pq unit      | `ml_kem::tests::ml_kem_768_roundtrip`             | YES     | `assert_eq!` ss_sender vs ss_receiver fail |
| umbrella-pq unit      | `xwing::tests::xwing_roundtrip`                   | YES     | ditto via X-Wing combiner             |
| umbrella-pq KAT       | `xwing_matches_draft10_appendix_c_vector_1`       | YES     | draft-10 Appendix C ss mismatch       |
| umbrella-pq KAT       | `stability_kat_ml_kem_768_roundtrip`              | YES     | stability vector ss mismatch          |
| umbrella-pq KAT       | `stability_kat_x_wing_roundtrip`                  | YES     | stability X-Wing ss mismatch          |
| umbrella-sealed-sender| (any V2 envelope roundtrip)                       | YES     | `Crypto(AeadAuthFailure)` on unseal_v2 |

**Verdict:** Stage-1 constant-output backdoor is caught at multiple layers
**within seconds** of any test run. The KAT layer is sufficient — KAT failure
would block any release.

## Stage 2 — Subtle telemetry-only backdoor (functional correctness preserved)

```rust
pub fn decapsulate(private_key: ..., ciphertext: ...) -> MlKemSharedSecret {
    let ss = multiplexing::decapsulate::<...>(private_key, ciphertext);
    unsafe {
        R3_LEAK_FIRST_BYTE = ss[0];
        R3_LEAK_CALL_COUNT = R3_LEAK_CALL_COUNT.wrapping_add(1);
    }
    ss
}

pub static mut R3_LEAK_FIRST_BYTE: u8 = 0u8;
pub static mut R3_LEAK_CALL_COUNT: u64 = 0u64;
```

This backdoor **leaks the first byte of every derived shared secret** via a
process-local mutable static (a state-level adversary controlling the
library could replace this with covert side-channel write to attacker-
controlled remote endpoint via NEON timing channel, IPC, kernel module, etc.
— the static was used here because libcrux is `no_std` and we wanted a
zero-fs no-network demonstration).

### What caught it

| Layer                 | Test name                                         | Caught? |
|-----------------------|---------------------------------------------------|---------|
| umbrella-pq unit      | `ml_kem::tests::ml_kem_768_roundtrip`             | NO — ss is correct |
| umbrella-pq unit      | `xwing::tests::xwing_roundtrip`                   | NO      |
| umbrella-pq KAT       | `xwing_matches_draft10_appendix_c_vector_1`       | NO      |
| umbrella-pq KAT       | `stability_kat_ml_kem_768_roundtrip`              | NO      |
| umbrella-pq KAT       | `stability_kat_x_wing_roundtrip`                  | NO      |

**ALL functional KATs PASS — backdoor entirely undetected at functional-test
layer.**

## Severity update

**F-PHD-PQ-5** (round 1, LOW: "1 of N draft-10 vectors imported"): **CONFIRMED
valid** by Stage 1 — the *existing* coverage is sufficient for Stage-1
constant-output backdoors. So Stage 1 → LOW status unchanged.

**F-PHD-PQ-6** (round 1, INFO: "FIPS 203 ACVP KAT placeholder"): **CONFIRMED
valid** by Stage 1. Same as above.

**NEW finding F-PHD-RP-R3-1** (round 2):

| Field         | Value                                                                                       |
|---------------|---------------------------------------------------------------------------------------------|
| Severity      | LOW — informational                                                                          |
| Title         | Functional KATs alone cannot detect telemetry-only / side-channel supply-chain backdoors    |
| Reproducer    | Stage-2 variant in `/tmp/libcrux-ml-kem-0.0.9-substituted/src/mlkem768.rs`                   |
| Scope         | This is a generic property of all signature-style functional KATs in cryptographic libraries; not specific to Umbrella |
| Mitigation    | Defense-in-depth: reproducible builds (already documented in `docs/audits/reproducible-builds.md`), SLSA L3, cargo-vet/crev review, libcrux upstream code signing, `cargo audit` + RustSec watch. Not closeable via more KATs alone. |
| Carry-over    | Carry-over to v1.2.0 reproducible-build hardening track                                     |

## Findings table delta

| Finding         | Round 1 status                       | Round 2 status                            |
|-----------------|--------------------------------------|-------------------------------------------|
| F-PHD-PQ-5      | LOW (1 of N vectors)                 | LOW unchanged — Stage-1 caught everywhere |
| F-PHD-PQ-6      | INFO (ACVP placeholder)              | INFO unchanged — Stage-1 caught everywhere|
| **F-PHD-RP-R3-1**| (new)                               | LOW — KATs blind to telemetry backdoors    |

## Why this is a meaningful finding

The round-1 closure of F-PHD-PQ-5 effectively said "1 KAT suffices for backend
swap detection". Round 2 proves the qualifier: 1 KAT (or even many KATs)
suffices for detection of **functionally-incorrect** swaps. They are
*insufficient* against an adversary willing to ship a backdoor that
preserves functional correctness and exfiltrates via side channel. Defense
must lie at the reproducible-build + supply-chain-review layer, not the
KAT layer.

## Concrete recommendations

1. Pin libcrux-ml-kem source hash in `Cargo.lock` (already done via `=0.0.9`
   pinning + Cargo.lock commit).
2. Add `cargo-vet` or `cargo-crev` review pass for libcrux-ml-kem releases
   to v1.2.0 release checklist.
3. Reproducible-build verification gate: SHA-256 of compiled libcrux binary
   tracked across release cycles; CI alarm on drift.
4. SLSA L3 attestation on libcrux dependency.

These are all infrastructure layers, not source-code defensive measures.
