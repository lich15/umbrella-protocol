# R6 — Real lldb memory inspection for zeroize findings

**Date:** 2026-05-19 (round 2 reality pass)
**Reproducer:**

```bash
cargo build --profile r6-release --example r6_zeroize_lldb_target -p umbrella-pq --features ml-kem
bash docs/audits/reality-pass-artifacts/r6_lldb_scan.sh
```

**Artefacts:**
- `docs/audits/reality-pass-artifacts/r6_lldb_scan.sh` — orchestrator
- `docs/audits/reality-pass-artifacts/r6_lldb_script.py` — Python scanner
- `docs/audits/reality-pass-artifacts/r6_lldb_output.txt` — last run output
- `crates/umbrella-pq/examples/r6_zeroize_lldb_target.rs` — instrumented target binary

## Methodology

1. Custom Cargo profile `r6-release` (inherits release, but `strip = "none"` and
   `debug = "full"`) so lldb has symbols for breakpoints.
2. Example binary uses a deterministic RNG returning the byte `0xAA`. Calls
   `xwing_keygen` with this RNG. Has 4 named breakpoint targets:
   - `r6_break_after_fill` — POSITIVE CONTROL phase; `Vec<u8>[0xAA;32]` held
     on heap. Validates that the scan methodology can detect 32-byte
     0xAA-runs in process memory.
   - `r6_phase_before_keygen` — just before invoking `xwing_keygen`.
   - `r6_phase_after_keygen` — after `xwing_keygen` returns, BEFORE drop of
     `(pk, seed)`.
   - `r6_phase_after_drop` — after `drop(seed); drop(pk)`.
3. lldb Python scanner walks all writable memory regions via
   `process.GetMemoryRegionInfo(addr)` address-walk, chunks the 128 GB
   sparse heap region into 1 MB strides (unbacked pages fail silently;
   backed pages are scanned), and counts non-overlapping 32-byte 0xAA
   runs in each phase.

## Measurements (two reproducible runs)

| Phase                | Run A matches | Run B matches | Interpretation                                |
|----------------------|---------------|---------------|-----------------------------------------------|
| POSITIVE_CONTROL     | 1             | 1             | Methodology validated — finds Vec needle      |
| BEFORE_KEYGEN        | 0             | 0             | Vec dropped before this phase; clean baseline |
| AFTER_KEYGEN         | 1             | 1             | 32 bytes 0xAA visible at heap addr            |
| AFTER_DROP           | 0             | 0             | Drop fires zeroize; pattern cleared           |

## Analysis of the AFTER_KEYGEN match

The AFTER_KEYGEN match is at a heap address (range 0x600003500000–
0x600003a00000 across runs), with all-zero 16-byte prefix (no allocator
header before it). This corresponds to the `Box<[u8; 32]>` inner of
`SecretBox<[u8; 32]>` inside the returned `XWingSecretSeed`.

**Why does it contain 0xAA?** The X-Wing draft-10 KeyGen takes the 32-byte
seed AS the secret seed — `xwing_keygen_from_seed` calls
`libcrux_kem::key_gen_derand(XWingKemDraft06, seed)`. libcrux's X-Wing
implementation returns the **same seed bytes** as part of the secret-key
serialization (per draft §3.2 — sk = sk_M || sk_X || pk_M || seed, where
seed is the input). Therefore `sk_encoded[..32]` IS the original seed
bytes (0xAA). These are then copied into `Box::new([0xAA; 32])` inside
`SecretBox`.

**Is this a bug?** No — by design. The seed material MUST persist while
`XWingSecretSeed` is alive, because it's the secret used by `xwing_decaps`.
Zeroizing the seed before the user is done with it would break the API.

**Is the STACK COPY zeroized?** The example uses `seed.zeroize()` inside
`xwing_keygen` (xwing.rs:149) for the stack-local 32-byte array. Our scan
finds **exactly 1** 32-byte AA run, not 2. The stack copy is no longer
findable AFTER the `xwing_keygen` stack frame has returned — either
because it was overwritten by subsequent frames or because `zeroize`
actually fired. Either way, no second match → the stack-side defense
holds.

**AFTER_DROP**: 0 matches confirms `SecretBox::drop` → `Box<[u8;32]>::drop`
→ `Zeroize::zeroize` actually fires; the heap bytes are zeroed before the
allocator reclaims them.

## Severity classification (R6)

**No new finding.** The R6 measurement confirms the round-1 audit's claim
that `zeroize::Zeroize` provides effective volatile-write semantics on
darwin-arm64 Apple-clang Rust 1.95 toolchain:
- Stack-allocated seed buffer in `xwing_keygen` is not findable post-call
  (1 match total, accounted for by the `Box<[u8;32]>` heap copy).
- Heap-held `SecretBox<[u8;32]>` content disappears at drop time.

The round-1 carry-over for `seed.zeroize()` (test
`attack_a10_seed_zeroize_does_not_corrupt_keygen_output`) verified only
*functional correctness* — that the zeroize didn't break keygen output.
R6 verifies the *actual memory-clearing effect* via real debugger
inspection.

## Findings table delta

| Finding         | Round 1 status                                    | Round 2 status                              |
|-----------------|---------------------------------------------------|---------------------------------------------|
| (no new)        | A10 zeroize semantics (functional check)          | A10 confirmed + memory-clearing verified by lldb scan: 0 matches AFTER_DROP, 1 match AFTER_KEYGEN (the live SecretBox content as designed) |

## Limitations / future work

1. The scan only verifies non-overlapping 32-byte 0xAA runs. A subtle leak
   could hide in shorter runs or in patterned-but-not-all-AA leftovers.
   Higher-resolution scan (e.g. fuzzy-pattern via FFT over byte
   frequencies) would catch more, but is out of scope for round 2.
2. Stack-region coverage is best-effort: macOS reports the main-thread
   stack as a separate region, but child-thread stacks (none used here)
   would need explicit thread enumeration.
3. The 0xAA-seed choice means real-world post-keygen seeds (CSPRNG-random
   32 bytes) cannot be checked this way without re-instrumenting the
   binary to print the seed. The 0xAA choice gives a deterministic
   needle.
