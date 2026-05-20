//! R6 — REAL lldb memory inspection target for `zeroize`.
//!
//! PhD-B Hybrid PQ **reality pass** (2026-05-19, round 2). The round-1
//! audit said "we trust zeroize::Zeroize for volatile-write semantics
//! preventing LLVM dead-store elimination". R6 actually compiles a release
//! binary, runs it with a known seed, and exposes lldb breakpoint hooks
//! around `xwing_keygen` for memory scanning.
//!
//! Usage:
//!   cargo build --release --example r6_zeroize_lldb_target -p umbrella-pq --features ml-kem
//!   ./docs/audits/reality-pass-artifacts/r6_lldb_scan.sh
//!
//! The example uses a known 32-byte seed of value 0xAA (chosen because 0xAA
//! has unmistakable hex pattern in dumps).

use rand_core::{impls, CryptoRng, RngCore};
use umbrella_pq::xwing_keygen;

/// Deterministic RNG that hands out the byte 0xAA repeatedly.
struct AARng;

impl RngCore for AARng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = 0xAA;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for AARng {}

/// `lldb` breakpoint target: BEFORE keygen.
#[inline(never)]
pub fn r6_phase_before_keygen() {
    // We use eprintln to ensure breakpoint cannot be DCE'd in release.
    eprintln!("[R6] PHASE BEFORE keygen");
    std::hint::black_box(0u8);
}

/// **Positive control** phase: hold a `Vec<u8>` of [0xAA; 32] alive AND in
/// scope so lldb scan can find it. If the scan reports 0 matches here, the
/// methodology is broken (we'd be testing zeroize against a false negative).
#[inline(never)]
pub fn r6_phase_positive_control_filled() {
    let needle: Vec<u8> = vec![0xAAu8; 32];
    let ptr = needle.as_ptr();
    eprintln!("[R6] PHASE positive_control_filled: holding 32 bytes 0xAA at {ptr:p}");
    std::hint::black_box(&needle);
    r6_break_after_fill();
    std::hint::black_box(&needle);
    drop(needle);
}

/// Marker function for lldb breakpoint AFTER needle Vec is filled.
#[inline(never)]
pub fn r6_break_after_fill() {
    std::hint::black_box(0xAAu8);
}

/// `lldb` breakpoint target: AFTER keygen (post-zeroize).
#[inline(never)]
pub fn r6_phase_after_keygen() {
    eprintln!("[R6] PHASE AFTER keygen");
    std::hint::black_box(0u8);
}

/// `lldb` breakpoint target: AFTER drop of secret.
#[inline(never)]
pub fn r6_phase_after_drop() {
    eprintln!("[R6] PHASE AFTER drop");
    std::hint::black_box(0u8);
}

fn main() {
    eprintln!("[R6] Process pid {} starting", std::process::id());

    r6_phase_positive_control_filled();
    r6_phase_before_keygen();
    let mut rng = AARng;
    let (pk, seed) = xwing_keygen(&mut rng).expect("keygen");
    eprintln!(
        "[R6] xwing_keygen complete, pk[0..4] = {:02x}{:02x}{:02x}{:02x}",
        pk.as_bytes()[0],
        pk.as_bytes()[1],
        pk.as_bytes()[2],
        pk.as_bytes()[3]
    );

    r6_phase_after_keygen();

    // Move bindings into a black_box-wrapped tuple, then drop the tuple. The
    // tuple itself is `()`-like (no Drop impl on `XWingSecretSeed`/`XWingPublicKey`),
    // but the move forces both stack slots to be considered released; the LLDB
    // scan at `r6_phase_after_drop()` inspects post-frame memory for the 0xAA
    // pattern. ZeroizeOnDrop semantics are enforced internally inside
    // `xwing_keygen` (see `xwing.rs:151`) — the local `seed` here is only the
    // public stamp, the secret half lives inside ML-KEM internals.
    // Переносим bindings в black_box-обёрнутую tuple и роняем её; LLDB-скан
    // на `r6_phase_after_drop()` смотрит post-frame память. ZeroizeOnDrop
    // обеспечивается внутри `xwing_keygen` (zeroize seed-buffer там);
    // локальные `seed` и `pk` — public материал без секрета.
    let _ = std::hint::black_box((seed, pk));

    r6_phase_after_drop();
}
