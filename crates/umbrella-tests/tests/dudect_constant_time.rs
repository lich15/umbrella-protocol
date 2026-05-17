//! Block 10.24 (Stage 10 Phase 3 cross-cutting third block) — measured
//! constant-time verification CT-критичных операций workspace через
//! локальный dudect bench harness `umbrella_tests::dudect`.
//!
//! Methodology + threshold per Reparaz et al. 2017 USENIX Security
//! «Dude, is my code constant time?»:
//!
//! - 10 000 samples per branch (in-block budget; weekly CI cron
//!   `dudect-benchmarks.yml` extends к 100 000 per branch через
//!   env var `DUDECT_SAMPLES`)
//! - Welch's t-test threshold `|t| ≤ 4.5` per spec §3 (α ≈ 10⁻⁵)
//! - percentile cropping bottom 5 % + top 5 % outliers
//! - alternating interleave Fixed/Random classes
//! - **input pools pre-allocated ВНЕ timing loop** (otherwise OsRng
//!   fill_bytes overhead доминирует и инжектит false positive |t|
//!   ~1000-3000)
//!
//! Verdict mapping в `DudectResult::verdict()`: CLEAN |t| ≤ 4.5 |
//! BORDERLINE 4.5-10 | LEAK > 10. Block 10.24 in-block ассерт LEAK
//! threshold > 10 (gross leaks); BORDERLINE наблюдения требуют
//! weekly CI с full sample budget + retry перед F-66+ classification.
//!
//! Direct dudect assertion coverage:
//! 1. `SecretBytes::ct_eq` (umbrella-crypto-primitives) — base
//!    constant-time comparison wrapper для fixed-size secret bytes
//! 2. HKDF expand wrapper `kdf::hkdf_sha256` (umbrella-crypto-primitives)
//!    — secret-keyed key derivation; secret-dependent on IKM
//! 3. Raw `[u8; 32]::ct_eq` (subtle 2.6 baseline) — upstream sanity
//!    reference baseline for all wrappers delegating to it
//! 4. `umbrella_padding::strip_padding` (post F-51 closure) — bucketed
//!    padding tail constant-time check
//! 5. `umbrella_oprf::threshold_combine` 3-of-5 (block 11.4 — closure
//!    half partial criterion 6) — Lagrange interpolation `λ_i(0) =
//!    ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)` через CT curve25519-dalek
//!    Scalar arithmetic + Ristretto255 RistrettoPoint scalar mul
//! 6. `umbrella_client::keystore::RowCipher::decrypt_row` (block 11.7 —
//!    closure F-79 LOW + closure second half partial criterion 6) —
//!    full ChaCha20-Poly1305 AEAD decrypt path с HKDF-SHA512 derive_nonce,
//!    subtle ct_eq nonce match, chacha20poly1305 decrypt+verify_tag
//!    на 200-byte fixed-length payloads
//! 7. `umbrella_pq::ml_kem_768_decaps` valid-vs-invalid ciphertext
//!    backend timing (feature `pq`)
//! 8. `umbrella_pq::xwing_decaps` valid-vs-invalid ciphertext backend
//!    timing (feature `pq`)
//!
//! Direct timing observations that are deliberately not CT assertions:
//! - `umbrella_pq::ml_dsa_65_verify` valid-vs-invalid signature timing.
//!   Verification consumes public inputs (public key, message, context,
//!   signature) and returns validity, so valid-vs-invalid timing is not a
//!   secret-dependent CT invariant.
//!
//! Architectural delegation coverage (verified via `[u8; N]::ct_eq`
//! baseline #3 — wrapper crates delegate без additional logic):
//! - `OprfLabel::ct_eq` (umbrella-oprf) — `pub(crate) from_bytes` исключает
//!   direct dudect bench из integration test scope; per-`label.rs:53-55`
//!   `self.0.ct_eq(&other.0)` — straight delegation к `[u8; 32]::ct_eq`
//! - `IdentityDtlsFingerprint::verify_constant_time` (umbrella-calls)
//!   — `pub(crate)` constructor исключает direct bench; per-`fingerprint.rs`
//!   `self.0.ct_eq(&other.0).into()` — straight delegation к
//!   `[u8; FINGERPRINT_LEN]::ct_eq`
//! - `code_recovery::derive_rotated_identity_material` ct_eq на
//!   pubkey match — function timing **by design** depends on match
//!   outcome (early-return на mismatch skips HKDF expand); ct_eq
//!   internal через `[u8; 32]::ct_eq` baseline
//!
//! Block 10.24 (Stage 10 Phase 3 cross-cutting third block) — measured
//! constant-time verification of CT-critical operations in the
//! workspace via the local dudect bench harness
//! `umbrella_tests::dudect`.
//!
//! Methodology + threshold per Reparaz et al. 2017 USENIX Security
//! "Dude, is my code constant time?":
//!
//! - 10 000 samples per branch (in-block budget; the weekly CI cron
//!   `dudect-benchmarks.yml` extends to 100 000 per branch via the env
//!   var `DUDECT_SAMPLES`)
//! - Welch's t-test threshold `|t| ≤ 4.5` per spec §3 (α ≈ 10⁻⁵)
//! - percentile cropping of the bottom 5 % + top 5 % outliers
//! - alternating interleave of Fixed/Random classes
//! - **input pools pre-allocated OUTSIDE the timing loop** (otherwise
//!   the OsRng `fill_bytes` overhead dominates and injects a
//!   false-positive |t| ~1000-3000)
//!
//! Verdict mapping in `DudectResult::verdict()`: CLEAN |t| ≤ 4.5 |
//! BORDERLINE 4.5-10 | LEAK > 10. Block 10.24 in-block asserts the
//! LEAK threshold > 10 (gross leaks); BORDERLINE observations require
//! the weekly CI with the full sample budget + retry before F-66+
//! classification.
//!
//! Direct dudect assertion coverage:
//! 1. `SecretBytes::ct_eq` (umbrella-crypto-primitives) — base
//!    constant-time comparison wrapper for fixed-size secret bytes
//! 2. HKDF expand wrapper `kdf::hkdf_sha256`
//!    (umbrella-crypto-primitives) — secret-keyed key derivation;
//!    secret-dependent on IKM
//! 3. Raw `[u8; 32]::ct_eq` (subtle 2.6 baseline) — upstream sanity
//!    reference baseline for all wrappers delegating to it
//! 4. `umbrella_padding::strip_padding` (post F-51 closure) — bucketed
//!    padding tail constant-time check
//! 5. `umbrella_oprf::threshold_combine` 3-of-5 (block 11.4 — closure
//!    half partial criterion 6) — Lagrange interpolation `λ_i(0) =
//!    ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)` via CT curve25519-dalek Scalar
//!    arithmetic + Ristretto255 RistrettoPoint scalar mul
//! 6. `umbrella_client::keystore::RowCipher::decrypt_row` (block 11.7 —
//!    closure F-79 LOW + closure second half partial criterion 6) —
//!    full ChaCha20-Poly1305 AEAD decrypt path with HKDF-SHA512 derive_nonce,
//!    subtle ct_eq nonce match, chacha20poly1305 decrypt+verify_tag
//!    on 200-byte fixed-length payloads
//! 7. `umbrella_pq::ml_kem_768_decaps` valid-vs-invalid ciphertext
//!    backend timing (feature `pq`)
//! 8. `umbrella_pq::xwing_decaps` valid-vs-invalid ciphertext backend
//!    timing (feature `pq`)
//!
//! Direct timing observations that are deliberately not CT assertions:
//! - `umbrella_pq::ml_dsa_65_verify` valid-vs-invalid signature timing.
//!   Verification consumes public inputs (public key, message, context,
//!   signature) and returns validity, so valid-vs-invalid timing is not a
//!   secret-dependent CT invariant.
//!
//! Architectural delegation coverage (verified via the
//! `[u8; N]::ct_eq` baseline #3 — wrapper crates delegate without
//! additional logic):
//! - `OprfLabel::ct_eq` (umbrella-oprf) — `pub(crate) from_bytes`
//!   excludes a direct dudect bench from the integration test scope;
//!   per `label.rs:53-55` `self.0.ct_eq(&other.0)` — a straight
//!   delegation to `[u8; 32]::ct_eq`
//! - `IdentityDtlsFingerprint::verify_constant_time` (umbrella-calls)
//!   — the `pub(crate)` constructor excludes a direct bench; per
//!   `fingerprint.rs` `self.0.ct_eq(&other.0).into()` — a straight
//!   delegation to `[u8; FINGERPRINT_LEN]::ct_eq`
//! - `code_recovery::derive_rotated_identity_material` ct_eq on the
//!   pubkey match — function timing **by design** depends on the
//!   match outcome (an early return on mismatch skips HKDF expand);
//!   the internal ct_eq uses the `[u8; 32]::ct_eq` baseline

use core::hint::black_box;

use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;

use umbrella_tests::dudect::{run_dudect, DudectResult, DUDECT_T_THRESHOLD, IN_BLOCK_SAMPLES};

/// Sample budget для in-block run (override через env var в weekly CI).
/// Sample budget for in-block runs (overridable via env var in weekly CI).
fn sample_budget() -> usize {
    std::env::var("DUDECT_SAMPLES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 100)
        .unwrap_or(IN_BLOCK_SAMPLES)
}

/// Block 10.24 in-block guard threshold — `|t| ≤ 10` allowing
/// BORDERLINE без F-66+ classification (subject к weekly CI с full
/// budget recheck). Strict `|t| ≤ DUDECT_T_THRESHOLD` enforced в
/// weekly CI cron job через env var override.
///
/// Block 10.24 in-block guard threshold — `|t| ≤ 10` allowing
/// BORDERLINE without an F-66+ classification (subject to weekly CI
/// with full budget recheck). Strict `|t| ≤ DUDECT_T_THRESHOLD` is
/// enforced in the weekly CI cron job via the env var override.
const IN_BLOCK_GUARD: f64 = 10.0;

/// Diagnostic helper: печатает t-statistic + means в test stdout для
/// человеко-читаемого audit log + assert |t| ≤ 10 (in-block guard).
///
/// Diagnostic helper: prints the t-statistic + means to test stdout
/// for a human-readable audit log + asserts |t| ≤ 10 (in-block guard).
fn report(name: &str, result: &DudectResult) {
    let strict = std::env::var("DUDECT_STRICT")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let guard = if strict {
        DUDECT_T_THRESHOLD
    } else {
        IN_BLOCK_GUARD
    };

    println!(
        "[dudect:{}] t={:+.3} mean_fixed={:.1}ns mean_random={:.1}ns \
         n_fixed={} n_random={} verdict={} (active threshold |t| ≤ {})",
        name,
        result.t,
        result.mean_fixed_ns,
        result.mean_random_ns,
        result.n_fixed,
        result.n_random,
        result.verdict(),
        guard,
    );
    assert!(
        result.t.abs() <= guard,
        "[dudect:{}] guard breached: |t|={:.3} > {} \
         (potential timing leak or invalid measurement design — escalate к F-66+)",
        name,
        result.t.abs(),
        guard,
    );
}

/// Diagnostic helper for timing measurements that are security-relevant
/// observations but not constant-time assertions because the measured
/// class distinction is public by protocol construction.
fn report_public_observation(name: &str, result: &DudectResult, rationale: &str) {
    println!(
        "[dudect:{}] t={:+.3} mean_fixed={:.1}ns mean_random={:.1}ns \
         n_fixed={} n_random={} verdict_observation={} ({})",
        name,
        result.t,
        result.mean_fixed_ns,
        result.mean_random_ns,
        result.n_fixed,
        result.n_random,
        result.verdict(),
        rationale,
    );
}

// =============================================================================
// Site 8: ML-KEM-768 decapsulation backend timing
// =============================================================================

#[cfg(feature = "pq")]
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn ml_kem_768_decaps_valid_vs_invalid_ciphertext_timing() {
    use secrecy::ExposeSecret;
    use umbrella_pq::{ml_kem_768_decaps, ml_kem_768_encaps, ml_kem_768_keygen};

    let samples = sample_budget();
    let mut rng = OsRng;
    let (pk, sk) = ml_kem_768_keygen(&mut rng);
    let (valid_ct, expected_ss) = ml_kem_768_encaps(&mut rng, &pk);

    let invalid_pool: Vec<_> = (0..32)
        .map(|i| {
            let mut ct = valid_ct;
            let first = i % ct.len();
            let second = (i * 17) % ct.len();
            ct[first] ^= 0x80;
            ct[second] ^= 0x01;
            ct
        })
        .collect();

    let result = run_dudect(
        samples,
        |_idx| {
            let ss = ml_kem_768_decaps(black_box(&sk), black_box(&valid_ct));
            assert_eq!(ss.expose_secret(), expected_ss.expose_secret());
            let _ = black_box(ss);
        },
        |idx| {
            let ct = &invalid_pool[idx % invalid_pool.len()];
            let ss = ml_kem_768_decaps(black_box(&sk), black_box(ct));
            let _ = black_box(ss);
        },
    );

    report("umbrella_pq::ml_kem_768_decaps valid-vs-invalid", &result);
}

// =============================================================================
// Site 9: ML-DSA-65 verification public-input timing observation
// =============================================================================

#[cfg(feature = "pq")]
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn ml_dsa_65_verify_valid_vs_invalid_signature_public_observation() {
    use umbrella_pq::{ml_dsa_65_keygen, ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65Signature};

    let samples = sample_budget();
    let mut rng = OsRng;
    let (pk, sk) = ml_dsa_65_keygen(&mut rng);
    let message = b"umbrella production readiness pq timing message";
    let context = b"umbrella-production-readiness-2026-05-09";
    let valid_sig = ml_dsa_65_sign(&mut rng, &sk, message, context).expect("sign fixture");

    let invalid_pool: Vec<_> = (0..32)
        .map(|i| {
            let mut bytes = *valid_sig.as_bytes();
            let index = i % bytes.len();
            bytes[index] ^= 0x40;
            MlDsa65Signature::from_bytes(&bytes).expect("mutated signature has valid length")
        })
        .collect();

    assert!(ml_dsa_65_verify(&pk, message, context, &valid_sig).is_ok());
    for sig in &invalid_pool {
        assert!(ml_dsa_65_verify(&pk, message, context, sig).is_err());
    }

    let result = run_dudect(
        samples,
        |_idx| {
            let r = ml_dsa_65_verify(
                black_box(&pk),
                black_box(message),
                black_box(context),
                black_box(&valid_sig),
            );
            let _ = black_box(r);
        },
        |idx| {
            let sig = &invalid_pool[idx % invalid_pool.len()];
            let r = ml_dsa_65_verify(
                black_box(&pk),
                black_box(message),
                black_box(context),
                black_box(sig),
            );
            let _ = black_box(r);
        },
    );

    report_public_observation(
        "umbrella_pq::ml_dsa_65_verify valid-vs-invalid",
        &result,
        "NOT a CT assertion: verify uses public key, message, context, and signature only; validity is returned",
    );
}

// =============================================================================
// Site 10: X-Wing decapsulation backend timing
// =============================================================================

#[cfg(feature = "pq")]
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn xwing_decaps_valid_vs_invalid_ciphertext_timing() {
    use secrecy::ExposeSecret;
    use umbrella_pq::{xwing_decaps, xwing_encaps, xwing_keygen};

    let samples = sample_budget();
    let mut rng = OsRng;
    let (pk, sk) = xwing_keygen(&mut rng).expect("xwing keygen fixture");
    let (valid_ct, expected_ss) = xwing_encaps(&mut rng, &pk).expect("xwing encaps fixture");

    let invalid_pool: Vec<_> = (0..32)
        .map(|i| {
            let mut ct = valid_ct;
            let first = i % ct.len();
            let second = (i * 29) % ct.len();
            ct[first] ^= 0x20;
            ct[second] ^= 0x02;
            ct
        })
        .collect();

    let result = run_dudect(
        samples,
        |_idx| {
            let ss = xwing_decaps(black_box(&sk), black_box(&valid_ct)).expect("valid decaps");
            assert_eq!(ss.expose_secret(), expected_ss.expose_secret());
            let _ = black_box(ss);
        },
        |idx| {
            let ct = &invalid_pool[idx % invalid_pool.len()];
            let ss = xwing_decaps(black_box(&sk), black_box(ct));
            let _ = black_box(ss);
        },
    );

    report("umbrella_pq::xwing_decaps valid-vs-invalid", &result);
}

// =============================================================================
// Site 11: V2 backup-wrap unwrap_v2_to_v1 end-to-end timing
// (PhD-B Hybrid PQ audit 2026-05-19, F-PHD-PQ-8 carry-over)
// =============================================================================

/// `unwrap_v2_to_v1` valid envelope vs tampered envelope CT measurement.
/// Fixed class: valid V2 envelope with correct AAD; Random class: tampered
/// envelope variants (bit-flips inside aead_payload). Function timing should
/// not distinguish — both paths run through xwing_decaps + HKDF +
/// ChaCha20-Poly1305 decrypt. Invalid runs return Err early at AEAD MAC
/// verification; the CT invariant is that **AEAD MAC verification is
/// constant-time**, which Poly1305 guarantees by design (universal hash).
#[cfg(feature = "pq")]
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn unwrap_v2_to_v1_valid_vs_tampered_envelope_timing() {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use umbrella_backup::cloud_wrap::{
        unwrap_v2_to_v1, wrap_message_key, wrap_v1_into_v2, CanonicalAad, ThresholdConfig,
        WrappingParams, ED25519_PUB_LEN, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION,
    };
    use umbrella_pq::{xwing_keygen, HedgedWitness};

    let samples = sample_budget();
    let mut rng = OsRng;

    // Build baseline V2 envelope.
    let k = Scalar::from(7u64);
    let y = RISTRETTO_BASEPOINT_POINT * k;
    let v1_params = WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys: [[0u8; POINT_LEN]; 5],
        config: ThresholdConfig::default(),
    };
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = CanonicalAad {
        sender_identity_pubkey: [0xAA; ED25519_PUB_LEN],
        recipient_device_pubkey: [0xBB; ED25519_PUB_LEN],
        chat_id: [0xCC; 32],
        msg_seq: 13,
    };
    let v1 = wrap_message_key(&v1_params, &mk, &aad, &mut rng).expect("v1 wrap");
    let (pk, sk) = xwing_keygen(&mut rng).expect("xwing keygen");
    let test_witness = HedgedWitness::zeroed_for_tests_only();
    let valid_v2 =
        wrap_v1_into_v2(&pk, &v1, &aad, &test_witness, &mut rng).expect("v2 wrap");

    // Pool of tampered envelopes (mutate aead_payload at different offsets).
    let tampered_pool: Vec<_> = (0..32)
        .map(|i| {
            let mut v = valid_v2.clone();
            let pos = i % v.aead_payload.len();
            v.aead_payload[pos] ^= 0x55;
            v
        })
        .collect();

    let result = run_dudect(
        samples,
        |_idx| {
            // Valid: must succeed.
            let recovered = unwrap_v2_to_v1(
                black_box(&sk),
                black_box(&pk),
                black_box(&valid_v2),
                black_box(&aad),
            )
            .expect("valid unwrap");
            let _ = black_box(recovered);
        },
        |idx| {
            // Tampered: must fail; either AeadDecryptFailed or XWingDecapsFailed.
            let v = &tampered_pool[idx % tampered_pool.len()];
            let r = unwrap_v2_to_v1(black_box(&sk), black_box(&pk), black_box(v), black_box(&aad));
            let _ = black_box(r);
        },
    );

    // PhD-B audit F-PHD-PQ-8 finding: the valid vs tampered distinction is
    // **already adversary-observable** from the Result variant (`Ok(...)`
    // vs `Err(BackupError::AeadDecryptFailed)`). The function timing
    // unsurprisingly differs by ~hundreds of nanoseconds — valid path
    // completes the full inner V1 WrappedKey parse, while tampered path
    // exits at AEAD MAC verification or X-Wing decaps failure. This is NOT
    // a CT-secret-bit leak (no SECRET KEY material distinguishes the two
    // classes); the distinguishing input — the envelope wire bytes —
    // is public per protocol. Same classification as `ml_dsa_65_verify`
    // (site 9): security-relevant magnitude observation, not a strict CT
    // assertion.
    //
    // The actual CT invariant for V2 unwrap — that AEAD MAC verification
    // is constant-time — is enforced by the underlying chacha20poly1305
    // crate's `Poly1305` (universal hash, secret-independent comparison).
    // That invariant is exercised by site 6 (`RowCipher::decrypt_row`).
    report_public_observation(
        "umbrella_backup::unwrap_v2_to_v1 valid-vs-tampered",
        &result,
        "NOT a CT assertion: success vs error variant is adversary-observable from Result; \
         AEAD MAC constant-time invariant is exercised separately at site 6",
    );
}

/// Pre-генерирует pool из `n` 32-byte random secrets ВНЕ timing loop
/// для dudect Random class — критично для accurate measurement (без
/// этого OsRng overhead доминирует над секретно-зависимой операцией).
///
/// Pre-generates a pool of `n` 32-byte random secrets OUTSIDE the
/// timing loop for the dudect Random class — critical for accurate
/// measurement (otherwise OsRng overhead dominates over the
/// secret-dependent operation).
fn pre_allocate_random_32(n: usize) -> Vec<[u8; 32]> {
    let mut pool = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        pool.push(bytes);
    }
    pool
}

/// Pre-генерирует pool из `n` byte-vectors указанной длины (для
/// padding tests requiring varying-length plaintext inputs).
///
/// Pre-generates a pool of `n` byte vectors of the specified length
/// (for padding tests requiring varying-length plaintext inputs).
fn pre_allocate_random_vec(n: usize, len: usize) -> Vec<Vec<u8>> {
    let mut pool = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        pool.push(bytes);
    }
    pool
}

// =============================================================================
// Site 1: SecretBytes::ct_eq (umbrella-crypto-primitives)
// =============================================================================

/// Verifies `SecretBytes<32>::ct_eq` constant-time invariant. Оба класса
/// читаются из pre-allocated pools одинакового размера; Fixed class
/// сравнивает разные, но одинаковые между samples значения, Random class
/// сравнивает разные случайные значения. Так dudect измеряет содержимое
/// сравниваемых bytes, а не hot-buffer/cache эффект от одного reused object.
///
/// Verifies the `SecretBytes<32>::ct_eq` constant-time invariant. Both
/// classes read from equally sized pre-allocated pools; the Fixed class
/// compares different but sample-stable values, and the Random class
/// compares different random values. This makes dudect measure byte-content
/// dependence instead of a hot-buffer/cache effect from one reused object.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn secret_bytes_ct_eq_constant_time() {
    use umbrella_crypto_primitives::SecretBytes;

    let samples = sample_budget();

    let left_pool: Vec<SecretBytes<32>> = pre_allocate_random_32(samples)
        .into_iter()
        .map(SecretBytes::<32>::new)
        .collect();
    let fixed_pool: Vec<SecretBytes<32>> = (0..samples)
        .map(|_| SecretBytes::<32>::new([0xBB; 32]))
        .collect();
    let random_pool: Vec<SecretBytes<32>> = pre_allocate_random_32(samples)
        .into_iter()
        .map(SecretBytes::<32>::new)
        .collect();

    let result = run_dudect(
        samples,
        |idx| {
            let _ = black_box(black_box(&left_pool[idx]).ct_eq(black_box(&fixed_pool[idx])));
        },
        |idx| {
            let _ = black_box(black_box(&left_pool[idx]).ct_eq(black_box(&random_pool[idx])));
        },
    );

    report("SecretBytes<32>::ct_eq", &result);
}

// =============================================================================
// Site 2: HKDF expand wrapper (umbrella-crypto-primitives)
// =============================================================================

/// Verifies `umbrella_crypto_primitives::kdf::hkdf_sha256` wrapper
/// constant-time invariant — same IKM + same salt + same info (Fixed
/// class) против random IKM каждый index из pre-allocated pool
/// (Random class). HKDF underlying HMAC должно быть CT относительно
/// IKM secrecy.
///
/// Verifies the `umbrella_crypto_primitives::kdf::hkdf_sha256` wrapper
/// constant-time invariant — same IKM + same salt + same info (Fixed
/// class) versus a random IKM for every index from a pre-allocated
/// pool (Random class). The HKDF underlying HMAC must be CT with
/// respect to the IKM secrecy.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn hkdf_expand_constant_time() {
    use umbrella_crypto_primitives::kdf::hkdf_sha256;

    let samples = sample_budget();

    // Fixed IKM + salt + info.
    // Fixed IKM + salt + info.
    let ikm_fixed = [0x42u8; 32];
    let salt: &[u8] = b"umbrella-dudect-test-salt";
    let info: &[u8] = b"umbrella-dudect-test-info";

    // Pre-allocated random IKM pool.
    // Pre-allocated random IKM pool.
    let random_pool = pre_allocate_random_32(samples);

    let result = run_dudect(
        samples,
        |_idx| {
            let okm: umbrella_crypto_primitives::SecretBytes<32> =
                hkdf_sha256(black_box(salt), black_box(&ikm_fixed), black_box(info))
                    .expect("HKDF expand 32 bytes ok");
            let _ = black_box(okm);
        },
        |idx| {
            let okm: umbrella_crypto_primitives::SecretBytes<32> = hkdf_sha256(
                black_box(salt),
                black_box(&random_pool[idx]),
                black_box(info),
            )
            .expect("HKDF expand 32 bytes ok");
            let _ = black_box(okm);
        },
    );

    report("kdf::hkdf_sha256<32>", &result);
}

// =============================================================================
// Site 3: Raw [u8; 32]::ct_eq baseline (subtle 2.6 upstream)
// =============================================================================

/// Reference baseline test — `subtle 2.6` upstream `[u8; 32]::ct_eq`
/// implementation. Если этот test показывает leak — issue в upstream
/// `subtle` crate, не в Umbrella code; carry-over к RustCrypto issue
/// tracker. Защитный baseline для сравнения с derived sites.
///
/// Reference baseline test — `subtle 2.6` upstream `[u8; 32]::ct_eq`
/// implementation. If this test shows a leak — the issue is in the
/// upstream `subtle` crate, not in Umbrella code; carry-over to the
/// RustCrypto issue tracker. A protective baseline for comparison
/// with derived sites.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn raw_array_ct_eq_baseline() {
    let samples = sample_budget();

    let array_a: [u8; 32] = [0xAA; 32];
    let array_b_fixed: [u8; 32] = [0xBB; 32];

    let random_pool = pre_allocate_random_32(samples);

    let result = run_dudect(
        samples,
        |_idx| {
            let _ = black_box(black_box(&array_a).ct_eq(black_box(&array_b_fixed)));
        },
        |idx| {
            let _ = black_box(black_box(&array_a).ct_eq(black_box(&random_pool[idx])));
        },
    );

    report("[u8;32]::ct_eq (subtle 2.6 baseline)", &result);
}

// =============================================================================
// Site 4: umbrella_padding::strip_padding (post F-51 closure)
// =============================================================================

/// Verifies `umbrella_padding::strip_padding` constant-time invariant
/// для tail bytes verification (post F-51 closure). Тест сравнивает
/// два invalid класса одинакового размера: ненулевой padding-byte в
/// фиксированной позиции против ненулевого padding-byte в меняющейся
/// позиции. Оба класса читаются из одинаково больших пулов, чтобы
/// dudect измерял offset-зависимость проверки tail, а не cache эффект
/// от повторного чтения одного hot buffer.
///
/// Verifies the `umbrella_padding::strip_padding` constant-time
/// invariant for tail bytes verification (post F-51 closure). The test
/// compares two invalid same-size classes: a non-zero padding byte at a
/// fixed position versus a non-zero padding byte at a varying position.
/// Both classes are read from equally sized pools so dudect measures
/// offset-dependence of the tail check, not cache effects from repeatedly
/// reading a single hot buffer.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn padding_strip_constant_time() {
    use umbrella_padding::{pad_to_bucket, strip_padding, PaddingError, LENGTH_HEADER_LEN};

    let samples = sample_budget();

    // Одинаковая длина payload → одинаковый bucket/tail size. Оба класса
    // используют pools размера `samples`, чтобы memory/cache footprint был
    // симметричным. Отличается только позиция первого non-zero tail byte.
    //
    // Same payload length → same bucket/tail size. Both classes use pools
    // of `samples` entries, making the memory/cache footprint symmetric.
    // Only the position of the first non-zero tail byte differs.
    let plaintext_len = 200usize;
    let random_plaintexts = pre_allocate_random_vec(samples, plaintext_len);
    let tail_start = LENGTH_HEADER_LEN + plaintext_len;
    let tail_len = pad_to_bucket(&random_plaintexts[0])
        .expect("pad sample ok")
        .len()
        - tail_start;
    assert!(
        tail_len > 1,
        "dudect padding bench requires a non-empty tail"
    );

    let mut fixed_offset_pool = Vec::with_capacity(samples);
    let mut varying_offset_pool = Vec::with_capacity(samples);
    for (idx, plaintext) in random_plaintexts.iter().enumerate() {
        let mut fixed = pad_to_bucket(plaintext).expect("pad fixed-class ok");
        fixed[tail_start] = 0xA5;
        fixed_offset_pool.push(fixed);

        let mut varying = pad_to_bucket(plaintext).expect("pad varying-class ok");
        varying[tail_start + (idx % tail_len)] = 0x5A;
        varying_offset_pool.push(varying);
    }

    let result = run_dudect(
        samples,
        |idx| {
            let err = strip_padding(black_box(&fixed_offset_pool[idx]))
                .expect_err("fixed-offset tamper must be rejected");
            let _ = black_box(matches!(err, PaddingError::NonZeroPadding));
        },
        |idx| {
            let err = strip_padding(black_box(&varying_offset_pool[idx]))
                .expect_err("varying-offset tamper must be rejected");
            let _ = black_box(matches!(err, PaddingError::NonZeroPadding));
        },
    );

    report("umbrella_padding::strip_padding (CT tail offset)", &result);
}

// =============================================================================
// Site 5: umbrella_oprf::threshold_combine 3-of-5 (block 11.4 — closure half partial criterion 6)
// =============================================================================

/// Pre-генерирует pool из `n` 3-of-5 threshold triplets `[(WitnessIndex,
/// ServerEvaluation); 3]`, каждый triplet derived from independent random
/// `master_sk` через Shamir split + actual OPRF blind+evaluate flow на
/// subset {0, 1, 2} (witness indices 1+2+3). Pre-allocation **OUTSIDE**
/// timing loop critical для accurate dudect measurement — без этого OsRng,
/// Shamir polynomial, blind и evaluate overhead доминирует над
/// `threshold_combine` operation и инжектит false positive |t| ~ 10⁴-10⁶.
///
/// Pool variability обеспечивается independent `generate_test_private_key`
/// call per triplet — каждое `master_sk` dictates uniquely 5 partial shares
/// через polynomial `f(x) = master_sk + a₁·x + a₂·x² (mod q)` степени
/// `threshold − 1 = 2`.
///
/// Pre-generates a pool of `n` 3-of-5 threshold triplets
/// `[(WitnessIndex, ServerEvaluation); 3]`, each derived from an
/// independent random `master_sk` via a Shamir split + an actual OPRF
/// blind+evaluate flow on the subset {0, 1, 2} (witness indices 1+2+3).
/// Pre-allocation **OUTSIDE** the timing loop is critical for accurate
/// dudect measurement — otherwise OsRng + Shamir polynomial + blind +
/// evaluate overhead dominates over the `threshold_combine` operation and
/// injects a false positive |t| ~ 10⁴-10⁶.
///
/// Pool variability is provided by an independent
/// `generate_test_private_key` call per triplet — each `master_sk` uniquely
/// dictates the 5 partial shares via the polynomial
/// `f(x) = master_sk + a₁·x + a₂·x² (mod q)` of degree
/// `threshold − 1 = 2`.
fn pre_allocate_threshold_triplets(
    n: usize,
) -> Vec<[(umbrella_oprf::WitnessIndex, umbrella_oprf::ServerEvaluation); 3]> {
    use curve25519_dalek::scalar::Scalar;
    use umbrella_oprf::{
        blind, evaluate_for_testing, generate_test_private_key, shamir_split_for_testing,
        OprfInput, ServerEvaluation, ThresholdConfig, WitnessIndex,
    };

    let config = ThresholdConfig::default();
    let oprf_input = OprfInput::new(b"dudect-threshold-bench-input")
        .expect("OprfInput::new accepts non-empty input under MAX_INPUT_BYTES");

    let mut pool: Vec<[(WitnessIndex, ServerEvaluation); 3]> = Vec::with_capacity(n);
    for _ in 0..n {
        let master_sk_bytes = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk_bytes)
            .expect("generate_test_private_key returns canonical Scalar bytes");
        let raw_shares = shamir_split_for_testing(k, config, &mut OsRng);

        let (blinded, _state) = blind(oprf_input, &mut OsRng).expect("blind ok for valid input");

        let triplet: [(WitnessIndex, ServerEvaluation); 3] = std::array::from_fn(|slot| {
            let (wi, share_scalar) = raw_shares[slot];
            let sk = share_scalar.to_bytes();
            let eval = evaluate_for_testing(&blinded, &sk)
                .expect("evaluate_for_testing ok for canonical share scalar");
            (wi, eval)
        });
        pool.push(triplet);
    }
    pool
}
//
// Threat model: SPEC-01 § 4 row 13 «Регулятор требует backdoor» — adversary
// с timing observation на client device после 100 000+ вызовов
// `threshold_combine` пытается extract информацию о partial evaluation values
// (либо witness indices subset choice) которые в количестве ≥ threshold (3)
// позволили бы reconstruction master_sk через Lagrange interpolation. Защита:
// `threshold_combine` должен быть constant-time относительно ServerEvaluation
// values + WitnessIndex order (Lagrange coefficients computed через CT
// curve25519-dalek Scalar arithmetic + Ristretto255 RistrettoPoint
// multiplication, validated upstream subtle 2.6+ baseline).
//
// Threat model: SPEC-01 § 4 row 13 "regulator demands backdoor" — an
// adversary with timing observations on the client device after 100 000+
// `threshold_combine` invocations attempts to extract information about
// partial evaluation values (or witness indices subset choice) which —
// when collected in the threshold count (3) — would allow master_sk
// reconstruction via Lagrange interpolation. Defence: `threshold_combine`
// must be constant-time with respect to ServerEvaluation values +
// WitnessIndex order (Lagrange coefficients computed via CT
// curve25519-dalek Scalar arithmetic + Ristretto255 RistrettoPoint
// multiplication, validated upstream subtle 2.6+ baseline).

/// **Sanity test (non-ignored)** — verifies `pre_allocate_threshold_triplets`
/// helper produces a well-formed pool of independent threshold triplets:
/// witness indices 1+2+3 fixed (subset {0, 1, 2} of 5-of-5 split), partial
/// evaluations vary per triplet (independent master_sk per triplet), and
/// each triplet is a valid input для `threshold_combine`.
///
/// Гарантирует что dudect bench Site 5 helper wiring корректно перед
/// измерением timing — выполняется в default `cargo test` (cfg-independent
/// + +1 net new test в baseline).
///
/// **Sanity test (non-ignored)** — verifies the
/// `pre_allocate_threshold_triplets` helper produces a well-formed pool of
/// independent threshold triplets: witness indices 1+2+3 are fixed (subset
/// {0, 1, 2} of a 5-of-5 split), partial evaluations vary per triplet
/// (independent master_sk per triplet), and each triplet is a valid input
/// for `threshold_combine`.
///
/// Ensures the dudect Site 5 helper wiring is correct prior to a timing
/// measurement — runs in the default `cargo test` (cfg-independent + +1 net
/// new test in the baseline).
#[test]
fn threshold_combine_dudect_pool_sanity() {
    use umbrella_oprf::{threshold_combine, ThresholdConfig, WitnessIndex};

    let pool = pre_allocate_threshold_triplets(3);
    assert_eq!(pool.len(), 3, "pool size matches request");

    let expected_indices = [1u8, 2, 3];
    for (triplet_idx, triplet) in pool.iter().enumerate() {
        for (slot, expected) in expected_indices.iter().enumerate() {
            assert_eq!(
                triplet[slot].0,
                WitnessIndex::new(*expected).expect("1..=5"),
                "triplet {triplet_idx} slot {slot}: expected WitnessIndex({expected})",
            );
        }
    }

    // Pool variability — different master_sk per triplet → different
    // ServerEvaluation values across triplets для same slot index.
    // Pool variability — a different master_sk per triplet leads to
    // different ServerEvaluation values across triplets at the same slot.
    assert_ne!(
        pool[0][0].1.as_bytes(),
        pool[1][0].1.as_bytes(),
        "pool[0][0] and pool[1][0] should differ — independent random master_sk",
    );

    // Каждый triplet — валидный вход для threshold_combine 3-of-5.
    // Each triplet is a valid input for threshold_combine 3-of-5.
    let config = ThresholdConfig::default();
    for (idx, triplet) in pool.iter().enumerate() {
        threshold_combine(triplet, config)
            .unwrap_or_else(|err| panic!("triplet {idx} must combine: {err:?}"));
    }
}

/// Verifies `umbrella_oprf::threshold_combine` 3-of-5 constant-time
/// invariant — fixed triplet `[(WitnessIndex, ServerEvaluation); 3]` (Fixed
/// class) против каждый sample берёт fresh independent triplet из
/// pre-allocated pool (Random class). Internal Lagrange interpolation
/// `λ_i(0) = ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)` использует CT
/// `curve25519_dalek::Scalar` arithmetic + CT Ristretto255 RistrettoPoint
/// scalar multiplication; CT гарантия naturally derives от upstream subtle
/// 2.6+ + curve25519-dalek 4.x guarantees. Если |t| > IN_BLOCK_GUARD = 10
/// → potential timing leak F-66+ requiring CT refactor либо upstream
/// curve25519-dalek issue investigation.
///
/// Verifies the `umbrella_oprf::threshold_combine` 3-of-5 constant-time
/// invariant — a fixed triplet `[(WitnessIndex, ServerEvaluation); 3]`
/// (Fixed class) versus each sample drawing a fresh independent triplet
/// from a pre-allocated pool (Random class). The internal Lagrange
/// interpolation `λ_i(0) = ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)` uses CT
/// `curve25519_dalek::Scalar` arithmetic + CT Ristretto255 RistrettoPoint
/// scalar multiplication; the CT guarantee derives naturally from the
/// upstream subtle 2.6+ + curve25519-dalek 4.x guarantees. If
/// |t| > IN_BLOCK_GUARD = 10 → a potential timing leak F-66+ requiring a
/// CT refactor or an upstream curve25519-dalek issue investigation.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn threshold_combine_constant_time() {
    use umbrella_oprf::{threshold_combine, ThresholdConfig};

    let samples = sample_budget();
    let config = ThresholdConfig::default();

    // Fixed input — single triplet используется во всех Fixed class
    // iterations (полностью deterministic input).
    // Fixed input — a single triplet is reused across all Fixed class
    // iterations (a fully deterministic input).
    let fixed_pool = pre_allocate_threshold_triplets(1);
    let fixed_triplet = fixed_pool.into_iter().next().expect("pool size >= 1");

    // Pre-allocated random pool — N independent random triplets.
    // Pre-allocated random pool — N independent random triplets.
    let random_pool = pre_allocate_threshold_triplets(samples);

    let result = run_dudect(
        samples,
        |_idx| {
            let combined = threshold_combine(black_box(&fixed_triplet), black_box(config))
                .expect("threshold_combine fixed triplet ok");
            let _ = black_box(combined);
        },
        |idx| {
            let combined = threshold_combine(black_box(&random_pool[idx]), black_box(config))
                .expect("threshold_combine random triplet ok");
            let _ = black_box(combined);
        },
    );

    report("umbrella_oprf::threshold_combine 3-of-5", &result);
}

// =============================================================================
// Site 6: umbrella_client::keystore::RowCipher::decrypt_row (block 11.7 —
//         closure F-79 LOW + closure second half partial criterion 6
//         ADR-015 §Решение 5)
// =============================================================================
//
// Threat model: SPEC-01 § 4 row 11 «Cold-boot/forensics on device» — local
// adversary с physical либо memory-dump доступом к user device может вызывать
// `RowCipher::decrypt_row` 100 000+ раз и измерять wall-clock execution time
// с nanosecond resolution. Если decrypt operation timing зависит от:
//   (a) byte content зашифрованных rows (различная компрессия, branch на
//       byte values),
//   (b) AEAD authentication tag verification path (early-return на mismatch
//       vs full verification на match),
//   (c) HKDF-SHA512 nonce derive operation timing (различные info bytes
//       → различные internal HMAC state),
//   (d) `subtle::ConstantTimeEq::ct_eq` сравнение derived vs supplied nonce
//       (post F-57 closure block 10.16 ChaCha20-Poly1305 в ADR-010 Решение 5
//       §C.1.2),
// → adversary через timing side-channel может через статистический анализ
// извлечь биты master-key либо plaintext content (Lucky-13-style attack
// adapted к ChaCha20-Poly1305 row-cipher).
//
// Defence: end-to-end decrypt path должен быть constant-time relative к
// (ciphertext content × master-key bytes × derived nonce × tag bytes) для
// fixed-length payloads (одинаковая длина → одинаковая работа AEAD core).
// Site 6 measures full decrypt path с fixed-length 200-byte payloads + 8-byte
// row_id + fixed `messages.text` context (production string per ADR-010);
// Fixed class повторно decrypt'ит one-and-the-same encrypted row; Random
// class draws fresh independent encrypted row из bounded pool каждую
// iteration. Constant-time invariant держится если |t| ≤ DUDECT_T_THRESHOLD
// = 4.5 per Reparaz et al. 2017 USENIX Security spec §3 α ≈ 10⁻⁵.
//
// **Cache-contamination mitigation** (block 11.7 design lesson; не повторять
// Site 5 large-pool pattern для μs-scale operations): RowCipher::decrypt_row
// timing ~2.7 μs per call. Если Random pool grows к WEEKLY_CI_SAMPLES
// (100 000) records × ~256 bytes per fixture → ~25 MB working set, что
// **превышает L3 cache** (~8 MB на arm64 / ~16 MB на ubuntu CI). Random
// class fetch'ит cache-cold lines (~100 ns penalty per fetch); Fixed class
// hot reads single fixture (~2 ns penalty). Resulting cache-bias mean
// difference ~3 ns на 2670 ns timing = 0.11 % relative — статистически
// значимо при 100 000 samples (|t| ≈ −24) **но НЕ secret-dependent leak**:
// adversary в реальной угрозе SPEC-01 § 4 row 11 не контролирует cache state
// и не имеет возможности batch'ить 100 000 decrypt'ов own choice ciphertexts
// в bench-friendly cache-cold patterns. Mitigation: bound `RANDOM_POOL_SIZE
// = 32` (~8 KB working set, fits L1d cache 16-32 KB modern arm64/x86_64) →
// Random class cycle через 32 cache-hot fixtures, Fixed class reuses single
// cache-hot fixture; cache state symmetric для обеих классов; t-statistic
// reflects genuine CT-relevant operation timing variance (HKDF + ct_eq +
// AEAD decrypt) без cache-bias artifact. CT discriminator preserved: 32
// independent random plaintexts/nonces/tags per row covers Lucky-13-style
// CT operation variability на bit-level (see RFC 7457 Appendix B Figure 2).
// Site 5 (`threshold_combine` ~133 μs) не affected потому что cache effect
// 3 ns / 133 760 ns = 0.0023 % — sub-noise-floor для 9000 samples.
//
// Threat model: SPEC-01 § 4 row 11 "Cold-boot / forensics on device" — a
// local adversary with physical or memory-dump access to the user device
// can invoke `RowCipher::decrypt_row` 100 000+ times and measure wall-clock
// execution time with nanosecond resolution. If the decrypt operation
// timing depends on:
//   (a) byte content of the encrypted rows (varying compression, branches
//       on byte values),
//   (b) the AEAD authentication tag verification path (early-return on
//       mismatch vs. a full verification on match),
//   (c) HKDF-SHA512 nonce derivation timing (different info bytes →
//       different internal HMAC state),
//   (d) the `subtle::ConstantTimeEq::ct_eq` comparison between the derived
//       and the supplied nonce (post F-57 closure block 10.16
//       ChaCha20-Poly1305 in ADR-010 Decision 5 §C.1.2),
// → the adversary, via a timing side channel, can statistically recover
// bits of the master-key or plaintext content (a Lucky-13-style attack
// adapted to the ChaCha20-Poly1305 row-cipher).
//
// Defence: the end-to-end decrypt path must be constant-time relative to
// (ciphertext content × master-key bytes × derived nonce × tag bytes) for
// fixed-length payloads (identical length → identical AEAD core work).
// Site 6 measures the full decrypt path with fixed-length 200-byte payloads
// + 8-byte row_id + fixed `messages.text` context (a production string per
// ADR-010); the Fixed class re-decrypts one-and-the-same encrypted row;
// the Random class draws a fresh independent encrypted row from a bounded
// pool on every iteration. The constant-time invariant holds when |t| ≤
// DUDECT_T_THRESHOLD = 4.5 per Reparaz et al. 2017 USENIX Security spec §3
// α ≈ 10⁻⁵.
//
// **Cache-contamination mitigation** (block 11.7 design lesson; do not
// reuse the Site 5 large-pool pattern for μs-scale operations):
// RowCipher::decrypt_row timing is ~2.7 μs per call. If the Random pool
// grows to WEEKLY_CI_SAMPLES (100 000) records × ~256 bytes per fixture →
// ~25 MB working set, which **exceeds the L3 cache** (~8 MB on arm64 /
// ~16 MB on ubuntu CI). The Random class fetches cache-cold lines
// (~100 ns penalty per fetch); the Fixed class hot-reads a single fixture
// (~2 ns penalty). The resulting cache-bias mean difference is ~3 ns on
// a 2670 ns timing = 0.11 % relative — statistically significant at
// 100 000 samples (|t| ≈ −24) **but NOT a secret-dependent leak**: the
// adversary in the real SPEC-01 § 4 row 11 threat does not control cache
// state and cannot batch 100 000 decrypts of own-choice ciphertexts in
// bench-friendly cache-cold patterns. Mitigation: bound `RANDOM_POOL_SIZE
// = 32` (~8 KB working set, fits the L1d cache of 16-32 KB on modern
// arm64/x86_64) → the Random class cycles through 32 cache-hot fixtures
// while the Fixed class reuses a single cache-hot fixture; the cache
// state is symmetric for both classes; the t-statistic reflects the
// genuine CT-relevant operation timing variance (HKDF + ct_eq + AEAD
// decrypt) without the cache-bias artifact. The CT discriminator is
// preserved: 32 independent random plaintexts/nonces/tags per row cover
// Lucky-13-style CT operation variability at the bit level (see RFC 7457
// Appendix B Figure 2). Site 5 (`threshold_combine` ~133 μs) is not
// affected because the cache effect 3 ns / 133 760 ns = 0.0023 % is below
// the noise floor for 9000 samples.

/// Bounded Random pool size для Site 6 — 32 fixtures × ~256 bytes per
/// fixture ≈ 8 KB working set fits в L1d cache (16-32 KB modern arm64 /
/// x86_64). Eliminates cache-contamination bias на μs-scale decrypt
/// operation; CT discriminator preserved через 32 независимых random
/// (plaintext × ciphertext × nonce × tag) variants. См. cache-contamination
/// mitigation rationale выше.
///
/// Bounded Random pool size for Site 6 — 32 fixtures × ~256 bytes per
/// fixture ≈ 8 KB working set fits in the L1d cache (16-32 KB on modern
/// arm64 / x86_64). Eliminates the cache-contamination bias on the
/// μs-scale decrypt operation; the CT discriminator is preserved by 32
/// independent random (plaintext × ciphertext × nonce × tag) variants.
/// See the cache-contamination mitigation rationale above.
const ROW_CIPHER_RANDOM_POOL_SIZE: usize = 32;

/// Self-contained fixture for one pre-encrypted row — `(row_id, ciphertext,
/// nonce, tag)` плюс optional original `plaintext` для sanity-roundtrip
/// проверки. Pool of fixtures возвращается from `pre_allocate_encrypted_rows`
/// и используется dudect bench без recreate `RowCipher` либо invoke
/// `encrypt_row` ВНУТРИ timing loop (otherwise encrypt overhead доминирует
/// над decrypt и инжектит false positive |t| ~ 10⁴).
///
/// Self-contained fixture for one pre-encrypted row — `(row_id, ciphertext,
/// nonce, tag)` plus the optional original `plaintext` for a sanity
/// roundtrip check. The pool of fixtures returned from
/// `pre_allocate_encrypted_rows` is consumed by the dudect bench without
/// recreating the `RowCipher` or invoking `encrypt_row` INSIDE the timing
/// loop (otherwise encrypt overhead dominates over decrypt and injects a
/// false-positive |t| ~ 10⁴).
struct EncryptedRowFixture {
    row_id: [u8; 8],
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; 16],
}

/// Pre-генерирует pool из `n` encrypted row fixtures одинаковой
/// `plaintext_len` под shared `cipher` и `context` — каждый row получает
/// уникальный `row_id` (8-byte big-endian counter) → unique HKDF-derived
/// nonce → no nonce reuse под one master-key (AEAD invariant preserved).
/// Pool variability обеспечивается independent random `plaintext` per row;
/// `cipher.encrypt_row` invoked OUTSIDE timing loop → encrypt overhead
/// (HKDF expand 50-byte info + ChaCha20 keystream + Poly1305 tag) не
/// загрязняет measurement decrypt operation.
///
/// Pre-generates a pool of `n` encrypted row fixtures of the same
/// `plaintext_len` under a shared `cipher` and `context` — each row gets a
/// unique `row_id` (8-byte big-endian counter) → a unique HKDF-derived
/// nonce → no nonce reuse under a single master-key (the AEAD invariant
/// is preserved). Pool variability is provided by an independent random
/// `plaintext` per row; `cipher.encrypt_row` is invoked OUTSIDE the timing
/// loop, so the encrypt overhead (HKDF expand on a 50-byte info +
/// ChaCha20 keystream + Poly1305 tag) does not contaminate the decrypt
/// operation measurement.
fn pre_allocate_encrypted_rows(
    cipher: &umbrella_client::keystore::RowCipher,
    context: &str,
    n: usize,
    plaintext_len: usize,
) -> Vec<EncryptedRowFixture> {
    let mut pool = Vec::with_capacity(n);
    for i in 0..n {
        let row_id = (i as u64).to_be_bytes();
        let mut plaintext = vec![0u8; plaintext_len];
        OsRng.fill_bytes(&mut plaintext);
        let (ciphertext, nonce, tag) = cipher
            .encrypt_row(context, &row_id, &plaintext)
            .expect("encrypt_row на valid input infallible per ChaCha20-Poly1305 spec");
        pool.push(EncryptedRowFixture {
            row_id,
            plaintext,
            ciphertext,
            nonce,
            tag,
        });
    }
    pool
}

/// **Sanity test (non-ignored)** — verifies `pre_allocate_encrypted_rows`
/// helper produces a well-formed pool of independent encrypted row
/// fixtures: pool size matches request, row_ids уникальные (counter
/// 0..n), ciphertexts отличаются друг от друга (random plaintexts per
/// row → random ChaCha20 keystream output → distinct ciphertexts с
/// overwhelming probability), nonces отличаются (deterministic HKDF
/// derive с unique row_id per row), и каждый fixture roundtrip'ает через
/// `RowCipher::decrypt_row` обратно в bit-exact исходный plaintext.
///
/// Гарантирует что dudect bench Site 6 helper wiring корректно перед
/// измерением timing — выполняется в default `cargo test` (cfg-independent;
/// 1 net new test в baseline; не требует `--release` для small-pool
/// correctness check).
///
/// **Sanity test (non-ignored)** — verifies the
/// `pre_allocate_encrypted_rows` helper produces a well-formed pool of
/// independent encrypted row fixtures: the pool size matches the request,
/// row_ids are unique (counter 0..n), ciphertexts differ from each other
/// (random plaintexts per row → random ChaCha20 keystream output →
/// distinct ciphertexts with overwhelming probability), nonces differ
/// (deterministic HKDF derivation with a unique row_id per row), and each
/// fixture roundtrips through `RowCipher::decrypt_row` back to the
/// bit-exact original plaintext.
///
/// Ensures the dudect Site 6 helper wiring is correct prior to a timing
/// measurement — runs in the default `cargo test` (cfg-independent +
/// 1 net new test in the baseline; does not require `--release` for the
/// small-pool correctness check).
#[test]
fn row_cipher_decrypt_dudect_pool_sanity() {
    use umbrella_client::keystore::RowCipher;

    let cipher = RowCipher::new([0xCCu8; 32]);
    let context = "messages.text";
    let plaintext_len = 200usize;

    let pool = pre_allocate_encrypted_rows(&cipher, context, 4, plaintext_len);
    assert_eq!(pool.len(), 4, "pool size matches request");

    // row_ids уникальные counter 0..n.
    // row_ids are unique counter 0..n.
    for (i, fixture) in pool.iter().enumerate() {
        let expected = (i as u64).to_be_bytes();
        assert_eq!(fixture.row_id, expected, "row_id at index {i}");
        assert_eq!(
            fixture.plaintext.len(),
            plaintext_len,
            "plaintext length at index {i}",
        );
        assert_eq!(
            fixture.ciphertext.len(),
            plaintext_len,
            "ChaCha20-Poly1305 ciphertext-length = plaintext-length (detached tag) at index {i}",
        );
    }

    // Pool variability — random plaintexts → random ChaCha20 keystream
    // outputs → distinct ciphertexts (collision probability ≈ 2⁻⁸⁰⁰ for
    // 200-byte payloads — astronomically negligible).
    // Pool variability — random plaintexts → random ChaCha20 keystream
    // outputs → distinct ciphertexts (collision probability ≈ 2⁻⁸⁰⁰ for
    // 200-byte payloads — astronomically negligible).
    assert_ne!(
        pool[0].ciphertext, pool[1].ciphertext,
        "independent random plaintexts must produce distinct ciphertexts",
    );

    // Nonces отличаются — HKDF-SHA512 deterministic от unique row_id per
    // row → distinct 12-byte outputs (12-byte HKDF output collision
    // probability negligible for distinct 8-byte info inputs).
    // Nonces differ — HKDF-SHA512 is deterministic on a unique row_id per
    // row → distinct 12-byte outputs (a 12-byte HKDF output collision
    // probability is negligible for distinct 8-byte info inputs).
    assert_ne!(
        pool[0].nonce, pool[1].nonce,
        "distinct row_ids must produce distinct HKDF-derived nonces",
    );

    // Каждая запись roundtrip'ает обратно в исходный plaintext bit-exact.
    // Each fixture roundtrips back to the original plaintext bit-exact.
    for (i, fixture) in pool.iter().enumerate() {
        let recovered = cipher
            .decrypt_row(
                context,
                &fixture.row_id,
                &fixture.ciphertext,
                fixture.nonce,
                fixture.tag,
            )
            .unwrap_or_else(|err| panic!("fixture {i} must decrypt: {err:?}"));
        assert_eq!(
            recovered, fixture.plaintext,
            "fixture {i} roundtrip must recover original plaintext",
        );
    }
}

/// Verifies `umbrella_client::keystore::RowCipher::decrypt_row`
/// constant-time invariant — fixed `EncryptedRowFixture` (Fixed class)
/// против каждый sample берёт fresh independent fixture из
/// pre-allocated pool (Random class). Decrypt path encompasses:
///
///   1. HKDF-SHA512 derive_nonce от `(master_key, info=PREFIX‖context‖row_id)`
///   2. `subtle::ConstantTimeEq::ct_eq` сравнение derived vs supplied nonce
///   3. ChaCha20-Poly1305 `decrypt_in_place_detached` (AEAD decrypt + tag
///      verify) на 200-byte ciphertext с 16-byte tag
///
/// CT гарантия naturally derives от:
///
///   - HKDF-SHA512 fixed-length info input (29 + 13 + 8 = 50 bytes) → CT
///     HMAC-SHA512 internal block processing
///   - subtle 2.6+ `[u8; 12]::ct_eq` upstream baseline (verified via Site 3
///     `[u8; 32]::ct_eq` — same wrapper variant differs only в array size)
///   - chacha20poly1305 0.10+ AEAD `decrypt_in_place_detached` upstream CT
///     guarantee (RustCrypto policy: "constant-time on equal-length inputs")
///
/// Если |t| > IN_BLOCK_GUARD = 10 → potential timing leak F-66+ requiring
/// либо CT refactor `RowCipher::decrypt_row` либо upstream RustCrypto
/// chacha20poly1305 / hkdf / subtle issue investigation.
///
/// Verifies the `umbrella_client::keystore::RowCipher::decrypt_row`
/// constant-time invariant — a fixed `EncryptedRowFixture` (Fixed class)
/// versus each sample drawing a fresh independent fixture from a
/// pre-allocated pool (Random class). The decrypt path encompasses:
///
///   1. HKDF-SHA512 derive_nonce on `(master_key, info=PREFIX‖context‖row_id)`
///   2. `subtle::ConstantTimeEq::ct_eq` comparison of derived vs supplied
///      nonce
///   3. ChaCha20-Poly1305 `decrypt_in_place_detached` (AEAD decrypt + tag
///      verify) on a 200-byte ciphertext with a 16-byte tag
///
/// The CT guarantee derives naturally from:
///
///   - HKDF-SHA512 with a fixed-length info input (29 + 13 + 8 = 50 bytes)
///     → CT HMAC-SHA512 internal block processing
///   - the subtle 2.6+ `[u8; 12]::ct_eq` upstream baseline (verified via
///     Site 3 `[u8; 32]::ct_eq` — the wrapper variant differs only in
///     array size)
///   - chacha20poly1305 0.10+ AEAD `decrypt_in_place_detached` upstream CT
///     guarantee (RustCrypto policy: "constant-time on equal-length inputs")
///
/// If |t| > IN_BLOCK_GUARD = 10 → a potential timing leak F-66+ requiring
/// either a CT refactor of `RowCipher::decrypt_row` or an upstream
/// investigation of the RustCrypto chacha20poly1305 / hkdf / subtle issue.
// Гейт `#[ignore]` — dudect bench tests требуют `--release` для accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead который invalidates Welch's t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// Weekly CI cron `dudect-benchmarks.yml` invokes this с `DUDECT_SAMPLES=100000`.
//
// Gate `#[ignore]` — dudect bench tests require `--release` for accurate
// timing measurements (debug-build panic checks + bounds checks add
// nanosecond-level overhead that invalidates the Welch t-test signal).
// Run via: `cargo test --release --locked -p umbrella-tests --test
// dudect_constant_time -- --ignored --nocapture --test-threads=1`.
// The weekly CI cron `dudect-benchmarks.yml` invokes this with
// `DUDECT_SAMPLES=100000`.
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn row_cipher_decrypt_constant_time() {
    use umbrella_client::keystore::RowCipher;

    let samples = sample_budget();
    let context = "messages.text";
    let plaintext_len = 200usize;

    let cipher = RowCipher::new([0xCCu8; 32]);

    // Fixed input — single fixture повторно decrypt'ится во всех Fixed
    // class iterations (полностью deterministic input, bit-exact same
    // operation повторно).
    // Fixed input — a single fixture is re-decrypted across all Fixed
    // class iterations (a fully deterministic input, the bit-exact same
    // operation repeated).
    let mut fixed_pool = pre_allocate_encrypted_rows(&cipher, context, 1, plaintext_len);
    let fixed = fixed_pool
        .pop()
        .expect("pre_allocate_encrypted_rows(n=1) returns 1 fixture");

    // Pre-allocated bounded random pool — `ROW_CIPHER_RANDOM_POOL_SIZE`
    // = 32 independent fixtures с fresh random plaintexts + unique
    // row_id per fixture. Bounded к L1d cache footprint (~8 KB) для
    // elimination cache-contamination bias на μs-scale decrypt
    // operation; см. mitigation rationale выше. CT discriminator
    // preserved через 32 independent random fixtures cycle.
    //
    // Pre-allocated bounded random pool — `ROW_CIPHER_RANDOM_POOL_SIZE`
    // = 32 independent fixtures with fresh random plaintexts + a unique
    // row_id per fixture. Bounded to the L1d cache footprint (~8 KB)
    // to eliminate the cache-contamination bias on the μs-scale decrypt
    // operation; see the mitigation rationale above. The CT
    // discriminator is preserved by cycling through 32 independent
    // random fixtures.
    let random_pool =
        pre_allocate_encrypted_rows(&cipher, context, ROW_CIPHER_RANDOM_POOL_SIZE, plaintext_len);

    let result = run_dudect(
        samples,
        |_idx| {
            let recovered = cipher
                .decrypt_row(
                    black_box(context),
                    black_box(&fixed.row_id),
                    black_box(&fixed.ciphertext),
                    black_box(fixed.nonce),
                    black_box(fixed.tag),
                )
                .expect("decrypt_row fixed fixture ok");
            let _ = black_box(recovered);
        },
        |idx| {
            // Cycle через bounded pool — `idx % 32` keeps Random class
            // cache-hot symmetrically с Fixed class (cache state
            // symmetric → t-statistic reflects only CT-relevant
            // operation timing variance, не cache-fetch bias).
            // Cycle through the bounded pool — `idx % 32` keeps the
            // Random class cache-hot symmetrically with the Fixed
            // class (cache state symmetric → t-statistic reflects only
            // CT-relevant operation timing variance, not cache-fetch
            // bias).
            let row = &random_pool[idx % ROW_CIPHER_RANDOM_POOL_SIZE];
            let recovered = cipher
                .decrypt_row(
                    black_box(context),
                    black_box(&row.row_id),
                    black_box(&row.ciphertext),
                    black_box(row.nonce),
                    black_box(row.tag),
                )
                .expect("decrypt_row random fixture ok");
            let _ = black_box(recovered);
        },
    );

    report("umbrella_client::keystore::RowCipher::decrypt_row", &result);
}

// =============================================================================
// Site 7: derive_rotated_identity_material function-level transparency observation
// (PhD-deep session #67 F-PHD-RETRO-5 — identity-specific dudect bench)
// =============================================================================

/// PhD-deep session #67 F-PHD-RETRO-5: function-level timing observation
/// для `derive_rotated_identity_material` в umbrella-identity. Block 10.24
/// §15 architectural note acknowledged: function timing **by design**
/// depends on match outcome of `old_identity_pubkey` ct_eq comparison —
/// matching path fires HKDF-SHA512 expand (~1-10 μs); mismatching path
/// early-returns с `IdentityError::OldIdentityMismatch` после ct_eq
/// (sub-μs). Это deliberate behavior per code_recovery.rs:255-260 since
/// rotation должна fail-fast при wrong old_identity.
///
/// Этот bench MEASURES magnitude of expected timing difference + reports
/// observed delta для transparency. **Constant-time invariant НЕ
/// asserted** — function-level CT не required design property; only
/// inner ct_eq operation требуется CT (covered baseline `[u8; 32]::ct_eq`
/// site 3). Bench fires `report_observation` (без strict |t| assert).
///
/// PhD-deep session #67 F-PHD-RETRO-5: function-level timing observation
/// for `derive_rotated_identity_material` in umbrella-identity. Block
/// 10.24 §15 architectural note acknowledged: the function's timing
/// **by design** depends on the match outcome of the
/// `old_identity_pubkey` ct_eq comparison — the matching path fires
/// HKDF-SHA512 expand (~1-10 μs); the mismatching path early-returns
/// with `IdentityError::OldIdentityMismatch` after the ct_eq (sub-μs).
/// This is deliberate behavior per code_recovery.rs:255-260 since
/// rotation must fail-fast on the wrong old_identity.
///
/// This bench MEASURES the magnitude of the expected timing difference
/// + reports the observed delta for transparency. **The constant-time
///   invariant is NOT asserted** — function-level CT is not a required
///   design property; only the inner ct_eq operation is required to be
///   CT (covered by the `[u8; 32]::ct_eq` baseline site 3). The bench
///   fires `report_observation` (no strict |t| assert).
#[test]
#[ignore = "dudect bench requires --release; run via cargo test --release -- --ignored"]
fn derive_rotated_identity_material_function_level_timing() {
    use umbrella_identity::{
        derive_rotated_identity_material, CodeRecoveryMnemonic, IdentityKey, IdentitySeed,
        MnemonicLanguage,
    };

    let samples = sample_budget();

    // Setup: один identity_seed + один code; matching old_pubkey vs
    // mismatching random old_pubkey. Pool small (cache-hot symmetry с
    // RowCipher pattern).
    //
    // Setup: a single identity_seed + a single code; matching old_pubkey
    // vs a mismatching random old_pubkey. The pool is small (cache-hot
    // symmetry with the RowCipher pattern).
    let mut rng = OsRng;
    let identity_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let code = CodeRecoveryMnemonic::generate(&mut rng, MnemonicLanguage::English);

    // Matching old_pubkey — derived from same seed account=0 (HKDF expand
    // path fires; `~1-10 μs`).
    // Matching old_pubkey — derived from the same seed account=0 (the HKDF
    // expand path fires; `~1-10 μs`).
    let derived = IdentityKey::derive(&identity_seed, 0).expect("derive ok");
    let matching_pubkey = derived.public();

    // Mismatching old_pubkey pool — random IdentityKeyPublic-shaped bytes
    // через random IdentityKey::derive с unrelated seed; each fresh ct_eq
    // mismatch triggers early-return (~sub-μs).
    // Mismatching old_pubkey pool — random IdentityKeyPublic-shaped bytes
    // via a random IdentityKey::derive with an unrelated seed; each fresh
    // ct_eq mismatch triggers an early-return (~sub-μs).
    const POOL: usize = 32;
    let mismatching_pool: Vec<_> = (0..POOL)
        .map(|_| {
            let other_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
            let other = IdentityKey::derive(&other_seed, 0).expect("derive ok");
            other.public()
        })
        .collect();

    let result = run_dudect(
        samples,
        |_idx| {
            // Matching path: ct_eq matches → HKDF expand fires → returns
            // RotatedIdentityMaterial.
            // Matching path: ct_eq matches → HKDF expand fires → returns
            // RotatedIdentityMaterial.
            let r = derive_rotated_identity_material(
                black_box(&identity_seed),
                black_box(&code),
                black_box(&matching_pubkey),
            )
            .expect("matching path ok");
            let _ = black_box(r);
        },
        |idx| {
            // Mismatching path: ct_eq mismatch → IdentityError::OldIdentityMismatch.
            // Mismatching path: ct_eq mismatch → IdentityError::OldIdentityMismatch.
            let pk = &mismatching_pool[idx % POOL];
            let r = derive_rotated_identity_material(
                black_box(&identity_seed),
                black_box(&code),
                black_box(pk),
            );
            // Expected Err — НЕ unwrap (отбираем сценарий just black_box).
            // Expected Err — do NOT unwrap (we only black_box the result).
            let _ = black_box(r);
        },
    );

    // Custom transparency report — без strict |t| assert (function-level
    // CT не invariant by design; this is a magnitude observation log).
    // Custom transparency report — without a strict |t| assert
    // (function-level CT is not an invariant by design; this is a
    // magnitude observation log).
    println!(
        "[dudect:umbrella_identity::derive_rotated_identity_material:function-level] \
         t={:+.3} mean_fixed={:.1}ns mean_random={:.1}ns n_fixed={} n_random={} \
         verdict_observation={} (NOT a CT assertion — function-level timing depends \
         on match outcome by design per code_recovery.rs:255-260; inner ct_eq is \
         covered by [u8; 32]::ct_eq baseline site 3)",
        result.t,
        result.mean_fixed_ns,
        result.mean_random_ns,
        result.n_fixed,
        result.n_random,
        result.verdict(),
    );
}
