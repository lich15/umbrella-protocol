//! Adversarial test для F-46 — manual seed/randomness buffers must use zeroize::Zeroize trait
//! после consumption бэкендом.
//! Adversarial test for F-46 — manual seed/randomness buffers must use the zeroize::Zeroize
//! trait after backend consumption.
//!
//! Контекст / Context:
//!
//! Umbrella-pq использует **derand API** libcrux/fips205 (фиксированный seed/randomness vs
//! `RngCore + CryptoRng` direct passing) — потому что libcrux-kem 0.0.7 non-derand path
//! требует rand_core 0.9 (наш workspace на rand_core 0.6). 7 sites имеют pattern:
//!
//! ```rust
//! let mut seed = [0u8; SIZE];
//! rng.fill_bytes(&mut seed);
//! backend::function(seed); // consume
//! // BAD: seed dropped без zeroize → row 11 Cold-boot/forensics
//! ```
//!
//! Все 7 sites должны вызывать `seed.zeroize()` после consumption бэкендом для предотвращения
//! LLVM dead-store elimination в release-сборке (manual byte-loop НЕ имеет volatile-write
//! semantics).
//!
//! umbrella-pq uses the **derand API** of libcrux/fips205 (fixed seed/randomness vs direct
//! `RngCore + CryptoRng` passing) — because libcrux-kem 0.0.7's non-derand path requires
//! rand_core 0.9 (our workspace is on rand_core 0.6). 7 sites have the pattern above.
//!
//! All 7 sites must call `seed.zeroize()` after backend consumption to prevent LLVM
//! dead-store elimination in release builds (a manual byte-loop has no volatile-write
//! semantics).
//!
//! Этот тест — статическая проверка: source code обязан содержать `seed.zeroize()` либо
//! `randomness.zeroize()` либо аналог по каждому из 7 sites; запрещён manual byte-loop
//! pattern. Регрессионный guard на случай accidental revert.
//!
//! This test is a static check: source code MUST contain `seed.zeroize()` or
//! `randomness.zeroize()` or an equivalent at each of the 7 sites; the manual byte-loop
//! pattern is forbidden. Regression guard against accidental reverts.

#![cfg(all(feature = "ml-kem", feature = "ml-dsa"))]

use std::path::PathBuf;

fn read_source(file: &str) -> String {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let path = PathBuf::from(manifest_dir).join("src").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
}

/// Возвращает только non-comment строки указанного source file (отсеивает `//`, `///`, `//!`),
/// чтобы pattern-search не давала false-positive на explanatory comments.
/// Returns only non-comment lines of the given source file.
fn read_code_only(file: &str) -> String {
    read_source(file)
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Helper: assert что source НЕ содержит manual byte-loop zeroing pattern.
/// Helper: assert source does NOT contain the manual byte-loop zeroing pattern.
fn assert_no_manual_loop(file: &str) {
    let code = read_code_only(file);
    assert!(
        !code.contains(".iter_mut().for_each(|b| *b = 0)"),
        "F-46 regression: {file} contains manual byte-loop zeroing — \
         use zeroize::Zeroize trait (`buf.zeroize()`) instead"
    );
}

/// Helper: assert что source имеет Zeroize trait import.
/// Helper: assert source imports the Zeroize trait.
fn assert_zeroize_imported(file: &str) {
    let code = read_code_only(file);
    assert!(
        code.contains("use zeroize::Zeroize"),
        "F-46 regression: {file} missing `use zeroize::Zeroize;` import"
    );
}

#[test]
fn f_46_xwing_seed_uses_zeroize_trait() {
    assert_no_manual_loop("xwing.rs");
    assert_zeroize_imported("xwing.rs");

    let code = read_code_only("xwing.rs");
    let zeroize_calls = code.matches("seed.zeroize()").count();
    assert!(
        zeroize_calls >= 2,
        "F-46 regression: xwing.rs expected ≥2 `seed.zeroize()` calls (xwing_keygen + xwing_encaps), got {zeroize_calls}"
    );
}

#[test]
fn f_46_ml_kem_seed_uses_zeroize_trait() {
    assert_no_manual_loop("ml_kem.rs");
    assert_zeroize_imported("ml_kem.rs");

    let code = read_code_only("ml_kem.rs");
    let zeroize_calls = code.matches("seed.zeroize()").count();
    assert!(
        zeroize_calls >= 2,
        "F-46 regression: ml_kem.rs expected ≥2 `seed.zeroize()` calls (keygen + encaps), got {zeroize_calls}"
    );
}

#[test]
fn f_46_ml_dsa_randomness_uses_zeroize_trait() {
    assert_no_manual_loop("ml_dsa.rs");
    assert_zeroize_imported("ml_dsa.rs");

    let code = read_code_only("ml_dsa.rs");
    // ml_dsa.rs использует названия `randomness` (keygen) и `sign_randomness` (sign).
    // ml_dsa.rs uses the names `randomness` (keygen) and `sign_randomness` (sign).
    let randomness_zeroize = code.matches("randomness.zeroize()").count();
    let sign_randomness_zeroize = code.matches("sign_randomness.zeroize()").count();
    assert!(
        randomness_zeroize >= 1,
        "F-46 regression: ml_dsa.rs missing `randomness.zeroize()` in keygen, got {randomness_zeroize}"
    );
    assert!(
        sign_randomness_zeroize >= 1,
        "F-46 regression: ml_dsa.rs missing `sign_randomness.zeroize()` in sign, got {sign_randomness_zeroize}"
    );
}

#[test]
fn f_46_hybrid_signature_ed_seed_uses_zeroize_trait() {
    assert_no_manual_loop("hybrid_signature.rs");
    assert_zeroize_imported("hybrid_signature.rs");

    let code = read_code_only("hybrid_signature.rs");
    assert!(
        code.contains("ed_seed.zeroize()"),
        "F-46 regression: hybrid_signature.rs missing `ed_seed.zeroize()` in hybrid_keygen"
    );
}

/// Aggregate sanity: total zeroize calls across all 4 affected files ≥ 7
/// (7 sites identified в block 10.6 detailed analysis).
/// Aggregate sanity: total zeroize calls across all 4 affected files ≥ 7
/// (7 sites identified in block 10.6 detailed analysis).
#[test]
fn f_46_total_zeroize_call_count_at_least_7_sites() {
    let xwing = read_code_only("xwing.rs");
    let ml_kem = read_code_only("ml_kem.rs");
    let ml_dsa = read_code_only("ml_dsa.rs");
    let hybrid = read_code_only("hybrid_signature.rs");

    // Count все variations: seed.zeroize, randomness.zeroize, sign_randomness.zeroize, ed_seed.zeroize.
    // Count all variations.
    let total = xwing.matches(".zeroize()").count()
        + ml_kem.matches(".zeroize()").count()
        + ml_dsa.matches(".zeroize()").count()
        + hybrid.matches(".zeroize()").count();

    assert!(
        total >= 7,
        "F-46 regression: total zeroize() calls across 4 source files = {total}, expected ≥ 7 (7 sites)"
    );
}
