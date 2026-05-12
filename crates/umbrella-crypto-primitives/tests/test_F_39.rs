//! Adversarial test для F-39 — manual seed zeroing must use zeroize::Zeroize trait.
//! Adversarial test for F-39 — manual seed zeroing must use the zeroize::Zeroize trait.
//!
//! Контекст / Context:
//! `PrivateSigningKey::generate()` ранее использовал ручной byte-loop
//! `seed.iter_mut().for_each(|b| *b = 0)` для очистки временного буфера. Этот pattern
//! может быть удалён компилятором (LLVM dead-store elimination в release-сборке) когда
//! seed выходит из scope сразу после loop'а — buffer остаётся в RAM ↦ row 11
//! Cold-boot/forensics. Fix: replaced с `seed.zeroize()` использующим volatile-write
//! semantics из crate `zeroize`.
//!
//! `PrivateSigningKey::generate()` previously used a manual byte-loop
//! `seed.iter_mut().for_each(|b| *b = 0)` to wipe the temporary buffer. This pattern
//! may be elided by the compiler (LLVM dead-store elimination in release builds)
//! when `seed` goes out of scope right after the loop — leaving the buffer in RAM
//! ↦ threat row 11 Cold-boot/forensics. Fix: replaced with `seed.zeroize()` using
//! volatile-write semantics from the `zeroize` crate.
//!
//! Этот тест — статическая проверка: source code НЕ должен содержать manual byte-loop
//! pattern для seed buffer; ДОЛЖЕН содержать `seed.zeroize()` call. Регрессионный
//! guard на случай accidental revert.
//!
//! This test is a static check: source code MUST NOT contain the manual byte-loop
//! pattern for the seed buffer; it MUST contain a `seed.zeroize()` call. Regression
//! guard against accidental reverts.

use std::path::PathBuf;

fn read_sig_source() -> String {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let path = PathBuf::from(manifest_dir).join("src").join("sig.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
}

/// Возвращает только non-comment строки sig.rs (отсеивает `//`, `///`, `//!`),
/// чтобы pattern-search не давала false-positive на explanatory comments.
/// Returns only non-comment lines of sig.rs (filters `//`, `///`, `//!`) so that
/// pattern-search does not false-positive on explanatory comments.
fn read_sig_code_only() -> String {
    read_sig_source()
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// Tests reading source files via `CARGO_MANIFEST_DIR` are static-source
// regression guards — они verify code shape, не runtime behavior. Под miri
// `CARGO_MANIFEST_DIR` env переменная НЕ forward'ится по умолчанию (требует
// explicit `MIRIFLAGS=-Zmiri-env-forward=CARGO_MANIFEST_DIR` opt-in), что
// делает эти тесты неприменимыми под miri runtime. Static analysis уже
// covers сам smoke от регулярных `cargo test`. Block 10.5b-active-retro
// session #65 closure: ignore-under-miri annotation для всех 3 tests.
//
// Tests that read source files via `CARGO_MANIFEST_DIR` are static-source
// regression guards — they verify code shape, not runtime behaviour. Under
// miri the `CARGO_MANIFEST_DIR` env variable is NOT forwarded by default
// (requires explicit `MIRIFLAGS=-Zmiri-env-forward=CARGO_MANIFEST_DIR`
// opt-in), which makes these tests inapplicable in the miri runtime. The
// static analysis is already exercised by regular `cargo test`. Block
// 10.5b-active-retro session #65 closure: ignore-under-miri annotation
// added to all 3 tests.
#[test]
#[cfg_attr(
    miri,
    ignore = "static-source regression guard; CARGO_MANIFEST_DIR not forwarded under miri"
)]
fn f_39_no_manual_seed_zeroing_loop() {
    let code = read_sig_code_only();
    assert!(
        !code.contains("seed.iter_mut().for_each(|b| *b = 0)"),
        "F-39 regression: sig.rs (non-comment code) contains manual byte-loop seed zeroing — \
         use zeroize::Zeroize trait (`seed.zeroize()`) instead. \
         The manual loop is subject to LLVM dead-store elimination in release builds, \
         leaving the secret seed in RAM (threat row 11 Cold-boot/forensics)."
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "static-source regression guard; CARGO_MANIFEST_DIR not forwarded under miri"
)]
fn f_39_seed_uses_zeroize_trait() {
    let code = read_sig_code_only();
    assert!(
        code.contains("seed.zeroize()"),
        "F-39 regression: sig.rs (non-comment code) missing `seed.zeroize()` call in \
         PrivateSigningKey::generate; temporary seed buffer must be wiped via the \
         zeroize::Zeroize trait (volatile writes)."
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "static-source regression guard; CARGO_MANIFEST_DIR not forwarded under miri"
)]
fn f_39_zeroize_trait_imported() {
    let code = read_sig_code_only();
    assert!(
        code.contains("Zeroize"),
        "F-39 regression: sig.rs (non-comment code) missing `Zeroize` import; \
         seed.zeroize() requires the trait to be in scope."
    );
}
