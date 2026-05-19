//! R5.B downstream compile-fail proof (round-3 hedged-encaps closure 2026-05-19).
//!
//! After round-3 changed `umbrella_pq::xwing_encaps_derand` visibility
//! from `pub` to `pub(crate)` (only re-exposed under internal feature
//! `__internal-kat-hooks`), any downstream production crate attempting
//! `use umbrella_pq::xwing_encaps_derand` must fail to compile.
//!
//! This test verifies that constructively by writing a tiny fixture
//! crate to a tempdir, attempting `cargo build` on it, and asserting
//! the build fails with the expected diagnostic.
//!
//! Threat closure: this prevents a confused downstream caller from
//! naively passing attacker-influenced bytes as the encaps seed (e.g.
//! using message hash as seed). Under round-2, `xwing_encaps_derand`
//! was `pub` and allowed this. Round-3 closes it constructively —
//! the type system prevents the misuse.
//!
//! Round-2 R5 reality-pass artefact: `r5e_doc_invariant_*` which
//! relied on grep-policy. Round-3 replaces that policy gate with this
//! compile-time gate.

#![cfg(feature = "pq")]

use std::process::Command;

/// Path к workspace root от `crates/umbrella-backup/tests/`.
/// Path to workspace root from `crates/umbrella-backup/tests/`.
fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/umbrella-backup; go up two.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    std::path::Path::new(&manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn attack_r5b_derand_pub_inaccessible_from_downstream_compile_fail() {
    // Build a tiny standalone crate that depends on the workspace
    // umbrella-pq with `ml-kem` feature ONLY (no `__internal-kat-hooks`).
    // The crate's only source is a `use umbrella_pq::xwing_encaps_derand;`
    // statement which must fail to compile.

    let ws = workspace_root();
    let tmpdir = tempdir_path("r5b_derand_compile_fail_fixture");

    // Clean any previous attempt.
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(tmpdir.join("src")).expect("create fixture src dir");

    // Cargo.toml — depends on umbrella-pq via path, feature ml-kem only.
    let umbrella_pq_path = ws.join("crates/umbrella-pq");
    let cargo_toml = format!(
        r#"[package]
name = "r5b-derand-fixture"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
umbrella-pq = {{ path = "{}", features = ["ml-kem"] }}
"#,
        umbrella_pq_path.display()
    );
    std::fs::write(tmpdir.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");

    // src/lib.rs — attempts to import `xwing_encaps_derand` from
    // umbrella_pq. Must fail to compile.
    let src = r#"// R5.B compile-fail fixture: downstream crate attempts to import the
// formerly-pub `xwing_encaps_derand`. After round-3 hedged-encaps closure,
// this symbol is `pub(crate)` and not re-exported under the default feature
// set, so this fixture MUST fail to compile.
#[allow(unused_imports)]
use umbrella_pq::xwing_encaps_derand;
"#;
    std::fs::write(tmpdir.join("src/lib.rs"), src).expect("write src/lib.rs");

    // Run `cargo build` on the fixture; expect failure.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .arg("build")
        .arg("--offline") // workspace deps already downloaded
        .current_dir(&tmpdir)
        // CARGO_TARGET_DIR redirect avoids polluting workspace target dir.
        .env("CARGO_TARGET_DIR", tmpdir.join("target"))
        .output()
        .expect("cargo build (fixture)");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Clean up tmpdir whether or not the test passes (避免 leaking).
    let _ = std::fs::remove_dir_all(&tmpdir);

    if output.status.success() {
        panic!(
            "[R5.B FAILED] downstream fixture compiled, meaning \
             `xwing_encaps_derand` is reachable from production-level \
             code despite round-3 closure. This is a regression — \
             closure must be restored. stdout=<<<{stdout}>>>"
        );
    }

    // Expected error: cannot find xwing_encaps_derand in `umbrella_pq`,
    // или `private item / function gated behind feature` warning.
    let expected_keywords = [
        "xwing_encaps_derand",      // symbol name
        "no `xwing_encaps_derand`", // not in root
    ];
    let stderr_lower = stderr.to_lowercase();
    let matched = expected_keywords
        .iter()
        .any(|kw| stderr_lower.contains(&kw.to_lowercase()));

    assert!(
        matched,
        "[R5.B] compile-fail occurred but error message didn't mention \
         `xwing_encaps_derand` — closure may have failed for a different \
         reason. Full stderr:\n{stderr}"
    );

    eprintln!(
        "[R5.B] CLOSURE CONFIRMED: downstream fixture `use \
         umbrella_pq::xwing_encaps_derand` failed compilation as \
         expected. Round-3 physical closure of R5.B works. Trimmed \
         stderr first 400 chars:\n{}",
        &stderr.chars().take(400).collect::<String>()
    );
}

/// Tempdir path used by the fixture. Lives под `target/r5b_*` чтобы быть
/// удобоудаляемым и не пересекаться с workspace target/.
/// Tempdir path used by the fixture. Lives under `target/r5b_*` to be
/// easy to clean up and to avoid colliding with the workspace `target/`.
fn tempdir_path(name: &str) -> std::path::PathBuf {
    // Use std::env::temp_dir() with a stable-named subdir; serial test
    // execution не нужен — name unique per-test.
    let mut p = std::env::temp_dir();
    p.push(format!("umbrella-r5b-fixture-{}", name));
    p
}
