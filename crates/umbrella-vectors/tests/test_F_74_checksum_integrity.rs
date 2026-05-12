//! Регрессионный тест F-74 — целостность test vectors через SHA-256
//! проверку против `CHECKSUMS.txt`.
//! Regression test F-74 — test-vector integrity via SHA-256 verification
//! against `CHECKSUMS.txt`.
//!
//! ## Обнаружение / Discovery
//!
//! Block 10.27 dev crates audit (active mode methodology) обнаружил silent
//! integrity gap в `umbrella-vectors`:
//! - `data/SOURCES.md` нормативно требует «Любой mismatch checksum при build
//!   = CI fail (постулат 13)»;
//! - `CHECKSUMS.txt` существует с SHA-256 хэшами всех 4 stability JSON
//!   файлов (`stability-ml-{kem-768,dsa-65}.json` + `stability-{slh-dsa-128f,
//!   x-wing}.json`);
//! - НО ни в коде (`build.rs` отсутствует), ни в CI workflow
//!   (`reproducibility-check.yml` хэширует только FFI-libs `libumbrella_ffi-
//!   *.so` под cross-runner diff, не vector-файлы), ни в test-suite этой
//!   библиотеки нет автоматической проверки соответствия.
//!
//! Block 10.27 dev crates audit (active-mode methodology) discovered a silent
//! integrity gap in `umbrella-vectors`:
//! - `data/SOURCES.md` normatively requires "any checksum mismatch at build
//!   time = CI fail (postulate 13)";
//! - `CHECKSUMS.txt` exists with SHA-256 hashes for all 4 stability JSON
//!   files;
//! - BUT neither the code (no `build.rs`), nor any CI workflow
//!   (`reproducibility-check.yml` hashes only FFI libs `libumbrella_ffi-*.so`
//!   for cross-runner diff, not vector files), nor the library test suite
//!   carries an automatic match check.
//!
//! ## Threat model / Угроза
//!
//! Attacker уровня D из SPEC-01 § 4 с git-repo-write доступом мог subtly
//! модифицировать один байт в `data/stability-ml-kem-768.json` (например,
//! изменить `expected_shared_secret_hex` для одного вектора), что прошло бы
//! все текущие cargo-test проходы — `nist_kat::tests::load_stability_kat_
//! files_if_present` загружает файл, но не сверяет hash. Downstream `umbrella-
//! pq` cross-test-against-libcrux мог бы пройти если encaps вектор seed
//! детерминированный, либо silently failed бы для невалидной vector pair —
//! нарушая постулат 4 «приватность превыше всего» (skip silent failure).
//!
//! Attacker level D from SPEC-01 § 4 with git-repo-write access could subtly
//! modify a single byte in `data/stability-ml-kem-768.json` (e.g. change
//! `expected_shared_secret_hex` for one vector), which would pass every
//! current cargo-test invocation — `nist_kat::tests::load_stability_kat_files
//! _if_present` loads the file but does not verify the hash. The downstream
//! `umbrella-pq` cross-test against libcrux could pass if the encaps vector
//! seed is deterministic, or silently fail for an invalid vector pair —
//! violating postulate 4 "privacy above all" (no silent failures allowed).
//!
//! ## Методика / Methodology
//!
//! Для каждой строки `<sha256>  <relative path>` в `CHECKSUMS.txt`
//! computer SHA-256 файла + assert match. Отсутствие файла либо checksum
//! mismatch = test failure с descriptive message указывающим конкретный
//! файл + expected + actual hash.
//!
//! For each line `<sha256>  <relative path>` in `CHECKSUMS.txt`, compute the
//! SHA-256 of the file and assert match. A missing file or checksum mismatch
//! results in test failure with a descriptive message identifying the file,
//! expected, and actual hash.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Закрывает F-74: верифицирует целостность всех vector файлов в `data/`
/// против committed `CHECKSUMS.txt`.
///
/// Closes F-74: verifies the integrity of all vector files in `data/`
/// against the committed `CHECKSUMS.txt`.
#[test]
fn checksum_integrity_matches_committed_hashes() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let checksums_path = crate_root.join("CHECKSUMS.txt");
    let checksums_text = fs::read_to_string(&checksums_path).unwrap_or_else(|e| {
        panic!(
            "F-74: cannot read CHECKSUMS.txt at {}: {}",
            checksums_path.display(),
            e
        )
    });

    // sha256sum формат: «<hex 64 chars><two spaces><relative path>».
    // sha256sum format: "<hex 64 chars><two spaces><relative path>".
    let mut entries: Vec<(String, String)> = Vec::new();
    for (idx, line) in checksums_text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Каноническая форма: 64 hex + два пробела + path.
        // Canonical: 64 hex + two spaces + path.
        let bytes = trimmed.as_bytes();
        assert!(
            bytes.len() > 66 && &bytes[64..66] == b"  ",
            "F-74: malformed CHECKSUMS.txt line {} — expected `<hex64>  <path>`: {trimmed:?}",
            idx + 1
        );
        let hex = trimmed[..64].to_string();
        let path = trimmed[66..].to_string();
        entries.push((hex, path));
    }

    assert!(
        !entries.is_empty(),
        "F-74: CHECKSUMS.txt parsed 0 entries — нечего проверять (file empty?)"
    );

    let mut failures: Vec<String> = Vec::new();
    for (expected_hex, rel_path) in &entries {
        let abs_path = crate_root.join(rel_path);
        let bytes = match fs::read(&abs_path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: cannot read ({})", abs_path.display(), e));
                continue;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual_bytes = hasher.finalize();
        let actual_hex = hex::encode(actual_bytes);
        if &actual_hex != expected_hex {
            failures.push(format!(
                "{}: SHA-256 mismatch — expected {} got {}",
                abs_path.display(),
                expected_hex,
                actual_hex
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "F-74 violation — {} файл(ов) не соответствуют CHECKSUMS.txt:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Гарантия что CHECKSUMS.txt содержит запись для каждого `data/*.json`
/// файла. Защищает от обратной атаки: добавление nового vector файла без
/// записи hash → silent gap.
///
/// Guarantees CHECKSUMS.txt has an entry for every `data/*.json` file.
/// Defends against the reverse attack: adding a new vector file without
/// recording its hash → silent gap.
#[test]
fn every_data_json_file_has_checksum_entry() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = crate_root.join("data");
    if !data_dir.exists() {
        // data/ может отсутствовать в некоторых cargo invocation (e.g.
        // `cargo test -p umbrella-vectors` под workspace exclude). Пропускаем
        // как nist_kat::tests::load_stability_kat_files_if_present.
        // data/ may be absent in some cargo invocations — skip gracefully.
        return;
    }

    let checksums_path = crate_root.join("CHECKSUMS.txt");
    let checksums_text =
        fs::read_to_string(&checksums_path).expect("F-74: cannot read CHECKSUMS.txt");

    let mut listed_paths: Vec<String> = Vec::new();
    for line in checksums_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.len() < 66 {
            continue;
        }
        listed_paths.push(trimmed[66..].to_string());
    }

    let mut missing: Vec<String> = Vec::new();
    for entry in fs::read_dir(&data_dir).expect("F-74: read data/ directory") {
        let entry = entry.expect("F-74: read data/ entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let rel = format!("data/{}", path.file_name().unwrap().to_str().unwrap());
        if !listed_paths.contains(&rel) {
            missing.push(rel);
        }
    }

    assert!(
        missing.is_empty(),
        "F-74 violation — {} JSON файл(ов) в data/ без записи в CHECKSUMS.txt:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}
