//! Cross-implementation interop snapshot тесты против reference
//! `openmls/test_vectors/*.json` (block 9.11).
//!
//! Источник: git submodule `crates/umbrella-tests/cross_impl/openmls/`,
//! pinned на tag `openmls-v0.8.1` (см. `.gitmodules` и
//! private cross-implementation notes). Snapshot RFC 9420 §A
//! reference vectors, поддерживаемых upstream openmls.
//!
//! Назначение: detect wire-format drift между нашей реализацией
//! `umbrella-mls` (built on top of openmls 0.8.1) и upstream openmls когда
//! upstream релизит новый minor — еженедельный CI прогон
//! `.github/workflows/cross-impl-interop.yml` обновляет submodule
//! (`git submodule update --remote --recursive`) и re-run этих тестов;
//! любая структурная регрессия = автоматический GitHub issue с
//! label `regression: cross-impl interop`.
//!
//! Покрытие (block 9.11 OPTION B + SPEC-03 §4.1 whitelist):
//! - 0x0001 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420)
//! - 0x0003 `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
//! - 0x0004 `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`
//! - 0x0006 `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`
//!
//! НЕ покрыто:
//! - 0x0002 / 0x0005 / 0x0007 ECDSA-варианты — заблокированы SPEC-03 §4.1
//!   (ETK split-view атака, Cremers et al. eprint 2025/229), скан snapshot
//!   их игнорирует.
//! - 0x004D PQ X-Wing — отсутствует в openmls 0.8.1; pending openmls 0.9+
//!   native X-Wing (см. design.md §11.1 future-migration playbook). Cross-
//!   тест PQ entries делается own-roundtrip в `tests/stage8_milestone.rs`.
//!
//! Cross-implementation interop snapshot tests against the reference
//! `openmls/test_vectors/*.json` (block 9.11).
//!
//! Source: git submodule `crates/umbrella-tests/cross_impl/openmls/`,
//! pinned to tag `openmls-v0.8.1` (see `.gitmodules` and
//! private cross-implementation notes). Snapshot of the RFC 9420
//! §A reference vectors maintained by upstream openmls.
//!
//! Purpose: detect wire-format drift between our `umbrella-mls`
//! implementation (built on top of openmls 0.8.1) and the upstream openmls
//! whenever upstream ships a new minor — the weekly CI run
//! `.github/workflows/cross-impl-interop.yml` updates the submodule
//! (`git submodule update --remote --recursive`) and re-runs these tests;
//! any structural regression results in an automatic GitHub issue with
//! label `regression: cross-impl interop`.
//!
//! Coverage (block 9.11 OPTION B + SPEC-03 §4.1 whitelist): 0x0001, 0x0003,
//! 0x0004, 0x0006. Not covered: ECDSA variants 0x0002 / 0x0005 / 0x0007
//! (blocked by SPEC-03 §4.1 due to the ETK split-view attack — Cremers et
//! al. eprint 2025/229 — the snapshot scan ignores them); PQ X-Wing 0x004D
//! is absent from openmls 0.8.1 (pending openmls 0.9+ native X-Wing per
//! design.md §11.1; cross-test PQ entries are exercised via own-roundtrip
//! in `tests/stage8_milestone.rs`).

use std::path::PathBuf;

/// IANA-номера ciphersuites RFC 9420, разрешённые SPEC-03 §4.1 (Ed25519/Ed448
/// only). ECDSA-варианты (0x0002 / 0x0005 / 0x0007) исключены ETK-митигацией.
///
/// IANA RFC 9420 ciphersuite numbers permitted by SPEC-03 §4.1 (Ed25519/Ed448
/// only). ECDSA variants (0x0002 / 0x0005 / 0x0007) are excluded due to the
/// ETK mitigation.
const WHITELISTED_CIPHERSUITES: [u16; 4] = [0x0001, 0x0003, 0x0004, 0x0006];

/// Корневая директория snapshot openmls test_vectors внутри submodule.
/// Path: `crates/umbrella-tests/cross_impl/openmls/openmls/test_vectors/`.
///
/// Root directory of the openmls test_vectors snapshot inside the submodule.
fn submodule_test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("cross_impl")
        .join("openmls")
        .join("openmls")
        .join("test_vectors")
}

/// Сообщение ошибки при отсутствии submodule. Submodule подтягивается
/// `git submodule update --init --recursive` при checkout репозитория.
///
/// Error message when the submodule is missing. The submodule is pulled in
/// via `git submodule update --init --recursive` after repo checkout.
const SUBMODULE_HELP: &str =
    "openmls submodule отсутствует — запустите `git submodule update --init --recursive` \
     либо см. README §setup. The openmls submodule is missing — run \
     `git submodule update --init --recursive` or see README §setup.";

/// Проверяет что snapshot содержит ожидаемое число JSON-файлов и каждый из
/// них структурно валидный JSON (десериализуется через `serde_json::Value`).
///
/// Это самый дешёвый детектор crash'а формата vectors при upstream обновлении —
/// если openmls сменит layout `test_vectors/`, тест fail-ит сразу с понятным
/// сообщением, не таская за собой шумные ошибки compile-time в `umbrella-mls`.
///
/// Verifies that the snapshot contains the expected number of JSON files and
/// that each one is a structurally valid JSON document (deserialises via
/// `serde_json::Value`).
///
/// This is the cheapest detector of a vector-format crash on an upstream
/// upgrade — if openmls changes the layout of `test_vectors/`, the test
/// fails immediately with a clear message, instead of dragging noisy
/// compile-time errors through `umbrella-mls`.
#[test]
fn openmls_test_vectors_snapshot_is_well_formed_json() {
    let dir = submodule_test_vectors_dir();
    assert!(dir.is_dir(), "{SUBMODULE_HELP} (path: {})", dir.display());

    let mut json_files = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read submodule test_vectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            json_files.push(path);
        }
    }
    json_files.sort();

    // openmls-v0.8.1 публикует ровно 19 JSON-файлов (audit 2026-04-29 при
    // закрытии block 9.11). При обновлении submodule на minor релиз ожидаем
    // ≥19, не точное равенство — upstream может добавить новые vectors.
    //
    // openmls-v0.8.1 publishes exactly 19 JSON files (audit 2026-04-29 at
    // block 9.11 close). On a minor-release submodule bump we accept ≥19,
    // not strict equality — upstream may add new vectors.
    assert!(
        json_files.len() >= 19,
        "expected ≥19 JSON files in openmls test_vectors snapshot, found {} \
         (upstream may have removed vectors — investigate before bumping pin)",
        json_files.len(),
    );

    for path in &json_files {
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&raw);
        assert!(
            parsed.is_ok(),
            "{} is not valid JSON: {:?}",
            path.display(),
            parsed.err(),
        );
    }
}

/// Проверяет что для каждого whitelisted ciphersuite SPEC-03 §4.1 в
/// `crypto-basics.json` есть хотя бы один test vector. Это гарантирует что
/// все наши supported ciphersuites покрыты cross-impl snapshot'ом.
///
/// Verifies that for each whitelisted ciphersuite per SPEC-03 §4.1 there is
/// at least one entry in `crypto-basics.json`. This guarantees that every
/// ciphersuite we support is covered by the cross-impl snapshot.
#[test]
fn crypto_basics_covers_whitelisted_ciphersuites() {
    let path = submodule_test_vectors_dir().join("crypto-basics.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{SUBMODULE_HELP} (path: {})", path.display()));
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("crypto-basics.json deserialises as array");

    for &expected_cs in &WHITELISTED_CIPHERSUITES {
        let count = entries
            .iter()
            .filter_map(|e| e.get("cipher_suite").and_then(|v| v.as_u64()))
            .filter(|&cs| cs == u64::from(expected_cs))
            .count();
        assert!(
            count >= 1,
            "ciphersuite {expected_cs:#06x} (SPEC-03 §4.1 whitelist) отсутствует \
             в crypto-basics.json — upstream openmls удалил test vector? \
             ciphersuite {expected_cs:#06x} (SPEC-03 §4.1 whitelist) is missing \
             from crypto-basics.json — has upstream openmls dropped the vector?",
        );
    }
}

/// Проверяет что snapshot openmls 0.8.1 НЕ содержит PQ-ciphersuite 0x004D
/// (X-Wing). Этот тест существует как **early-warning** для block 9.12
/// (PQ-first default switch) и block 9.14 (future-migration playbook §11.1):
/// как только upstream openmls добавит native X-Wing, weekly CI fail-ит
/// эту проверку и сигнализирует о готовности к Variant B миграции.
///
/// Pattern E (V1↔V2 coexistence): V1 entries покрыты openmls reference
/// vectors (этот файл), V2 entries — own roundtrip в
/// `tests/stage8_milestone.rs`. Пока V2 cross-impl невозможен — тест с
/// `must_still_be_v1_only` выступает как trip-wire.
///
/// Verifies that the openmls 0.8.1 snapshot does NOT contain the PQ
/// ciphersuite 0x004D (X-Wing). This test exists as an **early warning** for
/// block 9.12 (PQ-first default switch) and block 9.14 (future-migration
/// playbook §11.1): as soon as upstream openmls adds native X-Wing the
/// weekly CI fails this assertion and signals readiness for the Variant B
/// migration.
///
/// Pattern E (V1↔V2 coexistence): V1 entries are covered by openmls
/// reference vectors (this file), V2 entries by own-roundtrip in
/// `tests/stage8_milestone.rs`. Until V2 cross-impl becomes possible, this
/// `must_still_be_v1_only` test acts as the trip-wire.
#[test]
fn snapshot_does_not_yet_carry_x_wing_must_still_be_v1_only() {
    const X_WING_CIPHERSUITE: u64 = 0x004D;
    let path = submodule_test_vectors_dir().join("crypto-basics.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{SUBMODULE_HELP} (path: {})", path.display()));
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("crypto-basics.json deserialises as array");

    let x_wing_count = entries
        .iter()
        .filter_map(|e| e.get("cipher_suite").and_then(|v| v.as_u64()))
        .filter(|&cs| cs == X_WING_CIPHERSUITE)
        .count();

    // ВНИМАНИЕ при срабатывании: upstream openmls native X-Wing появился —
    // открыть GitHub issue «Migrate to upstream X-Wing per design.md §11.1
    // future-migration playbook». Снимок этого assertion остаётся trip-wire
    // до выполнения миграции (block 9.14).
    //
    // ATTENTION on failure: upstream openmls native X-Wing has landed — open
    // a GitHub issue «Migrate to upstream X-Wing per design.md §11.1
    // future-migration playbook». This assertion stays as a trip-wire until
    // the migration is executed (block 9.14).
    assert_eq!(
        x_wing_count, 0,
        "openmls upstream добавил native X-Wing (cipher_suite={X_WING_CIPHERSUITE:#06x}) — \
         запустить future-migration playbook design.md §11.1 (block 9.14). \
         openmls upstream has landed native X-Wing (cipher_suite={X_WING_CIPHERSUITE:#06x}) — \
         start the future-migration playbook design.md §11.1 (block 9.14).",
    );
}

/// Smoke-тест что pinned snapshot openmls submodule содержит ожидаемый
/// canonical KAT файл `kat_encryption_openmls.json` (≥1 MB) — крупнейший
/// vector в snapshot, прокси-метрика на «полный snapshot, не truncated
/// checkout».
///
/// Smoke test that the pinned openmls submodule snapshot contains the
/// expected canonical KAT file `kat_encryption_openmls.json` (≥1 MB) — the
/// largest vector in the snapshot, used as a proxy for «full snapshot, not
/// a truncated checkout».
#[test]
fn snapshot_carries_full_canonical_kat_files() {
    let path = submodule_test_vectors_dir().join("kat_encryption_openmls.json");
    let metadata = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{SUBMODULE_HELP} (path: {}, error: {e})", path.display()));
    assert!(
        metadata.len() >= 1_000_000,
        "kat_encryption_openmls.json size = {} bytes; expected ≥1 MB \
         (truncated checkout? broken submodule?)",
        metadata.len(),
    );
}
