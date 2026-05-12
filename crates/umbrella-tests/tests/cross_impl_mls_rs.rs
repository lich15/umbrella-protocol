//! Cross-implementation interop тесты против AWS Labs `mls-rs` (RFC 9420),
//! второй независимой Rust-реализации MLS (block 9.11).
//!
//! Подход: читаем reference test_vectors из **openmls** submodule
//! (`crates/umbrella-tests/cross_impl/openmls/openmls/test_vectors/`,
//! pinned `openmls-v0.8.1`) и пропускаем wire bytes каждого `MlsMessage`
//! через **mls-rs** парсер `MlsMessage::from_bytes` + `to_bytes`. Если
//! обе независимых Rust-реализации согласуются byte-for-byte по RFC 9420
//! wire-format — значит наш `umbrella-mls` (built on top of openmls) тоже
//! interop-совместим с mls-rs (transitive guarantee).
//!
//! Цель: detect drift между двумя production Rust MLS реализациями.
//! Любое расхождение byte-roundtrip = либо openmls вышел за RFC, либо
//! mls-rs, либо vector format поменялся; weekly CI ловит это автоматически.
//!
//! Покрытие SPEC-03 §4.1 whitelist (Ed25519/Ed448 only):
//! - 0x0001 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
//! - 0x0003 `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
//! - 0x0004 `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`
//! - 0x0006 `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`
//!
//! ECDSA-варианты (0x0002/0x0005/0x0007) тоже roundtrip-абельны wire-format
//! слоем (TLS-codec не зависит от криптографии), и тест их не отфильтровывает —
//! interop wire-format invariant держится для всего RFC 9420 регистра.
//!
//! НЕ покрыто:
//! - libsignal cross-test (block 9.11 OPTION B): public extractable test
//!   vectors libsignal не публикует (audit 2026-04-29 — wire vectors
//!   embedded в `/rust/protocol/tests/*.rs` без extractable JSON snapshot;
//!   v0.93.0). Absence is recorded in private cross-implementation notes.
//! - PQ X-Wing 0x004D: ни openmls 0.8.1, ни mls-rs 0.55.0 не имеют native
//!   X-Wing. Pending openmls 0.9+ + mls-rs equivalent (см. `cross_impl_openmls.rs`
//!   `snapshot_does_not_yet_carry_x_wing_must_still_be_v1_only`). До тех пор
//!   PQ entries roundtrip-аются own кодом в `tests/stage8_milestone.rs`.
//!
//! Cross-implementation interop tests against AWS Labs `mls-rs` (RFC 9420),
//! the second independent Rust MLS implementation (block 9.11).
//!
//! Approach: read reference test_vectors from the **openmls** submodule
//! (`crates/umbrella-tests/cross_impl/openmls/openmls/test_vectors/`, pinned
//! at `openmls-v0.8.1`) and feed the wire bytes of each `MlsMessage` through
//! the **mls-rs** parser `MlsMessage::from_bytes` + `to_bytes`. If two
//! independent Rust implementations agree byte-for-byte on the RFC 9420
//! wire format, our `umbrella-mls` (built on top of openmls) is also
//! interop-compatible with mls-rs (transitive guarantee).
//!
//! Goal: detect drift between two production Rust MLS implementations. Any
//! roundtrip mismatch ⇒ either openmls drifted from the RFC, or mls-rs did,
//! or the vector format changed; the weekly CI catches that automatically.
//!
//! Coverage per SPEC-03 §4.1 whitelist (Ed25519/Ed448 only): 0x0001, 0x0003,
//! 0x0004, 0x0006. ECDSA variants (0x0002/0x0005/0x0007) also roundtrip at
//! the wire-format layer (the TLS codec is independent of cryptography), and
//! the test does not filter them — the interop wire-format invariant holds
//! across the whole RFC 9420 registry.
//!
//! Not covered: libsignal cross-test (block 9.11 OPTION B) — libsignal does
//! not publish extractable test vectors (audit 2026-04-29 — wire vectors
//! are embedded in `/rust/protocol/tests/*.rs` with no extractable JSON
//! snapshot; v0.93.0). Documented as absence in
//! private cross-implementation notes. PQ X-Wing 0x004D — neither
//! openmls 0.8.1 nor mls-rs 0.55.0 has native X-Wing yet. Pending openmls
//! 0.9+ and the mls-rs equivalent (see `cross_impl_openmls.rs` test
//! `snapshot_does_not_yet_carry_x_wing_must_still_be_v1_only`). Until then,
//! PQ entries are roundtripped by own code in `tests/stage8_milestone.rs`.

use std::path::PathBuf;

use mls_rs::CipherSuite;
use mls_rs::CryptoProvider;
use mls_rs::MlsMessage;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// IANA-номера ciphersuites RFC 9420, разрешённые SPEC-03 §4.1 (Ed25519/Ed448
/// only). Используется для итерации по whitelist в `welcome.json` тесте.
///
/// IANA RFC 9420 ciphersuite numbers permitted by SPEC-03 §4.1 (Ed25519/Ed448
/// only). Used to iterate the whitelist in the `welcome.json` test.
const WHITELISTED_CIPHERSUITES: [u16; 4] = [0x0001, 0x0003, 0x0004, 0x0006];

/// Подмножество whitelist'а SPEC-03 §4.1 которое поддерживается **pure-Rust**
/// crypto provider'ом mls-rs (`mls-rs-crypto-rustcrypto = "0.22"`).
/// X448 / Ed448 (0x0004 / 0x0006) — известный gap RustCrypto ecosystem
/// (нет production-quality `ed448-goldilocks` impl на 2026-04). Wire-format
/// roundtrip Ed448 entries всё равно работает через `MlsMessage::from_bytes`
/// (TLS codec не зависит от crypto), что покрывается тестом
/// `openmls_welcome_json_roundtrip_per_whitelisted_ciphersuite_via_mls_rs`.
///
/// The subset of the SPEC-03 §4.1 whitelist supported by the **pure-Rust**
/// mls-rs crypto provider (`mls-rs-crypto-rustcrypto = "0.22"`).
/// X448 / Ed448 (0x0004 / 0x0006) is a known gap in the RustCrypto
/// ecosystem (no production-quality `ed448-goldilocks` impl as of
/// 2026-04). Wire-format roundtrip of Ed448 entries still works through
/// `MlsMessage::from_bytes` (the TLS codec is independent of crypto), which
/// is covered by the test
/// `openmls_welcome_json_roundtrip_per_whitelisted_ciphersuite_via_mls_rs`.
const WHITELISTED_X25519_RUSTCRYPTO: [u16; 2] = [0x0001, 0x0003];

/// Поля openmls `messages.json` representing serialized `MlsMessage` и
/// roundtrip-абельны через `mls_rs::MlsMessage::from_bytes` + `.to_bytes()`.
/// Соответствуют upstream mls-rs interop pattern в
/// `mls-rs/src/group/interop_test_vectors/serialization.rs`.
///
/// Fields in openmls's `messages.json` that represent a serialized
/// `MlsMessage` and roundtrip via `mls_rs::MlsMessage::from_bytes` +
/// `.to_bytes()`. They mirror the upstream mls-rs interop pattern at
/// `mls-rs/src/group/interop_test_vectors/serialization.rs`.
const MLS_MESSAGE_FIELDS: [&str; 3] = ["mls_welcome", "mls_group_info", "mls_key_package"];

/// Корневая директория snapshot openmls test_vectors (см. cross_impl_openmls.rs).
/// Root directory of the openmls test_vectors snapshot.
fn openmls_test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("cross_impl")
        .join("openmls")
        .join("openmls")
        .join("test_vectors")
}

const SUBMODULE_HELP: &str =
    "openmls submodule отсутствует — запустите `git submodule update --init --recursive`. \
     The openmls submodule is missing — run `git submodule update --init --recursive`.";

/// Извлекает hex-строку из JSON-поля с graceful обработкой пустых значений.
/// Возвращает `None` если поле отсутствует, не строка либо пустая строка
/// (RFC 9420 §A vectors иногда имеют empty values для irrelevant scenarios).
///
/// Extracts a hex string from a JSON field, gracefully handling empty values.
/// Returns `None` if the field is missing, not a string, or empty (RFC 9420
/// §A vectors sometimes have empty values for irrelevant scenarios).
fn json_hex_field<'a>(entry: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    entry
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Roundtrip каждое нелустое `MlsMessage` поле openmls `messages.json`
/// через `mls_rs::MlsMessage::from_bytes` → `.to_bytes()` и проверяет
/// byte-equivalence. Это **двусторонняя wire-format совместимость** между
/// двумя независимыми Rust-реализациями MLS (block 9.11 ядро).
///
/// Threshold ≥250 successful roundtrips: messages.json содержит 300 entries
/// × 3 поля = 900 потенциальных roundtrips, но не все entries имеют все
/// поля, и некоторые empty. Эмпирический минимум 250 (audit 2026-04-29 при
/// closing блока 9.11) с margin ≥30 для tolerance upstream additions/removals.
///
/// Roundtrip every non-empty `MlsMessage` field of openmls's `messages.json`
/// through `mls_rs::MlsMessage::from_bytes` → `.to_bytes()` and check
/// byte-equivalence. This is **two-way wire-format compatibility** between
/// two independent Rust MLS implementations (the core of block 9.11).
///
/// Threshold ≥250 successful roundtrips: messages.json contains 300 entries
/// × 3 fields = 900 potential roundtrips, but not every entry has every
/// field, and some are empty. Empirical minimum 250 (audit 2026-04-29 at
/// block 9.11 closure) with a margin of ≥30 for tolerance to upstream
/// additions/removals.
#[test]
fn openmls_messages_json_roundtrip_via_mls_rs() {
    let path = openmls_test_vectors_dir().join("messages.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{SUBMODULE_HELP} (path: {})", path.display()));
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("messages.json deserialises as array");

    let mut roundtrips_ok = 0usize;
    let mut roundtrips_failed = Vec::<String>::new();

    for (idx, entry) in entries.iter().enumerate() {
        for field in MLS_MESSAGE_FIELDS {
            let Some(hex_str) = json_hex_field(entry, field) else {
                continue;
            };
            let bytes = hex::decode(hex_str)
                .unwrap_or_else(|e| panic!("entry {idx} field {field}: hex decode {e}"));
            match MlsMessage::from_bytes(&bytes) {
                Ok(msg) => match msg.to_bytes() {
                    Ok(reser) if reser == bytes => roundtrips_ok += 1,
                    Ok(reser) => roundtrips_failed.push(format!(
                        "entry {idx} field {field}: byte mismatch — original {} bytes, \
                         reserialized {} bytes",
                        bytes.len(),
                        reser.len(),
                    )),
                    Err(e) => {
                        roundtrips_failed.push(format!("entry {idx} field {field}: to_bytes {e:?}"))
                    }
                },
                Err(e) => {
                    roundtrips_failed.push(format!("entry {idx} field {field}: from_bytes {e:?}"))
                }
            }
        }
    }

    assert!(
        roundtrips_failed.is_empty(),
        "{} cross-impl roundtrip failures (openmls → mls-rs):\n{}",
        roundtrips_failed.len(),
        roundtrips_failed.join("\n"),
    );
    assert!(
        roundtrips_ok >= 250,
        "expected ≥250 successful MlsMessage roundtrips against openmls messages.json, \
         got {roundtrips_ok} — upstream openmls dropped vectors? \
         (audit 2026-04-29 baseline 300 entries × 3 fields ≥ 250 non-empty)",
    );
}

/// Roundtrip welcome bundle openmls `welcome.json` (один entry per RFC 9420
/// ciphersuite 1-7) — оба `welcome` и `key_package` поля.
///
/// Это покрытие per-ciphersuite детектора: если upstream openmls когда-нибудь
/// удалит test vector для ciphersuite в нашем whitelist, тест fail-ит с
/// именованным ciphersuite вместо общей счётчик-проверки.
///
/// Roundtrip the welcome bundles in openmls's `welcome.json` (one entry per
/// RFC 9420 ciphersuite 1-7) — both the `welcome` and `key_package` fields.
///
/// This is the per-ciphersuite drift detector: if openmls upstream ever
/// drops a test vector for a ciphersuite in our whitelist, the test fails
/// with a named ciphersuite instead of relying on a generic counter.
#[test]
fn openmls_welcome_json_roundtrip_per_whitelisted_ciphersuite_via_mls_rs() {
    let path = openmls_test_vectors_dir().join("welcome.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{SUBMODULE_HELP} (path: {})", path.display()));
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("welcome.json deserialises as array");

    let mut whitelisted_seen = std::collections::BTreeSet::<u16>::new();

    for (idx, entry) in entries.iter().enumerate() {
        let cs = entry
            .get("cipher_suite")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| panic!("welcome.json entry {idx} missing cipher_suite"))
            as u16;

        for field in ["welcome", "key_package"] {
            let Some(hex_str) = json_hex_field(entry, field) else {
                panic!("welcome.json entry {idx} (cipher_suite={cs:#06x}) missing field {field}");
            };
            let bytes = hex::decode(hex_str)
                .unwrap_or_else(|e| panic!("entry {idx} cs={cs:#06x} field {field}: hex {e}"));
            let msg = MlsMessage::from_bytes(&bytes).unwrap_or_else(|e| {
                panic!(
                    "mls-rs не парсит {field} из openmls welcome.json для cipher_suite \
                     {cs:#06x}: {e:?}",
                )
            });
            let reser = msg.to_bytes().unwrap_or_else(|e| {
                panic!("mls-rs to_bytes failed for cs={cs:#06x} field {field}: {e:?}")
            });
            assert_eq!(
                reser,
                bytes,
                "byte roundtrip mismatch для cs={cs:#06x} field {field}: \
                 original {} bytes vs reserialized {} bytes",
                bytes.len(),
                reser.len(),
            );
        }

        if WHITELISTED_CIPHERSUITES.contains(&cs) {
            whitelisted_seen.insert(cs);
        }
    }

    for &expected in &WHITELISTED_CIPHERSUITES {
        assert!(
            whitelisted_seen.contains(&expected),
            "openmls welcome.json не содержит entry для whitelisted ciphersuite \
             {expected:#06x} (SPEC-03 §4.1) — upstream удалил test vector? \
             openmls welcome.json is missing an entry for the whitelisted ciphersuite \
             {expected:#06x} (SPEC-03 §4.1) — has upstream dropped the test vector?",
        );
    }
}

/// Smoke-тест что pure-Rust crypto provider mls-rs поддерживает **X25519
/// subset** whitelist SPEC-03 §4.1 (0x0001, 0x0003). X448/Ed448 варианты
/// (0x0004, 0x0006) умышленно не проверяются в этом тесте — это known gap
/// RustCrypto ecosystem, documented in private cross-implementation notes
/// §3 («Coverage matrix»).
///
/// Защита от silent drift: если будущий релиз `mls-rs-crypto-rustcrypto`
/// dropнет (например) ciphersuite 0x0001 (default), мы хотим узнать сразу,
/// не на этапе production rollout block 9.12 PQ-first switch.
///
/// Smoke test that the pure-Rust mls-rs crypto provider supports the
/// **X25519 subset** of the SPEC-03 §4.1 whitelist (0x0001, 0x0003). The
/// X448/Ed448 variants (0x0004, 0x0006) are intentionally not checked here:
/// they are a known gap in the RustCrypto ecosystem, documented in
/// private cross-implementation notes ("Coverage matrix").
///
/// Guards against silent drift: if a future `mls-rs-crypto-rustcrypto`
/// release drops (e.g.) ciphersuite 0x0001 (the default), we want to hear
/// about it immediately, not during the block 9.12 PQ-first rollout.
#[test]
fn mls_rs_rust_crypto_provider_covers_x25519_subset_of_spec03_whitelist() {
    let provider = RustCryptoProvider::new();
    let supported: Vec<CipherSuite> = provider.supported_cipher_suites();
    let supported_ids: Vec<u16> = supported.iter().map(|cs| u16::from(*cs)).collect();

    for &expected in &WHITELISTED_X25519_RUSTCRYPTO {
        assert!(
            supported.iter().any(|cs| u16::from(*cs) == expected),
            "mls-rs RustCryptoProvider не поддерживает X25519 whitelisted \
             ciphersuite {expected:#06x} (supported: {supported_ids:?}). \
             mls-rs RustCryptoProvider does not support the X25519 whitelisted \
             ciphersuite {expected:#06x} (supported: {supported_ids:?}).",
        );
    }
}

/// Trip-wire: если `mls-rs-crypto-rustcrypto` неожиданно начал поддерживать
/// X448/Ed448 (0x0004, 0x0006), это — позитивный сигнал, но требует
/// расширения coverage matrix в `cross_impl_compatibility.md` §3 и
/// активации полного whitelist'а в smoke-тесте выше. Тест fail-ит чтобы
/// не пропустить новые возможности upstream.
///
/// Trip-wire: if `mls-rs-crypto-rustcrypto` unexpectedly starts supporting
/// X448/Ed448 (0x0004, 0x0006), that is a positive signal, but it requires
/// extending the coverage matrix in `cross_impl_compatibility.md` §3 and
/// activating the full whitelist in the smoke test above. The test fails so
/// the new upstream capability is not missed.
#[test]
fn mls_rs_rust_crypto_provider_does_not_yet_support_ed448_known_gap() {
    let provider = RustCryptoProvider::new();
    let supported: Vec<CipherSuite> = provider.supported_cipher_suites();
    let supported_ids: Vec<u16> = supported.iter().map(|cs| u16::from(*cs)).collect();

    for &ed448_cs in &[0x0004u16, 0x0006u16] {
        let has_it = supported.iter().any(|cs| u16::from(*cs) == ed448_cs);
        assert!(
            !has_it,
            "mls-rs RustCryptoProvider добавил Ed448 ({ed448_cs:#06x}) — расширить \
             WHITELISTED_X25519_RUSTCRYPTO в этом файле + coverage matrix в \
             private cross-implementation notes (supported: {supported_ids:?}). \
             mls-rs RustCryptoProvider has landed Ed448 ({ed448_cs:#06x}) — extend \
             WHITELISTED_X25519_RUSTCRYPTO in this file plus the coverage matrix in \
             private cross-implementation notes (supported: {supported_ids:?}).",
        );
    }
}

/// Smoke-тест что mls-rs **trip-wire** для X-Wing PQ (0x004D): pure-Rust
/// crypto provider mls-rs пока не поддерживает X-Wing. Когда поддержка
/// появится — тест fail-ит и сигнализирует о готовности к Variant B
/// миграции (block 9.14 future-migration playbook §11.1).
///
/// Pattern E (V1↔V2 coexistence) symmetric с
/// `cross_impl_openmls.rs::snapshot_does_not_yet_carry_x_wing_must_still_be_v1_only`.
///
/// **Trip-wire** smoke test for X-Wing PQ (0x004D): the pure-Rust mls-rs
/// crypto provider does not yet support X-Wing. When support lands, this
/// test fails and signals readiness for the Variant B migration (block 9.14
/// future-migration playbook §11.1).
///
/// Pattern E (V1↔V2 coexistence) symmetric to
/// `cross_impl_openmls.rs::snapshot_does_not_yet_carry_x_wing_must_still_be_v1_only`.
#[test]
fn mls_rs_rust_crypto_provider_does_not_yet_support_x_wing_must_still_be_v1_only() {
    const X_WING: u16 = 0x004D;
    let provider = RustCryptoProvider::new();
    let supported = provider.supported_cipher_suites();

    let has_x_wing = supported.iter().any(|cs| u16::from(*cs) == X_WING);
    assert!(
        !has_x_wing,
        "mls-rs добавил native X-Wing (0x{X_WING:04x}) — запустить future-migration \
         playbook design.md §11.1 (block 9.14). \
         mls-rs has landed native X-Wing (0x{X_WING:04x}) — start the future-migration \
         playbook design.md §11.1 (block 9.14).",
    );
}
