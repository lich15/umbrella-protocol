//! Block 9.12 PQ-first default switch — migration tests + cfg-conditional
//! [`umbrella_client::DEFAULT_CIPHERSUITE`] gate behaviour + ABI invariant
//! verification.
//!
//! Подтверждает контракт ADR-013 + design.md §8 + plan §9.12: после default
//! switch на `0x004D` (X-Wing PQ) под feature `pq` —
//! [`UmbrellaClient::bootstrap_for_test`] возвращает client с
//! `default_ciphersuite = 0x004D` (PQ-first). Под cfg classical-only — `0x0003`
//! (legacy). [`UmbrellaClient::bootstrap_classical_for_test`] — explicit
//! classical bootstrap path для regression coverage и mixed groups (Pattern E
//! sixth application). Постулат 14 «no silent fallback» — выбор режима всегда
//! через named constructor либо per-чат `ChatSettings.ciphersuite` override.
//!
//! Block 9.12 PQ-first default switch — migration tests + cfg-conditional
//! [`umbrella_client::DEFAULT_CIPHERSUITE`] gate behaviour + ABI invariant
//! verification.
//!
//! Confirms the ADR-013 + design.md §8 + plan §9.12 contract: after the
//! default switch to `0x004D` (X-Wing PQ) under feature `pq` —
//! [`UmbrellaClient::bootstrap_for_test`] returns a client with
//! `default_ciphersuite = 0x004D` (PQ-first). Under cfg classical-only —
//! `0x0003` (legacy). [`UmbrellaClient::bootstrap_classical_for_test`] is the
//! explicit classical bootstrap path for regression coverage and mixed
//! groups (Pattern E sixth application). Postulate 14 «no silent fallback»
//! — mode selection is always through a named constructor or a per-chat
//! `ChatSettings.ciphersuite` override.
//!
//! ## Test matrix
//!
//! | # | Тест | Под cfg | Покрывает |
//! |---|---|---|---|
//! | T1 | `default_ciphersuite_const_value_classical` | not pq | `DEFAULT_CIPHERSUITE == 0x0003` |
//! | T2 | `default_ciphersuite_const_value_pq` | pq | `DEFAULT_CIPHERSUITE == 0x004D` |
//! | T3 | `client_config_default_default_ciphersuite_matches_const` | always | Default impl uses cfg-conditional const |
//! | T4 | `client_config_default_safe_stubs_for_other_fields` | always | URLs empty, kt_monitor_interval_secs = 3600, ThresholdConfig 3-of-5 |
//! | T5 | `client_config_default_rest_pattern_works` | always | `ClientConfig { default_ciphersuite: x, ..Default::default() }` works |
//! | T6 | `bootstrap_for_test_uses_classical_default_under_no_pq_feature` | not pq | `bootstrap_for_test → 0x0003` |
//! | T7 | `bootstrap_for_test_uses_pq_default_under_pq_feature` | pq | `bootstrap_for_test → 0x004D` (PQ-FIRST SWITCH) |
//! | T8 | `bootstrap_classical_for_test_classical_regardless_of_feature_pq` | always | `bootstrap_classical_for_test → 0x0003` |
//! | T9 | `bootstrap_classical_for_test_overrides_pq_input_under_pq_feature` | pq | override 0x004D → 0x0003 (postulate 14 explicit) |
//! | T10 | `bootstrap_pq_for_test_overrides_classical_input_under_pq_feature` | pq | override 0x0003 → 0x004D (existing block 8.8) |
//! | T11 | `pattern_e_classical_and_pq_clients_coexist_under_pq_feature` | pq | V1 + V2 clients side-by-side independent state |
//!
//! Глубокие сценарии mixed groups capability negotiation (block 8.8 milestone
//! scenario 6 — `ChatSettings.ciphersuite = Some(0x0003)` на PQ-default
//! клиенте → effective 0x0003) — уже покрыты в `tests/stage8_milestone.rs`
//! S6 под cfg `pq`. Block 9.12 не дублирует этот контракт; он verify-ит
//! cfg-conditional default + override semantics.
//!
//! Deep mixed-group capability negotiation scenarios (Block 8.8 milestone
//! scenario 6 — `ChatSettings.ciphersuite = Some(0x0003)` on a PQ-default
//! client → effective 0x0003) are already covered in `tests/stage8_milestone.rs`
//! S6 under cfg `pq`. Block 9.12 does not duplicate that contract; it
//! verifies the cfg-conditional default + override semantics.

use rand::rngs::OsRng;
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
#[cfg(feature = "pq")]
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_PQ_HYBRID;
use umbrella_client::{ClientConfig, UmbrellaClient, DEFAULT_CIPHERSUITE};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

/// CSPRNG-генерируемый IdentitySeed для bootstrap тестов. Не deterministic —
/// эти tests не проверяют detereminism property; нужен любой valid seed.
///
/// CSPRNG-generated `IdentitySeed` for bootstrap tests. Not deterministic —
/// these tests do not verify determinism; any valid seed works.
fn random_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

/// Тестовый `ClientConfig` со stub URL-ами через `Default` impl. Поскольку
/// integration scenarios block 9.12 не делают сетевых вызовов — пустые URL
/// stubs из Default::default() достаточны.
///
/// Test `ClientConfig` with stub URLs via the `Default` impl. Since Block 9.12
/// integration scenarios do not perform network I/O, the empty-URL stubs from
/// `Default::default()` are sufficient.
fn test_config() -> ClientConfig {
    ClientConfig::default()
}

// ───────────────────────────────────────────────────────────────────
// T1 / T2 — DEFAULT_CIPHERSUITE const value verification.
// ───────────────────────────────────────────────────────────────────

/// T1 — Под cfg classical-only [`DEFAULT_CIPHERSUITE`] = `0x0003`
/// (`UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT`). ADR-013 Решение 1 + 3.
///
/// T1 — Under cfg classical-only, [`DEFAULT_CIPHERSUITE`] = `0x0003`
/// (`UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT`). ADR-013 Decisions 1 and 3.
#[cfg(not(feature = "pq"))]
#[test]
fn default_ciphersuite_const_value_classical() {
    assert_eq!(
        DEFAULT_CIPHERSUITE, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T1: DEFAULT_CIPHERSUITE must be 0x0003 under cfg classical-only \
         (ADR-013 Решение 1 + 3 + ABI invariant ADR-010)"
    );
    assert_eq!(
        DEFAULT_CIPHERSUITE, 0x0003u16,
        "T1: 0x0003 IANA = MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
    );
}

/// T2 — Под cfg `pq` [`DEFAULT_CIPHERSUITE`] = `0x004D`
/// (`UMBRELLA_CIPHERSUITE_PQ_HYBRID`). ADR-013 Решение 1 + 3 — block 9.12
/// PQ-FIRST DEFAULT SWITCH. Quantum-adversary-today threat model active.
///
/// T2 — Under cfg `pq`, [`DEFAULT_CIPHERSUITE`] = `0x004D`
/// (`UMBRELLA_CIPHERSUITE_PQ_HYBRID`). ADR-013 Decisions 1 and 3 — Block
/// 9.12 PQ-FIRST DEFAULT SWITCH. Quantum-adversary-today threat model
/// active.
#[cfg(feature = "pq")]
#[test]
fn default_ciphersuite_const_value_pq() {
    assert_eq!(
        DEFAULT_CIPHERSUITE, UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "T2: DEFAULT_CIPHERSUITE must be 0x004D under cfg pq \
         (ADR-013 Решение 1 + 3, block 9.12 PQ-first default switch)"
    );
    assert_eq!(
        DEFAULT_CIPHERSUITE, 0x004Du16,
        "T2: 0x004D IANA = MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
    );
}

// ───────────────────────────────────────────────────────────────────
// T3 / T4 / T5 — ClientConfig::default Default impl behaviour.
// ───────────────────────────────────────────────────────────────────

/// T3 — `ClientConfig::default().default_ciphersuite` matches cfg-conditional
/// [`DEFAULT_CIPHERSUITE`] const. ADR-013 Решение 3 Вариант B (Default impl
/// с cfg-conditional const).
///
/// T3 — `ClientConfig::default().default_ciphersuite` matches the
/// cfg-conditional [`DEFAULT_CIPHERSUITE`] const. ADR-013 Decision 3 Variant
/// B (Default impl with cfg-conditional const).
#[test]
fn client_config_default_default_ciphersuite_matches_const() {
    let cfg = ClientConfig::default();
    assert_eq!(
        cfg.default_ciphersuite, DEFAULT_CIPHERSUITE,
        "T3: Default::default().default_ciphersuite must match \
         cfg-conditional DEFAULT_CIPHERSUITE const (ADR-013 Решение 3)"
    );
}

/// T4 — Default impl uses safe stubs for non-ciphersuite fields: URLs пусты,
/// kt_monitor_interval_secs = 3600 (SPEC-09 §3 default), wrapping_params
/// 3-of-5 ThresholdConfig + zeroed pubkeys. Production apps должны заполнить
/// URL и pubkeys через native bootstrap layer (Блок 7.4+).
///
/// T4 — The Default impl uses safe stubs for non-ciphersuite fields: URLs
/// empty, kt_monitor_interval_secs = 3600 (SPEC-09 §3 default),
/// wrapping_params with a 3-of-5 ThresholdConfig + zeroed pubkeys. Production
/// apps must populate URLs and pubkeys via the native bootstrap layer
/// (Block 7.4+).
#[test]
fn client_config_default_safe_stubs_for_other_fields() {
    let cfg = ClientConfig::default();
    assert!(
        cfg.sealed_server_urls.is_empty(),
        "T4: sealed_server_urls must be empty stub in Default"
    );
    assert!(
        cfg.postman_url.is_empty(),
        "T4: postman_url must be empty stub in Default"
    );
    assert!(
        cfg.kt_url.is_empty(),
        "T4: kt_url must be empty stub in Default"
    );
    assert!(
        cfg.call_relay_url.is_empty(),
        "T4: call_relay_url must be empty stub in Default"
    );
    assert_eq!(
        cfg.kt_monitor_interval_secs, 3600,
        "T4: kt_monitor_interval_secs default must be 3600s (SPEC-09 §3)"
    );
    assert_eq!(
        cfg.wrapping_params.version, 0,
        "T4: wrapping_params.version default = 0 (stub; production sets via native bootstrap)"
    );
    assert_eq!(
        cfg.wrapping_params.main_pubkey, [0u8; 32],
        "T4: wrapping_params.main_pubkey default = zeroed [u8; 32] stub"
    );
    assert_eq!(
        cfg.wrapping_params.server_pubkeys, [[0u8; 32]; 5],
        "T4: wrapping_params.server_pubkeys default = 5 × zeroed [u8; 32] stubs"
    );
}

/// T5 — Rest-pattern construction `ClientConfig { default_ciphersuite: x,
/// ..Default::default() }` компилируется и работает. ADR-013 Решение 3
/// Вариант B плюс — «existing test code через `ClientConfig::default()..custom_field`
/// работает».
///
/// T5 — Rest-pattern construction `ClientConfig { default_ciphersuite: x,
/// ..Default::default() }` compiles and works. ADR-013 Decision 3 Variant B
/// plus — «existing test code via `ClientConfig::default()..custom_field`
/// works».
#[test]
fn client_config_default_rest_pattern_works() {
    let cfg = ClientConfig {
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        ..ClientConfig::default()
    };
    assert_eq!(
        cfg.default_ciphersuite, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T5: rest-pattern override of default_ciphersuite must take effect"
    );
    // Other fields preserved from Default::default().
    assert_eq!(cfg.kt_monitor_interval_secs, 3600);
}

// ───────────────────────────────────────────────────────────────────
// T6 / T7 — bootstrap_for_test cfg-conditional default behaviour.
// ───────────────────────────────────────────────────────────────────

/// T6 — Под cfg classical-only [`UmbrellaClient::bootstrap_for_test`] →
/// клиент с `default_ciphersuite = 0x0003`. ABI invariant ADR-010 — existing
/// 0.0.11 path не меняется без feature pq.
///
/// T6 — Under cfg classical-only,
/// [`UmbrellaClient::bootstrap_for_test`] → client with
/// `default_ciphersuite = 0x0003`. ABI invariant ADR-010 — existing 0.0.11
/// path unchanged without feature `pq`.
#[cfg(not(feature = "pq"))]
#[tokio::test]
async fn bootstrap_for_test_uses_classical_default_under_no_pq_feature() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), random_seed())
        .await
        .expect("T6: bootstrap_for_test must succeed on a valid seed");

    assert_eq!(
        client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T6: bootstrap_for_test under cfg classical-only must produce \
         default_ciphersuite = 0x0003 (ABI invariant ADR-010 + ADR-013 Решение 2 \
         Вариант B — existing path unchanged)"
    );
}

/// T7 — Под cfg `pq` [`UmbrellaClient::bootstrap_for_test`] → клиент с
/// `default_ciphersuite = 0x004D`. **Block 9.12 PQ-FIRST DEFAULT SWITCH** —
/// quantum-adversary-today threat model: harvest-now-decrypt-later закрыт by
/// default для всех новых установок (постулат 3 максимум; ADR-013 Решение 1
/// Вариант C; SPEC-13 §13.3 Stage 1 active).
///
/// T7 — Under cfg `pq`, [`UmbrellaClient::bootstrap_for_test`] → client with
/// `default_ciphersuite = 0x004D`. **Block 9.12 PQ-FIRST DEFAULT SWITCH** —
/// quantum-adversary-today threat model: harvest-now-decrypt-later closed by
/// default for all new installs (postulate 3 maximum; ADR-013 Decision 1
/// Variant C; SPEC-13 §13.3 Stage 1 active).
#[cfg(feature = "pq")]
#[tokio::test]
async fn bootstrap_for_test_uses_pq_default_under_pq_feature() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), random_seed())
        .await
        .expect("T7: bootstrap_for_test must succeed on a valid seed");

    assert_eq!(
        client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "T7: bootstrap_for_test under cfg pq must produce default_ciphersuite = \
         0x004D (BLOCK 9.12 PQ-FIRST DEFAULT SWITCH; ADR-013 Решение 1 Вариант C; \
         SPEC-13 §13.3 Stage 1 active)"
    );
}

// ───────────────────────────────────────────────────────────────────
// T8 / T9 — bootstrap_classical_for_test always-classical behaviour.
// ───────────────────────────────────────────────────────────────────

/// T8 — [`UmbrellaClient::bootstrap_classical_for_test`] → клиент с
/// `default_ciphersuite = 0x0003` независимо от feature `pq`. Explicit
/// classical bootstrap path для regression coverage и mixed groups
/// (Pattern E sixth application; ADR-013 Решение 1 Вариант C).
///
/// T8 — [`UmbrellaClient::bootstrap_classical_for_test`] → client with
/// `default_ciphersuite = 0x0003` regardless of feature `pq`. Explicit
/// classical bootstrap path for regression coverage and mixed groups
/// (Pattern E sixth application; ADR-013 Decision 1 Variant C).
#[tokio::test]
async fn bootstrap_classical_for_test_classical_regardless_of_feature_pq() {
    let client = UmbrellaClient::bootstrap_classical_for_test(test_config(), random_seed())
        .await
        .expect("T8: bootstrap_classical_for_test must succeed on a valid seed");

    assert_eq!(
        client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T8: bootstrap_classical_for_test must produce default_ciphersuite = 0x0003 \
         regardless of feature pq (ADR-013 Решение 1 Вариант C — explicit V1 \
         bootstrap path для regression coverage)"
    );
}

/// T9 — Под cfg `pq` [`UmbrellaClient::bootstrap_classical_for_test`] явно
/// override-ит config с `default_ciphersuite = 0x004D` → `0x0003`. Постулат
/// 14 «no silent fallback» — caller-side override explicit, не runtime
/// magic.
///
/// T9 — Under cfg `pq`, [`UmbrellaClient::bootstrap_classical_for_test`]
/// explicitly overrides a config with `default_ciphersuite = 0x004D` to
/// `0x0003`. Postulate 14 «no silent fallback» — caller-side override is
/// explicit, not runtime magic.
#[cfg(feature = "pq")]
#[tokio::test]
async fn bootstrap_classical_for_test_overrides_pq_input_under_pq_feature() {
    let pq_config = ClientConfig {
        default_ciphersuite: UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        ..ClientConfig::default()
    };
    let client = UmbrellaClient::bootstrap_classical_for_test(pq_config, random_seed())
        .await
        .expect("T9: bootstrap_classical_for_test must succeed");

    assert_eq!(
        client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T9: bootstrap_classical_for_test must override caller-supplied 0x004D → \
         0x0003 (постулат 14 — explicit named-constructor choice)"
    );
}

// ───────────────────────────────────────────────────────────────────
// T10 — bootstrap_pq_for_test override behaviour (re-verify block 8.8).
// ───────────────────────────────────────────────────────────────────

/// T10 — Под cfg `pq` [`UmbrellaClient::bootstrap_pq_for_test`] явно
/// override-ит config с `default_ciphersuite = 0x0003` → `0x004D`.
/// Re-verify-ит block 8.8 milestone S4.a контракт после default switch — то
/// есть после block 9.12 changes existing `bootstrap_pq_for_test` поведение
/// **не меняется** (ABI invariant 0.0.11 + ADR-013 Решение 2 — existing
/// PQ-aware test path сохраняется).
///
/// T10 — Under cfg `pq`,
/// [`UmbrellaClient::bootstrap_pq_for_test`] explicitly overrides a config
/// with `default_ciphersuite = 0x0003` to `0x004D`. Re-verifies the Block
/// 8.8 milestone S4.a contract after the default switch — i.e. after Block
/// 9.12 changes, the existing `bootstrap_pq_for_test` behaviour is
/// **unchanged** (ABI invariant 0.0.11 + ADR-013 Decision 2 — existing
/// PQ-aware test path preserved).
#[cfg(feature = "pq")]
#[tokio::test]
async fn bootstrap_pq_for_test_overrides_classical_input_under_pq_feature() {
    let classical_config = ClientConfig {
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        ..ClientConfig::default()
    };
    let client = UmbrellaClient::bootstrap_pq_for_test(classical_config, random_seed())
        .await
        .expect("T10: bootstrap_pq_for_test must succeed");

    assert_eq!(
        client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "T10: bootstrap_pq_for_test must override caller-supplied 0x0003 → 0x004D \
         (block 8.8 S4.a re-verified post default switch — ABI 0.0.11 invariant)"
    );
}

// ───────────────────────────────────────────────────────────────────
// T11 — Pattern E sixth application: V1 + V2 client coexistence.
// ───────────────────────────────────────────────────────────────────

/// T11 — Pattern E sixth application: classical-bootstrap клиент + PQ-default
/// клиент работают side-by-side в одном процессе с независимым `default_ciphersuite`
/// state'ом. После default switch на 0x004D под feature `pq`, существующие
/// migration paths (V1 client → mixed group с V2 peer через
/// `bootstrap_classical_for_test`) сохраняются — block 9.11 cross-impl interop +
/// block 8.8 milestone scenario 6 теперь имеют explicit constructor вместо
/// implicit classical default.
///
/// T11 — Pattern E sixth application: a classical-bootstrap client + a
/// PQ-default client run side-by-side in the same process with independent
/// `default_ciphersuite` state. After the default switch to 0x004D under
/// feature `pq`, existing migration paths (V1 client → mixed group with V2
/// peer via `bootstrap_classical_for_test`) are preserved — Block 9.11
/// cross-impl interop + Block 8.8 milestone scenario 6 now have an explicit
/// constructor instead of an implicit classical default.
#[cfg(feature = "pq")]
#[tokio::test]
async fn pattern_e_classical_and_pq_clients_coexist_under_pq_feature() {
    let classical = UmbrellaClient::bootstrap_classical_for_test(test_config(), random_seed())
        .await
        .expect("T11: classical client bootstrap must succeed");
    let pq_default = UmbrellaClient::bootstrap_for_test(test_config(), random_seed())
        .await
        .expect("T11: PQ-default client bootstrap must succeed");
    let pq_explicit = UmbrellaClient::bootstrap_pq_for_test(test_config(), random_seed())
        .await
        .expect("T11: explicit PQ client bootstrap must succeed");

    // V1 path остаётся 0x0003.
    // V1 path remains 0x0003.
    assert_eq!(
        classical.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "T11: classical client default_ciphersuite isolated at 0x0003"
    );

    // V2 default path и V2 explicit path оба → 0x004D, no cross-talk с V1.
    // V2 default and V2 explicit paths both → 0x004D, no cross-talk with V1.
    assert_eq!(
        pq_default.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "T11: PQ-default client default_ciphersuite at 0x004D (block 9.12 switch)"
    );
    assert_eq!(
        pq_explicit.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "T11: explicit PQ client default_ciphersuite at 0x004D (block 8.8 path)"
    );

    // Independent state — изменения одного клиента не влияют на другого.
    // Independent state — changes to one client do not affect another.
    assert_ne!(
        classical.core().default_ciphersuite(),
        pq_default.core().default_ciphersuite(),
        "T11: V1 + V2 clients must have independent default_ciphersuite \
         (Pattern E V1↔V2 coexistence sixth application)"
    );
}
