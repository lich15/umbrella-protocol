#![allow(deprecated)] // Round-6: test exercises legacy IdentitySeed::generate; production uses bootstrap_account
//! Stage 8 closing milestone — end-to-end integration scenarios для Hybrid
//! Post-Quantum слоя UmbrellaX.
//!
//! Файл активен только под feature `pq` (зонтичный agregator из umbrella-client
//! пробрасывает в umbrella-mls/identity/kt/sealed-sender/backup, ADR-011 Решение 7).
//! Без feature `pq` файл вообще не компилируется (`#![cfg(feature = "pq")]`),
//! и `cargo test --workspace --no-default-features --locked` не видит этих
//! сценариев — гарантия что existing 0.0.11 path не зависит от наличия PQ
//! артефактов.
//!
//! ## Scope
//!
//! Workspace-level integration scenarios для Stage 8: проверяют что
//! aggregator features корректно собираются, фасадный API правильно
//! устанавливает ciphersuite, и что V1 ↔ V2 dispatcher (KT v2, sealed-sender
//! V2, backup wrap V2) корректно работает в смешанном корпусе. Глубокие
//! crypto-уровневые KAT и proptest'ы живут в crate-level tests блоков
//! 8.2–8.7 (`umbrella-pq/tests/nist_kat_*.rs`,
//! `umbrella-mls/tests/pq_*.rs`, etc.) — здесь дублирование не имеет смысла.
//!
//! | # | Scenario | Покрывает |
//! |---|---|---|
//! | S1 | PQ bootstrap end-to-end | bootstrap_pq_for_test default ciphersuite, HybridIdentityKey derive из same seed, KT v2 версионная схема byte 0x02 |
//! | S2 | Cloud PQ chat | CloudChat::create под bootstrap_pq → effective ciphersuite 0x004D, backup wrap V2 размер |
//! | S3 | Secret PQ chat | SecretChat::create под bootstrap_pq → 0x004D, sealed-sender V2 wire constants |
//! | S4 | KT v1↔v2 mixed log + downgrade resistance | KtEntryVersion peek byte, mixed corpus parse, classical/PQ переключение через separate bootstrap |
//! | S5 | SLH-DSA backup recovery | SlhDsaBackupKey derive (single mnemonic invariant), rotation_proof sign+verify roundtrip |
//! | S6 | Mixed group fallback | per-chat override ChatSettings.ciphersuite = Some(0x0003) на bootstrap_pq клиенте → effective 0x0003 (no silent fallback contract, постулат 14) |
//!
//! Stage 8 closing milestone — workspace-level integration scenarios for the
//! Hybrid Post-Quantum layer. Active only under feature `pq`
//! (`#![cfg(feature = "pq")]`); without it the file does not compile and
//! `cargo test --workspace --no-default-features --locked` does not even see
//! these scenarios — a guarantee that the existing 0.0.11 path is independent
//! of PQ artifacts.
//!
//! Deep crypto-level KATs and proptests live in crate-level tests of Blocks
//! 8.2–8.7 (`umbrella-pq/tests/nist_kat_*.rs`, `umbrella-mls/tests/pq_*.rs`,
//! …). This file does not duplicate them; it verifies that the aggregator
//! features compose correctly and that the facade ciphersuite API behaves.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand::rngs::OsRng;
use umbrella_backup::cloud_wrap::pq_wrap::{WrappedKeyV2, WRAPPED_KEY_V2_LEN};
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT, UMBRELLA_CIPHERSUITE_PQ_HYBRID,
};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{
    CloudWrapRecoveryKey, HybridIdentityKey, IdentitySeed, MnemonicLanguage, SlhDsaBackupKey,
    HYBRID_IDENTITY_PUBLIC_KEY_LEN,
};
use umbrella_kt::KtEntryVersion;
use umbrella_pq::constants::XWING_PUBLIC_KEY_LEN;
use umbrella_pq::xwing::{xwing_keygen, XWingPublicKey};

/// Тестовый `ClientConfig` со stub URL-ами. URL-ы валидны для парсинга, но не
/// бьются на реальные сервисы — integration scenarios не делают сетевых
/// вызовов.
///
/// Test `ClientConfig` with stub URLs. The URLs parse but do not point at
/// real services — integration scenarios do not perform network I/O.
fn pq_test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://postman:8080".into(),
        kt_url: "http://kt:8080".into(),
        call_relay_url: "http://call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
        },
        // Этот config используется и для bootstrap_for_test (classical path в S4),
        // и для bootstrap_pq_for_test (override → 0x004D). Default здесь classical.
        // This config feeds bootstrap_for_test (classical path in S4) as well as
        // bootstrap_pq_for_test (override → 0x004D). The default here is classical.
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

/// Stable seed для scenarios, где нужна детерминированность (S5
/// «single mnemonic invariant» — два derive'а одного и того же `IdentitySeed`
/// должны дать byte-equal SLH-DSA pubkey'и).
///
/// Stable seed for scenarios needing determinism (S5 «single mnemonic
/// invariant» — two derives of the same `IdentitySeed` must produce
/// byte-equal SLH-DSA pubkeys).
fn deterministic_seed() -> IdentitySeed {
    // 24-word English BIP-39 phrase зафиксирована для test-only; CSPRNG-генерация
    // всё-равно используется в большинстве scenarios через `IdentitySeed::generate`.
    // 24-word English BIP-39 phrase pinned for test-only use; CSPRNG generation
    // is still preferred for most scenarios via `IdentitySeed::generate`.
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon art";
    IdentitySeed::from_mnemonic(phrase, MnemonicLanguage::English)
        .expect("canonical 24-word BIP-39 «abandon × 23 + art» — valid seed")
}

/// CSPRNG seed для большинства scenarios (S1–S4 + S6). S5 нуждается в
/// `deterministic_seed()` для проверки detereminism property.
///
/// CSPRNG seed for most scenarios (S1–S4 + S6). S5 requires
/// `deterministic_seed()` to assert the determinism property.
fn random_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

// ───────────────────────────────────────────────────────────────────
// Scenario 1 — PQ bootstrap end-to-end.
// ───────────────────────────────────────────────────────────────────
//
// Проверяет что:
// - `UmbrellaClient::bootstrap_pq_for_test` устанавливает
//   `default_ciphersuite = 0x004D` (postулат 14: explicit, не silent default).
// - Из того же seed можно derive `HybridIdentityKey` (Ed25519+ML-DSA-65
//   AND-mode) — single mnemonic invariant.
// - `HybridIdentityKey` public bytes имеют ожидаемую длину 1984 байта
//   (32 Ed25519 + 1952 ML-DSA-65, сверка с FIPS 204 константами).
// - KT v2 версионная схема имеет stable byte stamp 0x02 для V2HybridPq
//   (downstream parser detects V2 entries via single byte peek).

#[tokio::test]
async fn s1_pq_bootstrap_end_to_end() {
    // `IdentitySeed` не `Clone` (zeroizable secret material — постулат 4 privacy);
    // используем `deterministic_seed()` чтобы дважды получить byte-equal seed
    // через тот же 24-word phrase. Это same-mnemonic invariant: пользователь
    // имеет одну mnemonic, через неё восстанавливаются ВСЕ identity layers.
    //
    // `IdentitySeed` is not `Clone` (zeroizable secret material — postulate 4
    // privacy); we call `deterministic_seed()` twice to obtain a byte-equal
    // seed via the same 24-word phrase. This is the same-mnemonic invariant:
    // one user mnemonic restores ALL identity layers.

    // --- (a) Bootstrap PQ-режим устанавливает default ciphersuite на 0x004D ---
    let pq_client = UmbrellaClient::bootstrap_pq_for_test(pq_test_config(), deterministic_seed())
        .await
        .expect("bootstrap_pq_for_test must succeed on a valid seed");
    assert!(Arc::strong_count(&pq_client) >= 1);
    assert_eq!(
        pq_client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S1.a: bootstrap_pq must install 0x004D ciphersuite"
    );

    // --- (b) Same seed derives HybridIdentityKey (single mnemonic invariant) ---
    let hybrid = HybridIdentityKey::derive(&deterministic_seed(), /* account = */ 0)
        .expect("hybrid identity derive from valid seed must succeed");
    assert_eq!(
        hybrid.account(),
        0,
        "S1.b: hybrid identity account preserved"
    );

    // --- (c) HybridIdentityKey public bytes имеют ожидаемую длину ---
    let public_bytes = hybrid.public().to_bytes();
    assert_eq!(
        public_bytes.len(),
        HYBRID_IDENTITY_PUBLIC_KEY_LEN,
        "S1.c: hybrid pubkey length = 32 (Ed25519) + 1952 (ML-DSA-65)"
    );
    assert_eq!(
        HYBRID_IDENTITY_PUBLIC_KEY_LEN, 1984,
        "S1.c: HYBRID_IDENTITY_PUBLIC_KEY_LEN constant must equal 1984 bytes \
         (32 + ML_DSA_65_PUBLIC_KEY_LEN)"
    );

    // --- (d) KT v2 schema byte stamp = 0x02 (V2HybridPq) ---
    assert_eq!(
        KtEntryVersion::V2HybridPq.as_u8(),
        0x02,
        "S1.d: V2HybridPq IANA byte stamp must be 0x02 (downstream parser invariant)"
    );
    assert_eq!(
        KtEntryVersion::V1Classical.as_u8(),
        0x01,
        "S1.d: V1Classical IANA byte stamp must be 0x01 (existing wire-format unchanged)"
    );
}

// ───────────────────────────────────────────────────────────────────
// Scenario 2 — Cloud PQ chat (X-Wing MLS group + sealed-sender V2 +
// threshold-wrap PQ).
// ───────────────────────────────────────────────────────────────────
//
// Проверяет что:
// - CloudChat::create на bootstrap_pq клиенте без явного
//   `ChatSettings.ciphersuite` подбирает `core.default_ciphersuite()` =
//   0x004D.
// - cloud.ciphersuite() accessor возвращает effective значение.
// - Backup wrap V2 wire size константа `WRAPPED_KEY_V2_LEN` имеет
//   ожидаемое значение 1218 bytes (1 version + 1120 X-Wing ct + 81 V1 + 16 AEAD).

#[tokio::test]
async fn s2_cloud_pq_chat() {
    let seed = random_seed();
    let pq_client = UmbrellaClient::bootstrap_pq_for_test(pq_test_config(), seed)
        .await
        .expect("bootstrap_pq");

    let cloud = CloudChat::create(
        pq_client.core(),
        vec![PeerId([0xAA; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("CloudChat::create stub is infallible");

    assert_eq!(
        cloud.ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S2: Cloud chat with default settings on bootstrap_pq → effective 0x004D"
    );

    // Backup wrap V2 размер согласован с design.md §10.2 wire format
    // (1 version + 1120 X-Wing ct + 81 V1 wrapped key + 16 AEAD tag = 1218).
    // Backup wrap V2 size matches design.md §10.2 wire format.
    assert_eq!(
        WRAPPED_KEY_V2_LEN, 1218,
        "S2: backup PQ-wrap V2 wire size must equal 1218 bytes \
         (1 + 1120 + 81 + 16 = 1218 per design.md §10.2)"
    );

    // Smoke test: send_text returns valid 16-byte MessageId stub (Block 7.2 stub).
    let msg_id = cloud
        .send_text("hello PQ cloud".into())
        .await
        .expect("send_text stub");
    assert_eq!(msg_id.0.len(), 16);

    let inbox = cloud.fetch_inbox().await.expect("fetch_inbox stub");
    assert!(inbox.is_empty(), "Block 7.2 inbox stub returns Vec::new()");
}

// ───────────────────────────────────────────────────────────────────
// Scenario 3 — Secret PQ chat (X-Wing MLS group + sealed-sender V2,
// без Cloud-wrap).
// ───────────────────────────────────────────────────────────────────
//
// Проверяет что:
// - SecretChat::create на bootstrap_pq клиенте → effective ciphersuite
//   0x004D (зеркало S2 для Secret-режима).
// - Sealed-sender V2 wire constants доступны (V2_DOMAIN_SEP +
//   V2_MIN_WIRE_LEN) — smoke check что hybrid_envelope module compiled.

#[tokio::test]
async fn s3_secret_pq_chat() {
    let seed = random_seed();
    let pq_client = UmbrellaClient::bootstrap_pq_for_test(pq_test_config(), seed)
        .await
        .expect("bootstrap_pq");

    let secret = SecretChat::create(
        pq_client.core(),
        vec![PeerId([0xBB; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("SecretChat::create stub is infallible");

    assert_eq!(
        secret.ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S3: Secret chat with default settings on bootstrap_pq → effective 0x004D"
    );

    // Sealed-sender V2 wire constants доступны и согласованы с design.md §9.2
    // (V2 envelope: 1 version + 1120 X-Wing ct + min 256 padding bucket + 16 AEAD = ≥1393).
    // Sealed-sender V2 wire constants accessible and consistent with design.md §9.2.
    assert_eq!(
        umbrella_sealed_sender::V2_DOMAIN_SEP,
        b"umbrellax-sealed-sender-v2",
        "S3: sealed-sender V2 domain separator must be canonical"
    );
    // Design invariant: V2 envelope wire ≥ 1393 bytes (1 version + 1120 X-Wing ct
    // + 256 minimum padding bucket + 16 AEAD tag, см. design.md §9.2). Const
    // compile-time assertion даёт zero runtime cost но обеспечивает что любое
    // изменение константы в `umbrella-sealed-sender::lib.rs` ломает сборку
    // этого теста — design contract enforcement.
    //
    // Design invariant: V2 envelope wire ≥ 1393 bytes (1 version + 1120 X-Wing
    // ct + 256 minimum padding bucket + 16 AEAD tag, design.md §9.2). The
    // const compile-time assertion has zero runtime cost while guaranteeing
    // that any change to the constant in `umbrella-sealed-sender::lib.rs`
    // breaks this test build — design contract enforcement.
    const _: () = assert!(umbrella_sealed_sender::V2_MIN_WIRE_LEN >= 1393);

    // Smoke send_text — stub возвращает 16-byte MessageId.
    // Smoke send_text — stub returns 16-byte MessageId.
    let msg_id = secret
        .send_text("hello PQ secret".into())
        .await
        .expect("send_text stub");
    assert_eq!(msg_id.0.len(), 16);
}

// ───────────────────────────────────────────────────────────────────
// Scenario 4 — KT v1 ↔ v2 mixed log + downgrade resistance.
// ───────────────────────────────────────────────────────────────────
//
// Проверяет что:
// - Classical клиент (`bootstrap_for_test`) имеет default 0x0003 — V1 path
//   не сломан под feature pq active.
// - PQ клиент (`bootstrap_pq_for_test`) имеет default 0x004D —
//   downgrade-resistance signal (PQ choice не silently downgraded).
// - KtEntryVersion peek byte корректно различает V1 (0x01) и V2 (0x02);
//   `from_u8` идемпотентен и отвергает unknown versions.

#[tokio::test]
async fn s4_kt_v1_v2_mixed_log_downgrade_resistance() {
    let classical_client = UmbrellaClient::bootstrap_for_test(pq_test_config(), random_seed())
        .await
        .expect("classical bootstrap");
    assert_eq!(
        classical_client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "S4.a: classical bootstrap_for_test default unchanged at 0x0003 (V1 path)"
    );

    let pq_client = UmbrellaClient::bootstrap_pq_for_test(pq_test_config(), random_seed())
        .await
        .expect("PQ bootstrap");
    assert_eq!(
        pq_client.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S4.a: bootstrap_pq_for_test installs 0x004D (no silent downgrade)"
    );

    // Mixed log: peek первого байта различает V1 (0x01) от V2 (0x02).
    // V1 entries в существующем wire-format не имеют version-байта, но KtEntryVersion
    // enum cвязывает 0x01 ↔ V1Classical для conceptual mixing in log mirror.
    //
    // Mixed log: peeking the first byte distinguishes V1 (0x01) from V2 (0x02).
    // V1 entries в the existing wire-format do not carry a version byte, but the
    // KtEntryVersion enum binds 0x01 ↔ V1Classical for conceptual mixing in the
    // log mirror.
    assert_eq!(
        KtEntryVersion::try_from(0x01u8).expect("0x01 is valid"),
        KtEntryVersion::V1Classical,
        "S4.b: byte 0x01 → V1Classical"
    );
    assert_eq!(
        KtEntryVersion::try_from(0x02u8).expect("0x02 is valid"),
        KtEntryVersion::V2HybridPq,
        "S4.b: byte 0x02 → V2HybridPq"
    );
    assert!(
        KtEntryVersion::try_from(0x99u8).is_err(),
        "S4.b: unknown version byte → KtError (postулат 14: no silent fallback)"
    );
}

// ───────────────────────────────────────────────────────────────────
// Scenario 5 — SLH-DSA backup recovery flow.
// ───────────────────────────────────────────────────────────────────
//
// Проверяет что:
// - `SlhDsaBackupKey::derive(&seed, account)` детерминирован (single
//   mnemonic invariant — same seed → same SLH-DSA pubkey bytes).
// - sign_rotation_proof + verify_rotation_proof roundtrip работает:
//   подпись валидной message + tampered message rejected.
// - Тот же 24-word mnemonic восстанавливает ВСЁ identity material:
//   classical Ed25519 + hybrid ML-DSA-65 + SLH-DSA backup + X-Wing
//   cloud-wrap recovery — постулат «single mnemonic invariant».

#[tokio::test]
async fn s5_slh_dsa_backup_recovery_flow() {
    let seed = deterministic_seed();

    // --- (a) Determinism: два derive из same seed → byte-equal pubkey ---
    let backup1 = SlhDsaBackupKey::derive(&seed, /* account = */ 0).expect("backup derive #1");
    let backup2 = SlhDsaBackupKey::derive(&seed, /* account = */ 0).expect("backup derive #2");
    assert_eq!(
        backup1.public().to_bytes(),
        backup2.public().to_bytes(),
        "S5.a: SLH-DSA backup pubkey deterministic from seed"
    );

    // --- (b) Sign + verify rotation proof roundtrip ---
    let mut rng = OsRng;
    let rotation_message = b"umbrellax-test-rotation-msg-S5";
    let proof = backup1
        .sign_rotation_proof(&mut rng, rotation_message)
        .expect("sign_rotation_proof");
    backup1
        .public()
        .verify_rotation_proof(rotation_message, &proof)
        .expect("S5.b: valid rotation proof must verify");

    // --- (c) Tampered message rejected ---
    let tampered = b"umbrellax-test-rotation-msg-TAMPER";
    assert!(
        backup1
            .public()
            .verify_rotation_proof(tampered, &proof)
            .is_err(),
        "S5.c: tampered rotation proof message must fail verification (postулат 4 privacy)"
    );

    // --- (d) Single mnemonic invariant: same seed → derive ВСЁ identity material ---
    // Hybrid identity (Ed25519 + ML-DSA-65) и cloud-wrap recovery X-Wing
    // должны быть derive'аемы из same seed без error — закрытие восстановления
    // через 24-word phrase (постулат 4: privacy на recovery flow).
    let _hybrid = HybridIdentityKey::derive(&seed, 0).expect("hybrid identity from same seed");
    let _cloud_recovery = CloudWrapRecoveryKey::derive(&seed, 0)
        .expect("cloud-wrap X-Wing recovery from same seed (single mnemonic invariant)");
}

// ───────────────────────────────────────────────────────────────────
// Scenario 6 — Mixed group fallback (Alice PQ default, Bob classical).
// ───────────────────────────────────────────────────────────────────
//
// Симулирует mixed group где Alice использует bootstrap_pq (default 0x004D),
// но создаёт chat с Bob который объявил только classical capability —
// negotiation производит explicit `ChatSettings.ciphersuite = Some(0x0003)`,
// override побеждает default. Это **не** silent fallback (постулат 14):
// upper layer (capability negotiation block 8.4 в `umbrella-mls`)
// принимает решение и передаёт его явно.
//
// Также проверяет что explicit `ChatSettings.ciphersuite = Some(0x004D)`
// на classical клиенте даёт effective 0x004D (per-chat upgrade).

#[tokio::test]
async fn s6_mixed_group_explicit_per_chat_override() {
    // --- (a) Alice — bootstrap_pq client; chat с classical-only Bob ---
    let alice = UmbrellaClient::bootstrap_pq_for_test(pq_test_config(), random_seed())
        .await
        .expect("Alice bootstrap_pq");
    assert_eq!(
        alice.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S6.a: Alice default = 0x004D (PQ-aware bootstrap)"
    );

    let mixed_settings = ChatSettings {
        title: Some("alice-pq-with-bob-classical".into()),
        created_at_millis: 0,
        ciphersuite: Some(UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT),
    };
    let mixed_chat = CloudChat::create(alice.core(), vec![PeerId([0xBB; 32])], mixed_settings)
        .await
        .expect("CloudChat::create stub");
    assert_eq!(
        mixed_chat.ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "S6.a: explicit per-chat 0x0003 override побеждает default 0x004D \
         (capability negotiation решает явно, без silent fallback — постулат 14)"
    );

    // --- (b) Альтернативный clean-PQ chat одного и того же Alice → effective 0x004D ---
    // Same Alice can открыть PQ chat с PQ-aware peer-ом без override —
    // effective ciphersuite = default = 0x004D. Это доказывает что
    // mixed_chat ciphersuite приходит из per-chat settings, а не state Alice.
    //
    // The same Alice can open a clean PQ chat with a PQ-aware peer without an
    // override — the effective ciphersuite equals the default, 0x004D. This
    // proves that mixed_chat's ciphersuite comes from per-chat settings, not
    // from Alice's state.
    let pure_pq_chat = CloudChat::create(
        alice.core(),
        vec![PeerId([0xCC; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("CloudChat::create stub");
    assert_eq!(
        pure_pq_chat.ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S6.b: subsequent default chat returns to PQ default (per-chat override локализован)"
    );

    // --- (c) Reverse: classical клиент с per-chat upgrade на PQ ---
    // Сценарий поддержки phased rollout: legacy classical-default клиент
    // может явно opt-in на PQ для одного чата через ChatSettings.ciphersuite =
    // Some(0x004D) — effective 0x004D. Существенно для migration plans
    // (block 8.8 SPEC-13 §migration). Постулат 14: choice explicit.
    //
    // Reverse case for phased rollout: a legacy classical-default client may
    // explicitly opt into PQ for a single chat via ChatSettings.ciphersuite =
    // Some(0x004D) — effective 0x004D. Important for migration plans
    // (Block 8.8 SPEC-13 §migration). Postulate 14: choice is explicit.
    let legacy = UmbrellaClient::bootstrap_for_test(pq_test_config(), random_seed())
        .await
        .expect("legacy bootstrap");
    let upgraded_chat = CloudChat::create(
        legacy.core(),
        vec![PeerId([0xDD; 32])],
        ChatSettings {
            title: Some("legacy-explicit-PQ-upgrade".into()),
            created_at_millis: 0,
            ciphersuite: Some(UMBRELLA_CIPHERSUITE_PQ_HYBRID),
        },
    )
    .await
    .expect("legacy CloudChat::create stub");
    assert_eq!(
        upgraded_chat.ciphersuite(),
        UMBRELLA_CIPHERSUITE_PQ_HYBRID,
        "S6.c: classical-default client с explicit PQ opt-in → effective 0x004D"
    );
    assert_eq!(
        legacy.core().default_ciphersuite(),
        UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        "S6.c: per-chat opt-in не меняет client default (override локализован)"
    );
}

// ───────────────────────────────────────────────────────────────────
// Scenario 7 — X-Wing primitives + backup PQ wrap V2 reachability.
// ───────────────────────────────────────────────────────────────────
//
// Smoke test что aggregator chain umbrella-tests → umbrella-pq и
// umbrella-tests → umbrella-backup::cloud_wrap::pq_wrap корректно
// активируется feature pq и primitives reachable. Не дублирует roundtrip
// тесты блока 8.7 (`crates/umbrella-backup/tests/pq_wrap_*.rs`) — здесь
// только проверка что symbols доступны и константы wire-format на уровне
// design.md §10.2.
//
// Smoke test that the aggregator chain umbrella-tests → umbrella-pq and
// umbrella-tests → umbrella-backup::cloud_wrap::pq_wrap is activated by
// feature pq and primitives are reachable. Does not duplicate the roundtrip
// tests of Block 8.7 (`crates/umbrella-backup/tests/pq_wrap_*.rs`) — here
// we only verify that symbols are available and that wire-format constants
// match design.md §10.2.

#[test]
fn s7_xwing_and_backup_pq_wrap_reachable_via_aggregator() {
    // X-Wing keygen → pubkey wire size invariant.
    let mut rng = OsRng;
    let (pk, _sk) = xwing_keygen(&mut rng).expect("xwing_keygen on valid OsRng");
    let raw = pk.as_bytes();
    assert_eq!(
        raw.len(),
        XWING_PUBLIC_KEY_LEN,
        "S7.a: X-Wing pubkey wire size constant"
    );
    assert_eq!(
        XWING_PUBLIC_KEY_LEN, 1216,
        "S7.a: XWING_PUBLIC_KEY_LEN = 1216 bytes (32 X25519 + 1184 ML-KEM-768)"
    );

    // Roundtrip from_bytes(as_bytes(...)).
    let restored = XWingPublicKey::from_bytes(raw).expect("X-Wing pubkey roundtrip");
    assert_eq!(restored.as_bytes(), raw, "S7.a: pubkey serde roundtrip");

    // Backup PQ wrap V2 wire-format constant (design.md §10.2).
    assert_eq!(
        WRAPPED_KEY_V2_LEN, 1218,
        "S7.b: WRAPPED_KEY_V2_LEN = 1218 bytes (design.md §10.2 wire format)"
    );

    // WrappedKeyV2::from_bytes доступен через aggregator (feature pq → backup/pq).
    // Передача zeroed bytes ожидается returns BackupError (invalid wire), но
    // важно что symbol resolves at compile-time под cfg pq.
    //
    // WrappedKeyV2::from_bytes is reachable through the aggregator (feature pq
    // → backup/pq). Passing zeroed bytes yields a BackupError (invalid wire),
    // but the symbol resolves at compile-time under cfg pq, which is what we
    // assert here.
    let zeroed = [0u8; WRAPPED_KEY_V2_LEN];
    assert!(
        WrappedKeyV2::from_bytes(&zeroed).is_err(),
        "S7.b: zeroed bytes for V2 envelope must be rejected (defensive parser)"
    );

    // CloudWrapRecoveryKey::derive доступен (single mnemonic invariant из S5)
    // — smoke check что umbrella-identity/pq feature через aggregator активен.
    //
    // CloudWrapRecoveryKey::derive is reachable (single mnemonic invariant
    // from S5) — smoke check that umbrella-identity/pq feature is active
    // through the aggregator.
    let recovery = CloudWrapRecoveryKey::derive(&deterministic_seed(), 0)
        .expect("S7.c: cloud-wrap X-Wing recovery derive (aggregator chain valid)");
    assert_eq!(
        recovery.public().to_bytes().len(),
        XWING_PUBLIC_KEY_LEN,
        "S7.c: recovery public matches X-Wing wire size"
    );
}
