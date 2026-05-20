#![allow(deprecated)] // Round-6: test exercises legacy IdentitySeed::generate; production uses bootstrap_account
//! Stage 7 integration milestone — end-to-end scenarios, не требующие
//! реального hardware / live Umbrella server implementation services.
//!
//! ## Scope
//!
//! Rust-side часть 6-сценарного checklist'а Блока 7.10. Покрывает
//! workspace-level integration (все нижние крейты + umbrella-client facade).
//! Scenarios требующие real hardware (App Attest / Secure Enclave / real
//! TURN relay) или live backend services — в `examples/ios-harness/` и
//! `examples/android-harness/` под manual device checklist.
//!
//! | # | Scenario | Scope здесь | Где real E2E |
//! |---|---|---|---|
//! | 1 | Registration | bootstrap через [`UmbrellaClient::bootstrap_for_test`] | harness real device |
//! | 2 | Cloud messaging | CloudChat create/send/fetch API smoke | harness + live services |
//! | 3 | Secret messaging | SecretChat create/send API smoke | harness + live services |
//! | 4 | Secret call no-P2P | **уже покрыт** в `umbrella-client/tests/call_no_p2p.rs` property×128 | — |
//! | 5 | Multi-device bootstrap | — (требует QR + Noise_IK в реальной сети) | harness |
//! | 6 | Catastrophic recovery | rotated-identity derive roundtrip | harness |
//!
//! Scenario 4 не дублируется здесь — property × 128 compliance-gate test в
//! `crates/umbrella-client/tests/call_no_p2p.rs` уже работает на
//! workspace уровне с реальным webrtc-ice Agent + AgentConfig фильтрацией.
//!
//! Stage 7 integration milestone — end-to-end scenarios that don't require
//! real hardware or a live Umbrella server implementation backend. The Rust-side portion of
//! the Block 7.10 six-scenario checklist. Scenarios needing real hardware
//! (App Attest, Secure Enclave, real TURN) or live backend services live
//! in `examples/ios-harness/` and `examples/android-harness/` under the
//! manual device checklist.

use std::sync::Arc;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatId, ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{IdentityKey, IdentitySeed, MnemonicLanguage};

fn test_config() -> ClientConfig {
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
        // Этап 7 path — classical 0x0003. PQ-aware test_config_pq() живёт в
        // crates/umbrella-tests/tests/stage8_milestone.rs (cfg pq).
        // Stage 7 path — classical 0x0003. The PQ-aware test_config_pq() lives
        // in crates/umbrella-tests/tests/stage8_milestone.rs (cfg pq).
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

fn test_seed() -> IdentitySeed {
    use rand::rngs::OsRng;
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

/// Scenario 1 — bootstrap identity roundtrip.
#[tokio::test]
async fn scenario1_registration_bootstrap_succeeds() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test must succeed on a valid seed");
    assert!(Arc::strong_count(&client) >= 1);
    // core() — публичный entry point для facade — должен быть доступен.
    // core() — the public entry point for facades — must be reachable.
    let _core = client.core();
}

/// Scenario 2 — CloudChat create + send_text + fetch_inbox API reachable.
#[tokio::test]
async fn scenario2_cloud_chat_api_reachable() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap");
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([0xBB; 32])],
        ChatSettings {
            title: Some("scenario 2".into()),
            created_at_millis: 0,
            ciphersuite: None,
        },
    )
    .await
    .expect("CloudChat::create stub is infallible");

    let id = cloud
        .send_text("hello cloud".into())
        .await
        .expect("send_text stub");
    assert_eq!(id.0.len(), 16);

    let inbox = cloud.fetch_inbox().await.expect("fetch_inbox stub");
    // Stub inbox пуст в Блоке 7.2 — real inbox fetch через blind-postman-svc
    // появляется в Блоке 7.4 (live integration).
    assert!(inbox.is_empty());
}

/// Scenario 3 — SecretChat create + send_text API reachable (без
/// Sealed Servers, только blind-postman path).
#[tokio::test]
async fn scenario3_secret_chat_api_reachable() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap");
    let secret = SecretChat::create(
        client.core(),
        vec![PeerId([0xCC; 32])],
        ChatSettings {
            title: None,
            created_at_millis: 0,
            ciphersuite: None,
        },
    )
    .await
    .expect("SecretChat::create stub is infallible");

    let id = secret
        .send_text("hello secret".into())
        .await
        .expect("send_text stub");
    assert_eq!(id.0.len(), 16);
}

/// Scenario 4 — SecretChat no-P2P compliance-gate. **Уже** покрыт property
/// × 128 в `umbrella-client/tests/call_no_p2p.rs` на workspace уровне;
/// дублировать не имеет смысла. Ограничимся sanity-проверкой что
/// `SecretChat::open` доступен (facade accessibility через все слои).
#[tokio::test]
async fn scenario4_secret_chat_opener_accessible() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap");
    let _secret = SecretChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("SecretChat::open stub is infallible");
    // Compliance-gate (Relay-only ICE candidates) проверен в
    // crates/umbrella-client/tests/call_no_p2p.rs (property × 128 cases).
}

/// Scenario 5 — multi-device bootstrap. Полный flow требует QR +
/// Noise_IK snapshot через real network; на Rust-стороне проверяем что
/// типы доступны через facade: `ChatSettings` + `PeerId` составимы.
#[tokio::test]
async fn scenario5_multi_device_facade_types_constructible() {
    let _settings = ChatSettings {
        title: Some("multi-device".into()),
        created_at_millis: 0xDEAD_BEEF,
        ciphersuite: None,
    };
    let _peer = PeerId([0xAA; 32]);
    // Real multi-device bootstrap (QR generate + Noise_IK snapshot
    // transfer) выполняется в examples/{ios,android}-harness scenario 5.
}

/// Scenario 6 — catastrophic recovery: code-recovery 12 слов + 24-слова
/// identity seed → deterministic rotated identity material.
#[tokio::test]
async fn scenario6_catastrophic_recovery_rotated_identity_derive() {
    use umbrella_identity::code_recovery::{
        derive_rotated_identity_material, CodeRecoveryMnemonic,
    };

    let seed = test_seed();
    let old_identity = IdentityKey::derive(&seed, 0).expect("derive account=0");
    let old_pub = old_identity.public();

    // Официальный BIP-39 test vector — 12 слов 16-byte zero entropy:
    // "abandon × 11 about".
    // Official BIP-39 test vector — 12 words, 16-byte zero entropy:
    // "abandon × 11 about".
    let code = CodeRecoveryMnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon about",
        MnemonicLanguage::English,
    )
    .expect("official BIP-39 test vector");

    let rotated = derive_rotated_identity_material(&seed, &code, &old_pub)
        .expect("derive_rotated_identity_material");

    // Rotated seed deterministic — повторный вызов с теми же inputs даёт
    // то же значение.
    // Rotated seed is deterministic — another call with the same inputs
    // produces the same value.
    let rotated_again =
        derive_rotated_identity_material(&seed, &code, &old_pub).expect("rotation deterministic");
    assert_eq!(rotated.seed_bytes(), rotated_again.seed_bytes());

    // Rotated ≠ original identity seed (rotation не idempotent).
    // Rotated differs from the original identity seed (rotation is not
    // idempotent).
    assert_ne!(rotated.seed_bytes(), seed.seed());
}
