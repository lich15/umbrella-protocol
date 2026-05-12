//! Runtime smoke-тесты facade в Блоке 7.2. Проверяют что:
//!
//! 1. `UmbrellaClient::bootstrap_for_test` возвращает рабочий `ClientCore` с
//!    in-memory stub транспортами.
//! 2. `CloudChat::create` / `SecretChat::create` и `open` не падают (stub
//!    реализации возвращают `ChatId([0u8; 32])` и `Ok(Self)`).
//! 3. `CloudChat::cloud_sync_history` существует runtime-wise (позитивный
//!    counterpart к `compile_fail` doctest в `facade/secret_chat.rs`).
//!
//! Реальная криптография (MLS create group, Cloud-wrap dispatch, sealed-
//! sender envelope, blind-postman delivery) появится в Блоке 7.4.
//!
//! Runtime smoke-tests for Block 7.2 facades. Verify that:
//!
//! 1. `UmbrellaClient::bootstrap_for_test` returns a working `ClientCore`
//!    wired to in-memory stub transports.
//! 2. `CloudChat::create` / `SecretChat::create` / `open` do not panic (stub
//!    impls return `ChatId([0u8; 32])` and `Ok(Self)`).
//! 3. `CloudChat::cloud_sync_history` exists at runtime (the positive
//!    counterpart to the `compile_fail` doctest in `facade/secret_chat.rs`).
//!
//! Real cryptography (MLS create group, Cloud-wrap dispatch, sealed-sender
//! envelope, blind-postman delivery) arrives in Block 7.4.

use rand::rngs::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatId, ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

/// Фиктивный `ClientConfig` с stub URL-ами. Реальные URL-ы приходят через
/// native app при bootstrap в Блоке 7.4+; stub использован только для того
/// чтобы `ClientCore` имел все необходимые поля заполненными.
///
/// Dummy `ClientConfig` with stub URLs. Real URLs come from the native app at
/// bootstrap (Block 7.4+); the stub here just ensures every `ClientCore`
/// field is populated.
fn test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://stub-postman:8080".into(),
        kt_url: "http://stub-kt:8080".into(),
        call_relay_url: "http://stub-call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
        },
        // Block 7.2 facade smoke tests — classical 0x0003 path только.
        // Block 7.2 facade smoke tests — classical 0x0003 path only.
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

/// Тестовый seed: CSPRNG (OsRng). В Блоке 7.2 `IdentitySeed::from_bytes` не
/// существует в API (план референсил несуществующий метод); используем
/// `IdentitySeed::generate` — стандартный путь bootstrap.
///
/// Test seed: CSPRNG (OsRng). `IdentitySeed::from_bytes` does not exist in
/// the API (the plan referenced a non-existent method); use
/// `IdentitySeed::generate` — the standard bootstrap path.
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

#[tokio::test]
async fn cloud_chat_create_open_roundtrip() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test must succeed on valid seed");

    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings {
            title: Some("test".into()),
            created_at_millis: 0,
            ciphersuite: None,
        },
    )
    .await
    .expect("CloudChat::create stub is infallible");

    // Stub `CloudChat::create` в Блоке 7.2 всегда возвращает ChatId([0u8; 32]).
    // В Блоке 7.4 это станет MLS group_id, и assertion изменится.
    assert_eq!(cloud.chat_id(), ChatId([0u8; 32]));

    // open должен работать для тех же stub chat_id'ов.
    let reopened = CloudChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("CloudChat::open stub is infallible");
    assert_eq!(reopened.chat_id(), ChatId([0u8; 32]));
}

#[tokio::test]
async fn secret_chat_create_open_roundtrip() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test must succeed on valid seed");

    let secret = SecretChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings {
            title: None,
            created_at_millis: 0,
            ciphersuite: None,
        },
    )
    .await
    .expect("SecretChat::create stub is infallible");
    assert_eq!(secret.chat_id(), ChatId([0u8; 32]));

    let reopened = SecretChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("SecretChat::open stub is infallible");
    assert_eq!(reopened.chat_id(), ChatId([0u8; 32]));
}

/// Позитивный runtime counterpart к `compile_fail` doctest-ам в
/// `facade/secret_chat.rs`: cloud-only методы существуют на `CloudChat`
/// и вызываются успешно (stub возвращает пустой `Vec`).
///
/// Positive runtime counterpart to the `compile_fail` doctests in
/// `facade/secret_chat.rs`: Cloud-only methods exist on `CloudChat` and
/// complete successfully (stub returns an empty `Vec`).
#[tokio::test]
async fn cloud_chat_cloud_only_methods_exist_at_runtime() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test must succeed on valid seed");

    let cloud = CloudChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("CloudChat::open stub is infallible");

    // cloud_sync_history: доступен только на CloudChat (ADR-006 Вариант C).
    let history = cloud
        .cloud_sync_history(None)
        .await
        .expect("cloud_sync_history stub returns Ok(empty)");
    assert!(history.is_empty(), "stub should return empty history vec");

    // add_bot: доступен только на CloudChat.
    cloud
        .add_bot([0u8; 32])
        .await
        .expect("add_bot stub is infallible");
}
