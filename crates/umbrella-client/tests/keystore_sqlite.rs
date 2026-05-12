//! Integration-тесты для `SqliteMetadataStore`. Проверяют:
//!
//! 1. Roundtrip put/fetch сообщений с корректным DESC сортировкой.
//! 2. Неверный master-ключ → decrypt fails (подтверждает per-row AEAD
//!    зависимость от master-key).
//! 3. `schema_version` записан после `apply_migrations`.
//!
//! Integration tests for `SqliteMetadataStore`. Verify:
//!
//! 1. Put/fetch roundtrip with correct DESC ordering.
//! 2. Wrong master-key → decrypt fails (confirms per-row AEAD dependence
//!    on master-key).
//! 3. `schema_version` is recorded after `apply_migrations`.

use rusqlite::Connection;
use tempfile::NamedTempFile;
use umbrella_client::keystore::{SqliteMetadataStore, SqliteStoreConfig};

#[test]
fn put_and_fetch_messages_roundtrip() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let store = SqliteMetadataStore::open(
        SqliteStoreConfig {
            db_path: tmp.path().to_path_buf(),
            max_connections: 2,
        },
        [0x07u8; 32],
    )
    .expect("open store");

    let chat_id = [0xAAu8; 32];
    let sender = [0xBBu8; 32];

    for i in 0..5u64 {
        let mut mid = [0u8; 16];
        mid[..8].copy_from_slice(&i.to_be_bytes());
        store
            .put_message(&mid, &chat_id, i * 1000, &sender, &format!("msg {i}"))
            .expect("put_message");
    }

    let msgs = store.fetch_messages(&chat_id, 10).expect("fetch_messages");
    assert_eq!(msgs.len(), 5, "5 messages inserted");
    // DESC timestamp — latest first.
    assert_eq!(msgs[0].text, "msg 4");
    assert_eq!(msgs[4].text, "msg 0");
    assert_eq!(msgs[0].sender, sender);
    assert_eq!(msgs[0].timestamp_ms, 4000);
}

#[test]
fn fetch_respects_limit() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let store = SqliteMetadataStore::open(
        SqliteStoreConfig {
            db_path: tmp.path().to_path_buf(),
            max_connections: 1,
        },
        [0x33u8; 32],
    )
    .expect("open store");

    let chat_id = [0xCCu8; 32];
    for i in 0..10u64 {
        let mut mid = [0u8; 16];
        mid[..8].copy_from_slice(&i.to_be_bytes());
        store
            .put_message(&mid, &chat_id, i, &[1u8; 32], "x")
            .expect("put_message");
    }

    let top3 = store.fetch_messages(&chat_id, 3).expect("fetch top 3");
    assert_eq!(top3.len(), 3);
}

#[test]
fn fetch_returns_empty_for_unknown_chat() {
    let store = SqliteMetadataStore::open(SqliteStoreConfig::default(), [0x01u8; 32])
        .expect("open in-memory store");
    let msgs = store
        .fetch_messages(&[0xFFu8; 32], 10)
        .expect("fetch_messages on empty");
    assert!(msgs.is_empty());
}

#[test]
fn different_master_key_fails_decrypt() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let chat_id = [0x22u8; 32];

    // Store под master-key A, записать сообщение.
    {
        let store = SqliteMetadataStore::open(
            SqliteStoreConfig {
                db_path: tmp.path().to_path_buf(),
                max_connections: 1,
            },
            [0x11u8; 32],
        )
        .expect("open with key A");
        store
            .put_message(&[1u8; 16], &chat_id, 100, &[3u8; 32], "secret")
            .expect("put secret");
    }

    // Открыть с master-key B — decrypt fails на fetch.
    let store_b = SqliteMetadataStore::open(
        SqliteStoreConfig {
            db_path: tmp.path().to_path_buf(),
            max_connections: 1,
        },
        [0x99u8; 32],
    )
    .expect("open with key B (migrations idempotent)");
    let result = store_b.fetch_messages(&chat_id, 10);
    assert!(
        result.is_err(),
        "decrypt with wrong master-key must fail, got {result:?}"
    );
}

#[test]
fn schema_version_recorded() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _store = SqliteMetadataStore::open(
        SqliteStoreConfig {
            db_path: tmp.path().to_path_buf(),
            max_connections: 1,
        },
        [0u8; 32],
    )
    .expect("open store");

    // Открываем тем же файлом напрямую через rusqlite чтобы прочитать version.
    let conn = Connection::open(tmp.path()).expect("reopen raw");
    let version: u32 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .expect("read schema version");
    assert_eq!(version, 1, "SCHEMA_VERSION constant matches");
}

#[test]
fn put_message_overwrites_on_duplicate_id() {
    let store = SqliteMetadataStore::open(SqliteStoreConfig::default(), [0x44u8; 32])
        .expect("open in-memory store");
    let mid = [0u8; 16];
    let chat = [0x55u8; 32];

    store
        .put_message(&mid, &chat, 100, &[1u8; 32], "first")
        .unwrap();
    store
        .put_message(&mid, &chat, 200, &[1u8; 32], "second")
        .unwrap();

    let msgs = store.fetch_messages(&chat, 10).expect("fetch");
    assert_eq!(msgs.len(), 1, "INSERT OR REPLACE collapses duplicates");
    assert_eq!(msgs[0].text, "second");
    assert_eq!(msgs[0].timestamp_ms, 200);
}
