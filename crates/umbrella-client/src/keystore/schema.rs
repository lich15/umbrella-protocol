//! SQL schema локального metadata-store (SPEC-12 §B.4 + ADR-010 Решение 5).
//!
//! Все поля с sensitive plaintext (text сообщений, display-name контактов,
//! state snapshot MLS-групп) хранятся зашифрованными через
//! [`super::RowCipher`] — в соответствующих колонках храним
//! `enc_payload/enc_nonce/enc_tag` вместо plaintext. Non-sensitive columns
//! (timestamps, chat_id, message_id, sender identity_pubkey) — plaintext,
//! т.к. они либо публичные (identity_pubkey в KT log), либо anti-correlation-
//! resistant (chat_id = 32 байта opaque, timestamp сам по себе не утекает
//! identity).
//!
//! SQL schema of the local metadata store (SPEC-12 §B.4 + ADR-010 Decision 5).
//!
//! All sensitive plaintext fields (message text, contact display name,
//! MLS-group state snapshots) are stored encrypted through
//! [`super::RowCipher`] — the columns hold `enc_payload/enc_nonce/enc_tag`
//! instead of plaintext. Non-sensitive columns (timestamps, chat_id,
//! message_id, sender identity_pubkey) are plaintext because they are
//! either public (identity_pubkey in KT log) or anti-correlation-resistant
//! (chat_id = 32-byte opaque; timestamps alone do not leak identity).

/// Schema version — bump при breaking change + добавить migration ветку в
/// `migrations.rs`. Матчится с [`NONCE_INFO_PREFIX`] в `row_cipher.rs` (при
/// пересмотре шифрования bump обоих одновременно).
///
/// [`NONCE_INFO_PREFIX`]: super::row_cipher
///
/// Schema version — bump on breaking change + add a branch in
/// `migrations.rs`. Kept in sync with `NONCE_INFO_PREFIX` (bump both when
/// revising encryption).
pub const SCHEMA_VERSION: u32 = 1;

/// SQL для создания всех таблиц + индексов. Идемпотентно
/// (`CREATE TABLE IF NOT EXISTS`) чтобы `apply_migrations` мог запускаться
/// многократно без эффекта.
///
/// SQL to create all tables + indexes. Idempotent (`CREATE TABLE IF NOT
/// EXISTS`) so `apply_migrations` can run repeatedly with no effect.
pub const CREATE_TABLES_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- KT log client-side mirror. device_pubkey — PK (Ed25519).
-- KT log client-side mirror. device_pubkey — PK (Ed25519).
CREATE TABLE IF NOT EXISTS kt_log_mirror (
    device_pubkey            BLOB PRIMARY KEY,  -- 32 bytes Ed25519 public
    entry_state              INTEGER NOT NULL,  -- 0 Pending, 1 Active, 2 Revoked, 3 BootstrapActive
    authorized_since_millis  INTEGER NOT NULL,
    history_cutoff_millis    INTEGER NOT NULL,
    identity_pubkey          BLOB NOT NULL,     -- identity_pubkey at time of publish
    enc_payload              BLOB NOT NULL,     -- encrypted auxiliary state
    enc_nonce                BLOB NOT NULL,     -- 12 bytes
    enc_tag                  BLOB NOT NULL      -- 16 bytes
);

-- Snapshot'ы MLS-групп (openmls serialized state). chat_id = MLS group_id.
-- MLS group state snapshots (openmls serialized). chat_id = MLS group_id.
CREATE TABLE IF NOT EXISTS mls_groups (
    chat_id            BLOB PRIMARY KEY,        -- 32 bytes
    snapshot_version   INTEGER NOT NULL,
    enc_payload        BLOB NOT NULL,           -- encrypted openmls group state
    enc_nonce          BLOB NOT NULL,
    enc_tag            BLOB NOT NULL,
    last_epoch         INTEGER NOT NULL,
    updated_at_millis  INTEGER NOT NULL
);

-- История сообщений (Secret-режим хранит здесь; Cloud-режим читает
-- через Sealed Servers unwrap и может не persist'ить — но этот store
-- работает в обоих режимах).
-- Message history (Secret mode stores here; Cloud mode reads via Sealed
-- Servers unwrap and may skip persistence — this store handles both).
CREATE TABLE IF NOT EXISTS messages (
    message_id    BLOB PRIMARY KEY,             -- 16 bytes (UUID-like)
    chat_id       BLOB NOT NULL,                -- 32 bytes
    timestamp_ms  INTEGER NOT NULL,             -- sender-clock ms since epoch
    sender        BLOB NOT NULL,                -- sender identity_pubkey (32 bytes)
    enc_text      BLOB NOT NULL,                -- encrypted plaintext
    enc_nonce     BLOB NOT NULL,                -- 12 bytes
    enc_tag       BLOB NOT NULL                 -- 16 bytes
);

-- Covering index для DESC timestamp lookup `fetch_messages`.
-- Covering index for the DESC-timestamp `fetch_messages` lookup.
CREATE INDEX IF NOT EXISTS idx_messages_chat_ts
    ON messages(chat_id, timestamp_ms DESC);

-- Адресная книга. oprf_label — deterministic через VOPRF (SPEC-05).
-- Contact list. oprf_label — deterministic via VOPRF (SPEC-05).
CREATE TABLE IF NOT EXISTS contacts (
    oprf_label        BLOB PRIMARY KEY,         -- deterministic OPRF label
    identity_pubkey   BLOB NOT NULL,            -- Ed25519 pub (32 bytes)
    enc_display_name  BLOB NOT NULL,            -- encrypted user-provided name
    enc_nonce         BLOB NOT NULL,
    enc_tag           BLOB NOT NULL
);

-- Кеш DeviceAttestation'ов собеседников (wire bytes публичные; plaintext OK).
-- Cached peer DeviceAttestations (wire bytes are public; plaintext is fine).
CREATE TABLE IF NOT EXISTS device_attestations (
    peer_pubkey    BLOB NOT NULL,               -- peer identity_pubkey (32 bytes)
    device_index   INTEGER NOT NULL,            -- 0..=15
    attestation    BLOB NOT NULL,               -- DeviceAttestation wire bytes (public)
    fetched_at_ms  INTEGER NOT NULL,
    PRIMARY KEY (peer_pubkey, device_index)
);
"#;
