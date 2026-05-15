//! SQLite metadata store: connection-pool'ированный `rusqlite` +
//! application-level per-row encryption через [`super::RowCipher`].
//!
//! # Почему r2d2 (не single `Mutex<Connection>`)
//!
//! - SQLite лучше всего работает в WAL-режиме с несколькими
//!   connection'ами: одно write + N reads параллельно без блокировок.
//!   Single `Mutex<Connection>` serial'изует всё чтение-на-запись.
//! - tokio задачи могут параллельно hit'ить store; r2d2 pool блокирует
//!   только при exhaustion, не на каждый запрос.
//!
//! # Синхронный API (Блок 7.3)
//!
//! В Блоке 7.3 store exposed sync (`put_message` / `fetch_messages`).
//! В Блоке 7.4 planned обернуть в `tokio::task::spawn_blocking` внутри
//! фасадов чтобы не блокировать tokio runtime на disk I/O.
//!
//! SQLite metadata store: pooled `rusqlite` + application-level per-row
//! encryption via [`super::RowCipher`].
//!
//! # Why r2d2 (not a single `Mutex<Connection>`)
//!
//! - SQLite performs best in WAL mode with multiple connections: one
//!   writer + N readers in parallel without locking. A single
//!   `Mutex<Connection>` serializes all read-on-write.
//! - Tokio tasks may hit the store in parallel; an r2d2 pool blocks only
//!   on exhaustion, not per request.
//!
//! # Synchronous API (Block 7.3)
//!
//! Block 7.3 exposes the store synchronously (`put_message` /
//! `fetch_messages`). Block 7.4 plans to wrap it in
//! `tokio::task::spawn_blocking` inside facades so the tokio runtime is
//! not blocked on disk I/O.

use std::path::PathBuf;
use std::sync::Arc;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

use crate::error::ClientError;
use crate::keystore::migrations::apply_migrations;
use crate::keystore::row_cipher::RowCipher;

/// Config для [`SqliteMetadataStore`]. Значения по умолчанию подходят для
/// unit-тестов (in-memory `:memory:` + pool size 4).
///
/// Config for [`SqliteMetadataStore`]. Defaults suit unit tests (in-memory
/// `:memory:` + pool size 4).
#[derive(Debug, Clone)]
pub struct SqliteStoreConfig {
    /// Path к SQLite файлу. В production — `~/Library/Application Support/
    /// UmbrellaX/state.db` (iOS) или `/data/data/xyz.umbrellax/databases/
    /// state.db` (Android), сконфигурируется из native app. В тестах —
    /// `NamedTempFile` или `:memory:`.
    ///
    /// Path to the SQLite file. Production: `~/Library/Application Support/
    /// UmbrellaX/state.db` (iOS) or `/data/data/xyz.umbrellax/databases/
    /// state.db` (Android), set by the native app. Tests: `NamedTempFile`
    /// or `:memory:`.
    pub db_path: PathBuf,

    /// Maximum connections в пуле. Default 4 — читатель + писатель + 2
    /// резерва для параллельных fetch из background tasks.
    ///
    /// Maximum connections in the pool. Default 4 — one writer + one
    /// reader + 2 spares for background parallel fetches.
    pub max_connections: u32,
}

impl Default for SqliteStoreConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from(":memory:"),
            max_connections: 4,
        }
    }
}

/// SQLite metadata store. Держит r2d2 `Pool<SqliteConnectionManager>` +
/// `Arc<RowCipher>` для encryption sensitive колонок.
///
/// Clone-able через `Arc<Self>` — несколько фасадов могут шарить один
/// store. Thread-safe: `Pool` Send+Sync; `Arc<RowCipher>` внутри Arc,
/// master-key в `SecretBox`.
///
/// SQLite metadata store. Holds an r2d2 `Pool<SqliteConnectionManager>` +
/// `Arc<RowCipher>` for encrypting sensitive columns.
///
/// Shareable via `Arc<Self>` — multiple facades can use a single store.
/// Thread-safe: `Pool` is Send+Sync; `Arc<RowCipher>` inside Arc,
/// master-key inside `SecretBox`.
pub struct SqliteMetadataStore {
    pool: Pool<SqliteConnectionManager>,
    cipher: Arc<RowCipher>,
}

impl SqliteMetadataStore {
    /// Открыть (или создать) store. Применяет migrations при первом
    /// открытии; идемпотентно на повторных. `master_key` — результат
    /// [`super::PersistentKeyStore::derive_storage_master_key`].
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Storage`] — r2d2 pool build / SQLite migration fail.
    ///
    /// Opens (or creates) the store. Applies migrations on first open;
    /// idempotent on subsequent opens. `master_key` comes from
    /// [`super::PersistentKeyStore::derive_storage_master_key`].
    ///
    /// # Errors
    ///
    /// - [`ClientError::Storage`] — r2d2 pool build / SQLite migration fail.
    pub fn open(config: SqliteStoreConfig, master_key: [u8; 32]) -> Result<Self, ClientError> {
        let manager = SqliteConnectionManager::file(&config.db_path);
        let pool = Pool::builder()
            .max_size(config.max_connections)
            .build(manager)
            .map_err(|e| ClientError::Storage(format!("r2d2 pool build: {e}")))?;

        {
            let conn = pool.get().map_err(|e| {
                ClientError::Storage(format!("r2d2 pool get (initial migration): {e}"))
            })?;
            apply_migrations(&conn)?;
        }

        Ok(Self {
            pool,
            cipher: Arc::new(RowCipher::new(master_key)),
        })
    }

    /// Сохранить сообщение. `text` шифруется через `RowCipher` с
    /// `context = "messages.text"` и `row_id = message_id`. Остальные
    /// колонки — plaintext (`chat_id`, `timestamp_ms`, `sender`).
    ///
    /// Если `message_id` уже существует — запись перезаписывается
    /// (`INSERT OR REPLACE`); это защищает от race condition когда две
    /// параллельные fetch inbox вернули одно и то же сообщение.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Storage`] — pool exhaustion / SQL I/O error /
    ///   AEAD encrypt.
    ///
    /// Stores a message. `text` is encrypted via `RowCipher` with
    /// `context = "messages.text"` and `row_id = message_id`. Other columns
    /// are plaintext (`chat_id`, `timestamp_ms`, `sender`).
    ///
    /// If `message_id` already exists, the row is overwritten
    /// (`INSERT OR REPLACE`); this protects against a race where two
    /// parallel inbox fetches return the same message.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Storage`] — pool exhaustion / SQL I/O / AEAD encrypt.
    pub fn put_message(
        &self,
        message_id: &[u8; 16],
        chat_id: &[u8; 32],
        timestamp_ms: u64,
        sender: &[u8; 32],
        text: &str,
    ) -> Result<(), ClientError> {
        let (ct, nonce, tag) =
            self.cipher
                .encrypt_row("messages.text", message_id, text.as_bytes())?;

        let conn = self
            .pool
            .get()
            .map_err(|e| ClientError::Storage(format!("r2d2 get (put_message): {e}")))?;
        // Note: `timestamp_ms as i64` — SQLite integer is signed 64-bit; u64
        // values > i64::MAX would wrap. Для realistic Unix-ms (years ≤ 292M)
        // безопасно.
        // `timestamp_ms as i64` — SQLite's INTEGER is signed 64-bit; u64
        // values above i64::MAX would wrap. Safe for realistic Unix-ms
        // timestamps (≤ 292M years).
        conn.execute(
            "INSERT OR REPLACE INTO messages
                (message_id, chat_id, timestamp_ms, sender, enc_text, enc_nonce, enc_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message_id.as_slice(),
                chat_id.as_slice(),
                timestamp_ms as i64,
                sender.as_slice(),
                ct,
                nonce.as_slice(),
                tag.as_slice()
            ],
        )
        .map_err(|e| ClientError::Storage(format!("insert message: {e}")))?;
        Ok(())
    }

    /// Прочитать `limit` последних сообщений чата (DESC timestamp).
    /// Расшифровывает `enc_text` через `RowCipher`. Если decrypt любого из
    /// сообщений падает — возвращает ошибку (обычно сигнал tampering или
    /// неверного master-ключа).
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Storage`] — SQL I/O / AEAD decrypt fail / UTF-8
    ///   decode fail.
    ///
    /// Reads up to `limit` most-recent chat messages (DESC timestamp).
    /// Decrypts `enc_text` via `RowCipher`. If decryption of any single
    /// message fails, returns an error (typically signaling tampering or a
    /// wrong master-key).
    ///
    /// # Errors
    ///
    /// - [`ClientError::Storage`] — SQL I/O / AEAD decrypt / UTF-8 decode.
    pub fn fetch_messages(
        &self,
        chat_id: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<StoredMessage>, ClientError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ClientError::Storage(format!("r2d2 get (fetch_messages): {e}")))?;
        let mut stmt = conn
            .prepare(
                "SELECT message_id, timestamp_ms, sender, enc_text, enc_nonce, enc_tag
                 FROM messages
                 WHERE chat_id = ?1
                 ORDER BY timestamp_ms DESC
                 LIMIT ?2",
            )
            .map_err(|e| ClientError::Storage(format!("prepare fetch_messages: {e}")))?;

        let rows = stmt
            .query_map(params![chat_id.as_slice(), limit], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(|e| ClientError::Storage(format!("query_map fetch_messages: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (mid, ts, sender, enc_text, enc_nonce, enc_tag) =
                row.map_err(|e| ClientError::Storage(format!("row iter: {e}")))?;

            let mid_arr = fixed_array::<16>(&mid, "message_id")?;
            let nonce_arr = fixed_array::<12>(&enc_nonce, "enc_nonce")?;
            let tag_arr = fixed_array::<16>(&enc_tag, "enc_tag")?;
            let sender_arr = fixed_array::<32>(&sender, "sender")?;

            let text_bytes = self.cipher.decrypt_row(
                "messages.text",
                &mid_arr,
                &enc_text,
                nonce_arr,
                tag_arr,
            )?;
            let text = String::from_utf8(text_bytes)
                .map_err(|e| ClientError::Storage(format!("utf-8 decode text: {e}")))?;

            out.push(StoredMessage {
                message_id: mid_arr,
                timestamp_ms: ts as u64,
                sender: sender_arr,
                text,
            });
        }
        Ok(out)
    }

    /// Копия `Arc<RowCipher>` — для внутренних модулей keystore,
    /// которые будут добавлены в Блоках 7.3+ (kt_log_mirror, mls_groups
    /// operations), чтобы не создавать multiple RowCipher на один
    /// master-key.
    ///
    /// Clone of `Arc<RowCipher>` — used by other keystore modules added in
    /// later blocks (kt_log_mirror, mls_groups operations) so multiple
    /// RowCipher instances aren't created per master-key.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn cipher(&self) -> Arc<RowCipher> {
        self.cipher.clone()
    }
}

/// Одно расшифрованное сообщение, возвращается из `fetch_messages`.
///
/// One decrypted message returned from `fetch_messages`.
#[derive(Clone)]
pub struct StoredMessage {
    /// 16-байтовый opaque message identifier.
    /// 16-byte opaque message identifier.
    pub message_id: [u8; 16],
    /// Unix-timestamp (ms) по часам отправителя.
    /// Unix-timestamp (ms) on the sender's clock.
    pub timestamp_ms: u64,
    /// Идентичность отправителя — Ed25519 identity_pubkey (32 байта).
    /// Sender identity — Ed25519 identity_pubkey (32 bytes).
    pub sender: [u8; 32],
    /// Plaintext (УТФ-8) сообщения после AEAD decrypt.
    /// Plaintext (UTF-8) message after AEAD decrypt.
    pub text: String,
}

/// `Debug` не печатает plaintext из локального хранилища.
/// `Debug` never prints plaintext loaded from local storage.
impl core::fmt::Debug for StoredMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredMessage")
            .field("message_id", &self.message_id)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("sender", &self.sender)
            .field("text_len", &self.text.len())
            .field("text", &"<redacted>")
            .finish()
    }
}

/// Вспомогательное преобразование `Vec<u8>` → `[u8; N]` с ошибкой если
/// длина не совпадает. Ошибка → [`ClientError::Storage`] с контекстом
/// имени колонки — упрощает диагностику при повреждении БД.
///
/// Helper `Vec<u8>` → `[u8; N]` with an error on length mismatch. The
/// error maps to [`ClientError::Storage`] carrying the column name — eases
/// diagnostics on DB corruption.
fn fixed_array<const N: usize>(src: &[u8], name: &str) -> Result<[u8; N], ClientError> {
    let arr: [u8; N] = src.try_into().map_err(|_| {
        ClientError::Storage(format!(
            "unexpected {} length: got {} bytes, expected {}",
            name,
            src.len(),
            N
        ))
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_message_debug_redacts_plaintext() {
        let msg = StoredMessage {
            message_id: [1u8; 16],
            timestamp_ms: 1_700_000_000_000,
            sender: [2u8; 32],
            text: "private-sqlite-secret".to_string(),
        };

        let debug = format!("{msg:?}");

        assert!(
            !debug.contains("private-sqlite-secret"),
            "Debug output must not leak decrypted stored message text: {debug}"
        );
        assert!(
            debug.contains("text_len"),
            "Debug output should keep text length metadata for diagnostics: {debug}"
        );
    }
}
