//! Простое schema versioning: читаем текущую версию из таблицы
//! `schema_version` и применяем `CREATE TABLE IF NOT EXISTS` заново
//! (идемпотентно). При будущих breaking changes в `schema.rs` нужно:
//!
//! 1. Bump `SCHEMA_VERSION` в `schema.rs`.
//! 2. Добавить ветку в `apply_migrations` с `ALTER TABLE` / `CREATE TABLE
//!    new_name + INSERT SELECT old + DROP old` для этой версии.
//! 3. Unit-test что migration применяется корректно к DB предыдущей
//!    версии.
//!
//! Simple schema versioning: we read the current version from the
//! `schema_version` table and (idempotently) re-apply `CREATE TABLE IF NOT
//! EXISTS`. For future breaking schema changes in `schema.rs`:
//!
//! 1. Bump `SCHEMA_VERSION` in `schema.rs`.
//! 2. Add a branch in `apply_migrations` with `ALTER TABLE` or `CREATE TABLE
//!    new_name + INSERT SELECT old + DROP old` for that version.
//! 3. Unit-test that the migration applies correctly to a prior-version DB.

use rusqlite::Connection;

use crate::error::ClientError;
use crate::keystore::schema::{CREATE_TABLES_SQL, SCHEMA_VERSION};

/// Применить schema migrations к SQLite connection. Идемпотентно:
/// многократный вызов на одном connection не даёт ошибок и не меняет
/// состояние БД.
///
/// Apply schema migrations to a SQLite connection. Idempotent: repeated
/// calls on the same connection succeed without changing DB state.
///
/// # Errors
///
/// - [`ClientError::Storage`] — SQLite I/O / syntax ошибка. Причина:
///   повреждённый файл БД или несовместимая SQLite версия (blocked
///   `bundled` feature rusqlite защищает от последнего, см.
///   `umbrella-client/Cargo.toml`).
///
/// # Errors
///
/// - [`ClientError::Storage`] — SQLite I/O / syntax error. Causes:
///   corrupted DB file or incompatible SQLite version (the latter is
///   blocked by `rusqlite`'s `bundled` feature — see
///   `umbrella-client/Cargo.toml`).
pub fn apply_migrations(conn: &Connection) -> Result<(), ClientError> {
    conn.execute_batch(CREATE_TABLES_SQL)
        .map_err(|e| ClientError::Storage(format!("create tables: {e}")))?;

    let current: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|e| ClientError::Storage(format!("read schema version: {e}")))?;

    if current < SCHEMA_VERSION {
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version) VALUES (?1)",
            [SCHEMA_VERSION],
        )
        .map_err(|e| ClientError::Storage(format!("update schema version: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_migrations_is_idempotent() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        apply_migrations(&conn).expect("first migration");
        apply_migrations(&conn).expect("second migration (idempotent)");
        apply_migrations(&conn).expect("third migration (idempotent)");

        let version: u32 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .expect("read version");
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn apply_migrations_creates_all_tables() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        apply_migrations(&conn).expect("migration");

        for table in &[
            "schema_version",
            "kt_log_mirror",
            "mls_groups",
            "messages",
            "contacts",
            "device_attestations",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .expect("query table count");
            assert_eq!(count, 1, "table {table} must exist after migration");
        }
    }
}
