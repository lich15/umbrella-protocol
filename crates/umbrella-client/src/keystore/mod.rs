//! Persistent KeyStore для hardware-backed identity/device ключей (через native
//! bridge в Блоках 7.8/7.9) + локальные метаданные в SQLite с per-row
//! application-level ChaCha20-Poly1305 encryption (ADR-010 Решение 5,
//! подвариант C.1.2).
//!
//! Persistent KeyStore for hardware-backed identity/device keys (native bridge
//! in Blocks 7.8/7.9) + local metadata in SQLite with application-level
//! per-row ChaCha20-Poly1305 encryption (ADR-010 Decision 5, subvariant C.1.2).
//!
//! # Round-5 closure additions
//!
//! - `hw_callback`: `PersistentKeyStoreCallback` trait + `MockHwKeystore` —
//!   Component 1 of the round-5 device-capture closure (F-PHD-DC-R7-1 +
//!   F-PHD-DC-R10-1).

pub mod distributed_identity_client;
pub mod hw_backed;
pub mod hw_callback;
pub mod migrations;
pub mod row_cipher;
pub mod schema;
pub mod sqlite_store;
pub mod trait_def;

#[doc(inline)]
pub use hw_backed::HwBackedKeyStore;
#[doc(inline)]
pub use hw_callback::{
    bootstrap_hw_identity, HwKeyHandle, HwKeystoreError, MockHwKeystore,
    PersistentKeyStoreCallback,
};
#[doc(inline)]
pub use row_cipher::RowCipher;
#[doc(inline)]
pub use sqlite_store::{SqliteMetadataStore, SqliteStoreConfig, StoredMessage};
#[doc(inline)]
pub use trait_def::{BootstrappedIdentity, KeyStoreError, PersistentKeyStore};
