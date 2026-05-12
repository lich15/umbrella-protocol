//! OpenMLS crypto-провайдеры Umbrella Protocol — classical и hybrid PQ.
//! OpenMLS crypto providers for Umbrella Protocol — classical and hybrid PQ.
//!
//! Этот модуль экспортирует две модели провайдера:
//!
//! 1. **`UmbrellaProvider`** (всегда compiled) — type alias на `OpenMlsRustCrypto`,
//!    реализующий все классические MLS ciphersuites (0x0001/0x0003/0x0004/0x0006).
//!    Используется по умолчанию во всех existing 0.0.11 code paths.
//!
//! 2. **`UmbrellaXWingProvider`** (только под feature `pq`) — кастомный provider,
//!    добавляющий поддержку MLS ciphersuite 0x004D
//!    (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`). Делегирует не-X-Wing
//!    операции в `OpenMlsRustCrypto`, X-Wing branch (HPKE base mode RFC 9180 §5.1
//!    поверх DHKEM(X-Wing) + HKDF-SHA256 + ChaCha20-Poly1305) реализует сам через
//!    `umbrella_pq::xwing::*` (`libcrux-kem 0.0.7` upstream API name
//!    `Algorithm::XWingKemDraft06`, checked against draft-10 KAT).
//!
//! ## Почему два провайдера, а не conditional alias
//!
//! `openmls_rust_crypto-0.5.1` имеет `unimplemented!()` для
//! `HpkeKemType::XWingKemDraft6` (`provider.rs:61-63`). Любая попытка
//! использовать ciphersuite 0x004D через стандартный `OpenMlsRustCrypto` —
//! runtime panic, нарушение постулата 14. Без feature `pq` мы НЕ декларируем
//! 0x004D в `Capabilities` (см. `caps.rs`), поэтому panic не воспроизводим. С
//! feature `pq` декларируем, но операции через `UmbrellaXWingProvider`, который
//! имеет свой X-Wing branch — никаких unimplemented!() / panic.
//!
//! Явный type-level выбор провайдера (вместо implicit conditional alias)
//! защищает от случайного смешивания: client с feature `pq` может per-call
//! выбирать classical (`UmbrellaProvider`) для performance-критичного secret chat
//! и `UmbrellaXWingProvider` для long-lived cloud chat где h-n-d-l резистентность
//! приоритет.
//!
//! ## Forward compat при upstream X-Wing support
//!
//! Когда openmls 0.9+ или openmls_rust_crypto 0.6+ добавит native X-Wing
//! impl, `UmbrellaXWingProvider` становится removable: `mod xwing` удаляется
//! целиком, `UmbrellaProvider` (alias на новую `OpenMlsRustCrypto`) автоматически
//! поддерживает 0x004D. Downstream никаких изменений (provider — implementation
//! detail; группа создаётся через `&impl OpenMlsProvider`).
//!
//! ## Why two providers, not a conditional alias
//!
//! `openmls_rust_crypto-0.5.1` has `unimplemented!()` for
//! `HpkeKemType::XWingKemDraft6` (`provider.rs:61-63`). Any attempt to use
//! ciphersuite 0x004D through the stock `OpenMlsRustCrypto` is a runtime panic
//! — postulate 14 violation. Without feature `pq` we do NOT declare 0x004D in
//! `Capabilities` (see `caps.rs`), so the panic is unreachable. With feature
//! `pq` we declare it, but the operations go through `UmbrellaXWingProvider`
//! which has its own X-Wing branch — no unimplemented!() / panic.
//!
//! Explicit type-level provider selection (instead of an implicit conditional
//! alias) prevents accidental mixing: a client with feature `pq` can choose
//! classical (`UmbrellaProvider`) per-call for performance-critical secret chat
//! and `UmbrellaXWingProvider` for long-lived cloud chats where h-n-d-l
//! resistance is the priority.
//!
//! ## Forward compatibility on upstream X-Wing support
//!
//! Once openmls 0.9+ or openmls_rust_crypto 0.6+ ships native X-Wing,
//! `UmbrellaXWingProvider` becomes removable: `mod xwing` is dropped entirely,
//! `UmbrellaProvider` (alias to the new `OpenMlsRustCrypto`) automatically
//! supports 0x004D. Downstream code is unaffected (the provider is an
//! implementation detail; groups are created via `&impl OpenMlsProvider`).

use openmls_rust_crypto::OpenMlsRustCrypto;

#[cfg(feature = "pq")]
pub mod xwing;

#[cfg(feature = "pq")]
pub use xwing::UmbrellaXWingProvider;

/// Дефолтный провайдер для Umbrella Protocol — RustCrypto AEAD/HPKE/Hash/Sig + memory storage.
/// Поддерживает classical ciphersuites 0x0001/0x0003/0x0004/0x0006. Для 0x004D X-Wing —
/// см. [`UmbrellaXWingProvider`] под feature `pq`.
///
/// **Production-нота:** это in-memory storage. Для долгоживущего state (epochs, group state)
/// нужна persistent storage реализация — будет добавлена в Этапе 2.2 как отдельный backend.
///
/// Default provider for Umbrella Protocol — RustCrypto AEAD/HPKE/Hash/Sig + memory storage.
/// Supports classical ciphersuites 0x0001/0x0003/0x0004/0x0006. For 0x004D X-Wing see
/// [`UmbrellaXWingProvider`] under feature `pq`.
///
/// **Production note:** this uses in-memory storage. For long-lived state (epochs, group
/// state) a persistent storage implementation is required — added in Stage 2.2 as a separate
/// backend.
pub type UmbrellaProvider = OpenMlsRustCrypto;
