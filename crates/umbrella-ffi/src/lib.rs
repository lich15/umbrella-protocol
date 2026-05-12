//! uniffi FFI слой UmbrellaX. ABI-stable типы для Swift + Kotlin биндингов
//! через uniffi 0.28+ proc-macro подход (ADR-010 Решение 2). Async-методы
//! через tokio runtime (Решение 3).
//!
//! # Структура
//!
//! - [`error::UmbrellaError`] — flat-error enum (Решение 6, ABI-stable).
//! - [`types`] — uniffi `Records`: [`types::ChatIdFfi`], [`types::PeerIdFfi`],
//!   [`types::MessageFfi`], [`types::CallPolicyFfi`].
//! - [`export`] — uniffi `Objects`:
//!   [`export::UmbrellaClientHandle`] (top-level entry),
//!   [`export::CloudChatHandle`] (Cloud-режим, full method set),
//!   [`export::SecretChatHandle`] (Secret-режим, БЕЗ Cloud-only методов —
//!   ADR-006 Вариант C на FFI уровне),
//!   [`export::CallSessionHandle`] (1-1 звонок, basic methods в Блоке 7.7;
//!   полный lifecycle в Блоке 7.10).
//!
//! # Сборка биндингов
//!
//! Swift binding — крейт `umbrella-ffi-swift` (Блок 7.8): XCFramework через
//! `uniffi-bindgen swift`. Kotlin binding — крейт `umbrella-ffi-kotlin`
//! (Блок 7.9): AAR через `uniffi-bindgen kotlin`.
//!
//! uniffi FFI layer for UmbrellaX. ABI-stable types for Swift + Kotlin
//! bindings via the uniffi 0.28+ proc-macro approach (ADR-010 Decision 2).
//! Async methods through the tokio runtime (Decision 3).
//!
//! # Layout
//!
//! - [`error::UmbrellaError`] — flat-error enum (Decision 6, ABI-stable).
//! - [`types`] — uniffi `Records`: [`types::ChatIdFfi`], [`types::PeerIdFfi`],
//!   [`types::MessageFfi`], [`types::CallPolicyFfi`].
//! - [`export`] — uniffi `Objects`:
//!   [`export::UmbrellaClientHandle`] (top-level entry),
//!   [`export::CloudChatHandle`] (Cloud mode, full method set),
//!   [`export::SecretChatHandle`] (Secret mode, no Cloud-only methods —
//!   ADR-006 Variant C at FFI),
//!   [`export::CallSessionHandle`] (1-1 call, basic methods in Block 7.7;
//!   full lifecycle in Block 7.10).
//!
//! # Building bindings
//!
//! Swift binding — crate `umbrella-ffi-swift` (Block 7.8): XCFramework via
//! `uniffi-bindgen swift`. Kotlin binding — crate `umbrella-ffi-kotlin`
//! (Block 7.9): AAR via `uniffi-bindgen kotlin`.

#![warn(missing_docs)]

pub mod error;
pub mod export;
pub mod types;

pub use error::UmbrellaError;
pub use export::{
    CallSessionHandle, CallStateFfi, ClientConfigFfi, CloudChatHandle, SecretChatHandle,
    UmbrellaClientHandle,
};
pub use types::{CallPolicyFfi, ChatIdFfi, MessageFfi, PeerIdFfi};

/// Маркер сборки. Обновляется при каждом мажорном изменении FFI ABI.
///
/// Build marker. Updated on every major FFI ABI revision.
pub const BUILD_MARKER: &str = "umbrella-ffi stage-7.7 uniffi-handles";

// Scaffolding setup для uniffi 0.28+ proc-macro mode (ADR-010 Решение 2).
// Один вызов на crate; UDL не используется.
//
// Scaffolding setup for uniffi 0.28+ proc-macro mode (ADR-010 Decision 2).
// Single per-crate call; no UDL.
uniffi::setup_scaffolding!();
