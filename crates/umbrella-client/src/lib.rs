//! Высокоуровневый orchestration-фасад для клиентских приложений UmbrellaX.
//! Объединяет lifecycle: connection, queue management, session restore, retry.
//! API финализируется в Этапе 7 перед FFI-биндингами.
//!
//! High-level orchestration facade for UmbrellaX client applications.
//! Combines lifecycle: connection, queue management, session restore, retry.
//! The API is finalized in Stage 7 prior to the FFI bindings.
//!
//! # Архитектура (ADR-006 Вариант C)
//!
//! Экспонирует два type-safe фасадных типа:
//!
//! - [`CloudChat`] — Cloud-режим. Multi-device, боты, большие группы через
//!   threshold-wrap 3-of-5 Sealed Servers. История хранится на Почтальоне
//!   постоянно в зашифрованном виде; новое устройство получает её через
//!   штатный запрос к Sealed Servers.
//! - [`SecretChat`] — Secret-режим. Чистый MLS RFC 9420 без Sealed Servers.
//!   Потеря устройства без заранее подготовленного второго = потеря истории.
//!   Direct P2P звонки запрещены (SPEC-06 §3 compliance-gate).
//!
//! Попытка вызвать метод Cloud-режима (`cloud_sync_history`, `add_bot`) на
//! `SecretChat` — **compile error**, не runtime check.
//!
//! # Architecture (ADR-006 Variant C)
//!
//! Exports two type-safe facade types:
//!
//! - [`CloudChat`] — Cloud mode. Multi-device, bots, large groups via 3-of-5
//!   Sealed Servers threshold-wrap. History persists on Postman in encrypted
//!   form; a new device fetches it via the standard Sealed Servers request.
//! - [`SecretChat`] — Secret mode. Pure MLS RFC 9420 without Sealed Servers.
//!   Losing a device without a pre-paired second device = history is lost.
//!   Direct P2P calls forbidden at facade (SPEC-06 §3 compliance-gate).
//!
//! Calling a Cloud-mode method (`cloud_sync_history`, `add_bot`) on a
//! `SecretChat` yields a **compile error**, not a runtime check.
//!
//! # Layering
//!
//! ```text
//! umbrella-client (this crate)
//!   └─ facade::{CloudChat, SecretChat}   (ADR-006 Вариант C type-safe API)
//!   └─ core::ClientCore                  (shared state: identity, KT, transports)
//!   └─ transport::*                      (HTTP/2 clients, stubs in Block 7.2)
//!   ↓
//! umbrella-{mls,sealed-sender,padding,kt,oprf,sealed-sender,backup,calls}
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attestation;
pub mod call;
pub mod core;
pub mod error;
pub mod facade;
pub mod keystore;
pub mod lifecycle;
pub mod transport;

#[doc(inline)]
pub use crate::attestation::{
    seal_unwrap_request_with_async_attestation, AttestationError, AttestationProvider, Platform,
    PlatformAttestation, StaticTestAttestationProvider,
};
#[doc(inline)]
pub use crate::core::{ClientConfig, ClientCore, UmbrellaClient, DEFAULT_CIPHERSUITE};
#[doc(inline)]
pub use crate::error::{ClientError, Result};
#[doc(inline)]
pub use crate::facade::{CloudChat, SecretChat};

/// Маркер сборки: обновляется при каждом мажорном обновлении API фасадов.
/// Build marker: updated on every major facade API revision.
pub const BUILD_MARKER: &str = "umbrella-client stage-7 0.0.1";
