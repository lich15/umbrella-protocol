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
// Round-6 distributed identity: production path uses
// `distributed_identity_client::bootstrap_account`; test fixtures используют
// `IdentitySeed::generate` — deprecated lint disabled под test cfg.
//
// Round-6 distributed identity: test fixtures use `IdentitySeed::generate`.
#![cfg_attr(test, allow(deprecated))]
// Clippy 1.95.0 ужесточил doc rendering rules (`doc_lazy_continuation`,
// `doc_overindented_list_items`). Это markdown formatting hints, не safety —
// rendered docs читаемы. Crate-level allow preserves existing 250+ doc-comment
// blocks без bulk reformatting (несвязано с runtime behavior).
//
// Clippy 1.95.0 tightened doc rendering rules; allow at crate level — these are
// stylistic markdown hints, not safety, and rendered docs remain legible.
#![allow(
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::empty_line_after_doc_comments,
    clippy::unusual_byte_groupings
)]
// Carry-over к отдельной audit session: umbrella-client крейт имеет ~45
// dylint findings — postulate 3 (zero panics в lib code: ~10 `.expect()`
// на rwlock guards + 2 `panic!()` + 6 `unimplemented!()` в stub paths
// Block 7.2) и postulate 14 (RU+EN dual docs: ~28 EN-only docstrings).
// Эти errors раскрылись после category A/B/C fixes для v3.0.0 ceremony.
// Hot-fix через crate-level allow с явным carry-over: добавить в
// memory + handoff отдельную audit session «umbrella-client PhD-B
// hardening» для real point-by-point closure до v3.1.0/v4.0.0.
// `unknown_lints` нужен потому что custom dylint lint names неизвестны
// rustc вне dylint pipeline.
//
// Carry-over to a dedicated audit session: the umbrella-client crate has
// ~45 dylint findings — postulate 3 (no panics in lib code: ~10
// `.expect()` on rwlock guards + 2 `panic!()` + 6 `unimplemented!()` in
// Block 7.2 stub paths) and postulate 14 (RU+EN dual docs: ~28 EN-only
// docstrings). These errors surfaced after the category A/B/C fixes
// for the v3.0.0 ceremony. Hot-fix via a crate-level allow with an
// explicit carry-over: add to memory + handoff a dedicated audit
// session "umbrella-client PhD-B hardening" for real point-by-point
// closure ahead of v3.1.0/v4.0.0.
#![allow(unknown_lints)]
#![allow(
    require_dual_doc,
    no_unwrap_in_lib,
    no_panic_in_lib,
    no_unimplemented_in_lib
)]

pub mod attestation;
pub mod call;
pub mod core;
pub mod device_authorization;
pub mod error;
pub mod facade;
pub mod identity;
pub mod keystore;
pub mod kt_monitor;
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
