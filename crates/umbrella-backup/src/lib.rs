//! Резервное копирование и восстановление идентичности и истории переписки.
//! Backup and recovery of identity and message history.
//!
//! Согласно ADR-006 крейт объединяет две независимые подсистемы, каждая
//! соответствует одному из двух продуктовых режимов UmbrellaX. Общая часть
//! (BIP-39 seed recovery) уже реализована в `umbrella-identity` (Этап 1);
//! данный крейт добавляет два mode-специфичных пути. Детальная спецификация —
//! в SPEC-12-BACKUP, архитектурное обоснование — в ADR-007.
//!
//! Per ADR-006 this crate combines two independent subsystems, one per
//! product mode of UmbrellaX. The common BIP-39 seed recovery path lives in
//! `umbrella-identity` (Stage 1); this crate adds two mode-specific paths.
//! Detailed spec — SPEC-12-BACKUP; architectural rationale — ADR-007.
//!
//! # Cloud-режим: threshold-HPKE через три из пяти Sealed Servers
//!
//! Модуль [`cloud_wrap`] реализует клиентскую сторону threshold-wrap
//! протокола: клиент-отправитель **локально** заворачивает одноразовый AEAD
//! -ключ сообщения под публично известный `Y = K · G` (Shamir 3-of-5 scalar
//! живёт в SEV-SNP enclaves Sealed Servers); клиент-получатель обращается
//! к трём Sealed Servers с `SignedUnwrapRequest`, получает partial shares
//! `k_i · R`, делает Lagrange combine на клиенте, разворачивает AEAD-ключ
//! через HKDF-SHA512 + ChaCha20-Poly1305.
//!
//! Cloud mode: client-side of a threshold-HPKE protocol. Sender wraps
//! locally under `Y = K · G`; recipient collects ≥ 3 partial shares via
//! `SignedUnwrapRequest`, combines them with Lagrange on client, derives
//! AEAD key via HKDF-SHA512 + ChaCha20-Poly1305.
//!
//! # Secret-режим: прямой перенос истории между устройствами (Этап 5.3)
//!
//! Модуль `device_transfer` (будет добавлен в под-этапе 5.3) реализует
//! QR-based handshake + Noise_IK_25519_ChaChaPoly_SHA512 через `snow`
//! для потоковой передачи MLS group state и локальной БД сообщений.
//!
//! Secret mode: `device_transfer` (added in Stage 5.3) implements QR-based
//! handshake + Noise_IK_25519_ChaChaPoly_SHA512 via `snow` for streaming
//! MLS group state and local message DB.
//!
//! # Что явно не бэкапится
//!
//! MLS ratchet state не попадает в облако ни в каком режиме: это сломало бы
//! forward secrecy. Локальная расшифрованная база сообщений попадает в
//! облако только в Cloud-режиме и только как часть Cloud message queue —
//! это инфраструктура вне крейта (`message-svc` Umbrella server implementation).
//!
//! MLS ratchet state is never backed up: that would break forward secrecy.
//! Decrypted local DB belongs to `message-svc` Umbrella server implementation for Cloud, or to
//! `device_transfer` stream for Secret.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cloud_wrap;
pub mod device_transfer;
pub mod error;
pub mod identity_adapters;

pub use error::{BackupError, Result};
