//! Обёртка над openmls с жёсткой политикой ciphersuites: только Ed25519/Ed448.
//! Wrapper around openmls with strict ciphersuite policy: Ed25519/Ed448 only.
//!
//! Этот крейт предоставляет production-grade обвязку над `openmls` с гарантиями:
//!
//! - **Только Ed25519 / Ed448 ciphersuites.** ECDSA-based ciphersuites (P-256, P-384, P-521)
//!   запрещены на уровне типов как митигация ETK атаки (Cremers et al CISPA, eprint 2025/229):
//!   не-SUF-CMA подписи позволяют split-brain через signature malleability.
//! - **External operations отключены для приватных групп.** External Commits и External Proposals
//!   разрешены только для public broadcast каналов с PSK (см. private protocol overview §4).
//! - **Domain-separated transcripts.** Все наши надстройки (KT, Sealed Sender, attestation)
//!   используют явные labels.
//! - **Compile-time изоляция.** `umbrella-mls` депендит от `umbrella-identity` для credential
//!   binding; `umbrella-server-blind-postman` намеренно НЕ депендит — серверный код не имеет
//!   доступа к приватным ключам даже на уровне типов.
//!
//! This crate provides a production-grade wrapper around `openmls` with the following guarantees:
//!
//! - **Ed25519 / Ed448 ciphersuites only.** ECDSA-based ciphersuites (P-256, P-384, P-521) are
//!   forbidden at the type level as the ETK mitigation (Cremers et al CISPA, eprint 2025/229):
//!   non-SUF-CMA signatures enable split-brain via signature malleability.
//! - **External operations disabled for private groups.** External Commits and External Proposals
//!   are allowed only for public broadcast channels with a PSK (see private protocol overview §4).
//! - **Domain-separated transcripts.** All our extensions (KT, Sealed Sender, attestation) use
//!   explicit labels.
//! - **Compile-time isolation.** `umbrella-mls` depends on `umbrella-identity` for credential
//!   binding; `umbrella-server-blind-postman` deliberately does NOT — server-side code has no
//!   access to private keys even at the type level.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod caps;
pub mod ciphersuite;
pub mod credential;
pub mod error;
pub mod group;
pub mod group_policy;
pub mod key_package;
pub mod parser;
pub mod provider;
pub mod screenshot_policy;
pub mod signer;

pub use ciphersuite::{UmbrellaCiphersuite, UMBRELLA_DEFAULT_CIPHERSUITE};
pub use credential::{build_credential_for_device, build_credential_for_identity};
pub use error::{MlsError, Result};
pub use group::{IncomingMessage, MemberChangeOutcome, UmbrellaGroup, MAX_EXPORTER_LEN};
pub use group_policy::{GroupPolicy, KEY_PACKAGE_LIFETIME_SECS, PRIVATE_GROUP_MAX_LIFETIME_SECS};
pub use key_package::{build_device_key_package, UmbrellaKeyPackageBundle};
pub use parser::{
    parse_key_package_safe, parse_mls_message_safe, KEY_PACKAGE_MIN_BYTES, MLS_MESSAGE_MIN_BYTES,
};
pub use provider::UmbrellaProvider;
pub use signer::{UmbrellaDeviceSigner, UmbrellaIdentitySigner};
