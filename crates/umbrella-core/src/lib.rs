//! Базовые типы и контракты Umbrella Protocol без крипто-зависимостей.
//! Base types and contracts of the Umbrella Protocol, free of crypto deps.
//!
//! Этот крейт содержит только newtypes и errors. Он не зависит от ни одной
//! криптографической библиотеки и может быть импортирован серверной
//! и клиентской частью без риска случайно затащить приватные ключи.
//!
//! This crate contains only newtypes and errors. It has no cryptographic
//! dependencies and can be imported by both server and client sides without
//! risk of accidentally pulling in private keys.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod ids;

pub use error::{CoreError, Result};
pub use ids::{DeviceId, EpochId, MessageId, UserId};
