//! Локальные платформенные проверяющие Umbrella Protocol.
//! Local platform verifiers for Umbrella Protocol.
//!
//! Крейт проверяет только то, что можно честно проверить локально. Айос и
//! Андроид закрыто отказывают без полного trust material. Веб-путь проверяет
//! WebAuthn-подобное утверждение через сохранённый ключ.
//!
//! The crate verifies only what can be verified honestly on the local server.
//! iOS and Android fail closed without complete trust material. The web path
//! verifies a WebAuthn-like assertion with the stored credential key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod android;
pub mod apple;
pub mod error;
pub mod types;
pub mod web;

pub use android::{AndroidPlayIntegrityConfig, AndroidPlayIntegrityVerifier};
pub use apple::{AppleAppAttestConfig, AppleAppAttestEnvironment, AppleAppAttestVerifier};
pub use error::{PlatformVerifierError, Result};
pub use types::{
    validate_token_size, DevicePublicKey, PlatformKind, PlatformVerificationContext,
    PlatformVerifier, PlatformVerifierOutput, RegisteredPlatformKey, ServerNonce,
};
pub use web::WebAuthnVerifier;
