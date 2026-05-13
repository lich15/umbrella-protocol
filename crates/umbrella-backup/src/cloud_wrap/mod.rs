//! Клиентский threshold-HPKE wrap/unwrap для Cloud-режима.
//! Client-side threshold-HPKE wrap/unwrap for Cloud-mode.
//!
//! Обёртка одноразового AEAD-ключа сообщения под публично известный
//! `Y = K · G` (локально, без обращения к серверам) и разворот через
//! кооперацию ≥ 3 Sealed Servers с Lagrange combine на клиенте. Структурно
//! симметрично `umbrella-oprf` Этапа 4: те же примитивы (Ristretto255,
//! Shamir 3-of-5, Lagrange combine), тот же паттерн SignedRequest с
//! attestation и device-signature, та же `WitnessIndex` семантика.
//!
//! Wrap a one-time message AEAD key under the public `Y = K · G` locally
//! (no server round-trip) and unwrap via cooperation of ≥ 3 Sealed Servers
//! with client-side Lagrange combine. Structurally mirrors `umbrella-oprf`
//! from Stage 4: same primitives (Ristretto255, Shamir 3-of-5, Lagrange
//! combine), same SignedRequest pattern with attestation and device
//! signature, same `WitnessIndex` semantics.
//!
//! Детали алгоритма — в SPEC-12-BACKUP §A. Обоснование выбора
//! threshold-ElGamal варианта над threshold-OPRF-style — в ADR-007.
//!
//! Algorithm details — SPEC-12-BACKUP §A. Rationale for picking
//! threshold-ElGamal over threshold-OPRF-style — ADR-007.

pub mod aead;
pub mod authorization;
pub mod identity_rotation;
pub mod params;
pub mod share;
pub mod signed_request;
pub mod threshold;
pub mod transport;
pub mod unwrap;
pub mod version;
pub mod wire;
pub mod wrap;

#[cfg(feature = "pq")]
pub mod pq_wrap;

pub use authorization::{
    canonical_signing_input_approval, canonical_signing_input_request,
    canonical_signing_input_revocation, seal_device_authorization_approval,
    seal_device_authorization_request, seal_device_authorization_revocation,
    DeviceAuthorizationApproval, DeviceAuthorizationRequest, DeviceAuthorizationRevocation,
    AUTHORIZATION_WIRE_VERSION, CHALLENGE_NONCE_LEN, DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR,
    DEVICE_AUTH_APPROVAL_LEN, DEVICE_AUTH_REQUEST_BASE_LEN, DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR,
    DEVICE_AUTH_REQUEST_MAX_LEN, DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR, DEVICE_AUTH_REVOKE_LEN,
    LOCATION_HINT_MAX, POLICY_FLAGS_RESERVED_MASK, POLICY_FLAG_HIGH_SECURITY,
};
pub use identity_rotation::{
    canonical_signing_input_rotation, seal_identity_rotation_record, IdentityRotationRecord,
    RotationReason, IDENTITY_ROTATION_DOMAIN_SEPARATOR, IDENTITY_ROTATION_LEN,
};
pub use params::{
    ThresholdConfig, WitnessIndex, WrappingParams, AEAD_BLOB_LEN, AEAD_TAG_LEN, CHAT_ID_LEN,
    DEFAULT_THRESHOLD, DEFAULT_TOTAL, MESSAGE_KEY_LEN, NONCE_LEN, POINT_LEN, PROTOCOL_VERSION,
    WRAPPED_KEY_LEN,
};
pub use share::{ServerUnwrapShare, SERVER_UNWRAP_SHARE_LEN};
pub use signed_request::{
    canonical_signing_input, seal_unwrap_request, verify_signed_unwrap_request,
    verify_signed_unwrap_request_for_production,
    verify_signed_unwrap_request_for_production_with_context, AttestationProvider, Platform,
    PlatformAttestation, PlatformVerificationInput, PlatformVerifierKind, ProductionDeviceState,
    ProductionFreshnessPolicy, ProductionNonceReplayGuard, ProductionPlatformVerifier,
    ProductionUnwrapVerificationContext, SharedPlatformVerifierForBackup, SignedUnwrapRequest,
    TestingAttestationProvider, UnavailableProductionPlatformVerifier, DEVICE_PUBKEY_LEN,
    DEVICE_SIG_LEN, MAX_ATTESTATION_TOKEN_BYTES, NONCE_LEN as UNWRAP_NONCE_LEN,
    SIGNATURE_DOMAIN_SEPARATOR, SIGNED_UNWRAP_REQUEST_FIXED_LEN, SIGNED_UNWRAP_REQUEST_MAX_LEN,
    UNWRAP_WIRE_VERSION,
};
pub use threshold::{shamir_split_for_testing, threshold_combine};
pub use transport::{
    DeviceEntryState, DeviceEntryStateFlag, MockSealedServer, MockServerBehavior,
    MockUnwrapTransport, UnwrapTransport,
};
pub use unwrap::{unwrap_message_key, unwrap_message_key_no_retry};
pub use version::WrappingCiphersuite;
pub use wire::{
    canonical_nonce, CanonicalAad, WrappedKey, CANONICAL_AAD_LEN, ED25519_PUB_LEN,
    NONCE_DERIVATION_SALT,
};
pub use wrap::wrap_message_key;

#[cfg(feature = "pq")]
pub use pq_wrap::{
    unwrap_v2_to_v1, wrap_v1_into_v2, WrappedKeyV2, V2_AEAD_KEY_LEN, V2_DOMAIN_SEP, V2_HKDF_SALT,
    V2_VERSION_LEN, WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN, WRAPPED_KEY_V2_LEN,
};
