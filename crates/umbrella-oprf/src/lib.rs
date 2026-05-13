//! OPRF-клиент Ristretto255 для скрытого поиска контактов через Sealed Servers (3-of-5).
//! Ristretto255 OPRF client for blinded contact discovery via Sealed Servers (3-of-5).
//!
//! Сервер физически не может ответить на вопрос «есть ли у вас номер X», потому что
//! получает только blinded points; реконструкция OPRF-метки требует кооперации 3 из 5
//! Sealed Servers. Реализует SPEC-05-OPRF-CONTACT-DISCOVERY и ADR-005 настоящего
//! репозитория + ADR-2026-04-20-22 основного проекта.
//!
//! The server physically cannot answer "do you have number X" because it only receives
//! blinded points; OPRF label reconstruction requires cooperation of 3 of 5 Sealed
//! Servers. Implements SPEC-05-OPRF-CONTACT-DISCOVERY and ADR-005 of this repository
//! plus ADR-2026-04-20-22 of the main project.
//!
//! # Модули
//!
//! | Module | Назначение |
//! |---|---|
//! | `error` | [`OprfError`] — все варианты ошибок OPRF-слоя |
//! | `input` | [`OprfInput`] — opaque идентификатор с валидацией длины |
//! | `label` | [`OprfLabel`] — 32-байтовая стабильная метка |
//! | `primitives` | blind / finalize + wire-wrappers над voprf |
//!
//! Последующие модули добавляются в под-этапах 4.3 (`threshold`, `client`),
//! 4.4 (`attestation`, `wire`), 4.5 (integration test).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attestation;
pub mod client;
pub mod error;
pub mod input;
pub mod label;
pub mod primitives;
pub mod threshold;

pub use attestation::{
    canonical_signing_input, seal_request, verify_signed_request,
    verify_signed_request_for_production, verify_signed_request_for_production_with_context,
    AttestationProvider, Platform, PlatformAttestation, PlatformVerificationInput,
    PlatformVerifierKind, ProductionDeviceState, ProductionFreshnessPolicy,
    ProductionNonceReplayGuard, ProductionOprfVerificationContext, ProductionPlatformVerifier,
    SharedPlatformVerifierForOprf, SignedOprfRequest, TestingAttestationProvider,
    UnavailableProductionPlatformVerifier, DEVICE_PUBKEY_LEN, DEVICE_SIG_LEN,
    MAX_ATTESTATION_TOKEN_BYTES, NONCE_LEN, SIGNATURE_DOMAIN_SEPARATOR, WIRE_VERSION,
};
pub use client::{batch_contact_query, batch_finalize, ContactQuery, MAX_BATCH_SIZE};
pub use error::OprfError;
pub use input::{OprfInput, MAX_INPUT_BYTES};
pub use label::{OprfLabel, LABEL_LEN};
pub use primitives::{
    blind, evaluate_for_testing, finalize, generate_test_private_key, BlindedRequest,
    BlindingState, ServerEvaluation, LABEL_DOMAIN_SEPARATOR, POINT_LEN, SCALAR_LEN,
};
pub use threshold::{
    shamir_split_for_testing, threshold_combine, ThresholdConfig, WitnessIndex, DEFAULT_THRESHOLD,
    DEFAULT_TOTAL,
};
