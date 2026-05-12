//! Secret device-to-device transfer: QR + Noise_IK + framed streaming snapshot.
//! Secret device-to-device transfer: QR + Noise_IK + framed streaming snapshot.
//!
//! Решает проблему миграции Secret-чата на новое устройство того же аккаунта
//! без серверной custody ключей. Старое устройство генерирует эфемерную X25519
//! пару, кладёт её вместе с pairing challenge и expiry в подписанный QR-код;
//! новое устройство сканирует, инициирует `Noise_IK_25519_ChaChaPoly_SHA512`
//! handshake через крейт `snow`, получает zero-RTT secure channel.
//!
//! Для защиты от MITM (подмена QR): после handshake обе стороны обмениваются
//! identity-signature над handshake_hash + верифицируют membership обеих
//! identity-keys в Key Transparency log под одним и тем же account_id.
//!
//! Solves Secret chat migration between devices of the same account without
//! server-side key custody. Old device generates ephemeral X25519 pair,
//! packages it with pairing challenge and expiry into a signed QR; new device
//! scans, initiates `Noise_IK_25519_ChaChaPoly_SHA512` handshake via `snow`,
//! gets a zero-RTT secure channel. Post-handshake, both sides exchange
//! identity-signature over handshake_hash and verify KT membership under the
//! same account_id.
//!
//! Архитектурное обоснование и обзор патэрнов — в ADR-007 §4-§6.
//! Детальная wire-спецификация и тесты — в SPEC-12-BACKUP §B.

pub mod handshake;
pub mod identity_verify;
pub mod qr;
pub mod snapshot;
pub mod stream;

pub use handshake::{
    PairingInitiator, PairingResponder, TransferHandshakeResult, HANDSHAKE_HASH_LEN,
    HANDSHAKE_PROLOGUE_DOMAIN, HANDSHAKE_WIRE_VERSION, MAX_HANDSHAKE_MSG_LEN, NOISE_PATTERN,
};
pub use identity_verify::{
    sign_handshake_hash, verify_handshake_hash_signature, KtLookup, MockKtLookup, ACCOUNT_ID_LEN,
    IDENTITY_BIND_DOMAIN,
};
pub use qr::{
    build_signed_qr, DevicePairingQr, PAIRING_CHALLENGE_LEN, PUBKEY_LEN, QR_PAYLOAD_LEN,
    QR_SIGNATURE_DOMAIN, QR_SIG_LEN, QR_VERSION,
};
pub use snapshot::{
    MlsGroupState, Snapshot, MLS_GROUP_ID_LEN, SNAPSHOT_EOF_MARKER, SNAPSHOT_VERSION,
};
pub use stream::{TransferSession, FRAME_OVERHEAD, MAX_FRAME_CIPHERTEXT, MAX_FRAME_PAYLOAD};
