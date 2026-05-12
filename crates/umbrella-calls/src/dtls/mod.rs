//! DTLS identity binding: связка DTLS certificate fingerprint с Ed25519
//! identity-key из KT. Реальный DTLS handshake — вне крейта, делается в
//! `webrtc-rs` на Этапе 7; здесь только детерминистический fingerprint,
//! который webrtc-rs подставит в сертификат.
//!
//! ## Цель
//!
//! Скомпрометированный TURN relay не должен иметь возможность подменить
//! DTLS certificate без компрометации Ed25519 identity-ключа пользователя
//! из KT (Key Transparency). Это связывает DTLS-слой с Umbrella identity,
//! закрывая MITM через подмену сертификата на стороне TURN.
//!
//! DTLS identity binding: links a DTLS certificate fingerprint to the
//! Ed25519 identity-key from KT. The actual DTLS handshake is outside this
//! crate and done by `webrtc-rs` in Stage 7; this module only produces a
//! deterministic fingerprint that webrtc-rs embeds in the certificate.
//!
//! ## Goal
//!
//! A compromised TURN relay must not be able to swap the DTLS certificate
//! without compromising the user's Ed25519 identity key in KT (Key
//! Transparency). This binds the DTLS layer to the Umbrella identity,
//! closing the MITM avenue via certificate swap on the TURN side.

pub mod fingerprint;

pub use fingerprint::{
    compute_mutual_identity_binding, IdentityDtlsFingerprint, FINGERPRINT_LEN, IDENTITY_PUBKEY_LEN,
    SESSION_NONCE_LEN,
};
