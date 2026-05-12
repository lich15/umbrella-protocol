//! Post-handshake identity binding: обе стороны подписывают handshake_hash
//! своими long-term identity-keys и проверяют KT-membership под тем же account.
//!
//! Post-handshake identity binding: both sides sign the handshake hash with
//! their long-term identity keys and check KT-membership under the same
//! account.
//!
//! Защищает от MITM где атакующий мог бы перехватить QR (physical shoulder-
//! surf) и заменить responder во время pairing. После handshake responder
//! подписывает handshake_hash своим identity-key; initiator проверяет что
//! identity совпадает с `qr.responder_identity_pubkey` и что identity есть в
//! KT под expected account_id (доступ через mockable [`KtLookup`]).
//!
//! Protects against MITM where attacker could intercept QR (physical
//! shoulder-surf) and replace responder. After handshake, responder signs
//! handshake_hash with identity-key; initiator verifies identity matches
//! `qr.responder_identity_pubkey` and is in KT under the expected account_id
//! (mockable through `KtLookup`).

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};

use crate::error::BackupError;

use super::handshake::HANDSHAKE_HASH_LEN;
use super::qr::{PUBKEY_LEN, QR_SIG_LEN};

/// Domain separator для identity-signature над handshake hash.
/// Domain separator for identity signature over handshake hash.
pub const IDENTITY_BIND_DOMAIN: &[u8] = b"umbrellax-device-transfer-identity-v1";

/// Длина AccountId в байтах (SHA-256 of identity-pubkey, канонически).
/// AccountId length in bytes (SHA-256 of identity-pubkey, canonical).
pub const ACCOUNT_ID_LEN: usize = 32;

/// Подписать handshake_hash под identity-key через signer-closure.
///
/// Sign handshake_hash under identity-key via signer closure.
///
/// `signer` — callback к identity-key (обычно оборачивает
/// `umbrella_identity::KeyStore::sign_with_identity`).
///
/// # Errors
/// - [`BackupError::DeviceSigning`] если signer-callback вернул ошибку.
pub fn sign_handshake_hash<F>(
    handshake_hash: &[u8; HANDSHAKE_HASH_LEN],
    signer: F,
) -> Result<[u8; QR_SIG_LEN], BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; QR_SIG_LEN], BackupError>,
{
    let mut input = Vec::with_capacity(IDENTITY_BIND_DOMAIN.len() + HANDSHAKE_HASH_LEN);
    input.extend_from_slice(IDENTITY_BIND_DOMAIN);
    input.extend_from_slice(handshake_hash);
    signer(&input)
}

/// Проверить Ed25519 identity-signature над handshake_hash.
/// Verify Ed25519 identity signature over handshake_hash.
///
/// # Errors
/// - [`BackupError::QrSignatureInvalid`] если pubkey не декодируется.
/// - [`BackupError::CryptoVerificationFailed`] если подпись не проходит.
pub fn verify_handshake_hash_signature(
    handshake_hash: &[u8; HANDSHAKE_HASH_LEN],
    signer_identity_pubkey: &[u8; PUBKEY_LEN],
    signature: &[u8; QR_SIG_LEN],
) -> Result<(), BackupError> {
    let vk = DalekVerifyingKey::from_bytes(signer_identity_pubkey)
        .map_err(|_| BackupError::QrSignatureInvalid)?;
    let sig = DalekSignature::from_bytes(signature);
    let mut input = Vec::with_capacity(IDENTITY_BIND_DOMAIN.len() + HANDSHAKE_HASH_LEN);
    input.extend_from_slice(IDENTITY_BIND_DOMAIN);
    input.extend_from_slice(handshake_hash);
    vk.verify(&input, &sig)
        .map_err(|_| BackupError::CryptoVerificationFailed)
}

/// Trait для запроса в Key Transparency log: принадлежит ли identity-pubkey
/// указанному account_id?
///
/// Trait for Key Transparency log query: does the identity pubkey belong to
/// the given account_id?
///
/// Реальная реализация — `umbrella-kt::KtClient` (Этап 3). В крейте backup
/// мы только определяем абстракцию; конкретная интеграция — в `umbrella-client`
/// (Этап 7). Для тестов — простой in-memory mock.
///
/// Real implementation in `umbrella-kt::KtClient` (Stage 3). This crate only
/// defines the abstraction; concrete integration is in `umbrella-client`
/// (Stage 7). Tests use a simple in-memory mock.
pub trait KtLookup {
    /// Проверить принадлежность identity-pubkey к account_id.
    /// Check identity-pubkey membership in account_id.
    ///
    /// # Errors
    /// - [`BackupError::CryptoVerificationFailed`] если identity не найдена
    ///   или принадлежит другому аккаунту.
    /// - Транспортные ошибки транслируются в подходящий вариант.
    fn verify_membership(
        &self,
        identity_pubkey: &[u8; PUBKEY_LEN],
        account_id: &[u8; ACCOUNT_ID_LEN],
    ) -> Result<(), BackupError>;
}

/// In-memory mock для KT lookup: список пар `(pubkey, account_id)`.
/// In-memory KT lookup mock: list of `(pubkey, account_id)` pairs.
#[derive(Debug, Clone, Default)]
pub struct MockKtLookup {
    entries: Vec<([u8; PUBKEY_LEN], [u8; ACCOUNT_ID_LEN])>,
}

impl MockKtLookup {
    /// Создать пустой mock. Create an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавить разрешённую пару. Add an allowed pair.
    pub fn register(&mut self, pubkey: [u8; PUBKEY_LEN], account_id: [u8; ACCOUNT_ID_LEN]) {
        self.entries.push((pubkey, account_id));
    }
}

impl KtLookup for MockKtLookup {
    fn verify_membership(
        &self,
        identity_pubkey: &[u8; PUBKEY_LEN],
        account_id: &[u8; ACCOUNT_ID_LEN],
    ) -> Result<(), BackupError> {
        if self
            .entries
            .iter()
            .any(|(pk, acc)| pk == identity_pubkey && acc == account_id)
        {
            Ok(())
        } else {
            Err(BackupError::CryptoVerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};

    fn make_keypair() -> (SigningKey, DalekVerifyingKey) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn random_handshake_hash() -> [u8; HANDSHAKE_HASH_LEN] {
        let mut hh = [0u8; HANDSHAKE_HASH_LEN];
        OsRng.fill_bytes(&mut hh);
        hh
    }

    #[test]
    fn sign_and_verify_handshake_hash_happy_path() {
        let (sk, vk) = make_keypair();
        let hh = random_handshake_hash();
        let sig = sign_handshake_hash(&hh, |payload| Ok(sk.sign(payload).to_bytes())).unwrap();
        verify_handshake_hash_signature(&hh, &vk.to_bytes(), &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_handshake_hash() {
        let (sk, vk) = make_keypair();
        let hh = random_handshake_hash();
        let sig = sign_handshake_hash(&hh, |payload| Ok(sk.sign(payload).to_bytes())).unwrap();

        let mut bad_hh = hh;
        bad_hh[0] ^= 1;
        let err = verify_handshake_hash_signature(&bad_hh, &vk.to_bytes(), &sig).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let (sk, _vk) = make_keypair();
        let (_sk_other, vk_other) = make_keypair();
        let hh = random_handshake_hash();
        let sig = sign_handshake_hash(&hh, |payload| Ok(sk.sign(payload).to_bytes())).unwrap();
        let err = verify_handshake_hash_signature(&hh, &vk_other.to_bytes(), &sig).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_invalid_pubkey_encoding() {
        let hh = random_handshake_hash();
        let sig = [0u8; QR_SIG_LEN];
        let bad_pub = [0xFFu8; PUBKEY_LEN];
        let err = verify_handshake_hash_signature(&hh, &bad_pub, &sig).unwrap_err();
        // Некоторые битпаттерны могут проходить as valid Ed25519 VerifyingKey (но
        // нажжать verify fail), другие — fail при decode. Оба варианта принимаем.
        assert!(matches!(
            err,
            BackupError::QrSignatureInvalid | BackupError::CryptoVerificationFailed
        ));
    }

    #[test]
    fn sign_propagates_signer_error() {
        let hh = random_handshake_hash();
        let err =
            sign_handshake_hash(&hh, |_| Err(BackupError::DeviceSigning("hw-fault"))).unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    #[test]
    fn mock_kt_lookup_accepts_registered_pair() {
        let mut kt = MockKtLookup::new();
        let pk = [0x11u8; PUBKEY_LEN];
        let acc = [0x22u8; ACCOUNT_ID_LEN];
        kt.register(pk, acc);
        kt.verify_membership(&pk, &acc).unwrap();
    }

    #[test]
    fn mock_kt_lookup_rejects_unregistered_pair() {
        let kt = MockKtLookup::new();
        let pk = [0x11u8; PUBKEY_LEN];
        let acc = [0x22u8; ACCOUNT_ID_LEN];
        let err = kt.verify_membership(&pk, &acc).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn mock_kt_lookup_rejects_wrong_account() {
        let mut kt = MockKtLookup::new();
        let pk = [0x11u8; PUBKEY_LEN];
        let acc_a = [0x22u8; ACCOUNT_ID_LEN];
        let acc_b = [0x33u8; ACCOUNT_ID_LEN];
        kt.register(pk, acc_a);
        let err = kt.verify_membership(&pk, &acc_b).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn identity_bind_domain_is_distinct_from_qr_domain() {
        use crate::device_transfer::qr::QR_SIGNATURE_DOMAIN;
        assert_ne!(IDENTITY_BIND_DOMAIN, QR_SIGNATURE_DOMAIN);
    }
}
