//! Адаптеры к `umbrella-identity::KeyStore` для обеих подсистем.
//! Adapters to `umbrella-identity::KeyStore` for both subsystems.
//!
//! Крейт `umbrella-backup` по дизайну не зависит напрямую от `KeyStore` в
//! публичном API (подписи принимаются через signer-closure) — это позволяет
//! подключать любой источник ключей (KeyStore, HSM, custom-wrapper). Но
//! типичный caller в `umbrella-client` всегда использует `KeyStore`; этот
//! модуль предоставляет готовые helper'ы с сохранением same-interface:
//!
//! - `seal_unwrap_request_with_keystore` — собрать `SignedUnwrapRequest`
//!   через `KeyStore::sign_with_device(device_idx, canonical)`.
//! - `build_signed_qr_with_identity` — собрать `DevicePairingQr` через
//!   `KeyStore::sign_with_identity(canonical)`.
//! - `sign_handshake_hash_with_identity` — подписать handshake_hash через
//!   identity-key.
//! - `verify_remote_pairing` — проверить что identity из QR совпадает с
//!   identity после handshake, и что оба устройства принадлежат одному
//!   аккаунту в KT.
//!
//! This crate does not depend on `KeyStore` in its public API by design
//! (signatures go through signer-closures), which lets any key source plug
//! in. But the typical caller in `umbrella-client` always uses `KeyStore`;
//! this module provides ready-made helpers preserving the same interface.

use umbrella_identity::{DeviceKeyPublic, IdentityKeyPublic, KeyStore};

use crate::cloud_wrap::params::POINT_LEN;
use crate::cloud_wrap::signed_request::{
    seal_unwrap_request, AttestationProvider, SignedUnwrapRequest, DEVICE_PUBKEY_LEN, NONCE_LEN,
};
use crate::cloud_wrap::wire::ED25519_PUB_LEN;
use crate::device_transfer::handshake::HANDSHAKE_HASH_LEN;
use crate::device_transfer::identity_verify::{
    sign_handshake_hash, verify_handshake_hash_signature, KtLookup, ACCOUNT_ID_LEN,
};
use crate::device_transfer::qr::{
    build_signed_qr, DevicePairingQr, PAIRING_CHALLENGE_LEN, PUBKEY_LEN, QR_SIG_LEN,
};
use crate::error::BackupError;

/// Длина canonical chat_id в байтах. Canonical chat_id length in bytes.
/// Re-export из `cloud_wrap::signed_request::CHAT_ID_LEN`.
pub use crate::cloud_wrap::signed_request::CHAT_ID_LEN;

/// Собрать `SignedUnwrapRequest` через `KeyStore::sign_with_device`.
///
/// Assemble `SignedUnwrapRequest` via `KeyStore::sign_with_device`.
///
/// # Errors
/// - [`BackupError::InvalidAttestationShape`] если attestation provider вернул
///   пустой или длинный token.
/// - [`BackupError::DeviceSigning`] если device с `device_idx` не зарегистрирован
///   или был revoked.
#[allow(clippy::too_many_arguments)] // параллель с `cloud_wrap::seal_unwrap_request`
pub fn seal_unwrap_request_with_keystore(
    ks: &dyn KeyStore,
    device_idx: u32,
    ephemeral_r: [u8; POINT_LEN],
    chat_id: [u8; CHAT_ID_LEN],
    recipient_device_pubkey: [u8; ED25519_PUB_LEN],
    timestamp_unix_millis: u64,
    server_nonce: [u8; NONCE_LEN],
    attestation_provider: &dyn AttestationProvider,
) -> Result<SignedUnwrapRequest, BackupError> {
    let device_pub = ks
        .device_public(device_idx)
        .ok_or(BackupError::DeviceSigning("device not registered"))?;
    let device_pubkey_bytes: [u8; DEVICE_PUBKEY_LEN] = device_pub_to_bytes(&device_pub);

    seal_unwrap_request(
        ephemeral_r,
        chat_id,
        recipient_device_pubkey,
        timestamp_unix_millis,
        server_nonce,
        attestation_provider,
        |payload| {
            ks.sign_with_device(device_idx, payload)
                .map(|sig| sig.to_bytes())
                .map_err(|_| BackupError::DeviceSigning("KeyStore::sign_with_device"))
        },
        device_pubkey_bytes,
    )
}

/// Собрать `DevicePairingQr` через `KeyStore::sign_with_identity`.
///
/// Assemble `DevicePairingQr` via `KeyStore::sign_with_identity`.
///
/// # Errors
/// Инфраструктурные ошибки KeyStore транслируются в [`BackupError::DeviceSigning`].
pub fn build_signed_qr_with_identity(
    ks: &dyn KeyStore,
    responder_ephemeral_static: [u8; PUBKEY_LEN],
    pairing_challenge: [u8; PAIRING_CHALLENGE_LEN],
    expiry_unix_millis: u64,
) -> Result<DevicePairingQr, BackupError> {
    let identity_pub = ks.identity_public();
    let identity_pub_bytes = identity_pub_to_bytes(&identity_pub);

    build_signed_qr(
        identity_pub_bytes,
        responder_ephemeral_static,
        pairing_challenge,
        expiry_unix_millis,
        |payload| Ok(ks.sign_with_identity(payload).to_bytes()),
    )
}

/// Подписать handshake hash через `KeyStore::sign_with_identity`.
///
/// Sign handshake hash via `KeyStore::sign_with_identity`.
///
/// # Errors
/// Инфраструктурные ошибки KeyStore → [`BackupError::DeviceSigning`].
pub fn sign_handshake_hash_with_identity(
    ks: &dyn KeyStore,
    handshake_hash: &[u8; HANDSHAKE_HASH_LEN],
) -> Result<[u8; QR_SIG_LEN], BackupError> {
    sign_handshake_hash(handshake_hash, |payload| {
        Ok(ks.sign_with_identity(payload).to_bytes())
    })
}

/// Проверить что remote identity (после post-handshake exchange) совпадает с
/// QR identity и принадлежит тому же account в KT.
///
/// Verify remote identity (post-handshake) matches QR identity and belongs to
/// the same account in KT.
///
/// Вызывается на стороне initiator'а после приёма ответного identity-
/// signature от responder'а. Защищает от MITM подмены QR.
///
/// Called on initiator side after receiving responder's identity signature.
/// Protects against QR MITM.
///
/// # Errors
/// - [`BackupError::QrSignatureInvalid`] если QR identity pubkey не
///   соответствует remote identity.
/// - [`BackupError::CryptoVerificationFailed`] если подпись handshake_hash
///   не проходит verify, или KT не подтверждает одинаковый account.
pub fn verify_remote_pairing<K: KtLookup>(
    qr: &DevicePairingQr,
    remote_identity_pubkey: &[u8; PUBKEY_LEN],
    expected_account_id: &[u8; ACCOUNT_ID_LEN],
    handshake_hash: &[u8; HANDSHAKE_HASH_LEN],
    remote_handshake_signature: &[u8; QR_SIG_LEN],
    kt: &K,
    our_identity_pubkey: &[u8; PUBKEY_LEN],
) -> Result<(), BackupError> {
    // 1. Remote identity из post-handshake должна совпадать с identity в QR
    //    (защита от того что злоумышленник подменил QR после scan).
    if qr.responder_identity_pubkey != *remote_identity_pubkey {
        return Err(BackupError::QrSignatureInvalid);
    }

    // 2. Подпись handshake_hash должна быть валидна под remote identity.
    verify_handshake_hash_signature(
        handshake_hash,
        remote_identity_pubkey,
        remote_handshake_signature,
    )?;

    // 3. Обе identity (наша и remote) должны быть в KT под одним account_id.
    kt.verify_membership(remote_identity_pubkey, expected_account_id)?;
    kt.verify_membership(our_identity_pubkey, expected_account_id)?;
    Ok(())
}

fn identity_pub_to_bytes(pk: &IdentityKeyPublic) -> [u8; 32] {
    pk.to_bytes()
}

fn device_pub_to_bytes(pk: &DeviceKeyPublic) -> [u8; DEVICE_PUBKEY_LEN] {
    pk.to_bytes()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

    use umbrella_identity::{
        IdentitySeed, InMemoryKeyStore, KeyStore as KeyStoreTrait, MnemonicLanguage, SystemClock,
    };

    use super::*;
    use crate::cloud_wrap::signed_request::{
        verify_signed_unwrap_request, TestingAttestationProvider,
    };
    use crate::device_transfer::handshake::{PairingInitiator, PairingResponder};
    use crate::device_transfer::identity_verify::MockKtLookup;

    fn fresh_keystore() -> InMemoryKeyStore {
        // Random BIP-39 seed для каждого теста.
        let seed = IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English);
        InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock)).unwrap()
    }

    fn register_test_device(ks: &InMemoryKeyStore, idx: u32) {
        ks.add_device(idx, None).unwrap();
    }

    #[test]
    fn seal_unwrap_request_with_keystore_happy_path() {
        let ks = fresh_keystore();
        register_test_device(&ks, 0);

        let provider = TestingAttestationProvider::default();
        let mut server_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut server_nonce);

        let req = seal_unwrap_request_with_keystore(
            &ks,
            0,
            [0xAAu8; POINT_LEN],
            [0x33u8; CHAT_ID_LEN],
            [0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000,
            server_nonce,
            &provider,
        )
        .unwrap();

        // Подпись под correct device_pubkey — проходит verify.
        verify_signed_unwrap_request(&req).expect("device signature must verify");

        // device_pubkey в запросе совпадает с device_public(0).
        let expected = ks.device_public(0).unwrap().to_bytes();
        assert_eq!(req.device_pubkey, expected);
    }

    #[test]
    fn seal_unwrap_request_with_keystore_rejects_unknown_device_idx() {
        let ks = fresh_keystore();
        // Не регистрируем device 0.
        let provider = TestingAttestationProvider::default();
        let err = seal_unwrap_request_with_keystore(
            &ks,
            0,
            [0xAAu8; POINT_LEN],
            [0x33u8; CHAT_ID_LEN],
            [0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000,
            [0u8; NONCE_LEN],
            &provider,
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    #[test]
    fn seal_unwrap_request_with_keystore_rejects_revoked_device() {
        let ks = fresh_keystore();
        register_test_device(&ks, 0);
        ks.revoke_device(0).unwrap();

        let provider = TestingAttestationProvider::default();
        let err = seal_unwrap_request_with_keystore(
            &ks,
            0,
            [0xAAu8; POINT_LEN],
            [0x33u8; CHAT_ID_LEN],
            [0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000,
            [0u8; NONCE_LEN],
            &provider,
        );
        // Для revoked — либо DeviceSigning в нашем adapter'е, либо в underlying
        // sign_with_device. Оба варианта валидны.
        match err {
            Err(BackupError::DeviceSigning(_)) => {}
            _ => panic!("expected DeviceSigning error, got: {err:?}"),
        }
    }

    #[test]
    fn build_signed_qr_with_identity_verifies() {
        let ks = fresh_keystore();
        let eph_secret = XStatic::random_from_rng(OsRng);
        let eph_pub = XPub::from(&eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);

        let qr = build_signed_qr_with_identity(&ks, eph_pub, chal, u64::MAX / 2).unwrap();
        qr.verify_identity()
            .expect("QR signed by identity must verify");
        assert_eq!(
            qr.responder_identity_pubkey,
            ks.identity_public().to_bytes()
        );
    }

    #[test]
    fn build_signed_qr_with_identity_cross_check_against_different_identity() {
        let ks_a = fresh_keystore();
        let ks_b = fresh_keystore();
        let eph_secret = XStatic::random_from_rng(OsRng);
        let eph_pub = XPub::from(&eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);

        // QR подписан ks_a identity.
        let mut qr = build_signed_qr_with_identity(&ks_a, eph_pub, chal, u64::MAX / 2).unwrap();
        // Подменяем responder_identity_pubkey на ks_b — подпись больше не валидна.
        qr.responder_identity_pubkey = ks_b.identity_public().to_bytes();
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn sign_handshake_hash_with_identity_verifies() {
        let ks = fresh_keystore();
        let mut hh = [0u8; HANDSHAKE_HASH_LEN];
        OsRng.fill_bytes(&mut hh);

        let sig = sign_handshake_hash_with_identity(&ks, &hh).unwrap();
        verify_handshake_hash_signature(&hh, &ks.identity_public().to_bytes(), &sig).unwrap();
    }

    #[test]
    fn verify_remote_pairing_accepts_same_account() {
        let ks_old = fresh_keystore();
        let ks_new = fresh_keystore();
        let account_id = [0xAAu8; ACCOUNT_ID_LEN];

        // Setup KT: обе identity в одном аккаунте.
        let mut kt = MockKtLookup::new();
        kt.register(ks_old.identity_public().to_bytes(), account_id);
        kt.register(ks_new.identity_public().to_bytes(), account_id);

        // Responder (ks_old) строит QR.
        let eph_secret = XStatic::random_from_rng(OsRng);
        let eph_pub = XPub::from(&eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr_with_identity(&ks_old, eph_pub, chal, u64::MAX / 2).unwrap();
        qr.verify_identity().unwrap();

        // Моделируем handshake hash (в реальности — результат Noise_IK).
        let mut hh = [0u8; HANDSHAKE_HASH_LEN];
        OsRng.fill_bytes(&mut hh);
        let remote_sig = sign_handshake_hash_with_identity(&ks_old, &hh).unwrap();

        // Initiator (ks_new) проверяет pairing.
        verify_remote_pairing(
            &qr,
            &ks_old.identity_public().to_bytes(),
            &account_id,
            &hh,
            &remote_sig,
            &kt,
            &ks_new.identity_public().to_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn verify_remote_pairing_rejects_different_account() {
        let ks_old = fresh_keystore();
        let ks_new = fresh_keystore();
        let account_old = [0xAAu8; ACCOUNT_ID_LEN];
        let account_new = [0xBBu8; ACCOUNT_ID_LEN];

        let mut kt = MockKtLookup::new();
        kt.register(ks_old.identity_public().to_bytes(), account_old);
        kt.register(ks_new.identity_public().to_bytes(), account_new);

        let eph_secret = XStatic::random_from_rng(OsRng);
        let eph_pub = XPub::from(&eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr_with_identity(&ks_old, eph_pub, chal, u64::MAX / 2).unwrap();

        let mut hh = [0u8; HANDSHAKE_HASH_LEN];
        OsRng.fill_bytes(&mut hh);
        let remote_sig = sign_handshake_hash_with_identity(&ks_old, &hh).unwrap();

        let err = verify_remote_pairing(
            &qr,
            &ks_old.identity_public().to_bytes(),
            &account_old,
            &hh,
            &remote_sig,
            &kt,
            &ks_new.identity_public().to_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_remote_pairing_rejects_mismatched_remote_identity() {
        let ks_old = fresh_keystore();
        let ks_impostor = fresh_keystore();
        let ks_new = fresh_keystore();
        let account_id = [0xCCu8; ACCOUNT_ID_LEN];

        let mut kt = MockKtLookup::new();
        kt.register(ks_old.identity_public().to_bytes(), account_id);
        kt.register(ks_new.identity_public().to_bytes(), account_id);

        let eph_secret = XStatic::random_from_rng(OsRng);
        let eph_pub = XPub::from(&eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr_with_identity(&ks_old, eph_pub, chal, u64::MAX / 2).unwrap();

        let mut hh = [0u8; HANDSHAKE_HASH_LEN];
        OsRng.fill_bytes(&mut hh);
        let impostor_sig = sign_handshake_hash_with_identity(&ks_impostor, &hh).unwrap();

        // Initiator видит impostor's identity pubkey, но QR подписан ks_old — mismatch.
        let err = verify_remote_pairing(
            &qr,
            &ks_impostor.identity_public().to_bytes(),
            &account_id,
            &hh,
            &impostor_sig,
            &kt,
            &ks_new.identity_public().to_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn end_to_end_device_transfer_with_real_keystores() {
        // Полная цепочка: два KeyStore → QR → Noise_IK handshake → identity
        // binding → pairing verification. Демонстрирует что adapter'ы работают
        // интегрированно с umbrella-identity.
        let ks_old = fresh_keystore();
        let ks_new = fresh_keystore();
        let account_id = [0xFFu8; ACCOUNT_ID_LEN];

        let mut kt = MockKtLookup::new();
        kt.register(ks_old.identity_public().to_bytes(), account_id);
        kt.register(ks_new.identity_public().to_bytes(), account_id);

        // Responder (ks_old) генерирует ephemeral pair + QR.
        let resp_eph_secret = XStatic::random_from_rng(OsRng);
        let resp_eph_pub = XPub::from(&resp_eph_secret).to_bytes();
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr_with_identity(&ks_old, resp_eph_pub, chal, u64::MAX / 2).unwrap();
        qr.verify_identity().unwrap();

        // Noise_IK handshake.
        let init_secret = XStatic::random_from_rng(OsRng);
        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        let mut responder =
            PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, resp_result) = responder.write_message_2_and_finalize().unwrap();
        let init_result = initiator.read_message_2_and_finalize(&msg2).unwrap();
        assert_eq!(init_result.handshake_hash, resp_result.handshake_hash);

        // Post-handshake: responder подписывает handshake hash своим identity.
        let remote_sig =
            sign_handshake_hash_with_identity(&ks_old, &resp_result.handshake_hash).unwrap();

        // Initiator проверяет pairing.
        verify_remote_pairing(
            &qr,
            &ks_old.identity_public().to_bytes(),
            &account_id,
            &init_result.handshake_hash,
            &remote_sig,
            &kt,
            &ks_new.identity_public().to_bytes(),
        )
        .unwrap();
    }
}
