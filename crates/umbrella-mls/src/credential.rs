//! Построение `CredentialWithKey` для openmls на основе `umbrella_identity::KeyStore`.
//! Building `CredentialWithKey` for openmls based on `umbrella_identity::KeyStore`.
//!
//! Поддерживается два режима credential:
//!
//! - **Identity credential** — `credential.identity = identity_pubkey_32`,
//!   `signature_key = identity_pubkey_32`. Подписывается через `UmbrellaIdentitySigner`.
//!   Используется для создания KeyPackage и операций самого высокого уровня доверия.
//!
//! - **Device credential** — `credential.identity = identity_pubkey_32 || device_index_4`,
//!   `signature_key = device_pubkey_32`. Подписывается через `UmbrellaDeviceSigner`.
//!   Используется для подписи application messages в группах. Получатель проверяет
//!   `DeviceAttestation` через KT log что данный device-pubkey легитимно зарегистрирован
//!   identity (Sesame pattern).
//!
//! Two credential modes are supported:
//!
//! - **Identity credential** — `credential.identity = identity_pubkey_32`,
//!   `signature_key = identity_pubkey_32`. Signed via `UmbrellaIdentitySigner`. Used for
//!   creating KeyPackages and the highest-trust operations.
//!
//! - **Device credential** — `credential.identity = identity_pubkey_32 || device_index_4`,
//!   `signature_key = device_pubkey_32`. Signed via `UmbrellaDeviceSigner`. Used for signing
//!   application messages in groups. Recipients verify `DeviceAttestation` via the KT log to
//!   confirm the device-pubkey is legitimately registered by the identity (Sesame pattern).

use openmls::credentials::{BasicCredential, CredentialWithKey};

use umbrella_identity::KeyStore;

use crate::error::{MlsError, Result};

/// Длина identity-pubkey в байтах (Ed25519 = 32).
/// Identity pubkey length in bytes (Ed25519 = 32).
pub const IDENTITY_PUBKEY_LEN: usize = 32;

/// Длина device credential payload: 32 байта identity_pubkey + 4 байта device_index.
/// Device credential payload length: 32 bytes identity_pubkey + 4 bytes device_index.
pub const DEVICE_CREDENTIAL_LEN: usize = IDENTITY_PUBKEY_LEN + 4;

/// Строит `CredentialWithKey` где credential identity = identity_pubkey, signing key = identity-key.
/// Builds a `CredentialWithKey` where the credential identity = identity_pubkey, signing key = identity key.
///
/// Используется на верхнем уровне доверия — например при первой регистрации в KT log,
/// при выпуске первого DeviceAttestation, при операциях миграции identity.
/// Used at the top level of trust — e.g. on first registration in the KT log, on issuing the
/// first DeviceAttestation, on identity-migration operations.
pub fn build_credential_for_identity(keystore: &dyn KeyStore) -> Result<CredentialWithKey> {
    let identity_bytes = keystore.identity_public().to_bytes();
    let basic = BasicCredential::new(identity_bytes.to_vec());
    Ok(CredentialWithKey {
        credential: basic.into(),
        signature_key: identity_bytes.to_vec().into(),
    })
}

/// Строит `CredentialWithKey` где credential identity = identity_pubkey || device_index_BE,
/// signing key = device-pubkey.
/// Builds a `CredentialWithKey` where the credential identity = identity_pubkey || device_index_BE,
/// signing key = device-pubkey.
///
/// Это credential подписывающий MLS commits и application messages в группах.
/// Получатель должен дополнительно скачать соответствующий `DeviceAttestation` из KT log
/// и проверить что identity подписал данный device-pubkey.
/// This is the credential that signs MLS commits and application messages in groups.
/// Recipients additionally fetch the corresponding `DeviceAttestation` from the KT log and verify
/// that the identity signed this device-pubkey.
///
/// Возвращает ошибку если `device_index` не зарегистрирован в keystore.
/// Returns an error if `device_index` is not registered in the keystore.
pub fn build_credential_for_device(
    keystore: &dyn KeyStore,
    device_index: u32,
) -> Result<CredentialWithKey> {
    let identity_bytes = keystore.identity_public().to_bytes();
    let device_pub = keystore
        .device_public(device_index)
        .ok_or(MlsError::Identity(
            umbrella_identity::IdentityError::UnknownDevice {
                index: device_index,
            },
        ))?
        .to_bytes();

    let mut payload = Vec::with_capacity(DEVICE_CREDENTIAL_LEN);
    payload.extend_from_slice(&identity_bytes);
    payload.extend_from_slice(&device_index.to_be_bytes());

    let basic = BasicCredential::new(payload);
    Ok(CredentialWithKey {
        credential: basic.into(),
        signature_key: device_pub.to_vec().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};

    fn fresh_keystore() -> Arc<InMemoryKeyStore> {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
    }

    #[test]
    fn identity_credential_payload_equals_pubkey() {
        let store = fresh_keystore();
        let cwk = build_credential_for_identity(store.as_ref()).unwrap();
        let credential_bytes: &[u8] = cwk.credential.serialized_content();
        assert_eq!(credential_bytes, &store.identity_public().to_bytes());
    }

    #[test]
    fn identity_credential_signature_key_equals_pubkey() {
        let store = fresh_keystore();
        let cwk = build_credential_for_identity(store.as_ref()).unwrap();
        let key_bytes: &[u8] = cwk.signature_key.as_slice();
        assert_eq!(key_bytes, &store.identity_public().to_bytes());
    }

    #[test]
    fn device_credential_payload_is_identity_concat_index_be() {
        let store = fresh_keystore();
        store.add_device(7, None).unwrap();
        let cwk = build_credential_for_device(store.as_ref(), 7).unwrap();
        let payload: &[u8] = cwk.credential.serialized_content();
        assert_eq!(payload.len(), DEVICE_CREDENTIAL_LEN);
        assert_eq!(&payload[..32], &store.identity_public().to_bytes());
        assert_eq!(&payload[32..36], &7u32.to_be_bytes());
    }

    #[test]
    fn device_credential_signature_key_equals_device_pubkey() {
        let store = fresh_keystore();
        store.add_device(3, None).unwrap();
        let cwk = build_credential_for_device(store.as_ref(), 3).unwrap();
        let key_bytes: &[u8] = cwk.signature_key.as_slice();
        assert_eq!(key_bytes, &store.device_public(3).unwrap().to_bytes());
    }

    #[test]
    fn device_credential_unknown_index_rejected() {
        let store = fresh_keystore();
        let result = build_credential_for_device(store.as_ref(), 99);
        assert!(matches!(
            result,
            Err(MlsError::Identity(
                umbrella_identity::IdentityError::UnknownDevice { index: 99 }
            ))
        ));
    }

    #[test]
    fn device_credential_distinct_index_distinct_payloads() {
        let store = fresh_keystore();
        store.add_device(0, None).unwrap();
        store.add_device(1, None).unwrap();
        let c0 = build_credential_for_device(store.as_ref(), 0).unwrap();
        let c1 = build_credential_for_device(store.as_ref(), 1).unwrap();
        assert_ne!(
            c0.credential.serialized_content(),
            c1.credential.serialized_content()
        );
        assert_ne!(c0.signature_key.as_slice(), c1.signature_key.as_slice());
    }
}
