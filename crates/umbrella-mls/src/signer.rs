//! `openmls_traits::signatures::Signer` adapters над `umbrella_identity::KeyStore`.
//! `openmls_traits::signatures::Signer` adapters over `umbrella_identity::KeyStore`.
//!
//! Эти адаптеры реализуют openmls `Signer` trait и делегируют подпись в `KeyStore` —
//! приватные ключи остаются внутри keystore (в production: Secure Enclave/StrongBox через FFI).
//! openmls получает только результат подписи; ключи не пересекают границу keystore.
//!
//! These adapters implement the openmls `Signer` trait and delegate signing to the `KeyStore` —
//! private keys remain inside the keystore (in production: Secure Enclave/StrongBox via FFI).
//! openmls receives only the signature output; keys never cross the keystore boundary.

use openmls_traits::signatures::Signer;
use openmls_traits::types::SignatureScheme;

use umbrella_identity::KeyStore;

/// `Signer` adapter подписывающий identity-key через `KeyStore::sign_with_identity`.
/// `Signer` adapter signing with the identity key via `KeyStore::sign_with_identity`.
///
/// Используется при операциях требующих identity-аутентификации:
/// создание group commitment в которой identity-key служит credential signer
/// (для Umbrella это редкий случай — обычно подписывает device-key, identity-key
/// используется только для attestation device-keys).
///
/// Used for operations requiring identity authentication: creating a group commitment where
/// the identity key serves as the credential signer (rare in Umbrella — device keys usually
/// sign, the identity key is reserved for device-key attestations).
pub struct UmbrellaIdentitySigner<'a> {
    keystore: &'a dyn KeyStore,
}

impl<'a> UmbrellaIdentitySigner<'a> {
    /// Создаёт adapter обёртывающий keystore по reference.
    /// Constructs an adapter wrapping the keystore by reference.
    pub fn new(keystore: &'a dyn KeyStore) -> Self {
        Self { keystore }
    }
}

impl<'a> Signer for UmbrellaIdentitySigner<'a> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        let sig = self.keystore.sign_with_identity(payload);
        Ok(sig.to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        // Все наши ciphersuites используют Ed25519 (или Ed448, но identity-key всегда Ed25519
        // согласно SLIP-0010 derivation в umbrella-identity).
        // All our ciphersuites use Ed25519 (or Ed448, but identity key is always Ed25519 per
        // the SLIP-0010 derivation in umbrella-identity).
        SignatureScheme::ED25519
    }
}

/// `Signer` adapter подписывающий device-key через `KeyStore::sign_with_device`.
/// `Signer` adapter signing with a device key via `KeyStore::sign_with_device`.
///
/// Это обычный signer для MLS application messages: device-key привязан к Sealed Enclave/
/// StrongBox конкретного устройства, identity-key подписал его через DeviceAttestation
/// (Sesame pattern) и опубликован в KT log.
///
/// This is the regular signer for MLS application messages: the device key is bound to the
/// Sealed Enclave/StrongBox of a specific device, the identity key signed it via
/// DeviceAttestation (Sesame pattern) and published to the KT log.
pub struct UmbrellaDeviceSigner<'a> {
    keystore: &'a dyn KeyStore,
    device_index: u32,
}

impl<'a> UmbrellaDeviceSigner<'a> {
    /// Создаёт adapter для указанного device_index в keystore.
    /// Constructs an adapter for the given device_index in the keystore.
    ///
    /// Возвращает ошибку если device_index не зарегистрирован.
    /// Returns an error if device_index is not registered.
    pub fn new(
        keystore: &'a dyn KeyStore,
        device_index: u32,
    ) -> Result<Self, umbrella_identity::IdentityError> {
        if keystore.device_public(device_index).is_none() {
            return Err(umbrella_identity::IdentityError::UnknownDevice {
                index: device_index,
            });
        }
        Ok(Self {
            keystore,
            device_index,
        })
    }

    /// Возвращает device_index подписывающего устройства.
    /// Returns the device_index of the signing device.
    pub fn device_index(&self) -> u32 {
        self.device_index
    }
}

impl<'a> Signer for UmbrellaDeviceSigner<'a> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        let sig = self
            .keystore
            .sign_with_device(self.device_index, payload)
            .map_err(|_| openmls_traits::signatures::SignerError::SigningError)?;
        Ok(sig.to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};

    fn fresh_keystore() -> Arc<InMemoryKeyStore> {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
    }

    fn verify_signature(pubkey_bytes: &[u8; 32], message: &[u8], sig_bytes: &[u8]) -> bool {
        let pk = VerifyingKey::from_bytes(pubkey_bytes).expect("valid pubkey");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let sig = DalekSig::from_bytes(&sig_arr);
        pk.verify(message, &sig).is_ok()
    }

    #[test]
    fn identity_signer_signature_verifies_with_identity_pubkey() {
        let store = fresh_keystore();
        let signer = UmbrellaIdentitySigner::new(store.as_ref());
        let payload = b"umbrella-test-payload";
        let sig_bytes = signer.sign(payload).unwrap();
        let pubkey = store.identity_public().to_bytes();
        assert!(verify_signature(&pubkey, payload, &sig_bytes));
    }

    #[test]
    fn identity_signer_reports_ed25519_scheme() {
        let store = fresh_keystore();
        let signer = UmbrellaIdentitySigner::new(store.as_ref());
        assert_eq!(signer.signature_scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn identity_signer_signature_does_not_verify_with_device_pubkey() {
        let store = fresh_keystore();
        store.add_device(0, None).unwrap();
        let signer = UmbrellaIdentitySigner::new(store.as_ref());
        let sig_bytes = signer.sign(b"msg").unwrap();
        let device_pub = store.device_public(0).unwrap().to_bytes();
        // Идентичная подпись от identity-key не должна верифицироваться device-pubkey.
        // The same identity-key signature must not verify under the device-pubkey.
        assert!(!verify_signature(&device_pub, b"msg", &sig_bytes));
    }

    #[test]
    fn device_signer_signature_verifies_with_device_pubkey() {
        let store = fresh_keystore();
        store.add_device(0, None).unwrap();
        let signer = UmbrellaDeviceSigner::new(store.as_ref(), 0).unwrap();
        let payload = b"device-payload";
        let sig_bytes = signer.sign(payload).unwrap();
        let device_pub = store.device_public(0).unwrap().to_bytes();
        assert!(verify_signature(&device_pub, payload, &sig_bytes));
    }

    #[test]
    fn device_signer_unknown_index_rejected_at_construction() {
        let store = fresh_keystore();
        // Не регистрируем устройство 7.
        // Device 7 is not registered.
        let result = UmbrellaDeviceSigner::new(store.as_ref(), 7);
        assert!(matches!(
            result,
            Err(umbrella_identity::IdentityError::UnknownDevice { index: 7 })
        ));
    }

    #[test]
    fn device_signer_after_revoke_returns_signer_error() {
        let store = fresh_keystore();
        store.add_device(0, None).unwrap();
        let signer = UmbrellaDeviceSigner::new(store.as_ref(), 0).unwrap();
        store.revoke_device(0).unwrap();
        // Подпись после revoke возвращает SignerError (не panic).
        // Signing after revoke returns SignerError (not a panic).
        let result = signer.sign(b"x");
        assert!(matches!(
            result,
            Err(openmls_traits::signatures::SignerError::SigningError)
        ));
    }

    #[test]
    fn device_signer_distinct_index_distinct_signatures() {
        let store = fresh_keystore();
        store.add_device(0, None).unwrap();
        store.add_device(1, None).unwrap();
        let s0 = UmbrellaDeviceSigner::new(store.as_ref(), 0).unwrap();
        let s1 = UmbrellaDeviceSigner::new(store.as_ref(), 1).unwrap();
        let payload = b"same-payload";
        let sig0 = s0.sign(payload).unwrap();
        let sig1 = s1.sign(payload).unwrap();
        // Подписи разные потому что device-keys разные (Ed25519 deterministic, но keys distinct).
        // Signatures differ because device keys differ (Ed25519 is deterministic, but keys are distinct).
        assert_ne!(sig0, sig1);
    }
}
