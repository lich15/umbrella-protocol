//! Device-key — Ed25519 ключ конкретного физического устройства пользователя.
//! Device key — Ed25519 key for a specific physical user device.
//!
//! Device-key подписан identity-key через `DeviceAttestation` (Sesame pattern).
//! Каждое устройство имеет свой `device_index`, ключ derive детерминистически.
//! Приватный device-key никогда не покидает Secure Enclave/StrongBox в production
//! (через `KeyStore` trait — будет добавлен в следующей фазе).
//!
//! Device key is signed by the identity key via `DeviceAttestation` (Sesame pattern).
//! Each device has its own `device_index`; the key is derived deterministically.
//! In production the private device key never leaves the Secure Enclave/StrongBox
//! (via the `KeyStore` trait — added in the next stage).
//!
//! **Канонический путь / Canonical path:** `m / 0x554D' / account' / 1' / device_index'`
//! (см. `path::DerivationPath::device` / see `path::DerivationPath::device`).

use core::fmt;

use zeroize::ZeroizeOnDrop;

use umbrella_crypto_primitives::sig::{Ed25519Signature, PrivateSigningKey, PublicVerifyingKey};

use crate::derive::MasterKey;
use crate::error::Result;
use crate::path::DerivationPath;
use crate::seed::IdentitySeed;

/// Приватный device-key конкретного устройства; обнуляется при Drop.
/// Private device key for a specific device; zeroized on Drop.
#[derive(ZeroizeOnDrop)]
pub struct DeviceKey {
    signing: PrivateSigningKey,
    #[zeroize(skip)]
    public: DeviceKeyPublic,
    #[zeroize(skip)]
    account: u32,
    #[zeroize(skip)]
    device_index: u32,
}

impl DeviceKey {
    /// Derive device-key из IdentitySeed для указанного аккаунта и устройства.
    /// Derives the device key from an IdentitySeed for the given account and device.
    pub fn derive(seed: &IdentitySeed, account: u32, device_index: u32) -> Result<Self> {
        let path = DerivationPath::device(account, device_index)?;
        let master = MasterKey::derive_from_seed(seed.seed(), &path)?;
        let signing = master.to_signing_key();
        let public = DeviceKeyPublic(signing.verifying_key());
        Ok(Self {
            signing,
            public,
            account,
            device_index,
        })
    }

    /// Возвращает соответствующий публичный device-key.
    /// Returns the corresponding public device key.
    pub fn public(&self) -> DeviceKeyPublic {
        self.public
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Индекс устройства внутри аккаунта.
    /// Device index within the account.
    pub fn device_index(&self) -> u32 {
        self.device_index
    }

    /// Подписывает произвольное сообщение device-key.
    /// Signs an arbitrary message with the device key.
    ///
    /// Используется верхними слоями для подписи MLS application messages и
    /// Sealed Sender envelope-ов. Все вызовы должны передавать domain-separated
    /// данные с явным label.
    /// Used by upper layers to sign MLS application messages and Sealed Sender
    /// envelopes. All callers must pass domain-separated data with an explicit label.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.signing.sign(message)
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceKey(account={}, device_index={}, public={:?})",
            self.account, self.device_index, self.public
        )
    }
}

/// Публичный device-key; стабильный 32-байтовый идентификатор устройства внутри аккаунта.
/// Public device key; stable 32-byte device identifier within an account.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceKeyPublic(PublicVerifyingKey);

impl DeviceKeyPublic {
    /// Конструирует из 32-байтовой Ed25519 публичной точки.
    /// Constructs from a 32-byte Ed25519 public point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self(PublicVerifyingKey::from_bytes(bytes)?))
    }

    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Проверяет подпись над сообщением.
    /// Verifies a signature over a message.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.0.verify(message, signature)?;
        Ok(())
    }
}

impl fmt::Debug for DeviceKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(
            f,
            "DeviceKeyPublic({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    #[test]
    fn derive_deterministic_per_seed_account_device() {
        let seed = fresh_seed();
        let a = DeviceKey::derive(&seed, 0, 0).unwrap();
        let b = DeviceKey::derive(&seed, 0, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn different_devices_distinct_keys() {
        let seed = fresh_seed();
        let d0 = DeviceKey::derive(&seed, 0, 0).unwrap();
        let d1 = DeviceKey::derive(&seed, 0, 1).unwrap();
        assert_ne!(d0.public().to_bytes(), d1.public().to_bytes());
    }

    #[test]
    fn different_accounts_distinct_devices() {
        let seed = fresh_seed();
        let a = DeviceKey::derive(&seed, 0, 0).unwrap();
        let b = DeviceKey::derive(&seed, 1, 0).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let seed = fresh_seed();
        let dk = DeviceKey::derive(&seed, 0, 0).unwrap();
        let pubkey = dk.public();
        let msg = b"umbrellax-test-message";
        let sig = dk.sign(msg);
        pubkey
            .verify(msg, &sig)
            .expect("valid signature must verify");
    }
}
