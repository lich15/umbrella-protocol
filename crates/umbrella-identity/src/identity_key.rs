//! Identity-key — корень доверия пользователя; Ed25519, derived at canonical path.
//! Identity key — user's root of trust; Ed25519, derived at canonical path.
//!
//! Identity-key долгоживущий и публикуется в Key Transparency log как "идентичность"
//! пользователя. Подписывает device-keys (Sesame pattern) и используется для
//! authentication отправителя сообщений на верхнем уровне.
//!
//! Identity key is long-lived and published to the Key Transparency log as the user's
//! "identity". It signs device keys (Sesame pattern) and is used for top-level
//! authentication of message senders.
//!
//! **Канонический путь / Canonical path:** `m / 0x554D' / account' / 0'`
//! (см. `path::DerivationPath::identity` / see `path::DerivationPath::identity`).

use core::fmt;

use zeroize::ZeroizeOnDrop;

use umbrella_crypto_primitives::sig::{Ed25519Signature, PrivateSigningKey, PublicVerifyingKey};

use crate::derive::MasterKey;
use crate::error::Result;
use crate::path::DerivationPath;
use crate::seed::IdentitySeed;

/// Приватный identity-key пользователя; обнуляется при Drop, никогда не экспортируется наружу.
/// User's private identity key; zeroized on Drop, never exported externally.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKey {
    signing: PrivateSigningKey,
    #[zeroize(skip)]
    public: IdentityKeyPublic,
    #[zeroize(skip)]
    account: u32,
}

impl IdentityKey {
    /// Derive identity-key из IdentitySeed для указанного аккаунта.
    /// Derives the identity key from an IdentitySeed for the given account.
    ///
    /// Канонический путь: `m / 0x554D' / account' / 0'`.
    /// Canonical path: `m / 0x554D' / account' / 0'`.
    pub fn derive(seed: &IdentitySeed, account: u32) -> Result<Self> {
        Self::derive_from_seed_bytes(seed.seed(), account)
    }

    /// Derive identity-key напрямую из 64-байтового seed-материала.
    /// Derives the identity key directly from the 64-byte seed material.
    ///
    /// Используется ротацией identity (ADR-008): `code_recovery::derive_rotated_identity_material`
    /// возвращает 64-байтовый rotated_seed минуя BIP-39 mnemonic, и именно такой вход тут принимается.
    /// Used by identity rotation (ADR-008): `code_recovery::derive_rotated_identity_material`
    /// returns a 64-byte rotated_seed bypassing BIP-39 mnemonic, and this function accepts exactly that.
    pub(crate) fn derive_from_seed_bytes(seed_bytes: &[u8], account: u32) -> Result<Self> {
        let path = DerivationPath::identity(account)?;
        let master = MasterKey::derive_from_seed(seed_bytes, &path)?;
        let signing = master.to_signing_key();
        let public = IdentityKeyPublic(signing.verifying_key());
        Ok(Self {
            signing,
            public,
            account,
        })
    }

    /// Возвращает соответствующий публичный identity-key.
    /// Returns the corresponding public identity key.
    pub fn public(&self) -> IdentityKeyPublic {
        self.public
    }

    /// Индекс аккаунта (в дереве BIP-32 derivation).
    /// Account index (within the BIP-32 derivation tree).
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Подписывает произвольное сообщение identity-key.
    /// Signs an arbitrary message with the identity key.
    ///
    /// Использовать только для domain-separated данных с явным label —
    /// прямая подпись пользовательского контента запрещена контрактом высоких слоёв.
    /// Use only for domain-separated data with an explicit label —
    /// direct signing of user content is forbidden by the upper-layer contract.
    pub(crate) fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.signing.sign(message)
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityKey(account={}, public={:?})",
            self.account, self.public
        )
    }
}

/// Публичный identity-key пользователя; стабильный 32-байтовый идентификатор в KT log.
/// User's public identity key; the stable 32-byte identifier in the KT log.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityKeyPublic(PublicVerifyingKey);

impl IdentityKeyPublic {
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

    /// Проверяет подпись над сообщением; возвращает Ok при валидной подписи.
    /// Verifies a signature over a message; returns Ok if valid.
    pub(crate) fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.0.verify(message, signature)?;
        Ok(())
    }
}

impl fmt::Debug for IdentityKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(
            f,
            "IdentityKeyPublic({:02x}{:02x}{:02x}{:02x}…)",
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
    fn derive_is_deterministic_per_seed_and_account() {
        let seed = fresh_seed();
        let a = IdentityKey::derive(&seed, 0).unwrap();
        let b = IdentityKey::derive(&seed, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = IdentityKey::derive(&seed, 0).unwrap();
        let b = IdentityKey::derive(&seed, 1).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn restore_from_mnemonic_yields_same_identity_pubkey() {
        let original_seed = fresh_seed();
        let mnemonic = original_seed.to_mnemonic();
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

        let original_id = IdentityKey::derive(&original_seed, 0).unwrap();
        let restored_id = IdentityKey::derive(&restored_seed, 0).unwrap();
        assert_eq!(
            original_id.public().to_bytes(),
            restored_id.public().to_bytes(),
            "восстановление из мнемоники должно давать идентичный identity_pubkey"
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let id = IdentityKey::derive(&seed, 0).unwrap();
        let formatted = format!("{id:?}");
        // В Debug нет hex 32-байтового приватного ключа, только public.
        // The Debug output contains no 32-byte private key hex, only the public key.
        assert!(formatted.starts_with("IdentityKey(account=0,"));
        assert!(formatted.contains("public=IdentityKeyPublic("));
    }
}
