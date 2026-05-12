//! Sealed-identity X25519 keypair: долгоживущий X25519-ключ derived из того же seed, но по
//! отдельному hardened-пути, используется для Sealed Sender ECDH.
//! Sealed-identity X25519 keypair: long-lived X25519 key derived from the same seed but a
//! separate hardened path, used for Sealed Sender ECDH.
//!
//! ## Зачем отдельный ключ
//!
//! Ed25519 identity-key используется для подписей (authentication). X25519 sealed-identity —
//! для key agreement (decryption Sealed Sender envelope). Смешивание подписей и ECDH на одном
//! ключевом материале технически возможно через ed2curve birational map, но увеличивает
//! поверхность атаки (любая уязвимость в одном слое компрометирует оба). Разделяем: `m /
//! 0x554D' / account' / 0'` для Ed25519 identity, `m / 0x554D' / account' / 4'` для X25519
//! sealed-identity. Детерминистически выводятся из одного seed — восстановление по 24 словам
//! даёт оба.
//!
//! ## Why a separate key
//!
//! The Ed25519 identity key is used for signatures (authentication). The X25519
//! sealed-identity is used for key agreement (decrypting Sealed Sender envelopes). Reusing
//! one key material for signing and ECDH via the ed2curve birational map is technically
//! possible but enlarges the attack surface (any vulnerability in one layer compromises both).
//! We keep them separate: `m / 0x554D' / account' / 0'` for Ed25519 identity, `m / 0x554D' /
//! account' / 4'` for X25519 sealed-identity. Both derive deterministically from the same
//! seed — recovery from 24 words yields both.

use core::fmt;

use zeroize::ZeroizeOnDrop;

use umbrella_crypto_primitives::dh::{X25519Public, X25519Static, X25519_PUBLIC_LEN};
use umbrella_crypto_primitives::secret::SecretBytes;

use crate::derive::MasterKey;
use crate::error::Result;
use crate::path::DerivationPath;
use crate::seed::IdentitySeed;

/// Приватный X25519 ключ identity-уровня для Sealed Sender; обнуляется при Drop.
/// X25519 identity-level private key for Sealed Sender; zeroized on Drop.
#[derive(ZeroizeOnDrop)]
pub struct IdentityX25519Key {
    secret: X25519Static,
    #[zeroize(skip)]
    public: IdentityX25519KeyPublic,
    #[zeroize(skip)]
    account: u32,
}

impl IdentityX25519Key {
    /// Derive X25519 identity-key из IdentitySeed для указанного аккаунта.
    /// Derives the X25519 identity key from an IdentitySeed for the given account.
    ///
    /// Путь: `m / 0x554D' / account' / 4'`.
    /// Path: `m / 0x554D' / account' / 4'`.
    pub fn derive(seed: &IdentitySeed, account: u32) -> Result<Self> {
        Self::derive_from_seed_bytes(seed.seed(), account)
    }

    /// Derive X25519 identity-key напрямую из 64-байтового seed-материала.
    /// Derives the X25519 identity key directly from the 64-byte seed material.
    ///
    /// Используется ротацией identity (ADR-008); ровно как `IdentityKey::derive_from_seed_bytes`.
    /// Used by identity rotation (ADR-008); analogous to `IdentityKey::derive_from_seed_bytes`.
    pub(crate) fn derive_from_seed_bytes(seed_bytes: &[u8], account: u32) -> Result<Self> {
        let path = DerivationPath::sealed_identity(account)?;
        let master = MasterKey::derive_from_seed(seed_bytes, &path)?;
        // SLIP-0010 extended secret (32 байта) используется как X25519 scalar.
        // X25519 clamp'ит автоматически при `from_bytes`. Это RFC 7748 корректно.
        // SLIP-0010 extended secret (32 bytes) is reused as the X25519 scalar. X25519
        // clamps automatically in `from_bytes`. This is RFC 7748 compliant.
        let mut scalar = *master.secret().as_bytes();
        let secret = X25519Static::from_bytes(scalar);
        // Обнуляем локальную копию после передачи в X25519Static.
        // Zeroise the local copy after handing off to X25519Static.
        zeroize::Zeroize::zeroize(&mut scalar);
        let public = IdentityX25519KeyPublic(secret.public_key());
        Ok(Self {
            secret,
            public,
            account,
        })
    }

    /// Возвращает соответствующий публичный X25519 identity-ключ.
    /// Returns the corresponding public X25519 identity key.
    pub fn public(&self) -> IdentityX25519KeyPublic {
        self.public
    }

    /// Индекс аккаунта (в BIP-32 derivation дереве).
    /// Account index (within the BIP-32 derivation tree).
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Вычисляет ECDH shared secret с указанным X25519 публичным ключом.
    /// Computes an ECDH shared secret with the given X25519 public key.
    pub(crate) fn diffie_hellman(&self, peer: &IdentityX25519KeyPublic) -> SecretBytes<32> {
        self.secret.diffie_hellman(&peer.0)
    }
}

impl fmt::Debug for IdentityX25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityX25519Key(account={}, public={:?})",
            self.account, self.public
        )
    }
}

/// Публичный X25519 identity-ключ; публикуется в KT log вместе с Ed25519 identity-ключом.
/// X25519 identity public key; published in the KT log alongside the Ed25519 identity key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityX25519KeyPublic(X25519Public);

impl IdentityX25519KeyPublic {
    /// Конструирует из 32-байтового X25519 публичного представления.
    /// Constructs from a 32-byte X25519 public representation.
    pub fn from_bytes(bytes: &[u8; X25519_PUBLIC_LEN]) -> Result<Self> {
        Ok(Self(X25519Public::from_bytes(*bytes)?))
    }

    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_LEN] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for IdentityX25519KeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(
            f,
            "IdentityX25519KeyPublic({:02x}{:02x}{:02x}{:02x}…)",
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
        let a = IdentityX25519Key::derive(&seed, 0).unwrap();
        let b = IdentityX25519Key::derive(&seed, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = IdentityX25519Key::derive(&seed, 0).unwrap();
        let b = IdentityX25519Key::derive(&seed, 1).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn ed25519_and_x25519_identities_have_distinct_publics() {
        // Ed25519 и X25519 identity — разные ключи по построению (разные paths).
        use crate::IdentityKey;
        let seed = fresh_seed();
        let ed = IdentityKey::derive(&seed, 0).unwrap();
        let x = IdentityX25519Key::derive(&seed, 0).unwrap();
        assert_ne!(
            ed.public().to_bytes(),
            x.public().to_bytes(),
            "Ed25519 и X25519 identity не должны совпадать по байтам"
        );
    }

    #[test]
    fn dh_round_trip_two_parties() {
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let alice = IdentityX25519Key::derive(&seed_a, 0).unwrap();
        let bob = IdentityX25519Key::derive(&seed_b, 0).unwrap();

        let shared_ab = alice.diffie_hellman(&bob.public());
        let shared_ba = bob.diffie_hellman(&alice.public());
        assert_eq!(shared_ab, shared_ba, "ECDH симметричен");
    }

    #[test]
    fn restore_from_mnemonic_yields_same_x25519_public() {
        let seed = fresh_seed();
        let mnemonic = seed.to_mnemonic();
        let restored =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let original_x = IdentityX25519Key::derive(&seed, 0).unwrap();
        let restored_x = IdentityX25519Key::derive(&restored, 0).unwrap();
        assert_eq!(
            original_x.public().to_bytes(),
            restored_x.public().to_bytes(),
            "восстановление через 24 слова должно вернуть тот же X25519 identity"
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let x = IdentityX25519Key::derive(&seed, 0).unwrap();
        let formatted = format!("{x:?}");
        assert!(formatted.starts_with("IdentityX25519Key(account=0,"));
        assert!(!formatted.contains("secret"));
    }

    #[test]
    fn public_from_bytes_round_trip() {
        let seed = fresh_seed();
        let x = IdentityX25519Key::derive(&seed, 0).unwrap();
        let bytes = x.public().to_bytes();
        let reparsed = IdentityX25519KeyPublic::from_bytes(&bytes).unwrap();
        assert_eq!(reparsed, x.public());
    }
}
