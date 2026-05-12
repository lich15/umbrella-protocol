//! Cloud-wrap recovery X-Wing keypair для блока 8.7 Hybrid PQ wrap.
//! Cloud-wrap recovery X-Wing keypair for block 8.7 Hybrid PQ wrap.
//!
//! # Назначение
//!
//! Recovery X-Wing keypair защищает recovery key от **квантового адверсария**
//! который компрометирует main scalar `K` через Shor algorithm применённый к
//! публичному `Y = K · G`. Даже зная `K` (и поэтому полный V1 layer), adversary
//! без recovery X-Wing private key не decapsulates outer X-Wing envelope над
//! V1 WrappedKey.
//!
//! Используется только в `umbrella-backup::cloud_wrap::pq_wrap` (V2 hybrid
//! wrapping layer); из hot path messaging исключён.
//!
//! # Purpose
//!
//! The recovery X-Wing keypair protects the recovery key against a **quantum
//! adversary** who compromises the main scalar `K` via Shor's algorithm
//! applied to public `Y = K · G`. Even knowing `K` (and therefore the full V1
//! layer), an adversary without the recovery X-Wing private key cannot
//! decapsulate the outer X-Wing envelope over the V1 WrappedKey.
//!
//! Used only in `umbrella-backup::cloud_wrap::pq_wrap` (V2 hybrid wrapping
//! layer); kept out of the messaging hot path.
//!
//! # Derive из BIP-39 IdentitySeed
//!
//! X-Wing keygen seed (32 bytes) деривируется через
//! `HKDF-SHA-256(seed_bytes, salt=account_be, info="umbrellax-cloud-wrap-recovery-xwing-v1")`
//! из 64-байтного BIP-39 PBKDF2 seed material. Pattern идентичен
//! `SlhDsaBackupKey` блока 8.3 (FIPS-style HKDF derivation, не SLIP-0010 BIP-32
//! потому что X-Wing seed — не Ed25519 chain code).
//!
//! Та же 24-word BIP-39 mnemonic восстанавливает classical Ed25519 identity,
//! hybrid ML-DSA-65 identity (блок 8.3), SLH-DSA backup (блок 8.3) **и** этот
//! cloud-wrap recovery X-Wing — single mnemonic, single recovery flow
//! (постулат 4: privacy first; постулат 14: senior+ unified UX).
//!
//! # Derive from BIP-39 IdentitySeed
//!
//! The X-Wing keygen seed (32 bytes) is derived via
//! `HKDF-SHA-256(seed_bytes, salt=account_be, info="umbrellax-cloud-wrap-recovery-xwing-v1")`
//! from the 64-byte BIP-39 PBKDF2 seed material. The pattern matches
//! `SlhDsaBackupKey` from block 8.3 (FIPS-style HKDF derivation, not SLIP-0010
//! BIP-32 because the X-Wing seed is not an Ed25519 chain code).
//!
//! The same 24-word BIP-39 mnemonic restores classical Ed25519 identity, hybrid
//! ML-DSA-65 identity (block 8.3), SLH-DSA backup (block 8.3) **and** this
//! cloud-wrap recovery X-Wing — single mnemonic, single recovery flow.
//!
//! # Domain separation
//!
//! HKDF info-context `"umbrellax-cloud-wrap-recovery-xwing-v1"` обеспечивает
//! что recovery X-Wing seed **byte-distinct** от SLH-DSA backup seed
//! (`umbrellax-slh-dsa-backup-v1`) и от identity hybrid seeds. Cross-protocol
//! seed reuse исключён.
//!
//! # Domain separation
//!
//! The HKDF info-context `"umbrellax-cloud-wrap-recovery-xwing-v1"` ensures the
//! recovery X-Wing seed is **byte-distinct** from the SLH-DSA backup seed
//! (`umbrellax-slh-dsa-backup-v1`) and from identity hybrid seeds. Cross-protocol
//! seed reuse is excluded.

use core::fmt;

use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha256;

use umbrella_pq::{
    xwing_decaps, xwing_keygen_from_seed, XWingPublicKey, XWingSecretSeed, XWING_CIPHERTEXT_LEN,
    XWING_KEYGEN_SEED_LEN, XWING_PUBLIC_KEY_LEN, XWING_SHARED_SECRET_LEN,
};

use crate::error::Result;
use crate::seed::IdentitySeed;

/// HKDF info-context для cloud-wrap recovery X-Wing keypair derivation.
/// Stable wire-level invariant.
///
/// HKDF info-context for cloud-wrap recovery X-Wing keypair derivation.
/// Stable wire-level invariant.
pub const CLOUD_WRAP_RECOVERY_HKDF_INFO: &[u8] = b"umbrellax-cloud-wrap-recovery-xwing-v1";

/// Приватный recovery X-Wing keypair для cloud-wrap V2 (Hybrid PQ wrap).
///
/// Хранит `XWingSecretSeed` (32-byte secret в `SecretBox` с zeroize on drop).
/// Используется только в backup recovery flows; не в hot path messaging.
///
/// Private recovery X-Wing keypair for cloud-wrap V2 (Hybrid PQ wrap).
///
/// Holds an `XWingSecretSeed` (32-byte secret in `SecretBox` with zeroize on
/// drop). Used only in backup recovery flows; not in the messaging hot path.
pub struct CloudWrapRecoveryKey {
    /// Приватный X-Wing seed (`XWingSecretSeed` zeroizes on drop).
    /// Private X-Wing seed (`XWingSecretSeed` zeroizes on drop).
    secret: XWingSecretSeed,

    /// Кешированный публичный X-Wing key.
    /// Cached public X-Wing key.
    public: CloudWrapRecoveryKeyPublic,

    /// Индекс аккаунта.
    /// Account index.
    account: u32,
}

impl CloudWrapRecoveryKey {
    /// Derive recovery X-Wing keypair детерминистично из IdentitySeed для аккаунта.
    /// Derives the recovery X-Wing keypair deterministically from an IdentitySeed.
    pub fn derive(seed: &IdentitySeed, account: u32) -> Result<Self> {
        Self::derive_from_seed_bytes(seed.seed(), account)
    }

    /// Derive напрямую из 64-байтового BIP-39 PBKDF2 seed material.
    /// Derives directly from 64-byte BIP-39 PBKDF2 seed material.
    pub(crate) fn derive_from_seed_bytes(seed_bytes: &[u8], account: u32) -> Result<Self> {
        let xwing_seed = derive_xwing_keygen_seed(seed_bytes, account);
        let (pk, sk) = xwing_keygen_from_seed(&xwing_seed)?;
        Ok(Self {
            secret: sk,
            public: CloudWrapRecoveryKeyPublic {
                pubkey: pk,
                account,
            },
            account,
        })
    }

    /// Возвращает публичную часть.
    /// Returns the public part.
    pub fn public(&self) -> &CloudWrapRecoveryKeyPublic {
        &self.public
    }

    /// Возвращает приватный seed (для прямого доступа в pq_wrap unwrap path).
    /// Returns the private seed (for direct access in the pq_wrap unwrap path).
    pub fn secret(&self) -> &XWingSecretSeed {
        &self.secret
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// X-Wing decapsulation: recovers shared secret из ciphertext под этот recovery key.
    ///
    /// Используется в `umbrella-backup::cloud_wrap::pq_wrap::unwrap_v2_to_v1` для
    /// раскрытия V2 envelope. Возвращает `SecretBox<[u8; 32]>` с zeroize on drop.
    ///
    /// X-Wing decapsulation: recovers shared secret from ciphertext under this
    /// recovery key. Used by `umbrella-backup::cloud_wrap::pq_wrap::unwrap_v2_to_v1`
    /// to open the V2 envelope. Returns `SecretBox<[u8; 32]>` with zeroize on drop.
    pub fn decapsulate(
        &self,
        ct: &[u8; XWING_CIPHERTEXT_LEN],
    ) -> Result<SecretBox<[u8; XWING_SHARED_SECRET_LEN]>> {
        Ok(xwing_decaps(&self.secret, ct)?)
    }
}

impl fmt::Debug for CloudWrapRecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug не должен утечь secret seed (постулат 14: senior+ memory hygiene).
        // Debug must not leak the secret seed (postulate 14: senior+ memory hygiene).
        write!(
            f,
            "CloudWrapRecoveryKey(account={}, public={:?})",
            self.account, self.public
        )
    }
}

/// Публичная часть recovery X-Wing keypair.
/// Public part of the recovery X-Wing keypair.
#[derive(Clone)]
pub struct CloudWrapRecoveryKeyPublic {
    /// X-Wing public key (1216 bytes = ML-KEM-768 pk 1184 || X25519 pk 32).
    /// X-Wing public key (1216 bytes = ML-KEM-768 pk 1184 || X25519 pk 32).
    pubkey: XWingPublicKey,

    /// Индекс аккаунта.
    /// Account index.
    account: u32,
}

impl CloudWrapRecoveryKeyPublic {
    /// Возвращает ссылку на X-Wing public key.
    /// Returns a reference to the X-Wing public key.
    pub fn pubkey(&self) -> &XWingPublicKey {
        &self.pubkey
    }

    /// Возвращает байты публичного ключа (1216 bytes).
    /// Returns the public-key bytes (1216 bytes).
    pub fn to_bytes(&self) -> [u8; XWING_PUBLIC_KEY_LEN] {
        *self.pubkey.as_bytes()
    }

    /// Десериализация публичного ключа из 1216 bytes.
    /// Deserialize the public key from 1216 bytes.
    pub fn from_bytes(bytes: &[u8], account: u32) -> Result<Self> {
        let pubkey = XWingPublicKey::from_bytes(bytes)?;
        Ok(Self { pubkey, account })
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }
}

impl fmt::Debug for CloudWrapRecoveryKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncated 4-byte prefix для debug; full pubkey не нужен в логах.
        // Truncated 4-byte prefix for debug; full pubkey not needed in logs.
        let bytes = self.to_bytes();
        write!(
            f,
            "CloudWrapRecoveryKeyPublic(account={}, pubkey={:02x}{:02x}{:02x}{:02x}…)",
            self.account, bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

impl PartialEq for CloudWrapRecoveryKeyPublic {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account && self.to_bytes() == other.to_bytes()
    }
}

impl Eq for CloudWrapRecoveryKeyPublic {}

/// Derive 32-byte X-Wing keygen seed через HKDF-SHA256.
///
/// Salt = `account.to_be_bytes()` (4 bytes); ikm = BIP-39 64-byte seed material;
/// info = `CLOUD_WRAP_RECOVERY_HKDF_INFO`; output 32 bytes (X-Wing keygen seed length).
///
/// Derive a 32-byte X-Wing keygen seed via HKDF-SHA256.
///
/// Salt = `account.to_be_bytes()` (4 bytes); ikm = BIP-39 64-byte seed material;
/// info = `CLOUD_WRAP_RECOVERY_HKDF_INFO`; output 32 bytes (X-Wing keygen seed length).
fn derive_xwing_keygen_seed(seed_bytes: &[u8], account: u32) -> [u8; XWING_KEYGEN_SEED_LEN] {
    let salt = account.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), seed_bytes);
    let mut okm = [0u8; XWING_KEYGEN_SEED_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF-SHA256 expand to 32 bytes always fits per RFC 5869"
    )]
    hk.expand(CLOUD_WRAP_RECOVERY_HKDF_INFO, &mut okm)
        .expect("HKDF-SHA256 32-byte expansion always fits");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;
    use secrecy::ExposeSecret;
    use umbrella_pq::xwing_encaps;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    /// Derive детерминистичен per (seed, account).
    /// Derive is deterministic per (seed, account).
    #[test]
    fn cloud_wrap_recovery_derive_deterministic_per_seed_and_account() {
        let seed = fresh_seed();
        let a = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();
        let b = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// Разные accounts → разные pubkey (HKDF salt = account_be).
    /// Different accounts → different pubkeys (HKDF salt = account_be).
    #[test]
    fn cloud_wrap_recovery_different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();
        let b = CloudWrapRecoveryKey::derive(&seed, 1).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// Разные seeds → разные pubkey (одинаковый account).
    /// Different seeds → different pubkeys (same account).
    #[test]
    fn cloud_wrap_recovery_different_seeds_distinct_keys() {
        let s1 = fresh_seed();
        let s2 = fresh_seed();
        let a = CloudWrapRecoveryKey::derive(&s1, 0).unwrap();
        let b = CloudWrapRecoveryKey::derive(&s2, 0).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// Encaps (через published pubkey) + decaps (через recovery secret) дают
    /// совпадающий shared secret — base round-trip of X-Wing layer.
    ///
    /// Encaps (via published pubkey) + decaps (via recovery secret) yield matching
    /// shared secrets — the base round-trip of the X-Wing layer.
    #[test]
    fn cloud_wrap_recovery_encaps_decaps_roundtrip() {
        let seed = fresh_seed();
        let recovery = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let (ct, ss_sender) = xwing_encaps(&mut rng, recovery.public().pubkey()).unwrap();
        let ss_recv = recovery.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender.expose_secret(), ss_recv.expose_secret());
    }

    /// Decapsulation под другой recovery key → shared secret НЕ совпадает.
    /// Decapsulation under a different recovery key → shared secret does NOT match.
    #[test]
    fn cloud_wrap_recovery_wrong_secret_yields_different_shared() {
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let recovery_a = CloudWrapRecoveryKey::derive(&seed_a, 0).unwrap();
        let recovery_b = CloudWrapRecoveryKey::derive(&seed_b, 0).unwrap();
        let mut rng = OsRng;
        let (ct, ss_a) = xwing_encaps(&mut rng, recovery_a.public().pubkey()).unwrap();
        // recovery_b может decaps без panic (X-Wing implicit rejection делает
        // shared secret pseudo-random если ct corrupted relative к sk), но result
        // не совпадает с ss_a.
        // recovery_b can decaps without panic (X-Wing implicit rejection makes the
        // shared secret pseudo-random if ct is corrupted relative to sk), but the
        // result will not match ss_a.
        if let Ok(ss_b) = recovery_b.decapsulate(&ct) {
            assert_ne!(
                ss_a.expose_secret(),
                ss_b.expose_secret(),
                "different recovery secrets must produce different shared secrets"
            );
        }
        // Если decaps вернул ошибку — это тоже OK (cross-keypair X-Wing combiner отказ).
        // If decaps returned an error — also OK (cross-keypair X-Wing combiner rejection).
    }

    /// Восстановление через BIP-39 mnemonic даёт identical recovery keypair.
    /// Restoring through a BIP-39 mnemonic yields an identical recovery keypair.
    #[test]
    fn cloud_wrap_recovery_restore_from_mnemonic_yields_same_pubkey() {
        let original_seed = fresh_seed();
        let mnemonic = original_seed.to_mnemonic();
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

        let original = CloudWrapRecoveryKey::derive(&original_seed, 0).unwrap();
        let restored = CloudWrapRecoveryKey::derive(&restored_seed, 0).unwrap();
        assert_eq!(
            original.public().to_bytes(),
            restored.public().to_bytes(),
            "restore from mnemonic must yield identical recovery pubkey"
        );
    }

    /// Pubkey byte roundtrip.
    /// Pubkey byte roundtrip.
    #[test]
    fn cloud_wrap_recovery_pubkey_byte_roundtrip() {
        let seed = fresh_seed();
        let recovery = CloudWrapRecoveryKey::derive(&seed, 5).unwrap();
        let original = recovery.public().clone();
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), XWING_PUBLIC_KEY_LEN);
        let decoded = CloudWrapRecoveryKeyPublic::from_bytes(&bytes, 5).unwrap();
        assert_eq!(decoded, original);
    }

    /// Pubkey невалидной длины отвергается.
    /// Pubkey of invalid length is rejected.
    #[test]
    fn cloud_wrap_recovery_pubkey_invalid_length_rejected() {
        let bad = vec![0u8; 100];
        let result = CloudWrapRecoveryKeyPublic::from_bytes(&bad, 0);
        assert!(result.is_err());
    }

    /// Account метаданные сохраняются.
    /// Account metadata is preserved.
    #[test]
    fn cloud_wrap_recovery_account_preserved() {
        let seed = fresh_seed();
        let key = CloudWrapRecoveryKey::derive(&seed, 42).unwrap();
        assert_eq!(key.account(), 42);
        assert_eq!(key.public().account(), 42);
    }

    /// Debug не должен утечь secret.
    /// Debug must not leak the secret.
    #[test]
    fn cloud_wrap_recovery_debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let key = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();
        let formatted = format!("{key:?}");
        assert!(formatted.starts_with("CloudWrapRecoveryKey(account=0,"));
        assert!(formatted.contains("public=CloudWrapRecoveryKeyPublic("));
        // Должна быть truncated 4-byte preview, а не полные 1216 bytes.
        // Should be a truncated 4-byte preview, not the full 1216 bytes.
        assert!(formatted.len() < 200);
    }

    /// Pubkey equality учитывает и pubkey bytes, и account.
    /// Pubkey equality considers both pubkey bytes and account.
    #[test]
    fn cloud_wrap_recovery_pubkey_equality_includes_account() {
        let seed = fresh_seed();
        let bytes = CloudWrapRecoveryKey::derive(&seed, 0)
            .unwrap()
            .public()
            .to_bytes();
        let pk_a = CloudWrapRecoveryKeyPublic::from_bytes(&bytes, 0).unwrap();
        let pk_b = CloudWrapRecoveryKeyPublic::from_bytes(&bytes, 1).unwrap();
        assert_ne!(pk_a, pk_b, "different account → not equal");
    }

    /// HKDF info-context — wire-level invariant.
    /// HKDF info-context — wire-level invariant.
    #[test]
    fn cloud_wrap_recovery_hkdf_info_constant() {
        assert_eq!(
            CLOUD_WRAP_RECOVERY_HKDF_INFO,
            b"umbrellax-cloud-wrap-recovery-xwing-v1"
        );
    }

    /// Recovery X-Wing seed **byte-distinct** от SLH-DSA backup seed (block 8.3)
    /// для same (seed, account) благодаря разным HKDF info.
    ///
    /// Recovery X-Wing seed is **byte-distinct** from the SLH-DSA backup seed
    /// (block 8.3) for the same (seed, account) thanks to different HKDF info.
    #[test]
    fn cloud_wrap_recovery_distinct_from_slh_dsa_backup_seed() {
        // Прямое сравнение HKDF outputs (hexvar.); не возвращаем actual SLH-DSA
        // pubkey т.к. он другой алгоритм, но проверяем что keygen seed разный.
        // Direct comparison of HKDF outputs (white-box); we don't return the actual
        // SLH-DSA pubkey since it's a different algorithm, but verify the keygen
        // seed differs.
        let seed = fresh_seed();
        let cloud_wrap_seed = derive_xwing_keygen_seed(seed.seed(), 0);

        // Imitate SLH-DSA backup seed derivation (block 8.3 pattern, info distinct).
        // Imitate SLH-DSA backup seed derivation (block 8.3 pattern, distinct info).
        let salt = 0u32.to_be_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), seed.seed());
        let mut slh_seed = [0u8; 32];
        hk.expand(b"umbrellax-slh-dsa-backup-v1", &mut slh_seed)
            .unwrap();

        assert_ne!(
            cloud_wrap_seed, slh_seed,
            "different HKDF info must yield distinct seeds"
        );
    }
}
