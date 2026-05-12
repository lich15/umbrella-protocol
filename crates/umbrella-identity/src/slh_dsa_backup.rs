//! SLH-DSA-128f-simple backup signature key для catastrophic recovery flow.
//! SLH-DSA-128f-simple backup signature key for the catastrophic recovery flow.
//!
//! # Назначение
//!
//! Hash-based stateless backup signature scheme, **изолированный** от hot path.
//! Используется только в:
//!
//! - **Catastrophic recovery подпись** — когда identity key утерян и нужен fallback
//!   через BIP-39 mnemonic + дополнительный SLH-DSA seed; KT принимает rotation
//!   если SLH-DSA verify ОК независимо от того, что Ed25519/ML-DSA-65 ключи
//!   возможно скомпрометированы (защита если найдут lattice-attack на ML-DSA).
//! - **Version-locking attestation** для производственных билдов (раз в release).
//! - **Code signing метаданных KAT vectors** в `umbrella-vectors` (offline процесс).
//!
//! **Не используется в hot path** — 17 KB подпись и ~15 ms signing time не подходят
//! для steady-state messaging.
//!
//! # Purpose
//!
//! Hash-based stateless backup signature scheme, **isolated** from the hot path.
//! Used only for:
//!
//! - **Catastrophic recovery signature** — when the identity key is lost and a
//!   fallback via BIP-39 mnemonic + extra SLH-DSA seed is needed; KT accepts
//!   the rotation if SLH-DSA verifies OK regardless of whether the Ed25519/ML-DSA-65
//!   keys may be compromised (protects against discovered lattice attacks on ML-DSA).
//! - **Version-locking attestation** for production builds (once per release).
//! - **Code signing for KAT vector metadata** in `umbrella-vectors` (offline process).
//!
//! **Not used in hot path** — the 17 KB signature and ~15 ms signing time are not
//! suitable for steady-state messaging.
//!
//! # Derive из BIP-39 IdentitySeed
//!
//! SLH-DSA-128f keypair детерминистично выводится через
//! `ChaCha20Rng::from_seed(HKDF-SHA-256(seed_bytes, salt=account_be, info=...))`,
//! где info = `"umbrellax-slh-dsa-backup-v1"`. Это даёт recovery flow: одна BIP-39
//! mnemonic восстанавливает classical Ed25519, hybrid ML-DSA-65, **и** SLH-DSA backup.
//!
//! # Derive from BIP-39 IdentitySeed
//!
//! The SLH-DSA-128f keypair is derived deterministically through
//! `ChaCha20Rng::from_seed(HKDF-SHA-256(seed_bytes, salt=account_be, info=...))`,
//! where info = `"umbrellax-slh-dsa-backup-v1"`. This yields a recovery flow: one
//! BIP-39 mnemonic restores classical Ed25519, hybrid ML-DSA-65, **and** SLH-DSA backup.
//!
//! # Domain separation
//!
//! Все SLH-DSA-128f подписи в backup flow идут с context-string
//! `"umbrellax-slh-dsa-backup-rotation-v1"`. Это предотвращает cross-protocol
//! signature reuse (например, SLH-DSA подпись для rotation proof не может
//! быть переиспользована как version-locking attestation подпись).
//!
//! # Domain separation
//!
//! All SLH-DSA-128f signatures in the backup flow use context string
//! `"umbrellax-slh-dsa-backup-rotation-v1"`. This prevents cross-protocol signature
//! reuse (e.g., a SLH-DSA rotation-proof signature cannot be reused as a version-locking
//! attestation signature).

use core::fmt;

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;

use umbrella_pq::{
    slh_dsa_128f_keygen, slh_dsa_128f_sign, slh_dsa_128f_verify, SlhDsa128fPublicKey,
    SlhDsa128fSecretKey, SlhDsa128fSignature, SLH_DSA_128F_PUBLIC_KEY_LEN,
};

use crate::error::Result;
use crate::seed::IdentitySeed;

/// HKDF info-context для SLH-DSA backup keypair derivation.
/// Stable wire-level invariant.
///
/// HKDF info-context for SLH-DSA backup keypair derivation.
/// Stable wire-level invariant.
const SLH_DSA_BACKUP_HKDF_INFO: &[u8] = b"umbrellax-slh-dsa-backup-v1";

/// Domain separation context для SLH-DSA подписей в catastrophic recovery flow.
/// Передаётся как `context` параметр в `slh_dsa_128f_sign/verify`.
///
/// Domain separation context for SLH-DSA signatures in the catastrophic recovery flow.
/// Passed as the `context` parameter to `slh_dsa_128f_sign/verify`.
pub const SLH_DSA_BACKUP_ROTATION_CONTEXT: &[u8] = b"umbrellax-slh-dsa-backup-rotation-v1";

/// Длина seed для ChaCha20Rng (внутренний invariant rand_chacha 0.3).
/// ChaCha20Rng seed length (rand_chacha 0.3 internal invariant).
const CHACHA20_SEED_LEN: usize = 32;

/// Приватный SLH-DSA backup ключ для catastrophic recovery.
///
/// Хранит `SlhDsa128fSecretKey` (64-byte secret в `SecretBox` с zeroize on drop).
/// Не используется для регулярных messaging operations — только для backup flows.
///
/// Private SLH-DSA backup key for catastrophic recovery.
///
/// Holds an `SlhDsa128fSecretKey` (64-byte secret in `SecretBox` with zeroize on drop).
/// Not used for regular messaging operations — only for backup flows.
pub struct SlhDsaBackupKey {
    /// Приватный SLH-DSA-128f-simple ключ.
    /// Private SLH-DSA-128f-simple key.
    secret: SlhDsa128fSecretKey,

    /// Кешированный публичный ключ.
    /// Cached public key.
    public: SlhDsaBackupKeyPublic,

    /// Индекс аккаунта.
    /// Account index.
    account: u32,
}

impl SlhDsaBackupKey {
    /// Derive SLH-DSA backup keypair детерминистично из IdentitySeed для аккаунта.
    /// Derives the SLH-DSA backup keypair deterministically from an IdentitySeed for an account.
    pub fn derive(seed: &IdentitySeed, account: u32) -> Result<Self> {
        Self::derive_from_seed_bytes(seed.seed(), account)
    }

    /// Derive напрямую из 64-байтового seed-материала.
    /// Derives directly from 64-byte seed material.
    pub(crate) fn derive_from_seed_bytes(seed_bytes: &[u8], account: u32) -> Result<Self> {
        let rng_seed = derive_slh_dsa_rng_seed(seed_bytes, account);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let (pk, sk) = slh_dsa_128f_keygen(&mut rng)?;
        Ok(Self {
            secret: sk,
            public: SlhDsaBackupKeyPublic {
                pubkey: pk,
                account,
            },
            account,
        })
    }

    /// Возвращает публичную часть.
    /// Returns the public part.
    pub fn public(&self) -> &SlhDsaBackupKeyPublic {
        &self.public
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Подписывает rotation-proof сообщение SLH-DSA backup ключом.
    ///
    /// Rotation-proof по SPEC-09 / ADR-008: сообщение содержит canonical encoding
    /// нового identity_pubkey + KT log seq номер + timestamp. SLH-DSA подпись над
    /// этим сообщением + domain context = доказательство что владелец BIP-39 mnemonic
    /// (с дополнительным SLH-DSA seed) разрешает rotation.
    ///
    /// Signs a rotation-proof message with the SLH-DSA backup key.
    ///
    /// Per SPEC-09 / ADR-008, the rotation proof message contains the canonical encoding
    /// of the new identity_pubkey + KT log seq + timestamp. The SLH-DSA signature over
    /// this message + domain context proves that the owner of the BIP-39 mnemonic
    /// (with the additional SLH-DSA seed) authorises the rotation.
    pub fn sign_rotation_proof<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<SlhDsa128fSignature> {
        Ok(slh_dsa_128f_sign(
            rng,
            &self.secret,
            message,
            SLH_DSA_BACKUP_ROTATION_CONTEXT,
        )?)
    }
}

impl fmt::Debug for SlhDsaBackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SlhDsaBackupKey(account={}, public={:?})",
            self.account, self.public
        )
    }
}

/// Публичная часть SLH-DSA backup ключа.
/// Public part of the SLH-DSA backup key.
#[derive(Clone)]
pub struct SlhDsaBackupKeyPublic {
    pubkey: SlhDsa128fPublicKey,
    account: u32,
}

impl SlhDsaBackupKeyPublic {
    /// Возвращает байты публичного ключа (32 bytes по FIPS 205).
    /// Returns the public-key bytes (32 bytes per FIPS 205).
    pub fn to_bytes(&self) -> [u8; SLH_DSA_128F_PUBLIC_KEY_LEN] {
        *self.pubkey.as_bytes()
    }

    /// Десериализация публичного ключа из 32 bytes.
    /// Deserialize the public key from 32 bytes.
    pub fn from_bytes(bytes: &[u8], account: u32) -> Result<Self> {
        let pubkey = SlhDsa128fPublicKey::from_bytes(bytes)?;
        Ok(Self { pubkey, account })
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Проверяет SLH-DSA backup rotation-proof подпись.
    ///
    /// Возвращает `Ok(())` если подпись валидна для (message, pubkey, domain context).
    /// Иначе `Err(IdentityError::Pq(PqError::SlhDsaSignatureVerificationFailed))`.
    ///
    /// Verifies an SLH-DSA backup rotation-proof signature.
    ///
    /// Returns `Ok(())` if the signature is valid for (message, pubkey, domain context).
    /// Otherwise `Err(IdentityError::Pq(PqError::SlhDsaSignatureVerificationFailed))`.
    pub fn verify_rotation_proof(&self, message: &[u8], sig: &SlhDsa128fSignature) -> Result<()> {
        Ok(slh_dsa_128f_verify(
            &self.pubkey,
            message,
            SLH_DSA_BACKUP_ROTATION_CONTEXT,
            sig,
        )?)
    }
}

impl fmt::Debug for SlhDsaBackupKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(
            f,
            "SlhDsaBackupKeyPublic(account={}, pubkey={:02x}{:02x}{:02x}{:02x}…)",
            self.account, bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

impl PartialEq for SlhDsaBackupKeyPublic {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account && self.to_bytes() == other.to_bytes()
    }
}

impl Eq for SlhDsaBackupKeyPublic {}

/// Derive 32-байтовый ChaCha20Rng seed для SLH-DSA backup keypair.
/// Derive a 32-byte ChaCha20Rng seed for the SLH-DSA backup keypair.
fn derive_slh_dsa_rng_seed(seed_bytes: &[u8], account: u32) -> [u8; CHACHA20_SEED_LEN] {
    let salt = account.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), seed_bytes);
    let mut okm = [0u8; CHACHA20_SEED_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF expand to 32 bytes always fits per RFC 5869"
    )]
    hk.expand(SLH_DSA_BACKUP_HKDF_INFO, &mut okm)
        .expect("HKDF expand to 32 bytes always fits");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IdentityError;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    #[test]
    fn slh_dsa_backup_derive_deterministic_per_seed_and_account() {
        let seed = fresh_seed();
        let a = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let b = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn slh_dsa_backup_different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let b = SlhDsaBackupKey::derive(&seed, 1).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn slh_dsa_backup_sign_verify_roundtrip() {
        let seed = fresh_seed();
        let backup = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let proof_msg = b"new_identity_pubkey || kt_seq=42 || ts=1234567890";
        let sig = backup.sign_rotation_proof(&mut rng, proof_msg).unwrap();
        backup
            .public()
            .verify_rotation_proof(proof_msg, &sig)
            .expect("rotation proof must verify");
    }

    #[test]
    fn slh_dsa_backup_tampered_message_rejected() {
        let seed = fresh_seed();
        let backup = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let sig = backup.sign_rotation_proof(&mut rng, b"original").unwrap();
        let result = backup.public().verify_rotation_proof(b"tampered", &sig);
        assert!(matches!(
            result,
            Err(IdentityError::Pq(
                umbrella_pq::PqError::SlhDsaSignatureVerificationFailed
            ))
        ));
    }

    #[test]
    fn slh_dsa_backup_pubkey_byte_roundtrip() {
        let seed = fresh_seed();
        let backup = SlhDsaBackupKey::derive(&seed, 5).unwrap();
        let original = backup.public().clone();
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), SLH_DSA_128F_PUBLIC_KEY_LEN);
        let decoded = SlhDsaBackupKeyPublic::from_bytes(&bytes, 5).unwrap();
        assert_eq!(decoded, original);
    }

    /// Восстановление через BIP-39 mnemonic должно дать identical SLH-DSA backup keypair.
    /// Restoring through a BIP-39 mnemonic must yield an identical SLH-DSA backup keypair.
    #[test]
    fn slh_dsa_backup_restore_from_mnemonic_yields_same_pubkey() {
        let original_seed = fresh_seed();
        let mnemonic = original_seed.to_mnemonic();
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

        let original = SlhDsaBackupKey::derive(&original_seed, 0).unwrap();
        let restored = SlhDsaBackupKey::derive(&restored_seed, 0).unwrap();
        assert_eq!(
            original.public().to_bytes(),
            restored.public().to_bytes(),
            "restore from mnemonic must yield identical SLH-DSA backup pubkey"
        );
    }

    /// Adversarial: подпись с другим контекстом не должна проходить через verify_rotation_proof.
    /// Это проверяет что domain context закреплён в публичном API и не подменяется.
    /// Adversarial: a signature with a different context must not pass verify_rotation_proof.
    /// This verifies that the domain context is enforced in the public API.
    #[test]
    fn slh_dsa_backup_wrong_context_rejected() {
        let seed = fresh_seed();
        let backup = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let msg = b"rotation proof";

        // Подписать с другим контекстом напрямую через umbrella_pq API.
        // Sign with a different context directly through umbrella_pq API.
        let other_ctx = b"different-context";
        let sig_with_wrong_ctx =
            umbrella_pq::slh_dsa_128f_sign(&mut rng, &backup.secret, msg, other_ctx).unwrap();

        // Теперь verify_rotation_proof должен отклонить — он использует
        // SLH_DSA_BACKUP_ROTATION_CONTEXT, а подписано с другим контекстом.
        // Now verify_rotation_proof must reject — it uses SLH_DSA_BACKUP_ROTATION_CONTEXT
        // while the signature was made with a different context.
        let result = backup
            .public()
            .verify_rotation_proof(msg, &sig_with_wrong_ctx);
        assert!(matches!(
            result,
            Err(IdentityError::Pq(
                umbrella_pq::PqError::SlhDsaSignatureVerificationFailed
            ))
        ));
    }

    #[test]
    fn slh_dsa_backup_pubkey_invalid_length_rejected() {
        let bad = vec![0u8; 100];
        let result = SlhDsaBackupKeyPublic::from_bytes(&bad, 0);
        assert!(matches!(
            result,
            Err(IdentityError::Pq(
                umbrella_pq::PqError::SlhDsaInvalidPublicKey { got: 100 }
            ))
        ));
    }

    #[test]
    fn slh_dsa_backup_debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let backup = SlhDsaBackupKey::derive(&seed, 0).unwrap();
        let formatted = format!("{backup:?}");
        assert!(formatted.starts_with("SlhDsaBackupKey(account=0,"));
        assert!(formatted.contains("public=SlhDsaBackupKeyPublic("));
    }

    #[test]
    fn slh_dsa_backup_domain_constants() {
        assert_eq!(
            SLH_DSA_BACKUP_ROTATION_CONTEXT,
            b"umbrellax-slh-dsa-backup-rotation-v1"
        );
        assert_eq!(SLH_DSA_BACKUP_HKDF_INFO, b"umbrellax-slh-dsa-backup-v1");
    }
}
