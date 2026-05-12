//! Hybrid identity-key — Ed25519 + ML-DSA-65 в AND-mode (Этап 8, ADR-011 Решение 5).
//! Hybrid identity-key — Ed25519 + ML-DSA-65 in AND-mode (Stage 8, ADR-011 Decision 5).
//!
//! Параллельный модуль к существующему `identity_key`: classical `IdentityKey`
//! не меняется (FFI ABI invariant ADR-010), а под feature `pq` появляется
//! `HybridIdentityKey` с post-quantum защитой против harvest-now-decrypt-later
//! на уровне identity подписей.
//!
//! Parallel module to the existing `identity_key`: the classical `IdentityKey` does
//! not change (FFI ABI invariant ADR-010), and under feature `pq` we introduce
//! `HybridIdentityKey` with post-quantum protection against harvest-now-decrypt-later
//! at the identity-signature layer.
//!
//! # Derive из BIP-39 IdentitySeed
//!
//! Оба компонента (Ed25519, ML-DSA-65) детерминистично выводятся из той же
//! `IdentitySeed`, что и classical identity, что обеспечивает unified recovery
//! flow: одна 24-слойная BIP-39 mnemonic → восстановление и classical, и
//! hybrid identities.
//!
//! - **Ed25519 part** — derive по тому же каноническому пути что и classical
//!   `IdentityKey::derive`: `m / 0x554D' / account' / 0'` (см. `path::DerivationPath::identity`).
//!   Это значит: classical `IdentityKey` и Ed25519-компонент `HybridIdentityKey`
//!   имеют **одинаковые байты публичного ключа** для того же seed+account.
//!   Это намеренно: hybrid не «другая личность», а та же самая личность плюс
//!   PQ companion подпись.
//! - **ML-DSA-65 part** — derive через ChaCha20Rng::from_seed(HKDF-SHA-256(...)),
//!   где HKDF input = `IdentitySeed::seed()` (64 байта BIP-39 PBKDF2 output),
//!   salt = account big-endian, info = `"umbrellax-hybrid-identity-mldsa-v1"`.
//!   Output 32 байта — seed для `ChaCha20Rng`, который пускается в
//!   `umbrella_pq::ml_dsa_65_keygen` (FIPS 204 keygen randomness).
//!
//! # Derive from BIP-39 IdentitySeed
//!
//! Both components (Ed25519, ML-DSA-65) are derived deterministically from the same
//! `IdentitySeed` as classical identity, providing a unified recovery flow: a single
//! 24-word BIP-39 mnemonic restores both classical and hybrid identities.
//!
//! - **Ed25519 part** — derived along the same canonical path as classical
//!   `IdentityKey::derive`: `m / 0x554D' / account' / 0'` (see `path::DerivationPath::identity`).
//!   This means: the classical `IdentityKey` and the Ed25519 component of
//!   `HybridIdentityKey` have **the same public-key bytes** for the same seed+account.
//!   This is intentional: hybrid is not «another identity», it is the same identity
//!   with a PQ companion signature.
//! - **ML-DSA-65 part** — derived through ChaCha20Rng::from_seed(HKDF-SHA-256(...)),
//!   where the HKDF input = `IdentitySeed::seed()` (64-byte BIP-39 PBKDF2 output),
//!   salt = account big-endian, info = `"umbrellax-hybrid-identity-mldsa-v1"`.
//!   Output 32 bytes — seed for the `ChaCha20Rng` that is fed into
//!   `umbrella_pq::ml_dsa_65_keygen` (FIPS 204 keygen randomness).
//!
//! # AND-mode policy
//!
//! `verify` принимает подпись только если **оба** компонента валидны (NIST SP 800-227 draft).
//! Атакующий должен сломать оба алгоритма (CRQC сломать Ed25519 + lattice attack
//! сломать ML-DSA-65) чтобы forge подпись.
//!
//! `verify` accepts a signature only if **both** components validate (NIST SP 800-227 draft).
//! An attacker must break both algorithms (CRQC for Ed25519 plus a lattice attack on
//! ML-DSA-65) to forge a signature.

use core::fmt;

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secrecy::SecretBox;
use sha2::Sha256;

use umbrella_crypto_primitives::sig::{PrivateSigningKey, PublicVerifyingKey, SECRET_KEY_LEN};
use umbrella_pq::{
    hybrid_sign, hybrid_verify, ml_dsa_65_keygen, HybridPublicKey as PqHybridPublicKey,
    HybridSecretKey as PqHybridSecretKey, HybridSignature, MlDsa65PublicKey,
};

use crate::derive::MasterKey;
use crate::error::{IdentityError, Result};
use crate::path::DerivationPath;
use crate::seed::IdentitySeed;

/// HKDF info-context для ML-DSA-65 derivation в hybrid identity layer.
/// Stable wire-level invariant: смена контекста ломает совместимость на recovery flow.
///
/// HKDF info-context for ML-DSA-65 derivation in the hybrid identity layer.
/// Stable wire-level invariant: changing the context breaks recovery flow compatibility.
const HYBRID_IDENTITY_MLDSA_HKDF_INFO: &[u8] = b"umbrellax-hybrid-identity-mldsa-v1";

/// Длина seed для ChaCha20Rng (внутренний invariant rand_chacha 0.3).
/// ChaCha20Rng seed length (rand_chacha 0.3 internal invariant).
const CHACHA20_SEED_LEN: usize = 32;

/// Приватный hybrid identity-key пользователя; обнуляется при Drop через Drop-impls компонентов.
///
/// **Не экспортируется наружу** — приватный материал доступен только через `sign`.
/// Аналог existing `IdentityKey`, но с post-quantum companion (ML-DSA-65). Используется
/// под feature `pq` параллельно с classical `IdentityKey`, не вместо него.
///
/// User's private hybrid identity key; zeroized on Drop via component Drop impls.
///
/// **Not exported externally** — the private material is reachable only via `sign`.
/// Analogous to the existing `IdentityKey` but with a post-quantum companion (ML-DSA-65).
/// Used under feature `pq` in parallel with classical `IdentityKey`, not as a replacement.
pub struct HybridIdentityKey {
    /// Ed25519 + ML-DSA-65 компоненты в формате `umbrella_pq` для прямого использования
    /// `hybrid_sign` без дублирования domain-separation logic.
    /// Ed25519 + ML-DSA-65 components in `umbrella_pq` shape for direct `hybrid_sign`
    /// usage without duplicating domain-separation logic.
    inner: PqHybridSecretKey,

    /// Кешированный публичный ключ.
    /// Cached public key.
    public: HybridIdentityKeyPublic,

    /// Индекс аккаунта (BIP-32 derivation tree).
    /// Account index (BIP-32 derivation tree).
    account: u32,
}

impl HybridIdentityKey {
    /// Derive hybrid identity-key из IdentitySeed для указанного аккаунта.
    /// Derives the hybrid identity key from an IdentitySeed for the given account.
    ///
    /// Канонический путь Ed25519 части: `m / 0x554D' / account' / 0'`
    /// (совпадает с `IdentityKey::derive` — Ed25519 pubkey будет идентичен).
    /// ML-DSA-65 часть детерминистично derive через HKDF + ChaCha20Rng.
    ///
    /// Canonical path for the Ed25519 part: `m / 0x554D' / account' / 0'`
    /// (same as `IdentityKey::derive` — the Ed25519 pubkey will be identical).
    /// The ML-DSA-65 part is derived deterministically via HKDF + ChaCha20Rng.
    pub fn derive(seed: &IdentitySeed, account: u32) -> Result<Self> {
        Self::derive_from_seed_bytes(seed.seed(), account)
    }

    /// Derive напрямую из 64-байтового seed-материала (для catastrophic recovery).
    /// Derives directly from 64-byte seed material (for catastrophic recovery).
    ///
    /// Используется ротацией identity (ADR-008): `code_recovery::derive_rotated_identity_material`
    /// возвращает 64-байтовый rotated_seed минуя BIP-39 mnemonic.
    /// Used by identity rotation (ADR-008): `code_recovery::derive_rotated_identity_material`
    /// returns a 64-byte rotated_seed bypassing BIP-39 mnemonic.
    pub(crate) fn derive_from_seed_bytes(seed_bytes: &[u8], account: u32) -> Result<Self> {
        // Ed25519 component — same canonical path как classical IdentityKey.
        // Ed25519 component — same canonical path as classical IdentityKey.
        let path = DerivationPath::identity(account)?;
        let master = MasterKey::derive_from_seed(seed_bytes, &path)?;
        let ed_signing: PrivateSigningKey = master.to_signing_key();
        let ed_verifying: PublicVerifyingKey = ed_signing.verifying_key();
        let ed_seed_bytes: [u8; SECRET_KEY_LEN] = ed_signing.to_seed_bytes();

        // Конвертация в umbrella_pq tipos: ed25519-dalek VerifyingKey/SigningKey
        // (umbrella_pq::HybridSecretKey хранит SecretBox<[u8; 32]> seed напрямую).
        // Convert into umbrella_pq types: ed25519-dalek VerifyingKey/SigningKey
        // (umbrella_pq::HybridSecretKey stores SecretBox<[u8; 32]> seed directly).
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: bytes from PublicVerifyingKey already validated as Ed25519 curve point"
        )]
        let ed_verifying_dalek = ed25519_dalek::VerifyingKey::from_bytes(&ed_verifying.to_bytes())
            .expect("ed25519 verifying-key bytes are guaranteed valid by derive");

        // ML-DSA-65 component — derive seed via HKDF-SHA-256 + ChaCha20Rng.
        let mldsa_rng_seed = derive_mldsa_rng_seed(seed_bytes, account);
        let mut mldsa_rng = ChaCha20Rng::from_seed(mldsa_rng_seed);
        let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_65_keygen(&mut mldsa_rng);

        // Build umbrella_pq HybridSecretKey/HybridPublicKey
        let inner = PqHybridSecretKey {
            ed25519: SecretBox::new(Box::new(ed_seed_bytes)),
            ml_dsa: ml_dsa_sk,
        };
        let public = HybridIdentityKeyPublic {
            inner: PqHybridPublicKey {
                ed25519: ed_verifying_dalek,
                ml_dsa: ml_dsa_pk,
            },
            account,
        };

        Ok(Self {
            inner,
            public,
            account,
        })
    }

    /// Возвращает публичную часть hybrid identity-key.
    /// Returns the public part of the hybrid identity key.
    pub fn public(&self) -> &HybridIdentityKeyPublic {
        &self.public
    }

    /// Индекс аккаунта (BIP-32 derivation tree).
    /// Account index (BIP-32 derivation tree).
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Подписывает произвольное сообщение в hybrid AND-mode.
    ///
    /// Принимает `rng: &mut R: RngCore + CryptoRng` для ML-DSA-65 hedged-randomness signing.
    /// В production callers пускают `OsRng`; KAT/deterministic тесты могут пускать
    /// `ChaCha20Rng::from_seed(...)`.
    ///
    /// Signs an arbitrary message in hybrid AND-mode.
    ///
    /// Takes `rng: &mut R: RngCore + CryptoRng` for ML-DSA-65 hedged-randomness signing.
    /// Production callers pass `OsRng`; KAT/deterministic tests may pass
    /// `ChaCha20Rng::from_seed(...)`.
    pub(crate) fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<HybridSignature> {
        Ok(hybrid_sign(rng, &self.inner, message)?)
    }
}

impl fmt::Debug for HybridIdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Никогда не показываем приватный материал.
        // Never reveal the private material.
        write!(
            f,
            "HybridIdentityKey(account={}, public={:?})",
            self.account, self.public
        )
    }
}

/// Публичная часть hybrid identity-key: Ed25519 verifying-key + ML-DSA-65 verification-key.
///
/// Wire-format публичного ключа = `[ed25519_pubkey 32 bytes || ml_dsa_pubkey 1952 bytes] = 1984 bytes total`.
/// Расположение байт фиксировано — изменение требует ADR-поправки.
///
/// Public part of the hybrid identity key: Ed25519 verifying key + ML-DSA-65 verification key.
///
/// Wire format = `[ed25519_pubkey 32 bytes || ml_dsa_pubkey 1952 bytes] = 1984 bytes total`.
/// Byte layout is fixed — changing it requires an ADR amendment.
#[derive(Clone)]
pub struct HybridIdentityKeyPublic {
    /// Inner umbrella_pq HybridPublicKey — изоляция wire-format на одном слое.
    /// Inner umbrella_pq HybridPublicKey — wire-format isolated on a single layer.
    inner: PqHybridPublicKey,

    /// Индекс аккаунта (для symmetry с `IdentityKeyPublic`; не serialized в pubkey bytes).
    /// Account index (for symmetry with `IdentityKeyPublic`; not serialized in pubkey bytes).
    account: u32,
}

/// Длина wire-format публичного ключа: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes.
/// Public-key wire-format length: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes.
pub const HYBRID_IDENTITY_PUBLIC_KEY_LEN: usize = 32 + umbrella_pq::ML_DSA_65_PUBLIC_KEY_LEN;

impl HybridIdentityKeyPublic {
    /// Возвращает байты Ed25519 component (32 bytes).
    /// Returns the Ed25519 component bytes (32 bytes).
    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.inner.ed25519.to_bytes()
    }

    /// Возвращает байты ML-DSA-65 component (1952 bytes).
    /// Returns the ML-DSA-65 component bytes (1952 bytes).
    pub fn ml_dsa_bytes(&self) -> &[u8; umbrella_pq::ML_DSA_65_PUBLIC_KEY_LEN] {
        self.inner.ml_dsa.as_bytes()
    }

    /// Сериализация в wire-format: `[ed25519 32 || ml_dsa_65 1952] = 1984 bytes`.
    /// Serialize to wire format: `[ed25519 32 || ml_dsa_65 1952] = 1984 bytes`.
    pub fn to_bytes(&self) -> [u8; HYBRID_IDENTITY_PUBLIC_KEY_LEN] {
        let mut out = [0u8; HYBRID_IDENTITY_PUBLIC_KEY_LEN];
        out[..32].copy_from_slice(&self.ed25519_bytes());
        out[32..].copy_from_slice(self.ml_dsa_bytes());
        out
    }

    /// Десериализация из wire-format. Валидирует длину и Ed25519 point validity.
    ///
    /// `account` принимается как параметр потому что он не serialized в pubkey bytes.
    /// Caller обязан восстановить корректный account из своего контекста (KT entry,
    /// device record, FFI argument).
    ///
    /// Deserialize from wire format. Validates length and Ed25519 point validity.
    ///
    /// `account` is taken as a parameter because it is not serialized in the pubkey bytes.
    /// The caller must restore the correct account from its own context (KT entry,
    /// device record, FFI argument).
    pub fn from_bytes(bytes: &[u8], account: u32) -> Result<Self> {
        if bytes.len() != HYBRID_IDENTITY_PUBLIC_KEY_LEN {
            return Err(IdentityError::Pq(
                umbrella_pq::PqError::HybridInvalidSignature { got: bytes.len() },
            ));
        }
        let mut ed_bytes = [0u8; 32];
        ed_bytes.copy_from_slice(&bytes[..32]);
        let ed_verifying = ed25519_dalek::VerifyingKey::from_bytes(&ed_bytes).map_err(|_| {
            IdentityError::Pq(umbrella_pq::PqError::BackendError {
                message: "ed25519 verifying-key bytes invalid (curve point)".into(),
            })
        })?;

        let ml_dsa_pubkey_slice = &bytes[32..];
        let ml_dsa = MlDsa65PublicKey::from_bytes(ml_dsa_pubkey_slice)?;

        Ok(Self {
            inner: PqHybridPublicKey {
                ed25519: ed_verifying,
                ml_dsa,
            },
            account,
        })
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Проверяет hybrid подпись в AND-mode: оба компонента (Ed25519 + ML-DSA-65) должны валидировать.
    /// Возвращает `Err(IdentityError::Pq(_))` с UX-полем (`ed25519_ok`, `ml_dsa_ok`) при failure.
    ///
    /// Verifies a hybrid signature in AND-mode: both components (Ed25519 + ML-DSA-65) must validate.
    /// Returns `Err(IdentityError::Pq(_))` with UX field (`ed25519_ok`, `ml_dsa_ok`) on failure.
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> Result<()> {
        Ok(hybrid_verify(&self.inner, message, sig)?)
    }
}

impl fmt::Debug for HybridIdentityKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ed = self.ed25519_bytes();
        write!(
            f,
            "HybridIdentityKeyPublic(account={}, ed25519={:02x}{:02x}{:02x}{:02x}…, ml_dsa=<1952B>)",
            self.account, ed[0], ed[1], ed[2], ed[3]
        )
    }
}

impl PartialEq for HybridIdentityKeyPublic {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account
            && self.ed25519_bytes() == other.ed25519_bytes()
            && self.ml_dsa_bytes() == other.ml_dsa_bytes()
    }
}

impl Eq for HybridIdentityKeyPublic {}

/// Derive 32-байтовый seed для ChaCha20Rng из 64-байтового IdentitySeed
/// через HKDF-SHA-256 с salt=account и info=`HYBRID_IDENTITY_MLDSA_HKDF_INFO`.
///
/// Domain separation гарантирует что:
/// 1. Ed25519 part и ML-DSA-65 part используют независимые keying material'ы
///    (Ed25519 идёт через SLIP-0010 BIP-32-Ed25519, ML-DSA через HKDF — это
///    разные derivation trees, не share state).
/// 2. Hybrid identity и hybrid device key получают разные seeds для ML-DSA
///    (разные HKDF info-strings).
/// 3. Разные account индексы дают независимые ML-DSA seeds (через HKDF salt).
///
/// Derive a 32-byte ChaCha20Rng seed from the 64-byte IdentitySeed via HKDF-SHA-256
/// with salt=account and info=`HYBRID_IDENTITY_MLDSA_HKDF_INFO`.
///
/// Domain separation guarantees:
/// 1. The Ed25519 part and ML-DSA-65 part use independent keying material
///    (Ed25519 goes via SLIP-0010 BIP-32-Ed25519, ML-DSA via HKDF — different
///    derivation trees, no shared state).
/// 2. Hybrid identity and hybrid device key get distinct seeds for ML-DSA
///    (different HKDF info strings).
/// 3. Different account indices yield independent ML-DSA seeds (via HKDF salt).
fn derive_mldsa_rng_seed(seed_bytes: &[u8], account: u32) -> [u8; CHACHA20_SEED_LEN] {
    let salt = account.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), seed_bytes);
    let mut okm = [0u8; CHACHA20_SEED_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF-SHA256 expand to 32 bytes always fits per RFC 5869"
    )]
    hk.expand(HYBRID_IDENTITY_MLDSA_HKDF_INFO, &mut okm)
        .expect("HKDF expand to 32 bytes always fits within 8160-byte limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_key::IdentityKey;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    #[test]
    fn hybrid_derive_is_deterministic_per_seed_and_account() {
        let seed = fresh_seed();
        let a = HybridIdentityKey::derive(&seed, 0).unwrap();
        let b = HybridIdentityKey::derive(&seed, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn hybrid_different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = HybridIdentityKey::derive(&seed, 0).unwrap();
        let b = HybridIdentityKey::derive(&seed, 1).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// Hybrid Ed25519 component должен byte-exact совпадать с classical IdentityKey
    /// для того же seed+account — это означает что hybrid это «classical + PQ companion»,
    /// а не «другая личность».
    /// Hybrid Ed25519 component must byte-exactly match classical IdentityKey for the
    /// same seed+account — this means hybrid is «classical + PQ companion», not «another
    /// identity».
    #[test]
    fn hybrid_ed25519_matches_classical_identity() {
        let seed = fresh_seed();
        let classical = IdentityKey::derive(&seed, 0).unwrap();
        let hybrid = HybridIdentityKey::derive(&seed, 0).unwrap();
        assert_eq!(
            classical.public().to_bytes(),
            hybrid.public().ed25519_bytes(),
            "Ed25519 component of hybrid must match classical IdentityKey"
        );
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let seed = fresh_seed();
        let id = HybridIdentityKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let sig = id.sign(&mut rng, b"hybrid identity message").unwrap();
        id.public()
            .verify(b"hybrid identity message", &sig)
            .expect("hybrid signature must verify");
    }

    #[test]
    fn hybrid_tampered_message_fails() {
        let seed = fresh_seed();
        let id = HybridIdentityKey::derive(&seed, 0).unwrap();
        let mut rng = OsRng;
        let sig = id.sign(&mut rng, b"original").unwrap();
        let result = id.public().verify(b"tampered", &sig);
        assert!(matches!(
            result,
            Err(IdentityError::Pq(
                umbrella_pq::PqError::HybridSignatureVerificationFailed { .. }
            ))
        ));
    }

    #[test]
    fn hybrid_pubkey_roundtrip_via_bytes() {
        let seed = fresh_seed();
        let id = HybridIdentityKey::derive(&seed, 7).unwrap();
        let original_pub = id.public().clone();
        let bytes = original_pub.to_bytes();
        assert_eq!(bytes.len(), HYBRID_IDENTITY_PUBLIC_KEY_LEN);
        let decoded = HybridIdentityKeyPublic::from_bytes(&bytes, 7).unwrap();
        assert_eq!(decoded, original_pub);
    }

    #[test]
    fn hybrid_pubkey_invalid_length_rejected() {
        let bad = vec![0u8; 100];
        let result = HybridIdentityKeyPublic::from_bytes(&bad, 0);
        assert!(matches!(result, Err(IdentityError::Pq(_))));
    }

    /// Подмена Ed25519 части public key (на корректную curve point из другого identity)
    /// должна приводить к verify failure для подписи оригинала. Это проверяет AND-mode
    /// gate: signature валидируется только если **обе** части matchают.
    /// Substituting the Ed25519 part of a public key (with a valid curve point from another
    /// identity) must cause verify to fail for the original's signature. This validates the
    /// AND-mode gate: a signature is accepted only if **both** parts match.
    #[test]
    fn hybrid_pubkey_substituted_ed25519_yields_verify_failure() {
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let id_a = HybridIdentityKey::derive(&seed_a, 0).unwrap();
        let id_b = HybridIdentityKey::derive(&seed_b, 0).unwrap();
        let mut rng = OsRng;
        let sig = id_a.sign(&mut rng, b"hybrid msg").unwrap();

        // Берём pubkey A но с Ed25519 байтами от B (валидная curve point, но «не та»).
        // Take pubkey A but with Ed25519 bytes from B (valid curve point, but «wrong»).
        let mut tampered_bytes = id_a.public().to_bytes();
        tampered_bytes[..32].copy_from_slice(&id_b.public().ed25519_bytes());
        let tampered_pub = HybridIdentityKeyPublic::from_bytes(&tampered_bytes, 0).unwrap();

        let result = tampered_pub.verify(b"hybrid msg", &sig);
        assert!(matches!(
            result,
            Err(IdentityError::Pq(
                umbrella_pq::PqError::HybridSignatureVerificationFailed {
                    ed25519_ok: false,
                    ml_dsa_ok: true
                }
            ))
        ));
    }

    /// Восстановление через BIP-39 mnemonic должно дать identical hybrid identity.
    /// Restoring through a BIP-39 mnemonic must yield an identical hybrid identity.
    #[test]
    fn hybrid_restore_from_mnemonic_yields_same_pubkey() {
        let original_seed = fresh_seed();
        let mnemonic = original_seed.to_mnemonic();
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

        let original = HybridIdentityKey::derive(&original_seed, 0).unwrap();
        let restored = HybridIdentityKey::derive(&restored_seed, 0).unwrap();
        assert_eq!(
            original.public().to_bytes(),
            restored.public().to_bytes(),
            "восстановление из мнемоники должно давать identical hybrid identity"
        );
    }

    #[test]
    fn hybrid_debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let id = HybridIdentityKey::derive(&seed, 0).unwrap();
        let formatted = format!("{id:?}");
        assert!(formatted.starts_with("HybridIdentityKey(account=0,"));
        assert!(formatted.contains("public=HybridIdentityKeyPublic("));
        // Никаких raw 32-byte hex сегментов от secret.
        // No raw 32-byte hex segments from the secret.
    }

    #[test]
    fn hybrid_pubkey_size_constant() {
        assert_eq!(HYBRID_IDENTITY_PUBLIC_KEY_LEN, 32 + 1952);
        assert_eq!(HYBRID_IDENTITY_PUBLIC_KEY_LEN, 1984);
    }

    #[test]
    fn mldsa_rng_seed_domain_separation() {
        // Разные account индексы → разные ML-DSA seeds.
        // Different account indices → distinct ML-DSA seeds.
        let seed_bytes = [0x42u8; 64];
        let s0 = derive_mldsa_rng_seed(&seed_bytes, 0);
        let s1 = derive_mldsa_rng_seed(&seed_bytes, 1);
        assert_ne!(s0, s1);
    }
}
