//! Hybrid device-key — Ed25519 + ML-DSA-65 для конкретного физического устройства.
//! Hybrid device-key — Ed25519 + ML-DSA-65 for a specific physical device.
//!
//! Параллельный модуль к существующему `device_key`: classical `DeviceKey`
//! не меняется (FFI ABI invariant), а под feature `pq` появляется
//! `HybridDeviceKey` с post-quantum companion подписью на уровне device-уровня.
//!
//! Parallel module to the existing `device_key`: the classical `DeviceKey` does
//! not change (FFI ABI invariant), and under feature `pq` we introduce
//! `HybridDeviceKey` with a post-quantum companion signature at the device level.
//!
//! # Derive из BIP-39 IdentitySeed
//!
//! - **Ed25519 part** — derive по тому же каноническому пути что и classical
//!   `DeviceKey::derive`: `m / 0x554D' / account' / 1' / device_index'`.
//!   Hybrid Ed25519 component byte-exact совпадает с classical для same seed.
//! - **ML-DSA-65 part** — derive через `ChaCha20Rng::from_seed(HKDF-SHA-256(...))`,
//!   где HKDF input = `IdentitySeed::seed()`, salt = `account_be || device_index_be`,
//!   info = `"umbrellax-hybrid-device-mldsa-v1"`.
//!
//! # Derive from BIP-39 IdentitySeed
//!
//! - **Ed25519 part** — derived along the same canonical path as classical
//!   `DeviceKey::derive`: `m / 0x554D' / account' / 1' / device_index'`.
//!   The hybrid Ed25519 component byte-exactly matches classical for the same seed.
//! - **ML-DSA-65 part** — derived through `ChaCha20Rng::from_seed(HKDF-SHA-256(...))`,
//!   where the HKDF input = `IdentitySeed::seed()`, salt = `account_be || device_index_be`,
//!   info = `"umbrellax-hybrid-device-mldsa-v1"`.

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

/// HKDF info-context для ML-DSA-65 derivation в hybrid device layer.
/// Stable wire-level invariant — отличается от identity layer для domain separation.
///
/// HKDF info-context for ML-DSA-65 derivation in the hybrid device layer.
/// Stable wire-level invariant — differs from the identity layer for domain separation.
const HYBRID_DEVICE_MLDSA_HKDF_INFO: &[u8] = b"umbrellax-hybrid-device-mldsa-v1";

/// Длина seed для ChaCha20Rng (внутренний invariant rand_chacha 0.3).
/// ChaCha20Rng seed length (rand_chacha 0.3 internal invariant).
const CHACHA20_SEED_LEN: usize = 32;

/// Приватный hybrid device-key конкретного устройства; обнуляется при Drop через компоненты.
///
/// Сравнить с classical `DeviceKey`:
/// - `signing` (Ed25519) ↔ `inner.ed25519` (32-byte seed).
/// - дополнительная ML-DSA-65 component для AND-mode hybrid подписи.
///
/// User's private hybrid device key for a specific device; zeroized on Drop via components.
///
/// Compare to classical `DeviceKey`:
/// - `signing` (Ed25519) ↔ `inner.ed25519` (32-byte seed).
/// - additional ML-DSA-65 component for AND-mode hybrid signatures.
pub struct HybridDeviceKey {
    /// Ed25519 + ML-DSA-65 компоненты в формате `umbrella_pq` для прямого `hybrid_sign`.
    /// Ed25519 + ML-DSA-65 components in `umbrella_pq` shape for direct `hybrid_sign`.
    inner: PqHybridSecretKey,

    /// Кешированный публичный device-key.
    /// Cached public device key.
    public: HybridDeviceKeyPublic,

    /// Индекс аккаунта.
    /// Account index.
    account: u32,

    /// Индекс устройства внутри аккаунта.
    /// Device index within the account.
    device_index: u32,
}

impl HybridDeviceKey {
    /// Derive hybrid device-key из IdentitySeed для указанного аккаунта и устройства.
    /// Derives the hybrid device key from an IdentitySeed for the given account and device.
    pub fn derive(seed: &IdentitySeed, account: u32, device_index: u32) -> Result<Self> {
        // Ed25519 component — same canonical path как classical DeviceKey.
        // Ed25519 component — same canonical path as classical DeviceKey.
        let path = DerivationPath::device(account, device_index)?;
        let master = MasterKey::derive_from_seed(seed.seed(), &path)?;
        let ed_signing: PrivateSigningKey = master.to_signing_key();
        let ed_verifying: PublicVerifyingKey = ed_signing.verifying_key();
        let ed_seed_bytes: [u8; SECRET_KEY_LEN] = ed_signing.to_seed_bytes();

        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: bytes from PublicVerifyingKey already validated as Ed25519 curve point"
        )]
        let ed_verifying_dalek = ed25519_dalek::VerifyingKey::from_bytes(&ed_verifying.to_bytes())
            .expect("ed25519 verifying-key bytes are guaranteed valid by derive");

        // ML-DSA-65 component — derive seed via HKDF-SHA-256 + ChaCha20Rng.
        let mldsa_rng_seed = derive_mldsa_rng_seed(seed.seed(), account, device_index);
        let mut mldsa_rng = ChaCha20Rng::from_seed(mldsa_rng_seed);
        let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_65_keygen(&mut mldsa_rng);

        let inner = PqHybridSecretKey {
            ed25519: SecretBox::new(Box::new(ed_seed_bytes)),
            ml_dsa: ml_dsa_sk,
        };
        let public = HybridDeviceKeyPublic {
            inner: PqHybridPublicKey {
                ed25519: ed_verifying_dalek,
                ml_dsa: ml_dsa_pk,
            },
            account,
            device_index,
        };

        Ok(Self {
            inner,
            public,
            account,
            device_index,
        })
    }

    /// Возвращает публичную часть hybrid device-key.
    /// Returns the public part of the hybrid device key.
    pub fn public(&self) -> &HybridDeviceKeyPublic {
        &self.public
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

    /// Подписывает произвольное сообщение в hybrid AND-mode.
    /// Signs an arbitrary message in hybrid AND-mode.
    pub(crate) fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<HybridSignature> {
        Ok(hybrid_sign(rng, &self.inner, message)?)
    }
}

impl fmt::Debug for HybridDeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridDeviceKey(account={}, device_index={}, public={:?})",
            self.account, self.device_index, self.public
        )
    }
}

/// Публичная часть hybrid device-key.
/// Public part of the hybrid device key.
#[derive(Clone)]
pub struct HybridDeviceKeyPublic {
    inner: PqHybridPublicKey,
    account: u32,
    device_index: u32,
}

/// Длина wire-format публичного device-key: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes.
/// Совпадает с `HYBRID_IDENTITY_PUBLIC_KEY_LEN`, но это разные namespaces.
///
/// Public-key wire-format length for device: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes.
/// Numerically matches `HYBRID_IDENTITY_PUBLIC_KEY_LEN` but they are distinct namespaces.
pub const HYBRID_DEVICE_PUBLIC_KEY_LEN: usize = 32 + umbrella_pq::ML_DSA_65_PUBLIC_KEY_LEN;

impl HybridDeviceKeyPublic {
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
    pub fn to_bytes(&self) -> [u8; HYBRID_DEVICE_PUBLIC_KEY_LEN] {
        let mut out = [0u8; HYBRID_DEVICE_PUBLIC_KEY_LEN];
        out[..32].copy_from_slice(&self.ed25519_bytes());
        out[32..].copy_from_slice(self.ml_dsa_bytes());
        out
    }

    /// Десериализация из wire-format с поданными account/device_index.
    /// Deserialize from wire format with the given account/device_index.
    pub fn from_bytes(bytes: &[u8], account: u32, device_index: u32) -> Result<Self> {
        if bytes.len() != HYBRID_DEVICE_PUBLIC_KEY_LEN {
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

        let ml_dsa = MlDsa65PublicKey::from_bytes(&bytes[32..])?;

        Ok(Self {
            inner: PqHybridPublicKey {
                ed25519: ed_verifying,
                ml_dsa,
            },
            account,
            device_index,
        })
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

    /// Проверяет hybrid подпись в AND-mode.
    /// Verifies a hybrid signature in AND-mode.
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> Result<()> {
        Ok(hybrid_verify(&self.inner, message, sig)?)
    }
}

impl fmt::Debug for HybridDeviceKeyPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ed = self.ed25519_bytes();
        write!(
            f,
            "HybridDeviceKeyPublic(account={}, device_index={}, ed25519={:02x}{:02x}{:02x}{:02x}…, ml_dsa=<1952B>)",
            self.account, self.device_index, ed[0], ed[1], ed[2], ed[3]
        )
    }
}

impl PartialEq for HybridDeviceKeyPublic {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account
            && self.device_index == other.device_index
            && self.ed25519_bytes() == other.ed25519_bytes()
            && self.ml_dsa_bytes() == other.ml_dsa_bytes()
    }
}

impl Eq for HybridDeviceKeyPublic {}

/// Derive 32-байтовый ChaCha20Rng seed для ML-DSA-65 device part.
///
/// Salt = `account_be (4 bytes) || device_index_be (4 bytes) = 8 bytes`. Это даёт
/// independent seeds per (account, device) pair; смена device_index изменяет seed.
///
/// Derive a 32-byte ChaCha20Rng seed for the ML-DSA-65 device part.
///
/// Salt = `account_be (4 bytes) || device_index_be (4 bytes) = 8 bytes`. Yields
/// independent seeds per (account, device) pair; changing the device_index changes the seed.
fn derive_mldsa_rng_seed(
    seed_bytes: &[u8],
    account: u32,
    device_index: u32,
) -> [u8; CHACHA20_SEED_LEN] {
    let mut salt = [0u8; 8];
    salt[..4].copy_from_slice(&account.to_be_bytes());
    salt[4..].copy_from_slice(&device_index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), seed_bytes);
    let mut okm = [0u8; CHACHA20_SEED_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF-SHA256 expand to 32 bytes always fits per RFC 5869"
    )]
    hk.expand(HYBRID_DEVICE_MLDSA_HKDF_INFO, &mut okm)
        .expect("HKDF expand to 32 bytes always fits");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_key::DeviceKey;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    #[test]
    fn hybrid_device_derive_deterministic_per_seed_account_device() {
        let seed = fresh_seed();
        let a = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        let b = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
    }

    #[test]
    fn hybrid_device_different_devices_distinct_keys() {
        let seed = fresh_seed();
        let d0 = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        let d1 = HybridDeviceKey::derive(&seed, 0, 1).unwrap();
        assert_ne!(d0.public().to_bytes(), d1.public().to_bytes());
    }

    #[test]
    fn hybrid_device_different_accounts_distinct_keys() {
        let seed = fresh_seed();
        let a = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        let b = HybridDeviceKey::derive(&seed, 1, 0).unwrap();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }

    /// Hybrid Ed25519 device component должен byte-exact совпадать с classical DeviceKey.
    /// Hybrid Ed25519 device component must byte-exactly match classical DeviceKey.
    #[test]
    fn hybrid_device_ed25519_matches_classical_device() {
        let seed = fresh_seed();
        let classical = DeviceKey::derive(&seed, 0, 5).unwrap();
        let hybrid = HybridDeviceKey::derive(&seed, 0, 5).unwrap();
        assert_eq!(
            classical.public().to_bytes(),
            hybrid.public().ed25519_bytes(),
            "Ed25519 component of hybrid device must match classical DeviceKey"
        );
    }

    #[test]
    fn hybrid_device_sign_verify_roundtrip() {
        let seed = fresh_seed();
        let dk = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        let mut rng = OsRng;
        let sig = dk.sign(&mut rng, b"device hybrid msg").unwrap();
        dk.public()
            .verify(b"device hybrid msg", &sig)
            .expect("hybrid device signature must verify");
    }

    #[test]
    fn hybrid_device_pubkey_roundtrip_via_bytes() {
        let seed = fresh_seed();
        let dk = HybridDeviceKey::derive(&seed, 3, 11).unwrap();
        let original = dk.public().clone();
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), HYBRID_DEVICE_PUBLIC_KEY_LEN);
        let decoded = HybridDeviceKeyPublic::from_bytes(&bytes, 3, 11).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn hybrid_device_pubkey_size_constant() {
        assert_eq!(HYBRID_DEVICE_PUBLIC_KEY_LEN, 32 + 1952);
        assert_eq!(HYBRID_DEVICE_PUBLIC_KEY_LEN, 1984);
    }

    /// Identity HKDF info ≠ Device HKDF info — domain separation между layers.
    /// Identity HKDF info ≠ Device HKDF info — domain separation between layers.
    #[test]
    fn hybrid_device_mldsa_seed_differs_from_identity_seed() {
        let seed_bytes = [0xA5u8; 64];
        // device(account=0, device_index=0).
        let device_okm = derive_mldsa_rng_seed(&seed_bytes, 0, 0);
        // identity(account=0) — через identity-layer HKDF info.
        let salt = 0u32.to_be_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &seed_bytes);
        let mut identity_okm = [0u8; CHACHA20_SEED_LEN];
        hk.expand(b"umbrellax-hybrid-identity-mldsa-v1", &mut identity_okm)
            .unwrap();
        assert_ne!(device_okm, identity_okm);
    }

    #[test]
    fn hybrid_device_pubkey_invalid_length_rejected() {
        let bad = vec![0u8; 100];
        let result = HybridDeviceKeyPublic::from_bytes(&bad, 0, 0);
        assert!(matches!(result, Err(IdentityError::Pq(_))));
    }

    #[test]
    fn hybrid_device_debug_does_not_leak_secret() {
        let seed = fresh_seed();
        let dk = HybridDeviceKey::derive(&seed, 0, 0).unwrap();
        let formatted = format!("{dk:?}");
        assert!(formatted.starts_with("HybridDeviceKey(account=0, device_index=0,"));
        assert!(formatted.contains("public=HybridDeviceKeyPublic("));
    }
}
