//! Identity слой: Ed25519 long-lived ключи, BIP-39 recovery, multi-device через Sesame-pattern.
//! Identity layer: Ed25519 long-lived keys, BIP-39 recovery, multi-device via Sesame pattern.
//!
//! Identity-key (Ed25519) — корень доверия пользователя. Подписывает device-keys (Ed25519),
//! каждый из которых живёт на одном физическом устройстве в Secure Enclave/StrongBox через
//! KeyStore trait. Восстановление identity — через BIP-39 24 слова → BIP-32-Ed25519 derive.
//!
//! Identity key (Ed25519) is the user's root of trust. It signs device keys (Ed25519),
//! each living on one physical device inside Secure Enclave/StrongBox via the KeyStore trait.
//! Identity recovery — via BIP-39 24 words → BIP-32-Ed25519 derive.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attestation;
pub mod code_recovery;
pub mod derive;
pub mod device_key;
pub mod error;
pub mod identity_key;
pub mod identity_x25519;
pub mod keystore;
pub mod path;
pub mod seed;

#[cfg(feature = "pq")]
pub mod cloud_wrap_recovery;
#[cfg(feature = "pq")]
pub mod hybrid_device_key;
#[cfg(feature = "pq")]
pub mod hybrid_identity;
#[cfg(feature = "pq")]
pub mod slh_dsa_backup;

pub use attestation::{
    DeviceAttestation, ATTESTATION_DOMAIN_SEPARATOR, ATTESTATION_VERSION, NEVER_EXPIRES,
};
pub use code_recovery::{
    derive_rotated_identity_material, CodeRecoveryMnemonic, RotatedIdentityMaterial,
    CODE_RECOVERY_ENTROPY_LEN, CODE_RECOVERY_WORD_COUNT, ROTATION_DOMAIN_SEPARATOR,
};
pub use derive::{ChainCode, ExtendedSecret, MasterKey, CHAIN_CODE_LEN, EXTENDED_SECRET_LEN};
pub use device_key::{DeviceKey, DeviceKeyPublic};
pub use error::{IdentityError, Result};
pub use identity_key::{IdentityKey, IdentityKeyPublic};
pub use identity_x25519::{IdentityX25519Key, IdentityX25519KeyPublic};
pub use keystore::{Clock, InMemoryKeyStore, KeyStore, SystemClock};
pub use path::{DerivationPath, HardenedIndex, UMBRELLA_COIN_TYPE};
pub use seed::{IdentitySeed, MnemonicLanguage, ENTROPY_LEN, MNEMONIC_WORD_COUNT, SEED_LEN};

#[cfg(feature = "pq")]
pub use cloud_wrap_recovery::{
    CloudWrapRecoveryKey, CloudWrapRecoveryKeyPublic, CLOUD_WRAP_RECOVERY_HKDF_INFO,
};
#[cfg(feature = "pq")]
pub use hybrid_device_key::{HybridDeviceKey, HybridDeviceKeyPublic, HYBRID_DEVICE_PUBLIC_KEY_LEN};
#[cfg(feature = "pq")]
pub use hybrid_identity::{
    HybridIdentityKey, HybridIdentityKeyPublic, HYBRID_IDENTITY_PUBLIC_KEY_LEN,
};
#[cfg(feature = "pq")]
pub use slh_dsa_backup::{SlhDsaBackupKey, SlhDsaBackupKeyPublic, SLH_DSA_BACKUP_ROTATION_CONTEXT};
