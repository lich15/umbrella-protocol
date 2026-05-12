//! Sesame-pattern device attestation: identity-key подписывает device-key + metadata.
//! Sesame-pattern device attestation: identity key signs the device key + metadata.
//!
//! Получатель сообщения от device-key проверяет attestation чтобы убедиться что устройство
//! легитимно зарегистрировано пользователем (а не подсунуто компрометированным провайдером).
//! Это аналог Signal Sesame multi-device authentication.
//!
//! Attestation transcript явно domain-separated, версионирован и привязан к device_pubkey,
//! account, device_index, окнам времени — это закрывает substitution и replay атаки.
//!
//! When a recipient receives a message signed by a device key, they verify the attestation
//! to ensure the device was legitimately registered by the user (not slipped in by a
//! compromised provider). This is the analog of Signal Sesame multi-device authentication.
//!
//! The attestation transcript is explicitly domain-separated, versioned, and bound to the
//! device_pubkey, account, device_index, and time windows — closing substitution and replay
//! attacks.

use core::fmt;

use umbrella_crypto_primitives::sig::Ed25519Signature;

use crate::device_key::DeviceKeyPublic;
use crate::error::{IdentityError, Result};
use crate::identity_key::{IdentityKey, IdentityKeyPublic};

/// Domain separator для подписываемого attestation transcript.
/// Domain separator for the signed attestation transcript.
pub const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-device-attestation-v1";

/// Версия формата attestation; меняется только через ADR при breaking schema change.
/// Attestation format version; changes only via ADR on a breaking schema change.
pub const ATTESTATION_VERSION: u8 = 1;

/// Sentinel значение `expires_at` означающее «никогда не истекает».
/// Используется только для bootstrap-устройства; production-устройства должны иметь явный TTL.
/// Sentinel `expires_at` value meaning "never expires".
/// Used only for the bootstrap device; production devices must have an explicit TTL.
pub const NEVER_EXPIRES: u64 = u64::MAX;

/// Подписанное identity-key attestation что данный device-key принадлежит пользователю.
/// Signed identity-key attestation that this device key belongs to the user.
///
/// Wire format (для сериализации в публичном KT log):
/// `version_u8 || account_u32_BE || device_index_u32_BE || issued_at_u64_BE
///  || expires_at_u64_BE || device_pubkey_32 || signature_64`
///
/// Подписываемый transcript:
/// `ATTESTATION_DOMAIN_SEPARATOR || 0x00 || version_u8 || account_u32_BE
///  || device_index_u32_BE || issued_at_u64_BE || expires_at_u64_BE || device_pubkey_32`
#[derive(Clone, Copy)]
pub struct DeviceAttestation {
    version: u8,
    account: u32,
    device_index: u32,
    issued_at: u64,
    expires_at: u64,
    device_pubkey: DeviceKeyPublic,
    signature: Ed25519Signature,
}

impl DeviceAttestation {
    /// Размер сериализованного attestation в байтах.
    /// Serialized attestation size in bytes.
    /// `1 + 4 + 4 + 8 + 8 + 32 + 64 = 121`
    pub const SERIALIZED_LEN: usize = 1 + 4 + 4 + 8 + 8 + 32 + 64;

    /// Создаёт attestation: identity-key подписывает device-pubkey + metadata.
    /// Creates an attestation: the identity key signs the device pubkey + metadata.
    ///
    /// `issued_at` и `expires_at` — unix-секунды; используйте `NEVER_EXPIRES` для bootstrap-устройства.
    /// `issued_at` and `expires_at` are unix seconds; use `NEVER_EXPIRES` for the bootstrap device.
    pub fn issue(
        identity: &IdentityKey,
        account: u32,
        device_index: u32,
        device_pubkey: DeviceKeyPublic,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        let transcript = Self::build_transcript(
            ATTESTATION_VERSION,
            account,
            device_index,
            issued_at,
            expires_at,
            &device_pubkey,
        );
        let signature = identity.sign(&transcript);
        Self {
            version: ATTESTATION_VERSION,
            account,
            device_index,
            issued_at,
            expires_at,
            device_pubkey,
            signature,
        }
    }

    /// Проверяет что attestation подписан указанным identity-pubkey, не истёк, версия поддержана.
    /// Verifies that the attestation is signed by the given identity pubkey, has not expired,
    /// and uses a supported version.
    ///
    /// `now` — текущее unix-время для проверки `expires_at`. Если `expires_at == NEVER_EXPIRES`,
    /// проверка времени пропускается.
    /// `now` is the current unix time for the `expires_at` check. If `expires_at == NEVER_EXPIRES`,
    /// the time check is skipped.
    pub fn verify(&self, identity_pubkey: &IdentityKeyPublic, now: u64) -> Result<()> {
        if self.version != ATTESTATION_VERSION {
            return Err(IdentityError::UnsupportedAttestationVersion {
                version: self.version,
            });
        }
        if self.expires_at != NEVER_EXPIRES && now > self.expires_at {
            return Err(IdentityError::AttestationExpired {
                expires_at: self.expires_at,
                now,
            });
        }
        let transcript = Self::build_transcript(
            self.version,
            self.account,
            self.device_index,
            self.issued_at,
            self.expires_at,
            &self.device_pubkey,
        );
        identity_pubkey.verify(&transcript, &self.signature)?;
        Ok(())
    }

    /// Сериализация в фиксированный wire-format.
    /// Serialization to the fixed wire format.
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = [0u8; Self::SERIALIZED_LEN];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.account.to_be_bytes());
        out[5..9].copy_from_slice(&self.device_index.to_be_bytes());
        out[9..17].copy_from_slice(&self.issued_at.to_be_bytes());
        out[17..25].copy_from_slice(&self.expires_at.to_be_bytes());
        out[25..57].copy_from_slice(&self.device_pubkey.to_bytes());
        out[57..121].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Десериализация из wire-format. Не выполняет криптовалидацию — вызывайте `verify`.
    /// Deserialization from the wire format. No cryptographic validation — call `verify`.
    pub fn from_bytes(bytes: &[u8; Self::SERIALIZED_LEN]) -> Result<Self> {
        let version = bytes[0];
        let mut account_bytes = [0u8; 4];
        account_bytes.copy_from_slice(&bytes[1..5]);
        let account = u32::from_be_bytes(account_bytes);

        let mut device_index_bytes = [0u8; 4];
        device_index_bytes.copy_from_slice(&bytes[5..9]);
        let device_index = u32::from_be_bytes(device_index_bytes);

        let mut issued_at_bytes = [0u8; 8];
        issued_at_bytes.copy_from_slice(&bytes[9..17]);
        let issued_at = u64::from_be_bytes(issued_at_bytes);

        let mut expires_at_bytes = [0u8; 8];
        expires_at_bytes.copy_from_slice(&bytes[17..25]);
        let expires_at = u64::from_be_bytes(expires_at_bytes);

        let mut device_pubkey_bytes = [0u8; 32];
        device_pubkey_bytes.copy_from_slice(&bytes[25..57]);
        let device_pubkey = DeviceKeyPublic::from_bytes(&device_pubkey_bytes)?;

        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&bytes[57..121]);
        let signature = Ed25519Signature::from_bytes(&signature_bytes);

        Ok(Self {
            version,
            account,
            device_index,
            issued_at,
            expires_at,
            device_pubkey,
            signature,
        })
    }

    /// Версия формата.
    /// Format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Индекс аккаунта.
    /// Account index.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// Индекс устройства.
    /// Device index.
    pub fn device_index(&self) -> u32 {
        self.device_index
    }

    /// Время выдачи (unix seconds).
    /// Issuance time (unix seconds).
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Время истечения (unix seconds; `NEVER_EXPIRES` если бессрочно).
    /// Expiration time (unix seconds; `NEVER_EXPIRES` if perpetual).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Public device-key, привязанный к этому attestation.
    /// Public device key bound to this attestation.
    pub fn device_pubkey(&self) -> &DeviceKeyPublic {
        &self.device_pubkey
    }

    fn build_transcript(
        version: u8,
        account: u32,
        device_index: u32,
        issued_at: u64,
        expires_at: u64,
        device_pubkey: &DeviceKeyPublic,
    ) -> [u8; ATTESTATION_DOMAIN_SEPARATOR.len() + 1 + 1 + 4 + 4 + 8 + 8 + 32] {
        const PREFIX_LEN: usize = ATTESTATION_DOMAIN_SEPARATOR.len();
        const TOTAL_LEN: usize = PREFIX_LEN + 1 + 1 + 4 + 4 + 8 + 8 + 32;
        let mut t = [0u8; TOTAL_LEN];
        t[..PREFIX_LEN].copy_from_slice(ATTESTATION_DOMAIN_SEPARATOR);
        t[PREFIX_LEN] = 0x00; // separator after label
        t[PREFIX_LEN + 1] = version;
        let mut o = PREFIX_LEN + 2;
        t[o..o + 4].copy_from_slice(&account.to_be_bytes());
        o += 4;
        t[o..o + 4].copy_from_slice(&device_index.to_be_bytes());
        o += 4;
        t[o..o + 8].copy_from_slice(&issued_at.to_be_bytes());
        o += 8;
        t[o..o + 8].copy_from_slice(&expires_at.to_be_bytes());
        o += 8;
        t[o..o + 32].copy_from_slice(&device_pubkey.to_bytes());
        t
    }
}

impl fmt::Debug for DeviceAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceAttestation(v{}, account={}, device_index={}, issued_at={}, expires_at={}, device={:?})",
            self.version, self.account, self.device_index, self.issued_at, self.expires_at, self.device_pubkey
        )
    }
}

impl PartialEq for DeviceAttestation {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for DeviceAttestation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_key::DeviceKey;
    use crate::seed::{IdentitySeed, MnemonicLanguage};
    use proptest::prelude::*;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    fn fresh_attestation_pair(
        seed: &IdentitySeed,
        account: u32,
        device_index: u32,
        issued_at: u64,
        expires_at: u64,
    ) -> (IdentityKey, DeviceAttestation) {
        let identity = IdentityKey::derive(seed, account).unwrap();
        let device = DeviceKey::derive(seed, account, device_index).unwrap();
        let att = DeviceAttestation::issue(
            &identity,
            account,
            device_index,
            device.public(),
            issued_at,
            expires_at,
        );
        (identity, att)
    }

    #[test]
    fn attestation_round_trip_verifies() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        att.verify(&identity.public(), 1_500)
            .expect("valid attestation must verify within window");
    }

    #[test]
    fn attestation_never_expires_sentinel() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, NEVER_EXPIRES);
        att.verify(&identity.public(), u64::MAX - 1)
            .expect("NEVER_EXPIRES must always verify");
    }

    #[test]
    fn attestation_expired_rejected() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        let result = att.verify(&identity.public(), 2_001);
        assert!(matches!(
            result,
            Err(IdentityError::AttestationExpired {
                expires_at: 2_000,
                now: 2_001
            })
        ));
    }

    #[test]
    fn attestation_signed_by_wrong_identity_rejected() {
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let (_, att) = fresh_attestation_pair(&seed_a, 0, 0, 1_000, 2_000);
        let other_identity = IdentityKey::derive(&seed_b, 0).unwrap();
        let result = att.verify(&other_identity.public(), 1_500);
        assert!(matches!(result, Err(IdentityError::Crypto(_))));
    }

    #[test]
    fn attestation_with_substituted_device_pubkey_rejected() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);

        // Подменяем device_pubkey, оставляя подпись прежней.
        // Substitute the device_pubkey while keeping the original signature.
        let mut bytes = att.to_bytes();
        let other_device = DeviceKey::derive(&seed, 0, 99).unwrap();
        bytes[25..57].copy_from_slice(&other_device.public().to_bytes());
        let tampered = DeviceAttestation::from_bytes(&bytes).unwrap();
        let result = tampered.verify(&identity.public(), 1_500);
        assert!(matches!(result, Err(IdentityError::Crypto(_))));
    }

    #[test]
    fn attestation_with_tampered_metadata_rejected() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);

        // Меняем device_index в wire-format, оставляя подпись.
        // Mutate device_index in the wire format, keeping the signature.
        let mut bytes = att.to_bytes();
        bytes[5..9].copy_from_slice(&7u32.to_be_bytes());
        let tampered = DeviceAttestation::from_bytes(&bytes).unwrap();
        let result = tampered.verify(&identity.public(), 1_500);
        assert!(matches!(result, Err(IdentityError::Crypto(_))));
    }

    #[test]
    fn attestation_with_tampered_signature_rejected() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        let mut bytes = att.to_bytes();
        bytes[57] ^= 0x01; // flip a bit in the signature
        let tampered = DeviceAttestation::from_bytes(&bytes).unwrap();
        let result = tampered.verify(&identity.public(), 1_500);
        assert!(matches!(result, Err(IdentityError::Crypto(_))));
    }

    #[test]
    fn attestation_unsupported_version_rejected() {
        let seed = fresh_seed();
        let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        let mut bytes = att.to_bytes();
        bytes[0] = 0xFF; // bogus version
        let bogus = DeviceAttestation::from_bytes(&bytes).unwrap();
        let result = bogus.verify(&identity.public(), 1_500);
        assert!(matches!(
            result,
            Err(IdentityError::UnsupportedAttestationVersion { version: 0xFF })
        ));
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let seed = fresh_seed();
        let (_, att) = fresh_attestation_pair(&seed, 7, 3, 1_000, 2_000);
        let bytes = att.to_bytes();
        let restored = DeviceAttestation::from_bytes(&bytes).unwrap();
        assert_eq!(att, restored);
    }

    #[test]
    fn serialized_size_constant() {
        let seed = fresh_seed();
        let (_, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        let bytes = att.to_bytes();
        assert_eq!(bytes.len(), DeviceAttestation::SERIALIZED_LEN);
        assert_eq!(DeviceAttestation::SERIALIZED_LEN, 121);
    }

    #[test]
    fn debug_does_not_leak_signature_bytes() {
        use core::fmt::Write;
        let seed = fresh_seed();
        let (_, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
        let s = format!("{att:?}");
        // Подпись 64 байта = 128 hex chars. В Debug её не должно быть полностью.
        // The 64-byte signature = 128 hex chars. It must not appear fully in Debug.
        let mut sig_hex = String::with_capacity(128);
        for b in &att.to_bytes()[57..121] {
            write!(sig_hex, "{b:02x}").expect("writing to String never fails");
        }
        assert!(
            !s.contains(&sig_hex),
            "Debug must not include full signature"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 100, .. ProptestConfig::default() })]

        #[test]
        fn prop_attestation_round_trip(account in 0u32..100, device_index in 0u32..100, issued in 0u64..u64::MAX/2, ttl in 1u64..1_000_000_u64) {
            let seed = fresh_seed();
            let identity = IdentityKey::derive(&seed, account).unwrap();
            let device = DeviceKey::derive(&seed, account, device_index).unwrap();
            let expires = issued.saturating_add(ttl);
            let att = DeviceAttestation::issue(&identity, account, device_index, device.public(), issued, expires);

            // В рамках окна — verify ok.
            // Within the window — verify ok.
            prop_assert!(att.verify(&identity.public(), issued + ttl/2).is_ok());

            // После expires_at — отказ.
            // After expires_at — rejected.
            if expires < u64::MAX {
                prop_assert!(att.verify(&identity.public(), expires + 1).is_err());
            }

            // Любой бит в сериализованной форме (кроме version sentinel) даёт отказ при verify.
            // Round-trip serialize.
            let bytes = att.to_bytes();
            let restored = DeviceAttestation::from_bytes(&bytes).unwrap();
            prop_assert_eq!(att, restored);
        }

        #[test]
        fn prop_any_bit_flip_in_signature_rejected(bit in 0usize..(64 * 8)) {
            let seed = fresh_seed();
            let (identity, att) = fresh_attestation_pair(&seed, 0, 0, 1_000, 2_000);
            let mut bytes = att.to_bytes();
            // bit относится к signature region [57..121]
            // bit refers to the signature region [57..121]
            let byte_offset = 57 + bit / 8;
            bytes[byte_offset] ^= 1 << (bit % 8);
            let tampered = DeviceAttestation::from_bytes(&bytes).unwrap();
            prop_assert!(tampered.verify(&identity.public(), 1_500).is_err());
        }
    }
}
