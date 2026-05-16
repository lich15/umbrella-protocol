//! Запись ротации identity-key из ADR-008 (SPEC-12 §A.2, §A.5.1, §A.12).
//! Identity-key rotation record from ADR-008 (SPEC-12 §A.2, §A.5.1, §A.12).
//!
//! Модуль реализует один wire-format тип `IdentityRotationRecord`
//! публикуемый в KT для трёх сценариев смены identity: катастрофическое
//! восстановление через 24+12 слов, плановая ротация по инициативе владельца,
//! emergency при доказанной утечке старого identity. Запись содержит
//! **две** Ed25519 подписи (старым и новым identity-key'ом) над одним
//! canonical signing input под domain separator
//! `"umbrellax-identity-rotation-v1"`. Обе подписи обязаны пройти verify
//! перед принятием записи — это защита от MITM где один из identity-keys
//! подменён (SPEC-12 §A.5.1 последний абзац).
//!
//! This module implements a single wire-format type `IdentityRotationRecord`
//! published to KT for three identity-rotation scenarios: catastrophic
//! recovery via 24+12 words, planned rotation initiated by the owner, and
//! emergency after a proven leak of the old identity. The record carries
//! **two** Ed25519 signatures (by the old and new identity-key) over one
//! canonical signing input under domain separator
//! `"umbrellax-identity-rotation-v1"`. Both signatures must verify before
//! the record is accepted — this is a guard against MITM where one of the
//! identity keys is substituted (SPEC-12 §A.5.1 last paragraph).
//!
//! Ротация identity автоматически триггерит плашку safety-number-changed у
//! всех собеседников (ADR-008 §2 Вариант B). Старые device-entries под
//! прежним identity автоматически помечаются revoked KT log-service'ом в
//! том же epoch (SPEC-09 §7.2 правило 3).
//!
//! Identity rotation automatically triggers a safety-number-changed banner
//! for all contacts (ADR-008 §2 Variant B). Old device-entries under the
//! previous identity are automatically marked revoked by the KT log service
//! in the same epoch (SPEC-09 §7.2 rule 3).

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};

use crate::error::BackupError;

use super::authorization::AUTHORIZATION_WIRE_VERSION;
use super::signed_request::{DEVICE_PUBKEY_LEN, DEVICE_SIG_LEN};

// ---------------------------------------------------------------------------
// Константы / Constants
// ---------------------------------------------------------------------------

/// Domain separator для canonical signing input `IdentityRotationRecord`.
/// Точно 30 байт, фиксировано ADR-008.
///
/// Domain separator for the canonical signing input of `IdentityRotationRecord`.
/// Exactly 30 bytes, fixed by ADR-008.
pub const IDENTITY_ROTATION_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-identity-rotation-v1";

/// Длина `code_recovery_public_half_proof` поля в wire-format. Это 32-байтовый
/// HKDF-SHA512 derivation от 12-словной энтропии (см. `CodeRecoveryMnemonic::public_half_proof`).
/// F-PHD-RETRO-3-E mitigation: блокирует rotation hijack через утечку 24 слов в одиночку.
///
/// Length of the `code_recovery_public_half_proof` field in wire format. This is a 32-byte
/// HKDF-SHA512 derivation of the 12-word entropy (see `CodeRecoveryMnemonic::public_half_proof`).
/// F-PHD-RETRO-3-E mitigation: blocks the rotation hijack via a 24-words leak alone.
pub const CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN: usize = 32;

/// Фиксированная длина wire-format `IdentityRotationRecord` (234 байта).
/// Изменено с 202 → 234 в рамках F-PHD-RETRO-3-E fix: добавлено 32-байтовое
/// поле `code_recovery_public_half_proof`, которое связывает запись смены
/// identity со знанием 12-словного кода восстановления.
///
/// Fixed wire-format length of `IdentityRotationRecord` (234 bytes).
/// Changed from 202 → 234 as part of the F-PHD-RETRO-3-E fix: added the
/// 32-byte `code_recovery_public_half_proof` field, which binds the identity
/// rotation record to knowledge of the 12-word recovery code.
pub const IDENTITY_ROTATION_LEN: usize = 1                          // version
    + DEVICE_PUBKEY_LEN                                             // old_identity_pubkey
    + DEVICE_PUBKEY_LEN                                             // new_identity_pubkey
    + 8                                                             // rotation_timestamp
    + 1                                                             // rotation_reason
    + DEVICE_SIG_LEN                                                // old_identity_signature
    + DEVICE_SIG_LEN                                                // new_identity_signature
    + CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN; // code_recovery_public_half_proof (F-PHD-RETRO-3-E)

// ---------------------------------------------------------------------------
// RotationReason
// ---------------------------------------------------------------------------

/// Причина ротации identity-key. Определяет semantic поведения:
/// `CatastrophicRecovery` разрешает bootstrap-active pattern для первого
/// нового device под новым identity (SPEC-11 §4.8); `PlannedRotation` и
/// `IdentityCompromise` требуют стандартного pending + approval flow.
///
/// Reason for identity-key rotation. Drives semantic behavior: `CatastrophicRecovery`
/// permits the bootstrap-active pattern for the first new device under the
/// new identity (SPEC-11 §4.8); `PlannedRotation` and `IdentityCompromise`
/// require the standard pending + approval flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RotationReason {
    /// Catastrophic recovery через 24+12 слов при потере всех устройств.
    /// Catastrophic recovery via 24+12 words after loss of all devices.
    CatastrophicRecovery = 0x01,
    /// Плановая ротация по явной инициативе владельца аккаунта.
    /// Planned rotation explicitly initiated by the account owner.
    PlannedRotation = 0x02,
    /// Emergency при доказанной утечке / компрометации старого identity.
    /// Emergency after a proven leak or compromise of the old identity.
    IdentityCompromise = 0x03,
}

impl RotationReason {
    /// Байтовый тег для wire-format. Byte tag for wire format.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Обратный декод из тега. `None` если тег неизвестен.
    /// Reverse decode from tag. `None` if tag is unknown.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::CatastrophicRecovery),
            0x02 => Some(Self::PlannedRotation),
            0x03 => Some(Self::IdentityCompromise),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// IdentityRotationRecord
// ---------------------------------------------------------------------------

/// Запись ротации identity-key. Содержит две Ed25519 подписи (старым и
/// новым identity-key'ом) над одним canonical signing input. Обе подписи
/// обязаны пройти verify — это двойной gate защищающий от MITM подмены
/// одного из identity-keys злоумышленником.
///
/// Identity-key rotation record. Carries two Ed25519 signatures (by the old
/// and new identity-key) over one canonical signing input. Both signatures
/// must verify — a dual gate that protects against MITM substitution of
/// either identity key by an attacker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRotationRecord {
    /// Wire-version (= `AUTHORIZATION_WIRE_VERSION`). Wire-format version.
    pub version: u8,
    /// Ed25519 pubkey прежнего identity (тот что был до ротации).
    /// Ed25519 public key of the old identity (prior to rotation).
    pub old_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Ed25519 pubkey нового identity (derived после ротации).
    /// Ed25519 public key of the new identity (derived after rotation).
    pub new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Unix-millis момент ротации.
    /// Unix-millis moment of rotation.
    pub rotation_timestamp: u64,
    /// Причина ротации (catastrophic / planned / compromise).
    /// Rotation reason (catastrophic / planned / compromise).
    pub rotation_reason: RotationReason,
    /// Подпись старого identity-key'а поверх canonical signing input.
    /// Signature by the old identity-key over the canonical signing input.
    pub old_identity_signature: [u8; DEVICE_SIG_LEN],
    /// Подпись нового identity-key'а поверх ТОГО ЖЕ canonical signing input.
    /// Signature by the new identity-key over the SAME canonical signing input.
    pub new_identity_signature: [u8; DEVICE_SIG_LEN],
    /// 32-байтовое HKDF-SHA512 доказательство знания 12-словного кода
    /// восстановления (см. `CodeRecoveryMnemonic::public_half_proof`).
    /// **F-PHD-RETRO-3-E mitigation**: блокирует rotation hijack через
    /// утечку 24 слов в одиночку. Сервер сравнивает это значение с
    /// `public_half_proof` сохранённым в KT при первом bootstrap'е; без
    /// знания 12 слов adversary не может пересчитать одностороннее HKDF.
    /// Обе подписи (old + new identity) покрывают это поле через
    /// canonical signing input.
    ///
    /// 32-byte HKDF-SHA512 proof of knowledge of the 12-word recovery
    /// mnemonic (see `CodeRecoveryMnemonic::public_half_proof`).
    /// **F-PHD-RETRO-3-E mitigation**: blocks the rotation hijack via a
    /// 24-words leak alone. The server compares this value with the
    /// `public_half_proof` recorded in KT at first bootstrap; without
    /// knowledge of the 12 words an adversary cannot recompute the
    /// one-way HKDF. Both signatures (old + new identity) cover this
    /// field via the canonical signing input.
    pub code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
}

/// Canonical signing input для `IdentityRotationRecord`. Обе подписи
/// (`old_identity_signature` и `new_identity_signature`) покрывают один и тот
/// же байтовый input — это зафиксировано ADR-008 и SPEC-12 §A.5.1.
///
/// **F-PHD-RETRO-3-E:** input включает `code_recovery_public_half_proof`
/// (32 байта). Это связывает подписи с конкретным значением 12-словного
/// public_half_proof: tampering с proof'ом ломает обе подписи, поэтому
/// adversary без 12 слов не может подменить proof и пройти dual-sig verify.
///
/// Canonical signing input for `IdentityRotationRecord`. Both signatures
/// (`old_identity_signature` and `new_identity_signature`) cover the same
/// byte input — fixed by ADR-008 and SPEC-12 §A.5.1.
///
/// **F-PHD-RETRO-3-E:** the input includes `code_recovery_public_half_proof`
/// (32 bytes). This binds the signatures to a specific 12-word
/// public_half_proof value: tampering with the proof breaks both signatures,
/// so an adversary without the 12 words cannot substitute the proof and
/// pass dual-signature verification.
///
/// Формат / Format:
/// ```text
/// "umbrellax-identity-rotation-v1"        // 30 bytes domain separator
/// || [version]                             // 1 byte
/// || old_identity_pubkey                   // 32 bytes
/// || new_identity_pubkey                   // 32 bytes
/// || rotation_timestamp_u64_be             // 8 bytes
/// || [rotation_reason]                     // 1 byte
/// || code_recovery_public_half_proof       // 32 bytes (F-PHD-RETRO-3-E)
/// ```
#[must_use]
pub fn canonical_signing_input_rotation(
    version: u8,
    old_identity_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    new_identity_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    rotation_timestamp: u64,
    rotation_reason: RotationReason,
    code_recovery_public_half_proof: &[u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
) -> Vec<u8> {
    let capacity = IDENTITY_ROTATION_DOMAIN_SEPARATOR.len()
        + 1
        + DEVICE_PUBKEY_LEN
        + DEVICE_PUBKEY_LEN
        + 8
        + 1
        + CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(IDENTITY_ROTATION_DOMAIN_SEPARATOR);
    out.push(version);
    out.extend_from_slice(old_identity_pubkey);
    out.extend_from_slice(new_identity_pubkey);
    out.extend_from_slice(&rotation_timestamp.to_be_bytes());
    out.push(rotation_reason.tag());
    out.extend_from_slice(code_recovery_public_half_proof);
    out
}

/// Построить и подписать `IdentityRotationRecord` двумя identity signer
/// closures. Обе подписи покрывают один и тот же canonical signing input,
/// включая `code_recovery_public_half_proof` (F-PHD-RETRO-3-E binding).
///
/// `code_recovery_public_half_proof` — 32-байтовое HKDF-SHA512 значение,
/// полученное из 12-словной энтропии через
/// `CodeRecoveryMnemonic::public_half_proof(account)`. Caller отвечает за
/// его получение: либо имеет `CodeRecoveryMnemonic` и считает на месте,
/// либо принимает proof из верхнеуровневого UX слоя где пользователь
/// вводит 12 слов. Семантически это «открытая половина» двухфакторного
/// recovery — она публикуется в KT при bootstrap и стабильна между
/// rotation'ами одной и той же 12-словной фразы.
///
/// Build and sign an `IdentityRotationRecord` with two identity signer
/// closures. Both signatures cover the same canonical signing input,
/// including the `code_recovery_public_half_proof` (F-PHD-RETRO-3-E binding).
///
/// `code_recovery_public_half_proof` is a 32-byte HKDF-SHA512 value derived
/// from the 12-word entropy via
/// `CodeRecoveryMnemonic::public_half_proof(account)`. The caller is
/// responsible for obtaining it: either holds a `CodeRecoveryMnemonic` and
/// computes locally, or receives the proof from a higher-level UX layer
/// that prompted the user for 12 words. Semantically this is the "public
/// half" of two-factor recovery — published in KT at bootstrap and stable
/// across rotations of the same 12-word phrase.
///
/// # Errors
/// - [`BackupError::InvalidWireFormat`] если `old_identity_pubkey` и
///   `new_identity_pubkey` совпадают (ротация обязана менять identity —
///   SPEC-09 §7.2 правило 3, SPEC-11 §9.3).
/// - Любая ошибка из любого из signer'ов.
pub fn seal_identity_rotation_record<FOld, FNew>(
    old_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    rotation_timestamp: u64,
    rotation_reason: RotationReason,
    code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
    old_identity_signer: FOld,
    new_identity_signer: FNew,
) -> Result<IdentityRotationRecord, BackupError>
where
    FOld: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
    FNew: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
{
    if old_identity_pubkey == new_identity_pubkey {
        return Err(BackupError::InvalidWireFormat);
    }

    let canonical = canonical_signing_input_rotation(
        AUTHORIZATION_WIRE_VERSION,
        &old_identity_pubkey,
        &new_identity_pubkey,
        rotation_timestamp,
        rotation_reason,
        &code_recovery_public_half_proof,
    );
    let old_identity_signature = old_identity_signer(&canonical)?;
    let new_identity_signature = new_identity_signer(&canonical)?;

    Ok(IdentityRotationRecord {
        version: AUTHORIZATION_WIRE_VERSION,
        old_identity_pubkey,
        new_identity_pubkey,
        rotation_timestamp,
        rotation_reason,
        old_identity_signature,
        new_identity_signature,
        code_recovery_public_half_proof,
    })
}

impl IdentityRotationRecord {
    /// Canonical signing input для текущего содержимого.
    /// Canonical signing input for the current contents.
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        canonical_signing_input_rotation(
            self.version,
            &self.old_identity_pubkey,
            &self.new_identity_pubkey,
            self.rotation_timestamp,
            self.rotation_reason,
            &self.code_recovery_public_half_proof,
        )
    }

    /// Доступ к `code_recovery_public_half_proof` (F-PHD-RETRO-3-E binding).
    /// Accessor for `code_recovery_public_half_proof` (F-PHD-RETRO-3-E binding).
    #[must_use]
    pub fn code_recovery_public_half_proof(&self) -> &[u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN] {
        &self.code_recovery_public_half_proof
    }

    /// Сериализовать в wire-format (234 байта, fixed).
    /// Serialize to wire format (234 bytes, fixed).
    #[must_use]
    pub fn encode(&self) -> [u8; IDENTITY_ROTATION_LEN] {
        let mut out = [0u8; IDENTITY_ROTATION_LEN];
        out[0] = self.version;
        out[1..33].copy_from_slice(&self.old_identity_pubkey);
        out[33..65].copy_from_slice(&self.new_identity_pubkey);
        out[65..73].copy_from_slice(&self.rotation_timestamp.to_be_bytes());
        out[73] = self.rotation_reason.tag();
        out[74..138].copy_from_slice(&self.old_identity_signature);
        out[138..202].copy_from_slice(&self.new_identity_signature);
        out[202..234].copy_from_slice(&self.code_recovery_public_half_proof);
        out
    }

    /// Десериализовать из wire-format (234 байта).
    ///
    /// Deserialize from wire format (234 bytes).
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если длина ≠ 234 байт, либо
    ///   `rotation_reason` не в {0x01, 0x02, 0x03}, либо
    ///   `old_identity_pubkey == new_identity_pubkey`.
    /// - [`BackupError::WrappedKeyVersionMismatch`] если version != `0x01`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if bytes.len() != IDENTITY_ROTATION_LEN {
            return Err(BackupError::InvalidWireFormat);
        }
        let version = bytes[0];
        if version != AUTHORIZATION_WIRE_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: AUTHORIZATION_WIRE_VERSION,
                found: version,
            });
        }
        let old_identity_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[1..33]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[33..65]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        if old_identity_pubkey == new_identity_pubkey {
            return Err(BackupError::InvalidWireFormat);
        }
        let rotation_timestamp = u64::from_be_bytes(
            bytes[65..73]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?,
        );
        let rotation_reason =
            RotationReason::from_tag(bytes[73]).ok_or(BackupError::InvalidWireFormat)?;
        let old_identity_signature: [u8; DEVICE_SIG_LEN] = bytes[74..138]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let new_identity_signature: [u8; DEVICE_SIG_LEN] = bytes[138..202]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN] = bytes
            [202..234]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;

        Ok(Self {
            version,
            old_identity_pubkey,
            new_identity_pubkey,
            rotation_timestamp,
            rotation_reason,
            old_identity_signature,
            new_identity_signature,
            code_recovery_public_half_proof,
        })
    }

    /// Проверить обе подписи (старого и нового identity) поверх canonical
    /// signing input. Обе обязаны пройти verify — это защита от MITM где
    /// один из identity-keys подменён. **F-PHD-RETRO-3-E:** canonical
    /// signing input включает `code_recovery_public_half_proof`, поэтому
    /// tampering с proof'ом ломает обе подписи: adversary без 12 слов не
    /// может подменить proof и пройти verify.
    ///
    /// Verify both signatures (old and new identity) over the canonical
    /// signing input. Both must verify — this is protection against MITM
    /// substitution of either identity key. **F-PHD-RETRO-3-E:** the
    /// canonical signing input includes `code_recovery_public_half_proof`,
    /// so tampering with the proof breaks both signatures: an adversary
    /// without the 12 words cannot substitute the proof and pass verify.
    ///
    /// # Errors
    /// - [`BackupError::InvalidRistrettoEncoding`] если хоть один pubkey
    ///   в record'е не декодируется в Ed25519.
    /// - [`BackupError::CryptoVerificationFailed`] если хоть одна подпись
    ///   не проходит.
    pub fn verify(&self) -> Result<(), BackupError> {
        let canonical = self.canonical_signing_input();

        let old_vk = DalekVerifyingKey::from_bytes(&self.old_identity_pubkey)
            .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
        let old_sig = DalekSignature::from_bytes(&self.old_identity_signature);
        old_vk
            .verify(&canonical, &old_sig)
            .map_err(|_| BackupError::CryptoVerificationFailed)?;

        let new_vk = DalekVerifyingKey::from_bytes(&self.new_identity_pubkey)
            .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
        let new_sig = DalekSignature::from_bytes(&self.new_identity_signature);
        new_vk
            .verify(&canonical, &new_sig)
            .map_err(|_| BackupError::CryptoVerificationFailed)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Тесты / Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use rand_core::{OsRng, RngCore};

    fn make_keypair() -> (SigningKey, [u8; DEVICE_PUBKEY_LEN]) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    fn sign_with(
        sk: &SigningKey,
    ) -> impl FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError> + '_ {
        move |message: &[u8]| Ok(sk.sign(message).to_bytes())
    }

    /// Свежий 32-байтовый `code_recovery_public_half_proof` для тестов.
    /// Содержательно неважен (тестам нужно лишь валидное non-zero значение
    /// которое подписи покроют как часть canonical input). В производстве
    /// получают через `CodeRecoveryMnemonic::public_half_proof(account)`.
    ///
    /// Fresh 32-byte `code_recovery_public_half_proof` for tests. The
    /// content is unimportant (tests only need a valid non-zero value
    /// that signatures cover as part of the canonical input). In
    /// production this comes from `CodeRecoveryMnemonic::public_half_proof(account)`.
    fn fresh_code_recovery_proof() -> [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN] {
        let mut proof = [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN];
        OsRng.fill_bytes(&mut proof);
        // Гарантируем что не all-zero (теоретически возможно для CSPRNG, но
        // вероятность 2⁻²⁵⁶). Defense-in-depth для тестов.
        proof[0] |= 0x01;
        proof
    }

    // -------- Constants sanity --------

    #[test]
    fn domain_separator_is_30_bytes() {
        assert_eq!(IDENTITY_ROTATION_DOMAIN_SEPARATOR.len(), 30);
        assert_eq!(
            IDENTITY_ROTATION_DOMAIN_SEPARATOR,
            b"umbrellax-identity-rotation-v1"
        );
    }

    #[test]
    fn wire_length_matches_spec() {
        // F-PHD-RETRO-3-E: 202 → 234 (+32 за code_recovery_public_half_proof).
        // F-PHD-RETRO-3-E: 202 → 234 (+32 for code_recovery_public_half_proof).
        assert_eq!(IDENTITY_ROTATION_LEN, 234);
    }

    #[test]
    fn code_recovery_public_half_proof_len_constant() {
        assert_eq!(CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN, 32);
    }

    #[test]
    fn rotation_reason_tags() {
        assert_eq!(RotationReason::CatastrophicRecovery.tag(), 0x01);
        assert_eq!(RotationReason::PlannedRotation.tag(), 0x02);
        assert_eq!(RotationReason::IdentityCompromise.tag(), 0x03);
    }

    #[test]
    fn rotation_reason_from_tag_all_variants() {
        for r in [
            RotationReason::CatastrophicRecovery,
            RotationReason::PlannedRotation,
            RotationReason::IdentityCompromise,
        ] {
            assert_eq!(RotationReason::from_tag(r.tag()), Some(r));
        }
    }

    #[test]
    fn rotation_reason_from_tag_rejects_unknown() {
        assert_eq!(RotationReason::from_tag(0x00), None);
        assert_eq!(RotationReason::from_tag(0x04), None);
        assert_eq!(RotationReason::from_tag(0xFF), None);
    }

    // -------- Happy path --------

    #[test]
    fn seal_verify_happy_path_catastrophic() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1_700_000_000_000u64,
            RotationReason::CatastrophicRecovery,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.verify().expect("dual signatures must verify");
    }

    #[test]
    fn seal_verify_happy_path_planned_rotation() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.verify().unwrap();
    }

    #[test]
    fn seal_verify_happy_path_compromise() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            u64::MAX,
            RotationReason::IdentityCompromise,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.verify().unwrap();
    }

    // -------- Canonical layout --------

    #[test]
    fn canonical_layout_is_dom_ver_old_new_ts_reason_proof() {
        let old_vk = [0x11u8; DEVICE_PUBKEY_LEN];
        let new_vk = [0x22u8; DEVICE_PUBKEY_LEN];
        let ts = 0x0102_0304_0506_0708u64;
        let reason = RotationReason::PlannedRotation;
        let proof = [0x33u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN];
        let canonical = canonical_signing_input_rotation(
            AUTHORIZATION_WIRE_VERSION,
            &old_vk,
            &new_vk,
            ts,
            reason,
            &proof,
        );

        let mut off = 0;
        assert_eq!(
            &canonical[off..off + IDENTITY_ROTATION_DOMAIN_SEPARATOR.len()],
            IDENTITY_ROTATION_DOMAIN_SEPARATOR
        );
        off += IDENTITY_ROTATION_DOMAIN_SEPARATOR.len();
        assert_eq!(canonical[off], AUTHORIZATION_WIRE_VERSION);
        off += 1;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &old_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &new_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + 8], &ts.to_be_bytes());
        off += 8;
        assert_eq!(canonical[off], reason.tag());
        off += 1;
        assert_eq!(
            &canonical[off..off + CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
            &proof
        );
        assert_eq!(off + CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN, canonical.len());
    }

    #[test]
    fn both_signatures_cover_identical_input() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let ts = 12345u64;
        let reason = RotationReason::PlannedRotation;
        let proof = fresh_code_recovery_proof();
        let canonical = canonical_signing_input_rotation(
            AUTHORIZATION_WIRE_VERSION,
            &old_vk,
            &new_vk,
            ts,
            reason,
            &proof,
        );

        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            ts,
            reason,
            proof,
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();

        let old_dalek_vk = DalekVerifyingKey::from_bytes(&old_vk).unwrap();
        let new_dalek_vk = DalekVerifyingKey::from_bytes(&new_vk).unwrap();
        let old_sig = DalekSignature::from_bytes(&record.old_identity_signature);
        let new_sig = DalekSignature::from_bytes(&record.new_identity_signature);
        old_dalek_vk.verify(&canonical, &old_sig).unwrap();
        new_dalek_vk.verify(&canonical, &new_sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_code_recovery_proof() {
        // F-PHD-RETRO-3-E: проверяем что tampering с code_recovery_public_half_proof
        // ломает обе подписи — гарантирует что adversary без 12 слов не может
        // подменить proof и пройти verify.
        // F-PHD-RETRO-3-E: verify that tampering with code_recovery_public_half_proof
        // breaks both signatures — guarantees that an adversary without the
        // 12 words cannot substitute the proof and pass verify.
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let mut record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.code_recovery_public_half_proof[0] ^= 0xFF;
        let err = record.verify().unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    // -------- Roundtrip --------

    #[test]
    fn encode_decode_roundtrip() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            999,
            RotationReason::CatastrophicRecovery,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        let encoded = record.encode();
        assert_eq!(encoded.len(), IDENTITY_ROTATION_LEN);
        let decoded = IdentityRotationRecord::from_bytes(&encoded).unwrap();
        assert_eq!(record, decoded);
        decoded.verify().unwrap();
    }

    // -------- Adversarial --------

    #[test]
    fn rejects_identical_pubkeys_at_seal() {
        let (old_sk, old_vk) = make_keypair();
        let err = seal_identity_rotation_record(
            old_vk,
            old_vk, // same pubkey
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            |_| Ok([0u8; DEVICE_SIG_LEN]),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn rejects_identical_pubkeys_at_decode() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        let mut bytes = record.encode();
        // Overwrite new_identity_pubkey slot with old bytes.
        bytes[33..65].copy_from_slice(&old_vk);
        let err = IdentityRotationRecord::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn verify_rejects_tampered_old_signature() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let mut record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.old_identity_signature[0] ^= 1;
        let err = record.verify().unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_new_signature() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let mut record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.new_identity_signature[0] ^= 1;
        let err = record.verify().unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_reason_field() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let mut record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.rotation_reason = RotationReason::CatastrophicRecovery;
        let err = record.verify().unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn from_bytes_rejects_bad_version() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        let mut bytes = record.encode();
        bytes[0] = 0x7F;
        let err = IdentityRotationRecord::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x7F
            }
        ));
    }

    #[test]
    fn from_bytes_rejects_unknown_reason() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        let mut bytes = record.encode();
        bytes[73] = 0x99;
        let err = IdentityRotationRecord::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let short = vec![0u8; IDENTITY_ROTATION_LEN - 1];
        let err = IdentityRotationRecord::from_bytes(&short).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
        let long = vec![0u8; IDENTITY_ROTATION_LEN + 1];
        let err = IdentityRotationRecord::from_bytes(&long).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn verify_rejects_mismatched_old_identity() {
        let (old_sk, old_vk) = make_keypair();
        let (_other_sk, other_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let mut record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        // Pretend the record claims a different old_identity. Both signatures
        // remain over the original canonical input, so either the
        // signature-fit against declared old_identity fails, or the new
        // declared old_identity != new_identity violates the distinct-key gate.
        record.old_identity_pubkey = other_vk;
        let err = record.verify().unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn old_identity_signer_error_propagates() {
        let (_new_sk, new_vk) = make_keypair();
        let (_old_sk, old_vk) = make_keypair();
        let err = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            |_| Err(BackupError::DeviceSigning("hw-unavailable")),
            |_| Ok([0u8; DEVICE_SIG_LEN]),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    #[test]
    fn new_identity_signer_error_propagates() {
        let (old_sk, old_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let err = seal_identity_rotation_record(
            old_vk,
            new_vk,
            1,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            |_| Err(BackupError::DeviceSigning("new-signer-offline")),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    // -------- Edge cases --------

    #[test]
    fn timestamp_zero_edge() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            0,
            RotationReason::PlannedRotation,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.verify().unwrap();
        let decoded = IdentityRotationRecord::from_bytes(&record.encode()).unwrap();
        assert_eq!(decoded.rotation_timestamp, 0);
    }

    #[test]
    fn timestamp_max_edge() {
        let (old_sk, old_vk) = make_keypair();
        let (new_sk, new_vk) = make_keypair();
        let record = seal_identity_rotation_record(
            old_vk,
            new_vk,
            u64::MAX,
            RotationReason::CatastrophicRecovery,
            fresh_code_recovery_proof(),
            sign_with(&old_sk),
            sign_with(&new_sk),
        )
        .unwrap();
        record.verify().unwrap();
        let decoded = IdentityRotationRecord::from_bytes(&record.encode()).unwrap();
        assert_eq!(decoded.rotation_timestamp, u64::MAX);
    }

    // -------- Property-based --------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_roundtrip_all_fields(
            timestamp in any::<u64>(),
            reason_tag in 1u8..=3u8,
            old_bytes in proptest::array::uniform32(any::<u8>()),
            proof in proptest::array::uniform32(any::<u8>()),
        ) {
            // Use a real keypair for new identity to ensure distinct pubkeys
            // (old_bytes is pseudo-random; chance of collision astronomical but
            // not impossible — regenerate if they coincide).
            let (old_sk, old_vk) = make_keypair();
            let _ = old_bytes; // ignore random old_bytes — use derived keypair
            let (new_sk, new_vk) = make_keypair();
            prop_assume!(old_vk != new_vk);

            let reason = RotationReason::from_tag(reason_tag).unwrap();
            let record = seal_identity_rotation_record(
                old_vk,
                new_vk,
                timestamp,
                reason,
                proof,
                sign_with(&old_sk),
                sign_with(&new_sk),
            ).unwrap();
            let bytes = record.encode();
            prop_assert_eq!(bytes.len(), IDENTITY_ROTATION_LEN);
            let decoded = IdentityRotationRecord::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&record, &decoded);
            prop_assert_eq!(decoded.code_recovery_public_half_proof(), &proof);
            decoded.verify().unwrap();
        }

        #[test]
        fn proptest_tamper_breaks_verify(
            byte_index in 0usize..IDENTITY_ROTATION_LEN,
        ) {
            let (old_sk, old_vk) = make_keypair();
            let (new_sk, new_vk) = make_keypair();
            let record = seal_identity_rotation_record(
                old_vk,
                new_vk,
                1_700_000_000_000u64,
                RotationReason::PlannedRotation,
                fresh_code_recovery_proof(),
                sign_with(&old_sk),
                sign_with(&new_sk),
            ).unwrap();
            let mut bytes = record.encode();
            bytes[byte_index] ^= 1;
            if let Ok(parsed) = IdentityRotationRecord::from_bytes(&bytes) {
                if parsed == record {
                    return Ok(());
                }
                prop_assert!(parsed.verify().is_err());
            }
        }

        #[test]
        fn proptest_from_bytes_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let _ = IdentityRotationRecord::from_bytes(&data);
        }

        #[test]
        fn proptest_rotation_reason_byte_roundtrip(tag in 0u8..=255u8) {
            match RotationReason::from_tag(tag) {
                Some(r) => prop_assert_eq!(r.tag(), tag),
                None => prop_assert!(tag == 0 || tag > 3),
            }
        }
    }
}
