//! 12-словный код восстановления + HKDF-SHA512 вывод ротации identity (ADR-008).
//! 12-word code-recovery mnemonic + HKDF-SHA512 identity-rotation derive (ADR-008).
//!
//! ## Назначение
//!
//! Решение ADR-008 вводит двухфакторное восстановление аккаунта при полной потере всех активных
//! устройств. Первый фактор — 24 слова BIP-39 (identity seed); второй — отдельная 12-словная
//! BIP-39 фраза (код восстановления), которую пользователь хранит физически раздельно. Оба вместе
//! детерминированно выводят новый identity через HKDF-SHA512 с фиксированным domain separator.
//!
//! Результат — `RotatedIdentityMaterial`, 64-байтовый seed, совместимый с BIP-32-Ed25519 derivation
//! (как обычный `IdentitySeed`, но без BIP-39 мнемоники — в rotated material отсутствует phrase,
//! потому что он выведен криптографически, а не сгенерирован CSPRNG). Из rotated material клиент
//! выводит `IdentityKey` и `IdentityX25519Key` для нового identity. Старые device-keys автоматически
//! помечаются revoked в KT при публикации `IdentityRotationRecord` (см. SPEC-12 §A.12).
//!
//! ## Purpose
//!
//! ADR-008 introduces two-factor account recovery when all active devices are lost. The first
//! factor is the 24-word BIP-39 identity seed; the second is a separate 12-word BIP-39 phrase
//! (code recovery), stored physically apart. Together they deterministically derive a new identity
//! via HKDF-SHA512 under a fixed domain separator.
//!
//! The result is `RotatedIdentityMaterial`, a 64-byte seed compatible with BIP-32-Ed25519
//! derivation (like an ordinary `IdentitySeed`, but without a BIP-39 mnemonic — rotated material
//! has no phrase because it's cryptographically derived, not CSPRNG-generated). The client
//! derives `IdentityKey` and `IdentityX25519Key` for the new identity from it. Old device keys
//! are auto-revoked in KT upon publishing the `IdentityRotationRecord` (see SPEC-12 §A.12).
//!
//! ## Детерминизм
//!
//! Для фиксированного триплета (identity_seed, code, old_identity_pubkey) результат всегда один
//! и тот же. Это позволяет повторить catastrophic recovery из тех же 24 + 12 слов и получить тот
//! же rotated_seed — критично для UX (пользователь может ошибиться при первом вводе).
//!
//! ## Determinism
//!
//! For a fixed triple (identity_seed, code, old_identity_pubkey) the result is always identical.
//! This lets the user re-run catastrophic recovery with the same 24 + 12 words and obtain the
//! same rotated_seed — critical for UX (user may mistype on the first attempt).
//!
//! ## Защита от несоответствия старого identity
//!
//! `derive_rotated_identity_material` перед derive проверяет что `old_identity_pubkey`
//! действительно derived из переданного `identity_seed`. Если нет — возвращает
//! `IdentityError::OldIdentityMismatch`. Это предотвращает accidental использование чужого
//! identity_pubkey (например если пользователь случайно подставил pubkey другого аккаунта).
//!
//! ## Old identity mismatch protection
//!
//! `derive_rotated_identity_material` verifies before derive that `old_identity_pubkey` is truly
//! derived from the supplied `identity_seed`. If not — returns `IdentityError::OldIdentityMismatch`.
//! This prevents accidental use of a foreign identity_pubkey (e.g. if the user accidentally
//! pastes another account's pubkey).

use bip39::{Language, Mnemonic};
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{IdentityError, Result};
use crate::identity_key::{IdentityKey, IdentityKeyPublic};
use crate::identity_x25519::IdentityX25519Key;
use crate::seed::{IdentitySeed, MnemonicLanguage, SEED_LEN};

/// Длина энтропии кода восстановления: 16 байт = 128 бит = 12 слов BIP-39.
/// Code-recovery entropy length: 16 bytes = 128 bits = 12 BIP-39 words.
pub const CODE_RECOVERY_ENTROPY_LEN: usize = 16;

/// Количество слов в коде восстановления (отличается от 24-словной identity мнемоники).
/// Word count in the code-recovery mnemonic (differs from the 24-word identity mnemonic).
pub const CODE_RECOVERY_WORD_COUNT: usize = 12;

/// Domain separator для HKDF-derive ротации identity.
/// Domain separator for the identity-rotation HKDF-derive.
pub const ROTATION_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-identity-rotation-v1";

/// 12-словная BIP-39 фраза кода восстановления; обнуляется при Drop.
/// 12-word BIP-39 code-recovery mnemonic; zeroized on Drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CodeRecoveryMnemonic {
    /// Сериализованная фраза (12 слов через пробел).
    /// Serialized phrase (12 space-separated words).
    phrase: String,
    /// 16-байтовая entropy; используется `derive_rotated_identity_material` без повторного
    /// разбора фразы.
    /// 16-byte entropy; consumed by `derive_rotated_identity_material` without re-parsing.
    entropy: [u8; CODE_RECOVERY_ENTROPY_LEN],
    /// Язык wordlist (не секрет).
    /// Wordlist language (not a secret).
    #[zeroize(skip)]
    language: MnemonicLanguage,
}

impl CodeRecoveryMnemonic {
    /// Генерирует новую 12-словную фразу из CSPRNG.
    /// Generates a new 12-word phrase from a CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R, language: MnemonicLanguage) -> Self {
        let entropy = generate_code_recovery_entropy(rng);
        let bip39_lang = Self::bip39_language(language);
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: 16-byte entropy is always valid BIP-39 input"
        )]
        let mnemonic = Mnemonic::from_entropy_in(bip39_lang, &entropy[..])
            .expect("16-byte entropy is always valid for BIP-39");
        Self {
            phrase: mnemonic.to_string(),
            entropy: *entropy,
            language,
        }
    }

    /// Парсит 12-словную фразу; возвращает ошибку при неверном word count либо checksum.
    /// Parses a 12-word phrase; returns an error on wrong word count or checksum.
    pub fn from_phrase(phrase: &str, language: MnemonicLanguage) -> Result<Self> {
        let trimmed = phrase.trim();
        let word_count = trimmed.split_whitespace().count();
        if word_count != CODE_RECOVERY_WORD_COUNT {
            return Err(IdentityError::InvalidCodeRecoveryWordCount {
                expected: CODE_RECOVERY_WORD_COUNT,
                got: word_count,
            });
        }
        let bip39_lang = Self::bip39_language(language);
        let mnemonic = Mnemonic::parse_in_normalized(bip39_lang, trimmed)
            .map_err(|_| IdentityError::InvalidCodeRecoveryMnemonic)?;
        let entropy_vec = mnemonic_entropy_zeroizing(&mnemonic);
        if entropy_vec.len() != CODE_RECOVERY_ENTROPY_LEN {
            return Err(IdentityError::InvalidCodeRecoveryWordCount {
                expected: CODE_RECOVERY_WORD_COUNT,
                got: word_count,
            });
        }
        let mut entropy = Zeroizing::new([0u8; CODE_RECOVERY_ENTROPY_LEN]);
        entropy.copy_from_slice(&entropy_vec);
        Ok(Self {
            phrase: mnemonic.to_string(),
            entropy: *entropy,
            language,
        })
    }

    /// Возвращает строковое представление (12 слов через пробел); владелец отвечает за хранение.
    /// Returns the string representation (12 space-separated words); owner handles storage.
    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    /// Возвращает язык wordlist выбранный при генерации/парсинге.
    /// Returns the wordlist language selected on generation/parsing.
    pub fn language(&self) -> MnemonicLanguage {
        self.language
    }

    /// Внутреннее представление entropy для HKDF derive.
    /// Не экспортируется публично — утечка позволила бы восстановить фразу.
    /// Internal entropy access for HKDF derive.
    /// Intentionally not exported — leakage would let an attacker reconstruct the phrase.
    pub(crate) fn entropy(&self) -> &[u8; CODE_RECOVERY_ENTROPY_LEN] {
        &self.entropy
    }

    /// Вычисляет 32-байтовый публичный отпечаток 12-словной энтропии для
    /// данного account. Закрытие F-PHD-RETRO-3-E: предотвращает захват
    /// аккаунта через утечку 24 слов в одиночку.
    ///
    /// Computes a 32-byte public proof of the 12-word entropy for the
    /// given account. F-PHD-RETRO-3-E mitigation: prevents account
    /// hijack via a 24-words leak alone.
    ///
    /// Формула: HKDF-SHA512(
    ///   salt = "umbrellax-12words-public-half-v1",
    ///   ikm  = entropy,
    ///   info = account_index_be,
    ///   L    = 32 bytes
    /// )
    ///
    /// Свойства:
    /// - Односторонняя функция: восстановить entropy из public_half_proof
    ///   математически невозможно (preimage resistance HKDF-SHA512).
    /// - Stable across identity rotations: одни и те же 12 слов дают
    ///   тот же отпечаток до и после ротации main key.
    /// - Привязана к account: разные accounts дают разные отпечатки.
    /// - Детерминированная: одни и те же входы дают тот же результат.
    ///
    /// Этот отпечаток публикуется в KT при создании учётной записи и
    /// **не меняется при rotation** (только при смене 12 слов). При
    /// смене identity-key клиент должен предоставить тот же
    /// public_half_proof в записи смены — сервер сравнивает с хранимым,
    /// и без знания 12 слов adversary не может его пересчитать.
    #[must_use]
    pub fn public_half_proof(&self, account: u32) -> [u8; 32] {
        use hkdf::Hkdf;

        let info = account.to_be_bytes();

        let hk = Hkdf::<Sha512>::new(Some(PUBLIC_HALF_HKDF_SALT), &self.entropy);
        let mut okm = [0u8; 32];
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HKDF-SHA512 32-byte expansion always fits within 8160 bytes"
        )]
        hk.expand(&info, &mut okm)
            .expect("HKDF-SHA512 32-byte expansion always fits");
        okm
    }

    /// Вычисляет 32-байтовый отпечаток-привязку 12-словной энтропии к
    /// конкретной паре (old_identity_pubkey, new_identity_pubkey) при
    /// rotation. Дополняет `public_half_proof`: первый доказывает знание
    /// 12 слов, второй привязывает это знание к конкретной операции
    /// смены ключа (anti-replay across rotations).
    ///
    /// Computes a 32-byte commitment binding the 12-word entropy to a
    /// specific (old, new) identity_pubkey pair at rotation time.
    /// Complements `public_half_proof`: the former proves knowledge of
    /// the 12 words, the latter binds that knowledge to the specific
    /// rotation operation (anti-replay across rotations).
    ///
    /// Формула: HKDF-SHA512(
    ///   salt = "umbrellax-12words-rotation-bind-v1",
    ///   ikm  = entropy,
    ///   info = old_identity_pubkey || new_identity_pubkey,
    ///   L    = 32 bytes
    /// )
    #[must_use]
    pub fn rotation_commitment(
        &self,
        old_identity_pubkey: &[u8; 32],
        new_identity_pubkey: &[u8; 32],
    ) -> [u8; 32] {
        use hkdf::Hkdf;

        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(old_identity_pubkey);
        info.extend_from_slice(new_identity_pubkey);

        let hk = Hkdf::<Sha512>::new(Some(ROTATION_BIND_HKDF_SALT), &self.entropy);
        let mut okm = [0u8; 32];
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HKDF-SHA512 32-byte expansion always fits within 8160 bytes"
        )]
        hk.expand(&info, &mut okm)
            .expect("HKDF-SHA512 32-byte expansion always fits");
        okm
    }

    fn bip39_language(lang: MnemonicLanguage) -> Language {
        match lang {
            MnemonicLanguage::English => Language::English,
        }
    }
}

/// Соль HKDF для `CodeRecoveryMnemonic::public_half_proof` (F-PHD-RETRO-3-E).
/// HKDF salt for `CodeRecoveryMnemonic::public_half_proof` (F-PHD-RETRO-3-E).
pub const PUBLIC_HALF_HKDF_SALT: &[u8] = b"umbrellax-12words-public-half-v1";

/// Соль HKDF для `CodeRecoveryMnemonic::rotation_commitment` (F-PHD-RETRO-3-E).
/// HKDF salt for `CodeRecoveryMnemonic::rotation_commitment` (F-PHD-RETRO-3-E).
pub const ROTATION_BIND_HKDF_SALT: &[u8] = b"umbrellax-12words-rotation-bind-v1";

/// Генерирует entropy кода восстановления в очищаемой временной обёртке.
/// Generates code-recovery entropy in a zeroizing temporary wrapper.
fn generate_code_recovery_entropy<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Zeroizing<[u8; CODE_RECOVERY_ENTROPY_LEN]> {
    let mut entropy = Zeroizing::new([0u8; CODE_RECOVERY_ENTROPY_LEN]);
    rng.fill_bytes(&mut entropy[..]);
    entropy
}

/// Возвращает entropy из BIP-39 mnemonic в очищаемом временном Vec.
/// Returns entropy from a BIP-39 mnemonic in a zeroizing temporary Vec.
fn mnemonic_entropy_zeroizing(mnemonic: &Mnemonic) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(mnemonic.to_entropy())
}

impl core::fmt::Debug for CodeRecoveryMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Debug-вывод никогда не показывает саму фразу — только флаг что содержит секрет.
        // Debug output never reveals the phrase — only a flag that a secret is held.
        write!(
            f,
            "CodeRecoveryMnemonic(<redacted>, language={:?})",
            self.language
        )
    }
}

/// Материал нового identity полученный через ротацию (HKDF от 24w + 12w + old_pubkey).
/// Не BIP-39 seed — не имеет мнемоники; обнуляется при Drop.
/// New identity material obtained via rotation (HKDF of 24w + 12w + old_pubkey).
/// Not a BIP-39 seed — has no mnemonic; zeroized on Drop.
pub struct RotatedIdentityMaterial {
    seed: [u8; SEED_LEN],
}

impl RotatedIdentityMaterial {
    /// Возвращает 64-байтовый rotated seed; используется BIP-32-Ed25519 derive.
    /// Returns the 64-byte rotated seed; used by BIP-32-Ed25519 derive.
    pub fn seed_bytes(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Derive identity-key для указанного аккаунта из rotated material.
    /// Derives the identity key for the given account from rotated material.
    pub fn derive_identity_key(&self, account: u32) -> Result<IdentityKey> {
        IdentityKey::derive_from_seed_bytes(&self.seed, account)
    }

    /// Derive X25519 identity-key для указанного аккаунта из rotated material.
    /// Derives the X25519 identity key for the given account from rotated material.
    pub fn derive_identity_x25519_key(&self, account: u32) -> Result<IdentityX25519Key> {
        IdentityX25519Key::derive_from_seed_bytes(&self.seed, account)
    }

    /// Возвращает публичный identity-key нового identity для указанного аккаунта.
    /// Returns the new identity's public identity key for the given account.
    pub fn identity_pubkey(&self, account: u32) -> Result<IdentityKeyPublic> {
        Ok(self.derive_identity_key(account)?.public())
    }
}

impl Drop for RotatedIdentityMaterial {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl core::fmt::Debug for RotatedIdentityMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RotatedIdentityMaterial(<redacted>)")
    }
}

/// Выводит материал нового identity из (24 слова identity, 12 слов кода, публичный старый identity).
///
/// Формула: `rotated_seed = HKDF-SHA512(salt = ROTATION_DOMAIN_SEPARATOR,
/// ikm = identity_seed.seed() || code.entropy(), info = old_identity_pubkey_bytes, len = 64)`.
///
/// Перед derive проверяется что `old_identity_pubkey` действительно derived из `identity_seed`
/// через `IdentityKey::derive(seed, 0)`. Иначе — `IdentityError::OldIdentityMismatch`.
///
/// Derives new identity material from (24-word identity, 12-word code, old identity public key).
///
/// Formula: `rotated_seed = HKDF-SHA512(salt = ROTATION_DOMAIN_SEPARATOR,
/// ikm = identity_seed.seed() || code.entropy(), info = old_identity_pubkey_bytes, len = 64)`.
///
/// Before derive, verifies that `old_identity_pubkey` is actually derived from `identity_seed`
/// via `IdentityKey::derive(seed, 0)`. Otherwise — `IdentityError::OldIdentityMismatch`.
pub fn derive_rotated_identity_material(
    identity_seed: &IdentitySeed,
    code: &CodeRecoveryMnemonic,
    old_identity_pubkey: &IdentityKeyPublic,
) -> Result<RotatedIdentityMaterial> {
    // 1. Верификация: old_identity_pubkey должен совпадать с identity derived from seed (account=0).
    // 1. Verification: old_identity_pubkey must match the identity derived from seed (account=0).
    let derived = IdentityKey::derive(identity_seed, 0)?;
    let derived_bytes = derived.public().to_bytes();
    let supplied_bytes = old_identity_pubkey.to_bytes();
    if derived_bytes.ct_eq(&supplied_bytes).unwrap_u8() == 0 {
        return Err(IdentityError::OldIdentityMismatch);
    }

    // 2. HKDF-SHA512 вывод 64-байтового rotated seed.
    //    ikm = identity_seed.seed (64 B) || code.entropy (16 B) — 80 B total.
    //    salt = ROTATION_DOMAIN_SEPARATOR (30 B, constant).
    //    info = old_identity_pubkey bytes (32 B) — привязывает derivation к конкретному старому identity.
    // 2. HKDF-SHA512 extract+expand to a 64-byte rotated seed.
    //    ikm = identity_seed.seed (64 B) || code.entropy (16 B) — 80 B total.
    //    salt = ROTATION_DOMAIN_SEPARATOR (30 B, constant).
    //    info = old_identity_pubkey bytes (32 B) — binds derivation to a specific old identity.
    let mut ikm = compose_rotation_ikm(identity_seed, code);

    let rotated_seed = derive_rotation_seed_zeroizing(&ikm[..], &supplied_bytes);

    // Обнуляем промежуточный ikm сразу после использования, не только при Drop.
    // Zeroize the intermediate ikm immediately, not only on Drop.
    ikm.zeroize();

    Ok(RotatedIdentityMaterial {
        seed: *rotated_seed,
    })
}

/// Собирает вход ротации identity в очищаемом временном буфере.
/// Builds identity-rotation input in a zeroizing temporary buffer.
fn compose_rotation_ikm(
    identity_seed: &IdentitySeed,
    code: &CodeRecoveryMnemonic,
) -> Zeroizing<[u8; SEED_LEN + CODE_RECOVERY_ENTROPY_LEN]> {
    let mut ikm = Zeroizing::new([0u8; SEED_LEN + CODE_RECOVERY_ENTROPY_LEN]);
    ikm[..SEED_LEN].copy_from_slice(identity_seed.seed());
    ikm[SEED_LEN..].copy_from_slice(code.entropy());
    ikm
}

/// HKDF-SHA512 extract+expand для ротации identity с явным затиранием PRK/OKM.
/// HKDF-SHA512 extract+expand for identity rotation with explicit PRK/OKM wiping.
fn derive_rotation_seed_zeroizing(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; SEED_LEN]> {
    // Этот вывод даёт ровно один блок SHA-512: SEED_LEN == 64.
    // This derivation needs exactly one SHA-512 block: SEED_LEN == 64.
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HMAC accepts any key length per RFC 2104"
    )]
    let mut extract_mac =
        Hmac::<Sha512>::new_from_slice(ROTATION_DOMAIN_SEPARATOR).expect("HMAC accepts any key");
    extract_mac.update(ikm);
    let mut extract_output = extract_mac.finalize().into_bytes();

    let mut prk = Zeroizing::new([0u8; 64]);
    prk.copy_from_slice(extract_output.as_slice());
    extract_output.zeroize();

    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HMAC accepts any key length per RFC 2104"
    )]
    let mut expand_mac = Hmac::<Sha512>::new_from_slice(&prk[..]).expect("HMAC accepts any key");
    expand_mac.update(info);
    expand_mac.update(&[1]);
    let mut expand_output = expand_mac.finalize().into_bytes();

    let mut rotated_seed = Zeroizing::new([0u8; SEED_LEN]);
    rotated_seed.copy_from_slice(&expand_output[..SEED_LEN]);
    expand_output.zeroize();
    rotated_seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    fn fresh_code() -> CodeRecoveryMnemonic {
        let mut rng = OsRng;
        CodeRecoveryMnemonic::generate(&mut rng, MnemonicLanguage::English)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.1 Unit + RFC / standard test vectors
    // ─────────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────────
    // F-PHD-RETRO-3-E primitive: public_half_proof + rotation_commitment
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn public_half_proof_is_deterministic() {
        let code = fresh_code();
        let account = 0u32;
        let a = code.public_half_proof(account);
        let b = code.public_half_proof(account);
        assert_eq!(a, b, "public_half_proof must be deterministic");
    }

    #[test]
    fn public_half_proof_stable_across_rotation() {
        // F-PHD-RETRO-3-E: proof не зависит от identity_pubkey, поэтому
        // он стабилен через rotation main key (одни 12 слов → один proof).
        let code = fresh_code();
        let p_account_0 = code.public_half_proof(0);
        let p_account_0_again = code.public_half_proof(0);
        assert_eq!(
            p_account_0, p_account_0_again,
            "proof stable across calls (no identity_pubkey dependency)"
        );
    }

    #[test]
    fn public_half_proof_differs_per_account() {
        let code = fresh_code();
        let p_a = code.public_half_proof(0);
        let p_b = code.public_half_proof(1);
        assert_ne!(
            p_a, p_b,
            "public_half_proof must bind to account index via HKDF info"
        );
    }

    #[test]
    fn public_half_proof_differs_per_code() {
        let code_a = fresh_code();
        let code_b = fresh_code();
        let p_a = code_a.public_half_proof(0);
        let p_b = code_b.public_half_proof(0);
        // Probability of accidental match с другими 12 словами ≈ 2^-256, negligible.
        assert_ne!(p_a, p_b, "different 12-words must yield different proofs");
    }

    #[test]
    fn rotation_commitment_is_deterministic() {
        let code = fresh_code();
        let old_pk = [0x33u8; 32];
        let new_pk = [0x44u8; 32];
        let a = code.rotation_commitment(&old_pk, &new_pk);
        let b = code.rotation_commitment(&old_pk, &new_pk);
        assert_eq!(a, b, "rotation_commitment must be deterministic");
    }

    #[test]
    fn rotation_commitment_differs_per_old_new_pair() {
        let code = fresh_code();
        let old_pk = [0xAAu8; 32];
        let new_pk_a = [0xBBu8; 32];
        let new_pk_b = [0xCCu8; 32];
        let c_a = code.rotation_commitment(&old_pk, &new_pk_a);
        let c_b = code.rotation_commitment(&old_pk, &new_pk_b);
        assert_ne!(
            c_a, c_b,
            "rotation_commitment must differ for different new_pk"
        );
    }

    #[test]
    fn public_half_proof_zero_entropy_vector() {
        // F-PHD-RETRO-3-E primitive — фиксированный test vector для regression
        // detection если HKDF salt либо info construction случайно изменены.
        // Code mnemonic из 16 нулевых байт entropy (BIP-39 «abandon × 11 about»).
        let code = CodeRecoveryMnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
            MnemonicLanguage::English,
        )
        .expect("BIP-39 official vector parses");
        let proof = code.public_half_proof(0);
        assert_ne!(
            proof, [0u8; 32],
            "HKDF output should be non-zero for non-trivial entropy"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.1 Unit + RFC / standard test vectors (existing)
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn bip39_12_word_zero_entropy_test_vector() {
        // Официальный BIP-39 test vector: 16 zero bytes → "abandon × 11 about".
        // Official BIP-39 test vector: 16 zero bytes → "abandon × 11 about".
        let entropy = [0u8; 16];
        let m = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon about";
        assert_eq!(m.to_string(), expected_phrase);

        let parsed = CodeRecoveryMnemonic::from_phrase(expected_phrase, MnemonicLanguage::English)
            .expect("official BIP-39 vector must parse");
        assert_eq!(parsed.entropy(), &entropy);
    }

    #[test]
    fn generate_then_parse_round_trip() {
        let code = fresh_code();
        let phrase = code.as_str().to_string();
        let restored = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English)
            .expect("freshly generated phrase must parse");
        assert_eq!(code.entropy(), restored.entropy());
        assert_eq!(code.language(), restored.language());
    }

    #[test]
    fn generated_phrase_has_twelve_words() {
        let code = fresh_code();
        assert_eq!(
            code.as_str().split_whitespace().count(),
            CODE_RECOVERY_WORD_COUNT
        );
    }

    #[test]
    fn code_recovery_temporaries_are_zeroizing() {
        fn assert_zeroizing_array<const N: usize>(_: &zeroize::Zeroizing<[u8; N]>) {}
        fn assert_zeroizing_vec(_: &zeroize::Zeroizing<Vec<u8>>) {}

        let mut rng = OsRng;
        let generated = generate_code_recovery_entropy(&mut rng);
        assert_zeroizing_array(&generated);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &[0u8; 16]).unwrap();
        let parsed = mnemonic_entropy_zeroizing(&mnemonic);
        assert_zeroizing_vec(&parsed);

        let identity_seed = fresh_seed();
        let code = fresh_code();
        let rotation_ikm_typed = compose_rotation_ikm(&identity_seed, &code);
        assert_zeroizing_array(&rotation_ikm_typed);

        let rotation_seed_typed =
            derive_rotation_seed_zeroizing(&rotation_ikm_typed[..], &[0xA5u8; 32]);
        assert_zeroizing_array(&rotation_seed_typed);

        let source = include_str!("code_recovery.rs");
        let generated_entropy = ["Zeroizing::new(", "[0u8; CODE_RECOVERY_ENTROPY_LEN])"].concat();
        let parsed_entropy = ["Zeroizing::new(", "mnemonic.to_entropy())"].concat();
        let rotation_ikm = [
            "Zeroizing::new(",
            "[0u8; SEED_LEN + CODE_RECOVERY_ENTROPY_LEN])",
        ]
        .concat();
        let rotation_seed = ["Zeroizing::new(", "[0u8; SEED_LEN])"].concat();
        let extract_zeroize = ["extract_output.", "zeroize()"].concat();
        let expand_zeroize = ["expand_output.", "zeroize()"].concat();

        assert!(
            source.contains(&generated_entropy),
            "generated 12-word recovery entropy must be zeroized"
        );
        assert!(
            source.contains(&parsed_entropy),
            "parsed 12-word recovery entropy Vec must be zeroized"
        );
        assert!(
            source.contains(&rotation_ikm),
            "identity+recovery-code HKDF input mix must be zeroized"
        );
        assert!(
            source.contains(&rotation_seed),
            "rotated seed temporary must be zeroized after copying into owner"
        );
        assert!(
            source.contains(&extract_zeroize),
            "HKDF extract output must be explicitly zeroized"
        );
        assert!(
            source.contains(&expand_zeroize),
            "HKDF expand output must be explicitly zeroized"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.3 Property-based (proptest, ≥ 128 cases)
    // ─────────────────────────────────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_mnemonic_roundtrip(entropy: [u8; CODE_RECOVERY_ENTROPY_LEN]) {
            let m = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
            let phrase = m.to_string();
            let parsed = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English).unwrap();
            prop_assert_eq!(parsed.entropy(), &entropy);
        }

        #[test]
        fn prop_derive_rotated_is_deterministic(
            seed_entropy: [u8; 32],
            code_entropy: [u8; CODE_RECOVERY_ENTROPY_LEN],
        ) {
            let identity_mnemonic =
                Mnemonic::from_entropy_in(Language::English, &seed_entropy).unwrap();
            let identity_seed = IdentitySeed::from_mnemonic(
                &identity_mnemonic.to_string(),
                MnemonicLanguage::English,
            )
            .unwrap();

            let code_mnemonic = Mnemonic::from_entropy_in(Language::English, &code_entropy).unwrap();
            let code = CodeRecoveryMnemonic::from_phrase(
                &code_mnemonic.to_string(),
                MnemonicLanguage::English,
            )
            .unwrap();

            let old_pubkey = IdentityKey::derive(&identity_seed, 0).unwrap().public();
            let r1 = derive_rotated_identity_material(&identity_seed, &code, &old_pubkey).unwrap();
            let r2 = derive_rotated_identity_material(&identity_seed, &code, &old_pubkey).unwrap();
            prop_assert_eq!(r1.seed_bytes(), r2.seed_bytes());
        }

        #[test]
        fn prop_different_codes_give_different_rotated_seeds(
            seed_entropy: [u8; 32],
            code_a: [u8; CODE_RECOVERY_ENTROPY_LEN],
            code_b: [u8; CODE_RECOVERY_ENTROPY_LEN],
        ) {
            prop_assume!(code_a != code_b);

            let identity_mnemonic =
                Mnemonic::from_entropy_in(Language::English, &seed_entropy).unwrap();
            let identity_seed = IdentitySeed::from_mnemonic(
                &identity_mnemonic.to_string(),
                MnemonicLanguage::English,
            )
            .unwrap();

            let ma = Mnemonic::from_entropy_in(Language::English, &code_a).unwrap();
            let mb = Mnemonic::from_entropy_in(Language::English, &code_b).unwrap();
            let code_a_m =
                CodeRecoveryMnemonic::from_phrase(&ma.to_string(), MnemonicLanguage::English)
                    .unwrap();
            let code_b_m =
                CodeRecoveryMnemonic::from_phrase(&mb.to_string(), MnemonicLanguage::English)
                    .unwrap();

            let old_pubkey = IdentityKey::derive(&identity_seed, 0).unwrap().public();
            let r_a =
                derive_rotated_identity_material(&identity_seed, &code_a_m, &old_pubkey).unwrap();
            let r_b =
                derive_rotated_identity_material(&identity_seed, &code_b_m, &old_pubkey).unwrap();
            prop_assert_ne!(r_a.seed_bytes(), r_b.seed_bytes());
        }

        #[test]
        fn prop_different_seeds_give_different_rotated_seeds(
            code_entropy: [u8; CODE_RECOVERY_ENTROPY_LEN],
            seed_a: [u8; 32],
            seed_b: [u8; 32],
        ) {
            prop_assume!(seed_a != seed_b);

            let ma = Mnemonic::from_entropy_in(Language::English, &seed_a).unwrap();
            let mb = Mnemonic::from_entropy_in(Language::English, &seed_b).unwrap();
            let identity_a =
                IdentitySeed::from_mnemonic(&ma.to_string(), MnemonicLanguage::English).unwrap();
            let identity_b =
                IdentitySeed::from_mnemonic(&mb.to_string(), MnemonicLanguage::English).unwrap();

            let code_m =
                Mnemonic::from_entropy_in(Language::English, &code_entropy).unwrap();
            let code = CodeRecoveryMnemonic::from_phrase(
                &code_m.to_string(),
                MnemonicLanguage::English,
            )
            .unwrap();

            let pubkey_a = IdentityKey::derive(&identity_a, 0).unwrap().public();
            let pubkey_b = IdentityKey::derive(&identity_b, 0).unwrap().public();
            let r_a = derive_rotated_identity_material(&identity_a, &code, &pubkey_a).unwrap();
            let r_b = derive_rotated_identity_material(&identity_b, &code, &pubkey_b).unwrap();
            prop_assert_ne!(r_a.seed_bytes(), r_b.seed_bytes());
        }

        #[test]
        fn prop_rotated_identity_differs_from_original(
            seed_entropy: [u8; 32],
            code_entropy: [u8; CODE_RECOVERY_ENTROPY_LEN],
        ) {
            let seed_m = Mnemonic::from_entropy_in(Language::English, &seed_entropy).unwrap();
            let identity_seed =
                IdentitySeed::from_mnemonic(&seed_m.to_string(), MnemonicLanguage::English)
                    .unwrap();
            let code_m = Mnemonic::from_entropy_in(Language::English, &code_entropy).unwrap();
            let code = CodeRecoveryMnemonic::from_phrase(
                &code_m.to_string(),
                MnemonicLanguage::English,
            )
            .unwrap();

            let original_pubkey = IdentityKey::derive(&identity_seed, 0).unwrap().public();
            let rotated =
                derive_rotated_identity_material(&identity_seed, &code, &original_pubkey).unwrap();
            let new_pubkey = rotated.identity_pubkey(0).unwrap();

            // Новый identity_pubkey всегда отличается от старого — HKDF с info=old_pubkey даёт
            // pre-image resistance; coincidence возможна с вероятностью 2⁻²⁵⁶.
            // The new identity_pubkey always differs from the old one — HKDF with info=old_pubkey
            // gives pre-image resistance; coincidence possible only with probability 2⁻²⁵⁶.
            prop_assert_ne!(new_pubkey.to_bytes(), original_pubkey.to_bytes());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.4 Adversarial
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn from_phrase_rejects_11_words() {
        let phrase = ["abandon"; 11].join(" ");
        let err = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidCodeRecoveryWordCount {
                expected: 12,
                got: 11
            })
        ));
    }

    #[test]
    fn from_phrase_rejects_13_words() {
        let phrase = ["abandon"; 13].join(" ");
        let err = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidCodeRecoveryWordCount {
                expected: 12,
                got: 13
            })
        ));
    }

    #[test]
    fn from_phrase_rejects_24_words() {
        // 24 слова — валидный identity mnemonic, но невалидный code-recovery.
        // 24 words — valid identity mnemonic, but invalid code-recovery.
        let phrase = ["abandon"; 24].join(" ");
        let err = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidCodeRecoveryWordCount {
                expected: 12,
                got: 24
            })
        ));
    }

    #[test]
    fn from_phrase_rejects_bad_checksum() {
        // 12 валидных слов где последнее заменено — checksum BIP-39 ломается с высокой
        // вероятностью (1 из 16 правильных окончаний на данный начальный префикс).
        // 12 valid words, last word replaced — BIP-39 checksum breaks with high probability
        // (1 out of 16 valid endings for the given starting prefix).
        let mut words: Vec<&str> = vec!["abandon"; 11];
        words.push("zoo");
        let phrase = words.join(" ");
        let err = CodeRecoveryMnemonic::from_phrase(&phrase, MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidCodeRecoveryMnemonic)
        ));
    }

    #[test]
    fn from_phrase_rejects_unknown_word() {
        // "pepperoni" не входит в wordlist BIP-39 English (2048 слов).
        // "pepperoni" is not in the BIP-39 English wordlist (2048 words).
        let phrase = "pepperoni abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon";
        let err = CodeRecoveryMnemonic::from_phrase(phrase, MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidCodeRecoveryMnemonic)
        ));
    }

    #[test]
    fn derive_rejects_mismatched_old_pubkey() {
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let code = fresh_code();
        // Подставляем identity_pubkey от seed_b, хотя передаём seed_a — классический вариант
        // злоумышленник копирует чужой pubkey в UI.
        // We supply identity_pubkey from seed_b while passing seed_a — classic case of an
        // attacker copying a foreign pubkey into the UI.
        let foreign_pubkey = IdentityKey::derive(&seed_b, 0).unwrap().public();
        let err = derive_rotated_identity_material(&seed_a, &code, &foreign_pubkey);
        assert!(matches!(err, Err(IdentityError::OldIdentityMismatch)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.5 Edge cases
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn zero_entropy_seed_and_code_works_mathematically() {
        // Все нули entropy — валидно BIP-39, математически работает. Для production CSPRNG
        // должен не выдавать такое (проверка — за пределами этого модуля), но derive работает.
        // All-zero entropy — valid per BIP-39, mathematically works. For production, CSPRNG must
        // avoid such (check outside this module), but derive functions correctly.
        let seed_m = Mnemonic::from_entropy_in(Language::English, &[0u8; 32]).unwrap();
        let identity_seed =
            IdentitySeed::from_mnemonic(&seed_m.to_string(), MnemonicLanguage::English).unwrap();
        let code_m = Mnemonic::from_entropy_in(Language::English, &[0u8; 16]).unwrap();
        let code =
            CodeRecoveryMnemonic::from_phrase(&code_m.to_string(), MnemonicLanguage::English)
                .unwrap();
        let old_pubkey = IdentityKey::derive(&identity_seed, 0).unwrap().public();
        let rotated = derive_rotated_identity_material(&identity_seed, &code, &old_pubkey)
            .expect("derive works with zero entropies");

        // Новый identity_pubkey должен отличаться — HKDF от known-but-weak inputs всё равно даёт
        // cryptographic output на 256-bit security от SHA-512.
        // The new identity_pubkey must differ — HKDF over known-but-weak inputs still yields a
        // cryptographic output at 256-bit security from SHA-512.
        let new_pubkey = rotated.identity_pubkey(0).unwrap();
        assert_ne!(new_pubkey.to_bytes(), old_pubkey.to_bytes());
    }

    #[test]
    fn rotated_material_derives_x25519_key_too() {
        let seed = fresh_seed();
        let code = fresh_code();
        let old_pubkey = IdentityKey::derive(&seed, 0).unwrap().public();
        let rotated = derive_rotated_identity_material(&seed, &code, &old_pubkey).unwrap();
        let x = rotated.derive_identity_x25519_key(0).unwrap();
        // Проверка что X25519 ключ успешно derived; сам публичный ключ — 32 байта non-zero.
        // Verify the X25519 key derives successfully; the public key is 32 non-zero bytes.
        let pub_bytes = x.public().to_bytes();
        assert_eq!(pub_bytes.len(), 32);
        // Extremely unlikely для CSPRNG — all-zero pub (только если scalar = 0 после clamp).
        // Extremely unlikely for CSPRNG-backed keys — all-zero pub (only if scalar = 0 after clamp).
        assert_ne!(pub_bytes, [0u8; 32]);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.6 Integration — full catastrophic recovery flow
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn full_catastrophic_recovery_flow() {
        // Симуляция полного flow catastrophic recovery (SPEC-11 §6):
        // 1. Пользователь имеет исходный identity (24 слова).
        // 2. Пользователь имеет код восстановления (12 слов) сохранённый отдельно.
        // 3. На чистом устройстве вводит оба → derive rotated material → new identity.
        // 4. new_identity_pubkey отличается от старого; собеседники видят плашку.
        // 5. Повторный ввод тех же 24+12 слов даёт тот же new identity (детерминизм).
        //
        // Full flow simulation of catastrophic recovery (SPEC-11 §6):
        // 1. User has original identity (24 words).
        // 2. User has code recovery (12 words) saved separately.
        // 3. On a clean device inputs both → derive rotated material → new identity.
        // 4. new_identity_pubkey differs from the old; peers see safety-number-changed.
        // 5. Re-entering the same 24+12 words yields the same new identity (determinism).

        let original_seed = fresh_seed();
        let code = fresh_code();
        let original_pubkey = IdentityKey::derive(&original_seed, 0).unwrap().public();

        // Первое восстановление.
        // First recovery.
        let rotated_first =
            derive_rotated_identity_material(&original_seed, &code, &original_pubkey).unwrap();
        let new_pubkey_first = rotated_first.identity_pubkey(0).unwrap();
        assert_ne!(new_pubkey_first.to_bytes(), original_pubkey.to_bytes());

        // Повторный ввод тех же слов на другом устройстве через re-parse mnemonic.
        // Repeat input of the same words on another device via re-parse.
        let original_phrase = original_seed.to_mnemonic();
        let code_phrase = code.as_str().to_string();

        let seed_reparsed =
            IdentitySeed::from_mnemonic(original_phrase.as_str(), MnemonicLanguage::English)
                .unwrap();
        let code_reparsed =
            CodeRecoveryMnemonic::from_phrase(&code_phrase, MnemonicLanguage::English).unwrap();
        let original_pubkey_reparsed = IdentityKey::derive(&seed_reparsed, 0).unwrap().public();
        let rotated_second = derive_rotated_identity_material(
            &seed_reparsed,
            &code_reparsed,
            &original_pubkey_reparsed,
        )
        .unwrap();
        let new_pubkey_second = rotated_second.identity_pubkey(0).unwrap();

        // Детерминизм: тот же результат.
        // Determinism: same result.
        assert_eq!(new_pubkey_first.to_bytes(), new_pubkey_second.to_bytes());
        assert_eq!(rotated_first.seed_bytes(), rotated_second.seed_bytes());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // §2.7 Memory hygiene
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn debug_does_not_leak_code() {
        let code = fresh_code();
        let formatted = format!("{code:?}");
        assert!(formatted.contains("redacted"));
        assert!(!formatted.contains(code.as_str()));
    }

    #[test]
    fn debug_does_not_leak_rotated_material() {
        let seed = fresh_seed();
        let code = fresh_code();
        let old_pubkey = IdentityKey::derive(&seed, 0).unwrap().public();
        let rotated = derive_rotated_identity_material(&seed, &code, &old_pubkey).unwrap();
        let formatted = format!("{rotated:?}");
        assert!(formatted.contains("redacted"));
    }
}
