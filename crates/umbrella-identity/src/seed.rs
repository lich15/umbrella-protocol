//! BIP-39 256-bit entropy ⇄ 24-word мнемоническая фраза ⇄ 64-byte seed.
//! BIP-39 256-bit entropy ⇄ 24-word mnemonic phrase ⇄ 64-byte seed.

use bip39::{Language, Mnemonic};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{IdentityError, Result};

/// Ожидаемая энтропия в байтах: 32 байта = 256 бит = 24 слова BIP-39.
/// Expected entropy in bytes: 32 bytes = 256 bits = 24 BIP-39 words.
pub const ENTROPY_LEN: usize = 32;

/// Количество слов в мнемонической фразе для нашего уровня безопасности.
/// Mnemonic word count for our security level.
pub const MNEMONIC_WORD_COUNT: usize = 24;

/// Размер выходного seed после PBKDF2 BIP-39 (всегда 64 байта).
/// Output seed size after BIP-39 PBKDF2 (always 64 bytes).
pub const SEED_LEN: usize = 64;

/// Поддерживаемые языки wordlist BIP-39; для приватных мессенджеров обычно EN.
/// Supported BIP-39 wordlists; for private messengers typically EN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnemonicLanguage {
    /// Английский wordlist (рекомендуется).
    /// English wordlist (recommended).
    English,
}

impl MnemonicLanguage {
    fn as_bip39(self) -> Language {
        match self {
            Self::English => Language::English,
        }
    }
}

/// 24-словная BIP-39 мнемоника, обнуляется при Drop.
/// 24-word BIP-39 mnemonic, zeroized on Drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityMnemonic(String);

impl IdentityMnemonic {
    /// Возвращает строковое представление мнемоники (24 слова через пробел).
    /// Returns the string representation (24 space-separated words).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for IdentityMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentityMnemonic(<redacted>)")
    }
}

/// Identity seed: 32 байта entropy + производный 64-байтовый PBKDF2 seed.
/// Identity seed: 32-byte entropy plus derived 64-byte PBKDF2 seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySeed {
    entropy: [u8; ENTROPY_LEN],
    seed: [u8; SEED_LEN],
    // Не секрет, но нужно скипнуть для derive.
    // Not a secret, but we must skip it for the derive macro.
    #[zeroize(skip)]
    language: MnemonicLanguage,
}

impl IdentitySeed {
    /// Генерирует новый identity seed из CSPRNG.
    /// Generates a new identity seed from a CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R, language: MnemonicLanguage) -> Self {
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        rng.fill_bytes(&mut entropy[..]);
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: 32-byte entropy is always valid BIP-39 input"
        )]
        let mnemonic = Mnemonic::from_entropy_in(language.as_bip39(), &entropy[..])
            .expect("32-byte entropy is always valid for BIP-39");
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        Self {
            entropy: *entropy,
            seed: *seed,
            language,
        }
    }

    /// Восстанавливает identity seed из мнемонической фразы.
    /// Восстановление падает если фраза не из 24 слов или checksum неверная.
    /// Restores identity seed from a mnemonic phrase.
    /// Fails if the phrase is not exactly 24 words or has an invalid checksum.
    pub fn from_mnemonic(phrase: &str, language: MnemonicLanguage) -> Result<Self> {
        let trimmed = phrase.trim();
        let word_count = trimmed.split_whitespace().count();
        if word_count != MNEMONIC_WORD_COUNT {
            return Err(IdentityError::InvalidWordCount {
                expected: MNEMONIC_WORD_COUNT,
                got: word_count,
            });
        }
        let mnemonic = Mnemonic::parse_in_normalized(language.as_bip39(), trimmed)
            .map_err(|_| IdentityError::InvalidMnemonic)?;
        let entropy_vec = Zeroizing::new(mnemonic.to_entropy());
        if entropy_vec.len() != ENTROPY_LEN {
            return Err(IdentityError::InvalidWordCount {
                expected: MNEMONIC_WORD_COUNT,
                got: word_count,
            });
        }
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        entropy[..].copy_from_slice(&entropy_vec);
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        Ok(Self {
            entropy: *entropy,
            seed: *seed,
            language,
        })
    }

    /// Возвращает мнемоническую фразу из 24 слов; владелец отвечает за её безопасное хранение.
    /// Returns the 24-word mnemonic phrase; the owner is responsible for safe storage.
    pub fn to_mnemonic(&self) -> IdentityMnemonic {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: self.entropy is always 32 bytes by struct invariant"
        )]
        let mnemonic = Mnemonic::from_entropy_in(self.language.as_bip39(), &self.entropy)
            .expect("entropy is always 32 bytes here");
        IdentityMnemonic(mnemonic.to_string())
    }

    /// Возвращает 32-байтовое entropy для дальнейшего derive (BIP-32-Ed25519).
    /// Returns the 32-byte entropy for downstream derive (BIP-32-Ed25519).
    pub fn entropy(&self) -> &[u8; ENTROPY_LEN] {
        &self.entropy
    }

    /// Возвращает 64-байтовый PBKDF2 seed (используется как master для KDF).
    /// Returns the 64-byte PBKDF2 seed (used as KDF master).
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Возвращает выбранный язык wordlist.
    /// Returns the chosen wordlist language.
    pub fn language(&self) -> MnemonicLanguage {
        self.language
    }
}

impl core::fmt::Debug for IdentitySeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentitySeed(<redacted>, language={:?})", self.language)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn generate_then_restore_round_trip() {
        let mut rng = OsRng;
        let original = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let phrase = original.to_mnemonic();
        let restored = IdentitySeed::from_mnemonic(phrase.as_str(), MnemonicLanguage::English)
            .expect("freshly generated phrase must restore");
        assert_eq!(original.entropy(), restored.entropy());
        assert_eq!(original.seed(), restored.seed());
    }

    #[test]
    fn wrong_word_count_rejected() {
        let bad = "abandon ".repeat(12);
        let err = IdentitySeed::from_mnemonic(bad.trim(), MnemonicLanguage::English);
        assert!(matches!(
            err,
            Err(IdentityError::InvalidWordCount {
                expected: 24,
                got: 12
            })
        ));
    }

    #[test]
    fn bad_checksum_rejected() {
        // Валидные 24 слова, последнее заменено на любое валидное другое слово —
        // checksum BIP-39 ломается с подавляющей вероятностью.
        // Valid 24 words, last replaced with any other valid word —
        // BIP-39 checksum breaks with overwhelming probability.
        let mut words: Vec<&str> = vec!["abandon"; 23];
        words.push("zoo");
        let phrase = words.join(" ");
        let err = IdentitySeed::from_mnemonic(&phrase, MnemonicLanguage::English);
        assert!(matches!(err, Err(IdentityError::InvalidMnemonic)));
    }

    #[test]
    fn bip39_test_vector_24_words() {
        // BIP-39 official test vector: 32 zero bytes entropy → known 24-word mnemonic.
        let entropy = [0u8; 32];
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon art";
        assert_eq!(mnemonic.to_string(), expected_phrase);

        let restored =
            IdentitySeed::from_mnemonic(expected_phrase, MnemonicLanguage::English).unwrap();
        assert_eq!(restored.entropy(), &entropy);
    }

    #[test]
    fn debug_does_not_leak_seed() {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let formatted = format!("{seed:?}");
        assert!(formatted.contains("redacted"));
        let phrase = seed.to_mnemonic();
        let phrase_formatted = format!("{phrase:?}");
        assert!(phrase_formatted.contains("redacted"));
    }

    #[test]
    fn bip39_derivation_temporaries_are_zeroizing() {
        let source = include_str!("seed.rs");
        let entropy_zeroizing = ["Zeroizing::new(", "[0u8; ENTROPY_LEN])"].concat();
        let mnemonic_entropy_zeroizing = ["Zeroizing::new(", "mnemonic.to_entropy())"].concat();
        let seed_zeroizing = ["Zeroizing::new(", "mnemonic.to_seed_normalized(\"\")"].concat();

        assert!(
            source.contains(&entropy_zeroizing),
            "generated entropy temporary must be zeroized"
        );
        assert!(
            source.contains(&mnemonic_entropy_zeroizing),
            "mnemonic entropy Vec temporary must be zeroized"
        );
        assert!(
            source.contains(&seed_zeroizing),
            "BIP-39 PBKDF2 seed temporary must be zeroized"
        );
    }
}
