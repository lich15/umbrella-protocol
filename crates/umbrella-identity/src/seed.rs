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
///
/// # Round-5 device-capture closure (F-PHD-DC-R7-3)
///
/// Round-4 R7 lldb scan нашёл 2 hits для entropy: **stack** (через
/// `*entropy` deref от `Zeroizing<[u8; 32]>` в конструктор) + **heap**
/// (positive control). Stack hit переживал `drop(seed)` потому что
/// `Zeroize` derive покрывает только field-resident bytes, не stack-spill
/// слоты от копирования при struct construction.
///
/// Closure: `entropy` и `seed` хранятся как `Box<[u8; N]>` — heap-resident
/// от первого момента, нет stack copy на момент construction. LLVM не
/// spillает `Box<[u8; N]>` потому что это 8-byte pointer, не 32/64-byte
/// массив. `Zeroize` derive wipes `**self.entropy` через `Box::zeroize`
/// (via `*mut [u8; N]`).
///
/// Identity seed: 32-byte entropy plus derived 64-byte PBKDF2 seed.
///
/// # Round-5 device-capture closure (F-PHD-DC-R7-3)
///
/// The round-4 R7 lldb scan found 2 hits for entropy: **stack** (via the
/// `*entropy` deref from a `Zeroizing<[u8; 32]>` in the constructor) +
/// **heap** (positive control). The stack hit survived `drop(seed)`
/// because the `Zeroize` derive covers only field-resident bytes, not
/// stack-spill slots from copying during struct construction.
///
/// Closure: `entropy` and `seed` are stored as `Box<[u8; N]>` — heap-
/// resident from inception, no stack copy at construction time. LLVM
/// does not spill `Box<[u8; N]>` because it is an 8-byte pointer, not a
/// 32/64-byte array. The `Zeroize` derive wipes `**self.entropy` via
/// `Box::zeroize` (through `*mut [u8; N]`).
pub struct IdentitySeed {
    /// 32 байта entropy на heap. `Box::zeroize` wipes `**entropy` корректно.
    /// 32-byte entropy on the heap. `Box::zeroize` wipes `**entropy` correctly.
    entropy: Box<[u8; ENTROPY_LEN]>,

    /// 64 байта PBKDF2 seed на heap. Same heap-resident semantics as `entropy`.
    /// 64-byte PBKDF2 seed on the heap. Same heap-resident semantics as `entropy`.
    seed: Box<[u8; SEED_LEN]>,

    /// Не секрет, но нужно скипнуть для derive.
    /// Not a secret, but skipped from the manual zeroize impl.
    language: MnemonicLanguage,
}

// Custom Zeroize / ZeroizeOnDrop вместо derive — `Zeroize` derive не
// работает для `Box<[u8; N]>` напрямую (нужно dereference + zeroize the
// pointed-to array). Pattern: `(*self.entropy).zeroize()` — `*Box`
// deref'ит до `[u8; N]` который имплементирует `Zeroize`.
//
// Custom Zeroize / ZeroizeOnDrop instead of derive — the `Zeroize` derive
// does not work directly for `Box<[u8; N]>` (we have to dereference +
// zeroize the pointed-to array). Pattern: `(*self.entropy).zeroize()` —
// `*Box` derefs to the `[u8; N]` value which implements `Zeroize`.
impl Zeroize for IdentitySeed {
    fn zeroize(&mut self) {
        // Single deref: `*Box<[u8; N]>` lookups `[u8; N]`; `Zeroize` for
        // arrays writes zeros volatile-safely.
        // Single deref: `*Box<[u8; N]>` looks up the `[u8; N]` value;
        // `Zeroize` for arrays writes zeros volatile-safely.
        self.entropy.as_mut().zeroize();
        self.seed.as_mut().zeroize();
        // `language` — public enum, не секрет; skip.
        // `language` — public enum, not a secret; skip.
    }
}

impl ZeroizeOnDrop for IdentitySeed {}

impl Drop for IdentitySeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl IdentitySeed {
    /// Генерирует новый identity seed из CSPRNG. **Heap-resident from
    /// inception** — round-5 device-capture closure F-PHD-DC-R7-3.
    ///
    /// # Round-6 deprecation notice
    ///
    /// На production пути этот метод **больше не вызывается**. Round-6
    /// distributed identity model перемещает identity-seed generation на
    /// 5 серверов через FROST DKG (см. `umbrella-threshold-identity::dkg`).
    /// На устройстве идентичность теперь существует только как public key
    /// + 5 anonymous IDs + cached offline ticket; 24+12 слов **никогда**
    ///   не материализуются на одном устройстве.
    ///
    /// Метод оставлен для тестов (`#[cfg(test)]`-style use) и legacy
    /// migration paths, но в production code use
    /// `umbrella_client::keystore::distributed_identity_client::bootstrap_account`.
    ///
    /// Generates a new identity seed from a CSPRNG. **Heap-resident from
    /// inception** — round-5 device-capture closure F-PHD-DC-R7-3.
    ///
    /// # Round-6 deprecation notice
    ///
    /// On the production path this method is **no longer called**. Round-6
    /// distributed identity moves seed generation to 5 servers via FROST
    /// DKG (see `umbrella-threshold-identity::dkg`). On-device identity now
    /// exists only as a public key + 5 anonymous IDs + cached offline
    /// ticket; the 24+12 words **never** materialise on a single device.
    ///
    /// The method is kept for tests and legacy migration paths; production
    /// code should use
    /// `umbrella_client::keystore::distributed_identity_client::bootstrap_account`.
    #[deprecated(
        since = "1.1.0",
        note = "Round-6 distributed identity: use \
                umbrella_client::keystore::distributed_identity_client::bootstrap_account \
                instead. On-device seed generation is forbidden on the production path."
    )]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R, language: MnemonicLanguage) -> Self {
        // Allocate heap storage FIRST, then fill in place. `Box::new` returns
        // heap pointer without a stack-resident intermediate; subsequent
        // `rng.fill_bytes(&mut **entropy_box)` writes directly into the
        // heap allocation.
        //
        // Allocate heap storage FIRST, then fill in place. `Box::new`
        // returns a heap pointer with no stack-resident intermediate;
        // the subsequent `rng.fill_bytes(&mut **entropy_box)` writes
        // directly into the heap allocation.
        let mut entropy_box: Box<[u8; ENTROPY_LEN]> = Box::new([0u8; ENTROPY_LEN]);
        rng.fill_bytes(entropy_box.as_mut());

        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: 32-byte entropy is always valid BIP-39 input"
        )]
        let mnemonic = Mnemonic::from_entropy_in(language.as_bip39(), entropy_box.as_ref())
            .expect("32-byte entropy is always valid for BIP-39");

        // `mnemonic.to_seed_normalized("")` returns `[u8; 64]` by value;
        // we copy the bytes into a freshly-allocated heap `Box<[u8; 64]>`.
        // The stack copy from `to_seed_normalized` is covered by
        // `Zeroizing`; the heap copy lives in `seed_box`.
        //
        // `mnemonic.to_seed_normalized("")` returns `[u8; 64]` by value;
        // we copy the bytes into a freshly-allocated heap `Box<[u8; 64]>`.
        // The stack copy from `to_seed_normalized` is covered by
        // `Zeroizing`; the heap copy lives in `seed_box`.
        let seed_bytes_temp = Zeroizing::new(mnemonic.to_seed_normalized(""));
        let mut seed_box: Box<[u8; SEED_LEN]> = Box::new([0u8; SEED_LEN]);
        seed_box.as_mut().copy_from_slice(seed_bytes_temp.as_ref());

        Self {
            entropy: entropy_box,
            seed: seed_box,
            language,
        }
    }

    /// Восстанавливает identity seed из мнемонической фразы.
    /// Восстановление падает если фраза не из 24 слов или checksum неверная.
    /// **Heap-resident from inception** — round-5 device-capture closure F-PHD-DC-R7-3.
    ///
    /// Restores identity seed from a mnemonic phrase. Fails if the phrase
    /// is not exactly 24 words or has an invalid checksum. **Heap-resident
    /// from inception** — round-5 device-capture closure F-PHD-DC-R7-3.
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

        // Heap allocate FIRST, then copy in place. No stack-resident
        // `Zeroizing<[u8; 32]>` intermediate that LLVM might spill.
        //
        // Heap allocate FIRST, then copy in place. No stack-resident
        // `Zeroizing<[u8; 32]>` intermediate that LLVM might spill.
        let mut entropy_box: Box<[u8; ENTROPY_LEN]> = Box::new([0u8; ENTROPY_LEN]);
        entropy_box.as_mut().copy_from_slice(&entropy_vec);

        let seed_bytes_temp = Zeroizing::new(mnemonic.to_seed_normalized(""));
        let mut seed_box: Box<[u8; SEED_LEN]> = Box::new([0u8; SEED_LEN]);
        seed_box.as_mut().copy_from_slice(seed_bytes_temp.as_ref());

        Ok(Self {
            entropy: entropy_box,
            seed: seed_box,
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
        let mnemonic = Mnemonic::from_entropy_in(self.language.as_bip39(), self.entropy.as_ref())
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
        // Round-5 device-capture closure F-PHD-DC-R7-3 refactored the
        // generation paths to write directly into `Box<[u8; N]>` heap
        // allocations instead of stack-resident `Zeroizing<[u8; N]>`
        // copies. The remaining zeroized temporaries are:
        //
        // 1. `mnemonic.to_entropy()` Vec (in `from_mnemonic` only).
        // 2. `mnemonic.to_seed_normalized("")` byte array.
        //
        // Round-5 device-capture closure F-PHD-DC-R7-3 refactored the
        // generation paths to write directly into `Box<[u8; N]>` heap
        // allocations instead of stack-resident `Zeroizing<[u8; N]>`
        // copies. The remaining zeroized temporaries are:
        //
        // 1. `mnemonic.to_entropy()` Vec (in `from_mnemonic` only).
        // 2. `mnemonic.to_seed_normalized("")` byte array.
        let source = include_str!("seed.rs");
        let mnemonic_entropy_zeroizing = ["Zeroizing::new(", "mnemonic.to_entropy())"].concat();
        let seed_zeroizing = ["Zeroizing::new(", "mnemonic.to_seed_normalized(\"\")"].concat();

        assert!(
            source.contains(&mnemonic_entropy_zeroizing),
            "mnemonic entropy Vec temporary must be zeroized"
        );
        assert!(
            source.contains(&seed_zeroizing),
            "BIP-39 PBKDF2 seed temporary must be zeroized"
        );

        // Round-5 closure: storage is heap-resident `Box<[u8; N]>`,
        // not stack `[u8; N]`. The struct field declarations must
        // reflect this.
        //
        // Round-5 closure: storage is heap-resident `Box<[u8; N]>`, not
        // stack `[u8; N]`. The struct field declarations must reflect this.
        assert!(
            source.contains("entropy: Box<[u8; ENTROPY_LEN]>"),
            "R7-3 closure: entropy must be Box-allocated (heap-resident)"
        );
        assert!(
            source.contains("seed: Box<[u8; SEED_LEN]>"),
            "R7-3 closure: seed must be Box-allocated (heap-resident)"
        );
    }

    /// Round-5 device-capture closure F-PHD-DC-R7-3 acceptance test.
    /// Verifies that the entropy + seed pointers returned by getters
    /// reside on the heap (not stack). Heuristic: compare the pointer
    /// value to a known stack address.
    ///
    /// Round-5 device-capture closure F-PHD-DC-R7-3 acceptance test.
    /// Verifies that the entropy + seed pointers returned by getters
    /// reside on the heap (not the stack). Heuristic: compare the
    /// pointer value to a known stack address.
    #[test]
    fn r7_closure_entropy_and_seed_are_heap_resident() {
        let stack_anchor = 0u8;
        let stack_addr = &stack_anchor as *const u8 as usize;

        let mut rng = OsRng;
        let s = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let entropy_addr = s.entropy().as_ptr() as usize;
        let seed_addr = s.seed().as_ptr() as usize;

        // On macOS arm64 / Linux x86_64, stack grows down from ~0x16f....
        // for main thread and heap is at ~0x600.... for Apple Silicon
        // jemalloc / system allocator. The exact addresses depend on
        // platform, but the distance between stack and heap is always
        // multi-megabyte. We assert |stack - heap_ptr| > 64 KiB which
        // catches any stack-resident array regression.
        //
        // On macOS arm64 / Linux x86_64 the stack grows down from
        // ~0x16f.... for the main thread and heap sits at ~0x600....
        // for Apple Silicon jemalloc / system allocator. Exact addresses
        // depend on platform, but the stack-to-heap distance is always
        // multi-megabyte. Asserting |stack - heap_ptr| > 64 KiB catches
        // any stack-resident array regression.
        let entropy_dist = entropy_addr.abs_diff(stack_addr);
        let seed_dist = seed_addr.abs_diff(stack_addr);
        assert!(
            entropy_dist > 64 * 1024,
            "R7-3 closure regression: entropy lives within 64 KiB of stack (entropy {entropy_addr:x} stack {stack_addr:x})"
        );
        assert!(
            seed_dist > 64 * 1024,
            "R7-3 closure regression: seed lives within 64 KiB of stack (seed {seed_addr:x} stack {stack_addr:x})"
        );
    }
}
