//! Hedged-encryption support for X-Wing encaps (Bellare-Hoang-Keelveedhi 2015).
//! Hedged-encryption support for X-Wing encaps (Bellare-Hoang-Keelveedhi 2015).
//!
//! # Назначение
//!
//! Defense-in-depth против compromised CSPRNG. Если adversary контролирует
//! `OsRng` (kernel-level compromise, Debian OpenSSL 2008 pattern,
//! Cloudflare 2017 pattern), стандартный `xwing_encaps` ломается полностью
//! — `xwing_encaps_derand(pk, rng.fill_bytes(seed))` deterministic по
//! seed-у, attacker replicates ss offline. См. R5 reality-pass round 2.
//!
//! Hedged variant: seed для encaps выводится через HKDF-SHA512 над
//! `rng_bytes || hedged_witness`, где `hedged_witness` — 32-byte
//! deterministic derivative of long-term identity secret, недоступный
//! attacker'у даже если он контролирует CSPRNG. Security claim
//! (Bellare-Hoang-Keelveedhi 2015 Theorem 4.1, специализация HKDF-as-RO):
//! если хотя бы одно из `{rng_bytes, hedged_witness}` остаётся
//! uniform-random для attacker'а, output seed вычислительно
//! неотличим от uniform.
//!
//! Это снижает threat surface с **single compromise** (один из двух:
//! либо OsRng либо identity_sk) до **double compromise** (оба
//! одновременно) — две независимые компрометации вместо одной.
//!
//! # Purpose
//!
//! Defense-in-depth against a compromised CSPRNG. If an adversary controls
//! `OsRng` (kernel-level compromise — Debian OpenSSL 2008 pattern,
//! Cloudflare 2017 pattern), the unhedged `xwing_encaps` is fully broken:
//! `xwing_encaps_derand(pk, rng.fill_bytes(seed))` is deterministic in the
//! seed, the attacker replicates ss offline. See R5 reality-pass round 2.
//!
//! The hedged variant derives the encaps seed via HKDF-SHA512 over
//! `rng_bytes || hedged_witness`, where `hedged_witness` is a 32-byte
//! deterministic derivative of the long-term identity secret, unavailable
//! to the attacker even if they control the CSPRNG. Security claim
//! (Bellare-Hoang-Keelveedhi 2015 Theorem 4.1 specialised to HKDF-as-RO):
//! if at least one of `{rng_bytes, hedged_witness}` remains uniform-random
//! to the attacker, the output seed is computationally indistinguishable
//! from uniform.
//!
//! Lowers the threat surface from **single compromise** (either OsRng OR
//! identity_sk) to **double compromise** (both at once) — two independent
//! compromises instead of one.
//!
//! # Storage
//!
//! `HedgedWitness` живёт в `KeyStore` рядом с identity-секретом. Derive
//! детерминистический (HKDF-SHA256 над identity_seed_bytes с info
//! `HEDGED_WITNESS_HKDF_INFO`), поэтому переживает restart без явного
//! персиста — KeyStore::open() пересчитывает его из той же BIP-39 mnemonic.
//! Identity rotation (F-PHD-RETRO-3-E) автоматически генерирует новый
//! witness, потому что меняется identity_seed_bytes.
//!
//! `HedgedWitness` lives in `KeyStore` alongside the identity secret. The
//! derivation is deterministic (HKDF-SHA256 over identity_seed_bytes with
//! info `HEDGED_WITNESS_HKDF_INFO`), so it survives restart without
//! explicit persistence — `KeyStore::open()` re-computes it from the same
//! BIP-39 mnemonic. Identity rotation (F-PHD-RETRO-3-E) automatically
//! generates a fresh witness because identity_seed_bytes changes.
//!
//! # Wire format
//!
//! Witness ничего не меняет в wire format X-Wing. Только генерация seed
//! внутри `xwing_encaps_hedged` инжектится HKDF над witness вместо чистого
//! `rng.fill_bytes`. Получатель использует тот же `xwing_decaps` —
//! изменение sender-only.
//!
//! No change to X-Wing wire format. Only the seed generation inside
//! `xwing_encaps_hedged` becomes HKDF over witness instead of raw
//! `rng.fill_bytes`. The receiver still uses the same `xwing_decaps` —
//! the change is sender-only.

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use umbrella_crypto_primitives::MlockedSecret;
use zeroize::Zeroize;

use crate::constants::XWING_ENCAPS_SEED_LEN;
use crate::error::{PqError, Result};

/// Длина hedged witness в байтах (32, чтобы совпадать по объёму с одним
/// раундом ML-KEM-768 seed material и не давать attacker'у структурного
/// преимущества).
///
/// Hedged witness length in bytes (32, matching one round of ML-KEM-768
/// seed material so the attacker gains no structural advantage).
pub const HEDGED_WITNESS_LEN: usize = 32;

/// HKDF salt для derive `HedgedWitness` из identity_seed (v1, stable wire-level
/// invariant; смена ломает совместимость в пределах одной mnemonic — каждый
/// re-open KeyStore получит другой witness).
///
/// HKDF salt for deriving `HedgedWitness` from identity_seed (v1, stable
/// wire-level invariant; changing this breaks compatibility within one
/// mnemonic — each `KeyStore::open()` will derive a different witness).
pub const HEDGED_WITNESS_HKDF_SALT: &[u8] = b"umbrellax-hedged-witness-v1";

/// HKDF salt для derive `xwing_encaps_hedged` seed (v1, stable wire-level
/// invariant; смена ломает совместимость sender → receiver — это **не**
/// wire-visible, потому что seed уходит в `xwing_encaps_derand`, который
/// производит обычный wire-format, но bytes между двумя sender'ами с
/// разным salt-ом расходятся).
///
/// HKDF salt for deriving the `xwing_encaps_hedged` seed (v1, stable
/// wire-level invariant; changing it breaks sender → receiver
/// compatibility — this is **not** wire-visible because the seed is fed
/// to `xwing_encaps_derand` which produces normal wire-format bytes, but
/// two senders with different salts produce divergent bytes).
pub const HEDGED_ENCAPS_HKDF_SALT: &[u8] = b"umbrellax-xwing-hedged-encaps-v1";

/// Длина блока сырой энтропии CSPRNG которая mix'ится с witness внутри HKDF
/// (64 = достаточно широкая ширина для HKDF-SHA512 extract chain, и
/// **двойной** размер `HEDGED_WITNESS_LEN` для гарантии что compromised
/// witness один не даёт нулевой энтропии).
///
/// Width of the raw CSPRNG entropy block that is mixed with the witness
/// inside HKDF (64 = wide enough for HKDF-SHA512 extract chain and
/// **double** the size of `HEDGED_WITNESS_LEN` so a compromised witness
/// alone never yields zero entropy).
pub const HEDGED_RNG_INPUT_LEN: usize = 64;

/// Hedged witness — 32-byte secret производный из identity_seed.
///
/// Round-5 device-capture closure F-PHD-DC-R11-1: содержит
/// [`MlockedSecret`] (heap-resident + `libc::mlock` + zeroize on drop)
/// вместо `secrecy::SecretBox` (heap-resident + zeroize, БЕЗ mlock).
/// НИКОГДА не сериализуется, не выходит за пределы process memory.
/// Cross-process leakage возможна только при дампе самой `IdentitySeed`,
/// который тоже zeroize'd + mlock'd.
///
/// Hedged witness — a 32-byte secret derived from identity_seed.
///
/// Round-5 device-capture closure F-PHD-DC-R11-1: wraps [`MlockedSecret`]
/// (heap-resident + `libc::mlock` + zeroize on drop) instead of
/// `secrecy::SecretBox` (heap-resident + zeroize, NO mlock). NEVER
/// serialized, never leaves process memory. Cross-process leakage is
/// only possible by dumping the `IdentitySeed` itself, which is also
/// zeroized + mlock'd.
pub struct HedgedWitness {
    bytes: MlockedSecret<[u8; HEDGED_WITNESS_LEN]>,
}

impl HedgedWitness {
    /// Derive `HedgedWitness` из произвольного long-term secret material.
    ///
    /// `identity_seed_bytes` — secret bytes из identity, обычно
    /// 64-byte BIP-39 PBKDF2 seed либо аналог. Не передаём raw Ed25519
    /// signing key — он секретен но KeyStore не экспортирует его наружу;
    /// IdentitySeed::seed() даёт нужный source.
    ///
    /// `account` — BIP-32 account index (mix'ится через HKDF info для
    /// per-account domain separation; разные accounts на одной mnemonic
    /// получают разные witness'ы).
    ///
    /// HKDF-SHA256(`identity_seed_bytes`, salt=`HEDGED_WITNESS_HKDF_SALT`,
    ///             info=`account.to_be_bytes()`).expand(32 bytes).
    ///
    /// Derive `HedgedWitness` from arbitrary long-term secret material.
    ///
    /// `identity_seed_bytes` — secret bytes from the identity, typically
    /// the 64-byte BIP-39 PBKDF2 seed or equivalent. We do not pass the
    /// raw Ed25519 signing key — it is secret but `KeyStore` does not
    /// expose it externally; `IdentitySeed::seed()` provides the right
    /// source.
    ///
    /// `account` — BIP-32 account index (mixed via HKDF info for
    /// per-account domain separation; different accounts under one
    /// mnemonic get different witnesses).
    pub fn derive_from_identity_seed(identity_seed_bytes: &[u8], account: u32) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(HEDGED_WITNESS_HKDF_SALT), identity_seed_bytes);
        let mut out = [0u8; HEDGED_WITNESS_LEN];
        let info = account.to_be_bytes();
        // expand на 32 bytes гарантированно умещается в SHA-256 (255 *
        // HashLen = 8160 bytes max); 32 bytes никогда не fail'ит.
        // 32-byte expand always fits in SHA-256 (255 * HashLen = 8160 max);
        // a 32-byte expand never fails.
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "HKDF-SHA256 expand of 32 bytes never fails (255 * 32 = 8160 byte max)"
        )]
        hk.expand(&info, &mut out)
            .expect("HKDF-SHA256 expand 32 bytes never fails");
        // Round-5 closure: MlockedSecret::new copies `out` into a heap
        // Box + calls libc::mlock; local stack `out` zeroized below for
        // defense-in-depth (caller-side path zeroized via Zeroize derive
        // на `IdentitySeed` который владел `out` derivation source).
        let witness = Self {
            bytes: MlockedSecret::new(out),
        };
        out.zeroize();
        witness
    }

    /// Эксплицитный testing helper: HedgedWitness с известным нулевым
    /// содержимым. Используется в `attack_r5_double_compromise_*` тестах,
    /// которые моделируют ситуацию когда attacker знает witness — чтобы
    /// явно задокументировать unavoidable break при double compromise.
    ///
    /// **НЕ ИСПОЛЬЗОВАТЬ В PRODUCTION**: zero-byte witness вырождает
    /// hedged-construction в обычный `xwing_encaps_derand(HKDF(rng))`
    /// который lopsided defeated при rng compromise.
    ///
    /// Explicit testing helper: HedgedWitness with known zero contents.
    /// Used in `attack_r5_double_compromise_*` tests that model the
    /// scenario in which the attacker knows the witness — to explicitly
    /// document the unavoidable break under double compromise.
    ///
    /// **DO NOT USE IN PRODUCTION**: a zero-byte witness degenerates the
    /// hedged construction into plain `xwing_encaps_derand(HKDF(rng))`,
    /// which is fully broken when rng is compromised.
    #[doc(hidden)]
    pub fn zeroed_for_tests_only() -> Self {
        Self {
            bytes: MlockedSecret::new([0u8; HEDGED_WITNESS_LEN]),
        }
    }

    /// Эксплицитный testing helper: HedgedWitness с произвольным
    /// содержимым (для attacker-known witness в double-compromise tests).
    ///
    /// **НЕ ИСПОЛЬЗОВАТЬ В PRODUCTION**: caller-supplied bytes не имеют
    /// доказанной uniform-randomness — security claim hedged construction
    /// требует чтобы witness был неизвестен attacker'у.
    ///
    /// Explicit testing helper: HedgedWitness with arbitrary contents
    /// (for attacker-known witness in double-compromise tests).
    ///
    /// **DO NOT USE IN PRODUCTION**: caller-supplied bytes have no
    /// proven uniform-randomness — the hedged construction's security
    /// claim requires the witness to be unknown to the attacker.
    #[doc(hidden)]
    pub fn from_bytes_for_tests_only(bytes: [u8; HEDGED_WITNESS_LEN]) -> Self {
        Self {
            bytes: MlockedSecret::new(bytes),
        }
    }

    /// Доступ к raw witness bytes (только для callers в umbrella-pq:
    /// xwing.rs::xwing_encaps_hedged). Round-5: `MlockedSecret::expose`
    /// возвращает `&[u8; N]` (canonical), не `.expose_secret()`.
    ///
    /// Access raw witness bytes (only for callers inside umbrella-pq:
    /// xwing.rs::xwing_encaps_hedged). Round-5: `MlockedSecret::expose`
    /// returns `&[u8; N]` (canonical), not `.expose_secret()`.
    pub(crate) fn expose(&self) -> &[u8; HEDGED_WITNESS_LEN] {
        self.bytes.expose()
    }
}

impl core::fmt::Debug for HedgedWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HedgedWitness(<redacted>)")
    }
}

/// Деривирует X-Wing encaps seed из `(rng_input, witness, transcript,
/// recipient_pk_hash)` через HKDF-SHA512.
///
/// Это **внутренняя** функция; вызывается из `xwing::xwing_encaps_hedged`.
/// Возвращает `[u8; XWING_ENCAPS_SEED_LEN]` готовый к `xwing_encaps_derand`.
///
/// HKDF-SHA512 вместо SHA-256 потому что output 64 bytes
/// = `XWING_ENCAPS_SEED_LEN` (32 для ML-KEM + 32 для X25519 ephemeral) —
/// single extract+expand call, no expand-iterations.
///
/// Derives the X-Wing encaps seed from `(rng_input, witness, transcript,
/// recipient_pk_hash)` via HKDF-SHA512.
///
/// This is an **internal** function; called from `xwing::xwing_encaps_hedged`.
/// Returns `[u8; XWING_ENCAPS_SEED_LEN]` ready for `xwing_encaps_derand`.
///
/// HKDF-SHA512 instead of SHA-256 because the output is 64 bytes =
/// `XWING_ENCAPS_SEED_LEN` (32 for ML-KEM + 32 for X25519 ephemeral) —
/// single extract+expand call, no expand iterations.
pub(crate) fn derive_hedged_encaps_seed(
    rng_input: &[u8; HEDGED_RNG_INPUT_LEN],
    witness: &HedgedWitness,
    transcript: &[u8],
    recipient_pk_hash: &[u8; 32],
) -> Result<[u8; XWING_ENCAPS_SEED_LEN]> {
    // ikm = rng_input (64) || witness (32) = 96 bytes;
    // Bellare-Hoang-Keelveedhi 2015 §4 hedged-CCA: ikm = R(adversary) || U(secret)
    // где либо R либо U остаётся uniform для adversary'я → ikm имеет
    // unknown-to-adversary suffix/prefix → HKDF-extract output uniform
    // под RO assumption.
    //
    // ikm = rng_input (64) || witness (32) = 96 bytes;
    // Bellare-Hoang-Keelveedhi 2015 §4 hedged-CCA: ikm = R(adversary) || U(secret)
    // where either R or U remains uniform to the adversary → ikm has an
    // unknown-to-adversary suffix/prefix → HKDF-extract output is uniform
    // under the RO assumption.
    let mut ikm = [0u8; HEDGED_RNG_INPUT_LEN + HEDGED_WITNESS_LEN];
    ikm[..HEDGED_RNG_INPUT_LEN].copy_from_slice(rng_input);
    ikm[HEDGED_RNG_INPUT_LEN..].copy_from_slice(witness.expose());

    // info = transcript || recipient_pk_hash — domain-separation per session/recipient.
    // Многосессионная безопасность: одинаковый (rng_input, witness) с
    // разными transcripts даёт разные seeds (HKDF expand binds info to
    // output под RO assumption).
    //
    // info = transcript || recipient_pk_hash — per-session/per-recipient
    // domain separation. Multi-session security: identical (rng_input,
    // witness) with different transcripts yields distinct seeds (HKDF
    // expand binds info to output under the RO assumption).
    let mut info = Vec::with_capacity(transcript.len() + recipient_pk_hash.len());
    info.extend_from_slice(transcript);
    info.extend_from_slice(recipient_pk_hash);

    let hk = Hkdf::<Sha512>::new(Some(HEDGED_ENCAPS_HKDF_SALT), &ikm);

    let mut seed = [0u8; XWING_ENCAPS_SEED_LEN];
    hk.expand(&info, &mut seed).map_err(|_| PqError::BackendError {
        message: "HKDF-SHA512 expand for hedged encaps seed failed".to_string(),
    })?;

    // Очищаем временный ikm buffer; содержит копию witness bytes.
    // Wipe the temporary ikm buffer; it holds a copy of the witness bytes.
    ikm.zeroize();

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: derive из одинакового identity_seed + account даёт
    /// идентичный witness (deterministic).
    /// Sanity: deriving from the same identity_seed + account yields
    /// the same witness (deterministic).
    #[test]
    fn witness_derive_is_deterministic() {
        let seed = [0xABu8; 64];
        let w1 = HedgedWitness::derive_from_identity_seed(&seed, 0);
        let w2 = HedgedWitness::derive_from_identity_seed(&seed, 0);
        assert_eq!(w1.expose(), w2.expose());
    }

    /// Разные accounts на одном seed → разные witness'ы (domain separation).
    /// Different accounts on the same seed → distinct witnesses (domain
    /// separation).
    #[test]
    fn witness_derive_differs_by_account() {
        let seed = [0xABu8; 64];
        let w0 = HedgedWitness::derive_from_identity_seed(&seed, 0);
        let w1 = HedgedWitness::derive_from_identity_seed(&seed, 1);
        assert_ne!(w0.expose(), w1.expose());
    }

    /// Разные seeds → разные witness'ы.
    /// Different seeds → distinct witnesses.
    #[test]
    fn witness_derive_differs_by_seed() {
        let seed_a = [0xABu8; 64];
        let seed_b = [0xCDu8; 64];
        let wa = HedgedWitness::derive_from_identity_seed(&seed_a, 0);
        let wb = HedgedWitness::derive_from_identity_seed(&seed_b, 0);
        assert_ne!(wa.expose(), wb.expose());
    }

    /// Derive из 32-байтного identity_seed (минимальный случай — энтропия
    /// IdentitySeed.entropy()) тоже работает.
    /// Derive from a 32-byte identity_seed (minimal case — entropy from
    /// IdentitySeed.entropy()) also works.
    #[test]
    fn witness_derive_accepts_32_byte_seed() {
        let seed = [0xABu8; 32];
        let w = HedgedWitness::derive_from_identity_seed(&seed, 0);
        // 32-byte witness output expected; не сравниваем содержимое потому что
        // оно abstract HKDF output.
        // Expect 32-byte witness output; don't compare contents because it is
        // an abstract HKDF output.
        assert_eq!(w.expose().len(), HEDGED_WITNESS_LEN);
    }

    /// `derive_hedged_encaps_seed` deterministic при одинаковых inputs.
    /// `derive_hedged_encaps_seed` is deterministic under identical inputs.
    #[test]
    fn hedged_seed_is_deterministic_for_same_inputs() {
        let rng_input = [0x11u8; HEDGED_RNG_INPUT_LEN];
        let witness = HedgedWitness::from_bytes_for_tests_only([0x22u8; HEDGED_WITNESS_LEN]);
        let transcript = b"chat=alice-bob,seq=1";
        let pk_hash = [0x33u8; 32];

        let s1 =
            derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_hash).unwrap();
        let s2 =
            derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_hash).unwrap();
        assert_eq!(s1, s2);
    }

    /// Изменение rng_input при том же witness/transcript → другой seed.
    /// Changing rng_input with same witness/transcript → different seed.
    #[test]
    fn hedged_seed_changes_on_rng_input_change() {
        let mut rng_input = [0x11u8; HEDGED_RNG_INPUT_LEN];
        let witness = HedgedWitness::from_bytes_for_tests_only([0x22u8; HEDGED_WITNESS_LEN]);
        let transcript = b"chat=alice-bob,seq=1";
        let pk_hash = [0x33u8; 32];

        let s1 =
            derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_hash).unwrap();
        rng_input[0] ^= 0xFF;
        let s2 =
            derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_hash).unwrap();
        assert_ne!(s1, s2);
    }

    /// Изменение witness при том же rng_input/transcript → другой seed.
    /// Changing witness with same rng_input/transcript → different seed.
    #[test]
    fn hedged_seed_changes_on_witness_change() {
        let rng_input = [0x11u8; HEDGED_RNG_INPUT_LEN];
        let transcript = b"chat=alice-bob,seq=1";
        let pk_hash = [0x33u8; 32];

        let w_a = HedgedWitness::from_bytes_for_tests_only([0x22u8; HEDGED_WITNESS_LEN]);
        let w_b = HedgedWitness::from_bytes_for_tests_only([0x77u8; HEDGED_WITNESS_LEN]);

        let s1 = derive_hedged_encaps_seed(&rng_input, &w_a, transcript, &pk_hash).unwrap();
        let s2 = derive_hedged_encaps_seed(&rng_input, &w_b, transcript, &pk_hash).unwrap();
        assert_ne!(s1, s2);
    }

    /// Изменение transcript → другой seed (multi-session domain separation).
    /// Changing transcript → different seed (multi-session domain separation).
    #[test]
    fn hedged_seed_changes_on_transcript_change() {
        let rng_input = [0x11u8; HEDGED_RNG_INPUT_LEN];
        let witness = HedgedWitness::from_bytes_for_tests_only([0x22u8; HEDGED_WITNESS_LEN]);
        let pk_hash = [0x33u8; 32];

        let s1 =
            derive_hedged_encaps_seed(&rng_input, &witness, b"session-1", &pk_hash).unwrap();
        let s2 =
            derive_hedged_encaps_seed(&rng_input, &witness, b"session-2", &pk_hash).unwrap();
        assert_ne!(s1, s2);
    }

    /// Изменение recipient_pk_hash → другой seed.
    /// Changing recipient_pk_hash → different seed.
    #[test]
    fn hedged_seed_changes_on_recipient_change() {
        let rng_input = [0x11u8; HEDGED_RNG_INPUT_LEN];
        let witness = HedgedWitness::from_bytes_for_tests_only([0x22u8; HEDGED_WITNESS_LEN]);
        let transcript = b"chat=alice-bob,seq=1";

        let pk_a = [0x33u8; 32];
        let pk_b = [0x44u8; 32];

        let s1 = derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_a).unwrap();
        let s2 = derive_hedged_encaps_seed(&rng_input, &witness, transcript, &pk_b).unwrap();
        assert_ne!(s1, s2);
    }

    /// Debug не leak'ит content.
    /// Debug does not leak content.
    #[test]
    fn witness_debug_does_not_leak() {
        let w = HedgedWitness::from_bytes_for_tests_only([0xAAu8; HEDGED_WITNESS_LEN]);
        let s = format!("{w:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("aa"));
    }
}
