//! Whitelist ciphersuites Umbrella Protocol; ECDSA-based варианты RFC 9420 отвергаются.
//! Umbrella Protocol ciphersuite whitelist; ECDSA-based RFC 9420 variants are rejected.
//!
//! ## Угроза
//!
//! ETK attack (Cremers, Gellert, Wiesmaier, Zhao — CISPA, eprint 2025/229) показывает, что
//! TreeKEM с подписями не-SUF-CMA позволяет split-brain атаку: атакующий перепаковывает подпись
//! с тем же содержимым, но другими байтами, и хеш-цепочки получателей расходятся → группа
//! разваливается на разные state.
//!
//! ECDSA (используется в P-256/P-384/P-521 ciphersuites RFC 9420) — EUF-CMA, но не SUF-CMA:
//! signature malleability через `s ↔ -s mod n`. Подвержена атаке.
//!
//! Ed25519 и Ed448 — SUF-CMA по построению (PureEdDSA, RFC 8032 §6). Не подвержены.
//!
//! ## Решение
//!
//! Whitelist на уровне типов: `UmbrellaCiphersuite` не содержит ECDSA-вариантов вообще.
//! Конверсия из `openmls_traits::types::Ciphersuite` валидирует и отвергает запрещённые.
//!
//! ## Threat
//!
//! The ETK attack (Cremers, Gellert, Wiesmaier, Zhao — CISPA, eprint 2025/229) shows that
//! TreeKEM with non-SUF-CMA signatures admits a split-brain attack: an attacker repacks a
//! signature with the same content but different bytes, recipients' hash chains diverge, and
//! the group splits into different states.
//!
//! ECDSA (used in P-256/P-384/P-521 RFC 9420 ciphersuites) is EUF-CMA but not SUF-CMA: signature
//! malleability via `s ↔ -s mod n`. Vulnerable to the attack.
//!
//! Ed25519 and Ed448 are SUF-CMA by construction (PureEdDSA, RFC 8032 §6). Not vulnerable.
//!
//! ## Solution
//!
//! Type-level whitelist: `UmbrellaCiphersuite` simply does not enumerate ECDSA variants.
//! Conversion from `openmls_traits::types::Ciphersuite` validates and rejects forbidden ones.

use core::fmt;

use openmls_traits::types::Ciphersuite as OpenMlsCiphersuite;

use crate::error::{MlsError, Result};

/// Whitelist допустимых ciphersuites Umbrella Protocol.
/// Каждый вариант — Ed25519 или Ed448 по signature scheme.
/// Whitelist of permitted Umbrella Protocol ciphersuites.
/// Each variant uses Ed25519 or Ed448 as its signature scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum UmbrellaCiphersuite {
    /// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (IANA 0x0001).
    /// AES-128-GCM AEAD, наиболее широкая аппаратная поддержка.
    /// AES-128-GCM AEAD, broadest hardware support.
    Mls128X25519AesGcmSha256Ed25519 = 0x0001,

    /// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (IANA 0x0003).
    /// **Дефолтная** — ChaCha20-Poly1305, лучшая performance на ARM-mobile без AES-NI.
    /// **Default** — ChaCha20-Poly1305, best performance on ARM-mobile without AES-NI.
    Mls128X25519ChaChaSha256Ed25519 = 0x0003,

    /// `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` (IANA 0x0004).
    /// 256-битный security уровень, Ed448 SUF-CMA.
    /// 256-bit security level, Ed448 SUF-CMA.
    Mls256X448AesGcmSha512Ed448 = 0x0004,

    /// `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` (IANA 0x0006).
    /// 256-битный с ChaCha20-Poly1305, для high-security и mobile одновременно.
    /// 256-bit with ChaCha20-Poly1305, for high-security and mobile simultaneously.
    Mls256X448ChaChaSha512Ed448 = 0x0006,

    /// `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (IANA 0x004D).
    /// **Hybrid PQ:** X-Wing (X25519 + ML-KEM-768) + Ed25519. Доступно только под feature `pq`
    /// — без феature `OpenMlsRustCrypto-0.5.1` падает в `unimplemented!()` на
    /// `HpkeKemType::XWingKemDraft6`. Compile-time gate защищает downstream от случайного
    /// конструирования этого варианта без активации `UmbrellaXWingProvider`.
    ///
    /// **Hybrid PQ:** X-Wing (X25519 + ML-KEM-768) + Ed25519. Available only under feature
    /// `pq` — without it, `OpenMlsRustCrypto-0.5.1` panics in `unimplemented!()` on
    /// `HpkeKemType::XWingKemDraft6`. The compile-time gate prevents downstream from
    /// accidentally constructing this variant without activating `UmbrellaXWingProvider`.
    ///
    /// **Cross-references / Перекрёстные ссылки**:
    /// - SPEC-13-PQ-HYBRID v0.0.2 §4.1 (MLS PQ ciphersuite definition + IANA TBD disclaimer
    ///   block 10.6 inline-fix per F-04). Финальная IANA assignment depends on
    ///   draft-ietf-mls-pq-ciphersuites RFC publication; текущее `0x004D` value — наша
    ///   ожидаемая интерпретация based on draft-04 (2026-03-18) WG Last Call placeholders.
    /// - SPEC-13-PQ-HYBRID §2 «X-Wing draft-10 compatibility note»
    ///   (libcrux API name remains `XWingKemDraft06`, output pinned by draft-10 KAT).
    /// - ADR-011 «Hybrid PQ» Решение 4 (X-Wing combiner + UmbrellaXWingProvider feature gate).
    /// - ADR-013 «Quantum-adversary-today policy» (Stage 1 default switch на 0x004D).
    #[cfg(feature = "pq")]
    Mls256XWingChaChaSha256Ed25519 = 0x004D,
}

/// Дефолтный ciphersuite для Umbrella Protocol — широко поддержан, эффективен на mobile.
/// Default ciphersuite for Umbrella Protocol — widely supported, efficient on mobile.
pub const UMBRELLA_DEFAULT_CIPHERSUITE: UmbrellaCiphersuite =
    UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;

impl UmbrellaCiphersuite {
    /// IANA-номер ciphersuite (RFC 9420 §17.1).
    /// IANA ciphersuite number (RFC 9420 §17.1).
    pub const fn raw_id(self) -> u16 {
        self as u16
    }

    /// Сильный ли это уровень (256-bit) или базовый (128-bit).
    /// Whether this is the strong level (256-bit) or baseline (128-bit).
    pub const fn is_256_bit(self) -> bool {
        match self {
            Self::Mls128X25519AesGcmSha256Ed25519 | Self::Mls128X25519ChaChaSha256Ed25519 => false,
            Self::Mls256X448AesGcmSha512Ed448 | Self::Mls256X448ChaChaSha512Ed448 => true,
            #[cfg(feature = "pq")]
            Self::Mls256XWingChaChaSha256Ed25519 => true,
        }
    }

    /// Включает ли ciphersuite пост-квантовый KEM (X-Wing).
    /// Whether the ciphersuite includes a post-quantum KEM (X-Wing).
    pub const fn is_post_quantum_hybrid(self) -> bool {
        match self {
            Self::Mls128X25519AesGcmSha256Ed25519
            | Self::Mls128X25519ChaChaSha256Ed25519
            | Self::Mls256X448AesGcmSha512Ed448
            | Self::Mls256X448ChaChaSha512Ed448 => false,
            #[cfg(feature = "pq")]
            Self::Mls256XWingChaChaSha256Ed25519 => true,
        }
    }

    /// Использует ли ciphersuite ChaCha20-Poly1305 (предпочтительно на ARM без AES-NI).
    /// Whether the ciphersuite uses ChaCha20-Poly1305 (preferred on ARM without AES-NI).
    pub const fn uses_chacha20(self) -> bool {
        match self {
            Self::Mls128X25519AesGcmSha256Ed25519 | Self::Mls256X448AesGcmSha512Ed448 => false,
            Self::Mls128X25519ChaChaSha256Ed25519 | Self::Mls256X448ChaChaSha512Ed448 => true,
            #[cfg(feature = "pq")]
            Self::Mls256XWingChaChaSha256Ed25519 => true,
        }
    }

    /// Конструирует из IANA-номера; отвергает любой не входящий в whitelist (ECDSA и unknown).
    /// Без feature `pq` 0x004D отвергается с `CiphersuiteRequiresPqFeature` (постулат 14:
    /// иначе нижележащий `OpenMlsRustCrypto` падает в `unimplemented!()` на X-Wing).
    ///
    /// Constructs from an IANA number; rejects anything not in the whitelist (ECDSA and unknown).
    /// Without feature `pq`, 0x004D is rejected with `CiphersuiteRequiresPqFeature` (postulate 14:
    /// otherwise the underlying `OpenMlsRustCrypto` panics in `unimplemented!()` on X-Wing).
    pub const fn from_raw_id(raw_id: u16) -> Result<Self> {
        match raw_id {
            0x0001 => Ok(Self::Mls128X25519AesGcmSha256Ed25519),
            0x0003 => Ok(Self::Mls128X25519ChaChaSha256Ed25519),
            0x0004 => Ok(Self::Mls256X448AesGcmSha512Ed448),
            0x0006 => Ok(Self::Mls256X448ChaChaSha512Ed448),
            #[cfg(feature = "pq")]
            0x004D => Ok(Self::Mls256XWingChaChaSha256Ed25519),
            #[cfg(not(feature = "pq"))]
            0x004D => Err(MlsError::CiphersuiteRequiresPqFeature { raw_id }),
            _ => Err(MlsError::DisallowedCiphersuite { raw_id }),
        }
    }

    /// Конструирует из openmls `Ciphersuite`; ECDSA-based варианты отвергаются.
    /// Constructs from an openmls `Ciphersuite`; ECDSA-based variants are rejected.
    pub fn from_openmls(suite: OpenMlsCiphersuite) -> Result<Self> {
        Self::from_raw_id(suite as u16)
    }

    /// Конверсия в openmls `Ciphersuite` для передачи в библиотеку.
    /// Conversion to openmls `Ciphersuite` for passing into the library.
    pub fn to_openmls(self) -> OpenMlsCiphersuite {
        match self {
            Self::Mls128X25519AesGcmSha256Ed25519 => {
                OpenMlsCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            }
            Self::Mls128X25519ChaChaSha256Ed25519 => {
                OpenMlsCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            }
            Self::Mls256X448AesGcmSha512Ed448 => {
                OpenMlsCiphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            }
            Self::Mls256X448ChaChaSha512Ed448 => {
                OpenMlsCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            }
            #[cfg(feature = "pq")]
            Self::Mls256XWingChaChaSha256Ed25519 => {
                OpenMlsCiphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            }
        }
    }
}

impl fmt::Display for UmbrellaCiphersuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Mls128X25519AesGcmSha256Ed25519 => "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            Self::Mls128X25519ChaChaSha256Ed25519 => {
                "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
            }
            Self::Mls256X448AesGcmSha512Ed448 => "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
            Self::Mls256X448ChaChaSha512Ed448 => "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
            #[cfg(feature = "pq")]
            Self::Mls256XWingChaChaSha256Ed25519 => "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        };
        write!(f, "{} (0x{:04X})", label, self.raw_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Все известные RFC 9420 IANA-коды ciphersuites — whitelist обязан корректно классифицировать.
    /// All known RFC 9420 IANA codes — the whitelist must classify them correctly.
    const ALL_RFC9420_CODES: &[u16] = &[
        0x0001, // X25519+AES128+SHA256+Ed25519       — allowed
        0x0002, // P-256+AES128+SHA256+ECDSA-P256     — DISALLOWED
        0x0003, // X25519+ChaCha20+SHA256+Ed25519     — allowed (default)
        0x0004, // X448+AES256+SHA512+Ed448           — allowed
        0x0005, // P-521+AES256+SHA512+ECDSA-P521     — DISALLOWED
        0x0006, // X448+ChaCha20+SHA512+Ed448         — allowed
        0x0007, // P-384+AES256+SHA384+ECDSA-P384     — DISALLOWED
        0x004D, // XWING+ChaCha20+SHA256+Ed25519      — allowed только с feature pq
    ];
    /// Безусловно запрещённые (ECDSA-семейство — ETK атака).
    /// Unconditionally forbidden (ECDSA family — ETK attack).
    const RFC9420_DISALLOWED: &[u16] = &[0x0002, 0x0005, 0x0007];

    /// 0x004D X-Wing — allowed только под feature `pq`. Под no-pq отвергается с
    /// `CiphersuiteRequiresPqFeature` (отдельный variant, чтобы отличать от ECDSA).
    /// 0x004D X-Wing — allowed only under feature `pq`. Without the feature it is rejected
    /// with `CiphersuiteRequiresPqFeature` (separate variant from ECDSA).
    const RFC9420_PQ_GATED: &[u16] = &[0x004D];

    #[test]
    fn default_ciphersuite_is_chacha_x25519_ed25519() {
        assert_eq!(
            UMBRELLA_DEFAULT_CIPHERSUITE,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519
        );
    }

    #[test]
    fn raw_id_round_trip_for_all_whitelisted() {
        // 0x004D — only with feature pq (без феature — runtime gate возвращает
        // CiphersuiteRequiresPqFeature, см. fn from_raw_id выше).
        // 0x004D — only with feature pq (without it the runtime gate returns
        // CiphersuiteRequiresPqFeature, see fn from_raw_id above).
        #[cfg(not(feature = "pq"))]
        let allowed_codes: &[u16] = &[0x0001, 0x0003, 0x0004, 0x0006];
        #[cfg(feature = "pq")]
        let allowed_codes: &[u16] = &[0x0001, 0x0003, 0x0004, 0x0006, 0x004D];

        for &allowed in allowed_codes {
            let cs =
                UmbrellaCiphersuite::from_raw_id(allowed).expect("whitelisted code must parse");
            assert_eq!(cs.raw_id(), allowed);
        }
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    fn xwing_rejected_without_pq_feature() {
        let result = UmbrellaCiphersuite::from_raw_id(0x004D);
        assert!(
            matches!(
                result,
                Err(MlsError::CiphersuiteRequiresPqFeature { raw_id: 0x004D })
            ),
            "0x004D must be runtime-gated to CiphersuiteRequiresPqFeature without feature pq, got: {result:?}"
        );
    }

    #[test]
    fn ecdsa_variants_rejected() {
        for &disallowed in RFC9420_DISALLOWED {
            let result = UmbrellaCiphersuite::from_raw_id(disallowed);
            assert!(
                matches!(
                    result,
                    Err(MlsError::DisallowedCiphersuite { raw_id }) if raw_id == disallowed
                ),
                "ECDSA ciphersuite {disallowed:#06x} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_codes_rejected() {
        for unknown in [0x0000u16, 0x0008, 0x00FF, 0x1000, 0xFFFF] {
            let result = UmbrellaCiphersuite::from_raw_id(unknown);
            assert!(
                matches!(
                    result,
                    Err(MlsError::DisallowedCiphersuite { raw_id }) if raw_id == unknown
                ),
                "unknown ciphersuite {unknown:#06x} must be rejected"
            );
        }
    }

    #[test]
    fn full_rfc9420_classification_matches_expected() {
        for &code in ALL_RFC9420_CODES {
            let result = UmbrellaCiphersuite::from_raw_id(code);
            let unconditionally_allowed =
                !RFC9420_DISALLOWED.contains(&code) && !RFC9420_PQ_GATED.contains(&code);
            // PQ-gated codes (0x004D) разрешены только под feature pq.
            // PQ-gated codes (0x004D) are allowed only under feature pq.
            let pq_gated = RFC9420_PQ_GATED.contains(&code);
            let expected_ok = if pq_gated {
                cfg!(feature = "pq")
            } else {
                unconditionally_allowed
            };
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "ciphersuite 0x{:04X}: expected ok={} (pq_gated={}, feature pq={})",
                code,
                expected_ok,
                pq_gated,
                cfg!(feature = "pq")
            );
        }
    }

    #[test]
    fn openmls_round_trip_all_whitelisted() {
        // X-Wing variant остаётся в enum всегда (для type-uniformity), но
        // round-trip from_openmls(0x004D) без feature pq возвращает Err через runtime gate.
        // X-Wing variant remains in the enum unconditionally (for type uniformity), but
        // round-trip from_openmls(0x004D) without feature pq fails via the runtime gate.
        #[cfg(not(feature = "pq"))]
        let all_ours: &[UmbrellaCiphersuite] = &[
            UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
            UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448,
            UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448,
        ];
        #[cfg(feature = "pq")]
        let all_ours: &[UmbrellaCiphersuite] = &[
            UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
            UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448,
            UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448,
            UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519,
        ];

        for cs in all_ours.iter().copied() {
            let openmls_cs = cs.to_openmls();
            let back = UmbrellaCiphersuite::from_openmls(openmls_cs)
                .expect("openmls round-trip must succeed for whitelisted");
            assert_eq!(cs, back);
            assert_eq!(cs.raw_id(), openmls_cs as u16);
        }
    }

    #[test]
    fn from_openmls_rejects_ecdsa_variants() {
        let ecdsa_variants = [
            OpenMlsCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            OpenMlsCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            OpenMlsCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        ];
        for cs in ecdsa_variants {
            let result = UmbrellaCiphersuite::from_openmls(cs);
            assert!(
                matches!(result, Err(MlsError::DisallowedCiphersuite { .. })),
                "ECDSA variant {cs:?} must be rejected through openmls conversion"
            );
        }
    }

    #[test]
    fn classification_flags_consistent() {
        // 256-bit и PQ-флаги корректно отражают спецификацию.
        // 256-bit and PQ flags correctly reflect the spec.
        assert!(!UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519.is_256_bit());
        assert!(!UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519.is_256_bit());
        assert!(UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448.is_256_bit());
        assert!(UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448.is_256_bit());

        assert!(!UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519.is_post_quantum_hybrid());
        assert!(!UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448.is_post_quantum_hybrid());

        assert!(!UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519.uses_chacha20());
        assert!(UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519.uses_chacha20());
        assert!(!UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448.uses_chacha20());
        assert!(UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448.uses_chacha20());

        // X-Wing variant compile-time gated на feature pq.
        // X-Wing variant compile-time gated on feature pq.
        #[cfg(feature = "pq")]
        {
            assert!(UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519.is_256_bit());
            assert!(UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519.is_post_quantum_hybrid());
            assert!(UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519.uses_chacha20());
        }
    }

    #[test]
    fn display_includes_label_and_raw_id() {
        let s = format!("{UMBRELLA_DEFAULT_CIPHERSUITE}");
        assert!(s.contains("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"));
        assert!(s.contains("0x0003"));
    }
}
