//! RFC 9605 / sframe-wg test vectors для SFrame ciphersuite
//! AES-256-GCM-SHA512-128 (`0x0005`).
//!
//! Vectors взяты из репозитория sframe-wg/sframe коммит `025d568`,
//! файл `test-vectors/test-vectors.json`, запись `cipher_suite = 5`.
//! Это канонический источник test vectors для RFC 9605 — он же упомянут в
//! Appendix C самого RFC как `[TestVectors]`.
//!
//! ## Зачем
//!
//! QUALITY_STANDARDS §2.2 требует cross-check по RFC vectors для любой
//! нормативной крипто-реализации. Наш `umbrella-calls::sframe` должен давать
//! bit-for-bit совпадение sframe_secret / sframe_key / sframe_salt / nonce и
//! (с тем же AAD) ciphertext+tag.
//!
//! ## Пайплайн vector'а
//!
//! ```text
//! base_key (16 B)
//!    │ HKDF-Extract(salt="")
//!    ▼
//! sframe_secret (64 B) ─── Nh = SHA-512 output
//!    │
//!    ├── HKDF-Expand("SFrame 1.0 Secret key "  || kid_be || cs_be, 32) → sframe_key  (32 B)
//!    └── HKDF-Expand("SFrame 1.0 Secret salt " || kid_be || cs_be, 12) → sframe_salt (12 B)
//!
//! nonce = sframe_salt XOR (zero_pad_4 || counter_be)
//!
//! aad = wire_header || metadata     ← RFC 9605 § «extra metadata as AAD»
//! wire = wire_header || AES-256-GCM(sframe_key, nonce, aad, plaintext) || tag
//! ```
//!
//! В нашем Протоколе `metadata` пустой (SPEC-06 §7), но test vector включает
//! non-empty metadata `"IETF SFrame WG"` для демонстрации. Cross-check тест
//! в `umbrella-calls` передаёт эту metadata напрямую в `aes256gcm_encrypt`,
//! что позволяет проверить полный шифро-путь без смены SPEC-06 поведения.
//!
//! RFC 9605 / sframe-wg test vectors for SFrame ciphersuite
//! AES-256-GCM-SHA512-128 (`0x0005`).
//!
//! Vectors are taken from the sframe-wg/sframe repository, commit `025d568`,
//! file `test-vectors/test-vectors.json`, record `cipher_suite = 5`. This is
//! the canonical test-vectors source for RFC 9605 — cited in its
//! Appendix C as `[TestVectors]`.
//!
//! ## Why
//!
//! QUALITY_STANDARDS §2.2 demands cross-checking any normative crypto
//! implementation against RFC vectors. Our `umbrella-calls::sframe` must
//! produce bit-for-bit matches for sframe_secret / sframe_key / sframe_salt
//! / nonce, and (given the same AAD) ciphertext+tag.
//!
//! ## Vector pipeline
//!
//! ```text
//! base_key (16 B)
//!    │ HKDF-Extract(salt="")
//!    ▼
//! sframe_secret (64 B) ─── Nh = SHA-512 output
//!    │
//!    ├── HKDF-Expand("SFrame 1.0 Secret key "  || kid_be || cs_be, 32) → sframe_key  (32 B)
//!    └── HKDF-Expand("SFrame 1.0 Secret salt " || kid_be || cs_be, 12) → sframe_salt (12 B)
//!
//! nonce = sframe_salt XOR (zero_pad_4 || counter_be)
//!
//! aad = wire_header || metadata     ← RFC 9605 «extra metadata as AAD»
//! wire = wire_header || AES-256-GCM(sframe_key, nonce, aad, plaintext) || tag
//! ```
//!
//! In our protocol `metadata` is empty (SPEC-06 §7), but the test vector
//! includes non-empty metadata `"IETF SFrame WG"` for demonstration. The
//! cross-check test in `umbrella-calls` forwards this metadata directly to
//! `aes256gcm_encrypt`, exercising the full crypto path without changing
//! the SPEC-06 behaviour.

/// RFC 9605 test vector для AES-256-GCM-SHA512-128.
/// RFC 9605 test vector for AES-256-GCM-SHA512-128.
#[derive(Debug)]
pub struct SframeVector {
    /// RFC 9605 §4.5 ciphersuite ID (0x0005 для AES-256-GCM-SHA512-128).
    /// RFC 9605 §4.5 ciphersuite ID (0x0005 for AES-256-GCM-SHA512-128).
    pub ciphersuite_id: u16,
    /// Входной `base_key` (ikm для HKDF-Extract). Может быть любой длины.
    /// Input `base_key` (ikm for HKDF-Extract). May be any length.
    pub base_key: &'static [u8],
    /// KID (u64).
    pub kid: u64,
    /// Counter (u64).
    pub counter: u64,
    /// Metadata, подаваемая в AAD после wire_header (может быть пустой).
    /// Metadata appended to AAD after wire_header (may be empty).
    pub metadata: &'static [u8],
    /// Ожидаемый wire_header (CONFIG + KID + CTR).
    /// Expected wire_header (CONFIG + KID + CTR).
    pub expected_wire_header: &'static [u8],
    /// Ожидаемый nonce per-frame.
    /// Expected per-frame nonce.
    pub expected_nonce: &'static [u8],
    /// Ожидаемый sframe_secret после HKDF-Extract (64 байта).
    /// Expected sframe_secret after HKDF-Extract (64 bytes).
    pub expected_sframe_secret: &'static [u8],
    /// Ожидаемый sframe_key (32 байта).
    /// Expected sframe_key (32 bytes).
    pub expected_sframe_key: &'static [u8],
    /// Ожидаемый sframe_salt (12 байт).
    /// Expected sframe_salt (12 bytes).
    pub expected_sframe_salt: &'static [u8],
    /// Plaintext (произвольная длина).
    /// Plaintext (arbitrary length).
    pub plaintext: &'static [u8],
    /// Ожидаемый ciphertext + AEAD tag (plaintext.len() + 16 байт).
    /// Expected ciphertext + AEAD tag (plaintext.len() + 16 bytes).
    pub expected_ciphertext_with_tag: &'static [u8],
}

/// RFC 9605 / sframe-wg vectors для ciphersuite `0x0005`.
/// Один vector в репозитории sframe-wg на commit `025d568`; добавятся по мере
/// публикации новых vectors в [IETF sframe-wg test suite].
///
/// RFC 9605 / sframe-wg vectors for ciphersuite `0x0005`. One vector in the
/// sframe-wg repo at commit `025d568`; more will be added as the
/// [IETF sframe-wg test suite] publishes them.
///
/// [IETF sframe-wg test suite]: https://github.com/sframe-wg/sframe/tree/025d568/test-vectors
pub const AES_256_GCM_SHA512_128_VECTORS: &[SframeVector] = &[
    // cipher_suite = 5
    // base_key          = 000102030405060708090a0b0c0d0e0f
    // kid               = 0x123 (291)
    // ctr               = 0x4567 (17767)
    // metadata          = "IETF SFrame WG"
    // header (wire)     = 99 01 23 45 67
    // sframe_secret     = 0fc3…83a3 (64 B)
    // sframe_key        = d3e2…9633 (32 B)
    // sframe_salt       = 8499…8ec7 (12 B)
    // nonce             = 8499…cba0 (12 B)
    // plaintext         = "draft-ietf-sframe-enc"
    // ciphertext+tag    = 94f5…d279 (plaintext.len() + 16 B)
    SframeVector {
        ciphersuite_id: 0x0005,
        base_key: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        kid: 0x0123,
        counter: 0x4567,
        metadata: b"IETF SFrame WG",
        expected_wire_header: &[0x99, 0x01, 0x23, 0x45, 0x67],
        expected_nonce: &[
            0x84, 0x99, 0x1c, 0x16, 0x7b, 0x8c, 0xd2, 0x3c, 0x93, 0x70, 0xcb, 0xa0,
        ],
        expected_sframe_secret: &[
            0x0f, 0xc3, 0xea, 0x6d, 0xe6, 0xaa, 0xc9, 0x7a, 0x35, 0xf1, 0x94, 0xcf, 0x9b, 0xed,
            0x94, 0xd4, 0xb5, 0x23, 0x0f, 0x1c, 0xb4, 0x5a, 0x78, 0x5c, 0x9f, 0xe5, 0xdc, 0xe9,
            0xc1, 0x88, 0x93, 0x8a, 0xb6, 0xba, 0x00, 0x5b, 0xc4, 0xc0, 0xa1, 0x91, 0x81, 0x59,
            0x9e, 0x9d, 0x1b, 0xcf, 0x7b, 0x74, 0xac, 0xa4, 0x8b, 0x60, 0xbf, 0x5e, 0x25, 0x4e,
            0x54, 0x6d, 0x80, 0x93, 0x13, 0xe0, 0x83, 0xa3,
        ],
        expected_sframe_key: &[
            0xd3, 0xe2, 0x7b, 0x0d, 0x4a, 0x5a, 0xe9, 0xe5, 0x5d, 0xf0, 0x1a, 0x70, 0xe6, 0xd4,
            0xd2, 0x8d, 0x96, 0x9b, 0x24, 0x6e, 0x29, 0x36, 0xf4, 0xb7, 0xa5, 0xd9, 0xb4, 0x94,
            0xda, 0x6b, 0x96, 0x33,
        ],
        expected_sframe_salt: &[
            0x84, 0x99, 0x1c, 0x16, 0x7b, 0x8c, 0xd2, 0x3c, 0x93, 0x70, 0x8e, 0xc7,
        ],
        // b"draft-ietf-sframe-enc"
        plaintext: &[
            0x64, 0x72, 0x61, 0x66, 0x74, 0x2d, 0x69, 0x65, 0x74, 0x66, 0x2d, 0x73, 0x66, 0x72,
            0x61, 0x6d, 0x65, 0x2d, 0x65, 0x6e, 0x63,
        ],
        expected_ciphertext_with_tag: &[
            0x94, 0xf5, 0x09, 0xd3, 0x6e, 0x9b, 0xea, 0xcb, 0x0e, 0x26, 0x1d, 0x99, 0xc7, 0xd1,
            0xe9, 0x72, 0xf1, 0xfe, 0xd7, 0x87, 0xd4, 0x04, 0x9f, 0x17, 0xca, 0x21, 0x35, 0x3c,
            0x1c, 0xc2, 0x4d, 0x56, 0xce, 0xab, 0xce, 0xd2, 0x79,
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_invariants() {
        for v in AES_256_GCM_SHA512_128_VECTORS {
            assert_eq!(v.ciphersuite_id, 0x0005);
            assert_eq!(
                v.expected_sframe_secret.len(),
                64,
                "Nh = 64 (SHA-512 output)"
            );
            assert_eq!(v.expected_sframe_key.len(), 32, "Nk = 32 (AES-256 key)");
            assert_eq!(v.expected_sframe_salt.len(), 12, "Nn = 12 (AES-GCM nonce)");
            assert_eq!(v.expected_nonce.len(), 12);
            assert_eq!(
                v.expected_ciphertext_with_tag.len(),
                v.plaintext.len() + 16,
                "AEAD tag = 16 bytes"
            );
        }
    }

    // Const-time check: QUALITY_STANDARDS §2.2 требует хотя бы один RFC vector.
    // Const-time check: QUALITY_STANDARDS §2.2 requires at least one RFC vector.
    const _NON_EMPTY_VECTORS: () = assert!(!AES_256_GCM_SHA512_128_VECTORS.is_empty());
}
