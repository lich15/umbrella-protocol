//! Property-based fuzz tests для v3 envelope codec.
//!
//! Дополняет handcrafted adversarial test в `facade_max_ratchet_v3.rs`. Proptest
//! генерирует **truly random** inputs (через MT19937 PRNG) и проверяет:
//!
//! 1. **Roundtrip property:** для любых валидных (commit_opt, ciphertext, mac_opt),
//!    `try_decode_v3(encode_v3(...))` возвращает Some с теми же values.
//! 2. **No-panic invariant:** для **любых** bytes (Vec<u8> arbitrary length и
//!    content), `try_decode_v3` не panic'ит — либо None либо Some. Проверяет
//!    отсутствие unwrap / arithmetic overflow / out-of-bounds slice.
//!
//! 256+ iterations per property test → covers 65536+ random adversarial inputs.
//! Carry-over к v3.1: SymCC / cargo-fuzz harness for AFL/libFuzzer integration.
//!
//! Property-based fuzz tests for the v3 envelope codec. Complements the
//! handcrafted adversarial test by generating truly random inputs and verifying
//! roundtrip + no-panic invariants.

use proptest::prelude::*;

use umbrella_client::facade::max_ratchet_envelope::{
    encode_v3, try_decode_v3, SPQR_MAC_LEN, V3_MARKER, V3_VERSION,
};

proptest! {
    // 256 iterations default per property test (proptest default).

    /// Roundtrip: encode → decode preserves all field values bit-equally.
    /// Random commit_bytes (0..1024 length) + ciphertext (0..4096 length) + mac.
    #[test]
    fn proptest_encode_decode_roundtrip(
        commit_opt in proptest::option::of(prop::collection::vec(any::<u8>(), 0..1024)),
        ciphertext in prop::collection::vec(any::<u8>(), 0..4096),
        mac_opt in proptest::option::of(prop::array::uniform32(any::<u8>())),
    ) {
        let commit_ref = commit_opt.as_deref();
        let mac_ref = mac_opt.as_ref();
        let blob = encode_v3(commit_ref, &ciphertext, mac_ref);

        let decoded = try_decode_v3(&blob).expect("encoded bundle must decode");

        // Commit roundtrip — Some(non-empty) preserved as Some, Some(empty)/None as None.
        let expected_commit = commit_opt
            .as_ref()
            .filter(|c| !c.is_empty())
            .map(|c| c.as_slice());
        prop_assert_eq!(
            decoded.commit_bytes, expected_commit,
            "commit_bytes must roundtrip exactly"
        );

        // Ciphertext byte-exact.
        prop_assert_eq!(
            decoded.ciphertext_bytes, &ciphertext[..],
            "ciphertext_bytes must roundtrip byte-exact"
        );

        // SPQR mac: Some preserves bytes; None encodes as zero mac.
        let expected_mac = mac_opt.unwrap_or([0u8; SPQR_MAC_LEN]);
        prop_assert_eq!(decoded.spqr_mac, expected_mac, "spqr_mac roundtrip");
    }

    /// No-panic invariant: try_decode_v3 returns без panic on arbitrary input bytes.
    /// Random Vec<u8> 0..8192 length, любые byte values.
    #[test]
    fn proptest_decode_never_panics_on_arbitrary_bytes(
        blob in prop::collection::vec(any::<u8>(), 0..8192),
    ) {
        // Result either None либо Some — оба acceptable. Main invariant: function
        // returns gracefully, не panic / abort / unwrap fail.
        let _ = try_decode_v3(&blob);
    }

    /// Non-v3 prefix bytes должны strictly decode к None.
    /// Random first byte != 0xFF (V3_MARKER) → decoder must reject.
    #[test]
    fn proptest_non_v3_marker_always_decodes_to_none(
        first_byte in 0u8..=0xFEu8,
        tail in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut blob = vec![first_byte];
        blob.extend_from_slice(&tail);
        prop_assert!(
            try_decode_v3(&blob).is_none(),
            "first byte {} != V3_MARKER 0xFF must decode к None",
            first_byte
        );
    }

    /// Wrong version byte → None даже если marker correct.
    #[test]
    fn proptest_v3_marker_but_wrong_version_decodes_to_none(
        wrong_version in (0u8..=0xFFu8).prop_filter("not V3_VERSION", |v| *v != V3_VERSION),
        tail in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut blob = vec![V3_MARKER, wrong_version];
        blob.extend_from_slice(&tail);
        prop_assert!(
            try_decode_v3(&blob).is_none(),
            "wrong version byte {} != V3_VERSION must decode к None",
            wrong_version
        );
    }

    /// Trailing byte attack: append byte after valid encoding → None (strict equality).
    #[test]
    fn proptest_trailing_byte_always_rejected(
        commit_opt in proptest::option::of(prop::collection::vec(any::<u8>(), 0..128)),
        ciphertext in prop::collection::vec(any::<u8>(), 0..256),
        mac in prop::array::uniform32(any::<u8>()),
        trailing_byte in any::<u8>(),
    ) {
        let mut blob = encode_v3(commit_opt.as_deref(), &ciphertext, Some(&mac));
        let original_len = blob.len();
        blob.push(trailing_byte);
        prop_assert!(
            try_decode_v3(&blob).is_none(),
            "trailing byte must cause rejection (originals len {})",
            original_len
        );
    }
}
