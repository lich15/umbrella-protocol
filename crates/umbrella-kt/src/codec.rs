//! Wire-format codec для типов `umbrella-kt` (на текущий момент —
//! [`SignedEpochRoot`]). Слой выше `Http2KtTransport` возвращает raw bytes
//! `Vec<u8>` от `kt-svc`; helpers facade (`verify_kt_witness_signatures_*`)
//! десериализуют их через [`decode_signed_epoch_root`] и валидируют через
//! `umbrella_kt::witness::verify_signed_epoch`.
//!
//! ## Wire format `SignedEpochRoot` (deterministic, fixed-layout)
//!
//! ```text
//! offset  length  field
//! ------  ------  -----
//! 0       1       version (`SIGNED_EPOCH_ROOT_WIRE_VERSION = 0x01`)
//! 1       8       epoch                 (u64 big-endian)
//! 9       32      root                  ([u8; NODE_HASH_LEN])
//! 41      8       log_size              (u64 big-endian)
//! 49      8       timestamp_unix_millis (u64 big-endian)
//! 57      1       signature_count       (u8, 0..=MAX_WITNESSES_PER_EPOCH=5)
//! 58      N × 96  signatures            (each = 32-byte witness_pubkey || 64-byte Ed25519 signature)
//! ```
//!
//! Header = 58 bytes. Per-signature payload = 32 + 64 = 96 bytes. Max wire
//! size (5 signatures) = 58 + 5 × 96 = 538 bytes. Zero signatures = 58 bytes
//! exactly. Wire format **не включает** `WITNESS_DOMAIN_SEP` — domain
//! separator живёт только внутри `canonical_sign_payload` (input для Ed25519
//! sign / verify), не на проводе.
//!
//! Wire-format codec for `umbrella-kt` types (currently `SignedEpochRoot`).
//! `Http2KtTransport` returns raw `Vec<u8>` from `kt-svc`; facade helpers
//! deserialise via `decode_signed_epoch_root` and validate via
//! `umbrella_kt::witness::verify_signed_epoch`.
//!
//! ## Wire format `SignedEpochRoot`
//!
//! Deterministic fixed-layout: version (1) || epoch_BE (8) || root (32) ||
//! log_size_BE (8) || timestamp_BE (8) || sig_count (1) || N × {pubkey (32) ||
//! signature (64)}. Header = 58 bytes, max wire (5 sigs) = 538 bytes.
//!
//! ## Defence-in-depth (постулат 14 fail-closed)
//!
//! `decode_signed_epoch_root` strict-rejects (returns
//! [`KtError::InvalidSignedEpochRootWire`]) any of:
//!
//! - input shorter than the 58-byte header (`"too_short"`);
//! - leading version byte ≠ `0x01` (`"unknown_version"`);
//! - `signature_count > MAX_WITNESSES_PER_EPOCH` (`"too_many_signatures"`);
//! - total length less than `58 + signature_count * 96` (`"truncated_signatures"`);
//! - any trailing bytes after the last signature (`"trailing_bytes"`).
//!
//! Strict rejection of trailing bytes blocks server-side smuggling of extra
//! payload past the documented field set — a passive adversary cannot append
//! out-of-band data that legitimate decoders would tolerate.

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::witness::{SignedEpochRoot, WitnessPublic, WitnessSignature};

use umbrella_crypto_primitives::sig::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Версия wire-format `SignedEpochRoot`. Wire-format version byte.
pub const SIGNED_EPOCH_ROOT_WIRE_VERSION: u8 = 0x01;

/// SPEC-09 §6 invariant: не более 5 witness-подписей на эпоху.
/// SPEC-09 §6 invariant: at most 5 witness signatures per epoch.
pub const MAX_WITNESSES_PER_EPOCH: usize = 5;

/// Размер одной witness-signature на проводе: 32 + 64 = 96 байт.
/// On-wire size of one witness signature: 32 + 64 = 96 bytes.
pub const SIGNATURE_WIRE_LEN: usize = PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// Размер header'а wire-format: 1 + 8 + 32 + 8 + 8 + 1 = 58 байт.
/// Wire-format header size: 1 + 8 + 32 + 8 + 8 + 1 = 58 bytes.
pub const SIGNED_EPOCH_ROOT_HEADER_LEN: usize = 1 + 8 + NODE_HASH_LEN + 8 + 8 + 1;

/// Размер wire-format при `signature_count` подписях.
/// Wire-format size for `signature_count` signatures.
#[must_use]
pub const fn signed_epoch_root_wire_len(signature_count: usize) -> usize {
    SIGNED_EPOCH_ROOT_HEADER_LEN + signature_count * SIGNATURE_WIRE_LEN
}

/// Serialise [`SignedEpochRoot`] в wire bytes (deterministic).
///
/// # Errors
///
/// - [`KtError::InvalidSignedEpochRootWire`] с tag `"too_many_signatures"`
///   если `signed.signatures.len() > MAX_WITNESSES_PER_EPOCH` (encoder
///   refuses to emit a frame the strict decoder would reject).
///
/// # Determinism
///
/// Деtermimistic byte-by-byte: same input → same output (no randomness, no
/// allocator dependency на content). Order of `signed.signatures` preserved
/// — Ed25519 signature verification is order-independent
/// ([`verify_signed_epoch`](crate::witness::verify_signed_epoch) dedupes by
/// witness pubkey), но кодек преданно zeros не вставляет.
pub fn encode_signed_epoch_root(signed: &SignedEpochRoot) -> Result<Vec<u8>> {
    if signed.signatures.len() > MAX_WITNESSES_PER_EPOCH {
        return Err(KtError::InvalidSignedEpochRootWire("too_many_signatures"));
    }

    let mut out = Vec::with_capacity(signed_epoch_root_wire_len(signed.signatures.len()));
    out.push(SIGNED_EPOCH_ROOT_WIRE_VERSION);
    out.extend_from_slice(&signed.epoch.to_be_bytes());
    out.extend_from_slice(&signed.root);
    out.extend_from_slice(&signed.log_size.to_be_bytes());
    out.extend_from_slice(&signed.timestamp_unix_millis.to_be_bytes());
    // Safe cast: bounded by MAX_WITNESSES_PER_EPOCH=5 < u8::MAX.
    out.push(signed.signatures.len() as u8);
    for sig in &signed.signatures {
        out.extend_from_slice(&sig.witness.to_bytes());
        out.extend_from_slice(&sig.signature);
    }
    debug_assert_eq!(
        out.len(),
        signed_epoch_root_wire_len(signed.signatures.len())
    );
    Ok(out)
}

/// Deserialise [`SignedEpochRoot`] из wire bytes (strict).
///
/// Любая нестандартная конфигурация — `Err(InvalidSignedEpochRootWire)` с
/// stable string tag. Это soft-fail в смысле «caller получает structured
/// reason», а не panic — но фактически передаётся как KT error к facade и
/// далее как `ClientError::Kt(...)` к caller (постулат 14).
///
/// # Errors
///
/// - [`KtError::InvalidSignedEpochRootWire`] с одним из тэгов:
///   - `"too_short"` — input короче 58-байт header'а.
///   - `"unknown_version"` — leading byte ≠ `0x01`.
///   - `"too_many_signatures"` — `signature_count > MAX_WITNESSES_PER_EPOCH`.
///   - `"truncated_signatures"` — длина < `58 + signature_count * 96`.
///   - `"trailing_bytes"` — длина > `58 + signature_count * 96`.
pub fn decode_signed_epoch_root(bytes: &[u8]) -> Result<SignedEpochRoot> {
    if bytes.len() < SIGNED_EPOCH_ROOT_HEADER_LEN {
        return Err(KtError::InvalidSignedEpochRootWire("too_short"));
    }
    if bytes[0] != SIGNED_EPOCH_ROOT_WIRE_VERSION {
        return Err(KtError::InvalidSignedEpochRootWire("unknown_version"));
    }

    // Header parse — все слайсы внутри [0, 58) гарантированно длины header.
    // Header parse — all slices within [0, 58) are guaranteed header-length.
    let mut cursor = 1usize;

    let epoch = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .expect("slice of length 8"),
    );
    cursor += 8;

    let mut root = [0u8; NODE_HASH_LEN];
    root.copy_from_slice(&bytes[cursor..cursor + NODE_HASH_LEN]);
    cursor += NODE_HASH_LEN;

    let log_size = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .expect("slice of length 8"),
    );
    cursor += 8;

    let timestamp_unix_millis = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .expect("slice of length 8"),
    );
    cursor += 8;

    let signature_count = bytes[cursor] as usize;
    cursor += 1;
    debug_assert_eq!(cursor, SIGNED_EPOCH_ROOT_HEADER_LEN);

    if signature_count > MAX_WITNESSES_PER_EPOCH {
        return Err(KtError::InvalidSignedEpochRootWire("too_many_signatures"));
    }

    let expected_len = signed_epoch_root_wire_len(signature_count);
    if bytes.len() < expected_len {
        return Err(KtError::InvalidSignedEpochRootWire("truncated_signatures"));
    }
    if bytes.len() > expected_len {
        return Err(KtError::InvalidSignedEpochRootWire("trailing_bytes"));
    }

    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
        pk_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LEN]);
        cursor += PUBLIC_KEY_LEN;
        let mut sig_bytes = [0u8; SIGNATURE_LEN];
        sig_bytes.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LEN]);
        cursor += SIGNATURE_LEN;
        signatures.push(WitnessSignature {
            witness: WitnessPublic::from_bytes(pk_bytes),
            signature: sig_bytes,
        });
    }
    debug_assert_eq!(cursor, bytes.len());

    Ok(SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::canonical_sign_payload;
    use rand_core::OsRng;
    use umbrella_crypto_primitives::sig::PrivateSigningKey;

    // ========================================================================
    // Test helpers
    // ========================================================================

    struct TestWitness {
        sk: PrivateSigningKey,
        pk: WitnessPublic,
    }

    fn fresh_witness() -> TestWitness {
        let sk = PrivateSigningKey::generate(&mut OsRng);
        let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
        TestWitness { sk, pk }
    }

    fn sign_for(
        witness: &TestWitness,
        epoch: u64,
        root: &[u8; NODE_HASH_LEN],
        log_size: u64,
        ts_ms: u64,
    ) -> WitnessSignature {
        let payload = canonical_sign_payload(epoch, root, log_size, ts_ms);
        let sig = witness.sk.sign(&payload);
        WitnessSignature {
            witness: witness.pk,
            signature: sig.to_bytes(),
        }
    }

    fn fresh_signed_root(num_signatures: usize) -> SignedEpochRoot {
        let epoch = 42u64;
        let root: [u8; NODE_HASH_LEN] = [0xCD; NODE_HASH_LEN];
        let log_size = 1_000_000u64;
        let ts_ms = 1_715_000_000_000u64;
        let signatures: Vec<WitnessSignature> = (0..num_signatures)
            .map(|_| {
                let w = fresh_witness();
                sign_for(&w, epoch, &root, log_size, ts_ms)
            })
            .collect();
        SignedEpochRoot {
            epoch,
            root,
            log_size,
            timestamp_unix_millis: ts_ms,
            signatures,
        }
    }

    // ========================================================================
    // Constants invariants
    // ========================================================================

    #[test]
    fn header_constants_match_layout_documentation() {
        // 1 (version) + 8 (epoch) + 32 (root) + 8 (log_size) + 8 (timestamp) + 1 (sig_count) = 58
        assert_eq!(SIGNED_EPOCH_ROOT_HEADER_LEN, 58);
        assert_eq!(SIGNATURE_WIRE_LEN, 32 + 64);
        assert_eq!(SIGNATURE_WIRE_LEN, 96);
        assert_eq!(signed_epoch_root_wire_len(0), 58);
        assert_eq!(signed_epoch_root_wire_len(3), 58 + 3 * 96);
        assert_eq!(signed_epoch_root_wire_len(5), 58 + 5 * 96);
        assert_eq!(signed_epoch_root_wire_len(5), 538);
    }

    // ========================================================================
    // Round-trip preservation
    // ========================================================================

    #[test]
    fn encode_then_decode_round_trip_preserves_all_fields_with_five_signatures() {
        let original = fresh_signed_root(5);
        let bytes = encode_signed_epoch_root(&original).expect("encode 5 sigs");
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(5));
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 5 sigs");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_round_trip_preserves_all_fields_with_three_signatures() {
        let original = fresh_signed_root(3);
        let bytes = encode_signed_epoch_root(&original).expect("encode 3 sigs");
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(3));
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 3 sigs");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_round_trip_with_zero_signatures_produces_header_only_bytes() {
        let original = SignedEpochRoot {
            epoch: 0xDEAD_BEEF_CAFE_F00Du64,
            root: [0xAB; NODE_HASH_LEN],
            log_size: u64::MAX,
            timestamp_unix_millis: 1u64,
            signatures: vec![],
        };
        let bytes = encode_signed_epoch_root(&original).expect("encode 0 sigs");
        assert_eq!(bytes.len(), SIGNED_EPOCH_ROOT_HEADER_LEN);
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 0 sigs");
        assert_eq!(decoded, original);
        assert!(decoded.signatures.is_empty());
    }

    #[test]
    fn encode_produces_deterministic_output_for_same_input() {
        let signed = fresh_signed_root(3);
        let a = encode_signed_epoch_root(&signed).expect("encode A");
        let b = encode_signed_epoch_root(&signed).expect("encode B");
        assert_eq!(
            a, b,
            "encoder MUST be byte-deterministic given identical input"
        );
    }

    #[test]
    fn decode_preserves_signature_order_under_round_trip() {
        let signed = fresh_signed_root(5);
        let pk_order_before: Vec<WitnessPublic> =
            signed.signatures.iter().map(|s| s.witness).collect();
        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let decoded = decode_signed_epoch_root(&bytes).expect("decode");
        let pk_order_after: Vec<WitnessPublic> =
            decoded.signatures.iter().map(|s| s.witness).collect();
        assert_eq!(
            pk_order_before, pk_order_after,
            "decoder MUST preserve insertion order of signatures"
        );
    }

    // ========================================================================
    // Wire-level reproducibility — explicit byte layout
    // ========================================================================

    #[test]
    fn encode_wire_layout_zero_signatures_explicit_bytes() {
        // Explicit byte-by-byte layout pin for header-only frame. Locks the
        // exact wire format so accidental field-order swap или endianness
        // regressions trip this test.
        let signed = SignedEpochRoot {
            epoch: 0x0102_0304_0506_0708u64,
            root: {
                let mut r = [0u8; NODE_HASH_LEN];
                for (i, b) in r.iter_mut().enumerate() {
                    *b = i as u8;
                }
                r
            },
            log_size: 0x1011_1213_1415_1617u64,
            timestamp_unix_millis: 0x2021_2223_2425_2627u64,
            signatures: vec![],
        };
        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let mut expected = Vec::with_capacity(58);
        expected.push(0x01); // version
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // epoch BE
        for i in 0..32u8 {
            expected.push(i);
        } // root 0..31
        expected.extend_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]); // log_size BE
        expected.extend_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]); // timestamp BE
        expected.push(0x00); // signature_count = 0
        assert_eq!(bytes, expected);
    }

    // ========================================================================
    // Strict rejection — too_short
    // ========================================================================

    #[test]
    fn decode_rejects_empty_input_with_too_short_tag() {
        let err = decode_signed_epoch_root(&[]).expect_err("empty input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_short")
        ));
    }

    #[test]
    fn decode_rejects_input_one_byte_below_header_length() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.pop(); // 57 bytes — one byte short of header
        assert_eq!(bytes.len(), SIGNED_EPOCH_ROOT_HEADER_LEN - 1);
        let err = decode_signed_epoch_root(&bytes).expect_err("57-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_short")
        ));
    }

    #[test]
    fn decode_rejects_truncation_at_every_header_field_boundary() {
        // Take a header-only frame (58 bytes) and truncate at every length
        // in [0, 58) — each MUST be rejected with too_short. Boundary 58
        // is the minimum valid (zero-signature) frame which passes.
        let signed = fresh_signed_root(0);
        let full = encode_signed_epoch_root(&signed).expect("encode");
        assert_eq!(full.len(), 58);
        for truncate_at in 0..SIGNED_EPOCH_ROOT_HEADER_LEN {
            let truncated = &full[..truncate_at];
            match decode_signed_epoch_root(truncated) {
                Err(KtError::InvalidSignedEpochRootWire("too_short")) => {}
                other => panic!("truncate_at={truncate_at} expected too_short, got {other:?}"),
            }
        }
    }

    // ========================================================================
    // Strict rejection — unknown_version
    // ========================================================================

    #[test]
    fn decode_rejects_unknown_version_byte_0x00() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes[0] = 0x00;
        let err = decode_signed_epoch_root(&bytes).expect_err("version 0x00 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("unknown_version")
        ));
    }

    #[test]
    fn decode_rejects_unknown_version_byte_0x02() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes[0] = 0x02;
        let err = decode_signed_epoch_root(&bytes).expect_err("version 0x02 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("unknown_version")
        ));
    }

    #[test]
    fn decode_rejects_every_non_0x01_version_byte() {
        // Exhaustive enumeration of all 255 unknown version bytes.
        let signed = fresh_signed_root(0);
        let bytes_template = encode_signed_epoch_root(&signed).expect("encode");
        for bad_version in 0u8..=255u8 {
            if bad_version == SIGNED_EPOCH_ROOT_WIRE_VERSION {
                continue;
            }
            let mut bytes = bytes_template.clone();
            bytes[0] = bad_version;
            match decode_signed_epoch_root(&bytes) {
                Err(KtError::InvalidSignedEpochRootWire("unknown_version")) => {}
                other => panic!(
                    "bad_version=0x{bad_version:02x} expected unknown_version, got {other:?}"
                ),
            }
        }
    }

    // ========================================================================
    // Strict rejection — too_many_signatures
    // ========================================================================

    #[test]
    fn encode_rejects_input_with_six_signatures_via_too_many_signatures_tag() {
        // Encoder защищает adversary-controlled callers от формирования
        // frame'а который strict-decoder отверг бы — symmetry между
        // encode и decode.
        let mut signed = fresh_signed_root(5);
        let extra_witness = fresh_witness();
        let extra_sig = sign_for(
            &extra_witness,
            signed.epoch,
            &signed.root,
            signed.log_size,
            signed.timestamp_unix_millis,
        );
        signed.signatures.push(extra_sig);
        assert_eq!(signed.signatures.len(), 6);
        let err = encode_signed_epoch_root(&signed).expect_err("encode 6 sigs must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    #[test]
    fn decode_rejects_wire_signature_count_byte_above_max_witnesses() {
        // Adversary вручную конструирует frame с signature_count=6 + 6 sigs.
        // Header parsed ok, signature_count > MAX → fail-closed before
        // attempting body parse.
        let signed = fresh_signed_root(5);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode 5");
        // Mutate signature_count byte at offset 57 to 6.
        bytes[57] = 0x06;
        // Append a fake 96-byte signature payload so length matches what
        // a non-strict decoder might expect for 6 sigs (58 + 6*96 = 634).
        bytes.extend_from_slice(&[0xFF; SIGNATURE_WIRE_LEN]);
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(6));
        let err = decode_signed_epoch_root(&bytes).expect_err("count=6 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    #[test]
    fn decode_rejects_wire_signature_count_byte_0xff_extreme() {
        // Adversary устанавливает count=255 — should be rejected before
        // attempting allocation of 255 signatures.
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode 0");
        bytes[57] = 0xFF;
        let err = decode_signed_epoch_root(&bytes).expect_err("count=255 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    // ========================================================================
    // Strict rejection — truncated_signatures
    // ========================================================================

    #[test]
    fn decode_rejects_frame_where_payload_shorter_than_signature_count_implies() {
        // signature_count = 3 (header byte at 57), но в payload ровно 2
        // signatures (192 bytes after header) → expected 58 + 288 = 346,
        // actual = 58 + 192 = 250 → truncated_signatures.
        let signed_three = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed_three).expect("encode 3");
        // Strip last 96-byte signature payload off the end (decoder sees
        // header claims 3 but only 2 signatures present).
        bytes.truncate(bytes.len() - SIGNATURE_WIRE_LEN);
        assert_eq!(
            bytes.len(),
            signed_epoch_root_wire_len(3) - SIGNATURE_WIRE_LEN
        );
        let err = decode_signed_epoch_root(&bytes).expect_err("truncated body must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("truncated_signatures")
        ));
    }

    #[test]
    fn decode_rejects_frame_truncated_one_byte_into_signature_payload() {
        // Header valid, signature_count = 1, but only 95 bytes of the 96-byte
        // signature follow — single missing byte must fail-close.
        let signed_one = fresh_signed_root(1);
        let mut bytes = encode_signed_epoch_root(&signed_one).expect("encode 1");
        bytes.pop(); // 58 + 95 = 153 bytes
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(1) - 1);
        let err = decode_signed_epoch_root(&bytes).expect_err("153-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("truncated_signatures")
        ));
    }

    // ========================================================================
    // Strict rejection — trailing_bytes
    // ========================================================================

    #[test]
    fn decode_rejects_one_trailing_byte_appended_after_last_signature() {
        let signed = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.push(0x00); // one extra byte beyond expected layout
        let err = decode_signed_epoch_root(&bytes).expect_err("trailing byte must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    #[test]
    fn decode_rejects_extra_signature_payload_size_chunk_appended() {
        // Adversary appends a full extra 96-byte signature payload but does
        // not bump the signature_count byte — strict decoder must reject.
        let signed = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.extend_from_slice(&[0xAA; SIGNATURE_WIRE_LEN]);
        let err =
            decode_signed_epoch_root(&bytes).expect_err("trailing signature payload must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    #[test]
    fn decode_rejects_one_trailing_byte_after_zero_signature_header() {
        // Edge case: header-only frame + 1 trailing byte = 59 bytes.
        // Without the strict trailing check this would silently parse
        // as «valid zero-sig header» ignoring the dangling byte.
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.push(0x42);
        let err = decode_signed_epoch_root(&bytes).expect_err("59-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    // ========================================================================
    // Verify-compat — decoded frame passes verify_signed_epoch
    // ========================================================================

    #[test]
    fn decoded_signed_epoch_root_verifies_against_pinned_witness_set_threshold_three_of_five() {
        // Integration cross-check: encode honest 5-of-5, decode, then run
        // verify_signed_epoch — confirms wire layout matches what witness
        // verify expects (no field swap / endianness regression).
        use crate::witness::{verify_signed_epoch, WitnessSet};

        let witnesses: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let epoch = 42u64;
        let root = [0xCD; NODE_HASH_LEN];
        let log_size = 1_000_000u64;
        let ts_ms = 1_715_000_000_000u64;
        let signatures: Vec<WitnessSignature> = witnesses
            .iter()
            .map(|w| sign_for(w, epoch, &root, log_size, ts_ms))
            .collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size,
            timestamp_unix_millis: ts_ms,
            signatures,
        };

        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let decoded = decode_signed_epoch_root(&bytes).expect("decode");

        let mut witness_set = WitnessSet::new();
        for w in &witnesses {
            witness_set.add(w.pk);
        }
        verify_signed_epoch(&decoded, &witness_set, 3).expect(
            "decoded SignedEpochRoot MUST verify under pinned set with threshold 3 — \
             confirms wire layout binds to canonical_sign_payload correctly",
        );
    }
}
