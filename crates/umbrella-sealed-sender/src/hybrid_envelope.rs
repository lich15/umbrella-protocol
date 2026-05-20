//! Sealed Sender V2 hybrid envelope — X-Wing ephemeral KEM (Этап 8, блок 8.6).
//! Sealed Sender V2 hybrid envelope — X-Wing ephemeral KEM (Stage 8, block 8.6).
//!
//! ## Назначение
//!
//! V2 envelope заменяет classical X25519 ephemeral ECDH (V1 `lib.rs::seal`)
//! на X-Wing combiner KEM (X25519 + ML-KEM-768 hybrid, draft-connolly-cfrg-xwing-kem-10).
//! Inner protocol (sender_identity || ed25519_signature || message + padding)
//! **не меняется** — same authentication semantics, same anti-tamper guarantees.
//!
//! Закрывает **post-quantum confidentiality** для sealed-sender envelopes:
//! attacker, накапливающий envelope трафик, не сможет recover plaintext
//! даже при появлении CRQC (cryptographically relevant quantum computer)
//! — ему нужно сломать **оба** компонента X-Wing combiner (X25519 ECDH +
//! ML-KEM-768 lattice) что в текущих pq cryptanalysis невозможно.
//!
//! ## Wire format
//!
//! ```text
//! Offset | Size  | Field
//! -------+-------+----------------------------------------------------
//!     0  |    1  | version = 0x02
//!     1  | 1120  | xwing_ciphertext (X-Wing encaps result;
//!        |       |    contains sender ephemeral X25519 pub +
//!        |       |    ML-KEM-768 ciphertext per draft-connolly-cfrg-xwing-kem-10)
//!  1121  |    *  | inner_ct (AEAD ChaCha20-Poly1305 over
//!        |       |    padded inner = sender_pub || sig || message)
//! ```
//!
//! Total V2 wire = 1 + 1120 + AEAD(inner_padded). Overhead vs V1: +1088 bytes
//! на envelope (X-Wing ct 1120 - X25519 ephemeral pub 32 = 1088). Это
//! разумная цена за post-quantum confidentiality (постулат 4.5 — measure
//! before optimize: ~3 KB total V2 envelope для типичного inner payload).
//!
//! **Важно:** design.md §9.2 ранее указывал wire layout
//! `version || ephemeral_xwing_pubkey 1216 || xwing_ciphertext 1120`. Это
//! **некорректно**: 1216 bytes — это recipient *static* X-Wing pubkey
//! (не часть envelope; recipient знает свой pubkey локально), а sender
//! ephemeral X25519 pubkey уже **встроен в** xwing_ciphertext per
//! draft-connolly-cfrg-xwing-kem-10 §5.4
//! (X-Wing ct = ML-KEM ct 1088 || X25519 ephemeral pub 32 = 1120 bytes total).
//! Финальный wire — этот module + design fix-on-sight
//! в TODO.md блока 8.6.
//!
//! ## KDF derivation
//!
//! Same pattern as V1 (`derive_keys` в lib.rs), но domain-separator другой
//! (`DOMAIN_SEP_V2` = `b"umbrellax-sealed-sender-v2"`). HKDF-SHA256:
//! - salt = `DOMAIN_SEP_V2`
//! - ikm  = X-Wing shared secret (32 bytes)
//! - info = `DOMAIN_SEP_V2 || ct (1120) || recipient_xwing_pubkey (1216)`
//! - L    = AEAD_KEY_LEN (32) + AEAD_NONCE_LEN (12) = 44 bytes
//!
//! ## AEAD AAD
//!
//! `version (1) || ct (1120) || recipient_xwing_pubkey (1216)` = 2337 bytes.
//! Tampering любого из этих полей → AEAD decrypt fails.
//!
//! ## Authentication invariant
//!
//! Inner ed25519 signature покрывает `DOMAIN_SEP_V2 || ct || message` —
//! привязка sender → конкретный envelope. Same recipe как V1 (только domain
//! separator другой, чтобы V1 и V2 signatures не cross-protocol replay'ились).
//!
//! ## Backward compat
//!
//! Без feature `pq` этот модуль не компилируется; existing 0.0.11 V1 path
//! (`lib.rs::seal` / `unseal`) работает identical. V2 envelope с leading byte
//! `0x02` отвергается V1 unseal через `SealedSenderError::UnsupportedVersion`
//! (existing behavior).

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use umbrella_crypto_primitives::aead::{AeadKey, AeadNonce, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use umbrella_crypto_primitives::kdf::hkdf_sha256;
use umbrella_crypto_primitives::secret::SecretBytes;
use umbrella_crypto_primitives::sig::{
    Ed25519Signature, PublicVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use umbrella_identity::{IdentityKeyPublic, KeyStore};
use umbrella_padding::{pad_to_bucket, strip_padding};
use umbrella_pq::{
    xwing_decaps, xwing_encaps_hedged, XWingPublicKey, XWingSecretSeed, XWING_CIPHERTEXT_LEN,
    XWING_PUBLIC_KEY_LEN, XWING_SHARED_SECRET_LEN,
};

use crate::version::SealedSenderVersion;
use crate::{OpenedEnvelope, OpenedMessage, Result, SealedSenderError, INNER_HEADER_LEN};

/// Domain separator для V2 KDF info, AEAD AAD и inner-signature payload.
/// ASCII literal; смена ломает совместимость, требует ADR-amendment.
///
/// Domain separator for the V2 KDF info, AEAD AAD, and inner-signature
/// payload. ASCII literal; changing it breaks compatibility and requires an
/// ADR amendment.
pub const V2_DOMAIN_SEP: &[u8] = b"umbrellax-sealed-sender-v2";

/// Длина version-байта (1).
/// Length of the version byte (1).
const VERSION_LEN: usize = 1;

/// Минимальный wire размер V2: version + xwing_ct + AEAD(min_bucket + tag).
/// bucket_min = 256 (umbrella-padding), AEAD tag = 16.
///
/// Minimum V2 wire size: version + xwing_ct + AEAD(min_bucket + tag).
/// bucket_min = 256 (umbrella-padding), AEAD tag = 16.
pub const V2_MIN_WIRE_LEN: usize = VERSION_LEN + XWING_CIPHERTEXT_LEN + 256 + 16;

/// Запечатывает application-message в V2 envelope с X-Wing ephemeral KEM.
///
/// Параметры:
/// - `keystore` — отправитель (identity_ed25519 для inner signature; X-Wing не нужен).
/// - `recipient_xwing_pubkey` — публичный X-Wing pubkey получателя (1216 bytes).
///   Caller обязан получить его через trusted channel (KT v2 entry в будущей
///   итерации — block 8.5 не включил X-Wing pubkey в KT entry; в текущей
///   итерации caller передаёт напрямую).
/// - `message` — application payload; padded to nearest bucket внутри.
/// - `rng` — CSPRNG для X-Wing encaps + ed25519 signature.
///
/// Wire format: `0x02 || xwing_ct (1120) || AEAD(inner_padded)`.
///
/// Seals an application message in a V2 envelope with X-Wing ephemeral KEM.
///
/// Parameters:
/// - `keystore` — sender (identity_ed25519 for the inner signature; X-Wing not needed).
/// - `recipient_xwing_pubkey` — recipient's public X-Wing pubkey (1216 bytes).
///   The caller must obtain it through a trusted channel (the KT v2 entry in
///   a future iteration — block 8.5 did not include the X-Wing pubkey in the
///   KT entry; in the current iteration the caller passes it directly).
/// - `message` — application payload; padded to the nearest bucket internally.
/// - `rng` — CSPRNG for X-Wing encaps + ed25519 signature.
///
/// Wire format: `0x02 || xwing_ct (1120) || AEAD(inner_padded)`.
pub fn seal_v2<R: CryptoRng + RngCore>(
    keystore: &dyn KeyStore,
    recipient_xwing_pubkey: &XWingPublicKey,
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if message.len() > crate::MAX_PAYLOAD {
        return Err(SealedSenderError::PayloadTooLarge {
            payload_len: message.len(),
            max: crate::MAX_PAYLOAD,
        });
    }

    // 1. X-Wing **hedged** encaps под recipient pubkey → (ct, shared_secret).
    // Round-3 hedged-encaps closure 2026-05-19 (Bellare-Hoang-Keelveedhi 2015).
    // Transcript = sender_identity (32) || recipient_pubkey (1216) ||
    //              version_byte (1) — byte-distinct per (sender, recipient,
    // version) tuple; даже compromised RNG не даст attacker'у возможности
    // replicate ss без secret hedged_witness.
    //
    // 1. X-Wing **hedged** encaps under recipient pubkey → (ct, shared_secret).
    // Round-3 hedged-encaps closure 2026-05-19 (Bellare-Hoang-Keelveedhi 2015).
    // Transcript = sender_identity (32) || recipient_pubkey (1216) ||
    //              version_byte (1) — byte-distinct per (sender, recipient,
    // version) tuple; a compromised RNG cannot let the attacker replicate
    // ss without the secret hedged_witness.
    let sender_identity_bytes = keystore.identity_public().to_bytes();
    let mut transcript = Vec::with_capacity(32 + XWING_PUBLIC_KEY_LEN + 1);
    transcript.extend_from_slice(&sender_identity_bytes);
    transcript.extend_from_slice(recipient_xwing_pubkey.as_bytes());
    transcript.push(SealedSenderVersion::V2HybridXWing.as_u8());

    let hedged_witness = keystore.hedged_encaps_witness();
    let (xwing_ct, shared_secret) =
        xwing_encaps_hedged(rng, recipient_xwing_pubkey, hedged_witness, &transcript)
            .map_err(|_| SealedSenderError::InvalidV2Envelope("xwing_encaps_failed"))?;

    // 2. Derive AEAD key + nonce из shared_secret (HKDF-SHA256).
    // 2. Derive AEAD key + nonce from shared_secret (HKDF-SHA256).
    let (aead_key, aead_nonce) = derive_v2_keys(&shared_secret, &xwing_ct, recipient_xwing_pubkey)?;

    // 3. Inner-payload: sender_pub || ed25519_sig(DOMAIN_SEP_V2 || ct || message) || message.
    // 3. Inner payload: sender_pub || ed25519_sig(DOMAIN_SEP_V2 || ct || message) || message.
    let sender_identity = keystore.identity_public();
    let sig_payload = signature_payload_v2(&xwing_ct, message);
    let sig = keystore.sign_with_identity(sig_payload.as_slice());

    // SPEC-08 §5.2 step 9 — `inner_plaintext` + `padded_blob` zeroize on
    // drop через `Zeroizing<Vec<u8>>` (row 11 cold-boot mitigation,
    // F-50 closure; same pattern V1 lib.rs).
    // SPEC-08 §5.2 step 9 — `inner_plaintext` + `padded_blob` zeroize on
    // drop via `Zeroizing<Vec<u8>>` (row 11 cold-boot mitigation,
    // F-50 closure; same pattern as V1 lib.rs).
    let mut inner: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(INNER_HEADER_LEN + message.len()));
    inner.extend_from_slice(&sender_identity.to_bytes());
    inner.extend_from_slice(&sig.to_bytes());
    inner.extend_from_slice(message);

    let padded: Zeroizing<Vec<u8>> = Zeroizing::new(pad_to_bucket(&inner)?);

    // 4. AEAD encrypt с AAD = version || ct || recipient_xwing_pubkey.
    // 4. AEAD encrypt with AAD = version || ct || recipient_xwing_pubkey.
    let ad = aead_ad_v2(&xwing_ct, recipient_xwing_pubkey);
    let inner_ct = aead_key.encrypt(&aead_nonce, &ad, &padded)?;

    // 5. Compose wire.
    // 5. Compose wire.
    let mut wire = Vec::with_capacity(VERSION_LEN + XWING_CIPHERTEXT_LEN + inner_ct.len());
    wire.push(SealedSenderVersion::V2HybridXWing.as_u8());
    wire.extend_from_slice(&xwing_ct);
    wire.extend_from_slice(&inner_ct);
    Ok(wire)
}

/// Раскрывает V2 envelope получателя через X-Wing decaps.
///
/// Параметры:
/// - `keystore` — получатель (для verifying-key sender'а; X-Wing не использует
///   classical X25519 identity, используется только Ed25519 для verify inner sig).
/// - `own_xwing_pubkey` — собственный X-Wing pubkey (1216 bytes); используется
///   в AEAD AAD и KDF info — должен совпадать с тем, что использовал sender.
/// - `own_xwing_seed` — собственный X-Wing secret seed (32 bytes wrapped в
///   `XWingSecretSeed`). На дату блока 8.6 caller предоставляет напрямую;
///   KeyStore X-Wing extension — отдельный block (8.8).
/// - `wire` — wire bytes (минимум 1393 bytes).
///
/// Errors:
/// - `UnsupportedVersion { got }` — первый byte != 0x02.
/// - `Malformed { reason }` — wire слишком короткий / структурно невалидный.
/// - `InvalidV2Envelope(tag)` — X-Wing decaps fail / KDF fail.
/// - `Crypto(_)` — AEAD fail (tampered ct / wrong recipient seed).
/// - `InvalidSignature` — inner ed25519 signature не verify.
///
/// Unseals a V2 envelope for the recipient via X-Wing decaps.
pub fn unseal_v2(
    keystore: &dyn KeyStore,
    own_xwing_pubkey: &XWingPublicKey,
    own_xwing_seed: &XWingSecretSeed,
    wire: &[u8],
) -> Result<OpenedEnvelope> {
    let _ = keystore; // identity_public не нужен на этом этапе — sender pub берётся из inner.

    // Order проверок: empty → version → length → parse. Diagnostic-friendly:
    // V1 envelope (короткое wire с byte 0x01) сразу даёт UnsupportedVersion,
    // не «too short» — caller знает что это V1, не corrupted V2 (постулат 14).
    //
    // Check order: empty → version → length → parse. Diagnostic-friendly:
    // V1 envelope (short wire with byte 0x01) immediately yields
    // UnsupportedVersion, not «too short» — the caller knows it is V1, not a
    // corrupted V2 (postulate 14).
    if wire.is_empty() {
        return Err(SealedSenderError::Malformed {
            reason: "V2 wire is empty",
        });
    }

    // Strict V2 dispatcher: первый байт == 0x02.
    // Strict V2 dispatcher: first byte == 0x02.
    let version = SealedSenderVersion::try_from(wire[0])?;
    if version != SealedSenderVersion::V2HybridXWing {
        return Err(SealedSenderError::UnsupportedVersion { got: wire[0] });
    }

    if wire.len() < V2_MIN_WIRE_LEN {
        return Err(SealedSenderError::Malformed {
            reason: "V2 wire shorter than minimum",
        });
    }

    // Parse xwing_ct.
    let mut ct_buf = [0u8; XWING_CIPHERTEXT_LEN];
    ct_buf.copy_from_slice(&wire[VERSION_LEN..VERSION_LEN + XWING_CIPHERTEXT_LEN]);

    // X-Wing decaps → shared_secret.
    let shared_secret = xwing_decaps(own_xwing_seed, &ct_buf)
        .map_err(|_| SealedSenderError::InvalidV2Envelope("xwing_decaps_failed"))?;

    // Derive AEAD key + nonce.
    let (aead_key, aead_nonce) = derive_v2_keys(&shared_secret, &ct_buf, own_xwing_pubkey)?;

    // AEAD decrypt с AAD = version || ct || own_xwing_pubkey.
    let inner_ct = &wire[VERSION_LEN + XWING_CIPHERTEXT_LEN..];
    let ad = aead_ad_v2(&ct_buf, own_xwing_pubkey);
    // SPEC-08 §5.2 step 9 — `padded_blob` zeroize on drop через
    // `Zeroizing<Vec<u8>>`; `inner` — borrow в этот же буфер (row 11
    // cold-boot mitigation, F-50 closure; same pattern V1 lib.rs).
    // SPEC-08 §5.2 step 9 — `padded_blob` zeroizes on drop via
    // `Zeroizing<Vec<u8>>`; `inner` is a borrow into the same buffer
    // (row 11 cold-boot mitigation, F-50 closure; same pattern as V1
    // lib.rs).
    let padded: Zeroizing<Vec<u8>> =
        Zeroizing::new(aead_key.decrypt(&aead_nonce, &ad, inner_ct)?);
    let inner = strip_padding(&padded)?;

    if inner.len() < INNER_HEADER_LEN {
        return Err(SealedSenderError::Malformed {
            reason: "V2 inner plaintext shorter than header",
        });
    }

    // Parse sender identity + signature + message.
    let mut sender_id_bytes = [0u8; PUBLIC_KEY_LEN];
    sender_id_bytes.copy_from_slice(&inner[..PUBLIC_KEY_LEN]);
    let sender_identity = IdentityKeyPublic::from_bytes(&sender_id_bytes)
        .map_err(|_| SealedSenderError::MalformedSenderKey)?;

    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(&inner[PUBLIC_KEY_LEN..INNER_HEADER_LEN]);
    let sig = Ed25519Signature::from_bytes(&sig_bytes);

    let mut message = Zeroizing::new(Vec::with_capacity(inner.len() - INNER_HEADER_LEN));
    message.extend_from_slice(&inner[INNER_HEADER_LEN..]);

    // Verify inner signature над DOMAIN_SEP_V2 || ct || message.
    let sig_payload = signature_payload_v2(&ct_buf, message.as_slice());
    let vk = PublicVerifyingKey::from_bytes(&sender_id_bytes)
        .map_err(|_| SealedSenderError::MalformedSenderKey)?;
    vk.verify(sig_payload.as_slice(), &sig)
        .map_err(|_| SealedSenderError::InvalidSignature)?;

    Ok(OpenedEnvelope {
        sender_identity,
        message: OpenedMessage::from_zeroizing(message),
    })
}

/// Derive AEAD key + nonce из X-Wing shared_secret через HKDF-SHA256.
/// `info` контекст: DOMAIN_SEP_V2 || ct || recipient_xwing_pubkey — domain
/// separation от V1 KDF (V1 использует `umbrellax-sealed-sender-v1`).
///
/// Derive AEAD key + nonce from the X-Wing shared_secret via HKDF-SHA256.
/// `info` context: DOMAIN_SEP_V2 || ct || recipient_xwing_pubkey — domain
/// separation from the V1 KDF (V1 uses `umbrellax-sealed-sender-v1`).
fn derive_v2_keys(
    shared_secret: &secrecy::SecretBox<[u8; XWING_SHARED_SECRET_LEN]>,
    xwing_ct: &[u8; XWING_CIPHERTEXT_LEN],
    recipient_xwing_pubkey: &XWingPublicKey,
) -> Result<(AeadKey, AeadNonce)> {
    use secrecy::ExposeSecret;

    let mut info =
        Vec::with_capacity(V2_DOMAIN_SEP.len() + XWING_CIPHERTEXT_LEN + XWING_PUBLIC_KEY_LEN);
    info.extend_from_slice(V2_DOMAIN_SEP);
    info.extend_from_slice(xwing_ct);
    info.extend_from_slice(recipient_xwing_pubkey.as_bytes());

    let okm = hkdf_sha256::<{ AEAD_KEY_LEN + AEAD_NONCE_LEN }>(
        V2_DOMAIN_SEP,
        shared_secret.expose_secret(),
        &info,
    )?;
    let bytes = okm.expose();

    let mut key_bytes = SecretBytes::<AEAD_KEY_LEN>::zeroed();
    key_bytes
        .expose_mut()
        .copy_from_slice(&bytes[..AEAD_KEY_LEN]);
    let aead_key = AeadKey::from_bytes(&key_bytes);

    let mut nonce_raw = [0u8; AEAD_NONCE_LEN];
    nonce_raw.copy_from_slice(&bytes[AEAD_KEY_LEN..AEAD_KEY_LEN + AEAD_NONCE_LEN]);
    let aead_nonce = AeadNonce::from_bytes(nonce_raw);

    Ok((aead_key, aead_nonce))
}

/// Inner-signature payload V2: `DOMAIN_SEP_V2 || xwing_ct || message`.
/// Подпись sender'а покрывает конкретный envelope (через ct) — anti-replay.
///
/// V2 inner-signature payload: `DOMAIN_SEP_V2 || xwing_ct || message`.
/// The sender's signature covers the specific envelope (via ct) — anti-replay.
fn signature_payload_v2(
    xwing_ct: &[u8; XWING_CIPHERTEXT_LEN],
    message: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(
        V2_DOMAIN_SEP.len() + XWING_CIPHERTEXT_LEN + message.len(),
    ));
    payload.extend_from_slice(V2_DOMAIN_SEP);
    payload.extend_from_slice(xwing_ct);
    payload.extend_from_slice(message);
    payload
}

/// AEAD AAD V2: `version (0x02) || xwing_ct || recipient_xwing_pubkey`.
/// Tampering любого из этих полей → AEAD decrypt fails.
///
/// V2 AEAD AAD: `version (0x02) || xwing_ct || recipient_xwing_pubkey`.
/// Tampering any of these fields → AEAD decrypt fails.
fn aead_ad_v2(
    xwing_ct: &[u8; XWING_CIPHERTEXT_LEN],
    recipient_xwing_pubkey: &XWingPublicKey,
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(VERSION_LEN + XWING_CIPHERTEXT_LEN + XWING_PUBLIC_KEY_LEN);
    ad.push(SealedSenderVersion::V2HybridXWing.as_u8());
    ad.extend_from_slice(xwing_ct);
    ad.extend_from_slice(recipient_xwing_pubkey.as_bytes());
    ad
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use rand_core::OsRng;
    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};
    use umbrella_pq::xwing_keygen;

    fn fresh_keystore() -> Arc<InMemoryKeyStore> {
        let mut rng = OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
    }

    fn fresh_xwing_keypair() -> (XWingPublicKey, XWingSecretSeed) {
        let mut rng = OsRng;
        xwing_keygen(&mut rng).unwrap()
    }

    #[test]
    fn seal_v2_unseal_v2_roundtrip_short() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"hello-bob-pq", &mut rng).unwrap();
        let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
        assert_eq!(opened.sender_identity, alice.identity_public());
        assert_eq!(opened.message, b"hello-bob-pq");
    }

    #[test]
    fn seal_v2_first_byte_is_version_stamp() {
        let alice = fresh_keystore();
        let (bob_xwing_pk, _) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"hi", &mut rng).unwrap();
        assert_eq!(wire[0], 0x02);
        assert_eq!(wire[0], SealedSenderVersion::V2HybridXWing.as_u8());
        assert!(wire.len() >= V2_MIN_WIRE_LEN);
    }

    #[test]
    fn seal_v2_wire_contains_xwing_ct() {
        let alice = fresh_keystore();
        let (bob_xwing_pk, _) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"hi", &mut rng).unwrap();
        // After version byte, next XWING_CIPHERTEXT_LEN bytes — это encaps result.
        // After version byte, next XWING_CIPHERTEXT_LEN bytes — encaps result.
        let ct_slice = &wire[1..1 + XWING_CIPHERTEXT_LEN];
        assert_eq!(ct_slice.len(), XWING_CIPHERTEXT_LEN);
    }

    #[test]
    fn unseal_v2_rejects_too_short_wire() {
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let short = vec![0x02; V2_MIN_WIRE_LEN - 1];
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &short);
        assert!(matches!(result, Err(SealedSenderError::Malformed { .. })));
    }

    #[test]
    fn unseal_v2_rejects_v1_version_byte() {
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut wire = vec![0x01u8; V2_MIN_WIRE_LEN];
        wire[0] = 0x01;
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        assert!(matches!(
            result,
            Err(SealedSenderError::UnsupportedVersion { got: 0x01 })
        ));
    }

    #[test]
    fn unseal_v2_rejects_unknown_version_byte() {
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut wire = vec![0xABu8; V2_MIN_WIRE_LEN];
        wire[0] = 0xAB;
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        assert!(matches!(
            result,
            Err(SealedSenderError::UnsupportedVersion { got: 0xAB })
        ));
    }

    #[test]
    fn unseal_v2_rejects_tampered_ct() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
        // Подменяем 1 byte X-Wing ct → AEAD decrypt fails (либо decaps fails).
        wire[VERSION_LEN] ^= 0x01;
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        assert!(result.is_err(), "tampered ct должен быть отвергнут");
    }

    #[test]
    fn unseal_v2_rejects_tampered_inner_ct() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let mut wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire);
        assert!(matches!(result, Err(SealedSenderError::Crypto(_))));
    }

    #[test]
    fn wrong_recipient_seed_cannot_unseal_v2() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, _bob_xwing_sk) = fresh_xwing_keypair();
        let (_eve_xwing_pk, eve_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"for-bob", &mut rng).unwrap();
        // Используем Bob's pubkey но Eve's seed → decaps возвращает другой shared.
        // Use Bob's pubkey but Eve's seed → decaps returns a different shared.
        let result = unseal_v2(bob.as_ref(), &bob_xwing_pk, &eve_xwing_sk, &wire);
        assert!(result.is_err(), "Eve не должна расшифровать envelope");
    }

    #[test]
    fn forged_inner_signature_rejected_after_successful_v2_decrypt() {
        let alice = fresh_keystore();
        let eve = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let message = b"forged-inner-signature";

        // Test-only: use legacy xwing_encaps (still in API for tests where
        // hedged witness не нужен). Production использует
        // xwing_encaps_hedged via seal_v2.
        // Test-only: use legacy xwing_encaps (still in API for tests where
        // the hedged witness is not needed). Production uses
        // xwing_encaps_hedged via seal_v2.
        let (xwing_ct, shared_secret) =
            umbrella_pq::xwing_encaps(&mut rng, &bob_xwing_pk).expect("xwing encaps");
        let (aead_key, aead_nonce) =
            derive_v2_keys(&shared_secret, &xwing_ct, &bob_xwing_pk).expect("v2 keys");

        let payload = signature_payload_v2(&xwing_ct, message);
        let eve_signature = eve.sign_with_identity(&payload);

        let mut inner = Vec::with_capacity(INNER_HEADER_LEN + message.len());
        inner.extend_from_slice(&alice.identity_public().to_bytes());
        inner.extend_from_slice(&eve_signature.to_bytes());
        inner.extend_from_slice(message);

        let padded = pad_to_bucket(&inner).expect("pad forged inner");
        let ad = aead_ad_v2(&xwing_ct, &bob_xwing_pk);
        let inner_ct = aead_key
            .encrypt(&aead_nonce, &ad, &padded)
            .expect("encrypt forged inner");

        let mut wire = Vec::with_capacity(VERSION_LEN + XWING_CIPHERTEXT_LEN + inner_ct.len());
        wire.push(SealedSenderVersion::V2HybridXWing.as_u8());
        wire.extend_from_slice(&xwing_ct);
        wire.extend_from_slice(&inner_ct);

        let err = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap_err();
        assert!(matches!(err, SealedSenderError::InvalidSignature));
    }

    #[test]
    fn seal_v2_rejects_payload_over_max() {
        let alice = fresh_keystore();
        let (bob_xwing_pk, _) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let payload = vec![0u8; crate::MAX_PAYLOAD + 1];
        let result = seal_v2(alice.as_ref(), &bob_xwing_pk, &payload, &mut rng);
        assert!(matches!(
            result,
            Err(SealedSenderError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn same_message_twice_produces_different_v2_wire() {
        let alice = fresh_keystore();
        let (bob_xwing_pk, _) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let w1 = seal_v2(alice.as_ref(), &bob_xwing_pk, b"x", &mut rng).unwrap();
        let w2 = seal_v2(alice.as_ref(), &bob_xwing_pk, b"x", &mut rng).unwrap();
        assert_ne!(w1, w2, "X-Wing encaps random — каждый envelope уникальный");
    }

    #[test]
    fn empty_message_roundtrip() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"", &mut rng).unwrap();
        let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
        assert_eq!(opened.message, Vec::<u8>::new());
    }

    #[test]
    fn boundary_lengths_roundtrip() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        for len in [0usize, 1, 100, 156, 157, 900, 4000] {
            let msg = vec![0x42; len];
            let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, &msg, &mut rng).unwrap();
            let opened = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap();
            assert_eq!(opened.message, msg, "len={len}");
        }
    }

    #[test]
    fn aad_pubkey_mismatch_fails() {
        // Если caller передал чужой xwing_pubkey в unseal — AEAD AAD не совпадает,
        // decrypt fails.
        // If caller passed a different xwing_pubkey to unseal — AEAD AAD mismatches,
        // decrypt fails.
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let (other_pk, _) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let wire = seal_v2(alice.as_ref(), &bob_xwing_pk, b"msg", &mut rng).unwrap();
        let result = unseal_v2(bob.as_ref(), &other_pk, &bob_xwing_sk, &wire);
        // shared secret выводится через bob_xwing_sk → корректный, но AAD = other_pk
        // → decrypt fails.
        // shared secret derived via bob_xwing_sk → correct, but AAD = other_pk
        // → decrypt fails.
        assert!(result.is_err(), "aad mismatch must fail");
    }

    #[test]
    fn min_wire_len_constant_matches_layout() {
        // 1 (version) + 1120 (xwing_ct) + 256 (min bucket) + 16 (AEAD tag) = 1393.
        // 1 (version) + 1120 (xwing_ct) + 256 (min bucket) + 16 (AEAD tag) = 1393.
        assert_eq!(V2_MIN_WIRE_LEN, 1 + 1120 + 256 + 16);
        assert_eq!(V2_MIN_WIRE_LEN, 1393);
    }

    #[test]
    fn v2_wire_overhead_vs_v1_is_xwing_ct_minus_x25519_pub() {
        // Overhead V2-V1 на envelope: XWING_CT (1120) - X25519_PUBLIC (32) = 1088 bytes.
        // V2-V1 envelope overhead: XWING_CT (1120) - X25519_PUBLIC (32) = 1088 bytes.
        assert_eq!(XWING_CIPHERTEXT_LEN - 32, 1088);
    }
}
