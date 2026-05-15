//! Cloud-wrap V2 hybrid wrapping layer — X-Wing envelope над V1 WrappedKey.
//! Cloud-wrap V2 hybrid wrapping layer — X-Wing envelope over V1 WrappedKey.
//!
//! ## Назначение
//!
//! Этап 8 блок 8.7: добавляет post-quantum confidentiality recovery key
//! через outer X-Wing layer. V1 ElGamal scheme полностью сохранена внутри;
//! Sealed Servers ceremony unchanged. Hybrid PQ layer полностью client-side.
//!
//! Защищает от **«harvest now, decrypt later»** атаки: квантовый адверсарий,
//! записывающий V2 wrapped recovery keys сегодня, не сможет расшифровать их
//! даже после появления CRQC (cryptographically relevant quantum computer)
//! — ему пришлось бы сломать оба компонента X-Wing combiner (X25519 ECDH +
//! ML-KEM-768 lattice).
//!
//! ## Purpose
//!
//! Stage 8 block 8.7: adds post-quantum confidentiality of the recovery key
//! through an outer X-Wing layer. The V1 ElGamal scheme is fully preserved
//! inside; the Sealed Servers ceremony is unchanged. The Hybrid PQ layer is
//! entirely client-side.
//!
//! Protects against the **"harvest now, decrypt later"** attack: a quantum
//! adversary recording V2 wrapped recovery keys today cannot decrypt them
//! even after a CRQC appears — they would need to break both components of
//! the X-Wing combiner (X25519 ECDH + ML-KEM-768 lattice).
//!
//! ## Архитектура
//!
//! V2 wrap = X-Wing encryption of V1 81-byte WrappedKey:
//! 1. Classical V1 wrap (standard `wrap_message_key`) → V1 WrappedKey 81 bytes.
//! 2. X-Wing encaps под recipient recovery X-Wing pubkey → (xwing_ct, shared_secret).
//! 3. Derive AEAD key + nonce из shared_secret через HKDF-SHA256.
//! 4. AEAD encrypt V1 WrappedKey bytes → 97-byte aead_payload.
//! 5. Wire format: `0x02 || xwing_ct (1120) || aead_payload (97)` = 1218 bytes.
//!
//! V2 unwrap = инверсия:
//! 1. Parse wire 1218 bytes (version + xwing_ct + aead_payload).
//! 2. X-Wing decaps под own X-Wing seed → shared_secret.
//! 3. Derive AEAD key + nonce.
//! 4. AEAD decrypt aead_payload → V1 WrappedKey bytes (81).
//! 5. WrappedKey::from_bytes → caller инициирует standard 3-of-5 V1 unwrap.
//!
//! ## Quantum threat analysis
//!
//! **Per-share X-Wing wrap of partial points** `k_i · R` (literal interpretation
//! design §10 первой редакции — wrap server-to-client transport partials в
//! X-Wing) **НЕ даёт** PQ confidentiality recovery key. Quantum adversary знает
//! публичный `Y = K · G`, derives `K = dlog(Y, G)` через Shor's algorithm за
//! polynomial time, затем reconstructs `S = K · R` напрямую без участия
//! серверов и расшифровывает V1 aead_blob. Per-share X-Wing защищает только
//! server-to-client transport (что уже под TLS) — PQ uplift косметический.
//!
//! **Hybrid wrapping layer over V1** (выбранное решение) даёт реальную PQ
//! confidentiality recovery key:
//! - Quantum adversary с записанной V2 wire не decapsulates xwing_ct без
//!   X-Wing private key (X-Wing == X25519 ⊕ ML-KEM-768 hybrid; ML-KEM-768
//!   lattice-based, квантово-стойкий).
//! - Без AEAD key (derived из X-Wing shared secret) не decrypts aead_payload.
//! - Quantum dlog over Y = K · G возвращает K, но это даёт только access к
//!   V1 layer; V1 WrappedKey encrypted внутри X-Wing outer payload — outer
//!   layer X-Wing защищает inner V1 wrap.
//!
//! ## Wire format
//!
//! ```text
//! Offset | Size | Field
//! -------+------+-------------------------------------------------
//!     0  |    1 | version = 0x02
//!     1  | 1120 | xwing_ciphertext (X-Wing encaps result;
//!        |      |   X25519 ephemeral pub встроен per draft-connolly-cfrg-xwing-kem-10)
//!  1121  |   97 | aead_payload (AEAD ChaCha20-Poly1305 over V1
//!        |      |   WrappedKey 81 bytes + Poly1305 tag 16 bytes)
//! ```
//!
//! Total V2 wire = **1218 bytes**. Overhead vs V1 = **+1137 bytes** per
//! envelope (1120 X-Wing ct + 16 AEAD tag). Это разумная цена за post-quantum
//! confidentiality (приоритет постулата 4 над 4.5).
//!
//! ## KDF + AEAD
//!
//! HKDF-SHA256 (RFC 5869):
//! - salt = `b"umbrellax-cloud-wrap-v2"`
//! - ikm  = X-Wing shared secret (32 bytes)
//! - info = `V2_DOMAIN_SEP || xwing_ct (1120) || recipient_xwing_pubkey (1216)`
//! - L    = 32 bytes AEAD key + 12 bytes nonce = 44 bytes
//!
//! AEAD = ChaCha20-Poly1305 (RFC 8439).
//!
//! AEAD AAD = `version (1) || canonical_aad_v1 (104) || recipient_xwing_pubkey (1216)`
//! = 1321 bytes — binds envelope к V1 AAD (sender_identity + recipient_device +
//! chat_id + msg_seq) и к recipient X-Wing identity. Tampering любого поля →
//! AEAD decrypt fails.
//!
//! ## Domain separation V1 vs V2
//!
//! V1 HKDF использует salt = `chat_id` + info-prefix `"umbrellax-cloud-wrap-v1"`.
//! V2 HKDF использует salt = `"umbrellax-cloud-wrap-v2"` + info = domain_sep ||
//! xwing_ct || xwing_pubkey. Cross-protocol replay невозможен — даже при
//! identical (chat_id, msg_seq) AEAD keys для V1 и V2 byte-distinct.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce as AeadNonce};
use core::convert::TryInto;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use secrecy::ExposeSecret;
use sha2::Sha256;
use zeroize::Zeroize;

use umbrella_pq::{
    xwing_decaps, xwing_encaps, XWingPublicKey, XWingSecretSeed, XWING_CIPHERTEXT_LEN,
    XWING_PUBLIC_KEY_LEN, XWING_SHARED_SECRET_LEN,
};

use crate::error::BackupError;

use super::params::{AEAD_TAG_LEN, NONCE_LEN, WRAPPED_KEY_LEN};
use super::version::WrappingCiphersuite;
use super::wire::{CanonicalAad, WrappedKey, CANONICAL_AAD_LEN};

/// Domain separator для V2 KDF info, AEAD AAD context, и HKDF salt.
/// ASCII literal; смена ломает совместимость, требует ADR-amendment.
///
/// Domain separator for V2 KDF info, AEAD AAD context, and HKDF salt.
pub const V2_DOMAIN_SEP: &[u8] = b"umbrellax-cloud-wrap-v2";

/// HKDF salt для V2 KDF (same string as `V2_DOMAIN_SEP`).
/// HKDF salt for V2 KDF (same string as `V2_DOMAIN_SEP`).
pub const V2_HKDF_SALT: &[u8] = V2_DOMAIN_SEP;

/// V2 AEAD key length (32 bytes для ChaCha20-Poly1305).
/// V2 AEAD key length (32 bytes for ChaCha20-Poly1305).
pub const V2_AEAD_KEY_LEN: usize = 32;

/// Длина version-байта в V2 wire format (1).
/// V2 wire-format version-byte length (1).
pub const V2_VERSION_LEN: usize = 1;

/// Длина aead_payload V2: V1 WrappedKey (81) + Poly1305 tag (16) = 97 bytes.
/// V2 aead_payload length: V1 WrappedKey (81) + Poly1305 tag (16) = 97 bytes.
pub const WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN: usize = WRAPPED_KEY_LEN + AEAD_TAG_LEN;

/// Длина V2 wire-format: version (1) + xwing_ct (1120) + aead_payload (97) = 1218 bytes.
/// V2 wire-format length: version (1) + xwing_ct (1120) + aead_payload (97) = 1218 bytes.
pub const WRAPPED_KEY_V2_LEN: usize =
    V2_VERSION_LEN + XWING_CIPHERTEXT_LEN + WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN;

/// Wrapped recovery key V2: X-Wing envelope над V1 WrappedKey (Hybrid PQ wrap).
///
/// Wrapped recovery key V2: X-Wing envelope over V1 WrappedKey (Hybrid PQ wrap).
///
/// Layout (1218 bytes):
/// ```text
/// [0..1)        version           : u8 = 0x02
/// [1..1121)     xwing_ciphertext  : 1120 bytes (X-Wing encaps result)
/// [1121..1218)  aead_payload      : 97 bytes (AEAD ChaCha20-Poly1305 over
///                                              V1 WrappedKey 81 + tag 16)
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedKeyV2 {
    /// X-Wing ciphertext (1120 bytes; sender ephemeral X25519 pub встроен per
    /// draft-connolly-cfrg-xwing-kem-10).
    /// X-Wing ciphertext (1120 bytes; sender ephemeral X25519 pub embedded per
    /// draft-connolly-cfrg-xwing-kem-10).
    pub xwing_ciphertext: [u8; XWING_CIPHERTEXT_LEN],

    /// AEAD payload = ChaCha20-Poly1305(V1 WrappedKey 81 bytes) + Poly1305 tag (16 bytes).
    /// AEAD payload = ChaCha20-Poly1305(V1 WrappedKey 81 bytes) + Poly1305 tag (16 bytes).
    pub aead_payload: [u8; WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN],
}

/// `Debug` скрывает V2 envelope bytes: журналы не должны хранить wrapped-key материал.
/// `Debug` redacts V2 envelope bytes: logs must not retain wrapped-key material.
impl core::fmt::Debug for WrappedKeyV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedKeyV2")
            .field("xwing_ciphertext_len", &self.xwing_ciphertext.len())
            .field("xwing_ciphertext", &"<redacted>")
            .field("aead_payload_len", &self.aead_payload.len())
            .field("aead_payload", &"<redacted>")
            .finish()
    }
}

impl WrappedKeyV2 {
    /// Сериализация в фиксированный 1218-byte буфер.
    /// Serialization into a fixed 1218-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; WRAPPED_KEY_V2_LEN] {
        let mut out = [0u8; WRAPPED_KEY_V2_LEN];
        out[0] = WrappingCiphersuite::V2HybridXWing.as_u8();
        out[V2_VERSION_LEN..V2_VERSION_LEN + XWING_CIPHERTEXT_LEN]
            .copy_from_slice(&self.xwing_ciphertext);
        out[V2_VERSION_LEN + XWING_CIPHERTEXT_LEN..].copy_from_slice(&self.aead_payload);
        out
    }

    /// Парсинг 1218 bytes V2 wire с валидацией версии и длины.
    ///
    /// Order проверок: empty → version → length → parse. Diagnostic-friendly:
    /// V1 wrapped key (81 bytes < V2_LEN) переданный в `from_bytes` сразу
    /// получает `UnsupportedWrappingCiphersuite { got: 0x01 }` (clear: «это V1,
    /// перенаправь в `WrappedKey::from_bytes`»), не misleading «truncated».
    /// Постулат 14: errors индицируют root cause, не симптом.
    ///
    /// Parses 1218 bytes of V2 wire with version and length validation.
    ///
    /// Check order: empty → version → length → parse. Diagnostic-friendly: a V1
    /// wrapped key (81 bytes < V2_LEN) passed into `from_bytes` immediately
    /// yields `UnsupportedWrappingCiphersuite { got: 0x01 }` (clear: "this is V1,
    /// redirect to `WrappedKey::from_bytes`"), not a misleading "truncated".
    ///
    /// # Errors
    /// - [`BackupError::WrappedKeyV2Truncated`] если `data.len() == 0` либо
    ///   `data.len() != WRAPPED_KEY_V2_LEN`.
    /// - [`BackupError::UnsupportedWrappingCiphersuite`] если первый byte != 0x02.
    /// - [`BackupError::PqFeatureRequiredForCiphersuite`] если первый byte = 0x02
    ///   при сборке без feature `pq` (в feature pq build не возникает).
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        if data.is_empty() {
            return Err(BackupError::WrappedKeyV2Truncated);
        }
        // Version byte check first для diagnostic-friendly errors.
        // Version byte check first for diagnostic-friendly errors.
        let cs = WrappingCiphersuite::try_from(data[0])?;
        if cs != WrappingCiphersuite::V2HybridXWing {
            return Err(BackupError::UnsupportedWrappingCiphersuite { got: data[0] });
        }
        if data.len() != WRAPPED_KEY_V2_LEN {
            return Err(BackupError::WrappedKeyV2Truncated);
        }
        let xwing_ciphertext: [u8; XWING_CIPHERTEXT_LEN] = data
            [V2_VERSION_LEN..V2_VERSION_LEN + XWING_CIPHERTEXT_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let aead_payload: [u8; WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN] = data
            [V2_VERSION_LEN + XWING_CIPHERTEXT_LEN..]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        Ok(Self {
            xwing_ciphertext,
            aead_payload,
        })
    }
}

/// Запечатывает V1 WrappedKey в V2 X-Wing envelope для PQ confidentiality.
///
/// Параметры:
/// - `recipient_xwing_pubkey` — recovery X-Wing public key получателя
///   (получен из `KeyStore::cloud_wrap_recovery_public()` либо derive
///   через `CloudWrapRecoveryKey::derive`).
/// - `v1_wrapped_key` — already-computed V1 81-byte wrapped key (через
///   `wrap_message_key`).
/// - `aad` — same canonical AAD что использовалась для V1 wrap (binds V2
///   envelope к V1 sender/recipient/chat/seq context).
/// - `rng` — CSPRNG для X-Wing encaps (sender ephemeral X25519 + ML-KEM
///   randomness).
///
/// Возвращает [`WrappedKeyV2`] (1218 bytes wire).
///
/// Seals a V1 WrappedKey into a V2 X-Wing envelope for PQ confidentiality.
///
/// Parameters:
/// - `recipient_xwing_pubkey` — recipient's recovery X-Wing public key
///   (obtained via `KeyStore::cloud_wrap_recovery_public()` or derived via
///   `CloudWrapRecoveryKey::derive`).
/// - `v1_wrapped_key` — already-computed V1 81-byte wrapped key (via
///   `wrap_message_key`).
/// - `aad` — same canonical AAD that was used for the V1 wrap (binds the V2
///   envelope to the V1 sender/recipient/chat/seq context).
/// - `rng` — CSPRNG for X-Wing encaps (sender ephemeral X25519 + ML-KEM
///   randomness).
///
/// Returns [`WrappedKeyV2`] (1218 bytes wire).
///
/// # Errors
/// - [`BackupError::XWingEncapsFailed`] если X-Wing backend отвергает recipient
///   pubkey или RNG fail (не должно возникать с валидным pubkey + working RNG).
/// - [`BackupError::InvalidWireFormat`] для unexpected AEAD blob length (defensive).
pub fn wrap_v1_into_v2<R>(
    recipient_xwing_pubkey: &XWingPublicKey,
    v1_wrapped_key: &WrappedKey,
    aad: &CanonicalAad,
    rng: &mut R,
) -> Result<WrappedKeyV2, BackupError>
where
    R: RngCore + CryptoRng,
{
    // 1. X-Wing encaps под recipient recovery X-Wing pubkey.
    // 1. X-Wing encaps under recipient's recovery X-Wing pubkey.
    let (xwing_ct, shared_secret) =
        xwing_encaps(rng, recipient_xwing_pubkey).map_err(|_| BackupError::XWingEncapsFailed)?;

    // 2. Derive AEAD key + nonce из shared_secret через HKDF-SHA256.
    // 2. Derive AEAD key + nonce from shared_secret via HKDF-SHA256.
    let (mut aead_key_bytes, aead_nonce_bytes) = derive_v2_aead_key_nonce(
        shared_secret.expose_secret(),
        &xwing_ct,
        recipient_xwing_pubkey,
    );

    // 3. Compose AEAD AAD = version || canonical_aad_v1 || recipient_xwing_pubkey.
    // 3. Compose AEAD AAD = version || canonical_aad_v1 || recipient_xwing_pubkey.
    let aad_bytes = compose_v2_aead_aad(aad, recipient_xwing_pubkey);

    // 4. AEAD encrypt V1 WrappedKey bytes (81) → ciphertext + tag (97 bytes).
    // 4. AEAD encrypt V1 WrappedKey bytes (81) → ciphertext + tag (97 bytes).
    let v1_bytes = v1_wrapped_key.to_bytes();
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&aead_key_bytes));
    let nonce = AeadNonce::from_slice(&aead_nonce_bytes);
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: ChaCha20-Poly1305 encrypt cannot fail for fixed-size input < 2^32"
    )]
    let blob = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &v1_bytes,
                aad: &aad_bytes,
            },
        )
        .expect("ChaCha20-Poly1305 encrypt never fails for fixed-size input");

    // Zeroize derived AEAD key bytes after use (postulate 14: senior+ memory hygiene).
    // Zeroize derived AEAD key bytes after use (postulate 14).
    aead_key_bytes.zeroize();

    if blob.len() != WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN {
        // Defensive — ChaCha20-Poly1305 для fixed input всегда даёт known-size output.
        // Defensive — ChaCha20-Poly1305 for fixed input always yields known-size output.
        return Err(BackupError::InvalidWireFormat);
    }
    let mut aead_payload = [0u8; WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN];
    aead_payload.copy_from_slice(&blob);

    Ok(WrappedKeyV2 {
        xwing_ciphertext: xwing_ct,
        aead_payload,
    })
}

/// Раскрывает V2 envelope и возвращает inner V1 WrappedKey.
///
/// V1 WrappedKey затем подаётся в обычный 3-of-5 unwrap flow
/// (`unwrap_message_key`) через Sealed Servers — V2 layer лежит **над** V1,
/// V1 ceremony unchanged.
///
/// Параметры:
/// - `own_xwing_seed` — собственный X-Wing recovery secret seed (32 bytes
///   wrapped в `XWingSecretSeed`). Получен через
///   `KeyStore::cloud_wrap_recovery_decapsulate` либо `CloudWrapRecoveryKey::secret`.
/// - `own_xwing_pubkey` — собственный X-Wing recovery public key (1216 bytes);
///   используется в AEAD AAD и KDF info — должен совпадать с тем, что использовал
///   sender при wrap.
/// - `wire` — `WrappedKeyV2` envelope (parsed через `from_bytes`).
/// - `aad` — same canonical AAD что использовалась при wrap.
///
/// Возвращает inner V1 [`WrappedKey`] (81 bytes), который затем разворачивается
/// через 3-of-5 sealed servers cooperation.
///
/// Unseals a V2 envelope and returns the inner V1 WrappedKey.
///
/// # Errors
/// - [`BackupError::XWingDecapsFailed`] — X-Wing decaps backend fail или
///   implicit rejection (corrupted ct, mismatched sk/pk).
/// - [`BackupError::AeadDecryptFailed`] — AEAD decrypt fail (tampered payload,
///   wrong AAD, wrong derived key).
/// - [`BackupError::WrappedKeyTruncated`] / [`BackupError::WrappedKeyVersionMismatch`]
///   — inner V1 wrapped key invalid (defensive — wrap_v1_into_v2 всегда даёт
///   valid wrapping).
pub fn unwrap_v2_to_v1(
    own_xwing_seed: &XWingSecretSeed,
    own_xwing_pubkey: &XWingPublicKey,
    wire: &WrappedKeyV2,
    aad: &CanonicalAad,
) -> Result<WrappedKey, BackupError> {
    // 1. X-Wing decaps под own seed → shared_secret.
    // 1. X-Wing decaps under own seed → shared_secret.
    let shared_secret = xwing_decaps(own_xwing_seed, &wire.xwing_ciphertext)
        .map_err(|_| BackupError::XWingDecapsFailed)?;

    // 2. Derive AEAD key + nonce.
    // 2. Derive AEAD key + nonce.
    let (mut aead_key_bytes, aead_nonce_bytes) = derive_v2_aead_key_nonce(
        shared_secret.expose_secret(),
        &wire.xwing_ciphertext,
        own_xwing_pubkey,
    );

    // 3. AEAD AAD.
    // 3. AEAD AAD.
    let aad_bytes = compose_v2_aead_aad(aad, own_xwing_pubkey);

    // 4. AEAD decrypt aead_payload → V1 WrappedKey bytes (81).
    // 4. AEAD decrypt aead_payload → V1 WrappedKey bytes (81).
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&aead_key_bytes));
    let nonce = AeadNonce::from_slice(&aead_nonce_bytes);
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &wire.aead_payload,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| BackupError::AeadDecryptFailed)?;

    // Zeroize derived AEAD key.
    // Zeroize derived AEAD key.
    aead_key_bytes.zeroize();

    if plain.len() != WRAPPED_KEY_LEN {
        // Defensive — V1 wrapped key — fixed 81 bytes; AEAD plaintext должен быть exactly that.
        // Defensive — V1 wrapped key is fixed 81 bytes; AEAD plaintext must be exactly that.
        return Err(BackupError::AeadDecryptFailed);
    }

    // 5. Parse inner V1 WrappedKey (validates version + length).
    // 5. Parse inner V1 WrappedKey (validates version + length).
    WrappedKey::from_bytes(&plain)
}

/// HKDF-SHA256 derive 32-byte AEAD key + 12-byte AEAD nonce из X-Wing shared secret.
///
/// `info` контекст: `V2_DOMAIN_SEP || xwing_ct || recipient_xwing_pubkey` —
/// domain separation от V1 KDF (V1 использует salt=chat_id +
/// info=`umbrellax-cloud-wrap-v1` || ...).
///
/// Derive a 32-byte AEAD key + 12-byte AEAD nonce from the X-Wing shared secret
/// via HKDF-SHA256.
fn derive_v2_aead_key_nonce(
    shared_secret: &[u8; XWING_SHARED_SECRET_LEN],
    xwing_ct: &[u8; XWING_CIPHERTEXT_LEN],
    recipient_xwing_pubkey: &XWingPublicKey,
) -> ([u8; V2_AEAD_KEY_LEN], [u8; NONCE_LEN]) {
    // info = V2_DOMAIN_SEP || xwing_ct || recipient_xwing_pubkey.
    // info = V2_DOMAIN_SEP || xwing_ct || recipient_xwing_pubkey.
    let mut info =
        Vec::with_capacity(V2_DOMAIN_SEP.len() + XWING_CIPHERTEXT_LEN + XWING_PUBLIC_KEY_LEN);
    info.extend_from_slice(V2_DOMAIN_SEP);
    info.extend_from_slice(xwing_ct);
    info.extend_from_slice(recipient_xwing_pubkey.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(V2_HKDF_SALT), shared_secret);
    let mut okm = [0u8; V2_AEAD_KEY_LEN + NONCE_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF-SHA256 44-byte expansion always fits per RFC 5869"
    )]
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 44-byte expansion always fits");

    let mut aead_key = [0u8; V2_AEAD_KEY_LEN];
    aead_key.copy_from_slice(&okm[..V2_AEAD_KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&okm[V2_AEAD_KEY_LEN..]);

    okm.zeroize();

    (aead_key, nonce)
}

/// Compose V2 AEAD AAD = `version (1) || canonical_aad_v1 (104) || recipient_xwing_pubkey (1216)`.
///
/// Total = 1321 bytes. Tampering любого поля (включая sender_identity, chat_id,
/// msg_seq, recipient pubkey) → AEAD decrypt fails.
///
/// Compose V2 AEAD AAD = `version (1) || canonical_aad_v1 (104) ||
/// recipient_xwing_pubkey (1216)`. Total = 1321 bytes. Tampering any field
/// (including sender_identity, chat_id, msg_seq, recipient pubkey) → AEAD
/// decrypt fails.
fn compose_v2_aead_aad(aad: &CanonicalAad, recipient_xwing_pubkey: &XWingPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(V2_VERSION_LEN + CANONICAL_AAD_LEN + XWING_PUBLIC_KEY_LEN);
    out.push(WrappingCiphersuite::V2HybridXWing.as_u8());
    out.extend_from_slice(&aad.canonical_bytes());
    out.extend_from_slice(recipient_xwing_pubkey.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    use crate::cloud_wrap::params::{
        ThresholdConfig, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION,
    };
    use crate::cloud_wrap::wire::ED25519_PUB_LEN;
    use crate::cloud_wrap::wrap::wrap_message_key;
    use crate::cloud_wrap::WrappingParams;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use umbrella_pq::xwing_keygen;

    fn sample_aad() -> CanonicalAad {
        CanonicalAad {
            sender_identity_pubkey: [0xAA; ED25519_PUB_LEN],
            recipient_device_pubkey: [0xBB; ED25519_PUB_LEN],
            chat_id: [0xCC; 32],
            msg_seq: 13,
        }
    }

    fn sample_v1_params(k: Scalar) -> WrappingParams {
        let y = RISTRETTO_BASEPOINT_POINT * k;
        WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; 5],
            config: ThresholdConfig::default(),
        }
    }

    fn fresh_xwing_keypair() -> (XWingPublicKey, XWingSecretSeed) {
        let mut rng = OsRng;
        xwing_keygen(&mut rng).unwrap()
    }

    /// Constants ровно совпадают с layout V2 wire format.
    /// Constants exactly match the V2 wire format layout.
    #[test]
    fn v2_constants_match_layout() {
        assert_eq!(V2_VERSION_LEN, 1);
        assert_eq!(WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN, 81 + 16);
        assert_eq!(WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN, 97);
        assert_eq!(WRAPPED_KEY_V2_LEN, 1 + 1120 + 97);
        assert_eq!(WRAPPED_KEY_V2_LEN, 1218);
        assert_eq!(V2_AEAD_KEY_LEN, 32);
        assert_eq!(V2_DOMAIN_SEP, b"umbrellax-cloud-wrap-v2");
        assert_eq!(V2_HKDF_SALT, V2_DOMAIN_SEP);
    }

    /// Базовый roundtrip: wrap V1 → wrap V2 → unwrap V2 → unwrap V1 → message_key.
    /// Basic roundtrip: wrap V1 → wrap V2 → unwrap V2 → unwrap V1 → message_key.
    #[test]
    fn wrap_v2_unwrap_v2_roundtrip_preserves_v1() {
        let mut rng = OsRng;
        let k = Scalar::from(7u64);
        let v1_params = sample_v1_params(k);
        let mk = [0xAB; MESSAGE_KEY_LEN];
        let aad = sample_aad();

        // V1 wrap.
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();

        // V2 wrap layer.
        let (recipient_xwing_pk, recipient_xwing_sk) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&recipient_xwing_pk, &v1_wrapped, &aad, &mut rng).unwrap();

        // V2 unwrap layer (recipient).
        let v1_recovered =
            unwrap_v2_to_v1(&recipient_xwing_sk, &recipient_xwing_pk, &v2_wrapped, &aad).unwrap();

        // V1 layer должна быть byte-identical.
        // V1 layer must be byte-identical.
        assert_eq!(v1_recovered.to_bytes(), v1_wrapped.to_bytes());
    }

    /// Wire format: первый байт — version stamp 0x02.
    /// Wire format: first byte — version stamp 0x02.
    #[test]
    fn v2_wire_first_byte_is_version_stamp() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let bytes = v2_wrapped.to_bytes();
        assert_eq!(bytes[0], 0x02);
        assert_eq!(bytes[0], WrappingCiphersuite::V2HybridXWing.as_u8());
        assert_eq!(bytes.len(), WRAPPED_KEY_V2_LEN);
    }

    /// Wire format: bytes 1..1121 — это xwing_ct.
    /// Wire format: bytes 1..1121 — xwing_ct.
    #[test]
    fn v2_wire_xwing_ct_offset() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let bytes = v2_wrapped.to_bytes();
        assert_eq!(
            &bytes[1..1 + XWING_CIPHERTEXT_LEN],
            &v2_wrapped.xwing_ciphertext[..]
        );
    }

    /// Roundtrip serialize → deserialize даёт identical V2.
    /// Roundtrip serialize → deserialize yields identical V2.
    #[test]
    fn v2_byte_roundtrip() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0xAB; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let bytes = v2_wrapped.to_bytes();
        let parsed = WrappedKeyV2::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, v2_wrapped);
    }

    #[test]
    fn v2_debug_redacts_wrapped_key_material() {
        let wrapped = WrappedKeyV2 {
            xwing_ciphertext: [0xAA; XWING_CIPHERTEXT_LEN],
            aead_payload: [0xBB; WRAPPED_KEY_V2_AEAD_PAYLOAD_LEN],
        };

        let debug = format!("{wrapped:?}");

        assert!(
            !debug.contains("170, 170, 170, 170"),
            "Debug output must not leak X-Wing ciphertext bytes: {debug}"
        );
        assert!(
            !debug.contains("187, 187, 187, 187"),
            "Debug output must not leak V2 AEAD payload bytes: {debug}"
        );
        assert!(debug.contains("xwing_ciphertext_len"));
    }

    /// `from_bytes` отвергает empty input.
    /// `from_bytes` rejects empty input.
    #[test]
    fn v2_from_bytes_rejects_empty() {
        let err = WrappedKeyV2::from_bytes(&[]).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyV2Truncated));
    }

    /// `from_bytes` отвергает V1 wrapped key (81 bytes) — V2 ожидает 0x02 как version.
    /// `from_bytes` rejects a V1 wrapped key (81 bytes) — V2 expects 0x02 as version.
    #[test]
    fn v2_from_bytes_rejects_v1_byte() {
        let v1_like = vec![0x01u8; WRAPPED_KEY_LEN]; // V1 length, V1 version byte
        let err = WrappedKeyV2::from_bytes(&v1_like).unwrap_err();
        assert!(matches!(
            err,
            BackupError::UnsupportedWrappingCiphersuite { got: 0x01 }
        ));
    }

    /// `from_bytes` отвергает unknown version byte.
    /// `from_bytes` rejects an unknown version byte.
    #[test]
    fn v2_from_bytes_rejects_unknown_version() {
        let mut buf = vec![0u8; WRAPPED_KEY_V2_LEN];
        buf[0] = 0xAB;
        let err = WrappedKeyV2::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BackupError::UnsupportedWrappingCiphersuite { got: 0xAB }
        ));
    }

    /// `from_bytes` отвергает V2 byte с длиной != WRAPPED_KEY_V2_LEN.
    /// `from_bytes` rejects V2 byte with length != WRAPPED_KEY_V2_LEN.
    #[test]
    fn v2_from_bytes_rejects_truncated() {
        let mut buf = vec![0u8; WRAPPED_KEY_V2_LEN - 1];
        buf[0] = 0x02;
        let err = WrappedKeyV2::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyV2Truncated));
    }

    /// `from_bytes` отвергает V2 byte с лишними байтами.
    /// `from_bytes` rejects V2 byte with extra bytes.
    #[test]
    fn v2_from_bytes_rejects_too_long() {
        let mut buf = vec![0u8; WRAPPED_KEY_V2_LEN + 1];
        buf[0] = 0x02;
        let err = WrappedKeyV2::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyV2Truncated));
    }

    /// Tampered xwing_ct: AEAD AAD tied к ct → decrypt fails (или decaps fails).
    /// Tampered xwing_ct: AEAD AAD tied to ct → decrypt fails (or decaps fails).
    #[test]
    fn v2_unwrap_rejects_tampered_xwing_ct() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, sk) = fresh_xwing_keypair();
        let mut v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();
        v2_wrapped.xwing_ciphertext[0] ^= 0x01;

        let result = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad);
        assert!(
            result.is_err(),
            "tampered xwing_ct must be rejected (AEAD AAD or decaps)"
        );
    }

    /// Tampered aead_payload: Poly1305 tag rejects.
    /// Tampered aead_payload: Poly1305 tag rejects.
    #[test]
    fn v2_unwrap_rejects_tampered_aead_payload() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, sk) = fresh_xwing_keypair();
        let mut v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();
        // Подменяем последний байт aead_payload (внутри Poly1305 tag).
        // Tamper the last byte of aead_payload (within the Poly1305 tag).
        let last = v2_wrapped.aead_payload.len() - 1;
        v2_wrapped.aead_payload[last] ^= 0x01;

        let result = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad);
        assert!(matches!(result, Err(BackupError::AeadDecryptFailed)));
    }

    /// Tampered aead_payload первый byte (внутри ciphertext): AEAD tag fails.
    /// Tampered aead_payload first byte (within ciphertext): AEAD tag fails.
    #[test]
    fn v2_unwrap_rejects_tampered_aead_ciphertext_first_byte() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, sk) = fresh_xwing_keypair();
        let mut v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();
        v2_wrapped.aead_payload[0] ^= 0x01;

        let result = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad);
        assert!(matches!(result, Err(BackupError::AeadDecryptFailed)));
    }

    /// Wrong recipient secret: AEAD decrypt fails (различный shared_secret →
    /// различный AEAD key, либо decaps fails первым).
    ///
    /// Wrong recipient secret: AEAD decrypt fails (different shared_secret →
    /// different AEAD key, or decaps fails first).
    #[test]
    fn v2_unwrap_rejects_wrong_seed() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _correct_sk) = fresh_xwing_keypair();
        let (_, wrong_sk) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let result = unwrap_v2_to_v1(&wrong_sk, &pk, &v2_wrapped, &aad);
        assert!(result.is_err(), "wrong seed must fail unwrap");
    }

    /// AAD pubkey mismatch: caller передал чужой xwing_pubkey в unwrap →
    /// derived AEAD key OR AAD не совпадает → decrypt fails.
    ///
    /// AAD pubkey mismatch: caller passed a different xwing_pubkey to unwrap →
    /// derived AEAD key OR AAD doesn't match → decrypt fails.
    #[test]
    fn v2_unwrap_rejects_aad_pubkey_mismatch() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (correct_pk, sk) = fresh_xwing_keypair();
        let (other_pk, _) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&correct_pk, &v1_wrapped, &aad, &mut rng).unwrap();

        // shared_secret derives correctly через sk; но AAD/info используют other_pk → mismatch.
        // shared_secret derives correctly via sk; but AAD/info use other_pk → mismatch.
        let result = unwrap_v2_to_v1(&sk, &other_pk, &v2_wrapped, &aad);
        assert!(result.is_err(), "aad pubkey mismatch must fail");
    }

    /// AAD canonical mismatch: tampered chat_id в AAD при unwrap → decrypt fails.
    /// AAD canonical mismatch: tampered chat_id in AAD on unwrap → decrypt fails.
    #[test]
    fn v2_unwrap_rejects_tampered_canonical_aad() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, sk) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let mut tampered_aad = aad.clone();
        tampered_aad.chat_id[0] ^= 0x01;

        let result = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &tampered_aad);
        assert!(matches!(result, Err(BackupError::AeadDecryptFailed)));
    }

    /// Same V1 wrapped + same recipient pubkey → разные V2 wires (X-Wing encaps random).
    /// Same V1 wrapped + same recipient pubkey → different V2 wires (X-Wing encaps random).
    #[test]
    fn v2_wrap_produces_distinct_envelopes_per_call() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = fresh_xwing_keypair();
        let w1 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();
        let w2 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        assert_ne!(
            w1.xwing_ciphertext, w2.xwing_ciphertext,
            "X-Wing encaps random — каждый envelope unique"
        );
    }

    /// Layout: bytes 1121..1218 — это aead_payload.
    /// Layout: bytes 1121..1218 — aead_payload.
    #[test]
    fn v2_wire_aead_payload_offset() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0u8; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let bytes = v2_wrapped.to_bytes();
        let payload_offset = V2_VERSION_LEN + XWING_CIPHERTEXT_LEN;
        assert_eq!(payload_offset, 1121);
        assert_eq!(&bytes[payload_offset..], &v2_wrapped.aead_payload[..]);
    }

    /// V2 wire-overhead vs V1: ровно +1137 bytes (1120 X-Wing ct + 16 AEAD tag).
    /// V2 wire-overhead vs V1: exactly +1137 bytes (1120 X-Wing ct + 16 AEAD tag).
    #[test]
    fn v2_wire_overhead_constant() {
        let v2_overhead = WRAPPED_KEY_V2_LEN - WRAPPED_KEY_LEN;
        assert_eq!(v2_overhead, 1 + XWING_CIPHERTEXT_LEN + AEAD_TAG_LEN);
        assert_eq!(v2_overhead, 1 + 1120 + 16);
        assert_eq!(v2_overhead, 1137);
    }

    /// V1 wrapped key байты внутри V2 envelope правильно validates: byte 0 = 0x01
    /// (version) после AEAD decrypt.
    ///
    /// V1 wrapped key bytes inside V2 envelope correctly validate: byte 0 = 0x01
    /// (version) after AEAD decrypt.
    #[test]
    fn v2_decrypted_inner_starts_with_v1_version() {
        let mut rng = OsRng;
        let k = Scalar::from(1u64);
        let v1_params = sample_v1_params(k);
        let mk = [0xCD; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, sk) = fresh_xwing_keypair();
        let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &mut rng).unwrap();

        let v1_recovered = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad).unwrap();
        assert_eq!(v1_recovered.version, PROTOCOL_VERSION);
        assert_eq!(v1_recovered.version, 0x01);
    }

    /// Domain separation V1 vs V2: V1 AEAD key bytes ≠ V2 AEAD key bytes (даже
    /// при identical inputs где это теоретически possible). Косвенная проверка
    /// через demonstration что V2 envelope для same V1 wrapping не decrypts
    /// под V1 path (через V1 unwrap function — это уже cover'ит integration test).
    /// Здесь — direct check: HKDF outputs distinct.
    ///
    /// Domain separation V1 vs V2: V1 AEAD key bytes ≠ V2 AEAD key bytes.
    /// Direct check: HKDF outputs distinct.
    #[test]
    fn v2_kdf_distinct_from_v1_pattern() {
        let shared = [0xFE; XWING_SHARED_SECRET_LEN];
        let ct = [0u8; XWING_CIPHERTEXT_LEN];
        let (pk, _) = fresh_xwing_keypair();
        let (v2_key, _v2_nonce) = derive_v2_aead_key_nonce(&shared, &ct, &pk);

        // Imitate V1 KDF в general shape: HKDF-SHA512 с salt=chat_id +
        // info=`umbrellax-cloud-wrap-v1`. Точной replicate не делаем (V1 KDF
        // не использует X-Wing inputs); важна distinctness output bytes.
        // Imitate V1 KDF in general shape: HKDF-SHA512 with salt=chat_id +
        // info=`umbrellax-cloud-wrap-v1`. Important: output bytes distinct.
        use hkdf::Hkdf;
        use sha2::Sha512;
        let chat_id = [0xCC; 32];
        let v1_hk = Hkdf::<Sha512>::new(Some(&chat_id), &shared);
        let mut v1_okm = [0u8; 32];
        v1_hk
            .expand(b"umbrellax-cloud-wrap-v1", &mut v1_okm)
            .unwrap();

        assert_ne!(
            v2_key, v1_okm,
            "V1 and V2 KDF outputs must be byte-distinct (domain separation)"
        );
    }
}
