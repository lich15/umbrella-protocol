//! UmbrellaXWingProvider — кастомный `OpenMlsCrypto` provider для активации
//! ciphersuite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (IANA 0x004D)
//! поверх `libcrux-kem 0.0.8` X-Wing API, проверенного официальным draft-10 KAT.
//!
//! UmbrellaXWingProvider — custom `OpenMlsCrypto` provider that activates the
//! `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` ciphersuite (IANA 0x004D)
//! atop the `libcrux-kem 0.0.8` X-Wing API, checked against the official draft-10 KAT.
//!
//! ## Архитектура
//!
//! Провайдер оборачивает `OpenMlsRustCrypto` (default openmls provider) и
//! делегирует все не-X-Wing операции в него (HKDF, AEAD, hash, signature,
//! HPKE для DhKem25519/DhKem448 и т.д.). Для X-Wing branch
//! (`HpkeKemType::XWingKemDraft6 == 0x004D`) реализуется HPKE base mode
//! RFC 9180 §5.1 поверх:
//!
//! - **KEM**: X-Wing draft-connolly-cfrg-xwing-kem-10 через
//!   `umbrella_pq::xwing_*`. X-Wing combiner внутри SHA3-256-derive shared
//!   secret из ML-KEM-768 shared + X25519 shared, гарантируя что compromise
//!   одного компонента не ломает joint security.
//! - **KDF**: HKDF-SHA256 (RFC 5869) с RFC 9180 LabeledExtract/LabeledExpand.
//! - **AEAD**: ChaCha20-Poly1305 (RFC 8439).
//!
//! ## Architecture
//!
//! The provider wraps `OpenMlsRustCrypto` (default openmls provider) and
//! delegates every non-X-Wing operation to it (HKDF, AEAD, hash, signature,
//! HPKE for DhKem25519/DhKem448, etc.). For the X-Wing branch
//! (`HpkeKemType::XWingKemDraft6 == 0x004D`) it implements HPKE base mode
//! RFC 9180 §5.1 over:
//!
//! - **KEM**: X-Wing draft-connolly-cfrg-xwing-kem-10 via `umbrella_pq::xwing_*`.
//!   The X-Wing combiner derives the shared secret with SHA3-256 from
//!   ML-KEM-768 shared || X25519 shared, ensuring that compromise of one
//!   component does not break joint security.
//! - **KDF**: HKDF-SHA256 (RFC 5869) with RFC 9180 LabeledExtract/LabeledExpand.
//! - **AEAD**: ChaCha20-Poly1305 (RFC 8439).
//!
//! ## Suite IDs (RFC 9180 §4)
//!
//! - KEM-context (DeriveKeyPair / KEM-уровневые операции):
//!   `"KEM" || I2OSP(0x004D, 2)` = `b"KEM\x00\x4D"`.
//! - HPKE-context (KeySchedule / Seal / Open / Export):
//!   `"HPKE" || I2OSP(0x004D, 2) || I2OSP(0x0001, 2) || I2OSP(0x0003, 2)` =
//!   `b"HPKE\x00\x4D\x00\x01\x00\x03"`.
//!
//! ## OpenMlsProvider композиция
//!
//! - `CryptoProvider = Self` — Self impl `OpenMlsCrypto` с X-Wing branch.
//! - `RandProvider = openmls_rust_crypto::RustCrypto` — делегируется в
//!   `inner.rand()`.
//! - `StorageProvider = openmls_rust_crypto::MemoryStorage` — делегируется в
//!   `inner.storage()`.
//!
//! ## Forward compat
//!
//! Когда openmls 0.9+ или openmls_rust_crypto 0.6+ добавит native X-Wing
//! impl, этот модуль удаляется целиком, и downstream code (использующий
//! `&impl OpenMlsProvider`) не меняется.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKemType, HpkeKeyPair, HpkePrivateKey, KemOutput, SignatureScheme,
    },
    OpenMlsProvider,
};
use rand_core::OsRng;
use secrecy::ExposeSecret;
use sha2::Sha256;
use tls_codec::SecretVLBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use umbrella_pq::{
    xwing_decaps_raw, xwing_encaps_hedged, xwing_keygen_from_seed, HedgedWitness, XWingPublicKey,
    XWING_CIPHERTEXT_LEN, XWING_KEYGEN_SEED_LEN, XWING_PUBLIC_KEY_LEN,
};

// ============================================================================
// HPKE wire-format constants (RFC 9180 §4 + §5.1)
// ============================================================================

/// HPKE wire-format version label (RFC 9180 §4).
const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// HPKE base mode (RFC 9180 §5.1 mode_base = 0).
const HPKE_MODE_BASE: u8 = 0x00;

/// KEM-suite-id для DeriveKeyPair и других KEM-уровневых операций
/// (RFC 9180 §4): `"KEM" || I2OSP(0x004D, 2)`.
/// KEM-suite-id for DeriveKeyPair and other KEM-level operations
/// (RFC 9180 §4): `"KEM" || I2OSP(0x004D, 2)`.
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x4D";

/// HPKE full suite id для KeySchedule / Seal / Open / Export
/// (X-Wing + HKDF-SHA256 + ChaCha20-Poly1305):
/// `"HPKE" || I2OSP(0x004D, 2) || I2OSP(0x0001, 2) || I2OSP(0x0003, 2)`.
/// HPKE full suite id for KeySchedule / Seal / Open / Export
/// (X-Wing + HKDF-SHA256 + ChaCha20-Poly1305):
/// `"HPKE" || I2OSP(0x004D, 2) || I2OSP(0x0001, 2) || I2OSP(0x0003, 2)`.
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x4D\x00\x01\x00\x03";

/// AEAD ChaCha20-Poly1305 key length (Nk).
const NK: usize = 32;
/// AEAD ChaCha20-Poly1305 nonce length (Nn).
const NN: usize = 12;
/// HKDF-SHA256 hash output length (Nh).
const NH: usize = 32;

// ============================================================================
// HPKE labeled KDF helpers (RFC 9180 §4)
// ============================================================================

/// `LabeledExtract(salt, label, ikm)` — RFC 9180 §4.
/// `labeled_ikm = "HPKE-v1" || suite_id || label || ikm`.
///
/// F-63 closure (block 10.8-active-retro): `labeled_ikm` Vec может содержать
/// секретный IKM (например, пользовательский HPKE setup IKM, из которого
/// деривируется приватный ключ через DeriveKeyPair) → `.zeroize()` перед
/// return. Возвращаемый `out: [u8; NH]` (HKDF-Extract PRK) перемещается в
/// caller, который зануляет его через ZeroizeOnDrop (HpkeContext) либо явный
/// `.zeroize()` (key_schedule_base + derive_keypair).
///
/// F-63 closure (block 10.8-active-retro): the `labeled_ikm` Vec may carry
/// secret IKM (e.g. the user-provided HPKE setup IKM that DeriveKeyPair uses
/// to derive the private key) → `.zeroize()` before returning. The returned
/// `out: [u8; NH]` (HKDF-Extract PRK) is moved into the caller which zeroizes
/// it via ZeroizeOnDrop (HpkeContext) or an explicit `.zeroize()`
/// (key_schedule_base + derive_keypair).
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; NH] {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_VERSION.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_VERSION);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, &labeled_ikm);
    let mut out = [0u8; NH];
    out.copy_from_slice(prk.as_slice());
    // F-63 closure: zeroize labeled_ikm через `Zeroize` (volatile-write semantics);
    // ручной byte-loop мог бы быть удалён LLVM dead-store elimination в release →
    // row 11 SPEC-01 §4 Cold-boot/forensics.
    // F-63 closure: zeroize labeled_ikm via `Zeroize` (volatile-write semantics);
    // a manual byte loop could be elided by LLVM dead-store elimination in release
    // → SPEC-01 §4 row 11 Cold-boot/forensics.
    labeled_ikm.zeroize();
    out
}

/// `LabeledExpand(prk, label, info, L)` — RFC 9180 §4.
/// `labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`.
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    if length > u16::MAX as usize {
        return Err(CryptoError::HkdfOutputLengthInvalid);
    }
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_VERSION.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
    let mut okm = vec![0u8; length];
    hk.expand(&labeled_info, &mut okm)
        .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
    Ok(okm)
}

// ============================================================================
// HPKE base mode context (RFC 9180 §5.1)
// ============================================================================

/// HPKE base mode context: derived AEAD key + base nonce + exporter_secret.
/// Используется для AEAD seal/open и export operations.
///
/// F-63 closure (block 10.8-active-retro, F-46 pattern recurrence в
/// umbrella-mls scope): `#[derive(ZeroizeOnDrop)]` гарантирует автоматическое
/// зануление всех 3 полей (`key` + `base_nonce` + `exporter_secret`) при
/// Drop через blanket `impl Zeroize for [u8; N]` zeroize crate'а. Это
/// адресует SPEC-01 §4 row 11 Cold-boot / forensics для случая когда
/// HpkeContext выделен на heap (через umbrella-сценарии sealed-sender V2 +
/// MLS exporter_secret derivation), а не только на stack — heap allocation
/// не получает stack-frame overwrite и нуждается в explicit zeroize.
///
/// HPKE base mode context: derived AEAD key + base nonce + exporter_secret.
/// Used for AEAD seal/open and export operations.
///
/// F-63 closure (block 10.8-active-retro, F-46 pattern recurrence in the
/// umbrella-mls scope): `#[derive(ZeroizeOnDrop)]` guarantees automatic
/// zeroization of all 3 fields (`key` + `base_nonce` + `exporter_secret`) on
/// Drop via the zeroize crate's blanket `impl Zeroize for [u8; N]`. This
/// addresses SPEC-01 §4 row 11 Cold-boot / forensics for the case where
/// HpkeContext is heap-allocated (via umbrella sealed-sender V2 + MLS
/// exporter_secret derivation scenarios) rather than only stack — heap
/// allocations do not benefit from stack-frame overwrite and require
/// explicit zeroize.
#[derive(ZeroizeOnDrop)]
struct HpkeContext {
    key: [u8; NK],
    base_nonce: [u8; NN],
    exporter_secret: [u8; NH],
}

/// `KeySchedule(mode_base, shared_secret, info, default_psk="", default_psk_id="")`
/// per RFC 9180 §5.1. Derive key/base_nonce/exporter_secret для последующих
/// AEAD seal/open и export.
fn key_schedule_base(shared_secret: &[u8], info: &[u8]) -> Result<HpkeContext, CryptoError> {
    // psk_id_hash = LabeledExtract("", "psk_id_hash", default_psk_id="")
    let psk_id_hash = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"");
    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info);

    // key_schedule_context = mode || psk_id_hash || info_hash
    let mut ksc = Vec::with_capacity(1 + NH + NH);
    ksc.push(HPKE_MODE_BASE);
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", default_psk="")
    //
    // F-63 closure (block 10.8-active-retro): `secret` хранит HKDF-Extract
    // PRK от X-Wing combiner shared_secret и используется как input к 3
    // последующим LabeledExpand → `mut` + `.zeroize()` после всех 3 expand.
    // F-63 closure: `secret` holds the HKDF-Extract PRK derived from the
    // X-Wing combiner shared_secret and feeds 3 subsequent LabeledExpand
    // calls → `mut` + `.zeroize()` after the last expand.
    let mut secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"");

    // key, base_nonce, exporter_secret = LabeledExpand(secret, label, ksc, len)
    //
    // F-63 closure: каждый Vec<u8> output из labeled_expand содержит
    // секретный keying material → копируем в фиксированный массив + сразу
    // зануляем Vec через `.zeroize()` (`zeroize` крейт vector impl
    // вызывает `as_mut_slice().zeroize()` без re-allocate'а capacity).
    // Финальный массив (key/base_nonce/exporter_secret) попадает в
    // HpkeContext с `#[derive(ZeroizeOnDrop)]`, поэтому зануляется
    // автоматически при Drop контекста.
    // F-63 closure: each Vec<u8> returned by labeled_expand carries secret
    // keying material → copy into a fixed-size array and immediately
    // `.zeroize()` the Vec (`zeroize` crate's vector impl calls
    // `as_mut_slice().zeroize()` without reallocating capacity). The final
    // array (key/base_nonce/exporter_secret) lands in HpkeContext, which
    // carries `#[derive(ZeroizeOnDrop)]`, so it is zeroized automatically
    // on context Drop.
    let mut key_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"key", &ksc, NK)?;
    let mut key = [0u8; NK];
    key.copy_from_slice(&key_vec);
    key_vec.zeroize();

    let mut nonce_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"base_nonce", &ksc, NN)?;
    let mut base_nonce = [0u8; NN];
    base_nonce.copy_from_slice(&nonce_vec);
    nonce_vec.zeroize();

    let mut exporter_secret_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"exp", &ksc, NH)?;
    let mut exporter_secret = [0u8; NH];
    exporter_secret.copy_from_slice(&exporter_secret_vec);
    exporter_secret_vec.zeroize();

    secret.zeroize();

    Ok(HpkeContext {
        key,
        base_nonce,
        exporter_secret,
    })
}

impl HpkeContext {
    /// `Context::Seal(aad, pt)` для seq=0 (single-shot HPKE).
    /// Для seq=0: nonce = base_nonce XOR I2OSP(0, Nn) = base_nonce.
    /// `Context::Seal(aad, pt)` for seq=0 (single-shot HPKE).
    /// For seq=0: nonce = base_nonce XOR I2OSP(0, Nn) = base_nonce.
    fn aead_seal(&self, aad: &[u8], ptxt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        cipher
            .encrypt(&self.base_nonce.into(), Payload { msg: ptxt, aad })
            .map_err(|_| CryptoError::HpkeEncryptionError)
    }

    /// `Context::Open(aad, ct)` для seq=0 (single-shot HPKE).
    /// `Context::Open(aad, ct)` for seq=0 (single-shot HPKE).
    fn aead_open(&self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        cipher
            .decrypt(&self.base_nonce.into(), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    /// `Context::Export(exporter_context, L)`:
    /// `LabeledExpand(exporter_secret, "sec", exporter_context, L)`.
    fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
        labeled_expand(
            HPKE_SUITE_ID,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            length,
        )
    }
}

// ============================================================================
// X-Wing HPKE setup (RFC 9180 §5.1) + DeriveKeyPair (RFC 9180 §7.1.3 pattern)
// ============================================================================

/// `SetupBaseS(pkR, info)` для X-Wing: encaps под pkR + key_schedule(mode_base).
/// Возвращает (`enc`, `context`) где `enc` — X-Wing ciphertext (1120 bytes).
///
/// **Hedged encaps (round-3 closure 2026-05-19, Bellare-Hoang-Keelveedhi 2015):**
/// если provider'у задан `hedged_witness` через
/// `UmbrellaXWingProvider::with_hedged_witness`, encaps использует
/// `xwing_encaps_hedged` с transcript = HPKE info bytes. Это даёт
/// defense-in-depth: compromised CSPRNG не ломает HPKE base mode encaps
/// если witness uncompromised. Если provider — `new()` без witness
/// (нет identity context — например в KAT tests), encaps использует
/// zero-byte witness как fallback. Production callers (через KeyStore)
/// ОБЯЗАНЫ использовать `with_hedged_witness`.
///
/// `SetupBaseS(pkR, info)` for X-Wing: encaps under pkR + key_schedule(mode_base).
/// Returns (`enc`, `context`) where `enc` is the X-Wing ciphertext (1120 bytes).
///
/// **Hedged encaps (round-3 closure 2026-05-19, Bellare-Hoang-Keelveedhi 2015):**
/// if the provider has a `hedged_witness` (set via
/// `UmbrellaXWingProvider::with_hedged_witness`), encaps uses
/// `xwing_encaps_hedged` with transcript = HPKE info bytes. This gives
/// defense-in-depth: a compromised CSPRNG does not break HPKE base mode
/// encaps if the witness is uncompromised. If the provider was created
/// via `new()` without a witness (no identity context — e.g. in KAT
/// tests), encaps uses a zero-byte witness as fallback. Production
/// callers (via KeyStore) MUST use `with_hedged_witness`.
fn setup_base_sender(
    pk_r: &[u8],
    info: &[u8],
    witness: &HedgedWitness,
) -> Result<(Vec<u8>, HpkeContext), CryptoError> {
    if pk_r.len() != XWING_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let pk = XWingPublicKey::from_bytes(pk_r).map_err(|_| CryptoError::InvalidPublicKey)?;
    let mut rng = OsRng;
    let (ct, ss) = xwing_encaps_hedged(&mut rng, &pk, witness, info)
        .map_err(|_| CryptoError::HpkeEncryptionError)?;
    let ctx = key_schedule_base(ss.expose_secret(), info)?;
    Ok((ct.to_vec(), ctx))
}

/// `SetupBaseR(enc, skR, info)` для X-Wing: decaps + key_schedule(mode_base).
/// `SetupBaseR(enc, skR, info)` for X-Wing: decaps + key_schedule(mode_base).
fn setup_base_receiver(enc: &[u8], sk_r: &[u8], info: &[u8]) -> Result<HpkeContext, CryptoError> {
    if enc.len() != XWING_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let ss = xwing_decaps_raw(sk_r, enc).map_err(|_| CryptoError::HpkeDecryptionError)?;
    let ctx = key_schedule_base(ss.expose_secret(), info)?;
    Ok(ctx)
}

/// `DeriveKeyPair(ikm)` для X-Wing — RFC 9180 §7.1.3 pattern:
///
/// ```text
/// dkp_prk = LabeledExtract("", "dkp_prk", ikm)         // под KEM-suite-id
/// seed    = LabeledExpand(dkp_prk, "sk", "", 32)       // под KEM-suite-id
/// (pk, _) = X-Wing.GenerateKeyPair(seed)               // libcrux key_gen_derand
/// ```
///
/// Возвращает `HpkeKeyPair { private = seed, public = pk_bytes }`. `private`
/// хранит 32-байтный seed (формат `XWingSecretSeed`); openmls передаёт его
/// обратно в `hpke_open` / `setup_base_receiver` через `HpkePrivateKey`.
///
/// `DeriveKeyPair(ikm)` for X-Wing — RFC 9180 §7.1.3 pattern. Returns
/// `HpkeKeyPair { private = seed, public = pk_bytes }`. `private` stores the
/// 32-byte seed (`XWingSecretSeed` format); openmls passes it back into
/// `hpke_open` / `setup_base_receiver` via `HpkePrivateKey`.
fn derive_keypair(ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    // F-63 closure (block 10.8-active-retro): `dkp_prk`, `seed_vec`,
    // `seed_arr` содержат материал, из которого деривируется приватный
    // ключ X-Wing (32-байтный seed для libcrux key_gen_derand). Каждый
    // intermediate buffer зануляется перед return через `.zeroize()`.
    // Финальный owned `private_seed_vec` владельчески перемещается в
    // HpkePrivateKey, который зануляется при Drop через openmls_traits
    // SecretVLBytes (zeroize-on-drop в upstream tls_codec ≥ 0.4).
    // F-63 closure: `dkp_prk`, `seed_vec`, `seed_arr` carry the material
    // from which the X-Wing private key is derived (32-byte seed for
    // libcrux's key_gen_derand). Each intermediate buffer is zeroized
    // before returning via `.zeroize()`. The final owned `private_seed_vec`
    // is moved into HpkePrivateKey, which gets zeroized on Drop through
    // openmls_traits SecretVLBytes (zeroize-on-drop in upstream
    // tls_codec ≥ 0.4).
    let mut dkp_prk = labeled_extract(KEM_SUITE_ID, b"", b"dkp_prk", ikm);
    let mut seed_vec = labeled_expand(KEM_SUITE_ID, &dkp_prk, b"sk", b"", XWING_KEYGEN_SEED_LEN)?;
    let mut seed_arr = [0u8; XWING_KEYGEN_SEED_LEN];
    seed_arr.copy_from_slice(&seed_vec);
    seed_vec.zeroize();
    let (pk, _sk_seed) =
        xwing_keygen_from_seed(&seed_arr).map_err(|_| CryptoError::CryptoLibraryError)?;
    let private_seed_vec = seed_arr.to_vec();
    seed_arr.zeroize();
    dkp_prk.zeroize();
    Ok(HpkeKeyPair {
        private: HpkePrivateKey::from(private_seed_vec),
        public: pk.as_bytes().to_vec(),
    })
}

// ============================================================================
// UmbrellaXWingProvider — public type
// ============================================================================

/// Кастомный openmls provider с поддержкой X-Wing ciphersuite (0x004D).
///
/// Делегирует все не-X-Wing операции в обёрнутый `OpenMlsRustCrypto`. Для
/// `HpkeKemType::XWingKemDraft6` реализует HPKE base mode RFC 9180 §5.1
/// поверх `umbrella_pq::xwing_*` (`libcrux-kem 0.0.8`
/// API-имя `Algorithm::XWingKemDraft06`, вывод проверен draft-10 KAT).
///
/// Custom openmls provider with X-Wing ciphersuite (0x004D) support.
///
/// Delegates every non-X-Wing operation to the wrapped `OpenMlsRustCrypto`.
/// For `HpkeKemType::XWingKemDraft6` it implements HPKE base mode RFC 9180
/// §5.1 atop `umbrella_pq::xwing_*` (`libcrux-kem 0.0.8`
/// API name `Algorithm::XWingKemDraft06`, output checked by draft-10 KAT).
#[derive(Debug)]
pub struct UmbrellaXWingProvider {
    inner: OpenMlsRustCrypto,
    /// Hedged-encaps witness — long-term identity-derived secret для
    /// defense-in-depth против compromised CSPRNG (round-3 closure
    /// 2026-05-19, Bellare-Hoang-Keelveedhi 2015). Если provider создан
    /// без witness (через `new()` — для KAT tests или transition path),
    /// заполняется zero-byte witness (НЕ безопасно для production!).
    /// Production callers ДОЛЖНЫ использовать
    /// [`UmbrellaXWingProvider::with_hedged_witness`].
    ///
    /// Hedged-encaps witness — long-term identity-derived secret for
    /// defense-in-depth against a compromised CSPRNG (round-3 closure
    /// 2026-05-19, Bellare-Hoang-Keelveedhi 2015). If the provider is
    /// created without a witness (via `new()` — for KAT tests or a
    /// transition path), it falls back to a zero-byte witness (NOT
    /// production-safe!). Production callers MUST use
    /// [`UmbrellaXWingProvider::with_hedged_witness`].
    hedged_witness: HedgedWitness,
}

// F-MLS-1 closure (PhD-B Pass 1/2/3/4 HIGH carry-over → Pass 5 remediation
// 2026-05-18): production callers MUST construct the provider via
// `with_hedged_witness(witness)`. The pre-fix `Default::default()` impl
// silently substituted `HedgedWitness::zeroed_for_tests_only()`, making
// production builds vulnerable to CSPRNG compromise (Bellare-Hoang-Keelveedhi
// 2015 hedged-encryption defense void). The `new()` test-rig method that
// wrapped `Default::default()` is gated behind the `test-utils` feature so
// production builds physically cannot reach the zeroed-witness path. See
// `docs/audits/phd-b-final-consolidation-2026-05-18.md` §6 Track B item 5.

impl UmbrellaXWingProvider {
    /// Конструирует новый provider с указанным `hedged_witness` для
    /// production-safe HPKE base mode X-Wing encaps. Witness получается
    /// от `KeyStore::hedged_encaps_witness()` либо аналогичного
    /// long-term source.
    ///
    /// **Это единственный production-safe конструктор** (F-MLS-1 closure):
    /// witness обязателен на стадии типов, нет silent fallback к нулевому
    /// witness который сделал бы hedged-encryption защиту бессмысленной.
    ///
    /// Constructs a new provider with the given `hedged_witness` for
    /// production-safe HPKE base mode X-Wing encaps. The witness should
    /// come from `KeyStore::hedged_encaps_witness()` or an equivalent
    /// long-term source.
    ///
    /// **This is the only production-safe constructor** (F-MLS-1 closure):
    /// the witness is required at the type level — no silent fallback to a
    /// zero-byte witness that would void the hedged-encryption defense.
    pub fn with_hedged_witness(witness: HedgedWitness) -> Self {
        Self {
            inner: OpenMlsRustCrypto::default(),
            hedged_witness: witness,
        }
    }

    /// **Test-rig only:** конструирует provider с нулевым hedged witness
    /// (для KAT-векторов draft-connolly-cfrg-xwing-kem-10 Appendix C,
    /// которые требуют детерминистический encaps без external entropy).
    /// Production callers MUST использовать [`Self::with_hedged_witness`];
    /// этот метод недоступен в production builds (`#[cfg(any(test,
    /// feature = "test-utils"))]` gate — F-MLS-1 closure).
    ///
    /// **Test-rig only:** constructs the provider with a zero hedged
    /// witness (for KAT vectors `draft-connolly-cfrg-xwing-kem-10`
    /// Appendix C, which require deterministic encaps without external
    /// entropy). Production callers MUST use
    /// [`Self::with_hedged_witness`]; this method is not present in
    /// production builds (`#[cfg(any(test, feature = "test-utils"))]`
    /// gate — F-MLS-1 closure).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_kat_tests_only() -> Self {
        Self {
            inner: OpenMlsRustCrypto::default(),
            hedged_witness: HedgedWitness::zeroed_for_tests_only(),
        }
    }
}

// ============================================================================
// impl OpenMlsCrypto for UmbrellaXWingProvider
// ============================================================================

impl OpenMlsCrypto for UmbrellaXWingProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => Ok(()),
            other => self.inner.crypto().supports(other),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        let mut suites = self.inner.crypto().supported_ciphersuites();
        if !suites.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519) {
            suites.push(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519);
        }
        suites
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.crypto().hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.crypto().hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner
            .crypto()
            .hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.crypto().hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.crypto().aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .crypto()
            .aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner.crypto().signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner
            .crypto()
            .verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.crypto().sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        if config.0 == HpkeKemType::XWingKemDraft6 {
            // X-Wing single-shot HPKE Seal: SetupBaseS + Context.Seal.
            let (enc, ctx) = setup_base_sender(pk_r, info, &self.hedged_witness)?;
            let ct = ctx.aead_seal(aad, ptxt)?;
            return Ok(HpkeCiphertext {
                kem_output: enc.into(),
                ciphertext: ct.into(),
            });
        }
        self.inner.crypto().hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if config.0 == HpkeKemType::XWingKemDraft6 {
            // X-Wing single-shot HPKE Open: SetupBaseR + Context.Open.
            let ctx = setup_base_receiver(input.kem_output.as_slice(), sk_r, info)?;
            return ctx.aead_open(aad, input.ciphertext.as_slice());
        }
        self.inner
            .crypto()
            .hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        if config.0 == HpkeKemType::XWingKemDraft6 {
            let (enc, ctx) = setup_base_sender(pk_r, info, &self.hedged_witness)?;
            let exported = ctx.export(exporter_context, exporter_length)?;
            return Ok((enc, ExporterSecret::from(exported)));
        }
        self.inner.crypto().hpke_setup_sender_and_export(
            config,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        if config.0 == HpkeKemType::XWingKemDraft6 {
            let ctx = setup_base_receiver(enc, sk_r, info)?;
            let exported = ctx.export(exporter_context, exporter_length)?;
            return Ok(ExporterSecret::from(exported));
        }
        self.inner.crypto().hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        if config.0 == HpkeKemType::XWingKemDraft6 {
            return derive_keypair(ikm);
        }
        self.inner.crypto().derive_hpke_keypair(config, ikm)
    }
}

// ============================================================================
// impl OpenMlsProvider for UmbrellaXWingProvider
// ============================================================================

impl OpenMlsProvider for UmbrellaXWingProvider {
    type CryptoProvider = Self;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.inner.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self
    }

    fn rand(&self) -> &Self::RandProvider {
        self.inner.rand()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::types::{HpkeAeadType, HpkeKdfType};

    fn xwing_config() -> HpkeConfig {
        HpkeConfig(
            HpkeKemType::XWingKemDraft6,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::ChaCha20Poly1305,
        )
    }

    /// supports(0x004D) → Ok; supports(0x0001) → делегирует в inner и тоже Ok.
    /// supports(0x004D) → Ok; supports(0x0001) → delegates to inner and is also Ok.
    #[test]
    fn supports_xwing_and_classical() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        assert!(provider
            .supports(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .is_ok());
        assert!(provider
            .supports(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
            .is_ok());
    }

    /// supported_ciphersuites включает 0x004D (через наш push) + classical.
    /// supported_ciphersuites includes 0x004D (via our push) + classical.
    #[test]
    fn supported_ciphersuites_includes_xwing() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let suites = provider.supported_ciphersuites();
        assert!(suites.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519));
        assert!(suites.contains(&Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519));
    }

    /// HPKE seal/open roundtrip: Alice (sender) → Bob (receiver) — текст совпадает.
    /// HPKE seal/open roundtrip: Alice (sender) → Bob (receiver) — text matches.
    #[test]
    fn hpke_seal_open_roundtrip_xwing() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();

        let ikm = [0x42u8; 32];
        let kp = provider
            .derive_hpke_keypair(xwing_config(), &ikm)
            .expect("derive keypair");

        let ptxt = b"umbrella protocol stage 8.4 X-Wing test";
        let info = b"umbrellax-mls-xwing-test-info";
        let aad = b"associated data";

        let ct = provider
            .hpke_seal(xwing_config(), &kp.public, info, aad, ptxt)
            .expect("hpke_seal");
        // X-Wing ciphertext = 1120 bytes.
        assert_eq!(ct.kem_output.as_slice().len(), XWING_CIPHERTEXT_LEN);

        let recovered = provider
            .hpke_open(xwing_config(), &ct, &kp.private, info, aad)
            .expect("hpke_open");
        assert_eq!(recovered, ptxt);
    }

    /// HPKE setup_sender/receiver_and_export даёт совпадающий exporter_secret
    /// (фундамент для MLS exporter_secret API → SFrame derivation, Этап 6.2).
    /// HPKE setup_sender/receiver_and_export yield a matching exporter_secret
    /// (foundation for MLS exporter_secret API → SFrame derivation, Stage 6.2).
    #[test]
    fn hpke_setup_export_matches_xwing() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let kp = provider
            .derive_hpke_keypair(xwing_config(), &[0x77u8; 32])
            .expect("derive keypair");

        let info = b"info-export";
        let exporter_ctx = b"sframe-test-context";

        let (enc, sender_export) = provider
            .hpke_setup_sender_and_export(xwing_config(), &kp.public, info, exporter_ctx, 32)
            .expect("setup_sender_and_export");

        let receiver_export = provider
            .hpke_setup_receiver_and_export(
                xwing_config(),
                &enc,
                &kp.private,
                info,
                exporter_ctx,
                32,
            )
            .expect("setup_receiver_and_export");

        assert_eq!(&*sender_export, &*receiver_export);
        assert_eq!(sender_export.len(), 32);
    }

    /// derive_hpke_keypair с одинаковым IKM → одинаковый keypair (deterministic).
    /// derive_hpke_keypair with the same IKM yields the same keypair (deterministic).
    #[test]
    fn derive_keypair_is_deterministic() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let ikm = [0xABu8; 64];
        let kp1 = provider.derive_hpke_keypair(xwing_config(), &ikm).unwrap();
        let kp2 = provider.derive_hpke_keypair(xwing_config(), &ikm).unwrap();
        assert_eq!(kp1.public, kp2.public);
        assert_eq!(&*kp1.private, &*kp2.private);
    }

    /// Bit-flip в kem_output ломает decap → HpkeDecryptionError.
    /// Bit-flip in kem_output breaks decap → HpkeDecryptionError.
    #[test]
    fn hpke_open_corrupted_kem_output_rejected() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let kp = provider
            .derive_hpke_keypair(xwing_config(), &[0x11u8; 32])
            .unwrap();
        let mut ct = provider
            .hpke_seal(xwing_config(), &kp.public, b"info", b"aad", b"msg")
            .unwrap();
        // Flip one bit в kem_output.
        let mut kem_bytes = ct.kem_output.as_slice().to_vec();
        kem_bytes[10] ^= 0x01;
        ct.kem_output = kem_bytes.into();

        let result = provider.hpke_open(xwing_config(), &ct, &kp.private, b"info", b"aad");
        assert!(matches!(result, Err(CryptoError::HpkeDecryptionError)));
    }

    /// Делегирование classical ciphersuites: HPKE seal/open для DhKem25519.
    /// `HpkeConfig` не Copy — конструируем заново для каждого вызова.
    /// Delegation of classical ciphersuites: HPKE seal/open for DhKem25519.
    /// `HpkeConfig` is not Copy — re-construct it for each call.
    #[test]
    fn classical_hpke_delegation_works() {
        fn classical_config() -> HpkeConfig {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            )
        }
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let kp = provider
            .derive_hpke_keypair(classical_config(), &[0x55u8; 32])
            .expect("classical derive_keypair");
        let ct = provider
            .hpke_seal(
                classical_config(),
                &kp.public,
                b"info",
                b"aad",
                b"classical msg",
            )
            .expect("classical hpke_seal");
        let pt = provider
            .hpke_open(classical_config(), &ct, &kp.private, b"info", b"aad")
            .expect("classical hpke_open");
        assert_eq!(pt, b"classical msg");
    }

    /// Невалидный размер pk_r → InvalidPublicKey (защита от mis-use).
    /// Invalid pk_r length → InvalidPublicKey (mis-use defence).
    #[test]
    fn hpke_seal_rejects_short_pubkey() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let result = provider.hpke_seal(xwing_config(), &[0u8; 100], b"info", b"aad", b"msg");
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey)));
    }

    /// LabeledExtract/LabeledExpand стабильность: тот же input → тот же output.
    /// LabeledExtract/LabeledExpand stability: same input → same output.
    #[test]
    fn labeled_kdf_deterministic() {
        let prk1 = labeled_extract(HPKE_SUITE_ID, b"salt", b"label", b"ikm");
        let prk2 = labeled_extract(HPKE_SUITE_ID, b"salt", b"label", b"ikm");
        assert_eq!(prk1, prk2);

        let okm1 = labeled_expand(HPKE_SUITE_ID, &prk1, b"label2", b"info", 64).unwrap();
        let okm2 = labeled_expand(HPKE_SUITE_ID, &prk1, b"label2", b"info", 64).unwrap();
        assert_eq!(okm1, okm2);
        assert_eq!(okm1.len(), 64);
    }

    /// Domain separation: KEM-suite-id vs HPKE-suite-id дают разные outputs.
    /// Domain separation: KEM-suite-id vs HPKE-suite-id yield different outputs.
    #[test]
    fn kem_vs_hpke_suite_id_domain_separated() {
        let kem_prk = labeled_extract(KEM_SUITE_ID, b"", b"dkp_prk", b"ikm");
        let hpke_prk = labeled_extract(HPKE_SUITE_ID, b"", b"dkp_prk", b"ikm");
        assert_ne!(kem_prk, hpke_prk);
    }

    /// F-63 closure (block 10.8-active-retro): compile-time гарантия что
    /// `HpkeContext` имплементирует `ZeroizeOnDrop`, и значит все 3 поля
    /// (`key: [u8; NK]` + `base_nonce: [u8; NN]` + `exporter_secret: [u8; NH]`)
    /// зануляются автоматически при Drop через blanket
    /// `impl<const N: usize> Zeroize for [u8; N]` zeroize крейт'а. Это
    /// исключает сценарий cold-boot/forensics row 11 SPEC-01 §4 для случая
    /// когда HpkeContext выделен на heap (sealed-sender V2 + MLS
    /// exporter_secret derivation pipelines), а не только на stack.
    ///
    /// F-63 closure (block 10.8-active-retro): compile-time guarantee that
    /// `HpkeContext` implements `ZeroizeOnDrop`, and therefore all 3 fields
    /// (`key: [u8; NK]` + `base_nonce: [u8; NN]` +
    /// `exporter_secret: [u8; NH]`) are zeroized automatically on Drop via
    /// the zeroize crate's blanket
    /// `impl<const N: usize> Zeroize for [u8; N]`. This rules out the
    /// cold-boot/forensics scenario of SPEC-01 §4 row 11 for the case where
    /// HpkeContext is heap-allocated (sealed-sender V2 + MLS
    /// exporter_secret derivation pipelines) rather than only stack.
    #[test]
    fn f63_hpke_context_zeroize_on_drop_compile_time_guarantee() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<HpkeContext>();
    }

    /// F-63 closure: семантическая регрессия — после inline-fix'а
    /// labeled_extract / key_schedule_base / derive_keypair (zeroize всех
    /// intermediate buffers) HPKE seal/open roundtrip остаётся
    /// корректным byte-exact для X-Wing draft-10. Тест ловит любую
    /// случайную регрессию pipeline'а — например, если будущий правщик
    /// заменит `key_vec.zeroize()` на ошибочный `key.zeroize()` (что
    /// затрёт уже сохранённый ключ перед HpkeContext конструированием).
    ///
    /// F-63 closure: semantic regression — after the inline fix in
    /// labeled_extract / key_schedule_base / derive_keypair (zeroize of
    /// all intermediate buffers) the HPKE seal/open roundtrip stays
    /// byte-exact for X-Wing draft-10. The test catches any accidental
    /// pipeline regression — e.g. if a future editor swaps
    /// `key_vec.zeroize()` for an erroneous `key.zeroize()` (which would
    /// wipe the already-stored key before HpkeContext construction).
    #[test]
    fn f63_seal_open_semantic_regression_post_zeroize_fix() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let kp = provider
            .derive_hpke_keypair(xwing_config(), &[0xC3u8; 32])
            .expect("derive keypair post-fix");
        let plaintext = b"F-63 closure semantic regression payload";
        let info = b"f63-test-info";
        let aad = b"f63-aad";
        let ct = provider
            .hpke_seal(xwing_config(), &kp.public, info, aad, plaintext)
            .expect("hpke_seal post-fix");
        let recovered = provider
            .hpke_open(xwing_config(), &ct, &kp.private, info, aad)
            .expect("hpke_open post-fix");
        assert_eq!(recovered, plaintext);
    }

    /// F-63 closure: семантическая регрессия — derive_keypair детерминирован
    /// post-fix (тот же IKM → bit-equal keypair) несмотря на zeroize всех
    /// intermediate buffers (`dkp_prk`, `seed_vec`, `seed_arr`). Tест
    /// гарантирует что zeroize не выполняется ДО finalize'а keypair'а.
    ///
    /// F-63 closure: semantic regression — derive_keypair stays
    /// deterministic post-fix (same IKM → bit-equal keypair) despite the
    /// zeroize of every intermediate buffer (`dkp_prk`, `seed_vec`,
    /// `seed_arr`). The test guarantees that zeroize does not run BEFORE
    /// the keypair finalisation.
    #[test]
    fn f63_derive_keypair_deterministic_post_zeroize_fix() {
        let provider = UmbrellaXWingProvider::new_for_kat_tests_only();
        let ikm = [0xA5u8; 64];
        let kp1 = provider.derive_hpke_keypair(xwing_config(), &ikm).unwrap();
        let kp2 = provider.derive_hpke_keypair(xwing_config(), &ikm).unwrap();
        assert_eq!(kp1.public, kp2.public);
        assert_eq!(&*kp1.private, &*kp2.private);
        // Дополнительно: убеждаемся что seed_arr.to_vec() сохранил исходный
        // seed (если бы dkp_prk.zeroize() сработал ДО seed_arr.to_vec(), то
        // private был бы все нули).
        // Additionally: confirm seed_arr.to_vec() preserved the original
        // seed (if dkp_prk.zeroize() ran BEFORE seed_arr.to_vec(), private
        // would be all zeros).
        assert_ne!(&*kp1.private, &[0u8; XWING_KEYGEN_SEED_LEN][..]);
    }
}
