//! X-Wing combiner (draft-connolly-cfrg-xwing-kem-10): X25519 + ML-KEM-768 hybrid KEM.
//! X-Wing combiner (draft-connolly-cfrg-xwing-kem-10): X25519 + ML-KEM-768 hybrid KEM.
//!
//! Используется как pq-ciphersuite в MLS (IANA 0x004D
//! `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`) и как ephemeral KEM в
//! sealed-sender hybrid envelope (блок 8.6).
//!
//! Used as the pq-ciphersuite in MLS (IANA 0x004D) and as ephemeral KEM in
//! sealed-sender hybrid envelope (block 8.6).
//!
//! Бэкенд: `libcrux-kem 0.0.8` через API-имя `Algorithm::XWingKemDraft06`.
//! Реальный вывод закреплён официальным draft-10 Appendix C KAT в
//! `tests/xwing_draft10_kat.rs`; отличие имени upstream API от draft-10
//! документальное, не wire-format mismatch. Используется derand API чтобы
//! обойти несовместимость `rand_core` версий между libcrux (0.9) и нашим
//! workspace (0.6).
//!
//! Backend: `libcrux-kem 0.0.8` via the upstream API name
//! `Algorithm::XWingKemDraft06`. Actual output is pinned against the official
//! draft-10 Appendix C KAT in `tests/xwing_draft10_kat.rs`; the upstream API
//! name is documentary drift, not a wire-format mismatch. Uses derand API to
//! bypass `rand_core` version incompatibility between libcrux (0.9) and our
//! workspace (0.6).

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::constants::{
    XWING_CIPHERTEXT_LEN, XWING_ENCAPS_SEED_LEN, XWING_KEYGEN_SEED_LEN, XWING_PUBLIC_KEY_LEN,
    XWING_SECRET_SEED_LEN, XWING_SHARED_SECRET_LEN,
};
use crate::error::{PqError, Result};
use crate::hedged::{
    derive_hedged_encaps_seed, HedgedWitness, HEDGED_RNG_INPUT_LEN,
};

/// X-Wing публичный ключ (1216 байт = ML-KEM-768 pk 1184 || X25519 pk 32).
/// X-Wing public key (1216 bytes = ML-KEM-768 pk 1184 || X25519 pk 32).
#[derive(Clone)]
pub struct XWingPublicKey {
    bytes: [u8; XWING_PUBLIC_KEY_LEN],
}

/// X-Wing secret seed (32 bytes; expand internally в keygen).
/// X-Wing secret seed (32 bytes; expanded internally during keygen).
pub struct XWingSecretSeed {
    inner: SecretBox<[u8; XWING_SECRET_SEED_LEN]>,
}

impl XWingPublicKey {
    /// Сериализация в bytes.
    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != XWING_PUBLIC_KEY_LEN {
            return Err(PqError::XWingInvalidPublicKey { got: bytes.len() });
        }
        let mut buf = [0u8; XWING_PUBLIC_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

impl XWingSecretSeed {
    /// Доступ к raw seed bytes (через `ExposeSecret`).
    /// Access raw seed bytes (via `ExposeSecret`).
    pub(crate) fn expose(&self) -> &[u8; XWING_SECRET_SEED_LEN] {
        self.inner.expose_secret()
    }
}

/// X-Wing KeyGen из заданного 32-байтного seed (deterministic).
///
/// Используется для HPKE base mode RFC 9180 §7.1.3 DeriveKeyPair, где IKM
/// деривируется в seed детерминированно через HKDF, и keygen должен быть
/// reproducible. seed expand'ится внутри libcrux в ML-KEM-768 keypair +
/// X25519 keypair по spec draft-connolly-cfrg-xwing-kem-10.
///
/// X-Wing KeyGen from a given 32-byte seed (deterministic).
///
/// Used by HPKE base mode RFC 9180 §7.1.3 DeriveKeyPair, where IKM is derived
/// into a seed deterministically via HKDF, and keygen must be reproducible.
/// The seed is expanded inside libcrux into an ML-KEM-768 keypair + X25519
/// keypair per draft-connolly-cfrg-xwing-kem-10.
pub fn xwing_keygen_from_seed(
    seed: &[u8; XWING_KEYGEN_SEED_LEN],
) -> Result<(XWingPublicKey, XWingSecretSeed)> {
    let (sk, pk) = libcrux_kem::key_gen_derand(libcrux_kem::Algorithm::XWingKemDraft06, seed)
        .map_err(|e| PqError::BackendError {
            message: format!("xwing keygen: {e:?}"),
        })?;

    let pk_encoded = pk.encode();
    if pk_encoded.len() != XWING_PUBLIC_KEY_LEN {
        return Err(PqError::BackendError {
            message: format!(
                "xwing pk length mismatch: got {}, expected {}",
                pk_encoded.len(),
                XWING_PUBLIC_KEY_LEN
            ),
        });
    }
    let mut pk_buf = [0u8; XWING_PUBLIC_KEY_LEN];
    pk_buf.copy_from_slice(&pk_encoded);

    let sk_encoded = sk.encode();
    if sk_encoded.len() < XWING_SECRET_SEED_LEN {
        return Err(PqError::BackendError {
            message: format!(
                "xwing sk too short: {} < {}",
                sk_encoded.len(),
                XWING_SECRET_SEED_LEN
            ),
        });
    }
    let mut seed_buf = [0u8; XWING_SECRET_SEED_LEN];
    seed_buf.copy_from_slice(&sk_encoded[..XWING_SECRET_SEED_LEN]);

    Ok((
        XWingPublicKey { bytes: pk_buf },
        XWingSecretSeed {
            inner: SecretBox::new(Box::new(seed_buf)),
        },
    ))
}

/// X-Wing KeyGen.
///
/// Генерирует пару (pk, secret seed). Seed expand'ится внутри libcrux в
/// ML-KEM-768 keypair + X25519 keypair по spec draft-connolly-cfrg-xwing-kem-10.
///
/// Generates a (pk, secret seed) pair. Seed is expanded inside libcrux into
/// an ML-KEM-768 keypair + X25519 keypair per draft-connolly-cfrg-xwing-kem-10.
pub fn xwing_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(XWingPublicKey, XWingSecretSeed)> {
    let mut seed = [0u8; XWING_KEYGEN_SEED_LEN];
    rng.fill_bytes(&mut seed);
    let result = xwing_keygen_from_seed(&seed);
    // Очищаем временный buffer seed через zeroize::Zeroize (volatile-write semantics);
    // ручной byte-loop через for_each мог бы быть удалён компилятором как dead store
    // в release-сборке (LLVM dead-store elimination) → row 11 Cold-boot/forensics.
    // Wipe the temporary seed buffer via zeroize::Zeroize (volatile-write semantics);
    // a manual byte-loop could be elided by the compiler as a dead store in release
    // builds (LLVM dead-store elimination) → threat row 11 Cold-boot/forensics.
    seed.zeroize();
    result
}

/// X-Wing Encapsulation.
///
/// Возвращает `(ciphertext, shared_secret)` под `pk`. Random encaps seed
/// (`[u8; 64]`) генерируется через `rng.fill_bytes` (32 bytes для ML-KEM
/// внутри X-Wing + 32 bytes для X25519 ephemeral).
///
/// Returns `(ciphertext, shared_secret)` under `pk`. Random encaps seed
/// (`[u8; 64]`) is generated via `rng.fill_bytes` (32 bytes for ML-KEM inside
/// X-Wing + 32 bytes for X25519 ephemeral).
pub fn xwing_encaps<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &XWingPublicKey,
) -> Result<(
    [u8; XWING_CIPHERTEXT_LEN],
    SecretBox<[u8; XWING_SHARED_SECRET_LEN]>,
)> {
    let mut seed = [0u8; XWING_ENCAPS_SEED_LEN];
    rng.fill_bytes(&mut seed);
    let result = xwing_encaps_derand_internal(pk, &seed);
    // Очищаем временный buffer encaps seed (32 bytes ML-KEM + 32 bytes X25519 ephemeral)
    // через zeroize::Zeroize ДО возврата — независимо от success/error backend'а.
    // Wipe the temporary encaps seed buffer (32-byte ML-KEM + 32-byte X25519 ephemeral)
    // via zeroize::Zeroize BEFORE returning — independent of backend success/error.
    seed.zeroize();
    result
}

/// X-Wing Encapsulation **hedged variant** (Bellare-Hoang-Keelveedhi 2015).
///
/// Defense-in-depth против compromised CSPRNG: seed для ML-KEM/X25519
/// деривируется через HKDF-SHA512 над `rng.fill_bytes(64) || hedged_witness ||
/// transcript || recipient_pk_hash`. Если adversary контролирует `rng`
/// но не witness — ss остаётся uniform (HKDF-as-RO assumption); если
/// контролирует witness но не rng — ss остаётся uniform. Single compromise
/// → no break. Double compromise → fundamental unavoidable break (см.
/// `attack_r5_double_compromise_unavoidable_break` test).
///
/// `transcript` — canonical AAD bytes для этой operation: сейчас вызывающий
/// слой (cloud-wrap, sealed-sender) подаёт `CanonicalAad` либо аналог.
/// Минимальный требования: byte-distinct для разных sessions/recipients,
/// чтобы multi-session replay блокировался HKDF info domain separation.
///
/// **Wire format**: byte-identical с обычным [`xwing_encaps`]
/// (`xwing_encaps_derand` внутри). Receivers не нуждаются в обновлении.
///
/// X-Wing Encapsulation **hedged variant** (Bellare-Hoang-Keelveedhi 2015).
///
/// Defense-in-depth against a compromised CSPRNG: the seed for
/// ML-KEM/X25519 is derived via HKDF-SHA512 over `rng.fill_bytes(64) ||
/// hedged_witness || transcript || recipient_pk_hash`. If the adversary
/// controls `rng` but not the witness — ss remains uniform (HKDF-as-RO
/// assumption); if they control the witness but not the rng — ss remains
/// uniform. Single compromise → no break. Double compromise → fundamental
/// unavoidable break (see `attack_r5_double_compromise_unavoidable_break`).
///
/// `transcript` — canonical AAD bytes for this operation: current callers
/// (cloud-wrap, sealed-sender) pass `CanonicalAad` or equivalent. The
/// minimum requirement is byte-distinctness across sessions/recipients,
/// so multi-session replay is blocked via HKDF info domain separation.
///
/// **Wire format**: byte-identical with plain [`xwing_encaps`] (uses
/// `xwing_encaps_derand` internally). Receivers do not need any update.
pub fn xwing_encaps_hedged<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &XWingPublicKey,
    hedged_witness: &HedgedWitness,
    transcript: &[u8],
) -> Result<(
    [u8; XWING_CIPHERTEXT_LEN],
    SecretBox<[u8; XWING_SHARED_SECRET_LEN]>,
)> {
    // 1. Draw 64-byte rng_input (даже компрометированный CSPRNG обязан
    // вернуть 64 bytes; если они attacker-known, HKDF над witness прячет
    // их).
    // 1. Draw 64-byte rng_input (even a compromised CSPRNG must return
    // 64 bytes; if attacker-known, HKDF over the witness masks them).
    let mut rng_input = [0u8; HEDGED_RNG_INPUT_LEN];
    rng.fill_bytes(&mut rng_input);

    // 2. Hash recipient_pk → 32 bytes (compact domain-separation против
    // 1216-byte raw pk в HKDF info).
    // 2. Hash recipient_pk → 32 bytes (compact domain separation versus
    // the 1216-byte raw pk in the HKDF info).
    let mut hasher = Sha256::new();
    hasher.update(pk.as_bytes());
    let pk_hash: [u8; 32] = hasher.finalize().into();

    // 3. Hedged seed derivation — HKDF-SHA512 над (rng_input || witness)
    // с info=(transcript || pk_hash).
    // 3. Hedged seed derivation — HKDF-SHA512 over (rng_input || witness)
    // with info=(transcript || pk_hash).
    let mut seed =
        derive_hedged_encaps_seed(&rng_input, hedged_witness, transcript, &pk_hash)?;

    // 4. Очищаем rng_input — он скопирован в HKDF ikm, оригинал не нужен.
    // 4. Wipe rng_input — it was copied into the HKDF ikm, the original is
    // no longer needed.
    rng_input.zeroize();

    // 5. Standard derand encaps под получившийся seed.
    // 5. Standard derand encaps using the resulting seed.
    let result = xwing_encaps_derand_internal(pk, &seed);

    // 6. Zeroize hedged seed после использования (содержит производный
    // material из witness; ослабленный witness recovery возможен только
    // через HKDF-SHA512 prf inverse что 2^256 hard).
    // 6. Zeroize the hedged seed after use (contains material derived
    // from the witness; weakened witness recovery requires HKDF-SHA512
    // PRF inversion, which is 2^256 hard).
    seed.zeroize();

    result
}

/// Детерминированный X-Wing encapsulation с 64-байтовым `eseed` из интерфейса
/// draft-connolly-cfrg-xwing-kem-10 `EncapsulateDerand(pk, eseed)`.
///
/// **Видимость (round-3 hedged-encaps closure 2026-05-19):** `pub(crate)`
/// под обычной сборкой; `pub` только под internal test-only feature
/// `__internal-kat-hooks` (используется integration tests
/// `tests/xwing_draft10_kat.rs` и `tests/r5_rng_injection_real_exploit.rs`).
/// Это физическое закрытие R5.B: downstream production крейты не могут
/// активировать `__internal-kat-hooks`, потому что workspace это не
/// делает (compile-fail из downstream при попытке вызова). Round 2 R5
/// reality-pass показал что `pub` API + adversary-known seed →
/// предсказуемый ss; round 3 закрыл это через `xwing_encaps_hedged` +
/// pub(crate) на сам derand path.
///
/// Это hook для KAT-тестов, KAT-вектора Appendix C draft-10, и
/// adversarial-documentation tests. Боевой код должен использовать
/// [`xwing_encaps_hedged`] (защита от compromised CSPRNG через
/// hedged-encryption pattern Bellare-Hoang-Keelveedhi 2015) либо
/// [`xwing_encaps`] (legacy non-hedged path для тестов и MLS HPKE
/// integration где hedged-API не подходит).
///
/// Deterministic X-Wing encapsulation using the 64-byte `eseed` from the
/// draft-connolly-cfrg-xwing-kem-10 `EncapsulateDerand(pk, eseed)` interface.
///
/// **Visibility (round-3 hedged-encaps closure 2026-05-19):** `pub(crate)`
/// under the normal build; `pub` only under the internal test-only feature
/// `__internal-kat-hooks` (used by the integration tests
/// `tests/xwing_draft10_kat.rs` and `tests/r5_rng_injection_real_exploit.rs`).
/// This is the physical closure of R5.B: downstream production crates
/// cannot activate `__internal-kat-hooks` because the workspace does not
/// do so (compile-fail from downstream when attempting to call). Round 2
/// R5 reality-pass demonstrated that the `pub` API + adversary-known seed
/// → predictable ss; round 3 closed that via `xwing_encaps_hedged` plus
/// pub(crate) on the derand path.
///
/// Production callers should use [`xwing_encaps_hedged`] (defense against
/// compromised CSPRNG via the Bellare-Hoang-Keelveedhi 2015 hedged-encryption
/// pattern) or [`xwing_encaps`] (legacy non-hedged path retained for tests
/// and the MLS HPKE integration where the hedged API is not a fit).
#[cfg(feature = "__internal-kat-hooks")]
pub fn xwing_encaps_derand(
    pk: &XWingPublicKey,
    eseed: &[u8; XWING_ENCAPS_SEED_LEN],
) -> Result<(
    [u8; XWING_CIPHERTEXT_LEN],
    SecretBox<[u8; XWING_SHARED_SECRET_LEN]>,
)> {
    xwing_encaps_derand_internal(pk, eseed)
}

/// Implementation detail of `xwing_encaps_derand` — same logic, single source
/// of truth regardless of the `__internal-kat-hooks` feature.
///
/// Used by `xwing_encaps` and `xwing_encaps_hedged` directly; under
/// `__internal-kat-hooks` it is additionally exposed via the wrapper
/// above as `pub xwing_encaps_derand`.
///
/// Implementation detail of `xwing_encaps_derand` — same logic, single
/// source of truth regardless of the `__internal-kat-hooks` feature. Used
/// by `xwing_encaps` and `xwing_encaps_hedged` directly; under
/// `__internal-kat-hooks` it is additionally exposed via the wrapper
/// above as `pub xwing_encaps_derand`.
pub(crate) fn xwing_encaps_derand_internal(
    pk: &XWingPublicKey,
    eseed: &[u8; XWING_ENCAPS_SEED_LEN],
) -> Result<(
    [u8; XWING_CIPHERTEXT_LEN],
    SecretBox<[u8; XWING_SHARED_SECRET_LEN]>,
)> {
    let pk_libcrux =
        libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, &pk.bytes)
            .map_err(|e| PqError::BackendError {
                message: format!("xwing pk decode: {e:?}"),
            })?;

    let encaps_result = pk_libcrux.encapsulate_derand(eseed);
    let (ss, ct) = encaps_result.map_err(|e| PqError::BackendError {
        message: format!("xwing encaps: {e:?}"),
    })?;

    let ct_encoded = ct.encode();
    if ct_encoded.len() != XWING_CIPHERTEXT_LEN {
        return Err(PqError::BackendError {
            message: format!(
                "xwing ct length mismatch: got {}, expected {}",
                ct_encoded.len(),
                XWING_CIPHERTEXT_LEN
            ),
        });
    }
    let mut ct_buf = [0u8; XWING_CIPHERTEXT_LEN];
    ct_buf.copy_from_slice(&ct_encoded);

    let ss_encoded = ss.encode();
    if ss_encoded.len() != XWING_SHARED_SECRET_LEN {
        return Err(PqError::BackendError {
            message: format!(
                "xwing ss length mismatch: got {}, expected {}",
                ss_encoded.len(),
                XWING_SHARED_SECRET_LEN
            ),
        });
    }
    let mut ss_buf = [0u8; XWING_SHARED_SECRET_LEN];
    ss_buf.copy_from_slice(&ss_encoded);

    Ok((ct_buf, SecretBox::new(Box::new(ss_buf))))
}

/// X-Wing Decapsulation на основе raw seed bytes (без `XWingSecretSeed`-типа).
///
/// Используется в HPKE base mode (`umbrella-mls::provider::xwing`) где
/// `OpenMlsCrypto::hpke_open` передаёт `sk_r` как `&[u8]` (из openmls
/// storage). Сам seed обязан быть произведён из `xwing_keygen*` (32 bytes,
/// не raw libcrux secret).
///
/// X-Wing Decapsulation from raw seed bytes (without the `XWingSecretSeed`
/// type).
///
/// Used by HPKE base mode (`umbrella-mls::provider::xwing`) where
/// `OpenMlsCrypto::hpke_open` passes `sk_r` as `&[u8]` (from openmls
/// storage). The seed must originate from `xwing_keygen*` (32 bytes,
/// not raw libcrux secret).
pub fn xwing_decaps_raw(
    seed_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<SecretBox<[u8; XWING_SHARED_SECRET_LEN]>> {
    if seed_bytes.len() != XWING_SECRET_SEED_LEN {
        return Err(PqError::XWingInvalidSecretSeed {
            got: seed_bytes.len(),
        });
    }
    if ct_bytes.len() != XWING_CIPHERTEXT_LEN {
        return Err(PqError::XWingInvalidCiphertext {
            got: ct_bytes.len(),
        });
    }
    let mut seed_arr = [0u8; XWING_SECRET_SEED_LEN];
    seed_arr.copy_from_slice(seed_bytes);
    let seed = XWingSecretSeed {
        inner: SecretBox::new(Box::new(seed_arr)),
    };
    let mut ct_arr = [0u8; XWING_CIPHERTEXT_LEN];
    ct_arr.copy_from_slice(ct_bytes);
    xwing_decaps(&seed, &ct_arr)
}

/// X-Wing Decapsulation.
///
/// Восстанавливает shared secret из ciphertext через secret seed.
///
/// **Rejection semantics (F-PHD-PQ-7, 2026-05-19 audit closure):** X-Wing
/// inherits ML-KEM-768's **implicit rejection** at the combiner level per
/// draft-connolly-cfrg-xwing-kem-10 §5.4. На tamper в ML-KEM половине ct
/// decapsulate чаще всего возвращает `Ok(ss')` где `ss'` — pseudo-random
/// shared secret, отличный от sender's (FIPS 203 §7.3 design). X25519
/// half проверяется unconditionally — invalid X25519 ephemeral public
/// возвращает all-zero shared secret вместо отдельного Err. Wrapper
/// возвращает `XWingDecapsulationFailed` только когда libcrux backend
/// reports decode/structural error (ct_len mismatch и т.п.), что редко
/// в production wire — caller обязан опираться на AEAD tag binding (V2
/// envelope + AEAD AAD coverage) для detection mismatch, **не** на
/// XWingDecapsulationFailed error path.
///
/// Recovers shared secret from ciphertext using secret seed.
///
/// **Rejection semantics (F-PHD-PQ-7, 2026-05-19 audit closure):**
/// X-Wing inherits ML-KEM-768 **implicit rejection** at the combiner per
/// draft-connolly-cfrg-xwing-kem-10 §5.4. For ML-KEM-half tampering, the
/// decapsulate path most often returns `Ok(ss')` where `ss'` is a
/// pseudo-random shared secret distinct from the sender's (FIPS 203 §7.3
/// design). The X25519 half is checked unconditionally — an invalid X25519
/// ephemeral public produces an all-zero shared secret rather than a
/// separate `Err`. The wrapper returns `XWingDecapsulationFailed` only when
/// libcrux reports a structural / decode error (length mismatch and so on),
/// which is rare on production wire — callers must rely on AEAD tag binding
/// (V2 envelope + AAD coverage) to detect a mismatch, **not** on the
/// `XWingDecapsulationFailed` error path.
pub fn xwing_decaps(
    seed: &XWingSecretSeed,
    ct: &[u8; XWING_CIPHERTEXT_LEN],
) -> Result<SecretBox<[u8; XWING_SHARED_SECRET_LEN]>> {
    let sk_libcrux =
        libcrux_kem::PrivateKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, seed.expose())
            .map_err(|e| PqError::BackendError {
                message: format!("xwing sk decode: {e:?}"),
            })?;

    let ct_libcrux =
        libcrux_kem::Ct::decode(libcrux_kem::Algorithm::XWingKemDraft06, ct).map_err(|e| {
            PqError::BackendError {
                message: format!("xwing ct decode: {e:?}"),
            }
        })?;

    let ss = ct_libcrux
        .decapsulate(&sk_libcrux)
        .map_err(|_| PqError::XWingDecapsulationFailed)?;

    let ss_encoded = ss.encode();
    if ss_encoded.len() != XWING_SHARED_SECRET_LEN {
        return Err(PqError::BackendError {
            message: format!(
                "xwing ss length mismatch: got {}, expected {}",
                ss_encoded.len(),
                XWING_SHARED_SECRET_LEN
            ),
        });
    }
    let mut ss_buf = [0u8; XWING_SHARED_SECRET_LEN];
    ss_buf.copy_from_slice(&ss_encoded);

    Ok(SecretBox::new(Box::new(ss_buf)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Roundtrip keygen → encaps → decaps даёт совпадающий shared secret.
    /// Roundtrip keygen → encaps → decaps yields matching shared secret.
    #[test]
    fn xwing_roundtrip() {
        let mut rng = OsRng;
        let (pk, seed) = xwing_keygen(&mut rng).expect("keygen");
        let (ct, ss_sender) = xwing_encaps(&mut rng, &pk).expect("encaps");
        let ss_receiver = xwing_decaps(&seed, &ct).expect("decaps");
        assert_eq!(ss_sender.expose_secret(), ss_receiver.expose_secret());
    }

    /// Невалидный pk size → XWingInvalidPublicKey.
    #[test]
    fn xwing_invalid_pubkey_rejected() {
        let bad = [0u8; 100];
        let result = XWingPublicKey::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::XWingInvalidPublicKey { got: 100 })
        ));
    }

    /// Pubkey roundtrip serialize → deserialize даёт identical bytes.
    /// Pubkey roundtrip serialize → deserialize yields identical bytes.
    #[test]
    fn xwing_pubkey_byte_roundtrip() {
        let mut rng = OsRng;
        let (pk, _) = xwing_keygen(&mut rng).expect("keygen");
        let pk_bytes = pk.as_bytes();
        let pk_decoded = XWingPublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk_decoded.as_bytes(), pk_bytes);
    }

    /// Различные seed дают различные pk и ss.
    /// Different seeds yield different pks and ss.
    #[test]
    fn xwing_distinct_keygens_distinct_outputs() {
        let mut rng = OsRng;
        let (pk1, _) = xwing_keygen(&mut rng).expect("keygen1");
        let (pk2, _) = xwing_keygen(&mut rng).expect("keygen2");
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());
    }
}
