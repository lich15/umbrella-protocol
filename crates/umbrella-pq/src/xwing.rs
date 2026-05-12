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
//! Бэкенд: `libcrux-kem 0.0.7` через API-имя `Algorithm::XWingKemDraft06`.
//! Реальный вывод закреплён официальным draft-10 Appendix C KAT в
//! `tests/xwing_draft10_kat.rs`; отличие имени upstream API от draft-10
//! документальное, не wire-format mismatch. Используется derand API чтобы
//! обойти несовместимость `rand_core` версий между libcrux (0.9) и нашим
//! workspace (0.6).
//!
//! Backend: `libcrux-kem 0.0.7` via the upstream API name
//! `Algorithm::XWingKemDraft06`. Actual output is pinned against the official
//! draft-10 Appendix C KAT in `tests/xwing_draft10_kat.rs`; the upstream API
//! name is documentary drift, not a wire-format mismatch. Uses derand API to
//! bypass `rand_core` version incompatibility between libcrux (0.9) and our
//! workspace (0.6).

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::constants::{
    XWING_CIPHERTEXT_LEN, XWING_ENCAPS_SEED_LEN, XWING_KEYGEN_SEED_LEN, XWING_PUBLIC_KEY_LEN,
    XWING_SECRET_SEED_LEN, XWING_SHARED_SECRET_LEN,
};
use crate::error::{PqError, Result};

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
    let result = xwing_encaps_derand(pk, &seed);
    // Очищаем временный buffer encaps seed (32 bytes ML-KEM + 32 bytes X25519 ephemeral)
    // через zeroize::Zeroize ДО возврата — независимо от success/error backend'а.
    // Wipe the temporary encaps seed buffer (32-byte ML-KEM + 32-byte X25519 ephemeral)
    // via zeroize::Zeroize BEFORE returning — independent of backend success/error.
    seed.zeroize();
    result
}

/// Deterministic X-Wing encapsulation using the 64-byte `eseed` from the
/// draft-connolly-cfrg-xwing-kem-10 `EncapsulateDerand(pk, eseed)` interface.
///
/// This is primarily a KAT/reproducibility hook. Production callers should
/// prefer [`xwing_encaps`], which fills `eseed` from a CSPRNG and zeroizes the
/// temporary seed before returning.
pub fn xwing_encaps_derand(
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
/// Восстанавливает shared secret из ciphertext через secret seed. При
/// corrupted ciphertext возвращает `XWingDecapsulationFailed` (X-Wing
/// combiner отвергает invalid X25519 части явно — не implicit rejection
/// как в pure ML-KEM).
///
/// Recovers shared secret from ciphertext using secret seed. On corrupted
/// ciphertext returns `XWingDecapsulationFailed` (X-Wing combiner explicitly
/// rejects invalid X25519 parts — not implicit rejection like in pure ML-KEM).
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
