//! ML-KEM-768 (NIST FIPS 203) wrapper через `libcrux-ml-kem 0.0.8` derand API.
//! ML-KEM-768 (NIST FIPS 203) wrapper using `libcrux-ml-kem 0.0.8` derand API.
//!
//! Derand API используется потому что libcrux-ml-kem 0.0.8 принимает фиксированный
//! seed (`[u8; 64]` для keygen, `[u8; 32]` для encaps), что независимо от версии
//! `rand_core` в downstream. Наш API принимает `&mut R: RngCore + CryptoRng` от
//! workspace `rand_core 0.6` и наполняет нужный seed через `fill_bytes`.
//!
//! Derand API is used because libcrux-ml-kem 0.0.8 takes fixed-size seeds
//! (`[u8; 64]` for keygen, `[u8; 32]` for encaps), which is independent of the
//! downstream `rand_core` version. Our API accepts `&mut R: RngCore + CryptoRng`
//! from workspace `rand_core 0.6` and fills the required seed via `fill_bytes`.

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::constants::{
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPS_SEED_LEN, ML_KEM_768_KEYGEN_SEED_LEN,
    ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN, ML_KEM_768_SHARED_SECRET_LEN,
};
use crate::error::{PqError, Result};

/// ML-KEM-768 public key (1184 bytes по FIPS 203).
/// ML-KEM-768 public key (1184 bytes per FIPS 203).
#[derive(Clone)]
pub struct MlKem768PublicKey {
    bytes: [u8; ML_KEM_768_PUBLIC_KEY_LEN],
}

/// ML-KEM-768 secret key (2400 bytes по FIPS 203). Хранится в `SecretBox`
/// с автоматическим zeroize on drop.
/// ML-KEM-768 secret key (2400 bytes per FIPS 203). Stored in `SecretBox`
/// with automatic zeroize on drop.
pub struct MlKem768SecretKey {
    inner: SecretBox<[u8; ML_KEM_768_SECRET_KEY_LEN]>,
}

impl MlKem768PublicKey {
    /// Сериализация в bytes (ссылка, без копирования).
    /// Serialize to bytes (reference, no copy).
    pub fn as_bytes(&self) -> &[u8; ML_KEM_768_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(PqError::MlKemInvalidPublicKey { got: bytes.len() });
        }
        let mut buf = [0u8; ML_KEM_768_PUBLIC_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

impl MlKem768SecretKey {
    /// Десериализация из bytes; валидирует длину.
    /// Deserialize from bytes; validates length.
    ///
    /// **Warning:** caller обязан передать только bytes полученные из
    /// `ml_kem_768_keygen` или эквивалентного источника. Невалидный sk не
    /// детектируется на этом этапе (проверка структуры — только в decapsulate).
    ///
    /// **Warning:** the caller must only pass bytes produced by
    /// `ml_kem_768_keygen` or an equivalent source. An invalid sk is not
    /// detected at this stage (structural validation happens only in decapsulate).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_KEM_768_SECRET_KEY_LEN {
            return Err(PqError::MlKemInvalidSecretKey { got: bytes.len() });
        }
        let mut buf = [0u8; ML_KEM_768_SECRET_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self {
            inner: SecretBox::new(Box::new(buf)),
        })
    }

    /// Доступ к внутренним bytes (через `ExposeSecret`).
    /// Access raw bytes (via `ExposeSecret`).
    ///
    /// Используется только внутри umbrella-pq для bridge с libcrux. Downstream
    /// крейты не должны напрямую вызывать этот метод.
    ///
    /// Used internally within umbrella-pq for bridging with libcrux. Downstream
    /// crates should not call this method directly.
    pub(crate) fn expose(&self) -> &[u8; ML_KEM_768_SECRET_KEY_LEN] {
        self.inner.expose_secret()
    }
}

/// ML-KEM-768 KeyGen (FIPS 203 §7.1).
///
/// Генерирует пару (pk, sk) через 64-byte seed из `rng`. Использует
/// `libcrux_ml_kem::mlkem768::generate_key_pair` (formally hax-verified).
///
/// Generates a (pk, sk) pair via 64-byte seed from `rng`. Uses
/// `libcrux_ml_kem::mlkem768::generate_key_pair` (formally hax-verified).
pub fn ml_kem_768_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (MlKem768PublicKey, MlKem768SecretKey) {
    let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
    rng.fill_bytes(&mut seed);

    let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(seed);
    // libcrux-ml-kem types: as_slice() returns &[u8; SIZE], as_ref() returns &[u8].
    // libcrux-ml-kem types: as_slice() returns &[u8; SIZE], as_ref() returns &[u8].
    let pk_bytes: [u8; ML_KEM_768_PUBLIC_KEY_LEN] = *key_pair.public_key().as_slice();
    let sk_bytes: [u8; ML_KEM_768_SECRET_KEY_LEN] = *key_pair.private_key().as_slice();

    // Очищаем временный buffer keygen seed (64 bytes — два 32-byte компонента FIPS 203)
    // через zeroize::Zeroize ПОСЛЕ передачи в backend; ручной byte-loop subject к
    // LLVM dead-store elimination → row 11 Cold-boot/forensics.
    // Wipe the temporary keygen seed buffer (64 bytes — two 32-byte FIPS 203 components)
    // via zeroize::Zeroize AFTER passing to the backend; a manual byte-loop is subject
    // to LLVM dead-store elimination → threat row 11 Cold-boot/forensics.
    seed.zeroize();

    (
        MlKem768PublicKey { bytes: pk_bytes },
        MlKem768SecretKey {
            inner: SecretBox::new(Box::new(sk_bytes)),
        },
    )
}

/// ML-KEM-768 Encapsulation (FIPS 203 §7.2).
///
/// Возвращает `(ciphertext, shared_secret)` под `pk`. Random encaps seed
/// (`[u8; 32]`) генерируется через `rng.fill_bytes`.
///
/// Returns `(ciphertext, shared_secret)` under `pk`. Random encaps seed
/// (`[u8; 32]`) is generated via `rng.fill_bytes`.
pub fn ml_kem_768_encaps<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &MlKem768PublicKey,
) -> (
    [u8; ML_KEM_768_CIPHERTEXT_LEN],
    SecretBox<[u8; ML_KEM_768_SHARED_SECRET_LEN]>,
) {
    let mut seed = [0u8; ML_KEM_768_ENCAPS_SEED_LEN];
    rng.fill_bytes(&mut seed);

    let pk_libcrux = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(pk.bytes);
    // libcrux::encapsulate consumes seed by value (not by reference); создаём копию
    // через `seed` move, далее zeroize'им local stack copy.
    // libcrux::encapsulate consumes seed by value (not by reference); we make a copy
    // via the `seed` move, then zeroize the local stack copy.
    let (ct, ss) = libcrux_ml_kem::mlkem768::encapsulate(&pk_libcrux, seed);
    // Очищаем local stack copy of seed после consumption бекендом (зеркальная копия
    // потенциально остаётся в frame через move semantics).
    // Wipe the local stack copy of seed after backend consumption (the mirror copy
    // potentially remains in the frame via move semantics).
    seed.zeroize();

    let ct_bytes: [u8; ML_KEM_768_CIPHERTEXT_LEN] = *ct.as_slice();
    // MlKemSharedSecret = [u8; 32]
    let ss_bytes: [u8; ML_KEM_768_SHARED_SECRET_LEN] = ss;

    (ct_bytes, SecretBox::new(Box::new(ss_bytes)))
}

/// ML-KEM-768 Decapsulation (FIPS 203 §7.3).
///
/// Восстанавливает shared secret из ciphertext через secret key. Implicit
/// rejection: при corrupted ciphertext возвращается valid-looking но
/// pseudo-random shared secret (FIPS 203 design); это **НЕ** ошибка decapsulate
/// — caller должен сравнить полученный ss с ожидаемым на higher level.
///
/// Recovers shared secret from ciphertext using secret key. Implicit rejection:
/// for a corrupted ciphertext, a valid-looking but pseudo-random shared secret
/// is returned (FIPS 203 design); this is **NOT** a decapsulate error — the
/// caller should compare the obtained ss with the expected one at a higher level.
pub fn ml_kem_768_decaps(
    sk: &MlKem768SecretKey,
    ct: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
) -> SecretBox<[u8; ML_KEM_768_SHARED_SECRET_LEN]> {
    let sk_libcrux = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(*sk.expose());
    let ct_libcrux = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(*ct);

    let ss: [u8; ML_KEM_768_SHARED_SECRET_LEN] =
        libcrux_ml_kem::mlkem768::decapsulate(&sk_libcrux, &ct_libcrux);
    SecretBox::new(Box::new(ss))
}

/// Валидация incoming public key через libcrux validation (FIPS 203 §7.1).
/// Validate incoming public key via libcrux validation (FIPS 203 §7.1).
pub fn ml_kem_768_validate_public_key(pk: &MlKem768PublicKey) -> bool {
    let pk_libcrux = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(pk.bytes);
    libcrux_ml_kem::mlkem768::validate_public_key(&pk_libcrux)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use secrecy::ExposeSecret;

    /// Roundtrip keygen → encaps → decaps даёт совпадающий shared secret.
    /// Roundtrip keygen → encaps → decaps yields matching shared secret.
    #[test]
    fn ml_kem_768_roundtrip() {
        let mut rng = OsRng;
        let (pk, sk) = ml_kem_768_keygen(&mut rng);
        let (ct, ss_sender) = ml_kem_768_encaps(&mut rng, &pk);
        let ss_receiver = ml_kem_768_decaps(&sk, &ct);
        assert_eq!(ss_sender.expose_secret(), ss_receiver.expose_secret());
    }

    /// Невалидный pk size → MlKemInvalidPublicKey.
    #[test]
    fn ml_kem_768_invalid_pubkey_rejected() {
        let bad = [0u8; 100];
        let result = MlKem768PublicKey::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::MlKemInvalidPublicKey { got: 100 })
        ));
    }

    /// Невалидный sk size → MlKemInvalidSecretKey.
    #[test]
    fn ml_kem_768_invalid_seckey_rejected() {
        let bad = [0u8; 100];
        let result = MlKem768SecretKey::from_bytes(&bad);
        assert!(matches!(
            result,
            Err(PqError::MlKemInvalidSecretKey { got: 100 })
        ));
    }

    /// Pubkey roundtrip serialize → deserialize даёт identical bytes.
    /// Pubkey roundtrip serialize → deserialize yields identical bytes.
    #[test]
    fn ml_kem_768_pubkey_byte_roundtrip() {
        let mut rng = OsRng;
        let (pk, _) = ml_kem_768_keygen(&mut rng);
        let pk_bytes = pk.as_bytes();
        let pk_decoded = MlKem768PublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk_decoded.as_bytes(), pk_bytes);
    }

    /// Bit-flip ciphertext → decaps даёт ДРУГОЙ (не error, но другой) shared secret
    /// — это implicit rejection, FIPS 203 design.
    /// Bit-flip ciphertext → decaps gives DIFFERENT shared secret — implicit rejection per FIPS 203.
    #[test]
    fn ml_kem_768_ciphertext_bit_flip_implicit_rejection() {
        let mut rng = OsRng;
        let (pk, sk) = ml_kem_768_keygen(&mut rng);
        let (mut ct, ss_sender) = ml_kem_768_encaps(&mut rng, &pk);
        ct[100] ^= 0x01;
        let ss_receiver = ml_kem_768_decaps(&sk, &ct);
        assert_ne!(ss_sender.expose_secret(), ss_receiver.expose_secret());
    }

    /// validate_public_key принимает свежесгенерированный pk.
    /// validate_public_key accepts a freshly generated pk.
    #[test]
    fn ml_kem_768_freshly_generated_pubkey_validates() {
        let mut rng = OsRng;
        let (pk, _) = ml_kem_768_keygen(&mut rng);
        assert!(ml_kem_768_validate_public_key(&pk));
    }
}
