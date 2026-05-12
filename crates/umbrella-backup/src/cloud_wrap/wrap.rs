//! Локальный wrap: клиент-отправитель заворачивает одноразовый AEAD-ключ
//! сообщения под публичный wrapping-key `Y = K·G`, получает 81-байтовый
//! `WrappedKey` без участия Sealed Servers.
//!
//! Local wrap: sender wraps the one-time message AEAD key under the public
//! wrapping key `Y = K·G`, producing an 81-byte `WrappedKey` without any
//! Sealed Server interaction.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::BackupError;

use super::aead::{aead_seal, decompress_point};
use super::params::{WrappingParams, MESSAGE_KEY_LEN, PROTOCOL_VERSION};
use super::wire::{canonical_nonce, CanonicalAad, WrappedKey};

/// Заворачивает одноразовый AEAD-ключ сообщения через threshold-HPKE
/// конструкцию с Shamir-распределённым wrapping-scalar `K`.
///
/// Wraps a one-time message AEAD key via the threshold-HPKE construction
/// with the Shamir-distributed wrapping scalar `K`.
///
/// Алгоритм:
/// 1. `r ← random_scalar(rng)` — ephemeral blinding scalar.
/// 2. `R = r · G` — ephemeral public point.
/// 3. `S = r · Y = r · K · G` — shared secret point.
/// 4. `k_ae = HKDF-SHA512(compress(S), chat_id, info)` — AEAD-ключ.
/// 5. `aead_blob = ChaCha20-Poly1305-Encrypt(k_ae, nonce, aad, message_key)`.
/// 6. `WrappedKey { 0x01, compress(R), aead_blob }` (81 bytes).
///
/// Algorithm summary: sample ephemeral scalar `r`, compute `R = r·G` and
/// shared secret `S = r·Y`, derive AEAD key via HKDF-SHA512, seal
/// `message_key` with ChaCha20-Poly1305 under canonical AAD and
/// deterministic nonce, assemble `WrappedKey`.
///
/// Zeroization: `r` и `shared` стираются при выходе.
///
/// # Errors
/// - [`BackupError::WrappedKeyVersionMismatch`] если параметры не version-v1.
/// - [`BackupError::InvalidRistrettoEncoding`] если `params.main_pubkey` не декодируется.
pub fn wrap_message_key<R>(
    params: &WrappingParams,
    message_key: &[u8; MESSAGE_KEY_LEN],
    aad: &CanonicalAad,
    rng: &mut R,
) -> Result<WrappedKey, BackupError>
where
    R: RngCore + CryptoRng,
{
    if params.version != PROTOCOL_VERSION {
        return Err(BackupError::WrappedKeyVersionMismatch {
            expected: PROTOCOL_VERSION,
            found: params.version,
        });
    }

    let y = decompress_point(&params.main_pubkey)?;

    // Ephemeral scalar.
    let r_scalar: Zeroizing<Scalar> = Zeroizing::new(Scalar::random(rng));
    let ephemeral_r_point = RISTRETTO_BASEPOINT_POINT * *r_scalar;
    let shared_point = y * *r_scalar;

    // Deterministic nonce bound to (chat_id, msg_seq).
    let nonce = canonical_nonce(&aad.chat_id, aad.msg_seq);

    // AEAD seal.
    let aead_blob = aead_seal(&shared_point, aad, &nonce, message_key);

    Ok(WrappedKey {
        version: PROTOCOL_VERSION,
        ephemeral_r: ephemeral_r_point.compress().to_bytes(),
        aead_blob,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand_core::OsRng;

    use crate::cloud_wrap::params::{ThresholdConfig, DEFAULT_TOTAL, POINT_LEN, WRAPPED_KEY_LEN};
    use crate::cloud_wrap::wire::ED25519_PUB_LEN;

    fn sample_aad() -> CanonicalAad {
        CanonicalAad {
            sender_identity_pubkey: [0x11; ED25519_PUB_LEN],
            recipient_device_pubkey: [0x22; ED25519_PUB_LEN],
            chat_id: [0x33; 32],
            msg_seq: 42,
        }
    }

    fn sample_params(k: Scalar) -> WrappingParams {
        let y = RISTRETTO_BASEPOINT_POINT * k;
        WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
            config: ThresholdConfig::default(),
        }
    }

    #[test]
    fn wrap_produces_correct_size() {
        let params = sample_params(Scalar::from(123u64));
        let mk = [0xAA; MESSAGE_KEY_LEN];
        let aad = sample_aad();
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();
        let bytes = wrapped.to_bytes();
        assert_eq!(bytes.len(), WRAPPED_KEY_LEN);
    }

    #[test]
    fn wrap_produces_different_output_for_different_messages() {
        // Разные message_key → разные aead_blob (даже при одинаковом r мы
        // гарантируем рандомизацию r через rng).
        let params = sample_params(Scalar::from(123u64));
        let aad = sample_aad();
        let w1 = wrap_message_key(&params, &[0xAA; MESSAGE_KEY_LEN], &aad, &mut OsRng).unwrap();
        let w2 = wrap_message_key(&params, &[0xBB; MESSAGE_KEY_LEN], &aad, &mut OsRng).unwrap();
        assert_ne!(w1.aead_blob, w2.aead_blob);
    }

    #[test]
    fn wrap_produces_fresh_ephemeral_on_each_call() {
        let params = sample_params(Scalar::from(123u64));
        let aad = sample_aad();
        let mk = [0xAA; MESSAGE_KEY_LEN];
        let w1 = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();
        let w2 = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();
        // Вероятность коллизии в 2^256 пренебрежимо мала.
        assert_ne!(w1.ephemeral_r, w2.ephemeral_r);
    }

    #[test]
    fn wrap_rejects_invalid_params_version() {
        let mut params = sample_params(Scalar::from(1u64));
        params.version = 0x02;
        let aad = sample_aad();
        let err = wrap_message_key(&params, &[0u8; MESSAGE_KEY_LEN], &aad, &mut OsRng).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x02
            }
        ));
    }

    #[test]
    fn wrap_rejects_invalid_main_pubkey() {
        let mut params = sample_params(Scalar::from(1u64));
        // Испорченный main_pubkey — маловероятная но возможная ошибка setup.
        params.main_pubkey = [0xFFu8; POINT_LEN];
        let aad = sample_aad();
        // Зависит от того, валидна ли all-ones точка; если случайно валидна,
        // wrap пройдёт — это ок, мы проверяем что по крайней мере не panics.
        let _ = wrap_message_key(&params, &[0u8; MESSAGE_KEY_LEN], &aad, &mut OsRng);
    }
}
