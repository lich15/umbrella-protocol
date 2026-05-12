//! Ed25519 подписи: только Ed25519, никакого ECDSA (митигация ETK eprint 2025/229).
//! Ed25519 signatures: Ed25519 only, no ECDSA (ETK eprint 2025/229 mitigation).

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

/// Размер Ed25519 публичного ключа в байтах.
/// Ed25519 public key size in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Размер Ed25519 подписи в байтах.
/// Ed25519 signature size in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Размер Ed25519 секретного скаляра в байтах.
/// Ed25519 secret scalar size in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Приватный ключ подписи Ed25519; обнуляется при Drop.
/// Ed25519 signing private key; zeroized on Drop.
#[derive(ZeroizeOnDrop)]
pub struct PrivateSigningKey(SigningKey);

impl PrivateSigningKey {
    /// Генерирует новый приватный ключ из CSPRNG.
    /// Generates a new signing key from a CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; SECRET_KEY_LEN];
        rng.fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        // Очищаем временный буфер seed через zeroize::Zeroize (volatile-write semantics);
        // ручной byte-loop `seed.iter_mut().for_each(|b| *b = 0)` могла бы быть удалена
        // компилятором как dead store в release-сборке (LLVM dead-store elimination).
        // Wipe the temporary seed buffer via zeroize::Zeroize (volatile-write semantics);
        // a manual byte-loop `seed.iter_mut().for_each(|b| *b = 0)` could be elided by the
        // compiler as a dead store in release builds (LLVM dead-store elimination).
        seed.zeroize();
        Self(key)
    }

    /// Восстанавливает приватный ключ из 32-байтового seed.
    /// Restores the signing key from a 32-byte seed.
    pub fn from_seed(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Возвращает соответствующий публичный ключ.
    /// Returns the matching public verifying key.
    pub fn verifying_key(&self) -> PublicVerifyingKey {
        PublicVerifyingKey(self.0.verifying_key())
    }

    /// Подписывает сообщение чистым Ed25519 (PureEdDSA, RFC 8032).
    /// Signs a message with pure Ed25519 (PureEdDSA, RFC 8032).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(message))
    }

    /// Возвращает байтовое представление seed (для secure storage).
    /// Returns the seed byte representation (for secure storage).
    pub fn to_seed_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }
}

/// Публичный verifying key Ed25519.
/// Ed25519 public verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicVerifyingKey(VerifyingKey);

impl PublicVerifyingKey {
    /// Восстанавливает публичный ключ из 32 байт; проверяет что это валидная точка curve25519.
    /// Restores the verifying key from 32 bytes; validates it is a curve25519 point.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Возвращает байтовое представление публичного ключа.
    /// Returns the byte representation of the verifying key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Проверяет подпись сообщения; возвращает Ok при валидной подписи.
    /// Verifies a message signature; returns Ok if valid.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Подпись Ed25519 длиной 64 байта.
/// 64-byte Ed25519 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature(DalekSig);

impl Ed25519Signature {
    /// Восстанавливает подпись из 64 байт; никакой валидации до verify.
    /// Restores a signature from 64 bytes; no validation until verify.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self(DalekSig::from_bytes(bytes))
    }

    /// Возвращает байтовое представление подписи.
    /// Returns the signature byte representation.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = sk.verifying_key();
        let msg = b"umbrella-protocol stage-1";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("valid signature must verify");
    }

    #[test]
    fn tampered_message_fails_verification() {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(pk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk = sk.verifying_key();
        let sig = sk.sign(b"msg");
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0x01;
        let bad = Ed25519Signature::from_bytes(&bytes);
        assert!(pk.verify(b"msg", &bad).is_err());
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 §7.1 test vector 1.
        let seed = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected_pk = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected_sig = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let sk = PrivateSigningKey::from_seed(&seed);
        let pk = sk.verifying_key();
        assert_eq!(pk.to_bytes(), expected_pk);

        let sig = sk.sign(&[]);
        assert_eq!(sig.to_bytes(), expected_sig);
        pk.verify(&[], &sig).expect("RFC 8032 vector must verify");
    }
}
