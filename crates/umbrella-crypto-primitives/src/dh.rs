//! X25519 Diffie-Hellman; RFC 7748. Shared secret обёрнут SecretBytes для zeroize.
//! X25519 Diffie-Hellman; RFC 7748. Shared secret wrapped in SecretBytes for zeroize.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::error::Result;
use crate::secret::SecretBytes;

/// Размер X25519 публичного ключа в байтах.
/// X25519 public key size in bytes.
pub const X25519_PUBLIC_LEN: usize = 32;

/// Размер X25519 секретного скаляра в байтах.
/// X25519 secret scalar size in bytes.
pub const X25519_SECRET_LEN: usize = 32;

/// Размер X25519 shared secret в байтах.
/// X25519 shared secret size in bytes.
pub const X25519_SHARED_LEN: usize = 32;

/// Долгоживущий приватный X25519 ключ; обнуляется при Drop.
/// Long-lived X25519 private key; zeroized on Drop.
#[derive(ZeroizeOnDrop)]
pub struct X25519Static(StaticSecret);

impl X25519Static {
    /// Генерирует новый ключ из CSPRNG.
    /// Generates a new key from a CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    /// Восстанавливает ключ из 32-байтового scalar.
    /// Restores the key from a 32-byte scalar.
    pub fn from_bytes(bytes: [u8; X25519_SECRET_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Возвращает соответствующий публичный ключ.
    /// Returns the corresponding public key.
    pub fn public_key(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0))
    }

    /// Вычисляет shared secret через ECDH с указанным публичным ключом.
    /// Computes a shared secret via ECDH with the given public key.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> SecretBytes<X25519_SHARED_LEN> {
        let shared = self.0.diffie_hellman(&peer.0);
        SecretBytes::new(*shared.as_bytes())
    }
}

/// Эфемерный X25519 секрет (живёт один handshake); обнуляется при Drop.
/// Ephemeral X25519 secret (single-handshake lifetime); zeroized on Drop.
#[derive(ZeroizeOnDrop)]
pub struct X25519Ephemeral(ReusableSecret);

impl X25519Ephemeral {
    /// Генерирует эфемерный ключ из CSPRNG.
    /// Generates an ephemeral key from a CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(ReusableSecret::random_from_rng(rng))
    }

    /// Возвращает публичный ключ эфемерного секрета.
    /// Returns the public key of the ephemeral secret.
    pub fn public_key(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0))
    }

    /// Вычисляет shared secret через ECDH.
    /// Computes a shared secret via ECDH.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> SecretBytes<X25519_SHARED_LEN> {
        let shared = self.0.diffie_hellman(&peer.0);
        SecretBytes::new(*shared.as_bytes())
    }
}

/// Публичный X25519 ключ; не секрет, можно свободно копировать.
/// X25519 public key; not a secret, freely copyable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519Public(PublicKey);

impl X25519Public {
    /// Создаёт публичный ключ из 32 байт; RFC 7748 §6 принимает любые 32 байта.
    /// Внутренняя clamping и cofactor-multiplication устраняют наиболее очевидные
    /// атаки малых порядков; downstream HPKE / X-Wing combiner предоставляют
    /// дополнительные слои защиты. Если caller получает peer public key из
    /// untrusted source и хочет явный low-order detection — используйте
    /// `SharedSecret::was_contributory()` от x25519-dalek 2.0 после `diffie_hellman`.
    ///
    /// Constructs a public key from 32 bytes; per RFC 7748 §6 any 32 bytes are accepted.
    /// Internal clamping and cofactor-multiplication eliminate the most obvious low-order
    /// attacks; downstream HPKE / X-Wing combiners provide additional defence layers.
    /// If the caller receives a peer public key from an untrusted source and wants
    /// explicit low-order detection, use `SharedSecret::was_contributory()` from
    /// x25519-dalek 2.0 after `diffie_hellman`.
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_LEN]) -> Result<Self> {
        Ok(Self(PublicKey::from(bytes)))
    }

    /// Возвращает байтовое представление публичного ключа.
    /// Returns the byte representation of the public key.
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_LEN] {
        *self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn dh_round_trip_static() {
        let mut rng = OsRng;
        let alice = X25519Static::generate(&mut rng);
        let bob = X25519Static::generate(&mut rng);
        let s_a = alice.diffie_hellman(&bob.public_key());
        let s_b = bob.diffie_hellman(&alice.public_key());
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn dh_round_trip_ephemeral() {
        let mut rng = OsRng;
        let alice = X25519Ephemeral::generate(&mut rng);
        let bob = X25519Ephemeral::generate(&mut rng);
        let s_a = alice.diffie_hellman(&bob.public_key());
        let s_b = bob.diffie_hellman(&alice.public_key());
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn rfc7748_test_vector_section_6_1() {
        // RFC 7748 §6.1 — Curve25519 X25519 sample handshake.
        let alice_priv: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_priv: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected_shared: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        let alice = X25519Static::from_bytes(alice_priv);
        let bob = X25519Static::from_bytes(bob_priv);
        let shared = alice.diffie_hellman(&bob.public_key());
        assert_eq!(shared.expose(), &expected_shared);
    }
}
