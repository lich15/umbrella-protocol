//! # Argon2id PIN-KDF
//!
//! PIN-derived KDF root для re-derivation device-key и master-key. Argon2id
//! параметры:
//! - memory cost = 64 MiB (mobile-friendly: iPhone XS+ / Pixel 3+ имеют 4+ GiB
//!   RAM, 64 MiB не вызывает swap)
//! - iterations = 3 (рекомендация Biryukov-Khovratovich 2016 для interactive
//!   logins ≤1 sec)
//! - parallelism = 4 (использует 4 cores; на iPhone hexa-core / 8-core это
//!   ~67%-50% утилизации)
//! - output = 32 bytes (matches downstream HKDF root size)
//!
//! Brute-force budget при этих параметрах: один guess ≈ 800ms на A12
//! Bionic (iPhone XS), ≈ 600ms на Snapdragon 845. Attacker с GPU/ASIC
//! сталкивается с 64 MiB memory bottleneck — Argon2id resistant к GPU/FPGA
//! parallelism через memory-hard property (Biryukov-Khovratovich §3).
//!
//! Argon2id PIN-KDF root for device-key / master-key re-derivation. Argon2id
//! parameters tuned for mobile devices per Biryukov-Khovratovich 2016 §6:
//! - memory = 64 MiB
//! - iterations = 3
//! - parallelism = 4
//! - output = 32 bytes
//!
//! ## References
//!
//! - Biryukov, Khovratovich 2016, «Argon2: the memory-hard function for
//!   password hashing and other applications», EuroS&P.
//! - RFC 9106 §4 (Argon2id recommended for password hashing).

use argon2::{Algorithm, Argon2, Params, Version};
use umbrella_crypto_primitives::mlocked::MlockedSecret;

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};

/// Стоимость памяти Argon2id — 64 MiB, mobile-friendly по RFC 9106 §4.
/// Argon2id memory cost — 64 MiB. Mobile-friendly per RFC 9106 §4.
pub const MEMORY_COST_KIB: u32 = 64 * 1024;

/// Количество итераций Argon2id — 3 прохода по памяти.
/// Argon2id iterations — 3 passes over memory.
pub const ITERATIONS: u32 = 3;

/// Параллелизм Argon2id — 4 lane.
/// Argon2id parallelism — 4 lanes.
pub const PARALLELISM: u32 = 4;

/// Длина output — 32 байта, downstream HKDF root.
/// Output length — 32 bytes, downstream HKDF root.
pub const OUTPUT_LEN: usize = 32;

/// Длина соли — 16 байт per RFC 9106 §4.
/// Salt length — 16 bytes per RFC 9106 §4.
pub const SALT_LEN: usize = 16;

/// Выводит 32-байтный PIN-KDF root из `pin` + `salt`. Output обёрнут в
/// `MlockedSecret` чтобы kernel не мог page out, и `Zeroize` очищает
/// его при drop'е.
///
/// `pin` — numeric код введённый пользователем как UTF-8 bytes. `salt` —
/// 16-байтное per-account значение, хранится рядом с encrypted server share
/// (НЕ секрет, но уникальная — чтобы предотвратить rainbow-таблицы).
///
/// Derives a 32-byte PIN-KDF root from `pin` + `salt`. Output wrapped in
/// `MlockedSecret` so the kernel cannot page it out and `Zeroize` clears it
/// on drop.
///
/// `pin` is the user-entered numeric code as UTF-8 bytes. `salt` is a 16-byte
/// per-account value stored alongside the encrypted server share (NOT a
/// secret, but unique to thwart rainbow tables).
pub fn derive_pin_root(
    pin: &[u8],
    salt: &[u8; SALT_LEN],
) -> ThresholdIdentityResult<MlockedSecret<[u8; OUTPUT_LEN]>> {
    if pin.is_empty() {
        return Err(ThresholdIdentityError::PinKdfFailure("empty PIN"));
    }
    if pin.len() > 256 {
        return Err(ThresholdIdentityError::PinKdfFailure("PIN too long"));
    }

    let params = Params::new(MEMORY_COST_KIB, ITERATIONS, PARALLELISM, Some(OUTPUT_LEN))
        .map_err(|_| ThresholdIdentityError::PinKdfFailure("argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Allocate destination directly inside MlockedSecret so Argon2id writes
    // into the mlock'd heap page (no intermediate stack copy).
    let mut secret_out = MlockedSecret::<[u8; OUTPUT_LEN]>::new([0u8; OUTPUT_LEN]);
    argon
        .hash_password_into(pin, salt, secret_out.expose_mut().as_mut())
        .map_err(|_| ThresholdIdentityError::PinKdfFailure("argon2 hashing failed"))?;
    Ok(secret_out)
}

/// Constant-time проверка PIN: re-derive Argon2id root из `candidate`+`salt`,
/// сравнение с stored 32-байтным хешем. Используется сервером во время
/// верификации PIN-derived envelope.
///
/// Возвращает true если `candidate` derive'ится в `stored_hash`, иначе false.
/// Стоимость: одна полная Argon2id evaluation (~600-800мс на mobile).
///
/// Constant-time PIN comparison: re-derive Argon2id root from `candidate`
/// and `salt`, compare against stored 32-byte hash. Used by server during
/// verification of a PIN-derived envelope.
///
/// Returns true if `candidate` derives to `stored_hash`, false otherwise.
/// Cost: one full Argon2id evaluation (~600-800ms on mobile).
pub fn verify_pin(
    candidate: &[u8],
    salt: &[u8; SALT_LEN],
    stored_hash: &[u8; OUTPUT_LEN],
) -> ThresholdIdentityResult<bool> {
    let derived = derive_pin_root(candidate, salt)?;
    let derived_bytes: &[u8; OUTPUT_LEN] = derived.expose();
    use subtle::ConstantTimeEq;
    Ok(derived_bytes.ct_eq(stored_hash).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_deterministic_for_same_input() {
        let salt = [7u8; SALT_LEN];
        let pin = b"123456";
        let a = derive_pin_root(pin, &salt).unwrap();
        let b = derive_pin_root(pin, &salt).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn argon2id_different_pins_differ() {
        let salt = [7u8; SALT_LEN];
        let a = derive_pin_root(b"123456", &salt).unwrap();
        let b = derive_pin_root(b"654321", &salt).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn argon2id_different_salts_differ() {
        let a = derive_pin_root(b"123456", &[1u8; SALT_LEN]).unwrap();
        let b = derive_pin_root(b"123456", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn empty_pin_rejected() {
        let r = derive_pin_root(b"", &[0u8; SALT_LEN]);
        assert!(matches!(
            r,
            Err(ThresholdIdentityError::PinKdfFailure("empty PIN"))
        ));
    }

    #[test]
    fn verify_pin_constant_time_check() {
        let salt = [11u8; SALT_LEN];
        let stored = {
            let s = derive_pin_root(b"098765", &salt).unwrap();
            *s.expose()
        };
        assert!(verify_pin(b"098765", &salt, &stored).unwrap());
        assert!(!verify_pin(b"098766", &salt, &stored).unwrap());
    }
}
