//! SPQR (Sparse Post-Quantum Ratchet) — отрицаемая аутентификация поверх каждого
//! application-сообщения.
//!
//! **Концепция отрицаемости:**
//! - У отправителя и получателя одинаковый эпоховый секрет (выведен из MLS exporter_secret)
//! - HMAC-SHA256 над ciphertext_bytes вычисляется с этим общим секретом
//! - Получатель проверяет MAC → знает что сообщение пришло от другой стороны (сам бы он
//!   мог forge но знает что не делал)
//! - **Третье лицо** (суд, атакующий) **не может математически доказать** кто из двух
//!   собеседников создал MAC — оба знают ключ, оба могли бы forge
//! - Это и есть отрицаемость в стиле OTR (Off-the-Record), применённая per-message
//!
//! **Post-quantum расширение** ([`pq_extend_epoch_secret`]): когда commit включал
//! X-Wing PQ extension, epoch_secret дополнительно прогоняется через HKDF с X-Wing
//! shared secret. Защита от квантового противника который мог бы вычислить
//! classical-only epoch_secret из observed commits.
//!
//! **Domain separation labels:**
//! - `"umbrellax-spqr-epoch-v1"` для базового derivation из exporter_secret
//! - `"umbrellax-spqr-pq-extend-v1"` для PQ-расширения
//!
//! SPQR (Sparse Post-Quantum Ratchet) — deniable authentication on every application
//! message.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Длина SPQR HMAC в байтах (HMAC-SHA256 → 32 байта).
/// SPQR HMAC length in bytes (HMAC-SHA256 → 32 bytes).
pub const SPQR_HMAC_LEN: usize = 32;

/// Вычисляет HMAC-SHA256(epoch_secret, message) → 32 байта.
///
/// Computes HMAC-SHA256(epoch_secret, message) → 32 bytes.
pub fn compute_hmac(epoch_secret: &[u8; 32], message: &[u8]) -> [u8; SPQR_HMAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(epoch_secret)
        .expect("HMAC-SHA256 accepts any key length up to block size");
    mac.update(message);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; SPQR_HMAC_LEN];
    output.copy_from_slice(&result);
    output
}

/// Проверяет валидность HMAC для (epoch_secret, message).
///
/// **Constant-time:** использует [`Mac::verify_slice`] который constant-time для защиты
/// от timing-side-channel атак.
///
/// Verifies the HMAC for (epoch_secret, message). Constant-time via
/// [`Mac::verify_slice`].
pub fn verify_hmac(epoch_secret: &[u8; 32], message: &[u8], mac_bytes: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(epoch_secret) else {
        return false;
    };
    mac.update(message);
    mac.verify_slice(mac_bytes).is_ok()
}

/// Выводит 32-байтовый epoch_secret из MLS exporter_secret через HKDF-SHA256.
///
/// Domain separation label: `"umbrellax-spqr-epoch-v1"` (per umbrella-crypto-primitives
/// convention `umbrellax-<purpose>-v1`).
///
/// Derives a 32-byte epoch_secret from the MLS exporter_secret via HKDF-SHA256. Domain
/// separation label: `"umbrellax-spqr-epoch-v1"`.
pub fn derive_epoch_secret_from_exporter(exporter_secret: &[u8]) -> Result<[u8; 32], &'static str> {
    let secret_bytes = umbrella_crypto_primitives::kdf::hkdf_sha256::<32>(
        b"",
        exporter_secret,
        b"umbrellax-spqr-epoch-v1",
    )
    .map_err(|_| "SPQR epoch secret HKDF derivation failed")?;

    let mut out = [0u8; 32];
    out.copy_from_slice(secret_bytes.expose());
    Ok(out)
}

/// Расширяет epoch_secret post-quantum X-Wing shared secret через HKDF-SHA256.
///
/// Используется когда commit включал X-Wing PQ extension (counter triggers через
/// `pq_ratchet_every_n_commits`). Защита от квантового противника. `pq_shared_secret`
/// извлекается из MLS exporter под label `"umbrellax-max-ratchet-pq-shared-v1"` через
/// [`UmbrellaGroup::force_rekey_with_pq`](crate::group::UmbrellaGroup::force_rekey_with_pq).
/// Domain separation label HKDF: `"umbrellax-spqr-pq-extend-v1"`.
///
/// Extends epoch_secret with a post-quantum X-Wing shared secret via HKDF-SHA256. Used
/// when the commit included an X-Wing PQ extension (counter triggers via
/// `pq_ratchet_every_n_commits`). Defends against a quantum adversary. `pq_shared_secret`
/// is extracted from the MLS exporter under label `"umbrellax-max-ratchet-pq-shared-v1"`
/// via `UmbrellaGroup::force_rekey_with_pq`. HKDF domain separation label:
/// `"umbrellax-spqr-pq-extend-v1"`.
pub fn pq_extend_epoch_secret(
    classical_epoch_secret: &[u8; 32],
    pq_shared_secret: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(classical_epoch_secret);
    combined[32..].copy_from_slice(pq_shared_secret);

    let secret = umbrella_crypto_primitives::kdf::hkdf_sha256::<32>(
        b"",
        &combined,
        b"umbrellax-spqr-pq-extend-v1",
    )
    .map_err(|_| "SPQR PQ-extension HKDF derivation failed")?;

    let mut out = [0u8; 32];
    out.copy_from_slice(secret.expose());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_deterministic_for_same_inputs() {
        let secret = [1u8; 32];
        let message = b"deterministic test";

        let m1 = compute_hmac(&secret, message);
        let m2 = compute_hmac(&secret, message);

        assert_eq!(m1, m2, "HMAC must be deterministic for same inputs");
    }

    #[test]
    fn hmac_changes_when_message_changes() {
        let secret = [1u8; 32];
        let m1 = compute_hmac(&secret, b"hello");
        let m2 = compute_hmac(&secret, b"world");
        assert_ne!(m1, m2);
    }

    #[test]
    fn hmac_changes_when_secret_changes() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let m1 = compute_hmac(&s1, b"test");
        let m2 = compute_hmac(&s2, b"test");
        assert_ne!(m1, m2);
    }

    #[test]
    fn verify_accepts_correct_mac() {
        let secret = [42u8; 32];
        let message = b"authenticate me";

        let mac = compute_hmac(&secret, message);
        assert!(verify_hmac(&secret, message, &mac));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let secret = [42u8; 32];
        let mac = compute_hmac(&secret, b"original");
        assert!(!verify_hmac(&secret, b"different", &mac));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let secret = [1u8; 32];
        let mac = compute_hmac(&secret, b"msg");
        let other_secret = [2u8; 32];
        assert!(!verify_hmac(&other_secret, b"msg", &mac));
    }

    #[test]
    fn verify_rejects_wrong_length_mac() {
        let secret = [0u8; 32];
        assert!(!verify_hmac(&secret, b"msg", &[0u8; 16]));
        assert!(!verify_hmac(&secret, b"msg", &[0u8; 64]));
    }

    #[test]
    fn derive_epoch_secret_produces_32_bytes() {
        let exporter = [9u8; 48];
        let result = derive_epoch_secret_from_exporter(&exporter).expect("HKDF ok");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn derive_epoch_secret_is_deterministic() {
        let exporter = [7u8; 48];
        let r1 = derive_epoch_secret_from_exporter(&exporter).unwrap();
        let r2 = derive_epoch_secret_from_exporter(&exporter).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn pq_extend_produces_32_bytes() {
        let classical = [1u8; 32];
        let pq = [2u8; 32];
        let extended = pq_extend_epoch_secret(&classical, &pq).expect("HKDF ok");
        assert_eq!(extended.len(), 32);
    }

    #[test]
    fn pq_extend_differs_from_classical_only() {
        let classical = [1u8; 32];
        let pq = [2u8; 32];
        let extended = pq_extend_epoch_secret(&classical, &pq).unwrap();
        // Extended secret must NOT equal classical (otherwise PQ adds no value).
        assert_ne!(extended, classical);
    }

    #[test]
    fn pq_extend_is_sensitive_to_both_inputs() {
        let r1 = pq_extend_epoch_secret(&[1u8; 32], &[2u8; 32]).unwrap();
        let r2 = pq_extend_epoch_secret(&[1u8; 32], &[3u8; 32]).unwrap();
        let r3 = pq_extend_epoch_secret(&[9u8; 32], &[2u8; 32]).unwrap();
        assert_ne!(r1, r2);
        assert_ne!(r1, r3);
        assert_ne!(r2, r3);
    }
}
