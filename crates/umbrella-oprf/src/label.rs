//! 32-байтовая стабильная метка OPRF-выхода. 32-byte stable OPRF output label.
//!
//! Значение детерминистически выводится из (input, k) — любые два клиента с
//! одинаковыми `(input, k)` получают один и тот же `OprfLabel`. Это даёт
//! механизм контактной сверки: две адресные книги с совпадающим номером
//! производят одинаковые labels, и сервер по индексу `label → account_id`
//! отвечает «существует ли такой аккаунт», не зная самого номера.
//!
//! Derived deterministically from `(input, k)`. Two clients with the same
//! `(input, k)` obtain the same `OprfLabel`, enabling contact matching
//! without revealing the underlying identifier.
//!
//! Сравнение — **constant-time** через `subtle::ConstantTimeEq`, чтобы
//! атакующий не мог bit-by-bit восстановить метку через timing side-channel
//! сервера (на клиенте этот риск ограничен, но соблюдаем правило).
//!
//! Equality is constant-time via `subtle::ConstantTimeEq` to avoid byte-wise
//! recovery through timing side-channels.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Длина метки в байтах (первые 32 из SHA-512 OPRF output).
/// Label length (first 32 bytes of SHA-512 OPRF output).
pub const LABEL_LEN: usize = 32;

/// 32-байтовая OPRF-метка. 32-byte OPRF label.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OprfLabel([u8; LABEL_LEN]);

impl OprfLabel {
    /// Обернуть известный 32-байтовый массив. Wrap a known 32-byte array.
    ///
    /// Используется только внутри крейта (для finalize) и в тестах. Внешний
    /// код получает `OprfLabel` исключительно через `primitives::finalize`.
    ///
    /// Internal (crate-private for finalize) and test-only constructor.
    /// External code obtains `OprfLabel` only via `primitives::finalize`.
    #[inline]
    #[must_use]
    pub(crate) fn from_bytes(bytes: [u8; LABEL_LEN]) -> Self {
        Self(bytes)
    }

    /// Сырые байты метки. Underlying raw bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LABEL_LEN] {
        &self.0
    }

    /// Байтовая копия метки. Byte copy of the label.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LABEL_LEN] {
        self.0
    }
}

impl ConstantTimeEq for OprfLabel {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for OprfLabel {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for OprfLabel {}

impl fmt::Debug for OprfLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OprfLabel")
            .field(&"<redacted 32 bytes>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_content() {
        // Два разных значения должны дать одинаковый Debug output (сам по
        // себе indicator что байты не утекают в форматирование).
        let a = OprfLabel::from_bytes([0xAB; LABEL_LEN]);
        let b = OprfLabel::from_bytes([0x00; LABEL_LEN]);
        let sa = format!("{a:?}");
        let sb = format!("{b:?}");
        assert_eq!(sa, sb, "Debug differs between labels — bytes leaking");
        assert!(sa.contains("redacted"));
        // Hex кодировка конкретных байт НЕ должна появляться в выводе.
        assert!(
            !sa.contains("ab ab"),
            "repeated hex bytes found in Debug output"
        );
        assert!(!sa.contains("AB AB"));
        assert!(!sa.contains("0xab"));
        assert!(!sa.contains("0xAB"));
    }

    #[test]
    fn ct_eq_same_bytes() {
        let a = OprfLabel::from_bytes([1; LABEL_LEN]);
        let b = OprfLabel::from_bytes([1; LABEL_LEN]);
        assert_eq!(a, b);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn ct_eq_different_bytes() {
        let a = OprfLabel::from_bytes([1; LABEL_LEN]);
        let mut other = [1u8; LABEL_LEN];
        other[31] = 2;
        let b = OprfLabel::from_bytes(other);
        assert_ne!(a, b);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn as_bytes_roundtrip() {
        let bytes = [7u8; LABEL_LEN];
        let label = OprfLabel::from_bytes(bytes);
        assert_eq!(label.as_bytes(), &bytes);
        assert_eq!(label.to_bytes(), bytes);
    }
}
