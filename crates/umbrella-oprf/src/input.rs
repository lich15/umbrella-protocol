//! Opaque вход для OPRF (номер телефона, email и т. п., pre-normalized caller'ом).
//! Opaque OPRF input (phone, email, etc., pre-normalized by the caller).
//!
//! Крейт намеренно **не** реализует phone normalization (E.164). Нормализация —
//! ответственность вызывающей стороны (обычно FFI-слой использует нативный
//! platform API: `CNContact` на iOS, `PhoneNumberUtil` на Android). Это
//! зафиксировано в ADR-005 §6.
//!
//! Phone normalization is intentionally **not** performed here. Caller supplies
//! opaque bytes (see ADR-005 §6 for rationale).
//!
//! Допустимый диапазон длины: `1..=512` байт. Пустой вход запрещён (OPRF
//! требует non-empty input), больше 512 байт — защита от медленного
//! hash-to-curve на patологически длинных входах.
//!
//! Allowed length range: `1..=512`. Empty input is forbidden (OPRF requires
//! non-empty input); > 512 bytes protects against slow hash-to-curve on
//! pathologically large inputs.

use crate::error::OprfError;

/// Максимально допустимая длина входа в байтах. Maximum allowed input length.
pub const MAX_INPUT_BYTES: usize = 512;

/// Проверенный opaque вход для OPRF. Validated opaque OPRF input.
///
/// Содержит ссылку на исходные байты без копирования. Borrow-based тип —
/// избегает лишней аллокации для типичного случая когда вход живёт короткий
/// промежуток между нормализацией и отправкой request.
///
/// Zero-copy borrow over the caller-supplied bytes. No allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OprfInput<'a>(&'a [u8]);

impl<'a> OprfInput<'a> {
    /// Создать проверенный `OprfInput`. Validate and wrap bytes.
    ///
    /// # Errors
    /// - [`OprfError::EmptyInput`] если `bytes.is_empty()`.
    /// - [`OprfError::InputTooLarge`] если `bytes.len() > MAX_INPUT_BYTES`.
    pub fn new(bytes: &'a [u8]) -> Result<Self, OprfError> {
        if bytes.is_empty() {
            return Err(OprfError::EmptyInput);
        }
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(OprfError::InputTooLarge {
                got: bytes.len(),
                max: MAX_INPUT_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Сырые байты входа. Underlying raw bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Длина входа в байтах. Input length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Всегда `false` — тип не может быть пустым после конструктора.
    /// Always `false` — type cannot be empty post-construction.
    #[inline]
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rejected() {
        let err = OprfInput::new(b"").unwrap_err();
        assert!(matches!(err, OprfError::EmptyInput));
    }

    #[test]
    fn max_size_accepted() {
        let buf = vec![0u8; MAX_INPUT_BYTES];
        let inp = OprfInput::new(&buf).unwrap();
        assert_eq!(inp.len(), MAX_INPUT_BYTES);
        assert!(!inp.is_empty());
    }

    #[test]
    fn oversize_rejected() {
        let buf = vec![0u8; MAX_INPUT_BYTES + 1];
        let err = OprfInput::new(&buf).unwrap_err();
        match err {
            OprfError::InputTooLarge { got, max } => {
                assert_eq!(got, MAX_INPUT_BYTES + 1);
                assert_eq!(max, MAX_INPUT_BYTES);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn minimal_size_accepted() {
        let inp = OprfInput::new(b"x").unwrap();
        assert_eq!(inp.as_bytes(), b"x");
    }

    #[test]
    fn typical_phone_accepted() {
        let inp = OprfInput::new(b"+12125551212").unwrap();
        assert_eq!(inp.len(), 12);
    }
}
