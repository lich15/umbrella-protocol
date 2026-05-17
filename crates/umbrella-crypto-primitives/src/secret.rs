//! Обёртка для секретного байтового материала: zeroize при Drop, constant-time сравнение.
//! Wrapper for secret byte material: zeroize on Drop, constant-time comparison.

#![forbid(unsafe_code)]

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Секретные байты фиксированного размера; обнуляются при Drop, сравниваются constant-time.
/// Fixed-size secret bytes; zeroized on Drop, compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Конструирует SecretBytes из массива; копия владеется внутренне.
    /// Constructs SecretBytes from an array; the copy is owned internally.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Создаёт SecretBytes заполненный нулями.
    /// Creates a zero-filled SecretBytes.
    pub const fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Возвращает неизменяемую ссылку на содержимое; вызывающий обязан минимизировать видимость.
    /// Returns an immutable reference to the contents; the caller must minimize exposure.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Возвращает изменяемую ссылку для in-place заполнения секрета.
    /// Returns a mutable reference for in-place secret population.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Длина секрета в байтах.
    /// Secret length in bytes.
    pub const fn len(&self) -> usize {
        N
    }

    /// Признак нулевого размера; ложь для всех ненулевых N.
    /// Zero-size indicator; false for all non-zero N.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_same_value() {
        let a = SecretBytes::<32>::new([7u8; 32]);
        let b = SecretBytes::<32>::new([7u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn ct_eq_different_value() {
        let a = SecretBytes::<32>::new([7u8; 32]);
        let mut bytes = [7u8; 32];
        bytes[31] = 0;
        let b = SecretBytes::<32>::new(bytes);
        assert_ne!(a, b);
    }

    #[test]
    fn debug_does_not_leak() {
        let s = SecretBytes::<32>::new([0xAA; 32]);
        let formatted = format!("{s:?}");
        assert!(formatted.contains("redacted"));
        assert!(!formatted.contains("AA"));
        assert!(!formatted.contains("aa"));
    }
}
