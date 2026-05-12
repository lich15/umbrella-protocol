//! Идентификаторы сущностей протокола как newtypes поверх байтовых массивов.
//! Protocol entity identifiers as newtypes over byte arrays.

use core::fmt;

/// Идентификатор пользователя — 32-байтовый Ed25519 публичный ключ.
/// User identifier — a 32-byte Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId([u8; 32]);

impl UserId {
    /// Создаёт UserId из сырых 32 байт; вызывающий обязан гарантировать что это валидный pubkey.
    /// Constructs a UserId from raw 32 bytes; caller must ensure it is a valid pubkey.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Возвращает байтовое представление идентификатора.
    /// Returns the byte representation of the identifier.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

/// Идентификатор конкретного устройства пользователя; подписан identity-key владельца.
/// Identifier of a specific user device; signed by the owner's identity key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Создаёт DeviceId из сырых 32 байт.
    /// Constructs a DeviceId from raw 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

/// Номер эпохи MLS-группы; монотонно возрастает при каждом Commit.
/// MLS group epoch number; monotonically increases on every Commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(pub u64);

/// Глобально уникальный идентификатор сообщения (UUIDv7 или аналогичный).
/// Globally unique message identifier (UUIDv7 or equivalent).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 16]);

impl MessageId {
    /// Создаёт MessageId из сырых 16 байт.
    /// Constructs a MessageId from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_round_trip() {
        let bytes = [42u8; 32];
        let id = UserId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn epoch_ordering() {
        assert!(EpochId(1) < EpochId(2));
    }
}
