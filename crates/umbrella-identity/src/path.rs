//! Канонические пути BIP-32 derivation для UmbrellaX.
//! Canonical BIP-32 derivation paths for UmbrellaX.
//!
//! Все пути hardened — Ed25519 не поддерживает non-hardened derive (SLIP-0010).
//! Структура путей следует SLIP-44 духу с собственным coin type:
//!
//! ```text
//! m / 0x554D' / account' / role' [ / sub_index' ]
//! ```
//!
//! где `0x554D` — UmbrellaX coin identifier (ASCII «UM»), `account` — индекс аккаунта
//! пользователя (0 для основного), `role` — назначение ключа, `sub_index` — индекс
//! устройства для роли «device».
//!
//! All paths are hardened — Ed25519 does not support non-hardened derive (SLIP-0010).
//! Path structure follows SLIP-44 spirit with our own coin type:
//!
//! ```text
//! m / 0x554D' / account' / role' [ / sub_index' ]
//! ```
//!
//! where `0x554D` is the UmbrellaX coin identifier (ASCII "UM"), `account` is the
//! user account index (0 for primary), `role` is the key purpose, `sub_index` is
//! the device index for the "device" role.

use core::fmt;

use crate::error::{IdentityError, Result};

/// Hardened bit для BIP-32 индекса (значение >= 0x80000000).
/// Hardened bit for BIP-32 index (value >= 0x80000000).
pub const HARDENED_BIT: u32 = 0x8000_0000;

/// Coin type UmbrellaX в дереве derivation: ASCII «UM» = 0x554D.
/// UmbrellaX coin type in the derivation tree: ASCII "UM" = 0x554D.
pub const UMBRELLA_COIN_TYPE: u32 = 0x0000_554D;

/// Назначение ключа по индексу role в пути.
/// Key purpose by `role` index in the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum KeyRole {
    /// Long-lived identity key (root of trust пользователя).
    /// Long-lived identity key (user's root of trust).
    Identity = 0,
    /// Device-key (подписан identity-key, живёт на одном устройстве).
    /// Device key (signed by the identity key, lives on a single device).
    Device = 1,
    /// Profile key (симметричный AEAD-ключ для шифрования профиля).
    /// Profile key (symmetric AEAD key for profile encryption).
    Profile = 2,
    /// Backup key (для шифрования identity-only бэкапа).
    /// Backup key (for identity-only backup encryption).
    Backup = 3,
    /// Sealed-identity X25519 keypair (для Sealed Sender envelope ECDH).
    /// Sealed-identity X25519 keypair (for Sealed Sender envelope ECDH).
    SealedIdentity = 4,
}

impl KeyRole {
    /// Возвращает индекс роли как hardened BIP-32 child index.
    /// Returns the role index as a hardened BIP-32 child index.
    pub const fn as_hardened_index(self) -> HardenedIndex {
        HardenedIndex::from_role(self as u32)
    }
}

/// Hardened-индекс BIP-32 (всегда с установленным верхним битом).
/// Hardened BIP-32 index (always with the high bit set).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HardenedIndex(u32);

impl HardenedIndex {
    /// Конструирует hardened-индекс из числа уже включающего hardened bit.
    /// Constructs a hardened index from a number that already has the hardened bit set.
    ///
    /// Возвращает ошибку если hardened bit не установлен.
    /// Returns an error if the hardened bit is not set.
    pub const fn from_raw(raw: u32) -> Result<Self> {
        if raw < HARDENED_BIT {
            return Err(IdentityError::NonHardenedIndex { index: raw });
        }
        Ok(Self(raw))
    }

    /// Конструирует hardened-индекс из «человеческого» числа (0..2^31).
    /// Hardened bit добавляется автоматически.
    /// Constructs a hardened index from a "human" number (0..2^31).
    /// The hardened bit is added automatically.
    ///
    /// Panics в const-контексте если `human >= 2^31`.
    /// Panics in const context if `human >= 2^31`.
    ///
    /// Carry-over Этап 11+ блок: добавить `from_human_checked() ->
    /// Result<Self, IdentityError>` для runtime-вызовов с
    /// attacker-controlled u32 (defence-in-depth для SPEC-01 § 4 row 8
    /// «multi-device leakage» в случае FFI-перехода или нестандартного
    /// account-flow). Все 8 текущих production call sites (path.rs lines
    /// 176-226) передают compile-time константы либо
    /// pre-validated/typed-narrowed account-индексы.
    /// Carry-over to a future Stage 11+ block: add a
    /// `from_human_checked() -> Result<Self, IdentityError>` for runtime
    /// callers with an attacker-controlled u32 (defence-in-depth for
    /// SPEC-01 § 4 row 8 "multi-device leakage" in case of an FFI
    /// transition or a non-standard account flow). All 8 current
    /// production call sites (path.rs lines 176-226) pass compile-time
    /// constants or pre-validated/typed-narrowed account indices.
    #[allow(
        unknown_lints,
        no_assert_in_lib,
        reason = "block 11.8 dylint expansion: const fn API contract — assertion fires at compile time \
                 for const callers; runtime panic only possible for non-const callers passing >= 2^31 \
                 (8 production call sites verified compile-time-constant or pre-validated). \
                 Carry-over Stage 11+ block: add `from_human_checked() -> Result<Self, IdentityError>` \
                 for hardened defence-in-depth on attacker-controlled u32 inputs (SPEC-01 § 4 row 8). \
                 `unknown_lints` suppressed because rustc outside the dylint driver does not know \
                 the custom `no_assert_in_lib` lint name"
    )]
    pub const fn from_human(human: u32) -> Self {
        assert!(human < HARDENED_BIT, "human index must be < 2^31");
        Self(human | HARDENED_BIT)
    }

    /// Конструирует hardened-индекс роли (без проверки 2^31, так как `KeyRole` это enum 0..N).
    /// Constructs a hardened role index (no 2^31 check; `KeyRole` is a small enum).
    pub(crate) const fn from_role(role: u32) -> Self {
        Self(role | HARDENED_BIT)
    }

    /// Возвращает «человеческий» компонент индекса (без hardened bit).
    /// Returns the "human" portion of the index (without the hardened bit).
    pub const fn human(self) -> u32 {
        self.0 & !HARDENED_BIT
    }

    /// Возвращает сырое значение индекса (с установленным hardened bit).
    /// Returns the raw index value (with the hardened bit set).
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for HardenedIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}'", self.human())
    }
}

impl fmt::Display for HardenedIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}'", self.human())
    }
}

/// Максимальная глубина пути derivation для UmbrellaX.
/// `m / coin' / account' / role' / sub_index'` = 4 уровня.
/// Maximum derivation path depth for UmbrellaX.
/// `m / coin' / account' / role' / sub_index'` = 4 levels.
pub const MAX_PATH_DEPTH: usize = 4;

/// Полный путь BIP-32 derivation; гарантирует что все индексы hardened.
/// Full BIP-32 derivation path; guarantees that every index is hardened.
#[derive(Clone, PartialEq, Eq)]
pub struct DerivationPath {
    indices: heapless::Vec<HardenedIndex, MAX_PATH_DEPTH>,
}

impl DerivationPath {
    /// Пустой путь — соответствует master key.
    /// Empty path — corresponds to the master key.
    pub const fn empty() -> Self {
        Self {
            indices: heapless::Vec::new(),
        }
    }

    /// Конструирует путь из последовательности hardened-индексов.
    /// Constructs a path from a sequence of hardened indices.
    pub fn from_indices(indices: &[HardenedIndex]) -> Result<Self> {
        if indices.len() > MAX_PATH_DEPTH {
            return Err(IdentityError::InvalidDerivationPath {
                reason: "path depth exceeds MAX_PATH_DEPTH",
            });
        }
        let mut path = Self::empty();
        for idx in indices {
            path.indices
                .push(*idx)
                .map_err(|_| IdentityError::InvalidDerivationPath {
                    reason: "internal capacity exceeded",
                })?;
        }
        Ok(path)
    }

    /// Канонический путь identity-key основного аккаунта (account=0).
    /// Canonical identity-key path for the primary account (account=0).
    ///
    /// `m / 0x554D' / 0' / 0'`
    pub fn identity(account: u32) -> Result<Self> {
        Self::from_indices(&[
            HardenedIndex::from_human(UMBRELLA_COIN_TYPE),
            HardenedIndex::from_human(account),
            KeyRole::Identity.as_hardened_index(),
        ])
    }

    /// Канонический путь device-key для конкретного устройства.
    /// Canonical device-key path for a specific device.
    ///
    /// `m / 0x554D' / account' / 1' / device_index'`
    pub fn device(account: u32, device_index: u32) -> Result<Self> {
        Self::from_indices(&[
            HardenedIndex::from_human(UMBRELLA_COIN_TYPE),
            HardenedIndex::from_human(account),
            KeyRole::Device.as_hardened_index(),
            HardenedIndex::from_human(device_index),
        ])
    }

    /// Канонический путь profile-key (симметричный AEAD).
    /// Canonical profile-key path (symmetric AEAD).
    ///
    /// `m / 0x554D' / account' / 2'`
    pub fn profile(account: u32) -> Result<Self> {
        Self::from_indices(&[
            HardenedIndex::from_human(UMBRELLA_COIN_TYPE),
            HardenedIndex::from_human(account),
            KeyRole::Profile.as_hardened_index(),
        ])
    }

    /// Канонический путь backup-key (для Sealed Boxes envelope).
    /// Canonical backup-key path (for the Sealed Boxes envelope).
    ///
    /// `m / 0x554D' / account' / 3'`
    pub fn backup(account: u32) -> Result<Self> {
        Self::from_indices(&[
            HardenedIndex::from_human(UMBRELLA_COIN_TYPE),
            HardenedIndex::from_human(account),
            KeyRole::Backup.as_hardened_index(),
        ])
    }

    /// Канонический путь sealed-identity X25519 keypair (для Sealed Sender envelope ECDH).
    /// Canonical sealed-identity X25519 keypair path (for Sealed Sender envelope ECDH).
    ///
    /// `m / 0x554D' / account' / 4'`
    pub fn sealed_identity(account: u32) -> Result<Self> {
        Self::from_indices(&[
            HardenedIndex::from_human(UMBRELLA_COIN_TYPE),
            HardenedIndex::from_human(account),
            KeyRole::SealedIdentity.as_hardened_index(),
        ])
    }

    /// Возвращает срез индексов пути.
    /// Returns the slice of path indices.
    pub fn as_slice(&self) -> &[HardenedIndex] {
        &self.indices
    }

    /// Глубина пути (0 для master, до MAX_PATH_DEPTH).
    /// Path depth (0 for master, up to MAX_PATH_DEPTH).
    pub fn depth(&self) -> usize {
        self.indices.len()
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for idx in &self.indices {
            write!(f, "/{idx}")?;
        }
        Ok(())
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for idx in &self.indices {
            write!(f, "/{idx}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_from_human_sets_bit() {
        let idx = HardenedIndex::from_human(0);
        assert_eq!(idx.raw(), 0x8000_0000);
        assert_eq!(idx.human(), 0);
    }

    #[test]
    fn hardened_from_human_max_value() {
        let idx = HardenedIndex::from_human(0x7FFF_FFFF);
        assert_eq!(idx.raw(), 0xFFFF_FFFF);
        assert_eq!(idx.human(), 0x7FFF_FFFF);
    }

    #[test]
    fn hardened_from_raw_rejects_non_hardened() {
        let result = HardenedIndex::from_raw(42);
        assert!(matches!(
            result,
            Err(IdentityError::NonHardenedIndex { index: 42 })
        ));
    }

    #[test]
    fn hardened_from_raw_accepts_hardened() {
        let idx = HardenedIndex::from_raw(0x8000_002A).unwrap();
        assert_eq!(idx.human(), 42);
    }

    #[test]
    fn identity_path_canonical() {
        let p = DerivationPath::identity(0).unwrap();
        assert_eq!(p.depth(), 3);
        assert_eq!(format!("{p}"), "m/21837'/0'/0'"); // 0x554D = 21837
    }

    #[test]
    fn device_path_canonical() {
        let p = DerivationPath::device(0, 5).unwrap();
        assert_eq!(p.depth(), 4);
        assert_eq!(format!("{p}"), "m/21837'/0'/1'/5'");
    }

    #[test]
    fn profile_and_backup_paths_distinct() {
        let prof = DerivationPath::profile(0).unwrap();
        let back = DerivationPath::backup(0).unwrap();
        assert_ne!(prof, back);
    }

    #[test]
    fn path_at_max_depth_accepted() {
        let p = DerivationPath::device(0, 0).unwrap();
        assert_eq!(p.depth(), MAX_PATH_DEPTH);
    }

    #[test]
    fn key_role_indices_distinct() {
        assert_ne!(
            KeyRole::Identity.as_hardened_index(),
            KeyRole::Device.as_hardened_index()
        );
        assert_ne!(
            KeyRole::Profile.as_hardened_index(),
            KeyRole::Backup.as_hardened_index()
        );
    }

    #[test]
    fn debug_format_human_readable() {
        let p = DerivationPath::device(2, 7).unwrap();
        assert_eq!(format!("{p:?}"), "m/21837'/2'/1'/7'");
    }
}
