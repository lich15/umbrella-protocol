//! Политика группы: приватная (нельзя посторонним вступить) или публичный broadcast канал с PSK.
//! Group policy: private (no outsider join) or public broadcast channel with PSK.
//!
//! ## Зачем разделение
//!
//! MLS RFC 9420 §12.2 определяет «External Commits» и «External Proposals» — операции, через
//! которые посторонняя сторона может вступить в группу или предложить изменение, не будучи её
//! членом. Это полезно для public broadcast каналов (медиа, новости), но опасно для приватных
//! групп: атакующий со скомпрометированным `GroupInfo` может вступить и читать сообщения до
//! момента когда его обнаружат и удалят.
//!
//! Поэтому Umbrella различает два режима групп. Для приватных групп external operations
//! полностью отключены. Для public broadcast разрешены, но обязательно требуется pre-shared
//! key (PSK) выданный модератором — это даёт authorization без раскрытия identity моде­ратора.
//!
//! ## Why the distinction
//!
//! MLS RFC 9420 §12.2 defines "External Commits" and "External Proposals" — operations through
//! which an outsider can join the group or propose changes without being a member. This is
//! useful for public broadcast channels (media, news), but dangerous for private groups: an
//! attacker with a leaked `GroupInfo` can join and read messages until they're detected and
//! removed.
//!
//! So Umbrella distinguishes two group modes. For private groups, external operations are
//! fully disabled. For public broadcast, they're allowed, but a moderator-issued pre-shared key
//! (PSK) is required — this gives authorization without revealing the moderator's identity.

use core::fmt;

/// Срок жизни KeyPackage по умолчанию: 28 дней (4 недели).
///
/// Это короче чем 90 дней дефолта openmls — мы вынуждаем устройства чаще обновлять KeyPackage
/// в KT log, что укорачивает окно использования утёкшего KeyPackage злоумышленником.
///
/// KeyPackage default lifetime: 28 days (4 weeks).
///
/// This is shorter than openmls's 90-day default — we force devices to refresh KeyPackages in
/// the KT log more often, shrinking the window an attacker can exploit a leaked KeyPackage.
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 60 * 60 * 24 * 28;

/// Максимальный срок жизни приватной группы без принудительного rekey: 24 часа.
///
/// По истечении этого срока клиенты обязаны выполнить epoch advance commit для обновления
/// group_secret. Это даёт регулярный post-compromise security даже при отсутствии активных
/// операций (никто не добавляется/удаляется/присылает сообщения).
///
/// Maximum private-group lifetime without a forced rekey: 24 hours.
///
/// After this period clients must perform an epoch advance commit to refresh the group_secret.
/// This provides regular post-compromise security even with no active operations (nobody being
/// added/removed/messaging).
pub const PRIVATE_GROUP_MAX_LIFETIME_SECS: u64 = 60 * 60 * 24;

/// Политика группы: определяет какие операции разрешены и какие защиты применяются.
/// Group policy: defines which operations are permitted and which protections apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroupPolicy {
    /// Приватная группа (1-1 чат, малая или большая приватная группа).
    ///
    /// - External Commits: запрещены
    /// - External Proposals: запрещены
    /// - Доступ: только через явный Add от существующего члена
    /// - Принудительный epoch advance каждые `PRIVATE_GROUP_MAX_LIFETIME_SECS`
    ///
    /// Private group (1-1 chat, small or large private group).
    ///
    /// - External Commits: forbidden
    /// - External Proposals: forbidden
    /// - Access: only via explicit Add from an existing member
    /// - Forced epoch advance every `PRIVATE_GROUP_MAX_LIFETIME_SECS`
    Private,

    /// Публичный broadcast канал (новости, медиа, channels).
    ///
    /// - External Commits: разрешены, но обязательно с PSK
    /// - External Proposals: разрешены от authorized senders (модераторы)
    /// - Доступ: через PSK выданный модератором (например QR-код подписки)
    /// - PSK ротируется по политике канала
    ///
    /// Public broadcast channel (news, media, channels).
    ///
    /// - External Commits: allowed, but PSK is mandatory
    /// - External Proposals: allowed from authorized senders (moderators)
    /// - Access: via PSK issued by a moderator (e.g. subscription QR)
    /// - PSK rotated per channel policy
    PublicBroadcast,
}

impl GroupPolicy {
    /// Дефолт для всех новых групп — Private.
    /// Default for all new groups — Private.
    pub const fn default_const() -> Self {
        Self::Private
    }

    /// Разрешает ли политика external operations (External Commits / External Proposals).
    /// Whether the policy allows external operations (External Commits / External Proposals).
    pub const fn allows_external_operations(self) -> bool {
        matches!(self, Self::PublicBroadcast)
    }

    /// Требует ли политика обязательного PSK при external join.
    /// Whether the policy requires a mandatory PSK on external join.
    pub const fn requires_psk_for_external_join(self) -> bool {
        matches!(self, Self::PublicBroadcast)
    }

    /// Является ли политика приватной (запрет любого external доступа).
    /// Whether the policy is private (forbids any external access).
    pub const fn is_private(self) -> bool {
        matches!(self, Self::Private)
    }
}

impl Default for GroupPolicy {
    fn default() -> Self {
        Self::default_const()
    }
}

impl fmt::Display for GroupPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => write!(f, "Private"),
            Self::PublicBroadcast => write!(f, "PublicBroadcast"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_private() {
        assert_eq!(GroupPolicy::default(), GroupPolicy::Private);
        assert!(GroupPolicy::default().is_private());
    }

    #[test]
    fn private_forbids_external_operations() {
        let p = GroupPolicy::Private;
        assert!(!p.allows_external_operations());
        assert!(!p.requires_psk_for_external_join());
        assert!(p.is_private());
    }

    #[test]
    fn public_broadcast_allows_external_with_psk() {
        let p = GroupPolicy::PublicBroadcast;
        assert!(p.allows_external_operations());
        assert!(p.requires_psk_for_external_join());
        assert!(!p.is_private());
    }

    #[test]
    fn key_package_lifetime_is_28_days() {
        assert_eq!(KEY_PACKAGE_LIFETIME_SECS, 60 * 60 * 24 * 28);
    }

    #[test]
    fn private_group_max_lifetime_is_24_hours() {
        assert_eq!(PRIVATE_GROUP_MAX_LIFETIME_SECS, 60 * 60 * 24);
    }

    #[test]
    fn key_package_lifetime_strictly_longer_than_group_rekey_interval() {
        // KeyPackage должен жить дольше чем интервал rekey, иначе устройство потеряет
        // активный KeyPackage между rekey-операциями. Проверка через переменные
        // (clippy замечает assert!(true) если оба константы и оптимизирует).
        // KeyPackage must live longer than the rekey interval, otherwise a device loses
        // its active KeyPackage between rekey operations. Use variables to avoid clippy
        // optimising away the constant comparison.
        let kp_lifetime = KEY_PACKAGE_LIFETIME_SECS;
        let rekey_interval = PRIVATE_GROUP_MAX_LIFETIME_SECS;
        assert!(
            kp_lifetime > rekey_interval,
            "KEY_PACKAGE_LIFETIME_SECS ({kp_lifetime}) must exceed PRIVATE_GROUP_MAX_LIFETIME_SECS ({rekey_interval})"
        );
    }

    #[test]
    fn display_format_human_readable() {
        assert_eq!(format!("{}", GroupPolicy::Private), "Private");
        assert_eq!(
            format!("{}", GroupPolicy::PublicBroadcast),
            "PublicBroadcast"
        );
    }

    #[test]
    fn const_default_matches_runtime_default() {
        assert_eq!(GroupPolicy::default_const(), GroupPolicy::default());
    }
}
