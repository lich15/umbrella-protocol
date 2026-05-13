//! Центральное состояние клиента. Один `ClientCore` на аккаунт на устройство.
//! Инициализируется через [`UmbrellaClient::bootstrap_for_test`] (Блок 7.2) или
//! — в 7.3+ — через production `UmbrellaClient::bootstrap` с hardware-backed
//! KeyStore и реальными HTTP/2 транспортами.
//!
//! Client core state. One `ClientCore` per account per device. Initialized via
//! [`UmbrellaClient::bootstrap_for_test`] (Block 7.2), or — in Block 7.3+ — the
//! production `UmbrellaClient::bootstrap` with a hardware-backed KeyStore and
//! real HTTP/2 transports.

use std::sync::Arc;

use tokio::sync::RwLock;
use umbrella_backup::cloud_wrap::WrappingParams;
use umbrella_calls::CallPolicy;
use umbrella_identity::{IdentityKey, IdentitySeed};
use umbrella_kt::KtLogState;

use crate::error::{ClientError, Result};
use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
#[cfg(feature = "pq")]
use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_PQ_HYBRID;
use crate::transport::async_unwrap::AsyncUnwrapTransport;
use crate::transport::stub::{
    StubCallRelayTransport, StubKtTransport, StubPostmanTransport, StubUnwrapTransport,
};

/// Cfg-conditional default IANA ciphersuite для нового [`ClientConfig`]
/// (block 9.12 PQ-first default switch + ADR-013 Решения 1 и 3).
///
/// - Под feature `pq` → `0x004D` ([`UMBRELLA_CIPHERSUITE_PQ_HYBRID`]),
///   `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`. Применяется policy
///   «делаем как будто квантовые компьютеры уже есть и ломают» (постулат 3
///   максимум, не минимум — quantum-adversary-today threat model;
///   harvest-now-decrypt-later закрыт by default).
/// - Без feature `pq` → `0x0003` ([`UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT`]),
///   `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Classical путь
///   для legacy 0.0.11 приложений (FFI ABI invariant ADR-010 + постулат 14
///   no silent fallback — переключение режима только через explicit
///   constructor [`UmbrellaClient::bootstrap_classical_for_test`]).
///
/// Применяется по умолчанию в [`ClientConfig::default`] и в FFI `TryFrom<ClientConfigFfi>`
/// (см. `umbrella-ffi/src/export/client.rs`); per-чат override через
/// `ChatSettings.ciphersuite = Some(value)` имеет приоритет над этим default'ом
/// (см. `CloudChat::create` / `SecretChat::create`).
///
/// Cfg-conditional default IANA ciphersuite for new [`ClientConfig`] values
/// (Block 9.12 PQ-first default switch + ADR-013 Decisions 1 and 3).
///
/// - Under feature `pq` → `0x004D` ([`UMBRELLA_CIPHERSUITE_PQ_HYBRID`]),
///   i.e. `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`. Implements the
///   «quantum computers already exist and break» policy (postulate 3
///   maximum, not minimum — quantum-adversary-today threat model;
///   harvest-now-decrypt-later closed by default).
/// - Without feature `pq` → `0x0003`
///   ([`UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT`]), i.e.
///   `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Classical path
///   for legacy 0.0.11 apps (FFI ABI invariant ADR-010 + postulate 14 no
///   silent fallback — switching mode happens only through the explicit
///   [`UmbrellaClient::bootstrap_classical_for_test`] constructor).
///
/// Applied as the default in [`ClientConfig::default`] and in the FFI
/// `TryFrom<ClientConfigFfi>` (see `umbrella-ffi/src/export/client.rs`); a
/// per-chat override through `ChatSettings.ciphersuite = Some(value)` takes
/// precedence over this default (see `CloudChat::create` /
/// `SecretChat::create`).
#[cfg(feature = "pq")]
pub const DEFAULT_CIPHERSUITE: u16 = UMBRELLA_CIPHERSUITE_PQ_HYBRID;

/// Cfg-conditional default IANA ciphersuite (classical-only build —
/// `0x0003`). См. подробное описание в PQ-варианте этого const'а выше.
///
/// Cfg-conditional default IANA ciphersuite (classical-only build —
/// `0x0003`). See the PQ variant above for the full description.
#[cfg(not(feature = "pq"))]
pub const DEFAULT_CIPHERSUITE: u16 = UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;

/// Базовый конфиг клиента. Инициализируется native-приложением при bootstrap.
///
/// Base client config. Populated by the native app at bootstrap.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// URL-ы пяти Sealed Servers (cloud-backup-svc). До блока 7.4 —
    /// stub-значения; `Http2UnwrapTransport` использует их в fan-out 3-of-5.
    ///
    /// URLs of the five Sealed Servers (cloud-backup-svc). Stub values until
    /// Block 7.4; `Http2UnwrapTransport` will fan out 3-of-5 across these.
    pub sealed_server_urls: Vec<String>,

    /// URL blind-postman-svc для доставки sealed-sender envelope'ов.
    ///
    /// URL of blind-postman-svc for sealed-sender envelope delivery.
    pub postman_url: String,

    /// URL kt-svc и его witness-ов 3-of-5.
    ///
    /// URL of kt-svc and its 3-of-5 witnesses.
    pub kt_url: String,

    /// URL call-relay-svc (TURN allocation).
    ///
    /// URL of call-relay-svc (TURN allocation endpoint).
    pub call_relay_url: String,

    /// Интервал self-monitoring KT в секундах (default 3600 = 1 час,
    /// SPEC-09 §3 — периодическая сверка local mirror с witness quorum).
    ///
    /// Interval (seconds) for KT self-monitoring (default 3600 = 1 hour;
    /// SPEC-09 §3 periodic reconciliation of the local mirror against the
    /// 3-of-5 witness quorum).
    pub kt_monitor_interval_secs: u64,

    /// Wrapping parameters для Cloud-wrap (пять public ключей Sealed Servers,
    /// threshold 3-of-5, версия протокола).
    ///
    /// Wrapping parameters for Cloud-wrap (five Sealed Server pubkeys,
    /// 3-of-5 threshold, protocol version).
    pub wrapping_params: WrappingParams,

    /// Ciphersuite по умолчанию для новых чатов когда `ChatSettings.ciphersuite`
    /// = `None`. Classical путь (existing 0.0.11 call sites + bootstrap_for_test):
    /// `0x0003` (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`). PQ путь
    /// (feature `pq` + `bootstrap_pq_for_test`): `0x004D`
    /// (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`).
    ///
    /// Поле добавлено в Этапе 8 блок 8.8 closing milestone (ADR-011 Решение 7,
    /// см. design.md §11.2). Backward-compat: existing struct literals
    /// расширяются через rest-pattern либо через explicit имя константы
    /// (рекомендуется в новом коде для документирования намерения).
    ///
    /// Per-chat override через `ChatSettings.ciphersuite = Some(value)` имеет
    /// приоритет над этим default'ом (см. `CloudChat::create` / `SecretChat::create`).
    ///
    /// Default ciphersuite for new chats when `ChatSettings.ciphersuite` is
    /// `None`. Classical path (existing 0.0.11 call sites + `bootstrap_for_test`):
    /// `0x0003`. PQ path (feature `pq` + `bootstrap_pq_for_test`): `0x004D`.
    ///
    /// Field added in Stage 8 Block 8.8 closing milestone (ADR-011 Decision 7,
    /// see design.md §11.2). Backwards-compatible: existing struct literals
    /// extend via rest-pattern or via an explicit constant assignment
    /// (recommended for new code to document intent).
    ///
    /// A per-chat override through `ChatSettings.ciphersuite = Some(value)`
    /// takes precedence over this default (see `CloudChat::create` /
    /// `SecretChat::create`).
    pub default_ciphersuite: u16,
}

impl Default for ClientConfig {
    /// Дефолтные значения для тестов и инициализации через rest-pattern
    /// (`ClientConfig { default_ciphersuite: 0x004D, ..Default::default() }`).
    /// URL-ы и Sealed Servers wrap public ключи — пустые / нулевые stubs;
    /// production-приложения должны заполнить их явно через native bootstrap
    /// layer перед использованием реальных HTTP/2 транспортов (блок 7.4+).
    /// [`Self::default_ciphersuite`] выставлен через cfg-conditional
    /// [`DEFAULT_CIPHERSUITE`]:
    /// - `0x004D` под feature `pq` (block 9.12 PQ-first default switch);
    /// - `0x0003` без feature `pq` (legacy classical, FFI ABI invariant
    ///   ADR-010 + постулат 14 no silent fallback).
    ///
    /// Default values for tests and rest-pattern initialization
    /// (`ClientConfig { default_ciphersuite: 0x004D, ..Default::default() }`).
    /// URLs and Sealed Server wrap pubkeys are empty / zeroed stubs;
    /// production apps must populate them explicitly via the native
    /// bootstrap layer before using real HTTP/2 transports (Block 7.4+).
    /// [`Self::default_ciphersuite`] is set via the cfg-conditional
    /// [`DEFAULT_CIPHERSUITE`]:
    /// - `0x004D` under feature `pq` (Block 9.12 PQ-first default switch);
    /// - `0x0003` without feature `pq` (legacy classical, FFI ABI invariant
    ///   ADR-010 + postulate 14 no silent fallback).
    fn default() -> Self {
        Self {
            sealed_server_urls: Vec::new(),
            postman_url: String::new(),
            kt_url: String::new(),
            call_relay_url: String::new(),
            kt_monitor_interval_secs: 3600,
            wrapping_params: WrappingParams {
                version: 0,
                main_pubkey: [0u8; 32],
                server_pubkeys: [[0u8; 32]; 5],
                // `ThresholdConfig::default()` возвращает каноничную 3-of-5
                // конфигурацию (см. `umbrella-backup/src/cloud_wrap/params.rs`
                // `DEFAULT_THRESHOLD = 3` + `DEFAULT_TOTAL = 5`).
                // `ThresholdConfig::default()` returns the canonical 3-of-5
                // configuration (see `umbrella-backup/src/cloud_wrap/params.rs`
                // `DEFAULT_THRESHOLD = 3` + `DEFAULT_TOTAL = 5`).
                config: umbrella_backup::cloud_wrap::ThresholdConfig::default(),
            },
            default_ciphersuite: DEFAULT_CIPHERSUITE,
        }
    }
}

/// Центральное состояние клиента. Все фасады ([`CloudChat`], [`SecretChat`])
/// держат `Arc<ClientCore>` и переиспользуют его компоненты (identity, KT
/// state, транспорты, call policy).
///
/// Поля `pub(crate)` — внутренний доступ из фасадов/transport/call stack;
/// внешний API клиентских приложений проходит через фасады, не напрямую.
///
/// Client core state. All facades ([`CloudChat`], [`SecretChat`]) hold
/// `Arc<ClientCore>` and share its components. Fields are `pub(crate)` for
/// internal access from facade/transport/call stack layers; external
/// applications interact via facades.
///
/// [`CloudChat`]: crate::facade::CloudChat
/// [`SecretChat`]: crate::facade::SecretChat
//
// Блок 7.2 stage: большинство полей зарезервированы под Блоки 7.3–7.6
// (PersistentKeyStore wire-up, HTTP/2 transports, call stack). Подавляем
// dead_code до тех блоков, где появляются первые reader-ы.
//
// Block 7.2 stage: most fields are reserved for Blocks 7.3–7.6 (PersistentKeyStore
// wire-up, HTTP/2 transports, call stack). Suppress dead_code until those
// blocks introduce the first readers.
#[allow(dead_code)]
pub struct ClientCore {
    /// Identity-key Ed25519 — корень доверия. В Блоке 7.2 хранится в памяти
    /// (`Arc<IdentityKey>`); в Блоке 7.3 заменяется на non-exportable ключ
    /// внутри Secure Enclave / StrongBox через `PersistentKeyStore` callback.
    ///
    /// Identity-key Ed25519 — root of trust. In Block 7.2 held in memory
    /// (`Arc<IdentityKey>`); Block 7.3 swaps it for a non-exportable key
    /// inside Secure Enclave / StrongBox via the `PersistentKeyStore`
    /// callback.
    pub(crate) identity: Arc<IdentityKey>,

    /// Index этого устройства в семействе (0 = primary, 1–15 = secondary,
    /// SPEC-11 §4). В Блоке 7.2 всегда 0 для тестов.
    ///
    /// Index of this device in the account family (0 = primary, 1–15 =
    /// secondary, SPEC-11 §4). Always 0 in Block 7.2 tests.
    pub(crate) device_index: u32,

    /// Клиентский mirror Key Transparency log-а. Обновляется periodic
    /// self-monitoring'ом через kt_transport (см. блок 7.5).
    ///
    /// Client-side mirror of the Key Transparency log, refreshed by periodic
    /// self-monitoring via kt_transport (see Block 7.5).
    pub(crate) kt_state: Arc<RwLock<KtLogState>>,

    /// Транспорт к cloud-backup-svc (Sealed Servers fan-out 3-of-5).
    /// Общий `dyn AsyncUnwrapTransport`-slot: тестовый [`ClientCore::new_for_test`]
    /// подставляет `StubUnwrapTransport` (через blanket adapter в
    /// `transport::stub`). Полный боевой конструктор должен подставить
    /// реальные транспорты только после появления SPKI-настроек для всех
    /// сервисов; текущий [`ClientCore::new_with_http2`] закрыто отказывает.
    ///
    /// Transport to cloud-backup-svc (Sealed Servers fan-out 3-of-5). Held as
    /// `dyn AsyncUnwrapTransport`: `new_for_test` plugs in `StubUnwrapTransport`
    /// via the blanket adapter in `transport::stub`. A full production
    /// constructor must install real transports only after SPKI settings exist
    /// for every service; the current [`ClientCore::new_with_http2`] fails
    /// closed.
    pub(crate) unwrap_transport: Arc<dyn AsyncUnwrapTransport + Send + Sync>,

    /// Транспорт к blind-postman-svc для Cloud ciphertext и Secret inbox.
    ///
    /// Transport to blind-postman-svc for Cloud ciphertext and Secret inbox.
    pub(crate) postman_transport: Arc<StubPostmanTransport>,

    /// Транспорт к kt-svc и 3-of-5 witness-ам.
    ///
    /// Transport to kt-svc and its 3-of-5 witnesses.
    pub(crate) kt_transport: Arc<StubKtTransport>,

    /// Транспорт к call-relay-svc для TURN allocation (SPEC-06 §3).
    ///
    /// Transport to call-relay-svc for TURN allocation (SPEC-06 §3).
    pub(crate) call_relay_transport: Arc<StubCallRelayTransport>,

    /// User-level call policy (default/sensitive/allow_p2p_global). Меняется
    /// пользователем через UI; передаётся в mode_enforcement слой (блок 7.6).
    ///
    /// User-level call policy (default/sensitive/allow_p2p_global). Set via UI
    /// and read by the mode_enforcement layer (Block 7.6).
    pub(crate) user_policy: Arc<RwLock<CallPolicy>>,

    /// Config, с которым клиент был bootstrapped.
    ///
    /// Config with which the client was bootstrapped.
    pub(crate) config: ClientConfig,
}

impl ClientCore {
    /// Создать тестовый `ClientCore` с in-memory stub транспортами. Используется
    /// в Блоке 7.2 и в integration-тестах фасадов до готовности реальных
    /// `Http2*Transport` (Блок 7.4) и `PersistentKeyStore` (Блок 7.3).
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Identity`] если `IdentityKey::derive(&seed, 0)` падает
    ///   (mnemonic-entropy некорректна; в тестах не случается на валидном
    ///   `IdentitySeed::generate`).
    ///
    /// Creates a test `ClientCore` with in-memory stub transports. Used in
    /// Block 7.2 and facade integration tests until real `Http2*Transport`
    /// (Block 7.4) and `PersistentKeyStore` (Block 7.3) are available.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Identity`] if `IdentityKey::derive(&seed, 0)` fails
    ///   (only on malformed seed entropy; does not occur on a seed from
    ///   `IdentitySeed::generate`).
    pub async fn new_for_test(config: ClientConfig, seed: IdentitySeed) -> Result<Arc<Self>> {
        let identity = Arc::new(IdentityKey::derive(&seed, 0)?);

        let unwrap_transport: Arc<dyn AsyncUnwrapTransport + Send + Sync> =
            Arc::new(StubUnwrapTransport::default());

        Ok(Arc::new(Self {
            identity,
            device_index: 0,
            kt_state: Arc::new(RwLock::new(KtLogState::new())),
            unwrap_transport,
            postman_transport: Arc::new(StubPostmanTransport::default()),
            kt_transport: Arc::new(StubKtTransport::default()),
            call_relay_transport: Arc::new(StubCallRelayTransport::default()),
            user_policy: Arc::new(RwLock::new(CallPolicy::default())),
            config,
        }))
    }

    /// Закрытая граница неполного HTTP/2 bootstrap.
    ///
    /// Этот метод оставлен как fail-fast защита для старых внутренних вызовов:
    /// он не должен создавать клиент, пока конфигурация не несёт SPKI pins для
    /// всех сервисов и пока `postman`, `kt` и `call_relay` не переведены с
    /// заглушек на реальные `dyn`-транспорты.
    ///
    /// Closed boundary for incomplete HTTP/2 bootstrap.
    ///
    /// This method remains as a fail-fast guard for older internal callers. It
    /// must not create a client until the config carries SPKI pins for all
    /// services and `postman`, `kt`, and `call_relay` are moved from stubs to
    /// real `dyn` transports.
    ///
    /// # Ошибки / Errors
    ///
    /// Всегда возвращает [`ClientError::Network`] с понятной причиной закрытия.
    pub async fn new_with_http2(config: ClientConfig, seed: IdentitySeed) -> Result<Arc<Self>> {
        let _ = (config, seed);
        Err(ClientError::Network(
            "production HTTP/2 bootstrap is closed: ClientCore::new_with_http2 does not carry SPKI pins and still leaves postman/KT/call relay stubs; use only explicit test constructors until full production transport wiring exists"
                .to_string(),
        ))
    }

    /// Index текущего устройства (0 = primary).
    ///
    /// Returns the current device index (0 = primary).
    #[must_use]
    pub fn device_index(&self) -> u32 {
        self.device_index
    }

    /// Копия `ClientConfig`, с которым произведён bootstrap.
    ///
    /// Returns a clone of the `ClientConfig` used at bootstrap.
    #[must_use]
    pub fn config(&self) -> ClientConfig {
        self.config.clone()
    }

    /// IANA ciphersuite по умолчанию для новых чатов. Применяется когда
    /// `ChatSettings.ciphersuite = None`. Зеркалирует `config.default_ciphersuite`;
    /// перенесён в accessor чтобы фасады не зависели от конкретного места
    /// хранения (рефакторинг под cfg pq в Этапе 9 hardening может перенести
    /// поле в отдельный `RuntimeMode` enum).
    ///
    /// Default IANA ciphersuite for new chats. Used when
    /// `ChatSettings.ciphersuite = None`. Mirrors `config.default_ciphersuite`;
    /// exposed as an accessor so facades do not depend on the field's
    /// concrete location (a Stage 9 hardening refactor under cfg pq may move
    /// the field into a dedicated `RuntimeMode` enum).
    #[must_use]
    pub fn default_ciphersuite(&self) -> u16 {
        self.config.default_ciphersuite
    }
}

/// Высокоуровневый вход в клиент. По сути — обёртка над `Arc<ClientCore>` +
/// future registration возможностей (push-notification token, call-kit
/// bridge handle). В Блоке 7.7 exposes через `#[uniffi::export]`.
///
/// High-level entry point. Wraps `Arc<ClientCore>` plus future registration
/// capabilities (push-notification token, CallKit bridge handle). Exposed via
/// `#[uniffi::export]` in Block 7.7.
pub struct UmbrellaClient {
    core: Arc<ClientCore>,
}

impl UmbrellaClient {
    /// Bootstrap клиента для тестов — создаёт `ClientCore` с in-memory stubs.
    ///
    /// # Ошибки / Errors
    ///
    /// Пробрасывает все ошибки [`ClientCore::new_for_test`].
    ///
    /// Bootstrap for tests — constructs a `ClientCore` with in-memory stubs.
    ///
    /// # Errors
    ///
    /// Forwards all errors from [`ClientCore::new_for_test`].
    pub async fn bootstrap_for_test(config: ClientConfig, seed: IdentitySeed) -> Result<Arc<Self>> {
        let core = ClientCore::new_for_test(config, seed).await?;
        Ok(Arc::new(Self { core }))
    }

    /// Bootstrap клиента в **PQ-режиме** для тестов и интеграционных сценариев.
    /// Фактически identical с [`Self::bootstrap_for_test`] плюс override
    /// `config.default_ciphersuite` на hybrid PQ ciphersuite `0x004D`
    /// (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`). Все новые чаты,
    /// созданные через фасад без явного `ChatSettings.ciphersuite`, получат
    /// X-Wing MLS group + post-quantum capabilities (capability negotiation
    /// в `umbrella-mls` блок 8.4 + `UmbrellaXWingProvider` под feature `pq`).
    ///
    /// Под cfg `pq` слои `umbrella-pq` (X-Wing primitives + KT v2 + sealed-sender
    /// V2 + PQ wrap) уже скомпилированы и доступны через aggregator features
    /// (см. ADR-011 Решение 7).
    ///
    /// # Постулат 14 (no silent fallback)
    ///
    /// Если caller передаёт `ChatSettings.ciphersuite = Some(0x004D)`
    /// без активной feature `pq` — фасад вернёт `ClientError::Mls(MlsError::Capabilities)`.
    /// Этот метод **не делает** automatic downgrade на `0x0003`.
    ///
    /// # Ошибки / Errors
    ///
    /// Те же что [`Self::bootstrap_for_test`] — `ClientError::Identity` при
    /// невалидной mnemonic-entropy.
    ///
    /// Bootstrap the client in **PQ mode** for tests and integration scenarios.
    /// Identical to [`Self::bootstrap_for_test`] plus an override of
    /// `config.default_ciphersuite` to the hybrid PQ ciphersuite `0x004D`
    /// (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`). All new chats
    /// created through the facade without an explicit
    /// `ChatSettings.ciphersuite` get an X-Wing MLS group + post-quantum
    /// capabilities (capability negotiation in `umbrella-mls` Block 8.4 +
    /// `UmbrellaXWingProvider` under feature `pq`).
    ///
    /// Under cfg `pq` the X-Wing primitives + KT v2 + sealed-sender V2 + PQ
    /// wrap layers are already compiled and available (ADR-011 Decision 7
    /// feature-flag hierarchy).
    ///
    /// # Postulate 14 (no silent fallback)
    ///
    /// If a caller passes `ChatSettings.ciphersuite = Some(0x004D)` without
    /// the `pq` feature active — the facade returns
    /// `ClientError::Mls(MlsError::Capabilities)`. This method does **not**
    /// silently downgrade to `0x0003`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::bootstrap_for_test`] — `ClientError::Identity` on
    /// invalid mnemonic entropy.
    #[cfg(feature = "pq")]
    pub async fn bootstrap_pq_for_test(
        mut config: ClientConfig,
        seed: IdentitySeed,
    ) -> Result<Arc<Self>> {
        config.default_ciphersuite = UMBRELLA_CIPHERSUITE_PQ_HYBRID;
        let core = ClientCore::new_for_test(config, seed).await?;
        Ok(Arc::new(Self { core }))
    }

    /// Bootstrap клиента в **classical-режиме** для тестов и интеграционных
    /// сценариев. Identical с [`Self::bootstrap_for_test`] плюс explicit
    /// override `config.default_ciphersuite = 0x0003`
    /// (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`), независимо
    /// от feature `pq`. Доступен всегда — в отличие от
    /// [`Self::bootstrap_pq_for_test`] (который требует feature `pq`).
    ///
    /// # Цель (block 9.12)
    ///
    /// После переключения PQ-first default в блоке 9.12
    /// [`Self::bootstrap_for_test`] под feature `pq` возвращает клиент с
    /// `default_ciphersuite = 0x004D`. `bootstrap_classical_for_test` —
    /// explicit V1-bootstrap path для regression coverage и migration
    /// scenarios (mixed groups V1↔V2 — Pattern E), сохраняющийся для
    /// тестирования classical путей даже под PQ-default builds (ADR-013
    /// Решение 1 Вариант C, design.md §8.1).
    ///
    /// # Постулат 14 (no silent fallback)
    ///
    /// Этот конструктор НЕ silent fallback с PQ на classical — он явный
    /// выбор classical mode caller'ом. Для перехода с PQ-default клиента на
    /// classical-only chat'ы используется per-чат override
    /// `ChatSettings.ciphersuite = Some(0x0003)` (см. block 8.8 milestone
    /// scenario 6 «Mixed group»).
    ///
    /// Bootstrap the client in **classical mode** for tests and integration
    /// scenarios. Identical to [`Self::bootstrap_for_test`] plus an explicit
    /// override of `config.default_ciphersuite = 0x0003`
    /// (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`), regardless
    /// of feature `pq`. Available unconditionally — unlike
    /// [`Self::bootstrap_pq_for_test`] (which requires feature `pq`).
    ///
    /// # Purpose (Block 9.12)
    ///
    /// After the PQ-first default switch in Block 9.12,
    /// [`Self::bootstrap_for_test`] under feature `pq` returns a client with
    /// `default_ciphersuite = 0x004D`. `bootstrap_classical_for_test` is the
    /// explicit V1-bootstrap path for regression coverage and migration
    /// scenarios (mixed V1↔V2 groups — Pattern E), preserved for testing
    /// classical paths even under PQ-default builds (ADR-013 Decision 1
    /// Variant C, design.md §8.1).
    ///
    /// # Postulate 14 (no silent fallback)
    ///
    /// This constructor is NOT a silent fallback from PQ to classical — it
    /// is the caller's explicit choice of classical mode. Switching a
    /// PQ-default client to classical-only chats happens through a per-chat
    /// override `ChatSettings.ciphersuite = Some(0x0003)` (see Block 8.8
    /// milestone scenario 6 «Mixed group»).
    ///
    /// # Ошибки / Errors
    ///
    /// Те же что [`Self::bootstrap_for_test`] — `ClientError::Identity`
    /// при невалидной mnemonic-entropy.
    pub async fn bootstrap_classical_for_test(
        mut config: ClientConfig,
        seed: IdentitySeed,
    ) -> Result<Arc<Self>> {
        config.default_ciphersuite = UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
        let core = ClientCore::new_for_test(config, seed).await?;
        Ok(Arc::new(Self { core }))
    }

    /// Underlying `Arc<ClientCore>` — для передачи в фасады.
    ///
    /// Underlying `Arc<ClientCore>` — passed into facades.
    #[must_use]
    pub fn core(&self) -> Arc<ClientCore> {
        self.core.clone()
    }
}

#[cfg(test)]
mod production_boundary_tests {
    use super::*;
    use rand_core::OsRng;
    use umbrella_identity::{IdentitySeed, MnemonicLanguage};

    fn production_shaped_config() -> ClientConfig {
        ClientConfig {
            sealed_server_urls: (0..5)
                .map(|idx| format!("https://sealed-{idx}.umbrella.example"))
                .collect(),
            postman_url: "https://postman.umbrella.example".to_string(),
            kt_url: "https://kt.umbrella.example".to_string(),
            call_relay_url: "https://relay.umbrella.example".to_string(),
            ..ClientConfig::default()
        }
    }

    fn test_seed() -> IdentitySeed {
        IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
    }

    #[tokio::test]
    async fn new_with_http2_fails_closed_until_full_production_transport_is_wired() {
        let result = ClientCore::new_with_http2(production_shaped_config(), test_seed()).await;
        let err = match result {
            Ok(_) => {
                panic!("new_with_http2 must fail closed until production transport is fully wired")
            }
            Err(err) => err,
        };
        let msg = err.to_string();

        assert!(
            msg.contains("production HTTP/2 bootstrap is closed"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("SPKI") && msg.contains("stubs"),
            "error must name missing SPKI/stub boundary: {msg}"
        );
    }
}
