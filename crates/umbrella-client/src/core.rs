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
use umbrella_identity::{IdentityKey, IdentitySeed, KeyStore};
use umbrella_kt::KtLogState;

use crate::error::{ClientError, Result};
use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
#[cfg(feature = "pq")]
use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_PQ_HYBRID;
use crate::keystore::hw_backed::HwBackedKeyStore;
use crate::keystore::hw_callback::{
    bootstrap_hw_identity, HwKeyHandle, PersistentKeyStoreCallback,
};
use crate::transport::async_unwrap::AsyncUnwrapTransport;
use crate::transport::gateway::GatewayConnection;
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
    /// Identity-key Ed25519 — корень доверия. `Some(...)` для legacy/test
    /// path'ей ([`ClientCore::new_for_test`]) — приватный материал лежит
    /// в Rust heap внутри `IdentityKey` (zeroize-on-drop). `None` если
    /// клиент был bootstrapped с hardware-backed identity
    /// ([`ClientCore::new_with_hw_callback`]) — приватный материал
    /// **физически** в Secure Enclave / StrongBox и НЕ материализуется
    /// в Rust heap. В этом режиме public-key bytes доступны через
    /// [`Self::hw_verifying_key`] (cache после bootstrap) или
    /// [`Self::identity_verifying_key`] (унифицированный accessor).
    ///
    /// **F-CLIENT-HW-1 closure (PhD-B Pass 5 remediation):** до closure
    /// поле было `Arc<IdentityKey>` без `Option`, и `new_with_hw_callback`
    /// синтезировало эфемерный `IdentitySeed` через
    /// `IdentitySeed::generate` + `IdentityKey::derive`, чтобы заполнить
    /// этот слот. Это материализовало 32 байта Ed25519 secret scalar
    /// в process heap на микросекунды между synthesis → derive → drop —
    /// узкое, но реальное окно для adversary с runtime memory access.
    /// Closure refactor'ит поле в `Option` и hw-bootstrap path выставляет
    /// `None`, полностью исключая materialization.
    ///
    /// Identity-key Ed25519 — root of trust. `Some(...)` for legacy / test
    /// paths ([`ClientCore::new_for_test`]) — secret material lives in
    /// Rust heap inside `IdentityKey` (zeroize-on-drop). `None` if the
    /// client was bootstrapped with a hardware-backed identity
    /// ([`ClientCore::new_with_hw_callback`]) — secret material is
    /// **physically** held in Secure Enclave / StrongBox and never
    /// materialises in Rust heap. In this mode the public-key bytes are
    /// available via [`Self::hw_verifying_key`] (cached at bootstrap)
    /// or [`Self::identity_verifying_key`] (unified accessor).
    ///
    /// **F-CLIENT-HW-1 closure (PhD-B Pass 5 remediation):** before the
    /// closure this field was `Arc<IdentityKey>` (no `Option`), and
    /// `new_with_hw_callback` synthesised an ephemeral `IdentitySeed`
    /// through `IdentitySeed::generate` + `IdentityKey::derive` to fill
    /// the slot. That materialised 32 bytes of Ed25519 secret scalar in
    /// process heap for microseconds (synthesis → derive → drop) — a
    /// narrow but real window for an adversary with runtime memory
    /// access. The closure refactors the field into `Option` and the
    /// hw-bootstrap path now sets `None`, eliminating the materialisation
    /// entirely.
    pub(crate) identity: Option<Arc<IdentityKey>>,

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

    /// Hardware-backed keystore callback (round-5 device-capture closure
    /// F-PHD-DC-R7-1 / F-PHD-DC-R10-1). `Some(...)` если клиент был
    /// bootstrapped через [`ClientCore::new_with_hw_callback`] —
    /// identity_sk **физически не находится в Rust heap**, все sign
    /// operations идут через FFI в Secure Enclave / StrongBox.
    ///
    /// `None` для legacy / test path'ей через [`ClientCore::new_for_test`].
    /// В этом случае `identity` (Rust heap-resident) — единственный источник
    /// signing material.
    ///
    /// Hardware-backed keystore callback (round-5 device-capture closure
    /// F-PHD-DC-R7-1 / F-PHD-DC-R10-1). `Some(...)` if the client was
    /// bootstrapped via [`ClientCore::new_with_hw_callback`] — identity_sk
    /// **does not physically reside on the Rust heap**, all sign operations
    /// route through FFI into Secure Enclave / StrongBox.
    ///
    /// `None` for the legacy / test paths via
    /// [`ClientCore::new_for_test`]. In that case `identity` (Rust heap-
    /// resident) is the sole signing-material source.
    pub(crate) hw_callback: Option<Arc<dyn PersistentKeyStoreCallback>>,

    /// `Some(handle)` если identity_sk живёт в hardware keystore и доступен
    /// только через [`hw_callback`]. `None` для legacy / test path'ей.
    ///
    /// `Some(handle)` if identity_sk lives in the hardware keystore and is
    /// only accessible via [`hw_callback`]. `None` for legacy / test paths.
    pub(crate) hw_identity_handle: Option<HwKeyHandle>,

    /// Cache 32-байтовых bytes Ed25519 verifying-key для hardware-resident
    /// identity. Заполняется в [`ClientCore::new_with_hw_callback`] через
    /// [`bootstrap_hw_identity`] → [`PersistentKeyStoreCallback::verifying_key`].
    /// `None` для legacy path'ей — в этом случае verifying-key читается из
    /// `identity.as_ref().unwrap().public()`.
    ///
    /// **F-CLIENT-HW-2 closure carry-over:** до F-CLIENT-HW-2
    /// `bootstrap_hw_identity` возвращал `[0u8; 32]` placeholder и call site
    /// в `new_with_hw_callback` его discard'ил через
    /// `_verifying_key_placeholder`. F-CLIENT-HW-2 закрыл placeholder; этот
    /// cache field — F-CLIENT-HW-1 closure storage для real verifying-key
    /// surfaced на bootstrap-time без round-trip к TEE на каждом read.
    ///
    /// Cache for the 32-byte Ed25519 verifying-key of the hardware-resident
    /// identity. Populated by [`ClientCore::new_with_hw_callback`] via
    /// [`bootstrap_hw_identity`] →
    /// [`PersistentKeyStoreCallback::verifying_key`]. `None` for legacy
    /// paths — in that case the verifying-key is read from
    /// `identity.as_ref().unwrap().public()`.
    ///
    /// **F-CLIENT-HW-2 closure carry-over:** before F-CLIENT-HW-2
    /// `bootstrap_hw_identity` returned a `[0u8; 32]` placeholder and the
    /// call site in `new_with_hw_callback` discarded it via
    /// `_verifying_key_placeholder`. F-CLIENT-HW-2 closed the placeholder
    /// itself; this cache field is the F-CLIENT-HW-1 closure storage for
    /// the real verifying-key surfaced at bootstrap-time without round-
    /// tripping to the TEE on every read.
    pub(crate) hw_verifying_key: Option<[u8; 32]>,

    /// Канонический `KeyStore` impl для этого ClientCore.
    /// `Some(HwBackedKeyStore)` если клиент был bootstrapped через
    /// [`ClientCore::new_with_hw_callback`] — identity-sk операции
    /// маршрутизируются через TEE callback. `None` для legacy / test
    /// path'ей через [`ClientCore::new_for_test`] — Block 7.2 facade
    /// stubs до сих пор конструируют [`umbrella_identity::InMemoryKeyStore`]
    /// inline в test wiring.
    ///
    /// **F-IDENT-1 + F-IDENT-2 closure (PhD-B Pass 5 remediation
    /// 2026-05-19):** до closure единственным `KeyStore` impl был
    /// `umbrella_identity::InMemoryKeyStore`, который держит
    /// `IdentitySeed` в process heap для lifetime keystore'а (F-IDENT-2
    /// gap). Closure добавляет [`HwBackedKeyStore`] (нет `seed` поля по
    /// дизайну) и регистрирует его в этом слоте на hw-bootstrap path —
    /// production deployment получает каноничный KeyStore без in-heap
    /// материализации identity_sk. Block 7.4+ facades будут consume
    /// `core.keystore()` accessor вместо inline `InMemoryKeyStore::open`.
    ///
    /// Canonical `KeyStore` impl for this ClientCore. `Some(HwBackedKeyStore)`
    /// if the client was bootstrapped through
    /// [`ClientCore::new_with_hw_callback`] — identity-sk operations
    /// route through the TEE callback. `None` for legacy / test paths
    /// through [`ClientCore::new_for_test`] — Block 7.2 facade stubs
    /// still construct [`umbrella_identity::InMemoryKeyStore`] inline in
    /// test wiring.
    ///
    /// **F-IDENT-1 + F-IDENT-2 closure (PhD-B Pass 5 remediation
    /// 2026-05-19):** before the closure the only `KeyStore` impl was
    /// `umbrella_identity::InMemoryKeyStore`, which keeps an
    /// `IdentitySeed` in the process heap for the keystore's lifetime
    /// (the F-IDENT-2 gap). The closure adds [`HwBackedKeyStore`] (no
    /// `seed` field by design) and registers it in this slot on the
    /// hw-bootstrap path — production deployment now gets a canonical
    /// KeyStore with no in-heap identity_sk materialisation. Block
    /// 7.4+ facades will consume the `core.keystore()` accessor instead
    /// of inline `InMemoryKeyStore::open` calls.
    pub(crate) keystore: Option<Arc<dyn KeyStore>>,

    /// Активное соединение с gateway-svc (QUIC либо WebSocket fallback). `Some(...)`
    /// после успешного `set_gateway` post-bootstrap; `None` до первого подключения
    /// или после умышленного `clear_gateway` (например, при logout).
    ///
    /// **F-CLIENT-FACADE-1 session 3 (2026-05-19):** новый слот для роутинга
    /// facade-уровневых сообщений через реальный gateway. До session 3
    /// `send_mls_text` возвращал `Ok(MessageId([0u8; 16]))` stub; теперь — если
    /// `gateway` is `Some`, маршрутизирует `ClientPayload::SendMessage` через
    /// `GatewayConnection::send_envelope` и возвращает `MessageId`, декодированный
    /// из `SendMessageAck.msg_id` (16 байт hex от gateway-svc). Если `None`,
    /// сохраняется backwards-compat stub-поведение для legacy/test callers,
    /// которые ещё не bootstrap'нули network connection.
    ///
    /// `RwLock` обоснован тем, что gateway connection — point-in-time runtime
    /// state: установка после bootstrap'а, замена при reconnect, очистка при
    /// logout/disconnect. Read-only path (send_mls_text) клонирует `Arc<GatewayConnection>`
    /// под short read-lock и работает с ним без удержания lock на время network I/O.
    ///
    /// Active gateway-svc connection (QUIC or WebSocket fallback). `Some(...)`
    /// after a successful `set_gateway` post-bootstrap; `None` before the first
    /// connect or after `clear_gateway` (e.g. logout).
    ///
    /// **F-CLIENT-FACADE-1 session 3 (2026-05-19):** new slot routing facade-
    /// level messages through the real gateway. Before session 3
    /// `send_mls_text` returned `Ok(MessageId([0u8; 16]))` stub; now — when
    /// `gateway` is `Some`, it routes `ClientPayload::SendMessage` through
    /// `GatewayConnection::send_envelope` and returns a `MessageId` decoded
    /// from `SendMessageAck.msg_id` (16-byte hex from gateway-svc). When
    /// `None`, the backwards-compat stub behaviour is kept for legacy/test
    /// callers that have not yet bootstrapped a network connection.
    ///
    /// `RwLock` is justified because the gateway connection is point-in-time
    /// runtime state: set post-bootstrap, swapped on reconnect, cleared on
    /// logout/disconnect. The read path (send_mls_text) clones the
    /// `Arc<GatewayConnection>` under a brief read-lock and performs network
    /// I/O outside the lock.
    pub(crate) gateway: RwLock<Option<Arc<GatewayConnection>>>,
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
            identity: Some(identity),
            device_index: 0,
            kt_state: Arc::new(RwLock::new(KtLogState::new())),
            unwrap_transport,
            postman_transport: Arc::new(StubPostmanTransport::default()),
            kt_transport: Arc::new(StubKtTransport::default()),
            call_relay_transport: Arc::new(StubCallRelayTransport::default()),
            user_policy: Arc::new(RwLock::new(CallPolicy::default())),
            config,
            hw_callback: None,
            hw_identity_handle: None,
            hw_verifying_key: None,
            // Legacy/test path: facades still construct InMemoryKeyStore
            // inline. F-IDENT-1 closure leaves this slot None on legacy
            // bootstraps; Block 7.4+ facade refactor will consolidate.
            keystore: None,
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap
            // via `set_gateway` — tests opting into the real send path
            // construct a mock GatewayTransport and install it here.
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap.
            gateway: RwLock::new(None),
        }))
    }

    /// Round-5 device-capture closure F-PHD-DC-R7-1 + F-PHD-DC-R10-1 entry
    /// point. Bootstrap `ClientCore` using a hardware-backed keystore
    /// callback (`PersistentKeyStoreCallback`). The identity signing key is
    /// **generated and held inside Secure Enclave / StrongBox**; only the
    /// opaque `HwKeyHandle` lives on the Rust side.
    ///
    /// **F-CLIENT-HW-1 closure (PhD-B Pass 5 remediation):** до closure
    /// этот конструктор синтезировал эфемерный `IdentitySeed` +
    /// `IdentityKey` чтобы заполнить теперь-`Option`-обёрнутое поле
    /// `core.identity`, материализуя 32 байта Ed25519 secret в heap на
    /// микросекунды (M-FINAL-1 disclosure). Closure refactor'ит
    /// `core.identity` в `Option<Arc<IdentityKey>>`, выставляет `None` в
    /// этой ветке и кэширует real verifying-key (после F-CLIENT-HW-2) в
    /// поле [`hw_verifying_key`]. Производство secret material'а в Rust
    /// heap в hw-bootstrap path eliminated полностью.
    ///
    /// Round-5 device-capture closure F-PHD-DC-R7-1 + F-PHD-DC-R10-1 entry
    /// point. Bootstrap a `ClientCore` using a hardware-backed keystore
    /// callback (`PersistentKeyStoreCallback`). The identity signing key
    /// is **generated and held inside Secure Enclave / StrongBox**; only
    /// the opaque `HwKeyHandle` lives on the Rust side.
    ///
    /// **F-CLIENT-HW-1 closure (PhD-B Pass 5 remediation):** prior to the
    /// closure this constructor synthesised an ephemeral `IdentitySeed` +
    /// `IdentityKey` to fill the (then non-`Option`) `core.identity`
    /// field, materialising 32 bytes of Ed25519 secret on the heap for
    /// microseconds (M-FINAL-1 disclosure). The closure refactors
    /// `core.identity` to `Option<Arc<IdentityKey>>`, sets `None` on this
    /// branch, and caches the real verifying-key (post-F-CLIENT-HW-2)
    /// in the [`hw_verifying_key`] field. Production of secret material
    /// on the Rust heap in the hw-bootstrap path is eliminated entirely.
    ///
    /// # Параметры / Parameters
    ///
    /// - `config` — клиентский конфиг (URLs, ciphersuite, …).
    /// - `callback` — implementation `PersistentKeyStoreCallback`
    ///   (iOS Swift `KeyStoreBridge`, Android Kotlin `KeyStoreBridge`,
    ///   или `MockHwKeystore` для тестов).
    /// - `label` — Keychain `kSecAttrApplicationTag` / Android Keystore
    ///   alias (e.g. `"xyz.umbrellax.identity.primary"`).
    ///
    /// # Ошибки / Errors
    ///
    /// - `ClientError::Platform(...)` — native side вернул [`HwKeystoreError`]
    ///   (user denied prompt, SE unavailable, etc.).
    pub async fn new_with_hw_callback(
        config: ClientConfig,
        callback: Arc<dyn PersistentKeyStoreCallback>,
        label: impl Into<String>,
    ) -> Result<Arc<Self>> {
        // Bootstrap identity inside the HW keystore. The handle and the
        // 32-byte Ed25519 verifying-key are the only things that come
        // back to Rust — the private signing scalar stays in the TEE.
        //
        // F-CLIENT-HW-1 closure: the verifying-key returned here is real
        // (post-F-CLIENT-HW-2); previously this binding was discarded as
        // `_verifying_key_placeholder` because `bootstrap_hw_identity`
        // returned `[0u8; 32]`.
        let label = label.into();
        let (handle, verifying_key) =
            bootstrap_hw_identity(&callback, label).map_err(ClientError::from)?;

        // F-CLIENT-HW-1 closure: the M-FINAL-1 disclosure block that
        // synthesised an ephemeral `IdentitySeed` + `IdentityKey` purely
        // to populate `core.identity` is removed. `core.identity` is now
        // `Option<Arc<IdentityKey>>` and stays `None` in the hw path —
        // no ephemeral secret scalar ever materialises in Rust heap.
        // Real verifying-key is cached in `hw_verifying_key` so callers
        // do not round-trip to the TEE on every public-key read.

        let unwrap_transport: Arc<dyn AsyncUnwrapTransport + Send + Sync> =
            Arc::new(StubUnwrapTransport::default());

        // F-IDENT-1 + F-IDENT-2 closure: construct the canonical
        // `HwBackedKeyStore` over the bootstrap byproducts. Identity-sk
        // operations route through `callback.sign_identity` — no
        // IdentitySeed materialisation. Account index hardcoded to 0
        // for Block 7.2; multi-account work is a Block 7.4+ refactor.
        let hw_keystore = HwBackedKeyStore::new(
            0,
            callback.clone(),
            handle.clone(),
            verifying_key,
        )?;
        let keystore: Arc<dyn KeyStore> = Arc::new(hw_keystore);

        Ok(Arc::new(Self {
            identity: None,
            device_index: 0,
            kt_state: Arc::new(RwLock::new(KtLogState::new())),
            unwrap_transport,
            postman_transport: Arc::new(StubPostmanTransport::default()),
            kt_transport: Arc::new(StubKtTransport::default()),
            call_relay_transport: Arc::new(StubCallRelayTransport::default()),
            user_policy: Arc::new(RwLock::new(CallPolicy::default())),
            config,
            hw_callback: Some(callback),
            hw_identity_handle: Some(handle),
            hw_verifying_key: Some(verifying_key),
            keystore: Some(keystore),
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap.
            gateway: RwLock::new(None),
        }))
    }

    /// `true` если ClientCore был bootstrapped с hardware-backed identity
    /// (через `new_with_hw_callback`) — identity_sk физически в TEE, не в
    /// Rust heap.
    ///
    /// `true` if ClientCore was bootstrapped with a hardware-backed
    /// identity (via `new_with_hw_callback`) — identity_sk physically
    /// resides in the TEE, not the Rust heap.
    #[must_use]
    pub fn has_hw_identity(&self) -> bool {
        self.hw_callback.is_some() && self.hw_identity_handle.is_some()
    }

    /// Returns a reference to the HW identity handle if bootstrapped with
    /// hardware backing.
    ///
    /// Returns a reference to the HW identity handle if bootstrapped with
    /// hardware backing.
    #[must_use]
    pub fn hw_identity_handle(&self) -> Option<&HwKeyHandle> {
        self.hw_identity_handle.as_ref()
    }

    /// Унифицированный accessor 32-байтового Ed25519 verifying-key для
    /// identity этого ClientCore. **F-CLIENT-HW-1 closure accessor.**
    ///
    /// Маршрутизация:
    ///
    /// - **HW path** ([`Self::new_with_hw_callback`]): возвращает cached
    ///   `hw_verifying_key`, заполненный через
    ///   [`PersistentKeyStoreCallback::verifying_key`] на bootstrap.
    ///   Identity_sk физически в TEE, accessor НЕ round-trip'ит в
    ///   keystore — O(1) memcpy из cached поля.
    /// - **Legacy path** ([`Self::new_for_test`]): возвращает
    ///   `identity.public().to_bytes()` через unwrap `Option`.
    /// - **Invariant violation** (не должен случаться у correctly-bootstrapped
    ///   ClientCore): обе ветки `None` → `ClientError::Internal`.
    ///
    /// Этот метод — единый точка для consumers (например `call/session.rs`
    /// DtlsRunner идентификация peer'а), которым нужны public bytes
    /// независимо от backing storage. До F-CLIENT-HW-1 closure consumers
    /// читали `core.identity.public().to_bytes()` напрямую, что (а)
    /// требовало hw path синтезировать ephemeral `IdentityKey` (M-FINAL-1
    /// gap) и (б) не позволяло выбрать между HW vs legacy без логики на
    /// caller-side.
    ///
    /// # Ошибки / Errors
    ///
    /// - `ClientError::Internal` если у ClientCore ни identity ни
    ///   hw_verifying_key — это invariant violation; correct construction
    ///   через [`Self::new_for_test`] / [`Self::new_with_hw_callback`]
    ///   гарантирует ровно одну из веток.
    ///
    /// Unified accessor for the 32-byte Ed25519 verifying-key of this
    /// ClientCore's identity. **F-CLIENT-HW-1 closure accessor.**
    ///
    /// Dispatch:
    ///
    /// - **HW path** ([`Self::new_with_hw_callback`]): returns the cached
    ///   `hw_verifying_key`, populated through
    ///   [`PersistentKeyStoreCallback::verifying_key`] at bootstrap. The
    ///   identity_sk lives in the TEE; this accessor does NOT round-trip
    ///   into the keystore — it is an O(1) memcpy from the cached field.
    /// - **Legacy path** ([`Self::new_for_test`]): returns
    ///   `identity.public().to_bytes()` through an `Option` unwrap.
    /// - **Invariant violation** (must not happen for a correctly
    ///   bootstrapped ClientCore): both branches `None` →
    ///   `ClientError::Internal`.
    ///
    /// This method is the single entry point for consumers (e.g. the
    /// `call/session.rs` DtlsRunner peer-identity binding) that need
    /// public bytes regardless of backing storage. Before the
    /// F-CLIENT-HW-1 closure consumers read
    /// `core.identity.public().to_bytes()` directly, which (a) forced
    /// the hw path to synthesise an ephemeral `IdentityKey` (the
    /// M-FINAL-1 gap) and (b) put HW-vs-legacy branching on the
    /// caller side.
    ///
    /// # Errors
    ///
    /// - `ClientError::Internal` if the ClientCore has neither identity
    ///   nor hw_verifying_key — an invariant violation; correct
    ///   construction via [`Self::new_for_test`] /
    ///   [`Self::new_with_hw_callback`] guarantees exactly one branch.
    pub fn identity_verifying_key(&self) -> Result<[u8; 32]> {
        if let Some(vk) = self.hw_verifying_key {
            return Ok(vk);
        }
        if let Some(id) = self.identity.as_ref() {
            return Ok(id.public().to_bytes());
        }
        Err(ClientError::Internal(
            "ClientCore invariant violated: neither identity nor hw_verifying_key is populated"
                .to_string(),
        ))
    }

    /// Канонический `KeyStore` impl для этого ClientCore.
    ///
    /// **F-IDENT-1 + F-IDENT-2 closure accessor (PhD-B Pass 5
    /// remediation 2026-05-19):** на hw-bootstrap path возвращает
    /// `Some(Arc<HwBackedKeyStore>)` — identity-sk операции
    /// маршрутизируются через TEE callback, без in-heap материализации.
    /// На legacy / test path возвращает `None` — Block 7.2 facade
    /// stubs до сих пор конструируют `InMemoryKeyStore` inline. Block
    /// 7.4+ facade refactor должен предпочитать `core.keystore()` над
    /// inline `InMemoryKeyStore::open` чтобы full closure F-IDENT-1
    /// + F-IDENT-2 был effective end-to-end (в hw-mode no seed
    /// materialised; в legacy mode keystore lifetime под контролем
    /// ClientCore).
    ///
    /// Canonical `KeyStore` impl for this ClientCore.
    ///
    /// **F-IDENT-1 + F-IDENT-2 closure accessor (PhD-B Pass 5
    /// remediation 2026-05-19):** on the hw-bootstrap path returns
    /// `Some(Arc<HwBackedKeyStore>)` — identity-sk operations route
    /// through the TEE callback, no in-heap materialisation. On the
    /// legacy / test path returns `None` — Block 7.2 facade stubs
    /// still construct `InMemoryKeyStore` inline. The Block 7.4+
    /// facade refactor must prefer `core.keystore()` over inline
    /// `InMemoryKeyStore::open` so the F-IDENT-1 + F-IDENT-2 closure
    /// is effective end-to-end (in hw-mode no seed is materialised;
    /// in legacy mode the keystore lifetime is owned by ClientCore).
    #[must_use]
    pub fn keystore(&self) -> Option<Arc<dyn KeyStore>> {
        self.keystore.clone()
    }

    /// Текущий активный gateway connection (QUIC либо WebSocket fallback) или
    /// `None`, если клиент ещё не установил соединение через
    /// [`Self::set_gateway`]. Клонирует `Arc<GatewayConnection>` под short
    /// read-lock — caller потом может делать network I/O без удержания
    /// блокировки на ClientCore.
    ///
    /// Currently active gateway connection (QUIC or WebSocket fallback), or
    /// `None` if the client has not yet attached one via [`Self::set_gateway`].
    /// Clones the `Arc<GatewayConnection>` under a brief read-lock — the
    /// caller can then perform network I/O without holding any ClientCore
    /// lock.
    pub async fn gateway(&self) -> Option<Arc<GatewayConnection>> {
        self.gateway.read().await.clone()
    }

    /// Install the given `GatewayConnection` as the active gateway transport.
    /// Replaces any previously installed connection (the old `Arc` drops when
    /// its last clone goes out of scope). Used by post-bootstrap connect flow
    /// and by tests that wire a mock gateway.
    ///
    /// Install the given `GatewayConnection` as the active gateway transport.
    /// Replaces any previously installed connection.
    pub async fn set_gateway(&self, gateway: Arc<GatewayConnection>) {
        *self.gateway.write().await = Some(gateway);
    }

    /// Clear the active gateway connection (e.g. logout / explicit disconnect).
    /// Subsequent facade sends will fall through to the backwards-compat stub
    /// path (returning `MessageId([0u8; 16])` for legacy callers) until a new
    /// `set_gateway` call.
    ///
    /// Clear the active gateway connection.
    pub async fn clear_gateway(&self) {
        *self.gateway.write().await = None;
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

    /// Bootstrap client с hardware-backed identity (round-5 device-capture
    /// closure F-PHD-DC-R7-1 / F-PHD-DC-R10-1). identity_sk физически
    /// находится в Secure Enclave / StrongBox; Rust держит только
    /// `HwKeyHandle`. Использует [`ClientCore::new_with_hw_callback`].
    ///
    /// Bootstrap a client with hardware-backed identity (round-5 device-
    /// capture closure F-PHD-DC-R7-1 / F-PHD-DC-R10-1). identity_sk
    /// physically resides in Secure Enclave / StrongBox; Rust holds only
    /// the `HwKeyHandle`. Uses [`ClientCore::new_with_hw_callback`].
    ///
    /// # Ошибки / Errors
    ///
    /// Same as [`ClientCore::new_with_hw_callback`]; in particular
    /// `ClientError::Platform(...)` on native-side failures.
    pub async fn bootstrap_with_hw_callback(
        config: ClientConfig,
        callback: Arc<dyn PersistentKeyStoreCallback>,
        label: impl Into<String>,
    ) -> Result<Arc<Self>> {
        let core = ClientCore::new_with_hw_callback(config, callback, label).await?;
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

    /// **F-CLIENT-HW-1 closure: legacy bootstrap invariant.**
    ///
    /// `new_for_test` (Block 7.2 wiring) materialises `IdentityKey` in
    /// Rust heap → `core.identity = Some(...)`. The hw_callback /
    /// hw_identity_handle / hw_verifying_key fields stay `None`. The
    /// `identity_verifying_key()` accessor returns the in-heap key's
    /// public bytes; this exactly matches a direct
    /// `IdentityKey::derive(...).public().to_bytes()` computation.
    ///
    /// Closure invariant after F-CLIENT-HW-1: HW-vs-legacy partition is
    /// total — every `ClientCore` is in exactly one of the two regimes.
    #[tokio::test]
    async fn f_client_hw_1_legacy_bootstrap_materializes_identity_and_no_hw_state() {
        let seed = test_seed();
        let direct_vk = umbrella_identity::IdentityKey::derive(&seed, 0)
            .expect("derive identity")
            .public()
            .to_bytes();

        let core = ClientCore::new_for_test(production_shaped_config(), seed)
            .await
            .expect("legacy bootstrap succeeds");

        assert!(
            core.identity.is_some(),
            "F-CLIENT-HW-1: legacy bootstrap MUST populate core.identity"
        );
        assert!(
            core.hw_callback.is_none(),
            "F-CLIENT-HW-1: legacy bootstrap MUST leave hw_callback None"
        );
        assert!(
            core.hw_identity_handle.is_none(),
            "F-CLIENT-HW-1: legacy bootstrap MUST leave hw_identity_handle None"
        );
        assert!(
            core.hw_verifying_key.is_none(),
            "F-CLIENT-HW-1: legacy bootstrap MUST leave hw_verifying_key None"
        );

        let accessor_vk = core
            .identity_verifying_key()
            .expect("identity_verifying_key succeeds on legacy core");
        assert_eq!(
            accessor_vk, direct_vk,
            "F-CLIENT-HW-1: legacy identity_verifying_key MUST match direct IdentityKey::derive(...).public()"
        );
    }

    /// **F-CLIENT-HW-1 closure: hw bootstrap invariant — no ephemeral
    /// IdentityKey materialization.**
    ///
    /// Pre-closure `new_with_hw_callback` synthesised an ephemeral
    /// `IdentitySeed` + `IdentityKey` to fill `core.identity`. That
    /// materialised 32 bytes of Ed25519 secret scalar in process heap
    /// for a microseconds-wide window (the M-FINAL-1 disclosure).
    ///
    /// Closure invariant: after `new_with_hw_callback`,
    /// `core.identity` is `None`, no `IdentityKey` instance exists, and
    /// the only identity-key material in Rust process state is the
    /// 32-byte verifying-key (public, not secret) cached in
    /// `hw_verifying_key`. Real signing scalar lives in
    /// Secure Enclave / StrongBox via the `hw_callback`.
    ///
    /// Concrete numbers: ephemeral identity_sk leak window pre-closure
    /// ≈ microseconds (sufficient for adversary process-memory inspection
    /// per round-4 R7 lldb attack); post-closure leak window = 0 (no
    /// secret scalar ever crosses into Rust heap on this path).
    #[tokio::test]
    async fn f_client_hw_1_hw_bootstrap_does_not_materialize_ephemeral_identity_key() {
        use crate::keystore::hw_callback::{MockHwKeystore, PersistentKeyStoreCallback};

        let mock = Arc::new(MockHwKeystore::new());
        let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
        let core = ClientCore::new_with_hw_callback(
            production_shaped_config(),
            callback,
            "f-client-hw-1.no-ephemeral-identity",
        )
        .await
        .expect("hw bootstrap succeeds");

        assert!(
            core.identity.is_none(),
            "F-CLIENT-HW-1 closure REGRESSION: hw bootstrap MUST NOT materialize \
             ephemeral IdentityKey — pre-closure synthesised one to fill the slot, \
             leaking 32 bytes of Ed25519 secret to Rust heap for microseconds"
        );
        assert!(
            core.hw_callback.is_some(),
            "F-CLIENT-HW-1: hw bootstrap MUST populate hw_callback"
        );
        assert!(
            core.hw_identity_handle.is_some(),
            "F-CLIENT-HW-1: hw bootstrap MUST populate hw_identity_handle"
        );
        assert!(
            core.hw_verifying_key.is_some(),
            "F-CLIENT-HW-1: hw bootstrap MUST populate hw_verifying_key cache"
        );

        // Cached verifying_key MUST equal the keystore's verifying_key
        // for the bound handle — no drift between bootstrap-time fetch
        // and runtime callback query (the smoke-test inside
        // bootstrap_hw_identity also covers this, but defense in depth).
        let handle = core.hw_identity_handle.as_ref().expect("handle present");
        let direct_vk = mock
            .verifying_key(handle)
            .expect("callback yields verifying_key");
        let cached_vk = core
            .hw_verifying_key
            .expect("hw_verifying_key cache populated");
        assert_eq!(
            cached_vk, direct_vk,
            "F-CLIENT-HW-1: cached hw_verifying_key MUST equal callback's verifying_key"
        );
    }

    /// **F-IDENT-1 + F-IDENT-2 closure: keystore partition invariant.**
    ///
    /// `core.keystore` populated on hw bootstrap (HwBackedKeyStore — no
    /// `IdentitySeed`, no `IdentityKey`, callback-only signing path);
    /// `None` on legacy bootstrap (Block 7.2 facades construct
    /// `InMemoryKeyStore` inline in test wiring). The partition is
    /// total — every correctly-bootstrapped ClientCore is in exactly one
    /// regime — and the two regimes are disjoint at runtime.
    ///
    /// Concrete F-IDENT-2 reduction: pre-closure, `InMemoryKeyStore`
    /// holds `seed: IdentitySeed` (64 bytes BIP-39 PBKDF2-derived seed)
    /// for the keystore's lifetime — `add_device` re-derives every
    /// device key from that seed at request time, so an adversary with
    /// runtime memory access can regenerate every device_sk plus the
    /// identity_sk without leaking individual device material directly.
    /// Post-closure, on the hw path, `core.keystore` is a
    /// `HwBackedKeyStore` instance whose memory layout contains 0 bytes
    /// of secret seed material (size_of check in
    /// `keystore::hw_backed::tests`); signing scalar lives in TEE.
    #[tokio::test]
    async fn f_ident_1_2_keystore_partition_total_and_disjoint() {
        use crate::keystore::hw_callback::{MockHwKeystore, PersistentKeyStoreCallback};

        // Legacy bootstrap: keystore is None (Block 7.2 facades still
        // use inline InMemoryKeyStore via test wiring).
        let legacy_core =
            ClientCore::new_for_test(production_shaped_config(), test_seed())
                .await
                .expect("legacy bootstrap");
        assert!(
            legacy_core.keystore.is_none(),
            "F-IDENT-1 closure: legacy bootstrap MUST leave core.keystore None — Block 7.2 \
             facades still construct InMemoryKeyStore inline; Block 7.4+ refactor will \
             consolidate via core.keystore() accessor"
        );

        // HW bootstrap: keystore is Some(HwBackedKeyStore) — F-IDENT-1
        // closure registers canonical KeyStore impl that routes
        // identity-sk operations through callback. F-IDENT-2 closure:
        // HwBackedKeyStore has no `seed` field (see hw_backed.rs tests).
        let mock = Arc::new(MockHwKeystore::new());
        let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
        let hw_core = ClientCore::new_with_hw_callback(
            production_shaped_config(),
            callback,
            "f-ident-1-2.keystore-partition",
        )
        .await
        .expect("hw bootstrap");
        assert!(
            hw_core.keystore.is_some(),
            "F-IDENT-1 closure: hw bootstrap MUST register canonical HwBackedKeyStore in core.keystore"
        );

        // Round-trip: sign through the registered keystore, verify
        // under hw_verifying_key. Pre-closure, NO production-suitable
        // KeyStore impl existed for hw bootstrap (InMemoryKeyStore needs
        // a seed); post-closure, the hw keystore is fully functional
        // for identity-sk operations. Verification uses ed25519_dalek
        // directly because `IdentityKeyPublic::verify` is `pub(crate)`
        // in umbrella-identity and not reachable across crates — same
        // pattern as the rest of the F-CLIENT-HW-1 closure regression
        // suite.
        let keystore = hw_core.keystore.as_ref().expect("hw keystore");
        let msg = b"F-IDENT-1 closure keystore round-trip";
        let sig = keystore.sign_with_identity(msg);

        let hw_vk_bytes = hw_core.hw_verifying_key.expect("hw_verifying_key");
        let dalek_vk = ed25519_dalek::VerifyingKey::from_bytes(&hw_vk_bytes)
            .expect("hw_verifying_key decodes as Ed25519 point");
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.to_bytes());
        ed25519_dalek::Verifier::verify(&dalek_vk, msg, &dalek_sig)
            .expect("F-IDENT-1: hw keystore signature MUST verify under cached hw_verifying_key");

        // Sanity: identity_public reported by the keystore matches the
        // cached hw_verifying_key bytes — no drift between the two
        // pubkey surfaces on the hw path.
        assert_eq!(
            keystore.identity_public().to_bytes(),
            hw_vk_bytes,
            "F-IDENT-1: hw keystore identity_public MUST equal cached hw_verifying_key bytes"
        );
        assert_eq!(keystore.account(), 0);
    }

    /// **F-CLIENT-HW-1 closure: unified accessor invariant.**
    ///
    /// `identity_verifying_key()` is the single accessor consumers (e.g.
    /// `call/session.rs` DtlsRunner) reach for. It MUST:
    ///
    /// 1. Return cached `hw_verifying_key` bytes verbatim when present.
    /// 2. Fall back to `identity.public().to_bytes()` for legacy cores.
    /// 3. Never call into the keystore callback (no TEE round-trip per
    ///    read — the cache exists to avoid that).
    ///
    /// Pre-closure consumers read `core.identity.public().to_bytes()`
    /// directly, which required `new_with_hw_callback` to synthesise an
    /// ephemeral IdentityKey (the M-FINAL-1 gap).
    #[tokio::test]
    async fn f_client_hw_1_identity_verifying_key_dispatches_correctly() {
        use crate::keystore::hw_callback::{MockHwKeystore, PersistentKeyStoreCallback};

        // HW path: accessor returns cached hw_verifying_key.
        let mock = Arc::new(MockHwKeystore::new());
        let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
        let hw_core = ClientCore::new_with_hw_callback(
            production_shaped_config(),
            callback,
            "f-client-hw-1.accessor.hw",
        )
        .await
        .expect("hw bootstrap");
        let hw_handle = hw_core
            .hw_identity_handle
            .as_ref()
            .expect("handle present");
        let hw_direct = mock
            .verifying_key(hw_handle)
            .expect("callback verifying_key");
        let hw_accessor = hw_core
            .identity_verifying_key()
            .expect("accessor on hw core");
        assert_eq!(
            hw_accessor, hw_direct,
            "F-CLIENT-HW-1: hw path accessor MUST equal callback.verifying_key(handle)"
        );

        // Legacy path: accessor returns identity.public().to_bytes().
        let seed = test_seed();
        let legacy_direct = umbrella_identity::IdentityKey::derive(&seed, 0)
            .expect("derive")
            .public()
            .to_bytes();
        let legacy_core = ClientCore::new_for_test(production_shaped_config(), seed)
            .await
            .expect("legacy bootstrap");
        let legacy_accessor = legacy_core
            .identity_verifying_key()
            .expect("accessor on legacy core");
        assert_eq!(
            legacy_accessor, legacy_direct,
            "F-CLIENT-HW-1: legacy path accessor MUST equal identity.public().to_bytes()"
        );

        // Cross-check: hw_accessor and legacy_accessor should differ
        // (the mock's randomly-generated hw identity vs the legacy
        // derived-from-seed identity are independent CSPRNG outputs;
        // collision probability ≈ 2^-256 per the Ed25519 spec).
        assert_ne!(
            hw_accessor, legacy_accessor,
            "F-CLIENT-HW-1 sanity: hw and legacy verifying-keys are independent"
        );
    }
}
