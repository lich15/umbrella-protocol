//! Центральное состояние клиента. Один `ClientCore` на аккаунт на устройство.
//! Инициализируется через [`UmbrellaClient::bootstrap_for_test`] (Блок 7.2) или
//! — в 7.3+ — через production `UmbrellaClient::bootstrap` с hardware-backed
//! KeyStore и реальными HTTP/2 транспортами.
//!
//! Client core state. One `ClientCore` per account per device. Initialized via
//! [`UmbrellaClient::bootstrap_for_test`] (Block 7.2), or — in Block 7.3+ — the
//! production `UmbrellaClient::bootstrap` with a hardware-backed KeyStore and
//! real HTTP/2 transports.

use std::collections::HashMap;
use std::sync::Arc;

use rand_core::OsRng;
use tokio::sync::{Mutex as TokioMutex, RwLock};
use umbrella_backup::cloud_wrap::WrappingParams;
use umbrella_calls::CallPolicy;
use umbrella_identity::{
    Clock, IdentityKey, IdentitySeed, IdentityX25519KeyPublic, InMemoryKeyStore, KeyStore,
    MnemonicLanguage, SystemClock,
};
use umbrella_kt::{KtLogState, WitnessSet};
use umbrella_mls::{MaxRatchetState, UmbrellaGroup, UmbrellaProvider};

use crate::error::{ClientError, Result};
#[cfg(feature = "pq")]
use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_PQ_HYBRID;
use crate::facade::chat_common::{ChatId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use crate::keystore::hw_backed::HwBackedKeyStore;
use crate::keystore::hw_callback::{
    bootstrap_hw_identity, HwKeyHandle, PersistentKeyStoreCallback,
};
use crate::transport::async_unwrap::AsyncUnwrapTransport;
use crate::transport::gateway::GatewayConnection;
use crate::transport::stub::{
    StubCallRelayTransport, StubKtTransport, StubPostmanTransport, StubUnwrapTransport,
};

pub use crate::transport::stub::CloudHistoryEntry;

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

/// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** combined hardware-keystore
/// identity state — opaque handle + cached 32-byte Ed25519 verifying-key.
/// Wrapped together in a single `std::sync::RwLock` inside [`ClientCore`]
/// so post-rotation refresh ([`ClientCore::swap_hw_identity`]) updates
/// both fields atomically — readers never see an `(new_handle, old_vk)`
/// либо `(old_handle, new_vk)` transient.
///
/// `handle` и `verifying_key` оба `Some` либо оба `None` invariant: the
/// hw-bootstrap path populates both; legacy / test paths leave both
/// `None`. The atomic swap operation preserves this invariant.
///
/// Public for tests + advanced FFI callers; production usage typically
/// flows through `ClientCore` accessor methods.
///
/// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** combined hardware-
/// keystore identity state — opaque handle + cached 32-byte Ed25519
/// verifying-key. Wrapped together in a single `std::sync::RwLock`
/// inside [`ClientCore`] so post-rotation refresh
/// ([`ClientCore::swap_hw_identity`]) updates both fields atomically —
/// readers never observe a `(new_handle, old_vk)` or
/// `(old_handle, new_vk)` transient.
#[derive(Clone, Debug, Default)]
pub struct HwIdentityState {
    /// Opaque alias на TEE-resident identity key. `None` для legacy /
    /// test path'ей либо до bootstrap.
    ///
    /// Opaque alias to the TEE-resident identity key. `None` for legacy /
    /// test paths or before bootstrap.
    pub handle: Option<HwKeyHandle>,
    /// 32-byte Ed25519 verifying-key for the hardware-resident identity.
    /// `None` если HW identity ещё не bootstrapped (или legacy path'ей).
    pub verifying_key: Option<[u8; 32]>,
}

/// Centralized state container shared across facade methods —
/// identity material, HW callback wiring, KT/MLS provider, transport
/// stubs, group registry, etc. Constructed via [`Self::new_for_test`]
/// (in-memory test path) or [`Self::new_with_hw_callback`] (production
/// HW-backed path). Mutability is field-scoped through interior locks
/// (e.g. [`Self::mls_keystore`] swap, [`Self::hw_identity_state`]
/// rotation refresh); the outer `Arc<ClientCore>` is shared read-only.
///
/// Centralized state container shared across facade methods. Mutability
/// is field-scoped through interior locks; the outer `Arc<ClientCore>`
/// is shared read-only.
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

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** typed clone of
    /// [`Self::unwrap_transport`] для test scaffolding. `Some` когда
    /// `new_for_test` / `new_with_hw_callback` поставили
    /// `StubUnwrapTransport` (текущее состояние Block 7.2); `None` когда
    /// будущий production transport будет wired (Block 7.4+). Не использовать
    /// в production code path'ах — только для test rigs которым нужно
    /// `push_response` с pre-baked Sealed Server shares.
    ///
    /// Typed clone of `unwrap_transport` for test scaffolding (some when stub,
    /// none when production transport is wired in Block 7.4+).
    pub(crate) stub_unwrap_transport: Option<Arc<StubUnwrapTransport>>,

    /// Транспорт к blind-postman-svc для Cloud ciphertext и Secret inbox.
    ///
    /// Transport to blind-postman-svc for Cloud ciphertext and Secret inbox.
    pub(crate) postman_transport: Arc<StubPostmanTransport>,

    /// Транспорт к kt-svc и 3-of-5 witness-ам.
    ///
    /// Transport to kt-svc and its 3-of-5 witnesses.
    pub(crate) kt_transport: Arc<StubKtTransport>,

    /// **F-CLIENT-FACADE-1 session 8c1 (2026-05-19):** pinned набор 5
    /// witness-Ed25519-pubkey'ев из SPKI pinning в production либо tests
    /// fixture. Используется
    /// [`crate::kt_monitor::verify_kt_witness_signatures_for_epoch`] как
    /// аргумент для `umbrella_kt::witness::verify_signed_epoch`. Default:
    /// empty `WitnessSet` (helper тогда возвращает
    /// `InsufficientValidSignatures { valid: 0, required: threshold }` пока
    /// witness set не настроен — fail-closed по постулату 14).
    ///
    /// **Runtime mutability**: production native bootstrap layer ставит
    /// pinned set через [`Self::set_kt_witness_set`] после reading SPKI
    /// pins; KT rotation events (epoch where witnesses themselves
    /// перевыбираются — рассматривается в SPEC-09 §6.2 future work,
    /// post-1.0.0) тоже идут через тот же setter.
    ///
    /// **F-CLIENT-FACADE-1 session 8c1:** pinned set of 5 witness Ed25519
    /// pubkeys (SPKI pinning in production / test fixture override).
    /// Read by `kt_monitor::verify_kt_witness_signatures_for_epoch`;
    /// mutated via [`Self::set_kt_witness_set`] at native bootstrap time
    /// and on future KT-witness-rotation events (post-1.0.0).
    pub(crate) kt_witness_set: Arc<RwLock<WitnessSet>>,

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

    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** combined HW identity
    /// state (handle + cached verifying-key) under a single `std::sync::RwLock`
    /// for **atomic refresh post-rotation** via [`Self::swap_hw_identity`].
    /// Wrapping both fields together (rather than two independent locks)
    /// guarantees readers never observe an `(new_handle, old_vk)` либо
    /// `(old_handle, new_vk)` transient — either both fields reflect the
    /// pre-rotation identity или both reflect the post-rotation identity.
    ///
    /// **Pre-session-9e**: two independent `Option` fields with no swap
    /// API — rotation orchestration left these stale (session 9d closure
    /// docs explicitly noted this as a follow-up). Session 9e closes
    /// the gap so `core.hw_identity_handle()` /
    /// `core.identity_verifying_key()` post-rotation reflect the new
    /// identity, completing the full-state-consistency invariant.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** combined HW identity
    /// state (handle + cached verifying-key) under a single
    /// `std::sync::RwLock` for **atomic refresh post-rotation** via
    /// [`Self::swap_hw_identity`]. Wrapping both fields together (rather
    /// than two independent locks) guarantees readers never observe an
    /// `(new_handle, old_vk)` or `(old_handle, new_vk)` transient —
    /// either both fields reflect the pre-rotation identity or both
    /// reflect the post-rotation identity.
    pub(crate) hw_identity_state: std::sync::RwLock<HwIdentityState>,

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
    ///
    /// **F-CLIENT-FACADE-1 session 9f (2026-05-19):** wrapped in
    /// `std::sync::RwLock` for atomic refresh post-rotation
    /// (`rotate_identity_full` Layer 4) — keeps the F-IDENT-1 partition
    /// invariant consistent после identity rotation. Without this swap
    /// the slot would hold a `HwBackedKeyStore` bound to the
    /// pre-rotation handle / verifying-key while
    /// `core.mls_keystore` + `core.hw_identity_state` reflect the
    /// post-rotation identity — split-state bug for Block 7.4+ facade
    /// consumers that read from `core.keystore()`.
    ///
    /// **F-CLIENT-FACADE-1 session 9f (2026-05-19):** wrapped in
    /// `std::sync::RwLock` for atomic refresh post-rotation
    /// (`rotate_identity_full` Layer 4). Keeps the F-IDENT-1 partition
    /// invariant consistent across rotation.
    pub(crate) keystore: std::sync::RwLock<Option<Arc<dyn KeyStore>>>,

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

    /// MLS RFC 9420 provider (RustCrypto AEAD/HPKE/Sig + in-memory storage). Один
    /// instance на `ClientCore` — все MLS-группы внутри одного клиента используют
    /// одну общую storage area (KeyPackage privates, group state, signing keys).
    ///
    /// **F-CLIENT-FACADE-1 session 5 (2026-05-19):** Wire-up для real MLS encrypt/
    /// decrypt через [`UmbrellaGroup`] вместо placeholder text-as-bytes. См.
    /// [`Self::mls_provider`] accessor для consumer-facing API; внутренний slot
    /// `pub(crate)` чтобы фасады могли передавать `&UmbrellaProvider` в
    /// `UmbrellaGroup::encrypt_application` / `process_incoming` без acquiring
    /// дополнительных lock-ов.
    ///
    /// MLS RFC 9420 provider (RustCrypto AEAD/HPKE/Sig + in-memory storage). One
    /// instance per `ClientCore` — all MLS groups inside a single client share
    /// one storage area (KeyPackage privates, group state, signing keys).
    pub(crate) mls_provider: Arc<UmbrellaProvider>,

    /// Каноничный MLS [`KeyStore`] этого `ClientCore`. Содержит identity-key и
    /// `device_index = 0` (Block 7.2 single-device); используется
    /// [`UmbrellaGroup::create_private`] / `encrypt_application` /
    /// `add_members` для credential binding + device signing.
    ///
    /// Поле **отдельно** от [`Self::keystore`] (F-IDENT-1 partition invariant): тот
    /// слот остаётся `None` на legacy path и `Some(HwBackedKeyStore)` на hw path
    /// и описывает identity-sk storage policy. `mls_keystore` — всегда
    /// `Some(InMemoryKeyStore)` независимо от bootstrap path; на hw path
    /// derive'ится из независимого random seed (production HW MLS device-key
    /// callback — F-IDENT-DEVICE-1 v1.2.x, scope outside session 5).
    ///
    /// Canonical MLS [`KeyStore`] for this `ClientCore`. Holds identity-key and
    /// `device_index = 0` (Block 7.2 single-device); consumed by
    /// [`UmbrellaGroup::create_private`] / `encrypt_application` /
    /// `add_members` for credential binding + device signing.
    ///
    /// This field is **separate** from [`Self::keystore`] (F-IDENT-1 partition
    /// invariant): the latter stays `None` on the legacy path and is
    /// `Some(HwBackedKeyStore)` on the hw path, describing the identity-sk
    /// storage policy. `mls_keystore` is always populated regardless of
    /// bootstrap path; on the hw path it derives from an independent random
    /// seed (production HW MLS device-key callback is F-IDENT-DEVICE-1, tracked
    /// for v1.2.x — outside session 5 scope).
    ///
    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** обёрнут в
    /// `std::sync::RwLock` для поддержки atomic replacement через
    /// [`Self::swap_mls_keystore`] после publication ротации identity
    /// (`rotate_identity_full` facade). Все readers идут через accessor
    /// [`Self::mls_keystore`] который returns `Arc` clone — поэтому
    /// держатели старого Arc продолжают видеть pre-rotation state, а
    /// новые `core.mls_keystore()` calls видят post-rotation state.
    /// Lock — `std::sync::RwLock` (не tokio): identity_public/sign — sync
    /// операции, не требуют `.await`.
    ///
    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** wrapped in
    /// `std::sync::RwLock` to support atomic replacement via
    /// [`Self::swap_mls_keystore`] after an identity-rotation publish
    /// (`rotate_identity_full` facade). All readers go through accessor
    /// [`Self::mls_keystore`] which returns an `Arc` clone — holders of
    /// the old `Arc` continue to see pre-rotation state while subsequent
    /// `core.mls_keystore()` calls see the post-rotation state. The lock
    /// is `std::sync::RwLock` (not tokio): identity_public/sign are sync
    /// operations and do not need `.await`.
    pub(crate) mls_keystore: std::sync::RwLock<Arc<dyn KeyStore>>,

    /// Map `ChatId -> UmbrellaGroup` — active MLS group state per chat.
    /// `Arc<TokioMutex<UmbrellaGroup>>` per value — каждой группе нужна
    /// exclusive mut access для encrypt/decrypt/add_members; разные группы
    /// независимы и могут оперировать concurrently (read-lock на outer map).
    ///
    /// **F-CLIENT-FACADE-1 session 5 (2026-05-19):** новое поле. До session 5
    /// `CloudChat::create` / `SecretChat::create` возвращали `ChatId([0u8; 32])`
    /// stub; теперь генерируют random 32-byte chat_id, конструируют real
    /// `UmbrellaGroup::create_private` и регистрируют её здесь. `send_mls_text`
    /// и `fetch_mls_inbox` (chat_common) lookup группы по `chat_id` и используют
    /// `encrypt_application` / `process_incoming`. Backwards-compat: если
    /// `chat_id` отсутствует в map (e.g. test, который открыл chat через
    /// stub `CloudChat::open(ChatId([0u8; 32]))`), facade fall-back в legacy
    /// raw-bytes path (без MLS).
    ///
    /// Map `ChatId -> UmbrellaGroup` — active MLS group state per chat.
    /// `Arc<TokioMutex<UmbrellaGroup>>` per value: each group needs exclusive
    /// mut access for encrypt/decrypt/add_members; distinct groups are
    /// independent and can operate concurrently (the outer map is read-locked).
    ///
    /// **F-CLIENT-FACADE-1 session 5 (2026-05-19):** new field. Prior to
    /// session 5 `CloudChat::create` / `SecretChat::create` returned
    /// `ChatId([0u8; 32])` stub; now they generate a random 32-byte chat_id,
    /// construct a real `UmbrellaGroup::create_private`, and register it here.
    /// `send_mls_text` and `fetch_mls_inbox` (chat_common) look the group up by
    /// `chat_id` and use `encrypt_application` / `process_incoming`. Backwards-
    /// compat: if `chat_id` is absent (e.g. a test that opened a chat via the
    /// stub `CloudChat::open(ChatId([0u8; 32]))`), the facade falls back to the
    /// legacy raw-bytes path (no MLS).
    pub(crate) groups: RwLock<HashMap<ChatId, Arc<TokioMutex<UmbrellaGroup>>>>,

    /// **F-CLIENT-FACADE-1 session 6c (2026-05-19):** per-chat монотонный
    /// counter для Cloud-режима at-rest `msg_seq` (binding в
    /// `canonical_nonce(chat_id, msg_seq)` deterministic AEAD nonce
    /// derivation + nonce-reuse prevention). Sender инкрементирует на
    /// каждый Cloud-mode send. Recipient получает `msg_seq` как часть
    /// `CloudHistoryEntry` для AEAD decrypt без negotiation с sender'ом.
    ///
    /// **Invariant**: counter strictly monotonic per `ChatId`. Reuse того же
    /// (chat_id, msg_seq) даёт nonce reuse → ChaCha20-Poly1305 security
    /// broken catastrophically (XOR encryption with same keystream). Postman
    /// side обязан dedup'ить (production); session 6c sender-side counter
    /// предотвращает naive reuse внутри одного process lifetime.
    ///
    /// **Persistence**: in-memory только (не serialized) — после restart
    /// counter сброс в 0, что нарушит invariant если те же chat'ы продолжают
    /// receive новые сообщения. Production persistent storage — session 7+.
    ///
    /// Per-chat monotonic counter for Cloud-mode at-rest `msg_seq` (used in
    /// `canonical_nonce` deterministic AEAD nonce derivation). Sender
    /// increments on each Cloud-mode send. Production-grade persistence
    /// across restarts is deferred to session 7+.
    pub(crate) cloud_msg_seq_counters: RwLock<HashMap<ChatId, u64>>,

    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** Map peer Ed25519
    /// identity_pk → [`IdentityX25519KeyPublic`] (long-lived X25519 identity
    /// pubkey, derived deterministically from the peer's seed via
    /// `m / 0x554D' / account' / 4'` per `umbrella_identity::identity_x25519`).
    /// Used by [`crate::SecretChat`] send/fetch path to look up recipient
    /// X25519 pubkey for sealed-sender envelope wrapping (V1 wire-format —
    /// `umbrella_sealed_sender::seal` requires explicit `recipient_x25519`
    /// argument, no implicit derivation from Ed25519 identity_pk possible).
    ///
    /// **Production**: populated from Key Transparency (KT) directory
    /// lookups when a chat is opened, a new peer is added, or KT
    /// self-monitoring catches a rotation — wire-up in session 8+ when
    /// `umbrella-kt` is consumed.
    /// **Tests**: populated explicitly via [`Self::register_peer_x25519`]
    /// before calls to `SecretChat::send_text` so envelope sealing finds
    /// the recipient X25519 pubkey.
    ///
    /// **Fail-closed invariant**: если group member для chat'а отсутствует
    /// в этом directory во время `SecretChat::send_text`, send fails с
    /// `ClientError::SealedSender(Malformed { reason: "no X25519 pubkey
    /// registered..." })`. Постулат 14 — никакого silent fallback на
    /// unsealed delivery (это бы leak'нуло sender identity_pk на gateway
    /// для одного-conditional-failed peer).
    ///
    /// **F-CLIENT-FACADE-1 session 7:** Map peer Ed25519 identity_pk →
    /// `IdentityX25519KeyPublic`. Populated from KT directory lookups
    /// (production) or test fixtures (session 7+). Fail-closed if a group
    /// member is missing from the directory at send time.
    pub(crate) peer_x25519_directory: RwLock<HashMap<[u8; 32], IdentityX25519KeyPublic>>,

    /// **Task 6 max_ratchet v3 facade integration (2026-05-20):** per-chat
    /// [`MaxRatchetState`] storage. Параллельно с `groups` хранит state защит
    /// (commit_counter + last_timer_check_unix + config) для каждого active chat'а.
    /// Auto-create'ится при [`Self::register_group`]; unregister'ится вместе с group.
    /// Sender side в `send_mls_text` lock'ает state перед encrypt_with_rekey_authenticated.
    ///
    /// **Task 6 max_ratchet v3 facade integration (2026-05-20):** per-chat
    /// `MaxRatchetState` storage, kept in parallel to `groups`. Auto-created at
    /// `register_group` and unregistered alongside the group.
    pub(crate) ratchet_states: RwLock<HashMap<ChatId, Arc<TokioMutex<MaxRatchetState>>>>,
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

        let stub_unwrap = Arc::new(StubUnwrapTransport::default());
        let unwrap_transport: Arc<dyn AsyncUnwrapTransport + Send + Sync> = stub_unwrap.clone();

        // F-CLIENT-FACADE-1 session 5: MLS keystore shares the same BIP-39
        // seed as `identity`, so the MLS credential payload (`identity_pk |
        // device_index_BE`) matches `IdentityKey::derive(&seed, 0).public()`
        // — wire-format consistency across identity-layer and MLS-layer
        // surfaces. `InMemoryKeyStore::open` re-derives identity internally
        // (small CPU cost, no semantic divergence). Device 0 registered
        // so `UmbrellaGroup::create_private` / `encrypt_application` can
        // build the device-key signer.
        let mls_keystore_inner =
            InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)?;
        mls_keystore_inner.add_device(0, None)?;
        let mls_keystore: Arc<dyn KeyStore> = Arc::new(mls_keystore_inner);
        let mls_keystore = std::sync::RwLock::new(mls_keystore);
        let mls_provider = Arc::new(UmbrellaProvider::default());

        Ok(Arc::new(Self {
            identity: Some(identity),
            device_index: 0,
            kt_state: Arc::new(RwLock::new(KtLogState::new())),
            unwrap_transport,
            postman_transport: Arc::new(StubPostmanTransport::default()),
            kt_transport: Arc::new(StubKtTransport::default()),
            kt_witness_set: Arc::new(RwLock::new(WitnessSet::new())),
            call_relay_transport: Arc::new(StubCallRelayTransport::default()),
            user_policy: Arc::new(RwLock::new(CallPolicy::default())),
            config,
            hw_callback: None,
            hw_identity_state: std::sync::RwLock::new(HwIdentityState::default()),
            // Legacy/test path: facades still construct InMemoryKeyStore
            // inline. F-IDENT-1 closure leaves this slot None on legacy
            // bootstraps; Block 7.4+ facade refactor will consolidate.
            keystore: std::sync::RwLock::new(None),
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap
            // via `set_gateway` — tests opting into the real send path
            // construct a mock GatewayTransport and install it here.
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap.
            gateway: RwLock::new(None),
            mls_provider,
            mls_keystore,
            groups: RwLock::new(HashMap::new()),
            stub_unwrap_transport: Some(stub_unwrap),
            cloud_msg_seq_counters: RwLock::new(HashMap::new()),
            peer_x25519_directory: RwLock::new(HashMap::new()),
            ratchet_states: RwLock::new(HashMap::new()),
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

        let stub_unwrap = Arc::new(StubUnwrapTransport::default());
        let unwrap_transport: Arc<dyn AsyncUnwrapTransport + Send + Sync> = stub_unwrap.clone();

        // F-IDENT-1 + F-IDENT-2 closure: construct the canonical
        // `HwBackedKeyStore` over the bootstrap byproducts. Identity-sk
        // operations route through `callback.sign_identity` — no
        // IdentitySeed materialisation. Account index hardcoded to 0
        // for Block 7.2; multi-account work is a Block 7.4+ refactor.
        let hw_keystore =
            HwBackedKeyStore::new(0, callback.clone(), handle.clone(), verifying_key)?;
        let keystore: Arc<dyn KeyStore> = Arc::new(hw_keystore);

        // F-CLIENT-FACADE-1 session 5: на hw path нет shared IdentitySeed —
        // identity-sk физически в TEE. MLS device-keys требуют отдельный
        // seed-backed `InMemoryKeyStore` (production HW MLS device-key
        // callback — F-IDENT-DEVICE-1 в v1.2.x, outside session 5 scope).
        // Эта material — fresh random Ed25519/X25519/HKDF-derived с
        // CSPRNG `OsRng`; на этом keystore credential.identity_pk ≠
        // `hw_verifying_key`, поэтому MLS-уровневая идентичность
        // на hw path **отделена** от identity-уровневой до F-IDENT-DEVICE-1
        // closure. Документировано в memory project_phd_b_pass5_complete
        // как session-5 transitional gap.
        // `IdentitySeed::generate` deprecated для production identity path
        // (round-6 distributed identity предписывает `bootstrap_account`); здесь
        // используется ТОЛЬКО для throwaway MLS device-keystore seed на hw path
        // — это **не** identity_sk. Identity_sk остаётся в TEE через
        // `callback`. F-IDENT-DEVICE-1 v1.2.x устранит need в этом seed
        // когда HW MLS device-key callback будет wired.
        //
        // `IdentitySeed::generate` deprecation deliberately suppressed: this is
        // a throwaway MLS device-key seed for the hw bootstrap path, NOT the
        // user's identity_sk (which stays in TEE via `callback`).
        // F-IDENT-DEVICE-1 (v1.2.x) will remove the need for this seed once
        // a HW MLS device-key callback is wired.
        #[allow(deprecated)]
        let mls_seed = IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English);
        let mls_keystore_inner =
            InMemoryKeyStore::open(mls_seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)?;
        mls_keystore_inner.add_device(0, None)?;
        let mls_keystore: Arc<dyn KeyStore> = Arc::new(mls_keystore_inner);
        let mls_keystore = std::sync::RwLock::new(mls_keystore);
        let mls_provider = Arc::new(UmbrellaProvider::default());

        Ok(Arc::new(Self {
            identity: None,
            device_index: 0,
            kt_state: Arc::new(RwLock::new(KtLogState::new())),
            unwrap_transport,
            postman_transport: Arc::new(StubPostmanTransport::default()),
            kt_transport: Arc::new(StubKtTransport::default()),
            kt_witness_set: Arc::new(RwLock::new(WitnessSet::new())),
            call_relay_transport: Arc::new(StubCallRelayTransport::default()),
            user_policy: Arc::new(RwLock::new(CallPolicy::default())),
            config,
            hw_callback: Some(callback),
            hw_identity_state: std::sync::RwLock::new(HwIdentityState {
                handle: Some(handle),
                verifying_key: Some(verifying_key),
            }),
            keystore: std::sync::RwLock::new(Some(keystore)),
            // F-CLIENT-FACADE-1 session 3: gateway is set post-bootstrap.
            gateway: RwLock::new(None),
            mls_provider,
            mls_keystore,
            groups: RwLock::new(HashMap::new()),
            stub_unwrap_transport: Some(stub_unwrap),
            cloud_msg_seq_counters: RwLock::new(HashMap::new()),
            peer_x25519_directory: RwLock::new(HashMap::new()),
            ratchet_states: RwLock::new(HashMap::new()),
        }))
    }

    /// `true` если ClientCore был bootstrapped с hardware-backed identity
    /// (через `new_with_hw_callback`) — identity_sk физически в TEE, не в
    /// Rust heap.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** reads `handle`
    /// presence under a brief read-lock on [`Self::hw_identity_state`].
    /// Post-rotation refresh via [`Self::swap_hw_identity`] preserves
    /// the invariant: HW identity is bootstrapped iff `hw_callback` is
    /// `Some` AND the current `hw_identity_state.handle` is `Some`.
    ///
    /// `true` if ClientCore was bootstrapped with a hardware-backed
    /// identity (via `new_with_hw_callback`) — identity_sk physically
    /// resides in the TEE, not the Rust heap.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** reads handle
    /// presence under a brief read-lock on [`Self::hw_identity_state`].
    #[must_use]
    pub fn has_hw_identity(&self) -> bool {
        self.hw_callback.is_some()
            && self
                .hw_identity_state
                .read()
                .expect("hw_identity_state rwlock poisoned")
                .handle
                .is_some()
    }

    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19) signature change:**
    /// returns an owned `Option<HwKeyHandle>` (cloned under brief read-
    /// lock) rather than the pre-9e `Option<&HwKeyHandle>` reference.
    /// The change is required by the new `RwLock<HwIdentityState>`
    /// storage — returning a borrow would require an unwieldy
    /// `MappedRwLockReadGuard` либо lifetime gymnastics that conflict
    /// with `swap_hw_identity` semantics.
    ///
    /// `HwKeyHandle` is cheap to clone (newtype around `String` alias),
    /// so this is acceptable for production hot paths. Callers that
    /// previously took `.as_ref().clone()` can drop the redundant
    /// `.clone()`.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19) signature change:**
    /// returns an owned `Option<HwKeyHandle>` (cloned under a brief
    /// read-lock) instead of the pre-9e `Option<&HwKeyHandle>`. The
    /// `RwLock<HwIdentityState>` storage made a borrow accessor
    /// awkward; `HwKeyHandle` is a cheap newtype around an alias
    /// `String`, so cloning is a non-issue on production hot paths.
    #[must_use]
    pub fn hw_identity_handle(&self) -> Option<HwKeyHandle> {
        self.hw_identity_state
            .read()
            .expect("hw_identity_state rwlock poisoned")
            .handle
            .clone()
    }

    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** snapshot of the
    /// HW identity state — opaque handle + cached verifying-key — under
    /// a single read-lock. Useful for callers that need both fields
    /// consistently (e.g. FFI bridge passing both to native UI after
    /// rotation). The returned value is a cloned [`HwIdentityState`];
    /// concurrent swap via [`Self::swap_hw_identity`] does not affect
    /// the snapshot.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** snapshot of HW
    /// identity state — opaque handle + cached verifying-key — under a
    /// single read-lock. Useful when both fields must be observed
    /// consistently.
    #[must_use]
    pub fn hw_identity_state_snapshot(&self) -> HwIdentityState {
        self.hw_identity_state
            .read()
            .expect("hw_identity_state rwlock poisoned")
            .clone()
    }

    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** atomically replace
    /// the HW identity state. Intended to be called by the rotation
    /// orchestration layer ([`crate::identity::rotate_identity_full`])
    /// after a successful publish + `mls_keystore` swap, so that
    /// `core.hw_identity_handle()` / `core.identity_verifying_key()`
    /// post-rotation reflect the new identity instead of going stale.
    ///
    /// Both fields update under a single write-lock, satisfying the
    /// atomic-state invariant: readers either see `(old_handle, old_vk)`
    /// либо `(new_handle, new_vk)` — never a transient mixed view.
    ///
    /// **Does NOT mutate** `hw_callback` (the same callback impl just
    /// rotated identity; the trait object is unchanged) либо `keystore`
    /// (the `Some(HwBackedKeyStore)` slot from `new_with_hw_callback`).
    /// Callers needing to refresh those slots use follow-up APIs либо
    /// reconstruct `ClientCore`.
    ///
    /// **F-CLIENT-FACADE-1 session 9e (2026-05-19):** atomically replace
    /// the HW identity state. Called by rotation orchestration
    /// ([`crate::identity::rotate_identity_full`]) after a successful
    /// publish + `mls_keystore` swap so that `core.hw_identity_handle()`
    /// / `core.identity_verifying_key()` reflect the new identity
    /// post-rotation. Both fields update under one write-lock — readers
    /// either see the old state or the new state, never a mix.
    pub fn swap_hw_identity(&self, new_handle: HwKeyHandle, new_verifying_key: [u8; 32]) {
        let mut state = self
            .hw_identity_state
            .write()
            .expect("hw_identity_state rwlock poisoned");
        state.handle = Some(new_handle);
        state.verifying_key = Some(new_verifying_key);
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
        // F-CLIENT-FACADE-1 session 9e (2026-05-19): the HW verifying-key
        // now lives inside `RwLock<HwIdentityState>`; read under a brief
        // read-lock and copy out the 32-byte value. Lock is released
        // before the Option destructuring и the legacy fallback. After
        // rotation via `swap_hw_identity` this accessor reflects the
        // new identity (session 9e closure of session 9d deferral).
        let hw_vk = self
            .hw_identity_state
            .read()
            .expect("hw_identity_state rwlock poisoned")
            .verifying_key;
        if let Some(vk) = hw_vk {
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
    ///
    /// **F-CLIENT-FACADE-1 session 9f (2026-05-19):** reads under a
    /// brief read-lock and returns an `Option<Arc<dyn KeyStore>>`
    /// clone. After identity rotation via
    /// [`crate::identity::rotate_identity_full`] this accessor
    /// returns the post-rotation [`HwBackedKeyStore`] bound to the
    /// new HW handle / verifying-key, preserving the F-IDENT-1
    /// partition invariant.
    #[must_use]
    pub fn keystore(&self) -> Option<Arc<dyn KeyStore>> {
        self.keystore
            .read()
            .expect("keystore rwlock poisoned")
            .clone()
    }

    /// **F-CLIENT-FACADE-1 session 9f (2026-05-19):** atomically replace
    /// the canonical `Option<Arc<dyn KeyStore>>` slot. Called by
    /// rotation orchestration ([`crate::identity::rotate_identity_full`])
    /// in tandem with [`Self::swap_mls_keystore`] so post-rotation
    /// `core.keystore()` reflects the new identity — without this
    /// the slot would hold a stale `HwBackedKeyStore` bound to the
    /// pre-rotation handle while every other HW-related accessor
    /// reflects the new identity (split-state bug).
    ///
    /// `Some(new_keystore)` on the hw path; `None` on the legacy
    /// path. Rotation orchestration passes `Some(new_hw_keystore)`
    /// since `rotate_identity_full` requires a HW-bootstrapped
    /// ClientCore (Layer 1 pre-flight cross-check enforces this).
    ///
    /// **F-CLIENT-FACADE-1 session 9f (2026-05-19):** atomically
    /// replace the `Option<Arc<dyn KeyStore>>` slot. Called by
    /// rotation orchestration in tandem with `swap_mls_keystore`.
    pub fn swap_keystore(&self, new_keystore: Option<Arc<dyn KeyStore>>) {
        let mut guard = self.keystore.write().expect("keystore rwlock poisoned");
        *guard = new_keystore;
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

    /// MLS provider shared between groups (F-CLIENT-FACADE-1 session 5).
    /// `Arc<UmbrellaProvider>` чтобы фасадам не приходилось клонировать
    /// in-memory storage — все группы внутри одного ClientCore используют
    /// одну общую storage area (KeyPackage privates, signing keys).
    ///
    /// MLS provider shared between groups (F-CLIENT-FACADE-1 session 5).
    #[must_use]
    pub fn mls_provider(&self) -> Arc<UmbrellaProvider> {
        self.mls_provider.clone()
    }

    /// MLS keystore (Block 7.2 device 0 single-device). Используется фасадами
    /// в комбинации с [`Self::mls_provider`] для create / encrypt / decrypt /
    /// add_members. См. doc-comment поля [`Self::mls_keystore`] для partition
    /// invariant vs [`Self::keystore`].
    ///
    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** accessor читает
    /// `RwLock<Arc<dyn KeyStore>>` под кратким read-lock'ом и возвращает
    /// `Arc` clone. Lock освобождается до того как caller вызовет любой
    /// метод KeyStore — concurrent readers полностью lock-free после
    /// получения Arc'а. Atomic swap через [`Self::swap_mls_keystore`]
    /// видит pending readers через write-lock contention; новые reader'ы
    /// после swap'а видят новый keystore.
    ///
    /// MLS keystore (Block 7.2 device 0 single-device). See the field
    /// doc-comment for the partition invariant vs [`Self::keystore`].
    ///
    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** the accessor reads
    /// the `RwLock<Arc<dyn KeyStore>>` under a brief read-lock and returns
    /// an `Arc` clone. The lock is released before the caller invokes any
    /// KeyStore method — concurrent readers are fully lock-free once they
    /// hold the `Arc`. Atomic swap via [`Self::swap_mls_keystore`] sees
    /// pending readers through write-lock contention; readers acquired
    /// after the swap see the new keystore.
    #[must_use]
    pub fn mls_keystore(&self) -> Arc<dyn KeyStore> {
        self.mls_keystore
            .read()
            .expect("mls_keystore rwlock poisoned — fatal invariant violation")
            .clone()
    }

    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** atomically replace the
    /// internal `mls_keystore` with a new implementation. Intended to be
    /// called by the rotation orchestration layer (`rotate_identity_full`
    /// facade либо follow-up state-management code) after an
    /// `IdentityRotationRecord` has been successfully published to KT.
    ///
    /// **Семантика concurrent access**: метод берёт `write`-lock на
    /// `mls_keystore` RwLock на время swap'а. Любые in-flight reader'ы
    /// (которые уже клонировали Arc до swap'а) продолжают видеть
    /// pre-swap keystore — это intentional invariant: facade operations
    /// в полёте не должны частично-переключаться между identity'ями.
    /// Readers acquired после swap'а возвращают новый keystore.
    ///
    /// **Не очищает hw_callback / hw_identity_handle / hw_verifying_key**:
    /// rotation orchestration отвечает за обновление этих полей через
    /// follow-up API (session 9e либо позже). На session 9d swap чисто
    /// MLS-keystore-scoped; tests verify post-rotation
    /// `core.mls_keystore().identity_public()` returns the new pubkey
    /// (acceptance criterion #9 из design spec).
    ///
    /// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** atomically replace
    /// the internal `mls_keystore` with a new implementation. Intended to
    /// be called by the rotation orchestration layer
    /// (`rotate_identity_full` facade or a follow-up state-management
    /// step) after an `IdentityRotationRecord` has been successfully
    /// published to KT.
    ///
    /// **Concurrent access**: this method takes a `write` lock on the
    /// `mls_keystore` RwLock for the duration of the swap. In-flight
    /// readers (which already cloned the `Arc` before the swap) continue
    /// to see the pre-swap keystore — this is the intentional invariant:
    /// in-flight facade operations must not flip between identities mid
    /// way. Readers acquired after the swap see the new keystore.
    ///
    /// **Does NOT clear `hw_callback` / `hw_identity_handle` /
    /// `hw_verifying_key`**: rotation orchestration is responsible for
    /// updating those fields via follow-up APIs (session 9e or later).
    /// In session 9d this swap is purely MLS-keystore-scoped; tests
    /// verify that after rotation
    /// `core.mls_keystore().identity_public()` returns the new pubkey
    /// (acceptance criterion #9 from the design spec).
    pub fn swap_mls_keystore(&self, new_keystore: Arc<dyn KeyStore>) {
        let mut guard = self
            .mls_keystore
            .write()
            .expect("mls_keystore rwlock poisoned — fatal invariant violation");
        *guard = new_keystore;
    }

    /// Извлечь `Arc<TokioMutex<UmbrellaGroup>>` для данного `chat_id`. Возвращает
    /// `None` если группа не зарегистрирована (e.g. test, который открыл chat
    /// через stub `CloudChat::open(ChatId([0u8; 32]))` без предварительного
    /// `create`). Read-only path для facade-уровневых send/fetch operations.
    ///
    /// Look up the `Arc<TokioMutex<UmbrellaGroup>>` for `chat_id`. Returns
    /// `None` when no group is registered for this id.
    pub async fn get_group(&self, chat_id: ChatId) -> Option<Arc<TokioMutex<UmbrellaGroup>>> {
        self.groups.read().await.get(&chat_id).cloned()
    }

    /// Регистрирует MLS-группу для `chat_id`. Перезапишет существующую группу
    /// под тем же chat_id (последний `create` / restore wins). Используется
    /// [`CloudChat::create`] / [`SecretChat::create`] после `UmbrellaGroup::create_private`.
    ///
    /// Register an MLS group for `chat_id`. Overwrites any existing group
    /// under the same id (last write wins). Called by `CloudChat::create` /
    /// `SecretChat::create` after `UmbrellaGroup::create_private`.
    ///
    /// **Task 6 max_ratchet v3 facade integration (2026-05-20):** также
    /// auto-create'ит `MaxRatchetState` под тем же `chat_id` (с дефолтной
    /// конфигурацией — все 4 защиты ON). Это обеспечивает что каждый
    /// зарегистрированный chat получает max ratchet защиты автоматически без
    /// явного opt-in caller'а — это base v3 design «default-on для всех».
    pub async fn register_group(&self, chat_id: ChatId, group: Arc<TokioMutex<UmbrellaGroup>>) {
        self.groups.write().await.insert(chat_id, group);
        self.ratchet_states
            .write()
            .await
            .insert(chat_id, Arc::new(TokioMutex::new(MaxRatchetState::new())));
    }

    /// Удалить MLS-группу для `chat_id`. Возвращает `Arc<TokioMutex<UmbrellaGroup>>`
    /// если была, чтобы caller мог решить какое финальное состояние нужно
    /// (например serialize в persistent storage). На текущем этапе используется
    /// только тестами; production cleanup (logout, remove last device) появится
    /// в session 6+.
    ///
    /// Remove the MLS group for `chat_id`. Returns the group if present so the
    /// caller can decide on final state handling. Tests-only today; production
    /// cleanup (logout, remove last device) arrives in session 6+.
    ///
    /// **Task 6 max_ratchet v3 facade integration (2026-05-20):** также удаляет
    /// `MaxRatchetState` под тем же `chat_id` для consistency.
    pub async fn unregister_group(
        &self,
        chat_id: ChatId,
    ) -> Option<Arc<TokioMutex<UmbrellaGroup>>> {
        self.ratchet_states.write().await.remove(&chat_id);
        self.groups.write().await.remove(&chat_id)
    }

    /// **Task 6 max_ratchet v3 facade integration (2026-05-20):** lookup
    /// `MaxRatchetState` для `chat_id`. Возвращает `None` если group не
    /// зарегистрирована либо устаревший test path где register_group ранее
    /// не вызывался. Используется sender side в `send_mls_text` для lock'а
    /// state'а перед `encrypt_with_rekey_authenticated`.
    ///
    /// **Task 6:** look up `MaxRatchetState` for `chat_id`. Used by the sender
    /// side in `send_mls_text` to lock the state before
    /// `encrypt_with_rekey_authenticated`.
    pub async fn get_ratchet_state(
        &self,
        chat_id: ChatId,
    ) -> Option<Arc<TokioMutex<MaxRatchetState>>> {
        self.ratchet_states.read().await.get(&chat_id).cloned()
    }

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** drain pending Welcome
    /// envelopes addressed to this device's identity pubkey from the postman
    /// inbox. Returns TLS-serialized `MlsMessage::Welcome` bytes in insertion
    /// order; queue is emptied on drain (one-shot fetch).
    ///
    /// Используется фасадным bootstrap flow: новое устройство дёргает
    /// `fetch_pending_welcomes(self_identity_pk)` после connect к gateway,
    /// затем для каждого welcome — `CloudChat::open_from_welcome` либо
    /// `SecretChat::open_from_welcome`, что вызывает
    /// `UmbrellaGroup::join_from_welcome` + регистрирует группу в
    /// `ClientCore.groups` → новое устройство готово к send/fetch/decrypt
    /// для всех чатов куда было добавлено.
    ///
    /// Drain pending Welcome envelopes from the postman inbox addressed to
    /// this device's identity pubkey. Used by the facade bootstrap flow: new
    /// device fetches Welcomes, opens each via `open_from_welcome`, then
    /// participates in those chats.
    ///
    /// **Production path** (session 6+ wire): real postman HTTP/2 transport
    /// will replace `StubPostmanTransport`; this accessor signature stays
    /// stable across that swap (returns raw bytes, no transport details).
    pub async fn fetch_pending_welcomes(&self, recipient_identity_pk: [u8; 32]) -> Vec<Vec<u8>> {
        self.postman_transport
            .drain_welcomes_for(&recipient_identity_pk)
    }

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** typed-Arc accessor для
    /// stub postman transport. Используется test rigs которые stage'ят
    /// `CloudHistoryEntry`-tuples + Welcome bytes для drain через
    /// [`Self::fetch_pending_welcomes`] / facade `cloud_sync_history`.
    /// В production (Block 7.4+) postman_transport переезжает на
    /// `Arc<dyn PostmanTransport + Send + Sync>` trait; этот accessor
    /// исчезнет либо станет `cfg(test)`-only.
    ///
    /// Typed accessor for stub postman — session 6 test scaffold.
    /// Disappears in Block 7.4+ when real `PostmanTransport` trait wired.
    #[must_use]
    pub fn postman_transport(&self) -> Arc<StubPostmanTransport> {
        self.postman_transport.clone()
    }

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** typed-Arc accessor для
    /// stub unwrap transport. `Some` пока ClientCore был bootstrap'нут с
    /// `StubUnwrapTransport` (текущий Block 7.2 state); `None` когда
    /// production `Http2UnwrapTransport` wired (Block 7.4+). Используется
    /// test rigs которые `push_response`-ят pre-baked Sealed Server shares
    /// перед facade.cloud_sync_history dispatch.
    ///
    /// Typed accessor for stub unwrap transport — `Some` while session-6
    /// stub; `None` after Block 7.4+ production wire.
    #[must_use]
    pub fn stub_unwrap_transport(&self) -> Option<Arc<StubUnwrapTransport>> {
        self.stub_unwrap_transport.clone()
    }

    /// **F-CLIENT-FACADE-1 session 8a (2026-05-19):** typed-Arc accessor для
    /// stub KT transport. Используется test rigs которые stage'ят
    /// `KtEntry` через [`StubKtTransport::push_staged_entry`] для facade
    /// self-monitor verify (`umbrella_client::kt_monitor::verify_own_kt_entry_for_epoch`).
    /// В production (session 8c+) ClientCore переедет на `Arc<dyn
    /// KtTransport + Send + Sync>` trait abstraction; этот accessor либо
    /// станет `cfg(test)`-only либо trait-typed.
    ///
    /// Typed accessor for stub KT transport — session 8a test scaffold.
    /// Will be retyped to `Arc<dyn KtTransport>` in session 8c.
    #[must_use]
    pub fn kt_transport(&self) -> Arc<StubKtTransport> {
        self.kt_transport.clone()
    }

    /// **F-CLIENT-FACADE-1 session 10a (2026-05-19):** typed accessor for
    /// the stub call-relay transport. Used by call-session orchestration
    /// (`CallSession::start_with_enforcement` → `allocate(...)`) and by
    /// integration tests inspecting the counter / last_request snapshot.
    /// Production wiring uses [`crate::transport::Http2CallRelayTransport`]
    /// instead; this accessor will be retyped to a trait object once a
    /// production-and-stub trait surface is defined (analogous to the
    /// kt_transport → KtTransport trait roadmap).
    ///
    /// **F-CLIENT-FACADE-1 session 10a (2026-05-19):** typed accessor for
    /// the stub call-relay transport. Used by call orchestration and
    /// integration tests inspecting counter / last_request state.
    #[must_use]
    pub fn call_relay_transport(&self) -> Arc<StubCallRelayTransport> {
        self.call_relay_transport.clone()
    }

    /// **F-CLIENT-FACADE-1 session 8c1 (2026-05-19):** snapshot pinned
    /// [`WitnessSet`] (5 witness Ed25519 pubkeys) для последующего
    /// [`crate::kt_monitor::verify_kt_witness_signatures_for_epoch`]
    /// вызова. Возвращает `WitnessSet::new()` если bootstrap не выставил
    /// pinned set (default state) — helper тогда fail-closed'ит по
    /// `InsufficientValidSignatures { valid: 0, required: threshold }`.
    ///
    /// Lock contention: brief read-lock над `Arc<RwLock<WitnessSet>>`,
    /// clone'ит inner `Vec<WitnessPublic>` (5 элементов × 32 bytes = 160
    /// bytes total). Negligible cost даже на hot path.
    ///
    /// **F-CLIENT-FACADE-1 session 8c1:** snapshot of the pinned 5-witness
    /// set. Returns `WitnessSet::new()` if bootstrap has not installed
    /// SPKI pins yet (helper fail-closes via InsufficientValidSignatures).
    #[must_use]
    pub async fn kt_witness_set(&self) -> WitnessSet {
        self.kt_witness_set.read().await.clone()
    }

    /// **F-CLIENT-FACADE-1 session 8c1 (2026-05-19):** установить pinned
    /// witness set. Production: native bootstrap layer вызывает этот
    /// setter ровно один раз после reading SPKI pinned 5-witness
    /// pubkeys из платформенного secure storage (`UserDefaults` /
    /// `SharedPreferences` либо bundled config). Test fixtures используют
    /// этот же setter после `bootstrap_for_test` для exercise of
    /// `verify_kt_witness_signatures_for_epoch` paths.
    ///
    /// **Idempotent**: повторный вызов с тем же набором — no-op effect.
    /// **Rotation**: если SPEC-09 §6.2 future work добавит witness
    /// rotation (post-1.0.0), тот же setter примет new set, и helper
    /// автоматически начнёт проверять подписи против нового quorum'а
    /// на следующем call'е.
    ///
    /// **F-CLIENT-FACADE-1 session 8c1:** install pinned 5-witness set.
    /// Production: called once by native bootstrap after reading SPKI
    /// pins. Tests: called after `bootstrap_for_test` to install a
    /// 5-witness fixture before exercising the helper.
    pub async fn set_kt_witness_set(&self, set: WitnessSet) {
        *self.kt_witness_set.write().await = set;
    }

    /// **F-CLIENT-FACADE-1 session 6c (2026-05-19):** allocate the next
    /// monotonic `msg_seq` для Cloud-mode at-rest write на указанный
    /// `chat_id`. Counter starts at 0; first call returns 0, next 1, etc.
    /// Strict per-chat — distinct chats имеют independent sequences.
    ///
    /// **Critical invariant**: never reuse `(chat_id, msg_seq)` — иначе
    /// ChaCha20-Poly1305 nonce reuse → keystream XOR'd reveals both
    /// plaintexts pointwise. Sender гарантирует через monotonic counter;
    /// recipient/postman side гарантирует через dedup при доставке.
    ///
    /// Allocate the next monotonic Cloud-mode `msg_seq` for `chat_id`.
    /// **Critical**: never reuse `(chat_id, msg_seq)` to avoid nonce reuse.
    pub async fn next_cloud_msg_seq(&self, chat_id: ChatId) -> u64 {
        let mut guard = self.cloud_msg_seq_counters.write().await;
        let counter = guard.entry(chat_id).or_insert(0);
        let value = *counter;
        *counter = counter.checked_add(1).unwrap_or_else(|| {
            // 2^64 messages per chat — astronomical for a single chat;
            // wrapping would cause nonce reuse, so panic is correct
            // policy here (postulate 14 — no silent fallback).
            panic!("Cloud-mode msg_seq counter overflow for chat {chat_id:?}")
        });
        value
    }

    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** Register a peer's
    /// long-lived X25519 identity pubkey, indexed by their Ed25519
    /// identity_pk. This mapping is consulted by Secret-mode
    /// `SecretChat::send_text` to wrap MLS ciphertext in a sealed-sender
    /// envelope per recipient (`umbrella_sealed_sender::seal` requires the
    /// recipient's X25519 pubkey explicitly; it cannot be derived from
    /// Ed25519 identity_pk, the two keys come from independent BIP-32
    /// derivation paths per `umbrella_identity::identity_x25519`).
    ///
    /// **Idempotent**: повторный вызов с тем же `peer_ed25519_identity_pk`
    /// перезаписывает предыдущий X25519 mapping (используется при KT
    /// rotation event'ах в production session 8+; в тестах поведение
    /// идемпотентно по re-registration).
    ///
    /// **Production**: вызывается из KT directory lookup pipeline когда
    /// chat opened, new peer added, либо KT self-monitoring обнаружил
    /// rotation. Wiring к `umbrella-kt` — session 8+ scope.
    /// **Tests**: вызывается явно перед `SecretChat::send_text` для
    /// каждого peer'а, который ожидаемо является получателем envelope.
    ///
    /// **F-CLIENT-FACADE-1 session 7:** register a peer's X25519 identity
    /// pubkey by their Ed25519 identity_pk. Idempotent; called from KT
    /// directory lookups (production, session 8+) or test fixtures.
    pub async fn register_peer_x25519(
        &self,
        peer_ed25519_identity_pk: [u8; 32],
        peer_x25519_pubkey: IdentityX25519KeyPublic,
    ) {
        self.peer_x25519_directory
            .write()
            .await
            .insert(peer_ed25519_identity_pk, peer_x25519_pubkey);
    }

    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** Lookup a peer's
    /// X25519 identity pubkey by their Ed25519 identity_pk. Returns
    /// `None` if not registered — caller (typically `send_secret_text`)
    /// should fail-closed with `ClientError::SealedSender` rather than
    /// fall back to unsealed delivery (post 14: no silent fallback —
    /// unsealed delivery would leak sender identity_pk on the wire for
    /// that one recipient).
    ///
    /// Read-only; uses a brief read-lock and clones the
    /// `IdentityX25519KeyPublic` (`Copy`-able 32-byte value type).
    ///
    /// **F-CLIENT-FACADE-1 session 7:** lookup peer X25519 pubkey by
    /// Ed25519 identity_pk. Returns `None` if not registered; caller
    /// must fail-closed rather than fall back to unsealed delivery.
    #[must_use]
    pub async fn lookup_peer_x25519(
        &self,
        peer_ed25519_identity_pk: &[u8; 32],
    ) -> Option<IdentityX25519KeyPublic> {
        self.peer_x25519_directory
            .read()
            .await
            .get(peer_ed25519_identity_pk)
            .copied()
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
        // F-CLIENT-FACADE-1 session 9e: read combined state under one
        // snapshot (cloned under read-lock; concurrent swap is fine).
        let hw_state = core.hw_identity_state_snapshot();
        assert!(
            hw_state.handle.is_none(),
            "F-CLIENT-HW-1: legacy bootstrap MUST leave hw_identity_state.handle None"
        );
        assert!(
            hw_state.verifying_key.is_none(),
            "F-CLIENT-HW-1: legacy bootstrap MUST leave hw_identity_state.verifying_key None"
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
        // F-CLIENT-FACADE-1 session 9e: combined state read.
        let hw_state = core.hw_identity_state_snapshot();
        assert!(
            hw_state.handle.is_some(),
            "F-CLIENT-HW-1: hw bootstrap MUST populate hw_identity_state.handle"
        );
        assert!(
            hw_state.verifying_key.is_some(),
            "F-CLIENT-HW-1: hw bootstrap MUST populate hw_identity_state.verifying_key cache"
        );

        // Cached verifying_key MUST equal the keystore's verifying_key
        // for the bound handle — no drift between bootstrap-time fetch
        // and runtime callback query (the smoke-test inside
        // bootstrap_hw_identity also covers this, but defense in depth).
        let handle = hw_state.handle.as_ref().expect("handle present");
        let direct_vk = mock
            .verifying_key(handle)
            .expect("callback yields verifying_key");
        let cached_vk = hw_state
            .verifying_key
            .expect("hw_identity_state.verifying_key cache populated");
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
        let legacy_core = ClientCore::new_for_test(production_shaped_config(), test_seed())
            .await
            .expect("legacy bootstrap");
        assert!(
            legacy_core.keystore().is_none(),
            "F-IDENT-1 closure: legacy bootstrap MUST leave core.keystore() None — Block 7.2 \
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
            hw_core.keystore().is_some(),
            "F-IDENT-1 closure: hw bootstrap MUST register canonical HwBackedKeyStore in core.keystore()"
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
        let keystore = hw_core.keystore().expect("hw keystore");
        let msg = b"F-IDENT-1 closure keystore round-trip";
        let sig = keystore.sign_with_identity(msg);

        let hw_vk_bytes = hw_core
            .hw_identity_state_snapshot()
            .verifying_key
            .expect("hw_identity_state.verifying_key");
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
        let hw_handle = hw_core.hw_identity_handle().expect("handle present");
        let hw_direct = mock
            .verifying_key(&hw_handle)
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
