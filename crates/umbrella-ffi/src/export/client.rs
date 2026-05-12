//! `UmbrellaClientHandle` — top-level FFI entry point. `bootstrap`
//! async-constructor + `open_cloud_chat` / `open_secret_chat` factories.
//!
//! Bootstrap принимает 24-словную BIP-39 mnemonic фразу (string) — стандартный
//! путь восстановления identity на устройстве. План референсил
//! `IdentitySeed::from_bytes([u8; 64])` — этот метод не существует
//! (см. `docs/audits/production-readiness-2026-05-09/residual-risks.md` 7.2 item #3); реальный API
//! `IdentitySeed::from_mnemonic(phrase, language)`. Mnemonic phrase
//! хранится native-стороной в Secure Enclave / StrongBox через
//! `PersistentKeyStore` callback (Блок 7.3).
//!
//! `UmbrellaClientHandle` — top-level FFI entry point. Async `bootstrap`
//! constructor plus `open_cloud_chat` / `open_secret_chat` factories.
//!
//! `bootstrap` accepts a 24-word BIP-39 mnemonic phrase (string) — the
//! standard identity-restore path on a device. The plan referenced
//! `IdentitySeed::from_bytes([u8; 64])`, which does not exist (see
//! `docs/audits/production-readiness-2026-05-09/residual-risks.md` 7.2 item #3); the real API is
//! `IdentitySeed::from_mnemonic(phrase, language)`. The mnemonic phrase
//! is held by the native side in Secure Enclave / StrongBox through a
//! `PersistentKeyStore` callback (Block 7.3).

use std::sync::Arc;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient, DEFAULT_CIPHERSUITE};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

use crate::error::UmbrellaError;
use crate::export::{CloudChatHandle, SecretChatHandle};
use crate::types::ChatIdFfi;

fn production_bootstrap_unavailable() -> UmbrellaError {
    UmbrellaError::Internal(
        "production bootstrap is not available: public FFI must not use test constructors until every client transport and required production verifier is wired"
            .into(),
    )
}

/// FFI представление [`ClientConfig`]. Sealed Servers wrap params (5 ×
/// 32-байтовые pubkeys + main pubkey + version) развёрнуты в плоский
/// набор полей; threshold = 3, total = 5 фиксированы.
///
/// FFI representation of [`ClientConfig`]. Sealed Servers wrap params
/// (5 × 32-byte pubkeys + main pubkey + version) flattened into a flat
/// field set; threshold = 3, total = 5 are fixed.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ClientConfigFfi {
    /// 5 URL-ов Sealed Servers (cloud-backup-svc).
    /// 5 Sealed Server URLs (cloud-backup-svc).
    pub sealed_server_urls: Vec<String>,
    /// blind-postman-svc URL.
    /// blind-postman-svc URL.
    pub postman_url: String,
    /// kt-svc URL.
    /// kt-svc URL.
    pub kt_url: String,
    /// call-relay-svc URL (TURN allocation).
    /// call-relay-svc URL (TURN allocation).
    pub call_relay_url: String,
    /// Интервал KT self-monitoring в секундах (default 3600).
    /// Interval (seconds) for KT self-monitoring (default 3600).
    pub kt_monitor_interval_secs: u64,
    /// 32-байтовый main wrapping pubkey.
    /// 32-byte main wrapping pubkey.
    pub main_pubkey: Vec<u8>,
    /// Ровно 5 × 32-байтовых Sealed Server pubkeys.
    /// Exactly 5 × 32-byte Sealed Server pubkeys.
    pub server_pubkeys: Vec<Vec<u8>>,
    /// Версия wrap-протокола.
    /// Wrap protocol version.
    pub wrapping_version: u8,
}

impl TryFrom<ClientConfigFfi> for ClientConfig {
    type Error = UmbrellaError;

    fn try_from(v: ClientConfigFfi) -> Result<Self, Self::Error> {
        if v.main_pubkey.len() != 32 {
            return Err(UmbrellaError::Internal(format!(
                "main_pubkey length {}, expected 32",
                v.main_pubkey.len()
            )));
        }
        if v.server_pubkeys.len() != 5 {
            return Err(UmbrellaError::Internal(format!(
                "server_pubkeys length {}, expected exactly 5",
                v.server_pubkeys.len()
            )));
        }
        let mut main = [0u8; 32];
        main.copy_from_slice(&v.main_pubkey);

        let mut servers = [[0u8; 32]; 5];
        for (i, sp) in v.server_pubkeys.iter().enumerate() {
            if sp.len() != 32 {
                return Err(UmbrellaError::Internal(format!(
                    "server_pubkeys[{i}] length {}, expected 32",
                    sp.len()
                )));
            }
            servers[i].copy_from_slice(sp);
        }

        let threshold = ThresholdConfig::new(3, 5)
            .map_err(|e| UmbrellaError::Internal(format!("3-of-5 ThresholdConfig: {e}")))?;

        Ok(ClientConfig {
            sealed_server_urls: v.sealed_server_urls,
            postman_url: v.postman_url,
            kt_url: v.kt_url,
            call_relay_url: v.call_relay_url,
            kt_monitor_interval_secs: v.kt_monitor_interval_secs,
            wrapping_params: WrappingParams {
                version: v.wrapping_version,
                main_pubkey: main,
                server_pubkeys: servers,
                config: threshold,
            },
            // Cfg-conditional default через [`umbrella_client::DEFAULT_CIPHERSUITE`]:
            // - Под feature `pq` → `0x004D` (block 9.12 PQ-first default switch +
            //   ADR-013 Решение 2 Вариант B: existing `bootstrap` cfg-conditional
            //   default — apps собранные с feature `pq` получают X-Wing PQ автоматически
            //   без breaking ABI 0.0.11).
            // - Без feature `pq` → `0x0003` (legacy classical, ABI invariant ADR-010
            //   сохранён — existing 0.0.11 Swift / Kotlin приложения собранные без
            //   feature `pq` продолжают работать без изменений).
            //
            // Поле в `ClientConfigFfi` (FFI Records) не выставляется напрямую — постулат
            // 14, ABI invariant ADR-010: Swift / Kotlin клиенты не должны выбирать
            // ciphersuite как сырой `u16`, только через explicit constructor выбора
            // режима ([`UmbrellaClientHandle::bootstrap`] cfg-conditional default,
            // [`UmbrellaClientHandle::bootstrap_pq`] под cfg pq, либо
            // [`UmbrellaClientHandle::bootstrap_classical`] под cfg classical-only).
            //
            // Cfg-conditional default through [`umbrella_client::DEFAULT_CIPHERSUITE`]:
            // - Under feature `pq` → `0x004D` (Block 9.12 PQ-first default switch +
            //   ADR-013 Decision 2 Variant B: existing `bootstrap` cfg-conditional
            //   default — apps built with feature `pq` get X-Wing PQ automatically
            //   without breaking ABI 0.0.11).
            // - Without feature `pq` → `0x0003` (legacy classical, ABI invariant
            //   ADR-010 preserved — existing 0.0.11 Swift / Kotlin apps built without
            //   feature `pq` continue to work unchanged).
            //
            // The field in `ClientConfigFfi` (FFI Records) is not surfaced directly —
            // postulate 14, ABI invariant ADR-010: Swift / Kotlin clients must not
            // pick the ciphersuite as a raw `u16`, only through an explicit
            // mode-choice constructor ([`UmbrellaClientHandle::bootstrap`] cfg-
            // conditional default, [`UmbrellaClientHandle::bootstrap_pq`] under cfg
            // `pq`, or [`UmbrellaClientHandle::bootstrap_classical`] under cfg
            // classical-only).
            default_ciphersuite: DEFAULT_CIPHERSUITE,
        })
    }
}

/// FFI-обёртка верхнего уровня для UmbrellaClient.
///
/// Top-level FFI handle.
#[derive(uniffi::Object)]
pub struct UmbrellaClientHandle {
    inner: Arc<UmbrellaClient>,
}

#[uniffi::export(async_runtime = "tokio")]
impl UmbrellaClientHandle {
    /// Bootstrap клиента из 24-словной BIP-39 mnemonic фразы. Только English
    /// wordlist в Блоке 7.7; multi-language расширение — в Блоке 7.11.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`UmbrellaError::Identity`] если фраза невалидна (не 24 слова /
    ///   неверный checksum).
    /// - [`UmbrellaError::Internal`] если `ClientConfigFfi` невалиден
    ///   (длины pubkeys, количество server_pubkeys).
    /// - [`UmbrellaError::Internal`] с понятным отказом, пока боевые
    ///   транспорты и проверяющие пути не подключены полностью.
    ///
    /// Bootstraps the client from a 24-word BIP-39 mnemonic. Block 7.7
    /// supports only the English wordlist; multi-language support arrives
    /// in Block 7.11.
    ///
    /// # Errors
    ///
    /// - [`UmbrellaError::Identity`] when the phrase is invalid (not 24
    ///   words / wrong checksum).
    /// - [`UmbrellaError::Internal`] when `ClientConfigFfi` is invalid
    ///   (pubkey lengths, server_pubkeys count).
    /// - [`UmbrellaError::Internal`] with a clear fail-fast message until
    ///   production transports and verifier paths are wired end to end.
    #[uniffi::constructor]
    pub async fn bootstrap(
        config: ClientConfigFfi,
        mnemonic_phrase: String,
    ) -> Result<Arc<Self>, UmbrellaError> {
        let _seed = IdentitySeed::from_mnemonic(&mnemonic_phrase, MnemonicLanguage::English)
            .map_err(|e| UmbrellaError::Identity(e.to_string()))?;

        let _rust_config: ClientConfig = config.try_into()?;
        Err(production_bootstrap_unavailable())
    }

    /// Открыть существующий Cloud-чат по `ChatId`.
    ///
    /// Open an existing Cloud chat by `ChatId`.
    pub async fn open_cloud_chat(
        &self,
        chat_id: ChatIdFfi,
    ) -> Result<Arc<CloudChatHandle>, UmbrellaError> {
        let cloud = CloudChat::open(self.inner.core(), chat_id.try_into()?).await?;
        Ok(Arc::new(CloudChatHandle::new(cloud)))
    }

    /// Открыть существующий Secret-чат по `ChatId`.
    ///
    /// Open an existing Secret chat by `ChatId`.
    pub async fn open_secret_chat(
        &self,
        chat_id: ChatIdFfi,
    ) -> Result<Arc<SecretChatHandle>, UmbrellaError> {
        let secret = SecretChat::open(self.inner.core(), chat_id.try_into()?).await?;
        Ok(Arc::new(SecretChatHandle::new(secret)))
    }
}

/// PQ-режим FFI surface — feature `pq` зонтичный (umbrella-ffi/pq →
/// umbrella-client/pq → all PQ-aware downstream крейты, ADR-011 Решение 7).
///
/// Вынесено в отдельный `impl` блок под `#[cfg(feature = "pq")]` потому что
/// uniffi 0.28+ proc-macro `#[uniffi::export]` обрабатывает impl целиком и
/// не учитывает `#[cfg]` атрибуты на отдельных методах внутри. Этот pattern
/// совместим со существующим bootstrap signature и не нарушает ABI invariant
/// (ADR-010 + design.md §11.2): existing 0.0.11 Swift / Kotlin приложения,
/// собранные через umbrella-ffi-swift / umbrella-ffi-kotlin без feature `pq`,
/// видят те же методы что и раньше.
///
/// PQ-mode FFI surface — feature `pq` umbrella aggregator (umbrella-ffi/pq →
/// umbrella-client/pq → all PQ-aware downstream crates, ADR-011 Decision 7).
///
/// Lives in a dedicated `impl` block under `#[cfg(feature = "pq")]` because
/// uniffi 0.28+ proc-macro `#[uniffi::export]` processes the entire impl block
/// and ignores `#[cfg]` attributes on individual methods inside. This pattern
/// is compatible with the existing bootstrap signature and does not violate
/// the ABI invariant (ADR-010 + design.md §11.2): existing 0.0.11 Swift /
/// Kotlin apps built through umbrella-ffi-swift / umbrella-ffi-kotlin without
/// feature `pq` see the same methods as before.
#[cfg(feature = "pq")]
#[uniffi::export(async_runtime = "tokio")]
impl UmbrellaClientHandle {
    /// PQ-зонтичный self-test accessor: возвращает `default_ciphersuite`
    /// клиента (который для PQ-bootstrap'a — `0x004D` X-Wing). Native
    /// приложения и block 8.8 milestone integration scenarios используют
    /// его для verify что `bootstrap_pq` действительно установил hybrid PQ
    /// режим, а не silent fallback на classical (постулат 14).
    ///
    /// Также служит вторым async-методом в этом impl блоке — uniffi 0.28+
    /// требует наличия как минимум одного non-constructor `async` method
    /// внутри `#[uniffi::export(async_runtime = "tokio")]` impl блока, иначе
    /// компилятор выдаёт «no async methods in this impl block».
    ///
    /// PQ-umbrella self-test accessor: returns the client's
    /// `default_ciphersuite` (which is `0x004D` X-Wing for a PQ bootstrap).
    /// Native apps and Block 8.8 milestone integration scenarios use it to
    /// verify that `bootstrap_pq` actually installed hybrid PQ mode rather
    /// than silently falling back to classical (postulate 14).
    ///
    /// Also serves as the second async method in this impl block — uniffi
    /// 0.28+ requires at least one non-constructor `async` method inside
    /// `#[uniffi::export(async_runtime = "tokio")]`, otherwise the compiler
    /// errors with «no async methods in this impl block».
    pub async fn pq_default_ciphersuite(&self) -> u16 {
        self.inner.core().default_ciphersuite()
    }

    /// Bootstrap клиента в **PQ-режиме** из 24-словной BIP-39 mnemonic фразы.
    /// Доступно только когда `umbrella-ffi` собран с feature `pq`.
    ///
    /// Отличается от [`Self::bootstrap`] тем, что устанавливает
    /// `default_ciphersuite = 0x004D` (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`,
    /// hybrid PQ через X-Wing combiner). Все новые чаты, созданные клиентом
    /// без явного `ChatSettings.ciphersuite`, получат X-Wing MLS group +
    /// post-quantum capabilities в KeyPackage (capability negotiation
    /// реализована в блоке 8.4 `umbrella-mls`).
    ///
    /// # Постулат 14 (no silent fallback)
    ///
    /// Этот конструктор НЕ выполняет automatic downgrade: если на peer-стороне
    /// `0x004D` не объявлен в KeyPackage capabilities, попытка create chat
    /// вернёт `UmbrellaError::Mls(...)` без silent fallback на classical
    /// `0x0003`. Переход на classical для конкретного чата требует **explicit**
    /// `ChatSettings.ciphersuite = Some(0x0003)` (block 8.8 milestone
    /// scenario 6 «Mixed group»).
    ///
    /// # ABI invariant (ADR-010)
    ///
    /// Этот метод — отдельный **дополнительный** конструктор. Существующая
    /// [`Self::bootstrap`] подпись и поведение **не меняются** — Swift / Kotlin
    /// приложения 0.0.11 продолжают работать без изменений.
    ///
    /// # Ошибки / Errors
    ///
    /// Те же что [`Self::bootstrap`]: входные данные проверяются, затем боевой
    /// запуск отказывает до полной связки транспортов и проверяющих путей.
    ///
    /// Bootstrap the client in **PQ mode** from a 24-word BIP-39 mnemonic.
    /// Available only when `umbrella-ffi` is built with feature `pq`.
    ///
    /// Differs from [`Self::bootstrap`] by setting `default_ciphersuite =
    /// 0x004D` (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`, hybrid PQ via
    /// the X-Wing combiner). All new chats created by the client without an
    /// explicit `ChatSettings.ciphersuite` get an X-Wing MLS group + post-
    /// quantum capabilities in the KeyPackage (capability negotiation lives
    /// in Block 8.4 `umbrella-mls`).
    ///
    /// # Postulate 14 (no silent fallback)
    ///
    /// This constructor does NOT perform automatic downgrade: if `0x004D`
    /// is not declared in the peer's KeyPackage capabilities, a chat-create
    /// attempt returns `UmbrellaError::Mls(...)` without silently falling
    /// back to classical `0x0003`. Switching to classical for a specific
    /// chat requires an **explicit** `ChatSettings.ciphersuite = Some(0x0003)`
    /// (Block 8.8 milestone scenario 6 «Mixed group»).
    ///
    /// # ABI invariant (ADR-010)
    ///
    /// This method is a separate **additional** constructor. The existing
    /// [`Self::bootstrap`] signature and behavior are unchanged — 0.0.11
    /// Swift / Kotlin apps continue to work as-is.
    ///
    /// # Errors
    ///
    /// Same as [`Self::bootstrap`]: inputs are validated, then production
    /// bootstrap fails fast until transports and verifier paths are complete.
    #[uniffi::constructor]
    pub async fn bootstrap_pq(
        config: ClientConfigFfi,
        mnemonic_phrase: String,
    ) -> Result<Arc<Self>, UmbrellaError> {
        let _seed = IdentitySeed::from_mnemonic(&mnemonic_phrase, MnemonicLanguage::English)
            .map_err(|e| UmbrellaError::Identity(e.to_string()))?;

        let _rust_config: ClientConfig = config.try_into()?;
        Err(production_bootstrap_unavailable())
    }
}

/// Classical-only FFI surface — exposed только когда `umbrella-ffi` собран
/// **без** feature `pq`. Block 9.12 (PQ-first default switch) — мостик для
/// legacy iOS / Android приложений 0.0.11 которые могут rebuild против
/// новой SDK без feature `pq` и продолжать использовать classical путь
/// без явной зависимости от X-Wing PQ stack (ADR-013 Решение 2 Вариант B,
/// design.md §8.2).
///
/// Под cfg classical-only [`UmbrellaClientHandle::bootstrap`] и
/// [`UmbrellaClientHandle::bootstrap_classical`] функционально эквивалентны
/// (оба → `default_ciphersuite = 0x0003` через cfg-conditional
/// [`umbrella_client::DEFAULT_CIPHERSUITE`]). Дублирование намеренное —
/// `bootstrap_classical` делает intent explicit ([`bootstrap_pq`] парный
/// под cfg `pq`); постулат 14 «no silent fallback» — выбор режима всегда
/// через named constructor, не через скрытое runtime-условие.
///
/// Вынесено в отдельный `impl` блок под `#[cfg(not(feature = "pq"))]`
/// потому что uniffi 0.28+ proc-macro `#[uniffi::export]` обрабатывает
/// `impl` целиком и не учитывает `#[cfg]` атрибуты на отдельных методах
/// внутри (mirror pattern с PQ-mode `impl` блоком выше — lesson 9 Этапа 8).
///
/// Classical-only FFI surface — exposed only when `umbrella-ffi` is built
/// **without** feature `pq`. Block 9.12 (PQ-first default switch) — bridge
/// for legacy 0.0.11 iOS / Android apps that may rebuild against the new
/// SDK without feature `pq` and continue using the classical path without
/// an explicit dependency on the X-Wing PQ stack (ADR-013 Decision 2
/// Variant B, design.md §8.2).
///
/// Under cfg classical-only [`UmbrellaClientHandle::bootstrap`] and
/// [`UmbrellaClientHandle::bootstrap_classical`] are functionally
/// equivalent (both → `default_ciphersuite = 0x0003` through the
/// cfg-conditional [`umbrella_client::DEFAULT_CIPHERSUITE`]). The
/// duplication is intentional — `bootstrap_classical` makes intent
/// explicit (the parallel of [`bootstrap_pq`] under cfg `pq`); postulate
/// 14 «no silent fallback» — mode selection is always via a named
/// constructor, not a hidden runtime conditional.
///
/// Lives in a dedicated `impl` block under `#[cfg(not(feature = "pq"))]`
/// because uniffi 0.28+ proc-macro `#[uniffi::export]` processes the
/// entire `impl` block and ignores `#[cfg]` attributes on individual
/// methods inside (mirror pattern of the PQ-mode `impl` block above —
/// Stage 8 lesson 9).
#[cfg(not(feature = "pq"))]
#[uniffi::export(async_runtime = "tokio")]
impl UmbrellaClientHandle {
    /// Classical-зонтичный self-test accessor: возвращает `default_ciphersuite`
    /// клиента (под cfg classical-only это `0x0003`). Mirror к
    /// [`Self::pq_default_ciphersuite`] под cfg `pq`. Block 9.12 ADR-013
    /// Решение 2 — native приложения и migration tests используют его для
    /// verify что `bootstrap_classical` действительно установил classical
    /// режим, а не silent fallback на что-то другое (постулат 14).
    ///
    /// Также служит вторым async non-constructor методом в этом impl блоке —
    /// uniffi 0.28+ требует наличия как минимум одного non-constructor
    /// `async` method внутри `#[uniffi::export(async_runtime = "tokio")]`
    /// impl блока, иначе компилятор выдаёт «no async methods in this impl
    /// block» (lesson 9 Этапа 8).
    ///
    /// Classical-umbrella self-test accessor: returns the client's
    /// `default_ciphersuite` (under cfg classical-only this is `0x0003`).
    /// Mirror of [`Self::pq_default_ciphersuite`] under cfg `pq`. Block
    /// 9.12 ADR-013 Decision 2 — native apps and migration tests use it to
    /// verify that `bootstrap_classical` actually installed classical mode
    /// rather than silently falling back to something else (postulate 14).
    ///
    /// Also serves as the second async non-constructor method in this impl
    /// block — uniffi 0.28+ requires at least one non-constructor `async`
    /// method inside `#[uniffi::export(async_runtime = "tokio")]`,
    /// otherwise the compiler errors with «no async methods in this impl
    /// block» (Stage 8 lesson 9).
    pub async fn classical_default_ciphersuite(&self) -> u16 {
        self.inner.core().default_ciphersuite()
    }

    /// Bootstrap клиента в **classical-режиме** из 24-словной BIP-39
    /// mnemonic фразы. Доступен только когда `umbrella-ffi` собран **без**
    /// feature `pq` — мостик для legacy iOS / Android приложений 0.0.11
    /// которые rebuild против новой SDK без активной PQ feature.
    ///
    /// # Цель (block 9.12 PQ-first default switch)
    ///
    /// Этот FFI surface explicitly pin-ит classical путь даже после
    /// default switch на `0x004D` под feature `pq`. Под cfg classical-only
    /// [`Self::bootstrap`] и [`Self::bootstrap_classical`] функционально
    /// эквивалентны (оба → `0x0003` через cfg-conditional
    /// [`umbrella_client::DEFAULT_CIPHERSUITE`]); под cfg `pq`
    /// [`Self::bootstrap_classical`] **не exposed** (postулат 14 — explicit
    /// choice через named constructor либо per-чат override
    /// `ChatSettings.ciphersuite = Some(0x0003)`).
    ///
    /// # Постулат 14 (no silent fallback)
    ///
    /// Этот конструктор НЕ silent fallback с PQ на classical — он явный
    /// выбор classical mode caller'ом. Caller-у, желающему PQ под cfg
    /// classical-only, необходимо rebuild SDK с feature `pq` и
    /// использовать [`Self::bootstrap_pq`] (cfg pq).
    ///
    /// # ABI invariant (ADR-010)
    ///
    /// Этот метод — отдельный **дополнительный** конструктор exposed только
    /// под cfg classical-only. [`Self::bootstrap`] signature и поведение
    /// **не меняются** — uniffi 0.28+ build-time gate
    /// (`cfg(not(feature = "pq"))`) гарантирует что existing 0.0.11 Swift /
    /// Kotlin приложения собранные без feature `pq` видят те же FFI
    /// методы что и раньше (block 9.12 commit добавляет `bootstrap_classical`
    /// и `classical_default_ciphersuite` — оба новые, существующие методы
    /// без изменений).
    ///
    /// # Ошибки / Errors
    ///
    /// Те же что [`Self::bootstrap`]: входные данные проверяются, затем боевой
    /// запуск отказывает до полной связки транспортов и проверяющих путей.
    ///
    /// Bootstrap the client in **classical mode** from a 24-word BIP-39
    /// mnemonic. Available only when `umbrella-ffi` is built **without**
    /// feature `pq` — bridge for legacy 0.0.11 iOS / Android apps that
    /// rebuild against the new SDK without an active PQ feature.
    ///
    /// # Purpose (Block 9.12 PQ-first default switch)
    ///
    /// This FFI surface explicitly pins the classical path even after the
    /// default switch to `0x004D` under feature `pq`. Under cfg
    /// classical-only [`Self::bootstrap`] and [`Self::bootstrap_classical`]
    /// are functionally equivalent (both → `0x0003` through the
    /// cfg-conditional [`umbrella_client::DEFAULT_CIPHERSUITE`]); under cfg
    /// `pq` [`Self::bootstrap_classical`] is **not exposed** (postulate 14
    /// — explicit choice via named constructor or per-chat override
    /// `ChatSettings.ciphersuite = Some(0x0003)`).
    ///
    /// # Postulate 14 (no silent fallback)
    ///
    /// This constructor is NOT a silent fallback from PQ to classical — it
    /// is the caller's explicit choice of classical mode. A caller wanting
    /// PQ under cfg classical-only must rebuild the SDK with feature `pq`
    /// and use [`Self::bootstrap_pq`] (cfg pq).
    ///
    /// # ABI invariant (ADR-010)
    ///
    /// This method is a separate **additional** constructor exposed only
    /// under cfg classical-only. [`Self::bootstrap`]'s signature and
    /// behavior are unchanged — the uniffi 0.28+ build-time gate
    /// (`cfg(not(feature = "pq"))`) guarantees that existing 0.0.11 Swift /
    /// Kotlin apps built without feature `pq` see the same FFI methods as
    /// before (Block 9.12 commit adds `bootstrap_classical` plus
    /// `classical_default_ciphersuite` — both new; existing methods are
    /// unchanged).
    ///
    /// # Errors
    ///
    /// Same as [`Self::bootstrap`]: inputs are validated, then production
    /// bootstrap fails fast until transports and verifier paths are complete.
    #[uniffi::constructor]
    pub async fn bootstrap_classical(
        config: ClientConfigFfi,
        mnemonic_phrase: String,
    ) -> Result<Arc<Self>, UmbrellaError> {
        let _seed = IdentitySeed::from_mnemonic(&mnemonic_phrase, MnemonicLanguage::English)
            .map_err(|e| UmbrellaError::Identity(e.to_string()))?;

        let _rust_config: ClientConfig = config.try_into()?;
        Err(production_bootstrap_unavailable())
    }
}
