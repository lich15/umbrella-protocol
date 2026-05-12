//! Trait для native platform key storage.
//!
//! Реализации:
//! - **iOS**: Keychain (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) +
//!   Secure Enclave (`kSecAttrTokenIDSecureEnclave`, non-exportable P-256).
//!   Код в `examples/ios-harness/NativeBridges/KeyStoreBridge.swift` (Блок 7.8).
//! - **Android**: AndroidKeyStore + StrongBox (`setIsStrongBoxBacked(true)`,
//!   EC P-256 non-exportable). Код в
//!   `examples/android-harness/.../KeyStoreBridge.kt` (Блок 7.9).
//!
//! Из Rust через FFI callback вызываются только операции «подпиши этим
//! ключом» или «сгенерируй новый hardware-backed ключ» — приватные ключи
//! **физически никогда не покидают TEE**. Ed25519 keys в SE/StrongBox
//! недоступны, поэтому реальная реализация маппит Ed25519-пары из
//! identity-seed на P-256 / EC внутри SE; детали — ADR-010 Решение 5.
//!
//! В Блоке 7.3 определена только абстракция; полноценная native bridge
//! реализация — Блоки 7.8 (iOS) и 7.9 (Android).
//!
//! Trait for native platform key storage.
//!
//! Implementations:
//! - **iOS**: Keychain + Secure Enclave (non-exportable P-256). Code in
//!   `examples/ios-harness/NativeBridges/KeyStoreBridge.swift` (Block 7.8).
//! - **Android**: AndroidKeyStore + StrongBox (EC P-256 non-exportable).
//!   Code in `examples/android-harness/.../KeyStoreBridge.kt` (Block 7.9).
//!
//! Rust invokes only "sign with this key" or "generate new hardware-backed
//! key" operations via FFI callbacks — private keys **physically never
//! leave TEE**. Ed25519 keys are not natively supported in SE/StrongBox, so
//! the real implementation maps Ed25519 pairs derived from identity-seed
//! onto P-256/EC material inside the TEE; details in ADR-010 Decision 5.
//!
//! Block 7.3 defines the abstraction only; the full native bridge
//! implementations are Blocks 7.8 (iOS) and 7.9 (Android).

use async_trait::async_trait;
use thiserror::Error;

/// Результат `bootstrap_identity`. Содержит публичные identity/device
/// материалы — все поля безопасно логируются / сериализуются. Private keys
/// остаются внутри Secure Enclave / StrongBox.
///
/// Result of `bootstrap_identity`. Holds public identity/device material —
/// all fields are safe to log / serialize. Private keys remain inside
/// Secure Enclave / StrongBox.
#[derive(Debug, Clone)]
pub struct BootstrappedIdentity {
    /// Ed25519 identity pubkey (32 байта) — корень доверия пользователя,
    /// публикуется в Key Transparency log как `IdentityAnnounce`.
    ///
    /// Ed25519 identity pubkey (32 bytes) — user's root of trust, published
    /// to the Key Transparency log as `IdentityAnnounce`.
    pub identity_pubkey: [u8; 32],

    /// X25519 identity pubkey (32 байта) — для HPKE sealed-sender envelope
    /// к этому аккаунту (SPEC-08 §4).
    ///
    /// X25519 identity pubkey (32 bytes) — for HPKE sealed-sender envelopes
    /// addressed to this account (SPEC-08 §4).
    pub identity_x25519_pubkey: [u8; 32],

    /// Primary device pubkey (Ed25519 32 байта). Первое устройство
    /// аккаунта (device_index = 0); non-exportable внутри SE/StrongBox.
    ///
    /// Primary device pubkey (Ed25519 32 bytes). The first device of the
    /// account (device_index = 0); non-exportable inside SE/StrongBox.
    pub primary_device_pubkey: [u8; 32],

    /// Attestation от платформы для primary device (wire bytes Apple App
    /// Attest / Google Play Integrity). Используется серверами для
    /// проверки что device действительно создан в TEE.
    ///
    /// Platform attestation for the primary device (Apple App Attest /
    /// Google Play Integrity wire bytes). Servers verify this to confirm the
    /// device was genuinely created inside a TEE.
    pub primary_device_attestation: Vec<u8>,
}

/// Ошибки KeyStore. Отдельный enum на уровне trait — реализация native
/// bridge возвращает именно эти варианты. В FFI слое (Блок 7.7)
/// конвертируется в `ClientError::Platform` / `ClientError::Storage`.
///
/// KeyStore errors. Separate enum at trait level — native bridge
/// implementations return these variants. Converted in the FFI layer
/// (Block 7.7) to `ClientError::Platform` / `ClientError::Storage`.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// Пользователь отказался разблокировать device / ввёл неверный
    /// PIN — `LAError` на iOS, `UserNotAuthenticatedException` на Android.
    /// User refused to unlock the device / entered wrong PIN.
    #[error("keychain access denied")]
    AccessDenied,

    /// Secure Enclave / StrongBox физически недоступны (старое iPhone 5s-,
    /// Android без StrongBox support). Требует graceful fallback на
    /// software-backed ключи — решение принимается приложением.
    /// Secure Enclave / StrongBox physically unavailable — caller chooses
    /// software-backed fallback policy.
    #[error("secure enclave unavailable")]
    EnclaveUnavailable,

    /// Identity ещё не было `bootstrap_identity`; методы-readers до этого
    /// валятся. Правильное поведение приложения: вызвать `bootstrap_identity`.
    /// Identity never bootstrapped; readers fail until `bootstrap_identity`
    /// runs.
    #[error("identity not bootstrapped")]
    NoIdentity,

    /// `device_index` вне [0, 15] (SPEC-11 §4 allows 16 devices per account).
    /// `device_index` outside [0, 15] (SPEC-11 §4 caps at 16 devices).
    #[error("device index out of range: {0}")]
    BadDeviceIndex(u32),

    /// Пользователь отозвал это устройство — signing запрещён.
    /// User revoked this device — signing is forbidden.
    #[error("device revoked: index {0}")]
    DeviceRevoked(u32),

    /// Hardware signing операция упала на уровне TEE (редко — hardware
    /// ошибка или OS policy restriction).
    /// Hardware signing failure inside the TEE (rare — hardware error or OS
    /// policy restriction).
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Прочая native-ошибка (OSStatus/JNI exception text).
    /// Other native error (raw OSStatus / JNI exception text).
    #[error("native error: {0}")]
    Native(String),
}

/// Преобразование в [`crate::ClientError`] для удобства `?`-оператора на
/// call-site. FFI слой (Блок 7.7) имеет своё mapping в ABI-stable
/// `UmbrellaError`.
///
/// Conversion into [`crate::ClientError`] so `?` works at the call site.
/// The FFI layer (Block 7.7) has its own mapping to the ABI-stable
/// `UmbrellaError`.
impl From<KeyStoreError> for crate::ClientError {
    fn from(err: KeyStoreError) -> Self {
        match err {
            KeyStoreError::AccessDenied | KeyStoreError::EnclaveUnavailable => {
                crate::ClientError::Platform(err.to_string())
            }
            KeyStoreError::NoIdentity
            | KeyStoreError::BadDeviceIndex(_)
            | KeyStoreError::DeviceRevoked(_)
            | KeyStoreError::SigningFailed(_)
            | KeyStoreError::Native(_) => crate::ClientError::Platform(err.to_string()),
        }
    }
}

/// Hardware-backed storage abstraction. Реализуется как **callback
/// interface** через uniffi (Блок 7.7) — native side предоставляет
/// конкретную реализацию, Rust только вызывает.
///
/// Семантика атомарности: каждый метод выполняется atomically на уровне
/// native OS primitives (Keychain транзакции / AndroidKeyStore operations).
/// Между вызовами состояние может измениться (например, user revoked device
/// в Settings) — readers должны переживать такие изменения через
/// `DeviceRevoked` / `AccessDenied` ошибки.
///
/// Hardware-backed storage abstraction. Implemented as a **callback
/// interface** via uniffi (Block 7.7) — the native side provides the
/// concrete implementation, Rust only invokes it.
///
/// Atomicity: each method runs atomically at the native OS primitive level
/// (Keychain transactions / AndroidKeyStore ops). Between calls the state
/// may change (e.g., user revokes a device in Settings) — readers must
/// tolerate such changes via `DeviceRevoked` / `AccessDenied` errors.
#[async_trait]
pub trait PersistentKeyStore: Send + Sync {
    /// `true` если ранее вызывался `bootstrap_identity` и state выжил на диске.
    /// Returns `true` if `bootstrap_identity` ran previously and persisted state survived.
    async fn has_identity(&self) -> Result<bool, KeyStoreError>;

    /// Bootstrap — сохранить 24-слов seed, derive identity (Ed25519 +
    /// X25519) + primary device (P-256 non-exportable) + получить platform
    /// attestation. `seed_24w` обязан быть zeroize'н сразу после return.
    ///
    /// Bootstrap — store the 24-word seed, derive identity (Ed25519 +
    /// X25519) + primary device (P-256 non-exportable) + obtain platform
    /// attestation. `seed_24w` MUST be zeroized immediately after return.
    async fn bootstrap_identity(
        &self,
        seed_24w: Vec<u8>,
    ) -> Result<BootstrappedIdentity, KeyStoreError>;

    /// Identity Ed25519 pubkey.
    async fn identity_pubkey(&self) -> Result<[u8; 32], KeyStoreError>;

    /// Identity X25519 pubkey (для HPKE sealed-sender, SPEC-08 §4).
    /// Identity X25519 pubkey (for HPKE sealed-sender, SPEC-08 §4).
    async fn identity_x25519_pubkey(&self) -> Result<[u8; 32], KeyStoreError>;

    /// Подписать `data` identity-ключом. Secure Enclave / StrongBox op —
    /// приватный ключ не покидает TEE. Возвращает 64-байтную Ed25519
    /// подпись.
    ///
    /// Sign `data` with the identity key. Secure Enclave / StrongBox op —
    /// the private key never leaves the TEE. Returns a 64-byte Ed25519
    /// signature.
    async fn sign_with_identity(&self, data: Vec<u8>) -> Result<[u8; 64], KeyStoreError>;

    /// Добавить новое устройство — сгенерировать non-exportable P-256 пару
    /// внутри SE/StrongBox + attestation. Возвращает `(device_index,
    /// attestation_bytes)`.
    ///
    /// Add a new device — generate a non-exportable P-256 pair inside the
    /// TEE + attestation. Returns `(device_index, attestation_bytes)`.
    async fn add_device(
        &self,
        issued_at_millis: u64,
        expires_at_millis: u64,
    ) -> Result<(u32, Vec<u8>), KeyStoreError>;

    /// Отозвать устройство (user action; удаление device-key из
    /// SE/StrongBox + пометка revoked в local index).
    /// Revoke a device (user action; device-key removed from TEE + marked
    /// revoked in the local index).
    async fn revoke_device(&self, device_index: u32) -> Result<(), KeyStoreError>;

    /// Список active device indices (не включает revoked).
    /// List of active device indices (excludes revoked).
    async fn list_active_devices(&self) -> Result<Vec<u32>, KeyStoreError>;

    /// Кэшированное attestation для device (используется при повторной
    /// bootstrap на новом устройстве — новому устройству передают
    /// DeviceAttestation'ы всех предыдущих, SPEC-11 §4).
    ///
    /// Cached attestation for a device (used during new-device bootstrap —
    /// the new device receives the previously-stored DeviceAttestations,
    /// SPEC-11 §4).
    async fn attestation_for_device(&self, device_index: u32) -> Result<Vec<u8>, KeyStoreError>;

    /// Подписать `data` device-ключом (Secure Enclave op).
    /// Sign `data` with the device key (Secure Enclave op).
    async fn sign_with_device(
        &self,
        device_index: u32,
        data: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError>;

    /// Полный purge identity + всех device-keys (account deletion;
    /// irreversible).
    /// Complete purge of identity + all device-keys (account deletion;
    /// irreversible).
    async fn purge_all(&self) -> Result<(), KeyStoreError>;

    /// Derive master-ключ для шифрования SQLite метаданных через
    /// HKDF-SHA512 из identity-seed. Detached from hardware TEE ops,
    /// derived **один раз на запуск клиента**, живёт в памяти в
    /// `SecretBox<[u8; 32]>` (см. [`super::RowCipher`]).
    ///
    /// PRK = HKDF-SHA512(identity_seed, info = b"umbrellax-sqlite-master-v1").
    /// Версия `v1` — для future-proof rotation master-ключа.
    ///
    /// Derive the SQLite metadata master-key via HKDF-SHA512 from the
    /// identity seed. Detached from hardware TEE ops, derived **once per
    /// client start**, kept in memory in a `SecretBox<[u8; 32]>` (see
    /// [`super::RowCipher`]).
    ///
    /// PRK = HKDF-SHA512(identity_seed, info = b"umbrellax-sqlite-master-v1").
    /// Version `v1` — future-proof master-key rotation.
    async fn derive_storage_master_key(&self) -> Result<[u8; 32], KeyStoreError>;
}
