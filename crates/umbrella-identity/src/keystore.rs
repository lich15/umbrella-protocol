//! KeyStore trait — абстракция хранения identity и device-keys без экспорта приватного материала.
//! KeyStore trait — abstraction over identity and device key storage without exporting private material.
//!
//! В production реализуется через Secure Enclave (iOS) или StrongBox (Android) через FFI bridge —
//! приватные ключи никогда не пересекают границу trusted execution.
//! `InMemoryKeyStore` предоставляется для тестов и desktop-разработки; его НЕ использовать
//! в production: ключи живут в обычной куче процесса.
//!
//! In production this is implemented via Secure Enclave (iOS) or StrongBox (Android) through an
//! FFI bridge — private keys never cross the trusted-execution boundary.
//! `InMemoryKeyStore` is provided for tests and desktop development; do NOT use in production:
//! keys live in the regular process heap.
//!
//! ## Lint allow для `Mutex::lock().expect("... poisoned")`
//!
//! `InMemoryKeyStore` использует `std::sync::Mutex` для thread-safe доступа к
//! map'ам устройств. Mutex poisoning означает panic в другом потоке держащим
//! lock — это всегда bug в коде, не runtime error от user input. Стандартный
//! Rust pattern в этом случае — `.expect("mutex poisoned")` с panic. Production
//! KeyStore (Secure Enclave / StrongBox через FFI) использует platform mutexes
//! без poisoning concept.
//!
//! ## Lint allow for `Mutex::lock().expect("... poisoned")`
//!
//! `InMemoryKeyStore` uses `std::sync::Mutex` for thread-safe access to device
//! maps. Mutex poisoning means a panic in another thread holding the lock —
//! always a code bug, not a runtime error from user input. The standard Rust
//! pattern in this case is `.expect("mutex poisoned")` with panic. The
//! production KeyStore (Secure Enclave / StrongBox via FFI) uses platform
//! mutexes without the poisoning concept.

#![allow(
    unknown_lints,
    no_unwrap_in_lib,
    reason = "InMemoryKeyStore: Mutex poisoning is a bug, not a runtime condition; production KeyStore uses platform mutexes via FFI"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use umbrella_crypto_primitives::secret::SecretBytes;
use umbrella_crypto_primitives::sig::Ed25519Signature;

use crate::attestation::DeviceAttestation;
use crate::device_key::{DeviceKey, DeviceKeyPublic};
use crate::error::{IdentityError, Result};
use crate::identity_key::{IdentityKey, IdentityKeyPublic};
use crate::identity_x25519::{IdentityX25519Key, IdentityX25519KeyPublic};
use crate::seed::IdentitySeed;

#[cfg(feature = "pq")]
use crate::cloud_wrap_recovery::{CloudWrapRecoveryKey, CloudWrapRecoveryKeyPublic};
#[cfg(feature = "pq")]
use crate::hybrid_device_key::{HybridDeviceKey, HybridDeviceKeyPublic};
#[cfg(feature = "pq")]
use crate::hybrid_identity::{HybridIdentityKey, HybridIdentityKeyPublic};
#[cfg(feature = "pq")]
use crate::slh_dsa_backup::{SlhDsaBackupKey, SlhDsaBackupKeyPublic};
#[cfg(feature = "pq")]
use secrecy::SecretBox;
#[cfg(feature = "pq")]
use umbrella_pq::{
    HedgedWitness, HybridSignature, SlhDsa128fSignature, XWING_CIPHERTEXT_LEN,
    XWING_SHARED_SECRET_LEN,
};

/// Источник wall-clock времени для проверки expiration в attestation.
/// Wall-clock time source for attestation expiration checks.
///
/// Trait чтобы тесты могли подменять контролируемым clock'ом.
/// Trait so tests can substitute a controlled clock.
pub trait Clock: Send + Sync {
    /// Возвращает текущее unix-время в секундах.
    /// Returns the current unix time in seconds.
    fn now_unix_secs(&self) -> u64;
}

/// Системные часы через `std::time::SystemTime`.
/// System clock via `std::time::SystemTime`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Фиксированный clock для детерминистических тестов.
/// Fixed clock for deterministic tests.
#[derive(Debug, Clone)]
pub struct FixedClock {
    now: Arc<Mutex<u64>>,
}

impl FixedClock {
    /// Создаёт clock с заданным начальным временем.
    /// Creates a clock with the given initial time.
    pub fn new(initial: u64) -> Self {
        Self {
            now: Arc::new(Mutex::new(initial)),
        }
    }

    /// Сдвигает clock вперёд на `delta` секунд.
    /// Advances the clock forward by `delta` seconds.
    pub fn advance(&self, delta: u64) {
        let mut g = self.now.lock().expect("FixedClock mutex poisoned");
        *g = g.saturating_add(delta);
    }

    /// Устанавливает абсолютное время.
    /// Sets an absolute time.
    pub fn set(&self, value: u64) {
        let mut g = self.now.lock().expect("FixedClock mutex poisoned");
        *g = value;
    }
}

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        *self.now.lock().expect("FixedClock mutex poisoned")
    }
}

/// Контракт хранилища ключей: identity-key плюс множество зарегистрированных device-key с attestation-ами.
/// Key storage contract: identity key plus a set of registered device keys with attestations.
///
/// Все методы подписи **никогда не возвращают приватный ключ наружу** — только результат подписи
/// либо публичный ключ.
/// All signing methods **never return the private key externally** — only the signature result
/// or the public key.
pub trait KeyStore: Send + Sync {
    /// Индекс аккаунта пользователя в дереве BIP-32 (обычно 0).
    /// User account index in the BIP-32 tree (usually 0).
    fn account(&self) -> u32;

    /// Возвращает публичный identity-key.
    /// Returns the public identity key.
    fn identity_public(&self) -> IdentityKeyPublic;

    /// Подписывает identity-key произвольное сообщение.
    /// Вызывающий ответственен за domain-separation сообщения.
    /// Signs arbitrary message with the identity key.
    /// Caller is responsible for message domain separation.
    fn sign_with_identity(&self, message: &[u8]) -> Ed25519Signature;

    /// Возвращает упорядоченный список индексов зарегистрированных (не отозванных) устройств.
    /// Returns the ordered list of indices of registered (not revoked) devices.
    fn active_device_indices(&self) -> Vec<u32>;

    /// Возвращает все известные индексы (включая revoked) — для KT мониторинга.
    /// Returns all known indices (including revoked) — for KT monitoring.
    fn all_known_device_indices(&self) -> Vec<u32>;

    /// Публичный device-key по индексу; None если не зарегистрирован.
    /// Public device key by index; None if not registered.
    fn device_public(&self, index: u32) -> Option<DeviceKeyPublic>;

    /// Подписанный identity-key attestation для устройства; None если не зарегистрирован.
    /// Identity-signed attestation for the device; None if not registered.
    fn device_attestation(&self, index: u32) -> Option<DeviceAttestation>;

    /// Подписывает device-key (по индексу) произвольное сообщение.
    /// Signs arbitrary message with the device key (by index).
    fn sign_with_device(&self, index: u32, message: &[u8]) -> Result<Ed25519Signature>;

    /// Регистрирует новое устройство, выдаёт attestation от identity-key.
    /// Registers a new device, issuing an attestation from the identity key.
    ///
    /// `ttl_secs` — срок действия attestation в секундах от текущего clock; `None` для бессрочного.
    /// `ttl_secs` — attestation lifetime in seconds from current clock; `None` for perpetual.
    fn add_device(&self, index: u32, ttl_secs: Option<u64>) -> Result<DeviceAttestation>;

    /// Отзывает устройство; subsequently `sign_with_device` для этого индекса возвращает `RevokedDevice`.
    /// Revokes a device; subsequently `sign_with_device` for that index returns `RevokedDevice`.
    fn revoke_device(&self, index: u32) -> Result<()>;

    /// Возвращает публичный X25519 identity-ключ (для Sealed Sender ECDH).
    /// Returns the public X25519 identity key (for Sealed Sender ECDH).
    fn identity_x25519_public(&self) -> IdentityX25519KeyPublic;

    /// Вычисляет ECDH shared secret между нашим identity X25519 приватным ключом и публичным
    /// ключом собеседника. Приватный ключ не покидает keystore.
    /// Computes an ECDH shared secret between our identity X25519 private key and the peer's
    /// public key. The private key never leaves the keystore.
    fn x25519_dh_with_identity(&self, peer: &IdentityX25519KeyPublic) -> SecretBytes<32>;

    // ─── Hybrid post-quantum API (Этап 8, ADR-011 Решение 5; feature `pq`) ───

    /// Возвращает публичный hybrid identity-key (Ed25519 + ML-DSA-65) для KT publishing.
    /// Returns the public hybrid identity key (Ed25519 + ML-DSA-65) for KT publishing.
    #[cfg(feature = "pq")]
    fn hybrid_identity_public(&self) -> HybridIdentityKeyPublic;

    /// Подписывает произвольное сообщение hybrid identity-key в AND-mode.
    ///
    /// Signing требует CSPRNG для ML-DSA-65 hedged-randomness. Implementation должен
    /// использовать high-entropy source (OsRng в production).
    ///
    /// Signs an arbitrary message with the hybrid identity key in AND-mode.
    ///
    /// Signing requires a CSPRNG for ML-DSA-65 hedged-randomness. Implementations must
    /// use a high-entropy source (OsRng in production).
    #[cfg(feature = "pq")]
    fn sign_with_hybrid_identity(&self, message: &[u8]) -> Result<HybridSignature>;

    /// Возвращает публичный hybrid device-key по индексу; None если не зарегистрирован.
    /// Returns the public hybrid device key by index; None if not registered.
    #[cfg(feature = "pq")]
    fn hybrid_device_public(&self, index: u32) -> Option<HybridDeviceKeyPublic>;

    /// Подписывает произвольное сообщение hybrid device-key (по индексу) в AND-mode.
    /// Signs an arbitrary message with the hybrid device key (by index) in AND-mode.
    #[cfg(feature = "pq")]
    fn sign_with_hybrid_device(&self, index: u32, message: &[u8]) -> Result<HybridSignature>;

    /// Возвращает публичный SLH-DSA backup ключ для KT v2 entry / catastrophic recovery.
    /// Returns the public SLH-DSA backup key for KT v2 entry / catastrophic recovery.
    #[cfg(feature = "pq")]
    fn slh_dsa_backup_public(&self) -> SlhDsaBackupKeyPublic;

    /// Подписывает rotation-proof сообщение SLH-DSA backup ключом.
    ///
    /// Используется в catastrophic recovery flow когда identity ключ скомпрометирован
    /// либо потерян и требуется fallback authorization rotation в KT log v2 (SPEC-09 / ADR-008).
    ///
    /// Signs a rotation-proof message with the SLH-DSA backup key.
    ///
    /// Used in the catastrophic recovery flow when the identity key is compromised or lost
    /// and a fallback authorisation for rotation in KT log v2 is needed (SPEC-09 / ADR-008).
    #[cfg(feature = "pq")]
    fn sign_slh_dsa_backup_proof(&self, message: &[u8]) -> Result<SlhDsa128fSignature>;

    /// Возвращает публичный recovery X-Wing ключ для cloud-wrap V2 (Hybrid PQ wrap).
    ///
    /// Используется отправителем (sealer) для X-Wing encapsulation V2 envelope над
    /// V1 WrappedKey. Recovery key derives детерминистично из той же BIP-39
    /// mnemonic что и identity (Этап 8 блок 8.7).
    ///
    /// Returns the public recovery X-Wing key for cloud-wrap V2 (Hybrid PQ wrap).
    ///
    /// Used by the sender (sealer) for X-Wing encapsulation in the V2 envelope
    /// over the V1 WrappedKey. The recovery key is derived deterministically from
    /// the same BIP-39 mnemonic as the identity (Stage 8 block 8.7).
    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_public(&self) -> CloudWrapRecoveryKeyPublic;

    /// X-Wing decapsulation на стороне получателя (unsealer) для cloud-wrap V2.
    ///
    /// Восстанавливает 32-byte shared secret из 1120-byte X-Wing ciphertext под
    /// recovery secret seed; используется в `umbrella-backup::cloud_wrap::pq_wrap::
    /// unwrap_v2_to_v1` для раскрытия outer X-Wing layer V2 envelope.
    ///
    /// Recipient-side X-Wing decapsulation for cloud-wrap V2.
    ///
    /// Recovers a 32-byte shared secret from a 1120-byte X-Wing ciphertext under
    /// the recovery secret seed; used by `umbrella-backup::cloud_wrap::pq_wrap::
    /// unwrap_v2_to_v1` to open the outer X-Wing layer of the V2 envelope.
    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_decapsulate(
        &self,
        ct: &[u8; XWING_CIPHERTEXT_LEN],
    ) -> Result<SecretBox<[u8; XWING_SHARED_SECRET_LEN]>>;

    /// Возвращает `HedgedWitness` — 32-байтный secret-derivative identity_seed,
    /// используемый sender-side `xwing_encaps_hedged` для defense-in-depth
    /// против compromised CSPRNG (Bellare-Hoang-Keelveedhi 2015).
    ///
    /// Derivation: HKDF-SHA256(identity_seed_bytes, salt=
    /// `HEDGED_WITNESS_HKDF_SALT`, info=account.to_be_bytes()) → 32 bytes.
    /// Deterministic — переживает restart, не нужно персиста beyond BIP-39
    /// mnemonic. Identity rotation генерирует свежий witness потому что
    /// меняется seed.
    ///
    /// Returns the `HedgedWitness` — a 32-byte secret derivative of
    /// identity_seed used by sender-side `xwing_encaps_hedged` for
    /// defense-in-depth against a compromised CSPRNG
    /// (Bellare-Hoang-Keelveedhi 2015).
    ///
    /// Derivation: HKDF-SHA256(identity_seed_bytes,
    /// salt=`HEDGED_WITNESS_HKDF_SALT`, info=account.to_be_bytes()) → 32 bytes.
    /// Deterministic — survives restart, no persistence required beyond
    /// the BIP-39 mnemonic. Identity rotation produces a fresh witness
    /// because the seed changes.
    #[cfg(feature = "pq")]
    fn hedged_encaps_witness(&self) -> &HedgedWitness;
}

/// Внутренняя запись о зарегистрированном устройстве в InMemoryKeyStore.
/// Internal record of a registered device in the InMemoryKeyStore.
struct DeviceRecord {
    /// Приватный device-key (DeviceKey уже ZeroizeOnDrop — обнуляется при удалении из map).
    /// Private device key (DeviceKey is already ZeroizeOnDrop — zeroized on map removal).
    private: DeviceKey,
    public: DeviceKeyPublic,
    attestation: DeviceAttestation,
    revoked: bool,
}

/// In-memory KeyStore для тестов и desktop-разработки.
/// In-memory KeyStore for tests and desktop development.
///
/// **НЕ для production.** Приватные ключи живут в куче процесса; используйте Secure Enclave/StrongBox
/// implementation через FFI bridge в production коде.
/// **NOT for production.** Private keys live in the process heap; use the Secure Enclave/StrongBox
/// implementation via FFI bridge in production code.
pub struct InMemoryKeyStore {
    seed: IdentitySeed,
    identity: IdentityKey,
    identity_x25519: IdentityX25519Key,
    account: u32,
    devices: Mutex<BTreeMap<u32, DeviceRecord>>,
    clock: Arc<dyn Clock>,

    // ─── Hybrid post-quantum slots (Этап 8 ADR-011, активны под feature `pq`) ───
    // Eagerly derived из same IdentitySeed при `open()` — recovery flow
    // унифицирован с classical (одна BIP-39 mnemonic восстанавливает всё).
    // Hybrid post-quantum slots (Stage 8 ADR-011, active under feature `pq`).
    // Eagerly derived from the same IdentitySeed at `open()` — the recovery flow is unified
    // with classical (one BIP-39 mnemonic restores everything).
    #[cfg(feature = "pq")]
    hybrid_identity: HybridIdentityKey,
    #[cfg(feature = "pq")]
    slh_dsa_backup: SlhDsaBackupKey,
    #[cfg(feature = "pq")]
    hybrid_devices: Mutex<BTreeMap<u32, HybridDeviceKey>>,
    #[cfg(feature = "pq")]
    cloud_wrap_recovery: CloudWrapRecoveryKey,

    // Hedged-encaps witness (round-3 hedged-encaps closure 2026-05-19,
    // Bellare-Hoang-Keelveedhi 2015). Derive'ится из IdentitySeed.seed()
    // через HKDF-SHA256 once at open(); zeroize-on-drop через
    // `HedgedWitness` SecretBox. Не сериализуется — детерминистически
    // воссоздается из той же mnemonic при следующем open().
    //
    // Hedged-encaps witness (round-3 hedged-encaps closure 2026-05-19,
    // Bellare-Hoang-Keelveedhi 2015). Derived from `IdentitySeed.seed()`
    // via HKDF-SHA256 once at `open()`; zeroize-on-drop via `HedgedWitness`
    // SecretBox. Not serialized — deterministically re-derived from the
    // same mnemonic on the next `open()`.
    #[cfg(feature = "pq")]
    hedged_witness: HedgedWitness,
}

impl InMemoryKeyStore {
    /// Конструирует keystore из IdentitySeed и аккаунта; identity-key и X25519 identity
    /// derive автоматически из того же seed по разным путям. Под feature `pq` дополнительно
    /// derive hybrid identity (Ed25519+ML-DSA-65) + SLH-DSA backup из той же seed.
    /// Constructs a keystore from an IdentitySeed and account; both identity keys (Ed25519
    /// and X25519) are derived automatically from the same seed at distinct paths. Under
    /// feature `pq`, the hybrid identity (Ed25519+ML-DSA-65) and the SLH-DSA backup key are
    /// additionally derived from the same seed.
    pub fn open(seed: IdentitySeed, account: u32, clock: Arc<dyn Clock>) -> Result<Self> {
        let identity = IdentityKey::derive(&seed, account)?;
        let identity_x25519 = IdentityX25519Key::derive(&seed, account)?;

        #[cfg(feature = "pq")]
        let hybrid_identity = HybridIdentityKey::derive(&seed, account)?;
        #[cfg(feature = "pq")]
        let slh_dsa_backup = SlhDsaBackupKey::derive(&seed, account)?;
        #[cfg(feature = "pq")]
        let cloud_wrap_recovery = CloudWrapRecoveryKey::derive(&seed, account)?;
        // Hedged-encaps witness: deterministic HKDF-SHA256 derivative из
        // 64-byte BIP-39 PBKDF2 seed + account index. Same source как
        // CloudWrapRecoveryKey / SlhDsaBackupKey — single recovery flow
        // через mnemonic.
        //
        // Hedged-encaps witness: deterministic HKDF-SHA256 derivative
        // from the 64-byte BIP-39 PBKDF2 seed + account index. Same source
        // as CloudWrapRecoveryKey / SlhDsaBackupKey — single recovery
        // flow via mnemonic.
        #[cfg(feature = "pq")]
        let hedged_witness = HedgedWitness::derive_from_identity_seed(seed.seed(), account);

        Ok(Self {
            seed,
            identity,
            identity_x25519,
            account,
            devices: Mutex::new(BTreeMap::new()),
            clock,
            #[cfg(feature = "pq")]
            hybrid_identity,
            #[cfg(feature = "pq")]
            slh_dsa_backup,
            #[cfg(feature = "pq")]
            hybrid_devices: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "pq")]
            cloud_wrap_recovery,
            #[cfg(feature = "pq")]
            hedged_witness,
        })
    }

    /// Возвращает количество зарегистрированных устройств (активных + revoked).
    /// Returns the count of registered devices (active + revoked).
    pub fn device_count(&self) -> usize {
        self.devices
            .lock()
            .expect("device map mutex poisoned")
            .len()
    }
}

impl KeyStore for InMemoryKeyStore {
    fn account(&self) -> u32 {
        self.account
    }

    fn identity_public(&self) -> IdentityKeyPublic {
        self.identity.public()
    }

    fn sign_with_identity(&self, message: &[u8]) -> Ed25519Signature {
        self.identity.sign(message)
    }

    fn active_device_indices(&self) -> Vec<u32> {
        let map = self.devices.lock().expect("device map mutex poisoned");
        map.iter()
            .filter_map(|(idx, rec)| if rec.revoked { None } else { Some(*idx) })
            .collect()
    }

    fn all_known_device_indices(&self) -> Vec<u32> {
        let map = self.devices.lock().expect("device map mutex poisoned");
        map.keys().copied().collect()
    }

    fn device_public(&self, index: u32) -> Option<DeviceKeyPublic> {
        let map = self.devices.lock().expect("device map mutex poisoned");
        map.get(&index).map(|rec| rec.public)
    }

    fn device_attestation(&self, index: u32) -> Option<DeviceAttestation> {
        let map = self.devices.lock().expect("device map mutex poisoned");
        map.get(&index).map(|rec| rec.attestation)
    }

    fn sign_with_device(&self, index: u32, message: &[u8]) -> Result<Ed25519Signature> {
        let map = self.devices.lock().expect("device map mutex poisoned");
        let rec = map
            .get(&index)
            .ok_or(IdentityError::UnknownDevice { index })?;
        if rec.revoked {
            return Err(IdentityError::RevokedDevice { index });
        }
        Ok(rec.private.sign(message))
    }

    fn add_device(&self, index: u32, ttl_secs: Option<u64>) -> Result<DeviceAttestation> {
        let mut map = self.devices.lock().expect("device map mutex poisoned");
        if map.contains_key(&index) {
            return Err(IdentityError::DuplicateDevice { index });
        }

        let device = DeviceKey::derive(&self.seed, self.account, index)?;
        let public = device.public();

        let issued_at = self.clock.now_unix_secs();
        let expires_at = match ttl_secs {
            Some(ttl) => issued_at.saturating_add(ttl),
            None => crate::attestation::NEVER_EXPIRES,
        };

        let attestation = DeviceAttestation::issue(
            &self.identity,
            self.account,
            index,
            public,
            issued_at,
            expires_at,
        );

        map.insert(
            index,
            DeviceRecord {
                private: device,
                public,
                attestation,
                revoked: false,
            },
        );

        // Под feature `pq` параллельно собираем hybrid device key (deterministic
        // derive из той же seed). Revocation tracked в classical map (single source of truth).
        // Under feature `pq` we also build the parallel hybrid device key (deterministic
        // derive from the same seed). Revocation is tracked in the classical map (single
        // source of truth).
        #[cfg(feature = "pq")]
        {
            let hybrid = HybridDeviceKey::derive(&self.seed, self.account, index)?;
            self.hybrid_devices
                .lock()
                .expect("hybrid device map mutex poisoned")
                .insert(index, hybrid);
        }

        Ok(attestation)
    }

    fn revoke_device(&self, index: u32) -> Result<()> {
        let mut map = self.devices.lock().expect("device map mutex poisoned");
        let rec = map
            .get_mut(&index)
            .ok_or(IdentityError::UnknownDevice { index })?;
        rec.revoked = true;
        Ok(())
    }

    fn identity_x25519_public(&self) -> IdentityX25519KeyPublic {
        self.identity_x25519.public()
    }

    fn x25519_dh_with_identity(&self, peer: &IdentityX25519KeyPublic) -> SecretBytes<32> {
        self.identity_x25519.diffie_hellman(peer)
    }

    // ─── Hybrid post-quantum API (Этап 8 ADR-011 Решение 5; feature `pq`) ───
    // Все методы под feature `pq` используют internal `OsRng` для ML-DSA-65 / SLH-DSA
    // hedged-randomness signing — production CSPRNG. Тесты которые требуют deterministic
    // подписей делаются на уровне `umbrella_pq::*` (где RNG injectable через generic).
    //
    // Hybrid post-quantum API (Stage 8 ADR-011 Decision 5; feature `pq`).
    // All methods under feature `pq` use internal `OsRng` for ML-DSA-65 / SLH-DSA
    // hedged-randomness signing — production CSPRNG. Tests that require deterministic
    // signatures use `umbrella_pq::*` directly (where RNG is injectable through generics).

    #[cfg(feature = "pq")]
    fn hybrid_identity_public(&self) -> HybridIdentityKeyPublic {
        self.hybrid_identity.public().clone()
    }

    #[cfg(feature = "pq")]
    fn sign_with_hybrid_identity(&self, message: &[u8]) -> Result<HybridSignature> {
        let mut rng = rand_core::OsRng;
        self.hybrid_identity.sign(&mut rng, message)
    }

    #[cfg(feature = "pq")]
    fn hybrid_device_public(&self, index: u32) -> Option<HybridDeviceKeyPublic> {
        let map = self
            .hybrid_devices
            .lock()
            .expect("hybrid device map mutex poisoned");
        map.get(&index).map(|hd| hd.public().clone())
    }

    #[cfg(feature = "pq")]
    fn sign_with_hybrid_device(&self, index: u32, message: &[u8]) -> Result<HybridSignature> {
        // Revocation enforced через classical map (single source of truth).
        // Revocation enforced through the classical map (single source of truth).
        let classical = self.devices.lock().expect("device map mutex poisoned");
        let classical_rec = classical
            .get(&index)
            .ok_or(IdentityError::UnknownDevice { index })?;
        if classical_rec.revoked {
            return Err(IdentityError::RevokedDevice { index });
        }
        drop(classical);

        let hybrid_map = self
            .hybrid_devices
            .lock()
            .expect("hybrid device map mutex poisoned");
        let hybrid_rec = hybrid_map
            .get(&index)
            .ok_or(IdentityError::UnknownDevice { index })?;

        let mut rng = rand_core::OsRng;
        hybrid_rec.sign(&mut rng, message)
    }

    #[cfg(feature = "pq")]
    fn slh_dsa_backup_public(&self) -> SlhDsaBackupKeyPublic {
        self.slh_dsa_backup.public().clone()
    }

    #[cfg(feature = "pq")]
    fn sign_slh_dsa_backup_proof(&self, message: &[u8]) -> Result<SlhDsa128fSignature> {
        let mut rng = rand_core::OsRng;
        self.slh_dsa_backup.sign_rotation_proof(&mut rng, message)
    }

    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_public(&self) -> CloudWrapRecoveryKeyPublic {
        self.cloud_wrap_recovery.public().clone()
    }

    #[cfg(feature = "pq")]
    fn cloud_wrap_recovery_decapsulate(
        &self,
        ct: &[u8; XWING_CIPHERTEXT_LEN],
    ) -> Result<SecretBox<[u8; XWING_SHARED_SECRET_LEN]>> {
        self.cloud_wrap_recovery.decapsulate(ct)
    }

    #[cfg(feature = "pq")]
    fn hedged_encaps_witness(&self) -> &HedgedWitness {
        &self.hedged_witness
    }
}

impl core::fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "InMemoryKeyStore(account={}, identity_public={:?}, devices={})",
            self.account,
            self.identity.public(),
            self.device_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::MnemonicLanguage;
    use rand_core::OsRng;

    fn fresh_seed() -> IdentitySeed {
        let mut rng = OsRng;
        IdentitySeed::generate(&mut rng, MnemonicLanguage::English)
    }

    fn store_with_clock(now: u64) -> (InMemoryKeyStore, FixedClock) {
        let clock = FixedClock::new(now);
        let store =
            InMemoryKeyStore::open(fresh_seed(), 0, Arc::new(clock.clone()) as Arc<dyn Clock>)
                .unwrap();
        (store, clock)
    }

    #[test]
    fn open_returns_identity_pubkey() {
        let (store, _) = store_with_clock(1_000);
        let pk = store.identity_public();
        assert_eq!(pk.to_bytes().len(), 32);
    }

    #[test]
    fn sign_with_identity_round_trip() {
        let (store, _) = store_with_clock(1_000);
        let sig = store.sign_with_identity(b"hello");
        store
            .identity_public()
            .verify(b"hello", &sig)
            .expect("identity signature must verify");
    }

    #[test]
    fn add_device_then_sign_and_verify() {
        let (store, _) = store_with_clock(1_000);
        let att = store.add_device(0, Some(10_000)).unwrap();
        att.verify(&store.identity_public(), 1_500).unwrap();

        let sig = store.sign_with_device(0, b"msg").unwrap();
        store
            .device_public(0)
            .unwrap()
            .verify(b"msg", &sig)
            .unwrap();
    }

    #[test]
    fn unknown_device_rejected() {
        let (store, _) = store_with_clock(1_000);
        let result = store.sign_with_device(42, b"x");
        assert!(matches!(
            result,
            Err(IdentityError::UnknownDevice { index: 42 })
        ));
    }

    #[test]
    fn duplicate_device_rejected() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        let result = store.add_device(0, None);
        assert!(matches!(
            result,
            Err(IdentityError::DuplicateDevice { index: 0 })
        ));
    }

    #[test]
    fn revoked_device_cannot_sign() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        store.revoke_device(0).unwrap();
        let result = store.sign_with_device(0, b"x");
        assert!(matches!(
            result,
            Err(IdentityError::RevokedDevice { index: 0 })
        ));
    }

    #[test]
    fn revoke_unknown_device_rejected() {
        let (store, _) = store_with_clock(1_000);
        let result = store.revoke_device(99);
        assert!(matches!(
            result,
            Err(IdentityError::UnknownDevice { index: 99 })
        ));
    }

    #[test]
    fn revoked_device_kept_in_all_known_excluded_from_active() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        store.add_device(1, None).unwrap();
        store.revoke_device(0).unwrap();
        assert_eq!(store.active_device_indices(), vec![1]);
        assert_eq!(store.all_known_device_indices(), vec![0, 1]);
    }

    #[test]
    fn attestation_uses_clock_for_issued_and_expires() {
        let (store, clock) = store_with_clock(5_000);
        let att = store.add_device(0, Some(60)).unwrap();
        assert_eq!(att.issued_at(), 5_000);
        assert_eq!(att.expires_at(), 5_060);

        // Перематываем clock за окно — attestation expired.
        // Advance the clock past the window — attestation expired.
        clock.set(5_100);
        let result = att.verify(&store.identity_public(), clock.now_unix_secs());
        assert!(matches!(
            result,
            Err(IdentityError::AttestationExpired { .. })
        ));
    }

    #[test]
    fn ttl_none_yields_never_expires() {
        let (store, _) = store_with_clock(0);
        let att = store.add_device(0, None).unwrap();
        assert_eq!(att.expires_at(), crate::attestation::NEVER_EXPIRES);
        att.verify(&store.identity_public(), u64::MAX - 1).unwrap();
    }

    #[test]
    fn deterministic_per_seed_and_account() {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let mnemonic = seed.to_mnemonic();
        let restored =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

        let store_a = InMemoryKeyStore::open(seed, 0, Arc::new(FixedClock::new(0))).unwrap();
        let store_b = InMemoryKeyStore::open(restored, 0, Arc::new(FixedClock::new(0))).unwrap();

        assert_eq!(
            store_a.identity_public().to_bytes(),
            store_b.identity_public().to_bytes()
        );
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let (store, _) = store_with_clock(0);
        store.add_device(0, None).unwrap();
        let s = format!("{store:?}");
        assert!(s.starts_with("InMemoryKeyStore(account=0,"));
        assert!(s.contains("devices=1"));
    }

    // ─── Hybrid post-quantum tests (feature `pq`, Этап 8 ADR-011 Решение 5) ───

    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_identity_public_matches_classical_ed25519_part() {
        let (store, _) = store_with_clock(1_000);
        let classical_pub = store.identity_public();
        let hybrid_pub = store.hybrid_identity_public();
        assert_eq!(
            classical_pub.to_bytes(),
            hybrid_pub.ed25519_bytes(),
            "Ed25519 component of hybrid identity must match classical IdentityKey"
        );
    }

    #[cfg(feature = "pq")]
    #[test]
    fn sign_with_hybrid_identity_round_trip() {
        let (store, _) = store_with_clock(1_000);
        let sig = store.sign_with_hybrid_identity(b"hello pq").unwrap();
        store
            .hybrid_identity_public()
            .verify(b"hello pq", &sig)
            .expect("hybrid identity signature must verify");
    }

    #[cfg(feature = "pq")]
    #[test]
    fn add_device_also_registers_hybrid_device() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        let hybrid_pub = store
            .hybrid_device_public(0)
            .expect("hybrid device key must be present after add_device");
        // Ed25519 part должен совпадать с classical device pubkey.
        // Ed25519 part must match the classical device pubkey.
        let classical_pub = store.device_public(0).unwrap();
        assert_eq!(classical_pub.to_bytes(), hybrid_pub.ed25519_bytes());
    }

    #[cfg(feature = "pq")]
    #[test]
    fn sign_with_hybrid_device_round_trip() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        let sig = store.sign_with_hybrid_device(0, b"device pq msg").unwrap();
        store
            .hybrid_device_public(0)
            .unwrap()
            .verify(b"device pq msg", &sig)
            .expect("hybrid device signature must verify");
    }

    #[cfg(feature = "pq")]
    #[test]
    fn unknown_hybrid_device_rejected() {
        let (store, _) = store_with_clock(1_000);
        let result = store.sign_with_hybrid_device(99, b"x");
        assert!(matches!(
            result,
            Err(IdentityError::UnknownDevice { index: 99 })
        ));
        assert!(store.hybrid_device_public(99).is_none());
    }

    #[cfg(feature = "pq")]
    #[test]
    fn revoked_hybrid_device_cannot_sign() {
        let (store, _) = store_with_clock(1_000);
        store.add_device(0, None).unwrap();
        // Revocation tracked в classical map — single source of truth.
        // Revocation tracked in the classical map — single source of truth.
        store.revoke_device(0).unwrap();
        let result = store.sign_with_hybrid_device(0, b"x");
        assert!(matches!(
            result,
            Err(IdentityError::RevokedDevice { index: 0 })
        ));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn slh_dsa_backup_public_and_sign_round_trip() {
        let (store, _) = store_with_clock(1_000);
        let backup_pub = store.slh_dsa_backup_public();
        let proof = b"new_identity || kt_seq=42 || ts=1234567890";
        let sig = store.sign_slh_dsa_backup_proof(proof).unwrap();
        backup_pub
            .verify_rotation_proof(proof, &sig)
            .expect("backup rotation proof must verify");
    }

    #[cfg(feature = "pq")]
    #[test]
    fn restore_from_mnemonic_yields_same_hybrid_identity_and_backup() {
        // Сохраняем mnemonic, открываем второй store с restored seed и сравниваем
        // hybrid identity + slh_dsa_backup pubkey'и.
        // Save the mnemonic, open a second store with the restored seed and compare
        // hybrid identity + slh_dsa_backup pubkeys.
        let mut rng = OsRng;
        let original_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let mnemonic = original_seed.to_mnemonic();

        let store_a = InMemoryKeyStore::open(
            original_seed,
            0,
            Arc::new(FixedClock::new(0)) as Arc<dyn Clock>,
        )
        .unwrap();

        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let store_b = InMemoryKeyStore::open(
            restored_seed,
            0,
            Arc::new(FixedClock::new(0)) as Arc<dyn Clock>,
        )
        .unwrap();

        assert_eq!(
            store_a.hybrid_identity_public().to_bytes(),
            store_b.hybrid_identity_public().to_bytes(),
            "hybrid identity must restore from mnemonic"
        );
        assert_eq!(
            store_a.slh_dsa_backup_public().to_bytes(),
            store_b.slh_dsa_backup_public().to_bytes(),
            "SLH-DSA backup must restore from mnemonic"
        );
    }

    /// Different accounts → different hybrid identities + SLH-DSA backups.
    /// Двa независимых seed'а из той же mnemonic фразы дают identical materials
    /// per account — ниже мы используем разные account для проверки domain separation.
    /// Different accounts → different hybrid identities + SLH-DSA backups.
    /// Two independent seeds from the same mnemonic yield identical materials per account —
    /// below we use distinct accounts to verify domain separation.
    #[cfg(feature = "pq")]
    #[test]
    fn different_accounts_give_distinct_hybrid_keys() {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let mnemonic = seed.to_mnemonic();

        let seed_a =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let store_a =
            InMemoryKeyStore::open(seed_a, 0, Arc::new(FixedClock::new(0)) as Arc<dyn Clock>)
                .unwrap();

        let seed_b =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let store_b =
            InMemoryKeyStore::open(seed_b, 1, Arc::new(FixedClock::new(0)) as Arc<dyn Clock>)
                .unwrap();

        assert_ne!(
            store_a.hybrid_identity_public().to_bytes(),
            store_b.hybrid_identity_public().to_bytes()
        );
        assert_ne!(
            store_a.slh_dsa_backup_public().to_bytes(),
            store_b.slh_dsa_backup_public().to_bytes()
        );
    }

    // ─── Cloud-wrap recovery (block 8.7, feature `pq`) ───

    /// `KeyStore::cloud_wrap_recovery_public` byte-identical с прямым
    /// `CloudWrapRecoveryKey::derive` для same (seed, account).
    ///
    /// `KeyStore::cloud_wrap_recovery_public` byte-identical to direct
    /// `CloudWrapRecoveryKey::derive` for the same (seed, account).
    #[cfg(feature = "pq")]
    #[test]
    fn cloud_wrap_recovery_public_matches_direct_derive() {
        use crate::cloud_wrap_recovery::CloudWrapRecoveryKey;

        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let mnemonic = seed.to_mnemonic();

        // Direct derive.
        let direct = CloudWrapRecoveryKey::derive(&seed, 0).unwrap();

        // Через KeyStore.
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let store = InMemoryKeyStore::open(restored_seed, 0, Arc::new(FixedClock::new(0))).unwrap();
        let via_store = store.cloud_wrap_recovery_public();

        assert_eq!(direct.public().to_bytes(), via_store.to_bytes());
        assert_eq!(via_store.account(), 0);
    }

    /// `KeyStore::cloud_wrap_recovery_decapsulate` correctly recovers shared
    /// secret для encaps под `cloud_wrap_recovery_public`.
    ///
    /// `KeyStore::cloud_wrap_recovery_decapsulate` correctly recovers a shared
    /// secret for encaps under `cloud_wrap_recovery_public`.
    #[cfg(feature = "pq")]
    #[test]
    fn cloud_wrap_recovery_keystore_decapsulate_roundtrip() {
        use secrecy::ExposeSecret;
        use umbrella_pq::xwing_encaps;

        let (store, _) = store_with_clock(1_000);
        let pub_key = store.cloud_wrap_recovery_public();

        let mut rng = OsRng;
        let (ct, ss_sender) = xwing_encaps(&mut rng, pub_key.pubkey()).unwrap();

        let ss_recv = store.cloud_wrap_recovery_decapsulate(&ct).unwrap();
        assert_eq!(ss_sender.expose_secret(), ss_recv.expose_secret());
    }

    /// Restore из mnemonic даёт byte-identical recovery pubkey через KeyStore.
    /// Restore from mnemonic yields a byte-identical recovery pubkey via KeyStore.
    #[cfg(feature = "pq")]
    #[test]
    fn cloud_wrap_recovery_restore_from_mnemonic_via_keystore() {
        let mut rng = OsRng;
        let original_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let mnemonic = original_seed.to_mnemonic();

        let store_a =
            InMemoryKeyStore::open(original_seed, 0, Arc::new(FixedClock::new(0))).unwrap();
        let restored_seed =
            IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
        let store_b =
            InMemoryKeyStore::open(restored_seed, 0, Arc::new(FixedClock::new(0))).unwrap();

        assert_eq!(
            store_a.cloud_wrap_recovery_public().to_bytes(),
            store_b.cloud_wrap_recovery_public().to_bytes(),
            "cloud-wrap recovery must restore from mnemonic"
        );
    }
}
