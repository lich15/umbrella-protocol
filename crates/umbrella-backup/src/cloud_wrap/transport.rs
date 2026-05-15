//! Transport trait для отправки `SignedUnwrapRequest` к 5 Sealed Servers.
//! Transport trait for dispatching `SignedUnwrapRequest` to 5 Sealed Servers.
//!
//! Крейт не зависит от HTTP-клиента напрямую. Реальный transport (HTTP/2 +
//! fan-out к `cloud-backup-svc` Umbrella server implementation) реализуется в `umbrella-client`
//! Этапа 7. Для unit- и integration-тестов предусмотрен `MockUnwrapTransport`
//! с конфигурируемым набором mock Sealed Servers.
//!
//! The crate does not depend on an HTTP client directly. Real transport
//! (HTTP/2 + fan-out to `cloud-backup-svc` in Umbrella server implementation) is implemented in
//! `umbrella-client` (Stage 7). For unit and integration tests we provide
//! `MockUnwrapTransport` with a configurable set of mock Sealed Servers.

use curve25519_dalek::scalar::Scalar;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::error::BackupError;

use super::aead::decompress_point;
use super::identity_rotation::IdentityRotationRecord;
use super::params::WitnessIndex;
use super::share::ServerUnwrapShare;
use super::signed_request::{verify_signed_unwrap_request, SignedUnwrapRequest, DEVICE_PUBKEY_LEN};

/// Transport для дисп-отправки unwrap-запроса и приёма shares.
/// Transport for dispatching unwrap request and collecting shares.
pub trait UnwrapTransport {
    /// Отправить запрос всем серверам (fan-out), вернуть до `total` shares.
    /// Send the request to all servers (fan-out), return up to `total` shares.
    ///
    /// # Errors
    /// - [`BackupError::InsufficientUnwrapShares`] если серверы вернули
    ///   меньше валидных shares чем threshold.
    /// - Транспортные ошибки транслируются в конкретные варианты.
    fn dispatch(
        &self,
        request: &SignedUnwrapRequest,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError>;
}

/// Поведение одного mock Sealed Server'а в тестах.
/// Behavior of one mock Sealed Server in tests.
#[derive(Debug, Clone)]
pub enum MockServerBehavior {
    /// Нормальное поведение: проверить подпись, вернуть `k_i · R`.
    /// Normal: verify signature, return `k_i · R`.
    Honest,
    /// Off-line: ответа нет.
    /// Off-line: no response.
    Offline,
    /// Malicious: вернуть `wrong_k · R` с корректным witness_index.
    /// Malicious: return `wrong_k · R` with the correct witness index.
    Tampered,
    /// Ignores signature check (simulates by-pass vulnerability) и отвечает.
    /// Ignores signature check (simulates bypass vuln) and responds.
    IgnoreSignature,
}

/// Один mock Sealed Server для тестов.
/// One mock Sealed Server for tests.
#[derive(Clone)]
pub struct MockSealedServer {
    /// Индекс сервера. Server witness index.
    pub witness_index: WitnessIndex,
    /// Доля `k_i`. Own share `k_i`.
    pub share: Scalar,
    /// Поведение. Behavior.
    pub behavior: MockServerBehavior,
}

/// `Debug` скрывает mock server share: тестовые секреты не должны приучать к логированию долей.
/// `Debug` redacts the mock server share so tests do not normalize logging secret shares.
impl core::fmt::Debug for MockSealedServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MockSealedServer")
            .field("witness_index", &self.witness_index)
            .field("share_redacted", &true)
            .field("behavior", &self.behavior)
            .finish()
    }
}

/// Флаг состояния device-entry в KT mirror (ADR-008 §A.11, SPEC-09 §3, SPEC-11 §4.3).
/// State flag of a device-entry in the KT mirror (ADR-008 §A.11, SPEC-09 §3, SPEC-11 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceEntryStateFlag {
    /// Ожидает `DeviceAuthorizationApproval` от существующего active device.
    /// Awaits `DeviceAuthorizationApproval` from an existing active device.
    Pending,
    /// Авторизован, может запрашивать partial unwrap shares.
    /// Authorized; may request partial unwrap shares.
    Active,
    /// Отозван — terminal state, Sealed Server отказывает навсегда.
    /// Revoked — terminal state, Sealed Server refuses forever.
    Revoked,
    /// Первое device-entry для identity (или после catastrophic recovery).
    /// Валидно только в двух сценариях (SPEC-11 §4.8): primary bootstrap
    /// либо catastrophic recovery bootstrap.
    ///
    /// First device-entry for identity (or after catastrophic recovery).
    /// Valid only in two scenarios (SPEC-11 §4.8): primary bootstrap or
    /// catastrophic recovery bootstrap.
    BootstrapActive,
}

/// Client-side mirror состояния одного device-entry в KT (SPEC-09 §3
/// `DeviceEntryRef`). Каждое поле — копия соответствующего поля из
/// `DeviceAuthorizationApproval` либо implicit bootstrap-параметров.
///
/// Client-side mirror of the state of a single device-entry in KT (SPEC-09
/// §3 `DeviceEntryRef`). Each field mirrors the corresponding field from
/// `DeviceAuthorizationApproval` or implicit bootstrap parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEntryState {
    /// Текущий флаг entry. Current entry flag.
    pub flag: DeviceEntryStateFlag,
    /// Unix-millis с которого entry считается authorized (`0` для pending).
    /// Unix-millis from which the entry is considered authorized (`0` for pending).
    pub authorized_since: u64,
    /// Unix-millis history cutoff из `DeviceAuthorizationApproval` (`0` =
    /// доступ ко всей истории).
    /// Unix-millis history cutoff from `DeviceAuthorizationApproval` (`0` =
    /// full history access).
    pub history_cutoff: u64,
    /// Identity-pubkey под которым device-entry был опубликован. При
    /// rotation старые entry считаются «под старым identity».
    ///
    /// Identity-pubkey under which the device-entry was published. After
    /// rotation, old entries count as "under the old identity".
    pub identity_pubkey_at_publish: [u8; DEVICE_PUBKEY_LEN],
}

/// Кластер из ≤ 5 mock серверов с расширениями ADR-008 (SPEC-12 §A.11).
/// Cluster of up to 5 mock servers with ADR-008 extensions (SPEC-12 §A.11).
///
/// Поведение:
/// - Если `device_entries` пустой (legacy) — используется `authorized_device_pubkeys`
///   HashSet из фазы 5.2 (простая authorize-list проверка).
/// - Если `device_entries` непустой — применяется полный set из пяти проверок
///   SPEC-12 §A.11 (entry flag → authorized_since → history_cutoff →
///   identity chain → revoked cross-check).
///
/// Behavior:
/// - If `device_entries` is empty (legacy) — uses the phase-5.2
///   `authorized_device_pubkeys` HashSet (simple authorize-list check).
/// - If `device_entries` is non-empty — applies the full SPEC-12 §A.11 set
///   of five checks (entry flag → authorized_since → history_cutoff →
///   identity chain → revoked cross-check).
#[derive(Clone)]
pub struct MockUnwrapTransport {
    servers: Vec<MockSealedServer>,
    /// Server-issued nonces already consumed by this mock cluster. Models the
    /// production stale-nonce replay cache before issuing partial shares.
    used_server_nonces: Arc<Mutex<HashSet<[u8; super::signed_request::NONCE_LEN]>>>,
    /// Authorized device pubkeys (legacy phase-5.2 path).
    authorized_device_pubkeys: HashSet<[u8; DEVICE_PUBKEY_LEN]>,
    /// KT mirror device-entry state (ADR-008 path).
    device_entries: HashMap<[u8; DEVICE_PUBKEY_LEN], DeviceEntryState>,
    /// Опубликованная identity rotation запись, если есть. Применяется
    /// при identity-chain consistency check.
    ///
    /// Published identity rotation record, if any. Used in the identity-chain
    /// consistency check.
    identity_rotation: Option<IdentityRotationRecord>,
}

/// `Debug` скрывает mock authorization state и consumed nonces.
/// `Debug` redacts mock authorization state and consumed nonces.
impl core::fmt::Debug for MockUnwrapTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let used_server_nonces_len = self.used_server_nonces.lock().map(|set| set.len()).ok();
        f.debug_struct("MockUnwrapTransport")
            .field("servers", &self.servers)
            .field("used_server_nonces_len", &used_server_nonces_len)
            .field(
                "authorized_device_pubkeys_len",
                &self.authorized_device_pubkeys.len(),
            )
            .field("device_entries_len", &self.device_entries.len())
            .field(
                "identity_rotation_present",
                &self.identity_rotation.is_some(),
            )
            .finish()
    }
}

impl MockUnwrapTransport {
    /// Создать кластер с переданным списком серверов.
    /// Construct a cluster with the given server set.
    #[must_use]
    pub fn new(servers: Vec<MockSealedServer>) -> Self {
        Self {
            servers,
            used_server_nonces: Arc::new(Mutex::new(HashSet::new())),
            authorized_device_pubkeys: HashSet::new(),
            device_entries: HashMap::new(),
            identity_rotation: None,
        }
    }

    /// Зарегистрировать pubkey как authorized (legacy phase-5.2 path).
    /// Register a pubkey as authorized (legacy phase-5.2 path).
    pub fn authorize_device(&mut self, device_pubkey: [u8; DEVICE_PUBKEY_LEN]) {
        self.authorized_device_pubkeys.insert(device_pubkey);
    }

    /// Зарегистрировать device-entry в KT mirror (ADR-008 path).
    /// Register a device-entry in the KT mirror (ADR-008 path).
    pub fn register_device_entry(
        &mut self,
        device_pubkey: [u8; DEVICE_PUBKEY_LEN],
        state: DeviceEntryState,
    ) {
        self.device_entries.insert(device_pubkey, state);
    }

    /// Установить identity rotation запись, применяемую в identity-chain
    /// consistency проверке. Обычно вызывается один раз на test instance.
    ///
    /// Install the identity rotation record used in the identity-chain
    /// consistency check. Typically called once per test instance.
    pub fn set_identity_rotation(&mut self, rotation: IdentityRotationRecord) {
        self.identity_rotation = Some(rotation);
    }

    /// Выполнить пять упорядоченных проверок SPEC-12 §A.11 для `request`
    /// с заявленным `envelope_timestamp` (timestamp конкретного
    /// `WrappedKey` для которого запрашиваются shares).
    ///
    /// Run the five ordered checks from SPEC-12 §A.11 for `request` with
    /// the declared `envelope_timestamp` (timestamp of the specific
    /// `WrappedKey` for which shares are requested).
    ///
    /// Порядок (SPEC-12 §A.11):
    /// 1. entry flag: `Pending` → `DevicePendingAuthorization`;
    ///    `Revoked` → `DeviceRevoked`;
    ///    `Active` / `BootstrapActive` → продолжить.
    /// 2. `authorized_since ≤ request.timestamp_unix_millis` иначе
    ///    `CryptoVerificationFailed`.
    /// 3. `envelope_timestamp ≥ history_cutoff` (если последний > 0)
    ///    иначе `HistoryCutoffApplies`.
    /// 4. Identity chain: если есть `IdentityRotationRecord` и
    ///    `identity_pubkey_at_publish == rotation.old_identity_pubkey` —
    ///    `IdentityRotatedRefuseOldRequests`.
    /// 5. revoked cross-check: если device стал revoked после rotation —
    ///    `DeviceRevoked`.
    ///
    /// # Errors
    /// Одна из перечисленных выше ошибок либо `Ok(())`.
    fn check_authorization_state(
        &self,
        request: &SignedUnwrapRequest,
        envelope_timestamp: u64,
    ) -> Result<(), BackupError> {
        let Some(entry) = self.device_entries.get(&request.device_pubkey) else {
            // Неизвестное устройство при включённом ADR-008 состоянии не получает доли.
            // Unknown devices fail closed once ADR-008 authorization state is active.
            return Err(BackupError::CryptoVerificationFailed);
        };

        // 1. Entry flag.
        match entry.flag {
            DeviceEntryStateFlag::Pending => return Err(BackupError::DevicePendingAuthorization),
            DeviceEntryStateFlag::Revoked => return Err(BackupError::DeviceRevoked),
            DeviceEntryStateFlag::Active | DeviceEntryStateFlag::BootstrapActive => {}
        }

        // 2. authorized_since ≤ request.timestamp_unix_millis.
        if entry.authorized_since > request.timestamp_unix_millis {
            return Err(BackupError::CryptoVerificationFailed);
        }

        // 3. envelope_timestamp ≥ history_cutoff.
        if entry.history_cutoff > 0 && envelope_timestamp < entry.history_cutoff {
            return Err(BackupError::HistoryCutoffApplies {
                envelope_timestamp,
                cutoff: entry.history_cutoff,
            });
        }

        // 4. Identity-chain consistency.
        if let Some(rotation) = &self.identity_rotation {
            if entry.identity_pubkey_at_publish == rotation.old_identity_pubkey {
                return Err(BackupError::IdentityRotatedRefuseOldRequests);
            }
        }

        // 5. revoked cross-check поглощён шагом 1 для этого mock. В production
        // Sealed Server дополнительно сверяет revocation records под текущим/
        // предыдущим identity в KT — для client-side mirror достаточно шага 1.
        Ok(())
    }

    fn check_and_record_nonce(&self, request: &SignedUnwrapRequest) -> Result<(), BackupError> {
        let mut used = self
            .used_server_nonces
            .lock()
            .map_err(|_| BackupError::CryptoVerificationFailed)?;
        if !used.insert(request.server_nonce) {
            return Err(BackupError::CryptoVerificationFailed);
        }
        Ok(())
    }

    /// Dispatch с явной поддержкой ADR-008 authorization checks. Применяет
    /// пять проверок SPEC-12 §A.11 **перед** выдачей partial shares.
    ///
    /// Dispatch with explicit ADR-008 authorization checks. Applies the five
    /// SPEC-12 §A.11 checks **before** issuing partial shares.
    ///
    /// # Errors
    /// Любая ошибка из `check_authorization_state` либо стандартные
    /// ошибки dispatch (verify, crypto).
    pub fn dispatch_with_envelope(
        &self,
        request: &SignedUnwrapRequest,
        envelope_timestamp: u64,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        self.check_authorization_state(request, envelope_timestamp)?;
        self.dispatch_inner(request)
    }

    /// Внутренний метод выдачи shares (после прохождения всех authorization
    /// проверок). Делится между `dispatch` (legacy) и `dispatch_with_envelope`.
    ///
    /// Internal share-issuance method (after all authorization checks pass).
    /// Shared between `dispatch` (legacy) and `dispatch_with_envelope`.
    fn dispatch_inner(
        &self,
        request: &SignedUnwrapRequest,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        let mut shares: Vec<ServerUnwrapShare> = Vec::new();
        let r_point = decompress_point(&request.ephemeral_r)?;
        self.check_and_record_nonce(request)?;

        for server in &self.servers {
            match server.behavior {
                MockServerBehavior::Offline => continue,
                MockServerBehavior::Honest => {
                    verify_signed_unwrap_request(request)?;
                    let partial = (server.share * r_point).compress().to_bytes();
                    shares.push(ServerUnwrapShare {
                        witness_index: server.witness_index,
                        partial,
                    });
                }
                MockServerBehavior::Tampered => {
                    verify_signed_unwrap_request(request)?;
                    let wrong_k = Scalar::from(0xDEAD_BEEFu64);
                    let partial = (wrong_k * r_point).compress().to_bytes();
                    shares.push(ServerUnwrapShare {
                        witness_index: server.witness_index,
                        partial,
                    });
                }
                MockServerBehavior::IgnoreSignature => {
                    let partial = (server.share * r_point).compress().to_bytes();
                    shares.push(ServerUnwrapShare {
                        witness_index: server.witness_index,
                        partial,
                    });
                }
            }
        }

        Ok(shares)
    }
}

impl UnwrapTransport for MockUnwrapTransport {
    fn dispatch(
        &self,
        request: &SignedUnwrapRequest,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        // ADR-008 путь приоритетен: если зарегистрированы device_entries или
        // identity_rotation — применяем полные SPEC-12 §A.11 проверки. Для
        // legacy dispatch envelope_timestamp считается «открытым» (u64::MAX)
        // чтобы history_cutoff не блокировал — вызывающий должен использовать
        // `dispatch_with_envelope` для явного cutoff enforcement.
        //
        // ADR-008 path has priority: if device_entries or identity_rotation
        // are registered, apply the full SPEC-12 §A.11 checks. For the
        // legacy dispatch, envelope_timestamp is treated as "open" (u64::MAX)
        // so that history_cutoff does not block — callers should use
        // `dispatch_with_envelope` for explicit cutoff enforcement.
        if !self.device_entries.is_empty() || self.identity_rotation.is_some() {
            self.check_authorization_state(request, u64::MAX)?;
        } else if !self.authorized_device_pubkeys.is_empty()
            && !self
                .authorized_device_pubkeys
                .contains(&request.device_pubkey)
        {
            return Err(BackupError::CryptoVerificationFailed);
        }

        self.dispatch_inner(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};

    use crate::cloud_wrap::params::{
        ThresholdConfig, WrappingParams, DEFAULT_TOTAL, POINT_LEN, PROTOCOL_VERSION,
    };
    use crate::cloud_wrap::signed_request::{
        seal_unwrap_request, TestingAttestationProvider, DEVICE_SIG_LEN, NONCE_LEN,
    };
    use crate::cloud_wrap::threshold::shamir_split_for_testing;
    use crate::cloud_wrap::unwrap::unwrap_message_key;
    use crate::cloud_wrap::wire::{CanonicalAad, ED25519_PUB_LEN};
    use crate::cloud_wrap::wrap::wrap_message_key;

    fn make_request(
        sk: &SigningKey,
        vk_bytes: [u8; 32],
        r: [u8; POINT_LEN],
    ) -> SignedUnwrapRequest {
        let mut n = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        let p = TestingAttestationProvider::default();
        seal_unwrap_request(
            r,
            [0x33u8; 32],
            [0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000u64,
            n,
            &p,
            |payload| Ok(sk.sign(payload).to_bytes()),
            vk_bytes,
        )
        .unwrap()
    }

    fn make_device_keypair() -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    fn _make_signature(sk: &SigningKey, msg: &[u8]) -> [u8; DEVICE_SIG_LEN] {
        sk.sign(msg).to_bytes()
    }

    #[test]
    fn mock_sealed_server_debug_redacts_secret_share_scalar() {
        let server = MockSealedServer {
            witness_index: WitnessIndex::new(2).unwrap(),
            share: Scalar::from(77u64),
            behavior: MockServerBehavior::Honest,
        };

        let debug = format!("{server:?}");

        assert!(
            debug.contains("share_redacted"),
            "Debug output must explicitly redact mock server secret share: {debug}"
        );
        assert!(
            !debug.contains("share:"),
            "Debug output must not print the raw secret share field: {debug}"
        );
    }

    #[test]
    fn mock_transport_debug_redacts_authorization_state() {
        let server = MockSealedServer {
            witness_index: WitnessIndex::new(2).unwrap(),
            share: Scalar::from(77u64),
            behavior: MockServerBehavior::Honest,
        };
        let mut transport = MockUnwrapTransport::new(vec![server]);
        transport.authorize_device([0x42; DEVICE_PUBKEY_LEN]);
        transport.register_device_entry(
            [0x43; DEVICE_PUBKEY_LEN],
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1_700_000_000_000,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x44; DEVICE_PUBKEY_LEN],
            },
        );

        let debug = format!("{transport:?}");

        for forbidden in [
            "authorized_device_pubkeys: {",
            "device_entries: {",
            "used_server_nonces: Mutex",
            "66, 66",
            "67, 67",
            "68, 68",
        ] {
            assert!(
                !debug.contains(forbidden),
                "Debug output must not leak mock transport authorization state `{forbidden}`: {debug}"
            );
        }
        assert!(
            debug.contains("authorized_device_pubkeys_len")
                && debug.contains("device_entries_len")
                && debug.contains("used_server_nonces_len")
                && debug.contains("identity_rotation_present"),
            "Debug output should keep safe state counts: {debug}"
        );
    }

    #[test]
    fn mock_transport_honest_cluster_returns_five_shares() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);

        let servers: Vec<MockSealedServer> = shares
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        let transport = MockUnwrapTransport::new(servers);

        let (sk, vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());

        let collected = transport.dispatch(&req).unwrap();
        assert_eq!(collected.len(), 5);
    }

    #[test]
    fn mock_transport_rejects_replayed_server_nonce() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);

        let servers: Vec<MockSealedServer> = shares
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        let transport = MockUnwrapTransport::new(servers);

        let (sk, vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());

        let first = transport.dispatch(&req).unwrap();
        assert_eq!(first.len(), 5);

        let replay = transport.dispatch(&req).unwrap_err();
        assert!(
            matches!(replay, BackupError::CryptoVerificationFailed),
            "replayed SignedUnwrapRequest nonce must be refused, got {replay:?}"
        );
    }

    #[test]
    fn mock_transport_respects_offline_behavior() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);

        let servers: Vec<MockSealedServer> = shares
            .iter()
            .enumerate()
            .map(|(i, (wi, ki))| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: if i < 2 {
                    MockServerBehavior::Offline
                } else {
                    MockServerBehavior::Honest
                },
            })
            .collect();
        let transport = MockUnwrapTransport::new(servers);

        let (sk, vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let collected = transport.dispatch(&req).unwrap();
        assert_eq!(collected.len(), 3);
    }

    #[test]
    fn mock_transport_enforces_authorization_when_configured() {
        let (sk, vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());

        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        let servers: Vec<MockSealedServer> = shares
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        let mut transport = MockUnwrapTransport::new(servers);
        // Authorize a DIFFERENT pubkey.
        transport.authorize_device([0xDEu8; 32]);

        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn mock_transport_end_to_end_unwrap_happy_path() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        let y = RISTRETTO_BASEPOINT_POINT * k;
        let params = WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
            config,
        };

        let aad = CanonicalAad {
            sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
            recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
            chat_id: [0x33u8; 32],
            msg_seq: 13,
        };
        let mk = [0x99u8; 32];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        // Cluster: 5 honest.
        let servers: Vec<MockSealedServer> = shares
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        let mut transport = MockUnwrapTransport::new(servers);

        let (sk, vk) = make_device_keypair();
        transport.authorize_device(vk);

        let req = make_request(&sk, vk, wrapped.ephemeral_r);
        let collected = transport.dispatch(&req).unwrap();
        assert_eq!(collected.len(), 5);

        // Переопределим aad.recipient_device_pubkey чтобы совпало с vk — иначе HKDF derive
        // по-другому, AEAD fail (это корректное поведение защиты, но для теста happy path
        // нам нужен consistent AAD + recipient).
        let aad_bound_to_device = CanonicalAad {
            sender_identity_pubkey: aad.sender_identity_pubkey,
            recipient_device_pubkey: aad.recipient_device_pubkey,
            chat_id: aad.chat_id,
            msg_seq: aad.msg_seq,
        };
        let recovered =
            unwrap_message_key(&params, &wrapped, &aad_bound_to_device, &collected).unwrap();
        assert_eq!(recovered, mk);
    }

    #[test]
    fn mock_transport_tampered_server_still_allows_unwrap() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        let y = RISTRETTO_BASEPOINT_POINT * k;
        let params = WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
            config,
        };
        let aad = CanonicalAad {
            sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
            recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
            chat_id: [0x33u8; 32],
            msg_seq: 1,
        };
        let mk = [0x55u8; 32];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let servers: Vec<MockSealedServer> = shares
            .iter()
            .enumerate()
            .map(|(i, (wi, ki))| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: if i == 1 {
                    MockServerBehavior::Tampered
                } else {
                    MockServerBehavior::Honest
                },
            })
            .collect();
        let mut transport = MockUnwrapTransport::new(servers);

        let (sk, vk) = make_device_keypair();
        transport.authorize_device(vk);

        let req = make_request(&sk, vk, wrapped.ephemeral_r);
        let collected = transport.dispatch(&req).unwrap();
        assert_eq!(collected.len(), 5);

        // unwrap_message_key делает retry на alternate subset → recovery OK.
        let recovered = unwrap_message_key(&params, &wrapped, &aad, &collected).unwrap();
        assert_eq!(recovered, mk);
    }

    // =====================================================================
    // ADR-008 (SPEC-12 §A.11) authorization state tests
    // =====================================================================

    use crate::cloud_wrap::identity_rotation::{seal_identity_rotation_record, RotationReason};

    fn build_honest_cluster() -> (Vec<MockSealedServer>, Scalar) {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares = shamir_split_for_testing(k, config, &mut OsRng);
        let servers: Vec<MockSealedServer> = shares
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        (servers, k)
    }

    fn sign_id(
        sk: &SigningKey,
    ) -> impl FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError> + '_ {
        move |m: &[u8]| Ok(sk.sign(m).to_bytes())
    }

    #[test]
    fn adr008_pending_device_rejected() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Pending,
                authorized_since: 0,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::DevicePendingAuthorization));
    }

    #[test]
    fn adr008_revoked_device_rejected() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Revoked,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::DeviceRevoked));
    }

    #[test]
    fn adr008_active_device_accepted() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let shares = transport.dispatch(&req).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_bootstrap_active_device_accepted() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::BootstrapActive,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let shares = transport.dispatch(&req).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_authorized_since_future_rejected() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        // request.timestamp = 1_700_000_000_000 по make_request, authorized_since дальше.
        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 2_000_000_000_000u64,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn adr008_history_cutoff_blocks_older_envelope() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 1_500_000_000_000u64,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let old_envelope_ts = 1_000_000_000_000u64; // < cutoff
        let err = transport
            .dispatch_with_envelope(&req, old_envelope_ts)
            .unwrap_err();
        assert!(matches!(
            err,
            BackupError::HistoryCutoffApplies {
                envelope_timestamp: 1_000_000_000_000u64,
                cutoff: 1_500_000_000_000u64,
            }
        ));
    }

    #[test]
    fn adr008_history_cutoff_allows_newer_envelope() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 1_500_000_000_000u64,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let new_envelope_ts = 2_000_000_000_000u64; // >= cutoff
        let shares = transport
            .dispatch_with_envelope(&req, new_envelope_ts)
            .unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_history_cutoff_zero_accepts_any_envelope() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 0, // all accepted
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let shares = transport.dispatch_with_envelope(&req, 0).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_history_cutoff_exact_boundary_accepted() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        let cutoff = 1_500_000_000_000u64;
        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: cutoff,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        // envelope_timestamp == cutoff → accepted (≥ условие).
        let shares = transport.dispatch_with_envelope(&req, cutoff).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_history_cutoff_max_rejects_all_envelopes() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: u64::MAX,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        // Любой envelope < u64::MAX → reject.
        let err = transport
            .dispatch_with_envelope(&req, u64::MAX - 1)
            .unwrap_err();
        assert!(matches!(err, BackupError::HistoryCutoffApplies { .. }));
    }

    #[test]
    fn adr008_identity_rotation_refuses_old_identity_requests() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        let (old_id_sk, old_id_vk) = make_device_keypair();
        let (new_id_sk, new_id_vk) = make_device_keypair();

        // Device originally published under old identity.
        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: old_id_vk,
            },
        );
        let rotation = seal_identity_rotation_record(
            old_id_vk,
            new_id_vk,
            2_000_000_000_000u64,
            RotationReason::PlannedRotation,
            sign_id(&old_id_sk),
            sign_id(&new_id_sk),
        )
        .unwrap();
        transport.set_identity_rotation(rotation);

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::IdentityRotatedRefuseOldRequests));
    }

    #[test]
    fn adr008_identity_rotation_accepts_new_identity_requests() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        let (old_id_sk, old_id_vk) = make_device_keypair();
        let (new_id_sk, new_id_vk) = make_device_keypair();

        // Device published under NEW identity after rotation. authorized_since
        // set before request timestamp (1_700_000_000_000 в make_request).
        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::BootstrapActive,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: new_id_vk,
            },
        );
        let rotation = seal_identity_rotation_record(
            old_id_vk,
            new_id_vk,
            2_000_000_000_000u64,
            RotationReason::CatastrophicRecovery,
            sign_id(&old_id_sk),
            sign_id(&new_id_sk),
        )
        .unwrap();
        transport.set_identity_rotation(rotation);

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let shares = transport.dispatch(&req).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn adr008_state_check_precedes_signature_verify() {
        // Revoked state должна отвергать **до** signature check: даже если
        // подпись идеальна, revoked = no shares.
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        let (sk, vk) = make_device_keypair();

        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Revoked,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        // Even with correct signature, revoked state blocks.
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::DeviceRevoked));
    }

    #[test]
    fn legacy_unknown_device_rejected_by_allowlist_when_adr008_state_absent() {
        // device_entries пустой, authorized_device_pubkeys содержит ДРУГОЙ pubkey —
        // legacy path должен вернуть CryptoVerificationFailed.
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);
        transport.authorize_device([0x42u8; 32]);

        let (sk, vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&sk, vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn adr008_unknown_device_rejected_when_device_entries_enabled() {
        let (servers, _k) = build_honest_cluster();
        let mut transport = MockUnwrapTransport::new(servers);

        let (_known_sk, known_vk) = make_device_keypair();
        transport.register_device_entry(
            known_vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let (unknown_sk, unknown_vk) = make_device_keypair();
        let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let req = make_request(&unknown_sk, unknown_vk, r_point.compress().to_bytes());
        let err = transport.dispatch(&req).unwrap_err();

        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn adr008_dispatch_with_envelope_full_happy_path() {
        let config = ThresholdConfig::default();
        let k = Scalar::random(&mut OsRng);
        let shares_raw = shamir_split_for_testing(k, config, &mut OsRng);
        let y = RISTRETTO_BASEPOINT_POINT * k;
        let params = WrappingParams {
            version: PROTOCOL_VERSION,
            main_pubkey: y.compress().to_bytes(),
            server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
            config,
        };

        let (sk, vk) = make_device_keypair();
        let aad = CanonicalAad {
            sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
            recipient_device_pubkey: vk,
            chat_id: [0x33u8; 32],
            msg_seq: 42,
        };
        let mk = [0xAAu8; 32];
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

        let servers: Vec<MockSealedServer> = shares_raw
            .iter()
            .map(|(wi, ki)| MockSealedServer {
                witness_index: *wi,
                share: *ki,
                behavior: MockServerBehavior::Honest,
            })
            .collect();
        let mut transport = MockUnwrapTransport::new(servers);
        transport.register_device_entry(
            vk,
            DeviceEntryState {
                flag: DeviceEntryStateFlag::Active,
                authorized_since: 1,
                history_cutoff: 0,
                identity_pubkey_at_publish: [0x11u8; 32],
            },
        );

        let req = make_request(&sk, vk, wrapped.ephemeral_r);
        let collected = transport
            .dispatch_with_envelope(&req, 1_700_000_000_000u64)
            .unwrap();
        assert_eq!(collected.len(), 5);

        let recovered = unwrap_message_key(&params, &wrapped, &aad, &collected).unwrap();
        assert_eq!(recovered, mk);
    }
}
