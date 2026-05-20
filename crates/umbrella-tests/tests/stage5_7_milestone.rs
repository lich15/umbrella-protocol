#![allow(deprecated)] // Round-6: test exercises legacy IdentitySeed::generate; production uses bootstrap_account
//! Integration milestone Этапа 5.7 — сквозные сценарии ADR-008:
//! полный lifecycle нового устройства (pending → approval → active → unwrap),
//! catastrophic recovery через 24 + 12 слов, отказ revoked устройства,
//! history_cutoff enforcement.
//!
//! Integration milestone for Stage 5.7 — end-to-end ADR-008 scenarios:
//! full new-device lifecycle (pending → approval → active → unwrap),
//! catastrophic recovery via 24 + 12 words, revoked-device denial,
//! history_cutoff enforcement.
//!
//! Источник правды: SPEC-12 §A.9.7 Integration (в 5.7 milestone) + SPEC-11 §4
//! state machine pending→active→revoked + SPEC-09 §7.2 cross-entry rules +
//! ADR-008 §2,§3,§4.
//!
//! Source of truth: SPEC-12 §A.9.7 Integration (in 5.7 milestone) + SPEC-11 §4
//! state machine pending→active→revoked + SPEC-09 §7.2 cross-entry rules +
//! ADR-008 §2,§3,§4.
//!
//! Каждый `#[test]` замыкает один из четырёх обязательных сценариев §A.9.7.
//! Сценарии используют honest cluster из пяти mock Sealed Servers, real
//! Shamir 3-of-5 split, и полный wire-format ADR-008 через single source of
//! truth `umbrella-backup::cloud_wrap` (Вариант A, см. SPEC-12 §A.13).
//!
//! Each `#[test]` covers one of the four mandatory scenarios in §A.9.7.
//! Scenarios use an honest five-member mock Sealed Server cluster, a real
//! Shamir 3-of-5 split, and the full ADR-008 wire format through the single
//! source of truth `umbrella-backup::cloud_wrap` (Variant A, see SPEC-12 §A.13).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::signed_request::{
    seal_unwrap_request, verify_signed_unwrap_request, SignedUnwrapRequest,
    TestingAttestationProvider,
};
use umbrella_backup::cloud_wrap::threshold::shamir_split_for_testing;
use umbrella_backup::cloud_wrap::{
    seal_device_authorization_approval, seal_device_authorization_revocation,
    seal_identity_rotation_record, unwrap_message_key, wrap_message_key, CanonicalAad,
    DeviceEntryState, DeviceEntryStateFlag, MockSealedServer, MockServerBehavior,
    MockUnwrapTransport, RotationReason, ThresholdConfig, UnwrapTransport, WitnessIndex,
    WrappedKey, WrappingParams, DEFAULT_TOTAL, ED25519_PUB_LEN, MESSAGE_KEY_LEN, POINT_LEN,
    PROTOCOL_VERSION, UNWRAP_NONCE_LEN,
};
use umbrella_backup::BackupError;

use umbrella_identity::{
    code_recovery::{derive_rotated_identity_material, CodeRecoveryMnemonic},
    IdentityKey, IdentitySeed, MnemonicLanguage,
};

use umbrella_kt::merkle::NODE_HASH_LEN;
use umbrella_kt::witness::{canonical_sign_payload, WitnessPublic, WitnessSet, WitnessSignature};
use umbrella_kt::{
    apply_authorization_approval, apply_authorization_revocation, apply_identity_rotation,
    lookup_device_entry, KtLogState, SignedEpochRoot,
};

use umbrella_crypto_primitives::sig::PrivateSigningKey;

// ============================================================================
// Константы тестового окружения / Test-environment constants
// ============================================================================

/// Порог multi-witness подписей (SPEC-09 §3). Threshold for multi-witness signatures.
const WITNESS_THRESHOLD: usize = 3;

/// Базовая эпоха KT для сценариев (monotonic, increments per apply).
/// Baseline KT epoch for scenarios (monotonic, increments per apply).
const EPOCH_BASELINE: u64 = 100;

/// Базовый unix-millis timestamp. Baseline unix-millis timestamp.
const TIMESTAMP_BASELINE: u64 = 1_700_000_000_000;

/// Длина Ed25519-подписи, используемая в `seal_*` closure'ах.
/// Ed25519 signature length used by `seal_*` closures.
const SIG_LEN: usize = 64;

// ============================================================================
// Witness helpers — mirror of umbrella-kt::authorization_entries::tests TestEnv
// ============================================================================

/// Один mock witness: приватный ключ + публичный идентификатор.
/// One mock witness: private key + public identifier.
struct Witness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

/// Сгенерировать новый witness на случайном ключе.
/// Generate a fresh witness with a random key.
fn gen_witness() -> Witness {
    let sk = PrivateSigningKey::generate(&mut OsRng);
    let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
    Witness { sk, pk }
}

/// Собрать [`WitnessSet`] из набора witness'ов.
/// Build a [`WitnessSet`] from a set of witnesses.
fn build_witness_set(ws: &[&Witness]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for w in ws {
        set.add(w.pk);
    }
    set
}

/// Подписать `epoch, root` каждым из переданных witness'ов и вернуть
/// `SignedEpochRoot` — ровно как в production KT log-service.
///
/// Sign `epoch, root` by each of the supplied witnesses and return a
/// `SignedEpochRoot` — exactly as the production KT log service does.
fn sign_epoch_root(
    witnesses: &[&Witness],
    epoch: u64,
    root: &[u8; NODE_HASH_LEN],
) -> SignedEpochRoot {
    let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
    let signatures: Vec<WitnessSignature> = witnesses
        .iter()
        .map(|w| WitnessSignature {
            witness: w.pk,
            signature: w.sk.sign(&payload).to_bytes(),
        })
        .collect();
    SignedEpochRoot {
        epoch,
        root: *root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures,
    }
}

/// Минимальное KT-окружение для тестов: 5 witness'ов + готовый
/// [`WitnessSet`]; повторяет `TestEnv` из unit-тестов `umbrella-kt`.
///
/// Minimal KT test environment: 5 witnesses + ready-made [`WitnessSet`];
/// mirrors `TestEnv` from `umbrella-kt` unit tests.
struct MiniKt {
    witnesses: Vec<Witness>,
    set: WitnessSet,
}

impl MiniKt {
    fn fresh() -> Self {
        let witnesses: Vec<Witness> = (0..5).map(|_| gen_witness()).collect();
        let set = build_witness_set(&witnesses.iter().collect::<Vec<_>>());
        Self { witnesses, set }
    }

    /// Собрать `SignedEpochRoot` от первых трёх witness'ов (threshold = 3).
    /// Build a `SignedEpochRoot` from the first three witnesses (threshold = 3).
    fn signed_epoch(&self, epoch: u64, root: &[u8; NODE_HASH_LEN]) -> SignedEpochRoot {
        let refs: Vec<&Witness> = self.witnesses.iter().take(WITNESS_THRESHOLD).collect();
        sign_epoch_root(&refs, epoch, root)
    }
}

/// 32-байтовый random root для тестов.
/// 32-byte random root for tests.
fn random_root() -> [u8; NODE_HASH_LEN] {
    let mut out = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut out);
    out
}

// ============================================================================
// Crypto helpers — device-keys, wrap-params, закрытые мелочи
// ============================================================================

/// Сгенерировать Ed25519 keypair и вернуть (sk, pubkey_bytes).
/// Generate an Ed25519 keypair and return (sk, pubkey_bytes).
fn gen_keypair() -> (PrivateSigningKey, [u8; ED25519_PUB_LEN]) {
    let sk = PrivateSigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Closure-сигнер для `seal_*` функций ADR-008.
/// Closure signer for ADR-008 `seal_*` functions.
fn sign_with(
    sk: &PrivateSigningKey,
) -> impl FnOnce(&[u8]) -> Result<[u8; SIG_LEN], BackupError> + '_ {
    move |message: &[u8]| Ok(sk.sign(message).to_bytes())
}

/// Случайный 32-байтовый chat-id.
/// Random 32-byte chat-id.
fn sample_chat_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    id
}

/// Случайный одноразовый AEAD message key (32 байта).
/// Random one-time AEAD message key (32 bytes).
fn sample_message_key() -> [u8; MESSAGE_KEY_LEN] {
    let mut mk = [0u8; MESSAGE_KEY_LEN];
    OsRng.fill_bytes(&mut mk);
    mk
}

/// Серверный nonce (freshness proof) для SignedUnwrapRequest.
/// Server nonce (freshness proof) for SignedUnwrapRequest.
fn sample_server_nonce() -> [u8; UNWRAP_NONCE_LEN] {
    let mut n = [0u8; UNWRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Собрать `WrappingParams` вокруг случайного главного scalar `K` и вернуть
/// 5-of-5 Shamir shares для настройки mock Sealed Servers. Структурно
/// идентичен helper'у из `stage5_milestone.rs`.
///
/// Build `WrappingParams` around a random master scalar `K` and return the
/// 5-of-5 Shamir shares used to configure mock Sealed Servers. Structurally
/// identical to the helper in `stage5_milestone.rs`.
fn setup_wrapping_params(config: ThresholdConfig) -> (WrappingParams, Vec<(WitnessIndex, Scalar)>) {
    let k = Scalar::random(&mut OsRng);
    let shares = shamir_split_for_testing(k, config, &mut OsRng);
    let y = RISTRETTO_BASEPOINT_POINT * k;
    let mut server_pubkeys = [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize];
    for (wi, k_i) in shares.iter() {
        let yi = RISTRETTO_BASEPOINT_POINT * *k_i;
        server_pubkeys[(wi.get() - 1) as usize] = yi.compress().to_bytes();
    }
    let params = WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys,
        config,
    };
    (params, shares.iter().copied().collect())
}

/// Построить honest кластер из пяти mock Sealed Servers по выданным shares.
/// Build an honest cluster of five mock Sealed Servers from the given shares.
fn honest_cluster(shares: &[(WitnessIndex, Scalar)]) -> MockUnwrapTransport {
    let servers: Vec<MockSealedServer> = shares
        .iter()
        .map(|(wi, ki)| MockSealedServer {
            witness_index: *wi,
            share: *ki,
            behavior: MockServerBehavior::Honest,
        })
        .collect();
    MockUnwrapTransport::new(servers)
}

/// Собрать `SignedUnwrapRequest` под заданный device-sk + wrapped envelope.
/// Используется во всех сценариях — одинаковая форма request'а.
///
/// Build a `SignedUnwrapRequest` for the given device-sk + wrapped envelope.
/// Used across all scenarios — the request shape is identical.
fn seal_unwrap_req(
    device_sk: &PrivateSigningKey,
    device_vk: [u8; ED25519_PUB_LEN],
    wrapped: &WrappedKey,
    chat_id: [u8; 32],
    recipient_device_pubkey: [u8; ED25519_PUB_LEN],
    timestamp_unix_millis: u64,
) -> SignedUnwrapRequest {
    let provider = TestingAttestationProvider::default();
    seal_unwrap_request(
        wrapped.ephemeral_r,
        chat_id,
        recipient_device_pubkey,
        timestamp_unix_millis,
        sample_server_nonce(),
        &provider,
        |payload| Ok(device_sk.sign(payload).to_bytes()),
        device_vk,
    )
    .expect("seal_unwrap_request happy path")
}

// ============================================================================
// Сценарий 1 / Scenario 1 — полный lifecycle нового устройства
// ============================================================================

/// Сценарий 1 (SPEC-12 §A.9.7 «полный lifecycle нового устройства»):
/// новое устройство публикует свой device-key в KT с флагом `pending`,
/// existing active approver подписывает `DeviceAuthorizationApproval`,
/// `apply_authorization_approval` переводит entry в `Active`,
/// `SignedUnwrapRequest` от нового устройства принимается Sealed Servers и
/// возвращает shares → `unwrap_message_key` восстанавливает исходный AEAD-key.
///
/// Scenario 1 (SPEC-12 §A.9.7 "full new-device lifecycle"): a new device
/// publishes its device-key in KT with the `pending` flag, an existing
/// active approver signs a `DeviceAuthorizationApproval`,
/// `apply_authorization_approval` transitions the entry to `Active`,
/// `SignedUnwrapRequest` from the new device is accepted by Sealed Servers
/// and returns shares → `unwrap_message_key` recovers the original AEAD key.
#[test]
fn scenario_1_full_lifecycle_new_device() {
    let env = MiniKt::fresh();
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    // Existing identity ID_A + primary active device under the same identity.
    let (_id_a_sk, id_a_pk) = gen_keypair();
    let (primary_sk, primary_pk) = gen_keypair();
    let (new_sk, new_pk) = gen_keypair();

    let mut log = KtLogState::with_identity(id_a_pk);
    log.register_bootstrap_active(primary_pk, TIMESTAMP_BASELINE, id_a_pk)
        .expect("bootstrap primary");
    log.register_pending(new_pk, id_a_pk)
        .expect("register pending new device");

    // Sanity: entry в состоянии Pending до approval.
    assert_eq!(
        lookup_device_entry(&log, &new_pk).unwrap().flag(),
        DeviceEntryStateFlag::Pending
    );

    // Primary подписывает approval с history_cutoff = 0 (полный доступ).
    let approval = seal_device_authorization_approval(
        new_pk,
        primary_pk,
        TIMESTAMP_BASELINE + 10,
        0,
        0,
        sign_with(&primary_sk),
    )
    .expect("seal approval");
    let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
    apply_authorization_approval(&approval, &mut log, &env.set, &signed0, WITNESS_THRESHOLD)
        .expect("apply approval");

    // Entry перешёл в Active с authorized_since и history_cutoff из approval.
    let entry = lookup_device_entry(&log, &new_pk).expect("entry after approval");
    assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
    assert_eq!(entry.authorized_since(), TIMESTAMP_BASELINE + 10);
    assert_eq!(entry.history_cutoff(), 0);
    assert_eq!(entry.identity_pubkey_at_publish(), &id_a_pk);

    // Sealed Server cluster mirror-ит entry и принимает unwrap request.
    let mut transport = honest_cluster(&shares);
    transport.register_device_entry(
        new_pk,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Active,
            authorized_since: TIMESTAMP_BASELINE + 10,
            history_cutoff: 0,
            identity_pubkey_at_publish: id_a_pk,
        },
    );

    // Отправитель wrap'ает message key под aad bound к new device.
    let chat_id = sample_chat_id();
    let aad = CanonicalAad {
        sender_identity_pubkey: id_a_pk,
        recipient_device_pubkey: new_pk,
        chat_id,
        msg_seq: 42,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).expect("wrap happy path");

    // New device signs unwrap request, dispatches with envelope_ts.
    let req = seal_unwrap_req(
        &new_sk,
        new_pk,
        &wrapped,
        chat_id,
        new_pk,
        TIMESTAMP_BASELINE + 100,
    );
    verify_signed_unwrap_request(&req).expect("request signature valid");

    let envelope_ts = TIMESTAMP_BASELINE + 50;
    let collected = transport
        .dispatch_with_envelope(&req, envelope_ts)
        .expect("dispatch honest cluster");
    assert_eq!(collected.len(), DEFAULT_TOTAL as usize);

    // Full unwrap — message key восстановлен бит-в-бит.
    let recovered = unwrap_message_key(&params, &wrapped, &aad, &collected).expect("unwrap");
    assert_eq!(recovered, mk, "recovered key must equal original");
}

// ============================================================================
// Сценарий 2 / Scenario 2 — catastrophic recovery через 24 + 12 слов
// ============================================================================

/// Сценарий 2 (SPEC-12 §A.9.7 «catastrophic recovery»):
/// пользователь потерял все устройства. На чистом устройстве вводит 24 слова
/// identity seed и 12 слов кода восстановления; `derive_rotated_identity_material`
/// HKDF-производит новый identity-seed; публикуется `IdentityRotationRecord`
/// с reason `CatastrophicRecovery`; `apply_identity_rotation` cascade-revokes
/// старые устройства; `register_bootstrap_active` под новым identity
/// принимается (catastrophic-recovery bootstrap pattern, SPEC-11 §4.8);
/// `SignedUnwrapRequest` от нового устройства под новым identity принимается
/// Sealed Servers (identity-chain check проходит по `new_identity_pubkey`).
///
/// Scenario 2 (SPEC-12 §A.9.7 "catastrophic recovery"): the user lost every
/// device. On a clean device they enter the 24-word identity seed and the
/// 12-word recovery code; `derive_rotated_identity_material` HKDF-derives a
/// new identity-seed; an `IdentityRotationRecord` with reason
/// `CatastrophicRecovery` is published; `apply_identity_rotation`
/// cascade-revokes old devices; `register_bootstrap_active` under the new
/// identity succeeds (catastrophic-recovery bootstrap pattern, SPEC-11 §4.8);
/// `SignedUnwrapRequest` from the new device under the new identity is
/// accepted by Sealed Servers (identity-chain check passes by
/// `new_identity_pubkey`).
#[test]
fn scenario_2_catastrophic_recovery_flow() {
    let env = MiniKt::fresh();
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    // Шаг 1: исходный identity из 24 слов + код восстановления из 12 слов.
    // Step 1: original identity from 24 words + recovery code from 12 words.
    let seed_24 = IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English);
    let code_12 = CodeRecoveryMnemonic::generate(&mut OsRng, MnemonicLanguage::English);
    let original_id_key = IdentityKey::derive(&seed_24, 0).expect("derive identity");
    let original_id_pubkey = original_id_key.public().to_bytes();

    // Шаг 2: HKDF-derive rotated material — sanity что новый identity отличается.
    // Полная verification детерминизма покрыта unit-тестами
    // `code_recovery::full_catastrophic_recovery_flow`.
    //
    // Step 2: HKDF-derive rotated material — sanity that the new identity
    // differs. Full determinism verification is covered by the unit test
    // `code_recovery::full_catastrophic_recovery_flow`.
    let rotated = derive_rotated_identity_material(&seed_24, &code_12, &original_id_key.public())
        .expect("catastrophic rotation derive");
    let rotated_pubkey_bytes = rotated
        .identity_pubkey(0)
        .expect("rotated identity pubkey")
        .to_bytes();
    assert_ne!(
        rotated_pubkey_bytes, original_id_pubkey,
        "rotated identity must differ from original (HKDF pre-image resistance)"
    );

    // Шаг 3: IdentityKey::sign — pub(crate), недоступно из umbrella-tests. Для
    // подписи rotation record поднимаем raw PrivateSigningKey для старого и
    // нового identity — wire-format проверяет лишь совпадение подписи с
    // заявленным pubkey. Rotated material выше служит sanity-check полного
    // derivation-pipeline; wire integrity rotation record не зависит от
    // конкретного HKDF derivation пути.
    //
    // Step 3: `IdentityKey::sign` is pub(crate), inaccessible from
    // umbrella-tests. To sign the rotation record we raise raw
    // PrivateSigningKey pairs for the old and new identities — the wire
    // format only cross-checks signature against the declared pubkey. The
    // rotated material above serves as a sanity check of the full derivation
    // pipeline; rotation-record wire integrity does not depend on the
    // specific HKDF derivation path.
    let (old_id_sk, old_id_pk) = gen_keypair();
    let (new_id_sk, new_id_pk) = gen_keypair();

    // Шаг 4: log mirror с текущим identity = old + одно legacy bootstrap device.
    // Step 4: log mirror with current identity = old + one legacy bootstrap device.
    let (_legacy_dev_sk, legacy_dev_pk) = gen_keypair();
    let mut log = KtLogState::with_identity(old_id_pk);
    log.register_bootstrap_active(legacy_dev_pk, TIMESTAMP_BASELINE, old_id_pk)
        .expect("bootstrap legacy device");

    // Шаг 5: seal_identity_rotation_record с reason = CatastrophicRecovery.
    // Step 5: seal_identity_rotation_record with reason = CatastrophicRecovery.
    let rotation_ts = TIMESTAMP_BASELINE + 100;
    // F-PHD-RETRO-3-E: rotation requires 12-words knowledge через
    // code_recovery_public_half_proof. Тест simulates valid rotation
    // путём passing того же proof который был бы stored при bootstrap.
    let rotation_proof = code_12.public_half_proof(0);
    let rotation = seal_identity_rotation_record(
        old_id_pk,
        new_id_pk,
        rotation_ts,
        RotationReason::CatastrophicRecovery,
        rotation_proof,
        sign_with(&old_id_sk),
        sign_with(&new_id_sk),
    )
    .expect("seal rotation");

    // Шаг 6: apply_identity_rotation — обновляет current_identity + cascade revoke.
    // Step 6: apply_identity_rotation — updates current_identity + cascade revoke.
    let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
    apply_identity_rotation(&rotation, &mut log, &env.set, &signed0, WITNESS_THRESHOLD)
        .expect("apply rotation");
    assert_eq!(log.current_identity_pubkey(), Some(&new_id_pk));
    assert_eq!(
        lookup_device_entry(&log, &legacy_dev_pk).unwrap().flag(),
        DeviceEntryStateFlag::Revoked,
        "legacy device under old identity must cascade-revoke"
    );
    assert!(
        log.identity_rotation().is_some(),
        "rotation must be remembered in mirror"
    );

    // Шаг 7: новое устройство под новым identity через bootstrap-active
    // (catastrophic-recovery bootstrap, SPEC-11 §4.8).
    //
    // Step 7: new device under the new identity via bootstrap-active
    // (catastrophic-recovery bootstrap, SPEC-11 §4.8).
    let (new_dev_sk, new_dev_pk) = gen_keypair();
    log.register_bootstrap_active(new_dev_pk, rotation_ts + 10, new_id_pk)
        .expect("bootstrap new device under new identity");
    assert_eq!(
        lookup_device_entry(&log, &new_dev_pk).unwrap().flag(),
        DeviceEntryStateFlag::BootstrapActive
    );

    // Шаг 8: MockUnwrapTransport mirror rotation + device-entry под новым identity.
    // Step 8: MockUnwrapTransport mirrors the rotation + device-entry under the new identity.
    let mut transport = honest_cluster(&shares);
    transport.set_identity_rotation(rotation.clone());
    transport.register_device_entry(
        new_dev_pk,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::BootstrapActive,
            authorized_since: rotation_ts + 10,
            history_cutoff: 0,
            identity_pubkey_at_publish: new_id_pk,
        },
    );

    // Шаг 9: wrap + unwrap под новым identity; envelope_ts > rotation_ts.
    // Step 9: wrap + unwrap under the new identity; envelope_ts > rotation_ts.
    let chat_id = sample_chat_id();
    let aad = CanonicalAad {
        sender_identity_pubkey: new_id_pk,
        recipient_device_pubkey: new_dev_pk,
        chat_id,
        msg_seq: 1,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).expect("wrap");

    let req = seal_unwrap_req(
        &new_dev_sk,
        new_dev_pk,
        &wrapped,
        chat_id,
        new_dev_pk,
        rotation_ts + 500,
    );
    let envelope_ts_post = rotation_ts + 200;
    let collected = transport
        .dispatch_with_envelope(&req, envelope_ts_post)
        .expect("dispatch under new identity");
    assert_eq!(collected.len(), DEFAULT_TOTAL as usize);

    let recovered = unwrap_message_key(&params, &wrapped, &aad, &collected).expect("unwrap");
    assert_eq!(recovered, mk, "recovered key must equal original");
}

// ============================================================================
// Сценарий 3 / Scenario 3 — отказ revoked устройства
// ============================================================================

/// Сценарий 3 (SPEC-12 §A.9.7 «отказ revoked устройства»):
/// existing admin device публикует `DeviceAuthorizationRevocation` для одного
/// из active устройств; `apply_authorization_revocation` переводит entry в
/// `Revoked`; `MockUnwrapTransport.dispatch` отвергает revoked device раньше
/// signature-verify с `BackupError::DeviceRevoked` (SPEC-12 §A.11.1).
///
/// Scenario 3 (SPEC-12 §A.9.7 "revoked-device denial"): an existing admin
/// device publishes a `DeviceAuthorizationRevocation` for one of the active
/// devices; `apply_authorization_revocation` transitions the entry to
/// `Revoked`; `MockUnwrapTransport.dispatch` rejects the revoked device
/// before signature-verify with `BackupError::DeviceRevoked` (SPEC-12 §A.11.1).
#[test]
fn scenario_3_revoked_device_denied() {
    let env = MiniKt::fresh();
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let (_id_sk, id_pk) = gen_keypair();
    let (primary_sk, primary_pk) = gen_keypair();
    let (laptop_sk, laptop_pk) = gen_keypair();

    let mut log = KtLogState::with_identity(id_pk);
    log.register_bootstrap_active(primary_pk, TIMESTAMP_BASELINE, id_pk)
        .expect("bootstrap primary");
    log.register_pending(laptop_pk, id_pk)
        .expect("register pending laptop");

    // Primary подтверждает laptop (previous session) → laptop = Active.
    let approval = seal_device_authorization_approval(
        laptop_pk,
        primary_pk,
        TIMESTAMP_BASELINE + 10,
        0,
        0,
        sign_with(&primary_sk),
    )
    .expect("seal approval");
    let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
    apply_authorization_approval(&approval, &mut log, &env.set, &signed0, WITNESS_THRESHOLD)
        .expect("apply approval");
    assert_eq!(
        lookup_device_entry(&log, &laptop_pk).unwrap().flag(),
        DeviceEntryStateFlag::Active
    );

    // Primary отзывает laptop через revocation.
    let revocation = seal_device_authorization_revocation(
        laptop_pk,
        primary_pk,
        TIMESTAMP_BASELINE + 20,
        sign_with(&primary_sk),
    )
    .expect("seal revocation");
    let signed1 = env.signed_epoch(EPOCH_BASELINE + 1, &random_root());
    apply_authorization_revocation(&revocation, &mut log, &env.set, &signed1, WITNESS_THRESHOLD)
        .expect("apply revocation");
    assert_eq!(
        lookup_device_entry(&log, &laptop_pk).unwrap().flag(),
        DeviceEntryStateFlag::Revoked
    );

    // Mock Sealed Server mirror-ит Revoked state.
    let mut transport = honest_cluster(&shares);
    transport.register_device_entry(
        laptop_pk,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Revoked,
            authorized_since: 0,
            history_cutoff: 0,
            identity_pubkey_at_publish: id_pk,
        },
    );

    // Revoked laptop пытается запросить shares (wrap используем просто чтобы
    // получить валидный ephemeral_r для SignedUnwrapRequest).
    //
    // Revoked laptop attempts to request shares (wrap only provides a valid
    // ephemeral_r for the SignedUnwrapRequest).
    let chat_id = sample_chat_id();
    let aad = CanonicalAad {
        sender_identity_pubkey: id_pk,
        recipient_device_pubkey: laptop_pk,
        chat_id,
        msg_seq: 7,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).expect("wrap");
    let req = seal_unwrap_req(
        &laptop_sk,
        laptop_pk,
        &wrapped,
        chat_id,
        laptop_pk,
        TIMESTAMP_BASELINE + 50,
    );

    // dispatch и dispatch_with_envelope оба возвращают DeviceRevoked.
    let err = transport.dispatch(&req).unwrap_err();
    assert!(
        matches!(err, BackupError::DeviceRevoked),
        "dispatch must reject revoked device: got {err:?}"
    );
    let err2 = transport
        .dispatch_with_envelope(&req, TIMESTAMP_BASELINE + 50)
        .unwrap_err();
    assert!(
        matches!(err2, BackupError::DeviceRevoked),
        "dispatch_with_envelope must reject revoked device: got {err2:?}"
    );
}

// ============================================================================
// Сценарий 4 / Scenario 4 — history_cutoff enforcement
// ============================================================================

/// Сценарий 4 (SPEC-12 §A.9.7 «history_cutoff enforcement»):
/// approver выдаёт approval с `history_cutoff_timestamp = T_CUT`;
/// `SignedUnwrapRequest` для envelope_ts < T_CUT отвергается с
/// `BackupError::HistoryCutoffApplies`; для envelope_ts ≥ T_CUT shares
/// выдаются (SPEC-12 §A.11.3).
///
/// Scenario 4 (SPEC-12 §A.9.7 "history_cutoff enforcement"): approver issues
/// an approval with `history_cutoff_timestamp = T_CUT`; a
/// `SignedUnwrapRequest` for envelope_ts < T_CUT is rejected with
/// `BackupError::HistoryCutoffApplies`; for envelope_ts ≥ T_CUT shares are
/// issued (SPEC-12 §A.11.3).
#[test]
fn scenario_4_history_cutoff_enforcement() {
    let env = MiniKt::fresh();
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let (_id_sk, id_pk) = gen_keypair();
    let (primary_sk, primary_pk) = gen_keypair();
    let (new_sk, new_pk) = gen_keypair();

    let mut log = KtLogState::with_identity(id_pk);
    log.register_bootstrap_active(primary_pk, TIMESTAMP_BASELINE, id_pk)
        .expect("bootstrap primary");
    log.register_pending(new_pk, id_pk)
        .expect("register pending new device");

    // Approval с history_cutoff = T_CUT. Все envelope < T_CUT будут отвергнуты.
    let cutoff: u64 = TIMESTAMP_BASELINE + 500;
    let approval = seal_device_authorization_approval(
        new_pk,
        primary_pk,
        TIMESTAMP_BASELINE + 10,
        cutoff,
        0,
        sign_with(&primary_sk),
    )
    .expect("seal approval with cutoff");
    let signed0 = env.signed_epoch(EPOCH_BASELINE, &random_root());
    apply_authorization_approval(&approval, &mut log, &env.set, &signed0, WITNESS_THRESHOLD)
        .expect("apply approval");
    let entry = lookup_device_entry(&log, &new_pk).expect("entry after approval");
    assert_eq!(entry.flag(), DeviceEntryStateFlag::Active);
    assert_eq!(entry.history_cutoff(), cutoff);

    // Sealed Server mirror-ит entry с cutoff.
    let mut transport = honest_cluster(&shares);
    transport.register_device_entry(
        new_pk,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Active,
            authorized_since: TIMESTAMP_BASELINE + 10,
            history_cutoff: cutoff,
            identity_pubkey_at_publish: id_pk,
        },
    );

    // Готовим два сообщения: одно «до cutoff», одно «после».
    // Prepare two messages: one "before cutoff", one "after".
    let chat_id = sample_chat_id();
    let aad_old = CanonicalAad {
        sender_identity_pubkey: id_pk,
        recipient_device_pubkey: new_pk,
        chat_id,
        msg_seq: 1,
    };
    let aad_new = CanonicalAad {
        sender_identity_pubkey: id_pk,
        recipient_device_pubkey: new_pk,
        chat_id,
        msg_seq: 2,
    };
    let mk_old = sample_message_key();
    let mk_new = sample_message_key();
    let wrapped_old = wrap_message_key(&params, &mk_old, &aad_old, &mut OsRng).expect("wrap old");
    let wrapped_new = wrap_message_key(&params, &mk_new, &aad_new, &mut OsRng).expect("wrap new");

    let req_old = seal_unwrap_req(
        &new_sk,
        new_pk,
        &wrapped_old,
        chat_id,
        new_pk,
        TIMESTAMP_BASELINE + 100,
    );
    let req_new = seal_unwrap_req(
        &new_sk,
        new_pk,
        &wrapped_new,
        chat_id,
        new_pk,
        TIMESTAMP_BASELINE + 100,
    );

    // envelope_ts = cutoff - 1 → HistoryCutoffApplies.
    let old_envelope_ts = cutoff - 1;
    let err = transport
        .dispatch_with_envelope(&req_old, old_envelope_ts)
        .unwrap_err();
    match err {
        BackupError::HistoryCutoffApplies {
            envelope_timestamp,
            cutoff: c,
        } => {
            assert_eq!(envelope_timestamp, old_envelope_ts);
            assert_eq!(c, cutoff);
        }
        other => panic!("expected HistoryCutoffApplies, got {other:?}"),
    }

    // envelope_ts = cutoff → accepted (≥ условие, boundary).
    let collected_boundary = transport
        .dispatch_with_envelope(&req_new, cutoff)
        .expect("cutoff boundary accepted");
    assert_eq!(collected_boundary.len(), DEFAULT_TOTAL as usize);

    // envelope_ts = cutoff + 200 → accepted и полный unwrap. Use a fresh
    // SignedUnwrapRequest nonce: replaying `req_new` is correctly rejected.
    let req_new_future = seal_unwrap_req(
        &new_sk,
        new_pk,
        &wrapped_new,
        chat_id,
        new_pk,
        TIMESTAMP_BASELINE + 100,
    );
    let collected_future = transport
        .dispatch_with_envelope(&req_new_future, cutoff + 200)
        .expect("post-cutoff accepted");
    let recovered = unwrap_message_key(&params, &wrapped_new, &aad_new, &collected_future)
        .expect("unwrap post-cutoff");
    assert_eq!(recovered, mk_new);
}
