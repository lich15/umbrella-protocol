//! Integration milestone Этапа 5 — полный цикл восстановления в Cloud и
//! Secret режимах плюс шесть adversarial сценариев.
//!
//! Integration milestone for Stage 5 — full recovery cycle in Cloud and
//! Secret modes plus six adversarial scenarios.
//!
//! Сценарии:
//! 1. Cloud happy-path: чистое устройство → recovery identity через 24 слова →
//!    получение 100 wrapped сообщений → unwrap через 3 Sealed Servers →
//!    расшифровка совпадает с reference.
//! 2. Cloud отказоустойчивость: 2 Sealed Servers offline — восстановление работает.
//! 3. Cloud threshold-too-low: 3 Sealed Servers offline — InsufficientUnwrapShares.
//! 4. Cloud malicious 1 сервер: retry на alternate subset восстанавливает.
//! 5. Cloud malicious 3 сервера: AllSubsetsFailedUnwrap.
//! 6. Cloud authorization: запрос с unauthorized device отвергается mock transport.
//! 7. Secret happy-path: full Noise_IK + identity-binding + snapshot transfer
//!    (2 MLS groups, 50 entries local DB blob) между двумя устройствами одного
//!    аккаунта через mock KT.
//! 8. Secret expired QR: ensure_not_expired → QrExpired.
//! 9. Secret tampered QR signature: verify_identity → QrSignatureInvalid.
//! 10. Secret interrupted stream: truncated frame payload → StreamUnexpectedEof.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use umbrella_backup::cloud_wrap::aead::decompress_point;
use umbrella_backup::cloud_wrap::signed_request::{
    verify_signed_unwrap_request, TestingAttestationProvider,
};
use umbrella_backup::cloud_wrap::{
    threshold::shamir_split_for_testing, unwrap_message_key, unwrap_message_key_no_retry,
    wrap_message_key, CanonicalAad, MockSealedServer, MockServerBehavior, MockUnwrapTransport,
    ServerUnwrapShare, ThresholdConfig, UnwrapTransport, WitnessIndex, WrappedKey, WrappingParams,
    DEFAULT_TOTAL, ED25519_PUB_LEN, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION, UNWRAP_NONCE_LEN,
};
use umbrella_backup::device_transfer::identity_verify::{MockKtLookup, ACCOUNT_ID_LEN};
use umbrella_backup::device_transfer::qr::{DevicePairingQr, QR_PAYLOAD_LEN, QR_SIG_LEN};
use umbrella_backup::device_transfer::{
    PairingInitiator, PairingResponder, Snapshot, TransferSession, MLS_GROUP_ID_LEN,
    PAIRING_CHALLENGE_LEN, SNAPSHOT_VERSION,
};
use umbrella_backup::identity_adapters::{
    build_signed_qr_with_identity, seal_unwrap_request_with_keystore,
    sign_handshake_hash_with_identity, verify_remote_pairing, CHAT_ID_LEN,
};
use umbrella_backup::BackupError;

use umbrella_identity::{IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock};

// ================= Helpers =================

fn fresh_keystore() -> InMemoryKeyStore {
    let seed = IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English);
    InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock)).unwrap()
}

fn sample_chat_id() -> [u8; CHAT_ID_LEN] {
    let mut id = [0u8; CHAT_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

fn sample_message_key() -> [u8; MESSAGE_KEY_LEN] {
    let mut mk = [0u8; MESSAGE_KEY_LEN];
    OsRng.fill_bytes(&mut mk);
    mk
}

/// Построить `WrappingParams` вокруг случайного главного scalar K.
/// Возвращает также Shamir-shares для настройки mock Sealed Servers.
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

/// Прямой вызов mock'а: каждый сервер выдает partial k_i · R.
/// Эмулирует sealed-backup-svc в integration тестах без настоящей сети.
fn compute_partial_share(wi: WitnessIndex, k_i: Scalar, wrapped: &WrappedKey) -> ServerUnwrapShare {
    let r = decompress_point(&wrapped.ephemeral_r).unwrap();
    let partial = (k_i * r).compress().to_bytes();
    ServerUnwrapShare {
        witness_index: wi,
        partial,
    }
}

fn make_device_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

// ================= Cloud scenarios =================

#[test]
fn cloud_full_recovery_100_messages() {
    // Сценарий 1: Новое устройство после recovery identity получает 100
    // wrapped сообщений от mock message-svc, разворачивает все через
    // кооперацию 3 Sealed Servers, plaintext'ы совпадают с reference.
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    // Старое устройство (отправитель) wrap'ает 100 message keys.
    let chat_id = sample_chat_id();
    let sender_identity = [0x11u8; ED25519_PUB_LEN];
    let recipient_device = [0x22u8; ED25519_PUB_LEN];

    let mut reference_keys = Vec::with_capacity(100);
    let mut wrapped_queue = Vec::with_capacity(100);

    for seq in 0..100u64 {
        let mk = sample_message_key();
        let aad = CanonicalAad {
            sender_identity_pubkey: sender_identity,
            recipient_device_pubkey: recipient_device,
            chat_id,
            msg_seq: seq,
        };
        let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();
        reference_keys.push(mk);
        wrapped_queue.push((aad, wrapped));
    }

    // Новое устройство разворачивает каждое сообщение через 3 честных Sealed Servers.
    for (i, (aad, wrapped)) in wrapped_queue.iter().enumerate() {
        let server_shares: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, k_i)| compute_partial_share(*wi, *k_i, wrapped))
            .collect();
        let recovered = unwrap_message_key_no_retry(&params, wrapped, aad, &server_shares).unwrap();
        assert_eq!(
            recovered, reference_keys[i],
            "message {i} diverged from reference"
        );
    }
}

#[test]
fn cloud_survives_two_offline_servers() {
    // Сценарий 2: 2 Sealed Servers offline — остаются 3, recovery работает.
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let chat_id = sample_chat_id();
    let aad = CanonicalAad {
        sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
        recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
        chat_id,
        msg_seq: 7,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

    // Shares от серверов 3, 4, 5 (1 и 2 offline).
    let subset: Vec<ServerUnwrapShare> = shares
        .iter()
        .skip(2)
        .take(3)
        .map(|(wi, k_i)| compute_partial_share(*wi, *k_i, &wrapped))
        .collect();

    let recovered = unwrap_message_key(&params, &wrapped, &aad, &subset).unwrap();
    assert_eq!(recovered, mk);
}

#[test]
fn cloud_fails_when_three_offline() {
    // Сценарий 3: 3 Sealed Servers offline — остаются 2, threshold не достигнут.
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let aad = CanonicalAad {
        sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
        recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
        chat_id: sample_chat_id(),
        msg_seq: 1,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

    let subset: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(2)
        .map(|(wi, k_i)| compute_partial_share(*wi, *k_i, &wrapped))
        .collect();

    let err = unwrap_message_key(&params, &wrapped, &aad, &subset).unwrap_err();
    assert!(matches!(
        err,
        BackupError::InsufficientUnwrapShares {
            valid: 2,
            required: 3
        }
    ));
}

#[test]
fn cloud_survives_one_malicious_server() {
    // Сценарий 4: 1 malicious сервер возвращает partial под другим k — клиент
    // пробует альтернативный subset из оставшихся 4 валидных, recovery успешен.
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let aad = CanonicalAad {
        sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
        recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
        chat_id: sample_chat_id(),
        msg_seq: 77,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

    let wrong_k = Scalar::random(&mut OsRng);
    let (wi0, k0) = shares[0];
    let (wi1, _) = shares[1];
    let (wi2, k2) = shares[2];
    let (wi3, k3) = shares[3];
    let (wi4, k4) = shares[4];

    let tampered = compute_partial_share(wi1, wrong_k, &wrapped);
    let mixed: Vec<ServerUnwrapShare> = vec![
        compute_partial_share(wi0, k0, &wrapped),
        tampered,
        compute_partial_share(wi2, k2, &wrapped),
        compute_partial_share(wi3, k3, &wrapped),
        compute_partial_share(wi4, k4, &wrapped),
    ];

    let recovered = unwrap_message_key(&params, &wrapped, &aad, &mixed).unwrap();
    assert_eq!(recovered, mk);
}

#[test]
fn cloud_fails_with_three_malicious_servers() {
    // Сценарий 5: 3 из 5 серверов возвращают partial под неверным k.
    // Клиент видит 5 shares, но любой subset из 3 содержит ≥ 1 tampered →
    // вероятность что все subsets дадут AEAD-fail очень высока.
    // AllSubsetsFailedUnwrap (или AeadDecryptFailed) — catastrophic signal.
    let config = ThresholdConfig::default();
    let (params, shares) = setup_wrapping_params(config);

    let aad = CanonicalAad {
        sender_identity_pubkey: [0x11u8; ED25519_PUB_LEN],
        recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
        chat_id: sample_chat_id(),
        msg_seq: 3,
    };
    let mk = sample_message_key();
    let wrapped = wrap_message_key(&params, &mk, &aad, &mut OsRng).unwrap();

    let wk1 = Scalar::random(&mut OsRng);
    let wk2 = Scalar::random(&mut OsRng);
    let wk3 = Scalar::random(&mut OsRng);
    let (wi0, _) = shares[0];
    let (wi1, _) = shares[1];
    let (wi2, _) = shares[2];
    let (wi3, k3) = shares[3];
    let (wi4, k4) = shares[4];

    let payload: Vec<ServerUnwrapShare> = vec![
        compute_partial_share(wi0, wk1, &wrapped),
        compute_partial_share(wi1, wk2, &wrapped),
        compute_partial_share(wi2, wk3, &wrapped),
        compute_partial_share(wi3, k3, &wrapped),
        compute_partial_share(wi4, k4, &wrapped),
    ];

    let err = unwrap_message_key(&params, &wrapped, &aad, &payload).unwrap_err();
    assert!(
        matches!(err, BackupError::AllSubsetsFailedUnwrap),
        "expected AllSubsetsFailedUnwrap, got {err:?}"
    );
}

#[test]
fn cloud_mock_transport_enforces_authorization() {
    // Сценарий 6: MockUnwrapTransport настроен с authorization list — запрос
    // подписанный неавторизованным device-key отвергается (симулирует KT lookup
    // на стороне Sealed Server).
    let config = ThresholdConfig::default();
    let (_params, shares) = setup_wrapping_params(config);

    let servers: Vec<MockSealedServer> = shares
        .iter()
        .map(|(wi, k_i)| MockSealedServer {
            witness_index: *wi,
            share: *k_i,
            behavior: MockServerBehavior::Honest,
        })
        .collect();
    let mut transport = MockUnwrapTransport::new(servers);
    // authorize-список содержит только специфический pubkey; наш запрос будет
    // подписан другим устройством — отказ.
    transport.authorize_device([0xDEu8; 32]);

    let sk = make_device_signing_key();
    let vk = sk.verifying_key().to_bytes();
    let provider = TestingAttestationProvider::default();

    // Создаём fake wrapped_key (нам не нужен реальный для этого теста — цель
    // проверить что transport отказывает до получения shares).
    let mut nonce = [0u8; UNWRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let req = umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request(
        [0xAAu8; POINT_LEN],
        [0x33u8; CHAT_ID_LEN],
        [0x22u8; ED25519_PUB_LEN],
        1_700_000_000_000u64,
        nonce,
        &provider,
        |payload| Ok(sk.sign(payload).to_bytes()),
        vk,
    )
    .unwrap();

    // device_pubkey != authorize-список → transport отвергает.
    let err = transport.dispatch(&req).unwrap_err();
    assert!(matches!(err, BackupError::CryptoVerificationFailed));

    // Подпись отдельно проходит verify (значит отказ — именно от authz layer).
    verify_signed_unwrap_request(&req).unwrap();
}

#[test]
fn cloud_recovery_via_real_keystore_adapter() {
    // Интеграция cloud_wrap + identity_adapters + реальный KeyStore.
    // Показывает что seal_unwrap_request_with_keystore корректно собирает
    // request подписанный device-key'ом из InMemoryKeyStore.
    let ks = fresh_keystore();
    ks.add_device(0, None).unwrap();

    let config = ThresholdConfig::default();
    let (params, _shares) = setup_wrapping_params(config);

    // Имитируем chat_id и device_pubkey получателя (для теста пусть это тот
    // же device pubkey — в реальности это другое устройство в этом аккаунте).
    let chat_id = sample_chat_id();
    let recipient_device = ks.device_public(0).unwrap().to_bytes();

    let provider = TestingAttestationProvider::default();
    let mut nonce = [0u8; UNWRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let req = seal_unwrap_request_with_keystore(
        &ks,
        0,
        [0xAAu8; POINT_LEN], // dummy R — для unit-verify
        chat_id,
        recipient_device,
        1_700_000_000_000u64,
        nonce,
        &provider,
    )
    .unwrap();

    verify_signed_unwrap_request(&req).unwrap();
    assert_eq!(req.device_pubkey, recipient_device);
    let _ = params; // params используется выше setup_wrapping_params
}

// ================= Secret scenarios =================

#[test]
fn secret_full_device_transfer_across_accounts() {
    // Сценарий 7: Полный Secret device-transfer через QR + Noise_IK + identity
    // binding + snapshot stream. Два KeyStore моделируют старое и новое
    // устройства одного аккаунта.
    let ks_old = fresh_keystore();
    let ks_new = fresh_keystore();
    let account_id = [0xABu8; ACCOUNT_ID_LEN];

    let mut kt = MockKtLookup::new();
    kt.register(ks_old.identity_public().to_bytes(), account_id);
    kt.register(ks_new.identity_public().to_bytes(), account_id);

    // Responder: ephemeral X25519 + подписанный QR через identity.
    let resp_eph_secret = XStatic::random_from_rng(OsRng);
    let resp_eph_pub = XPub::from(&resp_eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);
    let qr = build_signed_qr_with_identity(&ks_old, resp_eph_pub, chal, u64::MAX / 2).unwrap();

    // Initiator (новое устройство) сканирует, валидирует QR.
    qr.verify_identity().unwrap();
    qr.ensure_not_expired(1_000_000).unwrap();

    // Noise_IK.
    let init_secret = XStatic::random_from_rng(OsRng);
    let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
    let mut responder =
        PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let (msg2, resp_result) = responder.write_message_2_and_finalize().unwrap();
    let init_result = initiator.read_message_2_and_finalize(&msg2).unwrap();
    assert_eq!(init_result.handshake_hash, resp_result.handshake_hash);

    // Post-handshake: responder подписывает handshake hash, initiator verify'ит pairing.
    let remote_sig =
        sign_handshake_hash_with_identity(&ks_old, &resp_result.handshake_hash).unwrap();
    verify_remote_pairing(
        &qr,
        &ks_old.identity_public().to_bytes(),
        &account_id,
        &init_result.handshake_hash,
        &remote_sig,
        &kt,
        &ks_new.identity_public().to_bytes(),
    )
    .unwrap();

    // Snapshot transfer: responder шлёт 2 MLS groups + 50-byte encrypted DB blob.
    let mut resp_session =
        TransferSession::new(resp_result.transport, resp_result.handshake_hash.to_vec());
    let mut init_session =
        TransferSession::new(init_result.transport, init_result.handshake_hash.to_vec());

    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        mls_groups: (0..2)
            .map(|i| umbrella_backup::device_transfer::MlsGroupState {
                group_id: {
                    let mut g = [0u8; MLS_GROUP_ID_LEN];
                    g[0] = i as u8;
                    g
                },
                state_bytes: vec![0xB0u8 + i as u8; 512],
            })
            .collect(),
        local_db_ciphertext: vec![0x44u8; 50],
    };
    let payload = snapshot.to_bytes().unwrap();
    let frame = resp_session.encode_frame(&payload).unwrap();
    let decoded = init_session.decode_frame(&frame).unwrap();
    let recovered_snapshot = Snapshot::from_bytes(&decoded).unwrap();
    assert_eq!(recovered_snapshot, snapshot);
}

#[test]
fn secret_expired_qr_rejected() {
    // Сценарий 8: QR с expiry в прошлом → ensure_not_expired fails.
    let ks = fresh_keystore();
    let eph_secret = XStatic::random_from_rng(OsRng);
    let eph_pub = XPub::from(&eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);

    let qr = build_signed_qr_with_identity(&ks, eph_pub, chal, 1_000).unwrap();
    // now > expiry → expired.
    let err = qr.ensure_not_expired(2_000).unwrap_err();
    assert!(matches!(err, BackupError::QrExpired));
}

#[test]
fn secret_tampered_qr_rejected() {
    // Сценарий 9: Атакующий подменяет responder_identity_pubkey — identity_signature
    // (подпись под original identity) становится невалидной.
    let ks = fresh_keystore();
    let ks_other = fresh_keystore();
    let eph_secret = XStatic::random_from_rng(OsRng);
    let eph_pub = XPub::from(&eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);

    let mut qr = build_signed_qr_with_identity(&ks, eph_pub, chal, u64::MAX / 2).unwrap();
    qr.responder_identity_pubkey = ks_other.identity_public().to_bytes();

    let err = qr.verify_identity().unwrap_err();
    assert!(matches!(err, BackupError::QrSignatureInvalid));
}

#[test]
fn secret_interrupted_stream_rejected() {
    // Сценарий 10: Transfer прерывается посредине — truncated frame payload
    // приводит к StreamUnexpectedEof на стороне initiator'а.
    let ks_old = fresh_keystore();
    let resp_eph_secret = XStatic::random_from_rng(OsRng);
    let resp_eph_pub = XPub::from(&resp_eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);
    let qr = build_signed_qr_with_identity(&ks_old, resp_eph_pub, chal, u64::MAX / 2).unwrap();

    let init_secret = XStatic::random_from_rng(OsRng);
    let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
    let mut responder =
        PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let (msg2, resp_result) = responder.write_message_2_and_finalize().unwrap();
    let init_result = initiator.read_message_2_and_finalize(&msg2).unwrap();

    let mut resp_session =
        TransferSession::new(resp_result.transport, resp_result.handshake_hash.to_vec());
    let mut init_session =
        TransferSession::new(init_result.transport, init_result.handshake_hash.to_vec());

    let frame = resp_session
        .encode_frame(b"some encoded snapshot payload")
        .unwrap();
    // Truncate middle-of-frame: нехватает нескольких байт payload.
    let truncated = &frame[..frame.len() - 5];

    let err = init_session.decode_frame(truncated).unwrap_err();
    assert!(matches!(err, BackupError::StreamUnexpectedEof));
}

#[test]
fn secret_tampered_qr_wire_version_rejected() {
    // Bonus сценарий: QR с неправильной wire-version отвергается при парсинге.
    let ks = fresh_keystore();
    let eph_secret = XStatic::random_from_rng(OsRng);
    let eph_pub = XPub::from(&eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);
    let qr = build_signed_qr_with_identity(&ks, eph_pub, chal, u64::MAX / 2).unwrap();

    let mut bytes = qr.to_bytes();
    bytes[0] = 0x02; // unsupported version

    let err = DevicePairingQr::from_bytes(&bytes).unwrap_err();
    assert!(matches!(
        err,
        BackupError::QrVersionMismatch {
            expected: 0x01,
            found: 0x02
        }
    ));

    // Также гарантируем что полный payload валиден по длине.
    assert_eq!(bytes.len(), QR_PAYLOAD_LEN);
    // И что подпись имеет ожидаемую длину (sanity).
    assert_eq!(qr.identity_signature.len(), QR_SIG_LEN);
}
