//! Milestone Этапа 2: 2 `UmbrellaGroup` клиента + mock server-blind-postman + 1000 сообщений.
//! Stage 2 milestone: 2 `UmbrellaGroup` clients + mock server-blind-postman + 1000 messages.
//!
//! Это официальный критерий завершения Этапа 2 из private protocol overview: 2 клиента обмениваются 1000
//! сообщениями через сервер который никогда не расшифровывает payload, только валидирует
//! wire-format, проверяет anti-replay и rate-limit.
//!
//! Дополнительно: тесты отдельных сценариев:
//! - server отвергает повтор того же ciphertext;
//! - server отвергает слишком частого sender'а;
//! - server отвергает Welcome на messages-endpoint (by default).
//!
//! This is the official Stage 2 completion criterion from the private protocol overview: 2 clients exchange
//! 1000 messages through a server that never decrypts the payload — only validates wire
//! format, checks anti-replay and rate-limit.
//!
//! Additional scenario tests:
//! - server rejects replay of the same ciphertext;
//! - server rejects a too-frequent sender;
//! - server rejects Welcome on a messages endpoint (default).

use std::sync::Arc;

use openmls::group::GroupId;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider, UMBRELLA_DEFAULT_CIPHERSUITE,
};
use umbrella_server_blind_postman::{AllowAll, FixedWindow, ReplayGuard, Router, RoutingDecision};

/// Тестовый ciphersuite. Test ciphersuite.
const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;

/// Тестовое unix-время. Test unix time.
const T0: u64 = 1_700_000_000;

/// Общий клиент: keystore, provider, device_index.
/// Shared client: keystore, provider, device_index.
struct Client {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl Client {
    fn new(device_index: u32) -> Self {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        ks.add_device(device_index, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index,
        }
    }

    fn key_package(&self) -> openmls::key_packages::KeyPackage {
        build_device_key_package(
            &self.provider,
            self.ks.as_ref() as &dyn KeyStore,
            self.device_index,
            CS,
        )
        .expect("build key package")
        .key_package()
        .clone()
    }
}

/// Строит Alice-группу + Bob-группу через add_members/welcome.
/// Builds an Alice group + Bob group via add_members/welcome.
fn dyadic_pair() -> (Client, Client, UmbrellaGroup, UmbrellaGroup) {
    let alice = Client::new(0);
    let bob = Client::new(0);
    let bob_kp = bob.key_package();

    let mut alice_g = UmbrellaGroup::create_private(
        &alice.provider,
        alice.ks.as_ref() as &dyn KeyStore,
        alice.device_index,
        CS,
        GroupId::from_slice(&[0x42; 16]),
        T0,
    )
    .expect("alice create_private");

    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[bob_kp],
            T0 + 5,
        )
        .expect("alice add_members(bob)");

    let bob_g = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref() as &dyn KeyStore,
        bob.device_index,
        &outcome.welcome.expect("welcome"),
        GroupPolicy::Private,
        T0 + 5,
    )
    .expect("bob join_from_welcome");

    (alice, bob, alice_g, bob_g)
}

/// Пропускает через сервер; возвращает envelope-байты если Accept.
/// Routes through the server; returns envelope bytes on Accept.
fn dispatch_expect_accept<RL: umbrella_server_blind_postman::RateLimiter>(
    router: &mut Router<RL>,
    bytes: &[u8],
    sender_id: &[u8],
    now_unix: u64,
) -> Vec<u8> {
    match router.dispatch(bytes, sender_id, now_unix) {
        RoutingDecision::Accept(env) => {
            assert!(
                env.group_id.is_some(),
                "messages endpoint requires group_id"
            );
            assert!(env.epoch.is_some(), "messages endpoint requires epoch");
            bytes.to_vec()
        }
        other => panic!(
            "expected Accept on bytes len {}, sender {:?}, t={}: {:?}",
            bytes.len(),
            sender_id,
            now_unix,
            other
        ),
    }
}

// =========================================================================================
// Milestone: 1000 сообщений через blind server.
// =========================================================================================

#[test]
fn thousand_messages_through_blind_server() {
    let (alice, bob, mut alice_g, mut bob_g) = dyadic_pair();

    // Router: rate-limit 2000 сообщений в 60 секунд (с запасом), anti-replay 60 сек.
    let mut router = Router::new(
        ReplayGuard::with_default_window(),
        FixedWindow::new(60, 2000),
    );

    let now = T0 + 10;
    let mut now = now;

    for i in 0..1_000 {
        if i % 2 == 0 {
            let payload = format!("alice-msg-{i:04}");
            let ct = alice_g
                .encrypt_application(
                    &alice.provider,
                    alice.ks.as_ref() as &dyn KeyStore,
                    payload.as_bytes(),
                )
                .unwrap();
            let forwarded = dispatch_expect_accept(&mut router, &ct, b"alice", now);
            match bob_g.process_incoming(&bob.provider, &forwarded).unwrap() {
                IncomingMessage::Application {
                    payload: decoded,
                    sender_index,
                } => {
                    assert_eq!(sender_index, 0, "alice has leaf_index 0");
                    assert_eq!(decoded, payload.as_bytes());
                }
                other => panic!("alice→bob iter {i}: expected Application, got {other:?}"),
            }
        } else {
            let payload = format!("bob-msg-{i:04}");
            let ct = bob_g
                .encrypt_application(
                    &bob.provider,
                    bob.ks.as_ref() as &dyn KeyStore,
                    payload.as_bytes(),
                )
                .unwrap();
            let forwarded = dispatch_expect_accept(&mut router, &ct, b"bob", now);
            match alice_g
                .process_incoming(&alice.provider, &forwarded)
                .unwrap()
            {
                IncomingMessage::Application {
                    payload: decoded,
                    sender_index,
                } => {
                    assert_eq!(sender_index, 1, "bob has leaf_index 1");
                    assert_eq!(decoded, payload.as_bytes());
                }
                other => panic!("bob→alice iter {i}: expected Application, got {other:?}"),
            }
        }

        // Делаем шаг в 1 секунду каждые 30 итераций (имитируем реальный timeline).
        if i % 30 == 29 {
            now += 1;
        }
    }

    // Epoch'и остались прежними — никто не добавлял/удалял/ре-кеил в этом цикле.
    // Epochs are unchanged — nobody added/removed/rekeyed in this loop.
    assert_eq!(alice_g.epoch(), 1);
    assert_eq!(bob_g.epoch(), 1);
    assert_eq!(alice_g.member_count(), 2);
    assert_eq!(bob_g.member_count(), 2);
}

// =========================================================================================
// Server отвергает точный повтор.
// Server rejects an exact replay.
// =========================================================================================

#[test]
fn server_rejects_exact_replay() {
    let (alice, _bob, mut alice_g, _bob_g) = dyadic_pair();
    let mut router = Router::new(ReplayGuard::with_default_window(), AllowAll);

    let ct = alice_g
        .encrypt_application(&alice.provider, alice.ks.as_ref() as &dyn KeyStore, b"once")
        .unwrap();

    match router.dispatch(&ct, b"alice", T0 + 10) {
        RoutingDecision::Accept(_) => {}
        other => panic!("first dispatch must Accept: {other:?}"),
    }
    assert_eq!(
        router.dispatch(&ct, b"alice", T0 + 20),
        RoutingDecision::RejectReplay,
        "second dispatch of identical ciphertext must RejectReplay"
    );
}

// =========================================================================================
// Server отвергает слишком частого sender'а.
// Server rejects a too-frequent sender.
// =========================================================================================

#[test]
fn server_rejects_rate_limited_sender() {
    let (alice, _bob, mut alice_g, _bob_g) = dyadic_pair();
    let mut router = Router::new(ReplayGuard::with_default_window(), FixedWindow::new(60, 3));

    // 3 валидных сообщения проходят.
    for i in 0..3 {
        let payload = format!("msg-{i}");
        let ct = alice_g
            .encrypt_application(
                &alice.provider,
                alice.ks.as_ref() as &dyn KeyStore,
                payload.as_bytes(),
            )
            .unwrap();
        match router.dispatch(&ct, b"alice", T0 + 10) {
            RoutingDecision::Accept(_) => {}
            other => panic!("msg {i} expected Accept: {other:?}"),
        }
    }

    // 4-е отвергается по rate-лимиту.
    let ct4 = alice_g
        .encrypt_application(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            b"msg-4",
        )
        .unwrap();
    assert_eq!(
        router.dispatch(&ct4, b"alice", T0 + 10),
        RoutingDecision::RejectRateLimit,
        "4th message must be rate-limited"
    );
}

// =========================================================================================
// Server отвергает Welcome на messages-endpoint (default).
// Server rejects Welcome on a messages endpoint (default).
// =========================================================================================

#[test]
fn server_rejects_welcome_on_messages_endpoint() {
    let (alice, bob, mut alice_g, _bob_g) = dyadic_pair();
    // Alice приглашает Каролину — add_members возвращает welcome для Carol.
    let carol = Client::new(0);
    let carol_kp = carol.key_package();
    let outcome = alice_g
        .add_members(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            &[carol_kp],
            T0 + 20,
        )
        .unwrap();
    let welcome_bytes = outcome.welcome.unwrap();

    // Messages-endpoint: AllowAll rate-limiter; Welcome не в whitelist → RejectUnsupportedKind.
    let mut messages_router = Router::new(ReplayGuard::with_default_window(), AllowAll);
    match messages_router.dispatch(&welcome_bytes, b"alice", T0 + 20) {
        RoutingDecision::RejectUnsupportedKind(kind) => {
            assert_eq!(
                kind,
                umbrella_server_blind_postman::EnvelopeKind::Welcome,
                "Welcome must be reported as the rejected kind"
            );
        }
        other => panic!("Welcome on messages endpoint must reject: {other:?}"),
    }

    // Keypackage-swap endpoint (с .with_welcomes()) принимает.
    let mut kp_router = Router::new(ReplayGuard::with_default_window(), AllowAll).with_welcomes();
    match kp_router.dispatch(&welcome_bytes, b"alice", T0 + 20) {
        RoutingDecision::Accept(env) => {
            assert_eq!(
                env.kind,
                umbrella_server_blind_postman::EnvelopeKind::Welcome
            );
            // Welcome не имеет group_id/epoch (маршрутизация по KeyPackage hash).
            assert!(env.group_id.is_none());
            assert!(env.epoch.is_none());
        }
        other => panic!("KP-swap endpoint must accept Welcome: {other:?}"),
    }
    let _ = bob; // silence unused
}

// =========================================================================================
// Server парсит commit и application как PrivateMessage с одинаковыми group_id.
// Server parses commit and application as PrivateMessage with the same group_id.
// =========================================================================================

#[test]
fn server_sees_same_group_id_on_commit_and_application() {
    let (alice, _bob, mut alice_g, _bob_g) = dyadic_pair();
    // force_rekey — commit + self_update.
    let commit = alice_g
        .force_rekey(&alice.provider, alice.ks.as_ref() as &dyn KeyStore, T0 + 10)
        .unwrap();
    let app = alice_g
        .encrypt_application(
            &alice.provider,
            alice.ks.as_ref() as &dyn KeyStore,
            b"post-rekey",
        )
        .unwrap();

    let mut router = Router::new(ReplayGuard::with_default_window(), AllowAll);
    let commit_env = match router.dispatch(&commit, b"alice", T0 + 10) {
        RoutingDecision::Accept(env) => env,
        other => panic!("commit dispatch: {other:?}"),
    };
    let app_env = match router.dispatch(&app, b"alice", T0 + 11) {
        RoutingDecision::Accept(env) => env,
        other => panic!("app dispatch: {other:?}"),
    };

    assert_eq!(
        commit_env.group_id, app_env.group_id,
        "handshake and application in same group must share group_id"
    );
    // Epoch handshake коммита = 1 (после 0, дo merge); application message после merge = epoch 2.
    // Мы только что сделали force_rekey — alice локально на epoch 2 уже после merge.
    // commit сам был ИЗ epoch 1 (подписан commit в epoch 1, advance'ит в 2).
    assert_eq!(commit_env.epoch, Some(1), "commit carries source epoch 1");
    assert_eq!(app_env.epoch, Some(2), "application is in new epoch 2");
}
