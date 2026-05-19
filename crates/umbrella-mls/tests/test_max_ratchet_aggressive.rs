//! Интеграционные тесты максимального ratchet режима против реальной MLS группы.
//!
//! Проверяют что:
//! - Каждое сообщение через [`MaxRatchetGroup::encrypt_with_rekey`] продвигает MLS epoch
//!   на +1 (агрессивный DH-храповик).
//! - Таймер 5 минут (с переопределением до 60 секунд для теста) триггерит rekey при
//!   паузе ≥ timer_seconds.
//! - Счётчик commits правильно считает + флаг `pq_extension_used` ставится каждые 3
//!   commits (Task 4 flag-level).
//! - Полный поток `encrypt_with_rekey_authenticated` добавляет SPQR HMAC к outgoing.
//!
//! Integration tests for the max ratchet mode against a real MLS group.

use std::sync::Arc;

use openmls::group::GroupId;
#[allow(deprecated)]
use umbrella_identity::IdentitySeed;
use umbrella_identity::{Clock, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock};
use umbrella_mls::{
    MaxRatchetConfig, MaxRatchetGroup, UmbrellaCiphersuite, UmbrellaGroup, UmbrellaProvider,
    UMBRELLA_DEFAULT_CIPHERSUITE,
};

const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;
const T0: u64 = 1_700_000_000;

/// Тестовый клиент с собственным keystore + провайдером.
struct TestClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl TestClient {
    fn new(device_index: u32) -> Self {
        let mut rng = rand_core::OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        ks.add_device(device_index, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index,
        }
    }
}

fn fresh_group_id(tag: u8) -> GroupId {
    GroupId::from_slice(&[tag; 16])
}

fn make_solo_group(client: &TestClient, tag: u8) -> UmbrellaGroup {
    UmbrellaGroup::create_private(
        &client.provider,
        client.ks.as_ref(),
        client.device_index,
        CS,
        fresh_group_id(tag),
        T0,
    )
    .expect("create_private")
}

// ===== Task 2: Aggressive DH ratchet =====

#[test]
fn aggressive_dh_advances_epoch_on_every_send() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA1);
    let mut max_group = MaxRatchetGroup::new(group);

    let initial_epoch = max_group.inner().epoch();

    let out1 = max_group
        .encrypt_with_rekey(&alice.provider, alice.ks.as_ref(), b"first message", T0 + 1)
        .expect("first send");
    let epoch_after_first = max_group.inner().epoch();
    assert_eq!(
        epoch_after_first,
        initial_epoch + 1,
        "first send must advance epoch by 1 (aggressive DH ratchet)"
    );
    assert!(out1.commit_bytes.is_some(), "commit_bytes must be present");
    assert_eq!(out1.epoch_after_send, epoch_after_first);

    let out2 = max_group
        .encrypt_with_rekey(
            &alice.provider,
            alice.ks.as_ref(),
            b"second message",
            T0 + 2,
        )
        .expect("second send");
    let epoch_after_second = max_group.inner().epoch();
    assert_eq!(
        epoch_after_second,
        initial_epoch + 2,
        "second send must advance epoch by another 1"
    );
    assert!(out2.commit_bytes.is_some());
}

#[test]
fn no_aggressive_dh_keeps_epoch() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA2);

    let config = MaxRatchetConfig::with_overrides(
        /* aggressive_dh_per_message */ false, /* timer_rekey_seconds */ 300,
        /* pq_ratchet_every_n_commits */ 0, /* spqr_deniable_auth */ false,
    );
    let mut max_group = MaxRatchetGroup::with_config(group, config);

    let initial_epoch = max_group.inner().epoch();

    let outgoing = max_group
        .encrypt_with_rekey(&alice.provider, alice.ks.as_ref(), b"msg", T0 + 1)
        .expect("send");

    assert!(
        outgoing.commit_bytes.is_none(),
        "commit_bytes must be None when aggressive_dh_per_message=false"
    );
    assert_eq!(
        max_group.inner().epoch(),
        initial_epoch,
        "epoch must NOT advance when aggressive mode is off"
    );
}

#[test]
fn commit_counter_increments_with_each_aggressive_send() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA3);
    let mut max_group = MaxRatchetGroup::new(group);

    assert_eq!(max_group.commit_counter(), 0);

    for i in 1..=5 {
        let _ = max_group
            .encrypt_with_rekey(
                &alice.provider,
                alice.ks.as_ref(),
                format!("msg {}", i).as_bytes(),
                T0 + i,
            )
            .expect("send");
        assert_eq!(max_group.commit_counter(), i as u32);
    }
}

// ===== Task 4: PQ flag every 3 commits =====

#[test]
fn pq_extension_flag_set_on_every_3rd_send() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA4);
    let mut max_group = MaxRatchetGroup::new(group);

    let flags: Vec<bool> = (1..=9)
        .map(|i| {
            let outgoing = max_group
                .encrypt_with_rekey(
                    &alice.provider,
                    alice.ks.as_ref(),
                    format!("msg {}", i).as_bytes(),
                    T0 + i,
                )
                .expect("send");
            outgoing.pq_extension_used
        })
        .collect();

    // Counter 1,2: no PQ; 3: PQ; 4,5: no PQ; 6: PQ; 7,8: no PQ; 9: PQ.
    assert_eq!(
        flags,
        vec![false, false, true, false, false, true, false, false, true],
        "pq_extension_used must be true on every 3rd send (counter % 3 == 0)"
    );
}

#[test]
fn pq_flag_disabled_when_every_n_zero() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA5);

    let config = MaxRatchetConfig::with_overrides(
        /* aggressive_dh_per_message */ true, /* timer_rekey_seconds */ 300,
        /* pq_ratchet_every_n_commits */ 0, /* spqr_deniable_auth */ false,
    );
    let mut max_group = MaxRatchetGroup::with_config(group, config);

    for i in 1..=10 {
        let outgoing = max_group
            .encrypt_with_rekey(
                &alice.provider,
                alice.ks.as_ref(),
                format!("msg {}", i).as_bytes(),
                T0 + i,
            )
            .expect("send");
        assert!(
            !outgoing.pq_extension_used,
            "PQ flag must be false when pq_ratchet_every_n_commits=0 (counter={})",
            i
        );
    }
}

// ===== Task 3: 5-minute timer =====

#[test]
fn timer_triggers_rekey_after_pause() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA6);

    let config = MaxRatchetConfig::with_overrides(
        /* aggressive_dh_per_message */ false, /* timer_rekey_seconds */ 60,
        /* pq_ratchet_every_n_commits */ 0, /* spqr_deniable_auth */ false,
    );
    let mut max_group = MaxRatchetGroup::with_config(group, config);

    let initial_epoch = max_group.inner().epoch();

    // T0 + 30s: ещё рано, последний rekey был на T0 → elapsed=30 < 60.
    let early = max_group
        .check_timer_and_rekey(&alice.provider, alice.ks.as_ref(), T0 + 30)
        .expect("check timer early");
    assert!(early.is_none(), "timer must not trigger before period");
    assert_eq!(max_group.inner().epoch(), initial_epoch);

    // T0 + 70s: пора, elapsed=70 >= 60.
    let late = max_group
        .check_timer_and_rekey(&alice.provider, alice.ks.as_ref(), T0 + 70)
        .expect("check timer late");
    assert!(late.is_some(), "timer must trigger after period");
    assert_eq!(
        max_group.inner().epoch(),
        initial_epoch + 1,
        "epoch must advance by 1 after timer rekey"
    );
}

#[test]
fn timer_does_not_double_trigger_immediately() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA7);

    let config = MaxRatchetConfig::with_overrides(false, 30, 0, false);
    let mut max_group = MaxRatchetGroup::with_config(group, config);

    let initial_epoch = max_group.inner().epoch();

    // Первое срабатывание.
    let first = max_group
        .check_timer_and_rekey(&alice.provider, alice.ks.as_ref(), T0 + 100)
        .expect("check");
    assert!(first.is_some(), "first check triggers");
    let epoch_after_first = max_group.inner().epoch();
    assert_eq!(epoch_after_first, initial_epoch + 1);

    // Сразу повторно: last_rekey_at_unix теперь T0+100, elapsed=1 < 30.
    let second = max_group
        .check_timer_and_rekey(&alice.provider, alice.ks.as_ref(), T0 + 101)
        .expect("check");
    assert!(
        second.is_none(),
        "immediate re-check must not double-trigger"
    );
    assert_eq!(max_group.inner().epoch(), epoch_after_first);
}

// ===== Task 5: SPQR HMAC =====

#[test]
fn spqr_hmac_attached_to_authenticated_send() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA8);
    let mut max_group = MaxRatchetGroup::new(group);

    let outgoing = max_group
        .encrypt_with_rekey_authenticated(
            &alice.provider,
            alice.ks.as_ref(),
            b"deniable hello",
            T0 + 1,
        )
        .expect("authenticated send");

    assert!(outgoing.spqr_mac.is_some(), "spqr_mac must be present");
    let mac = outgoing.spqr_mac.as_ref().unwrap();
    assert_eq!(mac.len(), 32, "HMAC-SHA256 must produce 32 bytes");

    // commit + ciphertext также присутствуют (aggressive DH = true by default).
    assert!(outgoing.commit_bytes.is_some());
    assert!(!outgoing.ciphertext_bytes.is_empty());
}

#[test]
fn spqr_disabled_omits_mac() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xA9);

    let config =
        MaxRatchetConfig::with_overrides(true, 300, 3, /* spqr_deniable_auth */ false);
    let mut max_group = MaxRatchetGroup::with_config(group, config);

    let outgoing = max_group
        .encrypt_with_rekey_authenticated(&alice.provider, alice.ks.as_ref(), b"no mac", T0 + 1)
        .expect("send");

    assert!(
        outgoing.spqr_mac.is_none(),
        "spqr_mac must be None when spqr_deniable_auth=false"
    );
}

#[test]
fn full_default_flow_runs_all_four_defences() {
    let alice = TestClient::new(0);
    let group = make_solo_group(&alice, 0xAA);
    let mut max_group = MaxRatchetGroup::new(group); // default: all defences ON

    let initial_epoch = max_group.inner().epoch();

    // Отправляем 6 сообщений по default config.
    let outgoings: Vec<_> = (1..=6)
        .map(|i| {
            max_group
                .encrypt_with_rekey_authenticated(
                    &alice.provider,
                    alice.ks.as_ref(),
                    format!("msg {}", i).as_bytes(),
                    T0 + i,
                )
                .expect("send")
        })
        .collect();

    // 1. Aggressive DH: epoch продвинулся 6 раз.
    assert_eq!(max_group.inner().epoch(), initial_epoch + 6);

    // 2. Все outgoings имеют commit_bytes.
    for (i, out) in outgoings.iter().enumerate() {
        assert!(out.commit_bytes.is_some(), "msg {} missing commit", i + 1);
    }

    // 3. Все outgoings имеют SPQR mac.
    for (i, out) in outgoings.iter().enumerate() {
        assert!(out.spqr_mac.is_some(), "msg {} missing SPQR mac", i + 1);
        assert_eq!(out.spqr_mac.as_ref().unwrap().len(), 32);
    }

    // 4. PQ flag true на 3-м и 6-м (1-based), false на остальных.
    assert!(!outgoings[0].pq_extension_used, "msg 1 no PQ");
    assert!(!outgoings[1].pq_extension_used, "msg 2 no PQ");
    assert!(outgoings[2].pq_extension_used, "msg 3 PQ");
    assert!(!outgoings[3].pq_extension_used, "msg 4 no PQ");
    assert!(!outgoings[4].pq_extension_used, "msg 5 no PQ");
    assert!(outgoings[5].pq_extension_used, "msg 6 PQ");

    // 5. Counter == 6.
    assert_eq!(max_group.commit_counter(), 6);
}
