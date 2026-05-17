//! D-7 regression: rate-limit bypass via parallel queries from sibling
//! devices must be blocked by server-coordinated rate budget.
//!
//! D-7 атака: обход rate-limit через параллельные запросы от sibling-устройств
//! одного аккаунта.
//!
//! ## Attack model
//!
//! Адверсарь имеет 5 sibling devices одного account (т.е. знает PIN →
//! может re-derive master_key через round 6 protocol). Каждое устройство
//! отправляет 100 queries → total 500 queries. Server должен видеть, что
//! anon_ids все производят single master_key → коллаборативно applies budget
//! (даже сросткими anon_ids от 5 серверов).
//!
//! Однако в client-side budget tracker (этот крейт) каждое устройство
//! независимо ведёт budget. Поэтому test показывает: server-side
//! coordination (см. backend spec) — необходимое дополнение.
//!
//! ## Defense
//!
//! 1. Client-side: `ClientBudgetState` ограничивает каждое устройство
//!    100/hour, 5000/day.
//! 2. Server-side (out of scope этого крейта; backend spec): cluster видит
//!    anon_id с server_id; за день видит many distinct anon_ids; если 5
//!    serv1-anon_id'ы все sharing MK, cluster может coalesce их в один
//!    рейт-бак. Это требует deterministic association anon_id → account
//!    через privacy-preserving counter.
//!
//! ## Acceptance criterion
//!
//! - Один client достигает hourly cap → дальнейшие fail.
//! - Server-coordination simulation: 5 sibling devices генерируют distinct
//!   anon_ids на server #1 для one MK; backend могут идентифицировать
//!   common MK via *zero-knowledge сравнение* (out of scope; documented).

use umbrella_discovery::{ClientBudgetState, DiscoveryError, MockClock};

#[test]
fn d7_attack_single_device_burst_blocked_at_hourly_cap() {
    let clock = MockClock::new(1_700_000_000);
    let mut budget = ClientBudgetState::with_limits(100, 5000);
    for _ in 0..100 {
        budget.check_and_register(&clock).unwrap();
    }
    let err = budget.check_and_register(&clock).unwrap_err();
    assert!(matches!(err, DiscoveryError::RateLimited { .. }));
}

#[test]
fn d7_attack_five_sibling_devices_independent_budgets_documented() {
    // Симуляция: 5 sibling devices независимо ведут свой бюджет (100/h
    // each). На клиенте: total combined 500 quotes per hour.
    //
    // Это **client-side** ограничение. Server-side coordination — в
    // backend spec. Здесь test показывает: client-side каждое устройство
    // достигает только своего 100-h cap.
    let clock = MockClock::new(1_700_000_000);
    let mut devices: Vec<ClientBudgetState> =
        (0..5).map(|_| ClientBudgetState::with_limits(100, 5000)).collect();
    let mut total_accepted = 0u32;
    for d in &mut devices {
        for _ in 0..100 {
            d.check_and_register(&clock).unwrap();
            total_accepted += 1;
        }
        let err = d.check_and_register(&clock).unwrap_err();
        assert!(matches!(err, DiscoveryError::RateLimited { .. }));
    }
    // Combined: 500. Это describes that с **только client-side** budget
    // адверсарь способен сделать 500/h. Defence-in-depth = server-side
    // coordination (described in `docs/spec/discovery-backend-spec.md`).
    assert_eq!(total_accepted, 500);
}

#[test]
fn d7_attack_daily_cap_eventually_locks_burst() {
    let clock = MockClock::new(1_700_000_000);
    let mut budget = ClientBudgetState::with_limits(10_000, 5);
    for _ in 0..5 {
        budget.check_and_register(&clock).unwrap();
    }
    let err = budget.check_and_register(&clock).unwrap_err();
    assert!(matches!(err, DiscoveryError::RateLimited { .. }));
    // Advance 23 hour: daily cap всё ещё active.
    clock.advance(23 * 3600);
    let err = budget.check_and_register(&clock).unwrap_err();
    assert!(matches!(err, DiscoveryError::RateLimited { .. }));
    // Advance to 24h+: daily-cap evicts oldest.
    clock.advance(2 * 3600);
    budget.check_and_register(&clock).unwrap();
}

#[test]
fn d7_attack_burst_then_recovery_after_hour() {
    let clock = MockClock::new(1_700_000_000);
    let mut budget = ClientBudgetState::with_limits(5, 100);
    for _ in 0..5 {
        budget.check_and_register(&clock).unwrap();
    }
    // Burst of 50 attempts → all rejected.
    let mut rejected = 0;
    for _ in 0..50 {
        if budget.check_and_register(&clock).is_err() {
            rejected += 1;
        }
    }
    assert_eq!(rejected, 50);
    // Advance 1h → recovery.
    clock.advance(3601);
    budget.check_and_register(&clock).unwrap();
}

#[test]
fn d7_attack_exponential_backoff_visible_in_retry_after() {
    let clock = MockClock::new(1_700_000_000);
    let mut budget = ClientBudgetState::with_limits(1, 100);
    budget.check_and_register(&clock).unwrap();
    let first_err = budget.check_and_register(&clock).unwrap_err();
    let first_secs = match first_err {
        DiscoveryError::RateLimited { retry_after_secs } => retry_after_secs,
        other => panic!("expected RateLimited, got {other:?}"),
    };
    let second_err = budget.check_and_register(&clock).unwrap_err();
    let second_secs = match second_err {
        DiscoveryError::RateLimited { retry_after_secs } => retry_after_secs,
        other => panic!("expected RateLimited, got {other:?}"),
    };
    // Exponential backoff: каждая последующая попытка имеет ≥ предыдущее.
    assert!(second_secs >= first_secs);
}
