//! Максимальный режим криптографической защиты — включён по умолчанию для всех пользователей.
//!
//! Объединяет 4 техники защиты в одном слое:
//!
//! 1. **Агрессивный DH-храповик** — [`force_rekey`](crate::group::UmbrellaGroup::force_rekey)
//!    вызывается **перед каждой** отправкой сообщения. Окно компрометации = одно сообщение.
//! 2. **Symmetric ratchet на каждое сообщение** — MLS делает это автоматически в
//!    [`encrypt_application`](crate::group::UmbrellaGroup::encrypt_application).
//! 3. **Таймер 5 минут** — если переписка простаивает ≥5 минут, следующая операция
//!    триггерит принудительный rekey.
//! 4. **Post-quantum X-Wing ratchet каждые 3 commits** — flag для дополнительного
//!    PQ-extension в commit. Реальная X-Wing combine integration реализована через
//!    [`MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`] + [`UmbrellaGroup::force_rekey_with_pq`]
//!    под ciphersuite 0x004D + [`UmbrellaXWingProvider`](crate::provider::xwing::UmbrellaXWingProvider)
//!    (feature `pq`). См. `tests/test_max_ratchet_pq_real.rs` для верификации.
//! 5. **SPQR Deniable Authentication** — HMAC поверх каждого ciphertext через общий эпоховый
//!    секрет. Любая сторона могла бы forge MAC → невозможно доказать суду авторство.
//!
//! Это **default-on** режим: все пользователи v3 получают его автоматически без opt-in.
//! Stoимость замерена в `crates/umbrella-mls/benches/max_ratchet_benchmark.rs`.
//!
//! Maximum cryptographic protection mode — on by default for all users.
//!
//! Combines 4 protection techniques in one layer:
//!
//! 1. **Aggressive DH ratchet** — [`force_rekey`](crate::group::UmbrellaGroup::force_rekey)
//!    is invoked **before every** outgoing message. The compromise window = one message.
//! 2. **Per-message symmetric ratchet** — MLS does this automatically inside
//!    [`encrypt_application`](crate::group::UmbrellaGroup::encrypt_application).
//! 3. **5-minute timer** — if the conversation is idle ≥ 5 minutes, the next operation
//!    forces a rekey.
//! 4. **Post-quantum X-Wing ratchet every 3 commits** — flag for an extra PQ extension in
//!    the commit. Real X-Wing combine integration is implemented via
//!    [`MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`] +
//!    [`UmbrellaGroup::force_rekey_with_pq`] under ciphersuite 0x004D +
//!    [`UmbrellaXWingProvider`](crate::provider::xwing::UmbrellaXWingProvider) (feature
//!    `pq`). See `tests/test_max_ratchet_pq_real.rs` for verification.
//! 5. **SPQR Deniable Authentication** — HMAC over each ciphertext via the shared epoch
//!    secret. Either party could forge the MAC → impossible to prove authorship in court.
//!
//! This is a **default-on** mode: every v3 user gets it automatically with no opt-in. The
//! cost is measured in `crates/umbrella-mls/benches/max_ratchet_benchmark.rs`.

pub mod config;
pub mod counter;
pub mod group;
pub mod spqr;
pub mod timer;

pub use config::MaxRatchetConfig;
pub use group::{MaxRatchetGroup, MaxRatchetOutgoing};
