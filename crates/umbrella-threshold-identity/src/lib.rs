//! # Umbrella Threshold Identity (Round 6)
//!
//! ## Зачем (Why)
//!
//! Round 6 — фундаментальная архитектурная переделка. До раунда 6 24+12-слово
//! identity-secret генерировался на устройстве через CSPRNG и материализовывался
//! в RAM на миллисекунды-секунды. Это компромисс с угрозой «physical capture +
//! компрометация вендора Secure Enclave / StrongBox»: bytes have to exist at
//! some point on device.
//!
//! Round 6 устраняет эту единую точку: 24+12-слово identity-secret **никогда**
//! не материализуется на одном устройстве. Distributed Key Generation (FROST-
//! Ed25519, Pedersen-VSS) на 5 серверах создаёт identity public key, и каждый
//! сервер хранит только одну долю секрета. На устройстве — только PIN, public
//! key, и кэшированный 24-часовой offline-тикет.
//!
//! Round 6 — fundamental architectural change. Pre-round-6 the 24+12-word
//! identity secret was generated on-device via CSPRNG and materialised in RAM
//! for milliseconds-seconds. That compromises the «physical capture + chip
//! vendor compromise» threat: the bytes must exist at some point on device.
//!
//! Round 6 removes that single point: the 24+12-word identity secret never
//! materialises on one device. Distributed Key Generation (FROST-Ed25519,
//! Pedersen-VSS) across 5 servers creates the identity public key, and each
//! server holds only one share. The device only stores the PIN, the public
//! key, and a cached 24-hour offline ticket.
//!
//! ## Threat model
//!
//! - 5 серверов в разных юрисдикциях (т.е. Switzerland + Iceland + Norway +
//!   Singapore + Uruguay). До 2 могут быть скомпрометированы — threshold 3-of-5
//!   гарантирует, что меньше 3 не могут восстановить secret. Это formal
//!   verification property из Pedersen 1991 + Komlo-Goldberg 2020.
//! - Устройство пользователя может быть скомпрометировано (jailbreak, root, lldb,
//!   StrongBox vendor НСЛ). На устройстве **нет** identity-secret для exfiltration.
//! - Пользователь под физическим принуждением может ввести «duress PIN» (reverse
//!   PIN). Серверы получают `UNRECOVERABLE_DELETE` параллельно и удаляют доли;
//!   через несколько секунд аккаунт удалён с лица земли.
//!
//! ## Universal entry rule
//!
//! ```text
//! PIN → 24-word recovery (+OTP) → 12-word emergency → permanent delete
//! ```
//!
//! - Daily unlock: PIN. 3 wrong PIN → escalate to 24-word + OTP.
//! - 3 wrong 24-word → escalate to 12-word emergency.
//! - 5 wrong 12-word → permanent delete (irreversible).
//! - Reverse PIN at any prompt → duress (UNRECOVERABLE_DELETE).
//!
//! ## Architecture overview
//!
//! ```text
//!   Device                 Servers (5 of N, threshold 3)
//!   ──────                 ──────────────────────────────
//!   PIN ─┬─────► Argon2id ┌── Server A: encrypted share_A ─┐
//!        │  (mem=64MiB,   │                                │
//!        │   iter=3, p=4) │── Server B: encrypted share_B ─┤
//!        │                │                                │── DKG ──► identity_pk
//!        │                │── Server C: encrypted share_C ─┤    (Pedersen-VSS)
//!        │                │                                │
//!        │                ├── Server D: encrypted share_D ─┤
//!        │                │                                │
//!        │                └── Server E: encrypted share_E ─┘
//!        │
//!        └─► (PIN_KDF || server_share || device_random || transcript)
//!                          │
//!                          ▼
//!                  HKDF-Expand-Label
//!                          │
//!                  ┌───────┴───────┐
//!                  │               │
//!              device_key      master_key
//!              (per-device)    (account-wide)
//! ```
//!
//! ## Crate layout
//!
//! - [`dkg`] — Pedersen-VSS 3-round handshake between 5 servers via `frost-ed25519`.
//!   Output: each server holds one `KeyPackage`, no server holds full secret.
//! - [`signing`] — Threshold signing protocol (any 3-of-5 sign). Used for rare
//!   operations: rotate device-key, add new device, revoke device, confirm recovery.
//! - [`account_state`] — Server-side state: encrypted PIN-derived envelopes,
//!   anonymous account IDs (one per server, never correlated), attempt counters,
//!   time-lock states, push channels.
//! - [`attempt_counter`] — `PIN: 3 → 24w; 24w: 3 → 12w; 12w: 5 → delete` lock-out
//!   state machine. Persistent counters survive server restart.
//! - [`time_lock`] — 24-hour time-lock recovery requests + push to primary device.
//!   Primary device can cancel. Optional 1-hour acceleration via old PIN.
//! - [`duress`] — Reverse PIN detection + parallel `UNRECOVERABLE_DELETE` across
//!   all 5 servers + indistinguishable «account not found» UX afterward.
//! - [`dead_man`] — Opt-in dead-man switch: no heartbeat for N days → automatic
//!   share wipe.
//! - [`transport`] — Resilient transport selector: TLS direct → Tor SOCKS proxy
//!   → mixnet → alternative IPs. Each subsequent fallback adds 200-1000ms latency.
//! - [`offline_ticket`] — 24h short-lived offline auth token: device can operate
//!   without server contact for ≤24h after successful unlock.
//! - [`anonymous_id`] — Zero-knowledge account IDs: each of 5 servers has a
//!   different anonymous handle for the same user, cross-server correlation
//!   impossible without `master_key` (which device never persists).
//! - [`pin_kdf`] — Argon2id with `mem=64MiB, iter=3, parallelism=4` per
//!   Biryukov-Khovratovich 2016 mobile-friendly recommendation. Output:
//!   `[u8; 32]` rooted in `MlockedSecret` from `umbrella-crypto-primitives`.
//! - [`key_derivation`] — HKDF-SHA256 re-derivation of `device_key` /
//!   `master_key` from `(PIN_KDF || server_share || device_random || transcript)`.
//!
//! ## Acceptance gate
//!
//! Per round-6 spec §«Stage 1 — Server-side infrastructure»: FROST DKG protocol
//! works between 5 mock servers, threshold sign passes Ed25519 verification.
//! See `tests/dkg_e2e.rs` + `tests/threshold_sign.rs`.

#![warn(missing_docs)]
#![deny(rust_2018_idioms)]
#![deny(elided_lifetimes_in_paths)]

pub mod account_state;
pub mod anonymous_id;
pub mod attempt_counter;
pub mod dead_man;
pub mod dkg;
pub mod duress;
pub mod error;
pub mod key_derivation;
pub mod offline_ticket;
pub mod pin_kdf;
pub mod signing;
pub mod time_lock;
pub mod transport;

pub use error::{ThresholdIdentityError, ThresholdIdentityResult};

/// Топология кластера — 5 серверов, threshold 3-of-5 по архитектуре раунда 6.
///
/// Cluster topology — fixed at 5 servers, threshold 3-of-5 per design.
/// Selected per Pedersen 1991 §4 (3-of-5 minimises both safety and liveness
/// failure probability for nation-state adversary model with up to 2
/// compromised servers).
pub const TOTAL_SERVERS: u16 = 5;

/// Порог — 3 из 5 серверов требуется для восстановления share либо threshold-sign.
/// Threshold — 3 of 5 required to reconstruct any secret share or sign.
pub const THRESHOLD: u16 = 3;

/// Срок жизни offline-тикета — 24 часа.
/// 24-hour offline-ticket validity.
pub const OFFLINE_TICKET_VALIDITY_SECS: u64 = 24 * 60 * 60;

/// Дефолтный time-lock на восстановление нового устройства — 24 часа.
/// Default time-lock for new device recovery (24h).
pub const RECOVERY_TIME_LOCK_SECS: u64 = 24 * 60 * 60;

/// Ускоренный time-lock при наличии старого PIN — 1 час.
/// Accelerated time-lock when old PIN is provided (1h).
pub const RECOVERY_TIME_LOCK_ACCELERATED_SECS: u64 = 60 * 60;

/// Лимит ошибок PIN до эскалации к 24-словной recovery.
/// Wrong-PIN threshold before escalation to 24-word recovery.
pub const WRONG_PIN_LIMIT: u8 = 3;

/// Лимит ошибок 24-словной recovery до эскалации к 12-словной emergency.
/// Wrong-24-word-recovery threshold before escalation to 12-word emergency.
pub const WRONG_24WORD_LIMIT: u8 = 3;

/// Лимит ошибок 12-словной emergency до permanent delete (UNRECOVERABLE).
/// Wrong-12-word-emergency threshold before permanent delete.
pub const WRONG_12WORD_LIMIT: u8 = 5;

/// Интервал heartbeat — устройство пингует серверы каждые 30 сек пока активно.
/// Heartbeat interval — device pings servers every 30 sec while active.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
