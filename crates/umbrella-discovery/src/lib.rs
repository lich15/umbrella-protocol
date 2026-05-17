//! Round 7 PhD-B: Private contact discovery + @username lookup.
//!
//! Round 7 PhD-B: Private contact discovery + @username lookup.
//!
//! ## Цели
//!
//! - **Phone-number PSI:** клиент узнаёт `S_client ∩ S_server` без раскрытия
//!   `S_client` серверу (Pinkas-Rosulek-Trieu-Yanai 2018 §3.1, base OPRF-PSI).
//! - **Username lookup:** `@handle → device_pubkey` через OPRF + KT-bind,
//!   без раскрытия handle серверу.
//! - **KT-bind:** discovery ответ обязан содержать verifiable Merkle inclusion
//!   proof в текущей KT эпохе — silent swap detected.
//! - **Threshold 3-of-5:** до 2 of 5 серверов compromised — privacy сохраняется.
//!
//! ## Goals
//!
//! - **Phone-number PSI:** client learns `S_client ∩ S_server` without
//!   revealing `S_client` (Pinkas-Rosulek-Trieu-Yanai 2018 §3.1, base
//!   OPRF-PSI).
//! - **Username lookup:** `@handle → device_pubkey` via OPRF + KT bind,
//!   without revealing handle.
//! - **KT bind:** discovery answer must include verifiable Merkle inclusion
//!   proof in the current KT epoch — silent swap is detected.
//! - **Threshold 3-of-5:** up to 2 of 5 servers compromised — privacy is
//!   preserved.
//!
//! ## Структура крейта
//!
//! - [`anonymous_query`] — per-query anonymous-id derivation (HKDF over
//!   master_key + server_id + salt).
//! - [`error`] — единая иерархия [`DiscoveryError`] / [`KtBindKind`].
//! - [`kt_bind`] — Merkle inclusion proof verifier для discovery answers.
//! - [`psi`] — OPRF-PSI protocol (client + server-mock).
//! - [`rate_limit`] — client-side budget + nonce replay guard.
//! - [`username_lookup`] — `@handle → device_pubkey` lookup.
//! - [`wire`] — canonical wire-formats.
//!
//! ## Crate layout
//!
//! See module list above.
//!
//! ## Связь с другими crates
//!
//! | Зависимость | Зачем |
//! |---|---|
//! | [`umbrella-oprf`] | Ristretto255 OPRF primitives + Shamir 3-of-5 |
//! | [`umbrella-threshold-identity`] | Anonymous-id derivation pattern (round 6) |
//! | [`umbrella-kt`] | RFC 6962 Merkle inclusion proof verifier |
//!
//! ## Dependencies
//!
//! - [`umbrella-oprf`] — Ristretto255 OPRF primitives + Shamir 3-of-5.
//! - [`umbrella-threshold-identity`] — anonymous-id derivation pattern
//!   (round 6).
//! - [`umbrella-kt`] — RFC 6962 Merkle inclusion proof verifier.
//!
//! ## Литература
//!
//! - Pinkas, Rosulek, Trieu, Yanai 2018 — "SpOT-Light: Lightweight Private
//!   Set Intersection from Sparse OT Extension", CRYPTO 2018.
//! - Kales, Rindal, Rosulek, Trieu, Yanai 2019 — "Mobile Private Contact
//!   Discovery at Scale", USENIX Security 2019.
//! - Lindell 2017 — "How to Simulate It — A Tutorial on the Simulation Proof
//!   Technique".
//! - Hazay, Lindell 2010 — "Efficient Protocols for Set Intersection and
//!   Pattern Matching with Security Against Malicious and Covert
//!   Adversaries".
//! - Kissner, Song 2005 — "Privacy-Preserving Set Operations".
//! - RFC 9497 — "Oblivious Pseudorandom Functions (OPRFs) using Prime-Order
//!   Groups".
//! - Signal Blog 2017 — "Private Contact Discovery for Signal" (SGX-based,
//!   what we DON'T use).
//! - Apple Engineering 2021 — "Apple PSI System" (CSAM detection PSI).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anonymous_query;
pub mod error;
pub mod kt_bind;
pub mod psi;
pub mod rate_limit;
pub mod username_lookup;
pub mod wire;

pub use anonymous_query::{
    derive_per_query_anon_id, derive_per_query_anon_ids_all_servers, fresh_query_salt,
    ANON_ID_LEN, PER_QUERY_ANON_ID_LABEL, SALT_LEN,
};
pub use error::{DiscoveryError, DiscoveryResult, KtBindKind};
pub use kt_bind::{
    canonical_leaf_payload, verify_discovery_bind, DiscoveryBindExpectation,
    DISCOVERY_LEAF_DOMAIN,
};
pub use psi::{
    derive_per_contact_anon_ids, finalize_psi_query, intersect_with_server_table,
    prepare_psi_query, psi_server_respond, simulate_server_table, PsiQueryState,
};
pub use rate_limit::{
    ClientBudgetState, DiscoveryClock, MockClock, NonceReplayGuard, SystemClock,
    DEFAULT_BUDGET_PER_DAY, DEFAULT_BUDGET_PER_HOUR, MIN_BACKOFF_SECS, NONCE_WINDOW_SIZE,
};
pub use username_lookup::{
    derive_aead_key_from_label, finalize_username_query, prepare_username_query,
    username_server_respond, UsernameQueryState, AEAD_KEY_LEN, AEAD_NONCE_LEN,
    USERNAME_AEAD_KEY_LABEL,
};
pub use wire::{
    KtInclusionProof, PsiQueryEntry, PsiRequest, PsiResponse, PsiResponseEntry, UsernameRequest,
    UsernameResponse, DEVICE_PUBKEY_LEN, LABEL_LEN, MAX_INPUT_BYTES, MAX_PSI_BATCH,
    MAX_USERNAME_RECORD_LEN, NODE_HASH_LEN, POINT_LEN, SERVER_NONCE_LEN, TRANSCRIPT_TAG_LEN,
    WIRE_VERSION,
};
