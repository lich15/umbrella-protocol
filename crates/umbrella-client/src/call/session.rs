//! `CallSession` — lifecycle одной 1-1 сессии звонка. ADR-010 Решение 4:
//! `umbrella-client` владеет только сетевым слоем webrtc-rs
//! (ICE + DTLS + SRTP + identity binding); media capture/playback — на
//! native стороне через [`MediaSource`] / [`MediaSink`] callbacks.
//!
//! Compliance-gate SPEC-06 §3 реализован двумя линиями обороны:
//!
//! 1. [`ModeEnforcement`] strip'ает `allow_p2p_global` / `DirectP2P` из
//!    `CallPolicy` при SecretMode.
//! 2. [`IceAgent::new_no_p2p`] строит webrtc-ice `Agent` с
//!    `candidate_types = [Relay]` — direct P2P физически невозможен.
//!
//! `CallSession` — lifecycle of a single 1-1 call. ADR-010 Decision 4:
//! `umbrella-client` owns only the webrtc-rs network layer
//! (ICE + DTLS + SRTP + identity binding); media capture/playback runs on
//! the native side via [`MediaSource`] / [`MediaSink`] callbacks.
//!
//! The SPEC-06 §3 compliance-gate is implemented in two layers:
//!
//! 1. [`ModeEnforcement`] strips `allow_p2p_global` / `DirectP2P` out of the
//!    `CallPolicy` in SecretMode.
//! 2. [`IceAgent::new_no_p2p`] builds the webrtc-ice `Agent` with
//!    `candidate_types = [Relay]` — direct P2P is physically impossible.

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use umbrella_calls::CallPolicy;

use crate::call::dtls_runner::DtlsRunner;
use crate::call::ice_agent::{IceAgent, TurnConfig};
use crate::call::media::{MediaSink, MediaSource};
use crate::call::mode_enforcement::ModeEnforcement;
use crate::call::srtp_pipeline::SrtpPipeline;
use crate::core::ClientCore;
use crate::facade::chat_common::PeerId;
use crate::transport::{CallSecurityLevelWire, TurnAllocation};
use crate::ClientError;

/// UUID-подобный 16-байтовый идентификатор сессии звонка.
/// В Блоке 7.6 генерируется через [`rand::random`]. В Блоке 7.10 интеграция
/// с signalling-слоем принесёт matched pair-IDs c обеих сторон.
///
/// UUID-like 16-byte call session identifier. Block 7.6 generates it via
/// [`rand::random`]. Block 7.10 signalling integration will supply matched
/// pair-IDs on both peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId(pub [u8; 16]);

/// Lifecycle state machine сессии звонка.
///
/// Call session lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Offer/answer обмен через blind-postman-svc.
    /// Signalling offer/answer via blind-postman-svc.
    Signalling,
    /// ICE gathering — сбор candidates.
    /// ICE gathering — collecting candidates.
    IceGathering,
    /// ICE connectivity checks — STUN ping'и по парам candidates.
    /// ICE connectivity checks — STUN pings across candidate pairs.
    IceChecking,
    /// DTLS 1.3 handshake поверх ICE UDP.
    /// DTLS 1.3 handshake over ICE UDP.
    DtlsHandshake,
    /// Handshake завершён, SRTP keying установлен, media flows.
    /// Handshake complete, SRTP keying installed, media flows.
    Connected,
    /// Temporary disconnection — ICE restart in flight.
    /// Temporary disconnection — ICE restart in flight.
    Reconnecting,
    /// Сессия окончательно завершена.
    /// Session terminated.
    Terminated(CallTerminationReason),
}

/// Причина завершения сессии.
///
/// Call termination reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTerminationReason {
    /// Локальный пользователь положил трубку.
    /// Local user hung up.
    LocalHangup,
    /// Удалённый peer положил трубку.
    /// Remote peer hung up.
    RemoteHangup,
    /// ICE не смог установить connectivity.
    /// ICE failed to establish connectivity.
    IceFailure,
    /// DTLS handshake провалился.
    /// DTLS handshake failed.
    DtlsFailure,
    /// Identity binding — remote fingerprint не совпал с expected.
    /// Identity binding — remote fingerprint didn't match expected.
    IdentityMismatch,
    /// Сетевая ошибка (TURN allocation, loss of connectivity).
    /// Network error (TURN allocation, loss of connectivity).
    NetworkError,
}

/// `CallSession` — одна 1-1 сессия звонка.
///
/// `CallSession` — a single 1-1 call session.
#[allow(dead_code)] // Block 7.6 scaffolding — readers appear in 7.10 integration.
pub struct CallSession {
    core: Arc<ClientCore>,
    call_id: CallId,
    peer: PeerId,
    effective_policy: CallPolicy,
    state: Arc<RwLock<CallState>>,
    ice_agent: Arc<IceAgent>,
    dtls_runner: Arc<Mutex<DtlsRunner>>,
    srtp_pipeline: Arc<SrtpPipeline>,
    media_source: Arc<dyn MediaSource>,
    media_sink: Arc<dyn MediaSink>,
}

// `Arc<dyn MediaSource>` / `Arc<dyn MediaSink>` are not `Debug`, so
// `CallSession`'s `Debug` is provided manually with the publicly observable
// fields. Used by `Result::unwrap()` in tests and panic messages.
impl std::fmt::Debug for CallSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallSession")
            .field("call_id", &self.call_id)
            .field("peer", &self.peer)
            .field("effective_policy", &self.effective_policy)
            .finish_non_exhaustive()
    }
}

impl CallSession {
    /// Создаёт сессию с заданным enforcement-режимом.
    ///
    /// Пайплайн:
    ///
    /// 1. `enforcement.apply(user_policy)` → `effective_policy`.
    /// 2. TURN config allocation (stub в блоке 7.6; real allocation через
    ///    `call_relay_transport` в 7.10 milestone).
    /// 3. `IceAgent::new_with_p2p` если CloudMode и `allow_p2p_global = true`,
    ///    иначе `IceAgent::new_no_p2p` (compliance-gate).
    /// 4. `DtlsRunner::new` с derived `IdentityDtlsFingerprint` из локального
    ///    identity pubkey и random `session_nonce`.
    /// 5. `SrtpPipeline::new` — пустой; keying устанавливается после DTLS.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Network`] если ICE agent construction провалился
    ///   (invalid TURN URL, underlying webrtc-ice error).
    ///
    /// Builds a session with the given enforcement mode.
    ///
    /// Pipeline:
    ///
    /// 1. `enforcement.apply(user_policy)` → `effective_policy`.
    /// 2. TURN config allocation (stub in Block 7.6; real allocation via
    ///    `call_relay_transport` in the 7.10 milestone).
    /// 3. `IceAgent::new_with_p2p` when CloudMode with `allow_p2p_global =
    ///    true`; otherwise `IceAgent::new_no_p2p` (compliance-gate).
    /// 4. `DtlsRunner::new` with a derived `IdentityDtlsFingerprint` from the
    ///    local identity pubkey and a random `session_nonce`.
    /// 5. `SrtpPipeline::new` — empty; keying is installed after DTLS.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Network`] if ICE agent construction failed (invalid
    ///   TURN URL, underlying webrtc-ice error).
    pub async fn start_with_enforcement(
        core: Arc<ClientCore>,
        peer: PeerId,
        user_policy: CallPolicy,
        enforcement: ModeEnforcement,
        media_source: Arc<dyn MediaSource>,
        media_sink: Arc<dyn MediaSink>,
    ) -> Result<Self, ClientError> {
        let effective_policy = enforcement.apply(user_policy);
        let call_id = CallId(rand::random());

        // **F-CLIENT-FACADE-1 session 10a (2026-05-19):** TURN credential
        // allocation now flows through `core.call_relay_transport` instead
        // of a hardcoded placeholder URL. `security_level` derives from
        // the enforced mode + effective policy (compliance-gate carried
        // into the server-visible allocation request):
        //
        // - **SecretMode**: always `Sensitive` — relay-only invariant
        //   propagates to the server's TURN allocation policy.
        // - **CloudMode + `allow_p2p_global = true`**: `AllowP2pGlobal` —
        //   server may relax direct-p2p restrictions.
        // - **CloudMode + `allow_p2p_global = false`**: `Sensitive` —
        //   even in Cloud, the relay-only path is server-enforced.
        //
        // Stub call-relay returns a deterministic [`TurnAllocation`]; the
        // production [`crate::transport::Http2CallRelayTransport`] does
        // a real HTTP/2 round-trip. Either way the result is mapped into
        // [`TurnConfig`] (the webrtc-ice-facing struct).
        let security_level = derive_call_security_level(enforcement, &effective_policy);
        let allocation = core
            .call_relay_transport
            .allocate(peer.0, security_level)
            .await?;
        let turn = turn_config_from_allocation(&allocation);

        let ice_agent = match enforcement {
            ModeEnforcement::CloudMode if effective_policy.allow_p2p_global => {
                IceAgent::new_with_p2p(turn).await?
            }
            _ => IceAgent::new_no_p2p(turn).await?,
        };

        // F-CLIENT-HW-1 closure: route public-key fetch through the
        // unified accessor so HW-backed cores (where `core.identity` is
        // `None`) supply the verifying-key from the cached
        // `hw_verifying_key`. Pre-closure call site read
        // `core.identity.public().to_bytes()` directly, which forced
        // `new_with_hw_callback` to synthesise an ephemeral identity
        // seed (M-FINAL-1 gap, now closed).
        let identity_pub = core.identity_verifying_key()?;
        let session_nonce: [u8; 16] = rand::random();
        let dtls = DtlsRunner::new(identity_pub, session_nonce);

        Ok(Self {
            core,
            call_id,
            peer,
            effective_policy,
            state: Arc::new(RwLock::new(CallState::Signalling)),
            ice_agent: Arc::new(ice_agent),
            dtls_runner: Arc::new(Mutex::new(dtls)),
            srtp_pipeline: Arc::new(SrtpPipeline::new()),
            media_source,
            media_sink,
        })
    }

    /// Идентификатор сессии.
    ///
    /// Session identifier.
    #[must_use]
    pub fn call_id(&self) -> CallId {
        self.call_id
    }

    /// Идентификатор удалённого peer'а.
    ///
    /// Remote peer identifier.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Текущий state (async — state под `RwLock`).
    ///
    /// Current state (async — state sits behind `RwLock`).
    pub async fn state(&self) -> CallState {
        *self.state.read().await
    }

    /// Эффективный policy, применённый после enforcement.
    ///
    /// Effective policy after enforcement has been applied.
    #[must_use]
    pub fn effective_policy(&self) -> &CallPolicy {
        &self.effective_policy
    }

    /// Ссылка на внутренний [`IceAgent`] (для compliance-gate тестов).
    ///
    /// Inner [`IceAgent`] reference (used by compliance-gate tests).
    #[must_use]
    pub fn ice_agent(&self) -> Arc<IceAgent> {
        self.ice_agent.clone()
    }

    /// Локальный hangup — переводит state в `Terminated(LocalHangup)`.
    ///
    /// # Ошибки / Errors
    ///
    /// В блоке 7.6 инфallible; в 7.10 может вернуть [`ClientError::Network`]
    /// если нужно послать `BYE` через signalling.
    ///
    /// Local hangup — transitions state to `Terminated(LocalHangup)`.
    ///
    /// # Errors
    ///
    /// Infallible in Block 7.6; Block 7.10 may return [`ClientError::Network`]
    /// if a `BYE` must be posted through signalling.
    pub async fn hangup(&self) -> Result<(), ClientError> {
        *self.state.write().await = CallState::Terminated(CallTerminationReason::LocalHangup);
        Ok(())
    }
}

/// **F-CLIENT-FACADE-1 session 10a (2026-05-19):** map enforcement mode +
/// effective policy → server-visible [`CallSecurityLevelWire`]. The
/// server's TURN allocation policy reads this tag and decides whether
/// to issue p2p-friendly credentials или forced-relay credentials —
/// the client's compliance-gate (SPEC-06 §3) propagates into the
/// server's allocation invariant.
///
/// **Mapping rationale**:
///
/// - `SecretMode` → `Sensitive` regardless of policy: SecretChat is
///   relay-only by protocol, the server must enforce this even if a
///   client implementation misbehaves.
/// - `CloudMode + allow_p2p_global = true` → `AllowP2pGlobal`: user
///   explicitly opted into the relaxed allocation policy.
/// - `CloudMode + allow_p2p_global = false` → `Sensitive`: default
///   conservative path even in Cloud.
///
/// `Default` (least restrictive) is **not** reachable from the
/// current client-side enforcement matrix; reserved for future
/// per-call policy overrides (e.g. an explicit "p2p preferred for
/// this call only" toggle).
#[must_use]
fn derive_call_security_level(
    enforcement: ModeEnforcement,
    effective_policy: &CallPolicy,
) -> CallSecurityLevelWire {
    match enforcement {
        ModeEnforcement::SecretMode => CallSecurityLevelWire::Sensitive,
        ModeEnforcement::CloudMode if effective_policy.allow_p2p_global => {
            CallSecurityLevelWire::AllowP2pGlobal
        }
        ModeEnforcement::CloudMode => CallSecurityLevelWire::Sensitive,
    }
}

/// **F-CLIENT-FACADE-1 session 10a (2026-05-19):** lower a
/// [`TurnAllocation`] (server-wire shape) into the webrtc-ice-facing
/// [`TurnConfig`]. Drops the secondary URL + expiry metadata — only
/// primary credentials are passed into `webrtc-ice` agent config in
/// Block 7.6; secondary URL routing + credential refresh on expiry are
/// follow-up work.
///
/// **Field mapping**:
///
/// - `TurnConfig::url` ← `TurnAllocation::primary_url`
/// - `TurnConfig::username` ← `TurnAllocation::username`
/// - `TurnConfig::password` ← `TurnAllocation::password_hmac_hex` —
///   the HMAC-SHA256 hex string IS the TURN long-term-credential
///   password per RFC 7635 (server pre-computes
///   `HMAC(secret, username)`; client passes it through verbatim
///   to webrtc-ice).
#[must_use]
fn turn_config_from_allocation(allocation: &TurnAllocation) -> TurnConfig {
    TurnConfig {
        url: allocation.primary_url.clone(),
        username: allocation.username.clone(),
        password: allocation.password_hmac_hex.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
    use umbrella_calls::RoutingMode;
    use umbrella_identity::{IdentitySeed, MnemonicLanguage};

    use crate::call::media::{MediaError, MediaFrame};
    use crate::core::{ClientConfig, ClientCore};

    fn test_config() -> ClientConfig {
        use crate::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
        ClientConfig {
            sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
            postman_url: "http://stub-postman:8080".into(),
            kt_url: "http://stub-kt:8080".into(),
            call_relay_url: "http://stub-call-relay:8080".into(),
            kt_monitor_interval_secs: 3600,
            wrapping_params: WrappingParams {
                version: 0x01,
                main_pubkey: [0u8; 32],
                server_pubkeys: [[0u8; 32]; 5],
                config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
            },
            // Inline session unit-tests — classical путь.
            // Inline session unit tests — classical path.
            default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
        }
    }

    fn test_seed() -> IdentitySeed {
        IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
    }

    struct NullSource;
    #[async_trait]
    impl MediaSource for NullSource {
        async fn pull_audio_frame(&self) -> Result<MediaFrame, MediaError> {
            Err(MediaError::Native("test".into()))
        }
        async fn pull_video_frame(&self) -> Result<MediaFrame, MediaError> {
            Err(MediaError::Native("test".into()))
        }
    }

    struct NullSink;
    #[async_trait]
    impl MediaSink for NullSink {
        async fn push_audio_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
            Ok(())
        }
        async fn push_video_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
            Ok(())
        }
    }

    async fn start(enforcement: ModeEnforcement, policy: CallPolicy) -> CallSession {
        let core = ClientCore::new_for_test(test_config(), test_seed())
            .await
            .unwrap();
        CallSession::start_with_enforcement(
            core,
            PeerId([0xAA; 32]),
            policy,
            enforcement,
            Arc::new(NullSource),
            Arc::new(NullSink),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn initial_state_is_signalling() {
        let session = start(ModeEnforcement::CloudMode, CallPolicy::default()).await;
        assert_eq!(session.state().await, CallState::Signalling);
    }

    #[tokio::test]
    async fn hangup_transitions_to_terminated_local() {
        let session = start(ModeEnforcement::CloudMode, CallPolicy::default()).await;
        session.hangup().await.unwrap();
        assert_eq!(
            session.state().await,
            CallState::Terminated(CallTerminationReason::LocalHangup)
        );
    }

    #[tokio::test]
    async fn cloud_mode_with_p2p_uses_p2p_agent() {
        let policy = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: true,
            ..Default::default()
        };
        let session = start(ModeEnforcement::CloudMode, policy).await;
        assert!(!session.ice_agent().is_no_p2p());
    }

    #[tokio::test]
    async fn cloud_mode_without_p2p_uses_no_p2p_agent() {
        // allow_p2p_global = false → effective_policy.allow_p2p_global = false
        // → ice_agent = no_p2p.
        let session = start(ModeEnforcement::CloudMode, CallPolicy::default()).await;
        assert!(session.ice_agent().is_no_p2p());
    }

    #[tokio::test]
    async fn secret_mode_always_uses_no_p2p_agent() {
        let policy = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: true, // user asked for P2P — ignored.
            ..Default::default()
        };
        let session = start(ModeEnforcement::SecretMode, policy).await;
        assert!(session.ice_agent().is_no_p2p());
    }

    #[tokio::test]
    async fn secret_mode_effective_policy_strips_p2p() {
        let policy = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: true,
            ..Default::default()
        };
        let session = start(ModeEnforcement::SecretMode, policy).await;
        let effective = session.effective_policy();
        assert_eq!(effective.default_routing, RoutingMode::SingleRelay);
        assert!(!effective.allow_p2p_global);
    }

    #[tokio::test]
    async fn call_id_is_nonzero_random() {
        let session = start(ModeEnforcement::CloudMode, CallPolicy::default()).await;
        assert_ne!(session.call_id().0, [0u8; 16]);
    }

    #[tokio::test]
    async fn peer_is_recorded() {
        let session = start(ModeEnforcement::CloudMode, CallPolicy::default()).await;
        assert_eq!(session.peer(), PeerId([0xAA; 32]));
    }
}
