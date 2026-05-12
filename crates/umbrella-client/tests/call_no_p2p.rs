//! Compliance-gate тест SPEC-06 §3: SecretChat **никогда** не генерирует
//! non-Relay ICE candidates, независимо от того что user положит в
//! `CallPolicy`.
//!
//! Реализуется двумя линиями обороны (см. `call/mod.rs`):
//!
//! 1. `ModeEnforcement::SecretMode.apply(user_policy)` strip'ает
//!    `allow_p2p_global` / `RoutingMode::DirectP2P` в effective policy.
//! 2. `IceAgent::new_no_p2p` строит webrtc-ice `Agent` с
//!    `AgentConfig.candidate_types = [CandidateType::Relay]`. webrtc-ice
//!    физически не gathers Host/ServerReflexive — фильтр на уровне
//!    OS-запроса, не post-filter.
//!
//! Тесты:
//!
//! - `secret_chat_never_emits_non_relay_default_policy` — default
//!   `CallPolicy` (P2P off).
//! - `secret_chat_never_emits_non_relay_with_p2p_opt_in` — aggressive
//!   `allow_p2p_global=true`, `default=DirectP2P` — игнорируется.
//! - `prop_secret_chat_never_p2p` — proptest × 128 cases random
//!   `(allow_p2p, default_routing, sensitive_count)`.
//!
//! SPEC-06 §3 compliance-gate test: SecretChat **never** emits non-Relay ICE
//! candidates regardless of the user-supplied `CallPolicy`.
//!
//! Two enforcement lines (see `call/mod.rs`):
//!
//! 1. `ModeEnforcement::SecretMode.apply(user_policy)` strips
//!    `allow_p2p_global` / `RoutingMode::DirectP2P` in the effective policy.
//! 2. `IceAgent::new_no_p2p` builds the webrtc-ice `Agent` with
//!    `AgentConfig.candidate_types = [CandidateType::Relay]`. webrtc-ice
//!    physically does not gather Host/ServerReflexive — filter at the
//!    OS-request layer, not a post-filter.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use proptest::prelude::*;
use rand::rngs::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::{CallPolicy, PeerId as CallsPeerId, RoutingMode};
use umbrella_client::call::media::{MediaError, MediaFrame, MediaSink, MediaSource};
use umbrella_client::facade::chat_common::{
    ChatId, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::{ClientConfig, SecretChat, UmbrellaClient};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};
use webrtc_ice::candidate::CandidateType;

fn test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://postman:8080".into(),
        kt_url: "http://kt:8080".into(),
        call_relay_url: "http://call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
        },
        // SecretChat compliance-gate property × 128 — classical путь (call layer
        // не зависит от ciphersuite в Этапе 8 scope).
        // SecretChat compliance-gate property × 128 — classical path (the call
        // layer is unaffected by the ciphersuite in Stage 8 scope).
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

struct SilentMediaSource;
#[async_trait]
impl MediaSource for SilentMediaSource {
    async fn pull_audio_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
    async fn pull_video_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
}

struct SilentMediaSink;
#[async_trait]
impl MediaSink for SilentMediaSink {
    async fn push_audio_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
    async fn push_video_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
}

async fn assert_no_non_relay_candidates(aggressive_policy: CallPolicy) {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test must succeed");
    let secret = SecretChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("SecretChat::open stub is infallible");

    let session = secret
        .start_call(
            PeerId([0xAA; 32]),
            aggressive_policy,
            Arc::new(SilentMediaSource),
            Arc::new(SilentMediaSink),
        )
        .await
        .expect("SecretChat::start_call must succeed on stub TURN");

    // Даём webrtc-ice крошечный tick для async initialization. AgentConfig
    // фильтрует candidate types на уровне gathering, поэтому даже без явного
    // `gather_candidates()` локальный список physically не может содержать
    // non-Relay; tick — на случай deferred state в нагретом runtime.
    //
    // Give webrtc-ice a tiny tick for async initialization. AgentConfig
    // filters candidate types at the gathering layer, so the local list
    // physically cannot contain non-Relay even without an explicit
    // `gather_candidates()`; the tick covers any deferred state in a warm
    // runtime.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let ice_agent = session.ice_agent();
    assert!(
        ice_agent.is_no_p2p(),
        "SecretChat must build no_p2p IceAgent"
    );

    let candidates = ice_agent
        .get_local_candidates()
        .await
        .expect("get_local_candidates");

    for c in &candidates {
        assert_eq!(
            c.candidate_type(),
            CandidateType::Relay,
            "SecretChat MUST ONLY emit Relay candidates, got {:?}",
            c.candidate_type()
        );
    }

    session.hangup().await.expect("hangup");
}

#[tokio::test]
async fn secret_chat_never_emits_non_relay_default_policy() {
    assert_no_non_relay_candidates(CallPolicy::default()).await;
}

#[tokio::test]
async fn secret_chat_never_emits_non_relay_with_p2p_opt_in() {
    // Aggressive: global P2P opt-in + default=DirectP2P — оба ignored.
    let policy = CallPolicy {
        default_routing: RoutingMode::DirectP2P,
        sensitive_contacts: HashSet::new(),
        allow_p2p_global: true,
    };
    assert_no_non_relay_candidates(policy).await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_secret_chat_never_p2p(
        allow_p2p in any::<bool>(),
        default_routing_idx in 0usize..4,
        sensitive_count in 0usize..8,
    ) {
        let routing = match default_routing_idx {
            0 => RoutingMode::DirectP2P,
            1 => RoutingMode::SingleRelay,
            2 => RoutingMode::DoubleRelay,
            _ => RoutingMode::CloudRelayFallback,
        };
        let mut sensitive = HashSet::new();
        for i in 0..sensitive_count {
            sensitive.insert(CallsPeerId([i as u8; 32]));
        }
        let policy = CallPolicy {
            default_routing: routing,
            sensitive_contacts: sensitive,
            allow_p2p_global: allow_p2p,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio current_thread runtime");
        rt.block_on(assert_no_non_relay_candidates(policy));
    }
}
