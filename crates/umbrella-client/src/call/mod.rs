//! Call stack: `webrtc-ice` + identity-bound DTLS fingerprint glue +
//! `webrtc-srtp` + mode enforcement.
//!
//! В Этапе 7 блоке 7.6 реализован сетевой слой звонков 1-1:
//! ICE agent (с двумя режимами — с P2P и только Relay), DTLS fingerprint
//! runner (с подстановкой `IdentityDtlsFingerprint` из `umbrella-calls`),
//! SRTP pipeline boundary, media callback interfaces ([`MediaSource`] /
//! [`MediaSink`] — реализация на native iOS/Android). Реальный DTLS engine
//! остаётся отдельной integration boundary и не линкуется в production tree,
//! пока нет поддерживаемого пути без `bincode`.
//!
//! Ключевой compliance-gate этапа — [`ModeEnforcement::SecretMode`]: в
//! SecretChat `IceAgent` создаётся через [`ice_agent::IceAgent::new_no_p2p`]
//! с `AgentConfig.candidate_types = [CandidateType::Relay]`. Direct P2P
//! физически невозможен на уровне webrtc-ice gathering, не runtime-check.
//!
//! Call stack: `webrtc-ice` + identity-bound DTLS fingerprint glue +
//! `webrtc-srtp` + mode enforcement.
//!
//! Stage 7 block 7.6 ships the networking layer for 1-1 calls: ICE agent
//! (with-P2P / Relay-only modes), DTLS fingerprint runner (embeds
//! `IdentityDtlsFingerprint` from `umbrella-calls`), SRTP pipeline boundary,
//! and media callback interfaces ([`MediaSource`] / [`MediaSink`] —
//! implemented on the native iOS/Android side). The actual DTLS engine remains
//! a separate integration boundary and is not linked into the production tree
//! until a maintained path exists without `bincode`.
//!
//! The stage's key compliance-gate is [`ModeEnforcement::SecretMode`]: in
//! SecretChat the `IceAgent` is built through
//! [`ice_agent::IceAgent::new_no_p2p`] with
//! `AgentConfig.candidate_types = [CandidateType::Relay]`. Direct P2P is
//! physically impossible at the webrtc-ice gathering layer, not a runtime
//! check.

pub mod dtls_runner;
pub mod ice_agent;
pub mod media;
pub mod mode_enforcement;
pub mod session;
pub mod srtp_pipeline;

pub use media::{MediaCodec, MediaError, MediaFrame, MediaSink, MediaSource};
pub use mode_enforcement::ModeEnforcement;
pub use session::{CallId, CallSession, CallState, CallTerminationReason};
