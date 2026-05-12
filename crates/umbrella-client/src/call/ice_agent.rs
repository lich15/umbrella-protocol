//! `IceAgent` — обёртка над [`webrtc_ice::agent::Agent`] с поддержкой двух
//! режимов gathering:
//!
//! - [`IceAgent::new_with_p2p`] — `Host + ServerReflexive + Relay` candidate
//!   types. Используется CloudChat при `allow_p2p_global = true`.
//! - [`IceAgent::new_no_p2p`] — **только** `Relay`. SecretChat compliance-gate
//!   (SPEC-06 §3): direct P2P физически невозможен на уровне webrtc-ice
//!   gathering, не runtime-check.
//!
//! `AgentConfig.candidate_types` ограничивает webrtc-ice на уровне
//! gathering — не filter поверх готового списка, а фильтр при запросе
//! candidates у OS-уровня.
//!
//! `IceAgent` wraps [`webrtc_ice::agent::Agent`] with two gathering modes:
//!
//! - [`IceAgent::new_with_p2p`] — `Host + ServerReflexive + Relay` candidate
//!   types. Used by CloudChat when `allow_p2p_global = true`.
//! - [`IceAgent::new_no_p2p`] — **only** `Relay`. SecretChat compliance-gate
//!   (SPEC-06 §3): direct P2P is physically impossible at the webrtc-ice
//!   gathering layer, not a runtime check.
//!
//! `AgentConfig.candidate_types` restricts webrtc-ice at the gathering layer —
//! not a post-filter over a ready list, but a filter when asking the OS for
//! candidates.

use std::sync::Arc;

use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::agent::Agent;
use webrtc_ice::candidate::{Candidate, CandidateType};
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::url::Url as IceUrl;

use crate::ClientError;

/// Конфигурация TURN-сервера для `Relay` candidates. `url` — формат
/// `turn:host:port?transport=udp` (webrtc-ice [`IceUrl::parse_url`]).
///
/// TURN server configuration for `Relay` candidates. `url` follows
/// `turn:host:port?transport=udp` (webrtc-ice [`IceUrl::parse_url`]).
#[derive(Debug, Clone)]
pub struct TurnConfig {
    /// TURN server URL — например `turn:relay.example.com:3478?transport=udp`.
    ///
    /// TURN server URL, e.g. `turn:relay.example.com:3478?transport=udp`.
    pub url: String,
    /// TURN long-term credential username (RFC 8489 §9.2.3).
    ///
    /// TURN long-term credential username (RFC 8489 §9.2.3).
    pub username: String,
    /// TURN long-term credential password / HMAC key.
    ///
    /// TURN long-term credential password / HMAC key.
    pub password: String,
}

/// `IceAgent` — обёртка над [`Agent`] с флагом `no_p2p` для compliance-gate
/// проверки (SecretChat в Блоке 7.6).
///
/// `IceAgent` wraps [`Agent`] with a `no_p2p` flag for compliance-gate checks
/// (SecretChat in Block 7.6).
pub struct IceAgent {
    inner: Arc<Agent>,
    no_p2p: bool,
}

// `webrtc_ice::agent::Agent` does not implement `Debug`, so `Debug` for
// `IceAgent` is provided manually — exposes only the publicly observable
// `no_p2p` flag.
impl std::fmt::Debug for IceAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceAgent")
            .field("no_p2p", &self.no_p2p)
            .finish_non_exhaustive()
    }
}

impl IceAgent {
    /// Normal mode — `Host + ServerReflexive + Relay` candidate types.
    /// Используется CloudChat при `allow_p2p_global = true`.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Network`] если TURN URL невалиден или
    ///   [`Agent::new`] упал.
    ///
    /// Normal mode — `Host + ServerReflexive + Relay` candidate types. Used by
    /// CloudChat when `allow_p2p_global = true`.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Network`] if the TURN URL is invalid or
    ///   [`Agent::new`] fails.
    pub async fn new_with_p2p(turn: TurnConfig) -> Result<Self, ClientError> {
        let cfg = AgentConfig {
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            candidate_types: vec![
                CandidateType::Host,
                CandidateType::ServerReflexive,
                CandidateType::Relay,
            ],
            urls: vec![parse_turn_url(&turn)?],
            ..AgentConfig::default()
        };

        let agent = Agent::new(cfg)
            .await
            .map_err(|e| ClientError::Network(format!("ice agent: {e}")))?;

        Ok(Self {
            inner: Arc::new(agent),
            no_p2p: false,
        })
    }

    /// No-P2P mode — **только** `Relay` candidates. Compliance-gate для
    /// SecretChat (SPEC-06 §3): direct P2P физически невозможен — webrtc-ice
    /// не gathers Host/ServerReflexive на основе
    /// `AgentConfig.candidate_types`.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Network`] если TURN URL невалиден или
    ///   [`Agent::new`] упал.
    ///
    /// No-P2P mode — **only** `Relay` candidates. SecretChat compliance-gate
    /// (SPEC-06 §3): direct P2P is physically impossible — webrtc-ice does
    /// not gather Host/ServerReflexive based on
    /// `AgentConfig.candidate_types`.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Network`] if the TURN URL is invalid or
    ///   [`Agent::new`] fails.
    pub async fn new_no_p2p(turn: TurnConfig) -> Result<Self, ClientError> {
        let cfg = AgentConfig {
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            // CRITICAL: only Relay. No Host, no ServerReflexive.
            candidate_types: vec![CandidateType::Relay],
            urls: vec![parse_turn_url(&turn)?],
            ..AgentConfig::default()
        };

        let agent = Agent::new(cfg)
            .await
            .map_err(|e| ClientError::Network(format!("ice agent no-p2p: {e}")))?;

        Ok(Self {
            inner: Arc::new(agent),
            no_p2p: true,
        })
    }

    /// Список локальных ICE candidates после gathering.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Network`] если внутренний [`Agent::get_local_candidates`]
    ///   провалился.
    ///
    /// Local ICE candidates after gathering.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Network`] if the inner [`Agent::get_local_candidates`]
    ///   call failed.
    pub async fn get_local_candidates(
        &self,
    ) -> Result<Vec<Arc<dyn Candidate + Send + Sync>>, ClientError> {
        self.inner
            .get_local_candidates()
            .await
            .map_err(|e| ClientError::Network(format!("get candidates: {e}")))
    }

    /// `true` если agent создан в no-P2P режиме (SecretChat).
    ///
    /// `true` when the agent was built in no-P2P mode (SecretChat).
    #[must_use]
    pub fn is_no_p2p(&self) -> bool {
        self.no_p2p
    }

    /// Ссылка на внутренний [`Agent`] — для integration с DTLS handshake
    /// slots в блоке 7.10.
    ///
    /// Inner [`Agent`] reference — used by DTLS handshake integration in
    /// Block 7.10.
    #[must_use]
    pub fn inner(&self) -> Arc<Agent> {
        self.inner.clone()
    }
}

// `webrtc_ice::url::Url::parse_url` следует RFC 7064/7065: в query допустим
// только `transport=...`. TURN long-term credentials хранятся в полях
// `username` / `password` структуры `Url` и заполняются после парсинга.
//
// `webrtc_ice::url::Url::parse_url` follows RFC 7064/7065: only `transport=…`
// is permitted in the query. TURN long-term credentials live in the `username`
// / `password` fields of `Url` and are filled in after parsing.
fn parse_turn_url(turn: &TurnConfig) -> Result<IceUrl, ClientError> {
    let mut url = IceUrl::parse_url(&turn.url)
        .map_err(|e| ClientError::Network(format!("parse turn url: {e}")))?;
    url.username = turn.username.clone();
    url.password = turn.password.clone();
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_turn() -> TurnConfig {
        TurnConfig {
            url: "turn:relay.localhost:3478?transport=udp".into(),
            username: "test".into(),
            password: "test".into(),
        }
    }

    #[tokio::test]
    async fn new_with_p2p_flag_false() {
        let agent = IceAgent::new_with_p2p(test_turn()).await.unwrap();
        assert!(!agent.is_no_p2p());
    }

    #[tokio::test]
    async fn new_no_p2p_flag_true() {
        let agent = IceAgent::new_no_p2p(test_turn()).await.unwrap();
        assert!(agent.is_no_p2p());
    }

    #[tokio::test]
    async fn invalid_turn_url_errors() {
        let bad = TurnConfig {
            url: "not-a-turn-url".into(),
            username: "u".into(),
            password: "p".into(),
        };
        let err = IceAgent::new_no_p2p(bad).await.unwrap_err();
        assert!(matches!(err, ClientError::Network(_)));
    }

    #[tokio::test]
    async fn inner_returns_same_arc() {
        let agent = IceAgent::new_no_p2p(test_turn()).await.unwrap();
        let a = agent.inner();
        let b = agent.inner();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
