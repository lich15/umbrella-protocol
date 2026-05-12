//! `Http2CallRelayTransport` — HTTP/2 клиент к `call-relay-svc` для TURN
//! allocation в 1-1 звонках (design §5.5, SPEC-06 §3).
//!
//! Endpoint:
//! - `POST /turn/allocate` — request TURN credentials для звонка к конкретному
//!   peer'у. Body — JSON `{peer_id_hex, security_level}`; response — JSON
//!   [`TurnAllocation`] с primary/secondary TURN URL и short-lived
//!   credentials (valid_until).
//!
//! `Http2CallRelayTransport` — HTTP/2 client for `call-relay-svc` TURN
//! allocation in 1-1 calls (design §5.5, SPEC-06 §3).

use std::sync::Arc;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// Длина `peer_id` в байтах (Ed25519 identity-pubkey).
/// `peer_id` length in bytes (Ed25519 identity pubkey).
pub const PEER_ID_LEN: usize = 32;

/// TURN allocation ответ от `call-relay-svc`.
///
/// Поля:
/// - `primary_url` — главный TURN сервер (`turns:` URI).
/// - `secondary_url` — fallback TURN сервер (optional, для географического
///   redundancy).
/// - `username` — TURN username (обычно `<expiry_ts>:<peer_id_hex>`).
/// - `password_hmac_hex` — HMAC-SHA256 короткого-живущего password'а
///   (32 bytes, hex-encoded).
/// - `valid_until_ms` — Unix ms истечения credentials.
///
/// TURN allocation response from `call-relay-svc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnAllocation {
    /// Primary TURN URL (`turns:host:port`). Primary TURN URL.
    pub primary_url: String,
    /// Secondary TURN URL (optional). Secondary TURN URL (optional).
    pub secondary_url: Option<String>,
    /// TURN username. TURN username.
    pub username: String,
    /// HMAC-SHA256 TURN password (hex 64 символа).
    /// HMAC-SHA256 TURN password (64-char hex).
    pub password_hmac_hex: String,
    /// Unix ms истечения credentials. Unix ms expiry.
    pub valid_until_ms: u64,
}

/// Security level звонка. Маппится на TURN allocation policy:
/// `Default` — разрешён direct p2p при Cloud mode; `Sensitive` — forced
/// relay через TURN; `AllowP2pGlobal` — user-override (SPEC-06 §3.2).
///
/// Call security level. Maps onto TURN allocation policy: `Default` — direct
/// p2p allowed in Cloud mode; `Sensitive` — forced relay via TURN;
/// `AllowP2pGlobal` — user override (SPEC-06 §3.2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum CallSecurityLevelWire {
    /// Default (Cloud-friendly). Default (Cloud-friendly).
    Default = 0,
    /// Sensitive — forced relay. Sensitive — forced relay.
    Sensitive = 1,
    /// Allow p2p globally (user opt-in). User opted-in p2p globally.
    AllowP2pGlobal = 2,
}

/// HTTP/2 клиент к call-relay-svc. HTTP/2 client for call-relay-svc.
pub struct Http2CallRelayTransport {
    http: Arc<Client>,
    base_url: Url,
}

impl Http2CallRelayTransport {
    /// Создать клиент с `base_url` как корнем `call-relay-svc`.
    /// Construct the client with `base_url` rooted at `call-relay-svc`.
    #[must_use]
    pub fn new(http: Arc<Client>, base_url: Url) -> Self {
        Self { http, base_url }
    }

    /// Запросить TURN credentials для звонка с `peer`.
    ///
    /// Request TURN credentials for a call with `peer`.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках, status != 2xx
    ///   или невалидном JSON ответе.
    pub async fn allocate(
        &self,
        peer_id: [u8; PEER_ID_LEN],
        security_level: CallSecurityLevelWire,
    ) -> Result<TurnAllocation, ClientError> {
        #[derive(Serialize)]
        struct Request<'a> {
            peer_id_hex: &'a str,
            security_level: u8,
        }
        let url = self
            .base_url
            .join("/turn/allocate")
            .map_err(|e| ClientError::Network(format!("url /turn/allocate: {e}")))?;
        let peer_hex = hex::encode(peer_id);
        let body = Request {
            peer_id_hex: &peer_hex,
            security_level: security_level as u8,
        };
        // reqwest собран без feature `json` — сериализуем вручную через
        // serde_json и отправляем как application/json байтовый body.
        //
        // reqwest is built without the `json` feature — serialize manually via
        // serde_json and post as an application/json byte body.
        let payload = serde_json::to_vec(&body)
            .map_err(|e| ClientError::Network(format!("turn allocate serialize: {e}")))?;
        let resp = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("turn allocate: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "turn allocate status {}",
                resp.status()
            )));
        }
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Network(format!("turn allocate body: {e}")))?;
        serde_json::from_slice::<TurnAllocation>(&body_bytes)
            .map_err(|e| ClientError::Network(format!("turn allocate parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_allocation_roundtrip_json() {
        let original = TurnAllocation {
            primary_url: "turns:relay1.example:5349".to_string(),
            secondary_url: Some("turns:relay2.example:5349".to_string()),
            username: "1730000000:peer_abc".to_string(),
            password_hmac_hex: "a".repeat(64),
            valid_until_ms: 1_730_000_000_000,
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: TurnAllocation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.primary_url, original.primary_url);
        assert_eq!(parsed.secondary_url, original.secondary_url);
        assert_eq!(parsed.username, original.username);
        assert_eq!(parsed.password_hmac_hex, original.password_hmac_hex);
        assert_eq!(parsed.valid_until_ms, original.valid_until_ms);
    }

    #[test]
    fn turn_allocation_allows_missing_secondary() {
        let json = r#"{
            "primary_url": "turns:relay.example:5349",
            "username": "x",
            "password_hmac_hex": "00",
            "valid_until_ms": 1
        }"#;
        let parsed: TurnAllocation = serde_json::from_str(json).unwrap();
        assert!(parsed.secondary_url.is_none());
    }

    #[test]
    fn security_level_wire_encoding() {
        assert_eq!(CallSecurityLevelWire::Default as u8, 0);
        assert_eq!(CallSecurityLevelWire::Sensitive as u8, 1);
        assert_eq!(CallSecurityLevelWire::AllowP2pGlobal as u8, 2);
    }
}
