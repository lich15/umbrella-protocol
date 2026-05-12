//! `Http2PostmanTransport` — HTTP/2 клиент к `blind-postman-svc` для доставки
//! sealed-sender envelope'ов (design §5.3).
//!
//! Три endpoint'а:
//! - `POST /deliver` — отправить encrypted envelope.
//! - `GET  /inbox?since=<ms>` — long-poll входящих.
//! - `DELETE /inbox/{message_id_hex}` — zero-retention ack (сервер удаляет
//!   envelope при получении DELETE).
//!
//! Wire-format inbox-ответа: length-prefixed binary frames, `u32 BE len ||
//! N bytes`. Это наш контракт с сервером; parse helper — `parse_length_prefixed`.
//!
//! `Http2PostmanTransport` — HTTP/2 client for `blind-postman-svc` that
//! delivers sealed-sender envelopes (design §5.3).
//!
//! Three endpoints:
//! - `POST /deliver` — send an encrypted envelope.
//! - `GET  /inbox?since=<ms>` — long-poll inbound queue.
//! - `DELETE /inbox/{message_id_hex}` — zero-retention ack.
//!
//! Inbox response wire format: length-prefixed binary frames,
//! `u32 BE len || N bytes` per frame — shared with the server.

use std::sync::Arc;

use reqwest::{Client, Url};

use crate::error::ClientError;

/// Длина `message_id` в байтах (128-битный UUID-shaped idempotency key).
/// `message_id` length in bytes (128-bit UUID-shaped idempotency key).
pub const MESSAGE_ID_LEN: usize = 16;

/// HTTP/2 клиент к `blind-postman-svc`.
pub struct Http2PostmanTransport {
    http: Arc<Client>,
    base_url: Url,
}

impl Http2PostmanTransport {
    /// Создать клиент. `base_url` — корневой URL `blind-postman-svc` (без
    /// trailing path); все endpoint'ы резолвятся через [`Url::join`].
    ///
    /// Construct the client. `base_url` — root URL of `blind-postman-svc`
    /// (no trailing path); endpoints are resolved via [`Url::join`].
    #[must_use]
    pub fn new(http: Arc<Client>, base_url: Url) -> Self {
        Self { http, base_url }
    }

    /// Отправить sealed-sender envelope. Идемпотентно по `message_id`,
    /// включённому в payload — сервер dedupes.
    ///
    /// Deliver a sealed-sender envelope. Idempotent by `message_id` carried
    /// inside the payload — the server dedupes.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках или status != 2xx.
    pub async fn deliver(&self, envelope: Vec<u8>) -> Result<(), ClientError> {
        let url = self
            .base_url
            .join("/deliver")
            .map_err(|e| ClientError::Network(format!("url /deliver: {e}")))?;
        let resp = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(envelope)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("deliver: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "deliver status {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Long-poll inbox с момента `since_ms`. Возвращает список encrypted
    /// envelope'ов (application-layer deserialize — отдельный слой).
    ///
    /// Long-poll inbox since `since_ms`. Returns a list of encrypted
    /// envelopes (application-layer deserialization is a separate stage).
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках или status != 2xx,
    ///   а также если wire-ответ не валиден как length-prefixed binary stream.
    pub async fn fetch_inbox(&self, since_ms: u64) -> Result<Vec<Vec<u8>>, ClientError> {
        let url = self
            .base_url
            .join(&format!("/inbox?since={since_ms}"))
            .map_err(|e| ClientError::Network(format!("url /inbox: {e}")))?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("inbox: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "inbox status {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Network(format!("inbox body: {e}")))?;
        parse_length_prefixed(&bytes)
    }

    /// Подтвердить получение сообщения. Сервер удаляет envelope из
    /// inbox'а — это zero-retention ack.
    ///
    /// Acknowledge receipt. The server removes the envelope from the inbox —
    /// zero-retention ack.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках или status != 2xx.
    pub async fn ack(&self, message_id: [u8; MESSAGE_ID_LEN]) -> Result<(), ClientError> {
        let hex_id = hex::encode(message_id);
        let url = self
            .base_url
            .join(&format!("/inbox/{hex_id}"))
            .map_err(|e| ClientError::Network(format!("url /inbox/id: {e}")))?;
        let resp = self
            .http
            .delete(url)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("ack: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "ack status {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Парсить length-prefixed binary stream: `u32 BE len || N bytes` per frame.
/// Возвращает ошибку на truncated-stream; пустой stream → пустой `Vec`.
///
/// Parse a length-prefixed binary stream (`u32 BE len || N bytes` per frame).
/// Returns an error for a truncated stream; empty stream → empty `Vec`.
fn parse_length_prefixed(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if cursor + 4 > bytes.len() {
            return Err(ClientError::Network(
                "truncated inbox response: missing length prefix".into(),
            ));
        }
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: slice [cursor..cursor+4] has length exactly 4 (length-checked above)"
        )]
        let len_bytes: [u8; 4] = bytes[cursor..cursor + 4]
            .try_into()
            .expect("slice of length 4");
        let len = u32::from_be_bytes(len_bytes) as usize;
        cursor += 4;
        if cursor + len > bytes.len() {
            return Err(ClientError::Network(
                "truncated inbox response: payload shorter than length prefix".into(),
            ));
        }
        out.push(bytes[cursor..cursor + len].to_vec());
        cursor += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_length_prefixed_empty_stream() {
        let parsed = parse_length_prefixed(&[]).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_length_prefixed_single_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let parsed = parse_length_prefixed(&buf).unwrap();
        assert_eq!(parsed, vec![b"abc".to_vec()]);
    }

    #[test]
    fn parse_length_prefixed_multi_frame() {
        let mut buf = Vec::new();
        // Frame 1: "hi" (2 bytes).
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(b"hi");
        // Frame 2: "world" (5 bytes).
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(b"world");
        // Frame 3: empty (0 bytes).
        buf.extend_from_slice(&0u32.to_be_bytes());
        let parsed = parse_length_prefixed(&buf).unwrap();
        assert_eq!(
            parsed,
            vec![b"hi".to_vec(), b"world".to_vec(), Vec::<u8>::new()]
        );
    }

    #[test]
    fn parse_length_prefixed_rejects_missing_prefix_bytes() {
        let buf = vec![0u8, 0u8, 0u8]; // 3 bytes — prefix incomplete
        let err = parse_length_prefixed(&buf).unwrap_err();
        assert!(matches!(err, ClientError::Network(msg) if msg.contains("missing length prefix")));
    }

    #[test]
    fn parse_length_prefixed_rejects_truncated_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(b"short"); // 5 bytes, not 10
        let err = parse_length_prefixed(&buf).unwrap_err();
        assert!(matches!(err, ClientError::Network(msg) if msg.contains("payload shorter")));
    }
}
