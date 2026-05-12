//! `Http2KtTransport` — HTTP/2 клиент к `kt-svc` (Key Transparency log) и его
//! witness-кворуму (3-of-5), design §5.4.
//!
//! Endpoint'ы:
//! - `GET  /kt/account/{id_hex}/epoch/{epoch}` — получить entries + inclusion
//!   proof для аккаунта и конкретного epoch'а (SPEC-09 §3).
//! - `GET  /kt/signed-roots/{epoch}` — получить подписанные корни от всех
//!   witnesses (5 signatures); клиент верифицирует ≥ 3 валидных через
//!   `umbrella_kt::witness::verify_signed_epoch`.
//! - `POST /kt/publish` — публикация новой entry: authorization approval,
//!   revocation, rotation, либо device attestation (SPEC-11 §4).
//!
//! Wire-level клиент возвращает raw bytes — десериализацию в
//! `KtEntry` / `SignedEpochRoot` делает слой выше (`umbrella-kt::codec`).
//!
//! `Http2KtTransport` — HTTP/2 client for `kt-svc` and its 3-of-5 witness
//! quorum (design §5.4). The wire-level client returns raw bytes; decoding
//! into `KtEntry` / `SignedEpochRoot` is left to `umbrella-kt::codec`.

use std::sync::Arc;

use reqwest::{Client, Url};

use crate::error::ClientError;

/// Длина `account_id` в байтах (SPEC-09 §3 — hash-of-identity-pubkey).
/// `account_id` length in bytes (SPEC-09 §3 — hash of identity pubkey).
pub const ACCOUNT_ID_LEN: usize = 32;

/// HTTP/2 клиент к kt-svc. HTTP/2 client for kt-svc.
pub struct Http2KtTransport {
    http: Arc<Client>,
    base_url: Url,
}

impl Http2KtTransport {
    /// Создать клиент. `base_url` — корневой URL kt-svc (без trailing path).
    /// Construct the client. `base_url` — root URL of kt-svc.
    #[must_use]
    pub fn new(http: Arc<Client>, base_url: Url) -> Self {
        Self { http, base_url }
    }

    /// Получить entries + inclusion proof для аккаунта в конкретный epoch.
    /// Raw bytes возвращаются в layer выше (`umbrella-kt::codec`) для парсинга.
    ///
    /// Fetch entries + inclusion proof for an account at a given epoch. Raw
    /// bytes are returned to the upper layer (`umbrella-kt::codec`) to parse.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках или status != 2xx.
    pub async fn fetch_epoch(
        &self,
        account_id: &[u8; ACCOUNT_ID_LEN],
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let hex_id = hex::encode(account_id);
        let url = self
            .base_url
            .join(&format!("/kt/account/{hex_id}/epoch/{epoch}"))
            .map_err(|e| ClientError::Network(format!("url /kt/account: {e}")))?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("kt fetch_epoch: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "kt fetch_epoch status {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Network(format!("kt fetch_epoch body: {e}")))?;
        Ok(bytes.to_vec())
    }

    /// Получить 5 signed roots от всех witnesses для epoch'а.
    /// Возвращает `Vec<Vec<u8>>` — каждый элемент — raw bytes одного
    /// `SignedEpochRoot`; upstream `umbrella-kt::witness::verify_signed_epoch`
    /// проверяет ≥ 3 валидных подписи.
    ///
    /// Fetch signed roots from all witnesses for an epoch. Returns
    /// `Vec<Vec<u8>>` — each entry is raw bytes of one `SignedEpochRoot`;
    /// upstream `umbrella-kt::witness::verify_signed_epoch` checks for ≥ 3
    /// valid signatures.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках, status != 2xx
    ///   или truncated length-prefixed stream.
    pub async fn fetch_signed_roots(&self, epoch: u64) -> Result<Vec<Vec<u8>>, ClientError> {
        let url = self
            .base_url
            .join(&format!("/kt/signed-roots/{epoch}"))
            .map_err(|e| ClientError::Network(format!("url /kt/signed-roots: {e}")))?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("kt signed_roots: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "kt signed_roots status {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Network(format!("kt signed_roots body: {e}")))?;
        parse_length_prefixed_strict(&bytes)
    }

    /// Опубликовать новую KT entry (authorization, revocation, rotation,
    /// device attestation). Идемпотентна по entry id, который входит в
    /// payload — сервер dedupes.
    ///
    /// Publish a new KT entry (authorization, revocation, rotation, device
    /// attestation). Idempotent by entry id carried inside the payload.
    ///
    /// # Errors
    /// - [`ClientError::Network`] при DNS/TCP/TLS/HTTP ошибках или status != 2xx.
    pub async fn publish(&self, entry_bytes: Vec<u8>) -> Result<(), ClientError> {
        let url = self
            .base_url
            .join("/kt/publish")
            .map_err(|e| ClientError::Network(format!("url /kt/publish: {e}")))?;
        let resp = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(entry_bytes)
            .send()
            .await
            .map_err(|e| ClientError::Network(format!("kt publish: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::Network(format!(
                "kt publish status {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Строгая (не-tolerant) версия length-prefixed parser: любая неполная
/// frame — ошибка (в отличие от версии в `blind_postman.rs` которая
/// семантически той же, но раздельный helper уменьшает сцепку модулей).
///
/// Strict length-prefixed parser: any incomplete frame yields an error.
fn parse_length_prefixed_strict(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if cursor + 4 > bytes.len() {
            return Err(ClientError::Network(
                "truncated signed-roots response: missing length prefix".into(),
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
                "truncated signed-roots response: payload shorter than length prefix".into(),
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
    fn parse_strict_empty_stream() {
        let parsed = parse_length_prefixed_strict(&[]).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_strict_exactly_five_frames() {
        let mut buf = Vec::new();
        for i in 0..5u8 {
            buf.extend_from_slice(&1u32.to_be_bytes());
            buf.push(i);
        }
        let parsed = parse_length_prefixed_strict(&buf).unwrap();
        assert_eq!(parsed.len(), 5);
        for (i, frame) in parsed.iter().enumerate() {
            assert_eq!(frame, &vec![i as u8]);
        }
    }

    #[test]
    fn parse_strict_rejects_trailing_garbage_prefix() {
        let buf = vec![0u8, 1u8]; // 2 bytes — prefix incomplete
        let err = parse_length_prefixed_strict(&buf).unwrap_err();
        assert!(matches!(err, ClientError::Network(msg) if msg.contains("missing length prefix")));
    }
}
