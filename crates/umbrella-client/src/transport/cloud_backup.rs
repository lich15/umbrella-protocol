//! `Http2UnwrapTransport` — реальная HTTP/2 реализация
//! [`AsyncUnwrapTransport`] с fan-out к 5 Sealed Servers (design §5.2,
//! SPEC-12 §A.7).
//!
//! Алгоритм работы на `dispatch`:
//! 1. Сериализовать `SignedUnwrapRequest` через [`SignedUnwrapRequest::to_bytes`].
//! 2. Параллельно `tokio::spawn` для каждого из 5 URL — POST запрос с body.
//!    Каждый worker проверяет HTTP статус, парсит `ServerUnwrapShare` и
//!    сверяет `witness_index` с ожидаемым (i+1, 1-based).
//! 3. Worker'ы шлют валидные shares в общий `mpsc::channel` capacity=5.
//! 4. Главная задача читает shares с deadline `timeout`, early-return при
//!    ≥ 3 shares (оптимизация: latency ≈ 3-й по скорости сервер).
//! 5. Возвращает собранный `Vec<ServerUnwrapShare>` (0..=5). `threshold_combine`
//!    в `umbrella-backup` транслирует `< threshold` в
//!    `BackupError::InsufficientUnwrapShares`.
//!
//! Failure modes:
//! - DNS/connect error одного сервера — worker silently exits, channel просто
//!   не получает его share.
//! - HTTP 5xx / timeout — same silent skip (логика retry на fan-out уровне
//!   противоречит idempotency — лучше переспросить группой заново).
//! - Malformed `ServerUnwrapShare` body — silent skip (сервер misbehaves).
//! - Wrong `witness_index` в ответе — silent skip (защита от server swap).
//!
//! `Http2UnwrapTransport` — real HTTP/2 impl of [`AsyncUnwrapTransport`] with
//! fan-out to the 5 Sealed Servers (design §5.2, SPEC-12 §A.7). See above for
//! algorithm and failure modes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, Url};
use tokio::sync::mpsc;
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::signed_request::SignedUnwrapRequest;
use umbrella_backup::error::BackupError;

use crate::transport::async_unwrap::AsyncUnwrapTransport;

/// Число Sealed Servers в fan-out. Fixed by SPEC-12 threshold-3-of-5 protocol.
///
/// Number of Sealed Servers in the fan-out. Fixed by SPEC-12 threshold-3-of-5.
pub const SEALED_SERVER_COUNT: usize = 5;

/// Threshold для early-return: как только собрали ≥3 shares, останавливаемся.
/// Дальнейшие ответы — wasted work (но worker'ы уже spawned, они просто
/// получат `SendError` при попытке отправить в закрытый канал и завершатся).
///
/// Threshold for early return: once we have ≥3 shares we stop collecting.
/// Remaining workers are already spawned and exit once they observe the
/// channel closed.
pub const EARLY_RETURN_THRESHOLD: usize = 3;

/// HTTP-based `UnwrapTransport` — production реализация (design §5.2).
///
/// Держит `Arc<reqwest::Client>` (shared connection pool с другими транспортами
/// одного `ClientCore`) и массив из [`SEALED_SERVER_COUNT`] URL-ов Sealed Servers.
/// Индекс в массиве (`i`) определяет ожидаемый `witness_index = i + 1`.
///
/// HTTP-based `UnwrapTransport` — production impl (design §5.2). Holds an
/// `Arc<reqwest::Client>` sharing the connection pool with the other
/// transports of the same `ClientCore`, and an array of five Sealed Server
/// URLs. Array index `i` corresponds to expected `witness_index = i + 1`.
pub struct Http2UnwrapTransport {
    http: Arc<Client>,
    server_urls: [Url; SEALED_SERVER_COUNT],
}

impl Http2UnwrapTransport {
    /// Создать новый транспорт с переданным HTTP клиентом и массивом URL.
    ///
    /// `server_urls[i]` должен указывать на Sealed Server с witness_index
    /// `i + 1`. Неверное соответствие обнаруживается при dispatch: worker
    /// отбрасывает shares с неожиданным witness_index (silent skip).
    ///
    /// Construct a new transport with the given HTTP client and URL array.
    /// `server_urls[i]` must point at the Sealed Server whose `witness_index`
    /// is `i + 1`. Mismatch is detected at dispatch time — workers drop any
    /// share with an unexpected witness index.
    #[must_use]
    pub fn new(http: Arc<Client>, server_urls: [Url; SEALED_SERVER_COUNT]) -> Self {
        Self { http, server_urls }
    }
}

#[async_trait]
impl AsyncUnwrapTransport for Http2UnwrapTransport {
    async fn dispatch(
        &self,
        request: &SignedUnwrapRequest,
        timeout: Duration,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        let payload = request.to_bytes();
        let (tx, mut rx) = mpsc::channel::<ServerUnwrapShare>(SEALED_SERVER_COUNT);

        for (idx, url) in self.server_urls.iter().enumerate() {
            let http = Arc::clone(&self.http);
            let url = url.clone();
            let tx = tx.clone();
            let payload = payload.clone();
            let witness_index = (idx + 1) as u8;

            tokio::spawn(async move {
                let response = http
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .body(payload)
                    .send()
                    .await;

                let Ok(response) = response else {
                    // DNS/connect/TLS/timeout error — drop worker silently.
                    return;
                };
                if !response.status().is_success() {
                    // Any non-2xx (including 5xx) — drop silently.
                    return;
                }
                let Ok(bytes) = response.bytes().await else {
                    // Stream interrupted mid-body — drop silently.
                    return;
                };
                let Ok(share) = ServerUnwrapShare::from_bytes(&bytes) else {
                    // Malformed wire-format — drop silently.
                    return;
                };
                if share.witness_index.get() != witness_index {
                    // Server returned share with wrong witness_index —
                    // potential misconfiguration / swap attack — drop silently.
                    return;
                }
                // SendError ignored: the coordinator may already have collected
                // 3 shares and closed the receiver. That's early-return working
                // as intended, not a failure.
                let _ = tx.send(share).await;
            });
        }
        // Drop the parent sender handle so that `rx.recv()` returns `None` once
        // all 5 spawned workers finish — otherwise the receiver would block
        // even after every worker failed.
        drop(tx);

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        let mut shares: Vec<ServerUnwrapShare> = Vec::with_capacity(SEALED_SERVER_COUNT);
        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                maybe = rx.recv() => {
                    match maybe {
                        Some(s) => {
                            shares.push(s);
                            if shares.len() >= EARLY_RETURN_THRESHOLD {
                                break;
                            }
                        }
                        None => break, // all 5 workers finished without success
                    }
                }
            }
        }
        Ok(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::transport::http2_client::{build_http2_client, Http2Config};

    #[test]
    fn constants_match_spec12_threshold() {
        assert_eq!(SEALED_SERVER_COUNT, 5);
        assert_eq!(EARLY_RETURN_THRESHOLD, 3);
    }

    #[test]
    fn construct_requires_five_urls() {
        let http = build_http2_client(Http2Config::default()).expect("build");
        let urls: [Url; 5] = [
            Url::parse("https://s1.example").unwrap(),
            Url::parse("https://s2.example").unwrap(),
            Url::parse("https://s3.example").unwrap(),
            Url::parse("https://s4.example").unwrap(),
            Url::parse("https://s5.example").unwrap(),
        ];
        let transport = Http2UnwrapTransport::new(http, urls);
        assert_eq!(transport.server_urls.len(), SEALED_SERVER_COUNT);
    }
}
