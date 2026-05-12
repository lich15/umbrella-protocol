//! `SrtpPipeline` — обёртка над SRTP session для encrypt/decrypt RTP-пакетов
//! на keying material, экспортированном из DTLS handshake (RFC 5764 §4.2).
//!
//! Блок 7.6 (этот файл) — структурная подготовка: хранит keying material
//! внутри [`tokio::sync::Mutex`] и позволяет установить его после DTLS
//! handshake completion. Реальный encrypt/decrypt через
//! [`webrtc-srtp`](https://crates.io/crates/webrtc-srtp) появится в блоке 7.10
//! интеграции.
//!
//! Выбранный профиль — `AEAD_AES_256_GCM` (RFC 7714 §14 код `0x0008`) —
//! consistent с SFrame AEAD (`Aes256GcmSha512`, Этап 6).
//!
//! `SrtpPipeline` wraps an SRTP session for RTP encrypt/decrypt using keying
//! material exported from the DTLS handshake (RFC 5764 §4.2).
//!
//! Block 7.6 (this file) is structural scaffolding: holds the keying material
//! inside a [`tokio::sync::Mutex`] and lets callers install it after DTLS
//! handshake completion. Actual encrypt/decrypt via
//! [`webrtc-srtp`](https://crates.io/crates/webrtc-srtp) lands in the Block
//! 7.10 integration.
//!
//! Profile — `AEAD_AES_256_GCM` (RFC 7714 §14 code `0x0008`) — consistent
//! with the SFrame AEAD (`Aes256GcmSha512`, Stage 6).

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::ClientError;

/// Keying material для SRTP session. Получен из DTLS handshake exporter
/// (RFC 5764 §4.2): `client_write_SRTP_master_key || server_write_SRTP_master_key`
/// в `key`, `client_write_SRTP_master_salt || server_write_SRTP_master_salt`
/// в `salt`.
///
/// SRTP keying material. Exported from the DTLS handshake (RFC 5764 §4.2):
/// `key` is `client_write_SRTP_master_key || server_write_SRTP_master_key`,
/// `salt` is `client_write_SRTP_master_salt || server_write_SRTP_master_salt`.
#[derive(Clone)]
pub struct SrtpKeyingMaterial {
    /// Concatenated client + server master keys (32 + 32 bytes for
    /// `AEAD_AES_256_GCM`).
    ///
    /// Concatenated client + server master keys (32 + 32 bytes for
    /// `AEAD_AES_256_GCM`).
    pub key: Vec<u8>,
    /// Concatenated client + server master salts (12 + 12 bytes for
    /// `AEAD_AES_256_GCM`).
    ///
    /// Concatenated client + server master salts (12 + 12 bytes for
    /// `AEAD_AES_256_GCM`).
    pub salt: Vec<u8>,
    /// Профиль SRTP (алгоритм AEAD + длины ключей).
    ///
    /// SRTP profile — AEAD algorithm + key lengths.
    pub profile: SrtpProfile,
}

/// Профиль SRTP — `AEAD_AES_256_GCM` (RFC 7714 §14 code `0x0008`).
///
/// SRTP profile — `AEAD_AES_256_GCM` (RFC 7714 §14 code `0x0008`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// `AEAD_AES_256_GCM` — consistent с SFrame `Aes256GcmSha512`
    /// (Этап 6). 256-bit master key, 96-bit master salt, 128-bit tag.
    ///
    /// `AEAD_AES_256_GCM` — consistent with the SFrame `Aes256GcmSha512`
    /// choice (Stage 6). 256-bit master key, 96-bit master salt, 128-bit tag.
    AeadAes256Gcm,
}

/// SRTP pipeline — encrypt/decrypt RTP-пакетов для одной сессии.
/// Блок 7.6 — только owner keying material; реальный encrypt/decrypt через
/// `webrtc-srtp::Session` в блоке 7.10.
///
/// SRTP pipeline — RTP encrypt/decrypt for a single session. Block 7.6 only
/// owns the keying material; actual encrypt/decrypt via `webrtc-srtp::Session`
/// lands in Block 7.10.
pub struct SrtpPipeline {
    keying: Arc<Mutex<Option<SrtpKeyingMaterial>>>,
}

impl SrtpPipeline {
    /// Создаёт пустой pipeline; [`Self::set_keying`] вызывается после
    /// DTLS handshake completion.
    ///
    /// Creates an empty pipeline; [`Self::set_keying`] is called after DTLS
    /// handshake completion.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keying: Arc::new(Mutex::new(None)),
        }
    }

    /// Устанавливает keying material после DTLS handshake completion.
    ///
    /// # Ошибки / Errors
    ///
    /// В блоке 7.6 инфallible (заглушка); в блоке 7.10 может вернуть
    /// [`ClientError::Call`] при несовпадении профиля с договорённым на DTLS
    /// `use_srtp` extension.
    ///
    /// Installs keying material after DTLS handshake completion.
    ///
    /// # Errors
    ///
    /// Infallible in Block 7.6 (scaffolding); Block 7.10 may return
    /// [`ClientError::Call`] if the profile disagrees with what was negotiated
    /// on the DTLS `use_srtp` extension.
    pub async fn set_keying(&self, material: SrtpKeyingMaterial) -> Result<(), ClientError> {
        *self.keying.lock().await = Some(material);
        Ok(())
    }

    /// `true` если keying material установлен.
    ///
    /// `true` once keying material is installed.
    pub async fn is_keyed(&self) -> bool {
        self.keying.lock().await.is_some()
    }
}

impl Default for SrtpPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_material() -> SrtpKeyingMaterial {
        SrtpKeyingMaterial {
            key: vec![0xAB; 64],
            salt: vec![0xCD; 24],
            profile: SrtpProfile::AeadAes256Gcm,
        }
    }

    #[tokio::test]
    async fn new_pipeline_is_not_keyed() {
        let p = SrtpPipeline::new();
        assert!(!p.is_keyed().await);
    }

    #[tokio::test]
    async fn set_keying_marks_pipeline_keyed() {
        let p = SrtpPipeline::new();
        p.set_keying(sample_material()).await.unwrap();
        assert!(p.is_keyed().await);
    }

    #[tokio::test]
    async fn default_equals_new() {
        let a = SrtpPipeline::default();
        let b = SrtpPipeline::new();
        assert_eq!(a.is_keyed().await, b.is_keyed().await);
    }

    #[test]
    fn profile_is_aead_aes_256_gcm() {
        let m = sample_material();
        assert_eq!(m.profile, SrtpProfile::AeadAes256Gcm);
    }
}
