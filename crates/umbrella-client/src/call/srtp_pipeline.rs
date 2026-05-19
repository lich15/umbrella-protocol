//! `SrtpPipeline` — обёртка над SRTP cryptographic contexts для encrypt/decrypt
//! RTP-пакетов на keying material, экспортированном из DTLS handshake
//! (RFC 5764 §4.2).
//!
//! **F-CLIENT-FACADE-1 session 10e (2026-05-19):** real `webrtc-srtp 0.17.1`
//! integration. Pipeline держит **два** [`webrtc_srtp::context::Context`]
//! одновременно — encrypt и decrypt, потому что Context по-конструкции
//! one-way (encrypt-only либо decrypt-only). Encrypt-context инициализирован
//! local master key/salt из keying material, decrypt-context — remote
//! master key/salt. SRTP replay protection (64-кадровое окно sliding
//! window) включена только на decrypt стороне; outbound encryption не
//! проверяет replay (мы сами генерируем sequence numbers и доверяем
//! им).
//!
//! Выбранный профиль — `AEAD_AES_256_GCM` (RFC 7714 §14 код `0x0008`) —
//! consistent с SFrame AEAD (`Aes256GcmSha512`, Этап 6).
//!
//! `SrtpPipeline` wraps SRTP cryptographic contexts for RTP encrypt/decrypt
//! over keying material exported from the DTLS handshake (RFC 5764 §4.2).
//!
//! **F-CLIENT-FACADE-1 session 10e (2026-05-19):** real `webrtc-srtp 0.17.1`
//! integration. The pipeline holds **two**
//! [`webrtc_srtp::context::Context`] instances — encrypt + decrypt — because
//! Context is one-way by construction (encrypt-only OR decrypt-only). The
//! encrypt context is keyed with the local master key/salt from the
//! handshake exporter; the decrypt context with the remote half. SRTP
//! replay protection (sliding-window of 64 frames) is enabled only on the
//! decrypt side — outbound encryption does not run replay detection
//! because we generate the sequence numbers ourselves.
//!
//! Profile — `AEAD_AES_256_GCM` (RFC 7714 §14 code `0x0008`) — consistent
//! with the SFrame AEAD (`Aes256GcmSha512`, Stage 6).

use std::sync::Arc;

use tokio::sync::Mutex;
use umbrella_calls::CallError;
use webrtc_srtp::context::Context;
use webrtc_srtp::option::srtp_replay_protection;
use webrtc_srtp::protection_profile::ProtectionProfile;

use crate::ClientError;

/// AEAD_AES_256_GCM SRTP master key length per direction (RFC 7714 §14).
const SRTP_KEY_LEN: usize = 32;

/// AEAD_AES_256_GCM SRTP master salt length per direction (RFC 7714 §14).
const SRTP_SALT_LEN: usize = 12;

/// SRTP replay protection window size (frames). Matches webrtc-srtp's
/// session-level default of 64.
const SRTP_REPLAY_WINDOW: usize = 64;

/// Keying material для SRTP session. Получен из DTLS handshake exporter
/// (RFC 5764 §4.2): `client_write_SRTP_master_key || server_write_SRTP_master_key`
/// в `key`, `client_write_SRTP_master_salt || server_write_SRTP_master_salt`
/// в `salt`.
///
/// Layout invariant: первая половина `key` — **local** (наш encrypt) master
/// key; вторая — **remote** (наш decrypt) master key. Аналогично `salt`.
/// Caller обязан выровнять направление в зависимости от роли в DTLS
/// (client → local = client_write; server → local = server_write).
///
/// SRTP keying material. Exported from the DTLS handshake (RFC 5764 §4.2):
/// `key` is `client_write_SRTP_master_key || server_write_SRTP_master_key`,
/// `salt` is `client_write_SRTP_master_salt || server_write_SRTP_master_salt`.
///
/// Layout invariant: the first half of `key` is the **local** (our encrypt)
/// master key; the second half is the **remote** (our decrypt) master key.
/// Likewise for `salt`. The caller swaps the halves according to DTLS role
/// (client → local = client_write; server → local = server_write).
#[derive(Clone)]
pub struct SrtpKeyingMaterial {
    /// Concatenated local + remote master keys
    /// (`SRTP_KEY_LEN + SRTP_KEY_LEN = 64` bytes for `AEAD_AES_256_GCM`).
    ///
    /// Concatenated local + remote master keys
    /// (`SRTP_KEY_LEN + SRTP_KEY_LEN = 64` bytes for `AEAD_AES_256_GCM`).
    pub key: Vec<u8>,
    /// Concatenated local + remote master salts
    /// (`SRTP_SALT_LEN + SRTP_SALT_LEN = 24` bytes for `AEAD_AES_256_GCM`).
    ///
    /// Concatenated local + remote master salts
    /// (`SRTP_SALT_LEN + SRTP_SALT_LEN = 24` bytes for `AEAD_AES_256_GCM`).
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

/// Внутренний state pipeline'а после установки keying material.
/// Два `Context` экземпляра — encrypt и decrypt — потому что Context'ы
/// webrtc-srtp one-way по конструкции.
///
/// Internal pipeline state after keying material is installed. Two
/// `Context` instances — encrypt + decrypt — because webrtc-srtp's Context
/// is one-way by construction.
struct PipelineState {
    encrypt_ctx: Context,
    decrypt_ctx: Context,
    profile: SrtpProfile,
}

/// SRTP pipeline — encrypt/decrypt RTP-пакетов для одной сессии.
///
/// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** real webrtc-srtp 0.17.1
/// integration. После `set_keying` pipeline владеет двумя one-way Context
/// instances (encrypt + decrypt), готов encrypt/decrypt RTP пакетов.
///
/// SRTP pipeline — RTP encrypt/decrypt for a single session.
///
/// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** real webrtc-srtp 0.17.1
/// integration. After `set_keying` the pipeline owns two one-way Context
/// instances (encrypt + decrypt) and is ready to encrypt/decrypt RTP
/// packets.
pub struct SrtpPipeline {
    state: Arc<Mutex<Option<PipelineState>>>,
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
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// Устанавливает keying material после DTLS handshake completion и
    /// конструирует encrypt + decrypt Context'ы.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] если `material.profile` не поддерживается
    ///   (только `AeadAes256Gcm` в этой версии).
    /// - [`ClientError::Internal`] если длина `material.key` либо
    ///   `material.salt` не совпадает с ожидаемой для профиля
    ///   (`2 * SRTP_KEY_LEN` и `2 * SRTP_SALT_LEN` соответственно).
    /// - [`ClientError::Internal`] при ошибке `Context::new` (например,
    ///   internal webrtc-srtp validation).
    ///
    /// Installs keying material after DTLS handshake completion and builds
    /// the encrypt + decrypt Context's.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] if `material.profile` is unsupported
    ///   (only `AeadAes256Gcm` in this version).
    /// - [`ClientError::Internal`] if `material.key` or `material.salt`
    ///   length does not match the profile
    ///   (`2 * SRTP_KEY_LEN` and `2 * SRTP_SALT_LEN` respectively).
    /// - [`ClientError::Internal`] on `Context::new` failure (internal
    ///   webrtc-srtp validation, etc.).
    pub async fn set_keying(&self, material: SrtpKeyingMaterial) -> Result<(), ClientError> {
        if material.profile != SrtpProfile::AeadAes256Gcm {
            return Err(ClientError::Internal(format!(
                "SRTP: unsupported profile {:?} (only AeadAes256Gcm)",
                material.profile
            )));
        }
        let expected_key_len = SRTP_KEY_LEN * 2;
        let expected_salt_len = SRTP_SALT_LEN * 2;
        if material.key.len() != expected_key_len {
            return Err(ClientError::Internal(format!(
                "SRTP: key length {}, expected {} for AEAD_AES_256_GCM (local || remote)",
                material.key.len(),
                expected_key_len
            )));
        }
        if material.salt.len() != expected_salt_len {
            return Err(ClientError::Internal(format!(
                "SRTP: salt length {}, expected {} for AEAD_AES_256_GCM (local || remote)",
                material.salt.len(),
                expected_salt_len
            )));
        }

        let (local_key, remote_key) = material.key.split_at(SRTP_KEY_LEN);
        let (local_salt, remote_salt) = material.salt.split_at(SRTP_SALT_LEN);

        let encrypt_ctx = Context::new(
            local_key,
            local_salt,
            ProtectionProfile::AeadAes256Gcm,
            None,
            None,
        )
        .map_err(|e| ClientError::Internal(format!("SRTP: encrypt Context::new failed: {e}")))?;

        let decrypt_ctx = Context::new(
            remote_key,
            remote_salt,
            ProtectionProfile::AeadAes256Gcm,
            Some(srtp_replay_protection(SRTP_REPLAY_WINDOW)),
            None,
        )
        .map_err(|e| ClientError::Internal(format!("SRTP: decrypt Context::new failed: {e}")))?;

        *self.state.lock().await = Some(PipelineState {
            encrypt_ctx,
            decrypt_ctx,
            profile: material.profile,
        });
        Ok(())
    }

    /// `true` если keying material установлен и encrypt/decrypt Context'ы
    /// готовы.
    ///
    /// `true` once keying material is installed and the encrypt/decrypt
    /// Context's are ready.
    pub async fn is_keyed(&self) -> bool {
        self.state.lock().await.is_some()
    }

    /// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** шифрует RTP-пакет
    /// под outbound encrypt Context. Входной `plaintext` — полный RTP
    /// пакет (12+ byte header + payload); webrtc-srtp internally парсит
    /// header и шифрует только payload + добавляет 16-byte AEAD tag.
    ///
    /// Возвращаемые байты: `RTP header (unchanged) || ciphertext ||
    /// 16-byte AEAD tag` — формат RFC 7714 §14 для AEAD_AES_256_GCM.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] если pipeline не keyed (fail-closed
    ///   pre-keying invariant consistent с
    ///   `CallSession::mark_connected`).
    /// - [`ClientError::Internal`] для прочих ошибок webrtc-srtp
    ///   (slipped sequence number, malformed RTP header, etc).
    ///
    /// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** encrypts an RTP
    /// packet under the outbound encrypt Context. `plaintext` is the full
    /// RTP packet (12+ byte header + payload); webrtc-srtp internally
    /// parses the header and encrypts only the payload + appends a 16-byte
    /// AEAD tag.
    ///
    /// Returned bytes: `RTP header (unchanged) || ciphertext ||
    /// 16-byte AEAD tag` — RFC 7714 §14 format for AEAD_AES_256_GCM.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] if the pipeline is not keyed (fail-closed
    ///   pre-keying invariant consistent with
    ///   `CallSession::mark_connected`).
    /// - [`ClientError::Internal`] for other webrtc-srtp failures (slipped
    ///   sequence numbers, malformed RTP headers, etc.).
    pub async fn encrypt_rtp(&self, plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            ClientError::Internal(
                "SRTP: encrypt_rtp called pre-keying — install_srtp_keying must run before media \
                 flow"
                    .into(),
            )
        })?;
        state
            .encrypt_ctx
            .encrypt_rtp(plaintext)
            .map(|b| b.to_vec())
            .map_err(map_srtp_error)
    }

    /// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** расшифровывает
    /// SRTP-пакет под inbound decrypt Context. Входной `srtp` — полный
    /// SRTP wire-format пакет (RTP header + ciphertext + 16-byte AEAD
    /// tag для AEAD_AES_256_GCM). Replay protection через sliding
    /// window 64 (per-SSRC).
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] если pipeline не keyed (fail-closed
    ///   pre-keying invariant).
    /// - [`ClientError::Call`]`(CallError::AeadAuthFailure)` при
    ///   tampered ciphertext/tag/header либо неверном ключе.
    /// - [`ClientError::Internal`] при replay detection (с описанием ssrc
    ///   и sequence number в сообщении), out-of-window sequence numbers
    ///   и прочих webrtc-srtp ошибках.
    ///
    /// **F-CLIENT-FACADE-1 session 10e (2026-05-19):** decrypts an SRTP
    /// packet under the inbound decrypt Context. `srtp` is the full
    /// SRTP wire packet (RTP header + ciphertext + 16-byte AEAD tag for
    /// AEAD_AES_256_GCM). Replay protection uses a 64-frame sliding
    /// window per SSRC.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Internal`] if the pipeline is not keyed (fail-closed
    ///   pre-keying invariant).
    /// - [`ClientError::Call`]`(CallError::AeadAuthFailure)` on tampered
    ///   ciphertext/tag/header or a wrong key.
    /// - [`ClientError::Internal`] on replay detection (ssrc + sequence
    ///   number in the message), out-of-window sequence numbers, and other
    ///   webrtc-srtp failures.
    pub async fn decrypt_rtp(&self, srtp: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or_else(|| {
            ClientError::Internal(
                "SRTP: decrypt_rtp called pre-keying — install_srtp_keying must run before media \
                 flow"
                    .into(),
            )
        })?;
        state
            .decrypt_ctx
            .decrypt_rtp(srtp)
            .map(|b| b.to_vec())
            .map_err(map_srtp_error)
    }

    /// Возвращает профиль pipeline'а после `set_keying`. До keying —
    /// `None`.
    ///
    /// Returns the pipeline's profile after `set_keying`. `None`
    /// pre-keying.
    pub async fn profile(&self) -> Option<SrtpProfile> {
        self.state.lock().await.as_ref().map(|s| s.profile)
    }
}

impl Default for SrtpPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Map webrtc-srtp ошибок в `ClientError` для facade.
///
/// AEAD authentication failure имеет два возможных surface'а в
/// webrtc-srtp 0.17:
///
/// - `RtpFailedToVerifyAuthTag` — для AES-CM-HMAC-SHA1 path, где auth
///   tag это отдельный HMAC check.
/// - `AesGcm(aes_gcm::Error)` — для AEAD_AES_*_GCM path, где AEAD
///   verification embedded в decrypt operation; нижний слой
///   (`aes_gcm` crate) возвращает обёрнутую `aead::Error` при
///   tampered ciphertext/tag/неверном ключе.
///
/// Оба маппятся в единый `CallError::AeadAuthFailure` чтобы
/// adversarial tests могли `matches!` на конкретный вариант
/// (consistent с SFrame mapping в `umbrella-calls`).
///
/// - `SrtpSsrcDuplicated(ssrc, seq)` → `ClientError::Internal` с
///   текстовым описанием для test assertions (`contains("SRTP: replay")`).
/// - Прочее → `ClientError::Internal` с Display-репрезентацией.
///
/// Maps webrtc-srtp errors to `ClientError` for the facade.
///
/// AEAD authentication failure surfaces through two webrtc-srtp variants:
///
/// - `RtpFailedToVerifyAuthTag` — AES-CM-HMAC-SHA1 path with a separate
///   HMAC check.
/// - `AesGcm(aes_gcm::Error)` — AEAD_AES_*_GCM path where verification is
///   embedded in the decrypt operation; the underlying `aes_gcm` crate
///   surfaces a wrapped `aead::Error` on tampered ciphertext/tag or wrong
///   key.
///
/// Both map to a single `CallError::AeadAuthFailure` so adversarial tests
/// can `matches!` on a single variant (consistent with the SFrame mapping
/// in `umbrella-calls`).
///
/// - `SrtpSsrcDuplicated(ssrc, seq)` → `ClientError::Internal` with a
///   descriptive message for test assertions (`contains("SRTP: replay")`).
/// - Other → `ClientError::Internal` with the Display representation.
fn map_srtp_error(e: webrtc_srtp::Error) -> ClientError {
    match e {
        webrtc_srtp::Error::RtpFailedToVerifyAuthTag | webrtc_srtp::Error::AesGcm(_) => {
            ClientError::Call(CallError::AeadAuthFailure)
        }
        webrtc_srtp::Error::SrtpSsrcDuplicated(ssrc, seq) => ClientError::Internal(format!(
            "SRTP: replay detected ssrc={ssrc:#010x} sequence_number={seq}"
        )),
        other => ClientError::Internal(format!("SRTP: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_material() -> SrtpKeyingMaterial {
        SrtpKeyingMaterial {
            key: vec![0xAB; SRTP_KEY_LEN * 2],
            salt: vec![0xCD; SRTP_SALT_LEN * 2],
            profile: SrtpProfile::AeadAes256Gcm,
        }
    }

    #[tokio::test]
    async fn new_pipeline_is_not_keyed() {
        let p = SrtpPipeline::new();
        assert!(!p.is_keyed().await);
        assert!(p.profile().await.is_none());
    }

    #[tokio::test]
    async fn set_keying_marks_pipeline_keyed() {
        let p = SrtpPipeline::new();
        p.set_keying(sample_material()).await.unwrap();
        assert!(p.is_keyed().await);
        assert_eq!(p.profile().await, Some(SrtpProfile::AeadAes256Gcm));
    }

    #[tokio::test]
    async fn default_equals_new() {
        let a = SrtpPipeline::default();
        let b = SrtpPipeline::new();
        assert_eq!(a.is_keyed().await, b.is_keyed().await);
        assert_eq!(a.profile().await, b.profile().await);
    }

    #[test]
    fn profile_is_aead_aes_256_gcm() {
        let m = sample_material();
        assert_eq!(m.profile, SrtpProfile::AeadAes256Gcm);
    }

    #[tokio::test]
    async fn set_keying_rejects_short_key_length() {
        let p = SrtpPipeline::new();
        let bad = SrtpKeyingMaterial {
            key: vec![0xAB; SRTP_KEY_LEN], // only one half — must be 2x
            salt: vec![0xCD; SRTP_SALT_LEN * 2],
            profile: SrtpProfile::AeadAes256Gcm,
        };
        let err = p.set_keying(bad).await.expect_err("short key must reject");
        assert!(matches!(err, ClientError::Internal(msg) if msg.contains("key length")));
    }

    #[tokio::test]
    async fn set_keying_rejects_short_salt_length() {
        let p = SrtpPipeline::new();
        let bad = SrtpKeyingMaterial {
            key: vec![0xAB; SRTP_KEY_LEN * 2],
            salt: vec![0xCD; SRTP_SALT_LEN], // only one half — must be 2x
            profile: SrtpProfile::AeadAes256Gcm,
        };
        let err = p.set_keying(bad).await.expect_err("short salt must reject");
        assert!(matches!(err, ClientError::Internal(msg) if msg.contains("salt length")));
    }

    #[tokio::test]
    async fn encrypt_rtp_pre_keying_fails_closed() {
        let p = SrtpPipeline::new();
        let packet = vec![0u8; 32];
        let err = p
            .encrypt_rtp(&packet)
            .await
            .expect_err("encrypt_rtp pre-keying must fail closed");
        assert!(matches!(err, ClientError::Internal(msg) if msg.contains("pre-keying")));
    }

    #[tokio::test]
    async fn decrypt_rtp_pre_keying_fails_closed() {
        let p = SrtpPipeline::new();
        let packet = vec![0u8; 32];
        let err = p
            .decrypt_rtp(&packet)
            .await
            .expect_err("decrypt_rtp pre-keying must fail closed");
        assert!(matches!(err, ClientError::Internal(msg) if msg.contains("pre-keying")));
    }
}
