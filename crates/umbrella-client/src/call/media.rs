//! Media callback interfaces — `MediaSource` / `MediaSink`.
//!
//! Реализация на native-стороне: iOS через `AVAudioEngine`,
//! `AVCaptureSession`, `VideoToolbox` (Opus encode, H.264 encode); Android
//! через `AudioRecord`, `MediaCodec` (Opus encode, H.264 encode). В Rust
//! ядре — только async trait для pull/push encoded frames.
//!
//! Media callback interfaces — `MediaSource` / `MediaSink`.
//!
//! Native-side implementation: iOS via `AVAudioEngine`, `AVCaptureSession`,
//! `VideoToolbox` (Opus encode, H.264 encode); Android via `AudioRecord`,
//! `MediaCodec` (Opus encode, H.264 encode). The Rust core only exposes
//! async traits for pulling/pushing encoded frames.

use async_trait::async_trait;
use thiserror::Error;

/// Ошибка media-слоя. Propagates из native stack в Rust core.
///
/// Media-layer error. Propagates from the native stack into the Rust core.
#[derive(Debug, Error)]
pub enum MediaError {
    /// Ошибка кодека — encoder/decoder failure.
    ///
    /// Codec error — encoder/decoder failure.
    #[error("codec error: {0}")]
    Codec(String),
    /// Устройство захвата недоступно (microphone/camera permission denied).
    ///
    /// Capture device unavailable (microphone/camera permission denied).
    #[error("capture device unavailable: {0}")]
    Device(String),
    /// Платформо-специфичная ошибка native stack.
    ///
    /// Platform-specific native-stack error.
    #[error("native error: {0}")]
    Native(String),
}

/// Кодек media frame.
///
/// Media frame codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaCodec {
    /// Opus audio 48 kHz — default.
    ///
    /// Opus audio 48 kHz — default.
    Opus48k,
    /// H.264 video — основной видео-кодек (iOS VideoToolbox + Android MediaCodec).
    ///
    /// H.264 video — primary video codec (iOS VideoToolbox + Android MediaCodec).
    H264,
    /// VP9 video — опциональный альтернативный.
    ///
    /// VP9 video — optional alternative.
    Vp9,
}

/// Encoded media frame — готовый к SFrame/SRTP шифрованию.
///
/// Encoded media frame — ready for SFrame/SRTP encryption.
#[derive(Clone)]
pub struct MediaFrame {
    /// RTP timestamp (audio samples at 48k / video 90kHz clock).
    ///
    /// RTP timestamp (audio samples at 48 kHz / video 90 kHz clock).
    pub timestamp_rtp: u32,
    /// RTP sequence number.
    ///
    /// RTP sequence number.
    pub sequence_number: u16,
    /// Кодек payload.
    ///
    /// Payload codec.
    pub codec: MediaCodec,
    /// Encoded bytes (Opus frame / H.264 NAL / VP9 frame).
    ///
    /// Encoded bytes (Opus frame / H.264 NAL / VP9 frame).
    pub payload: Vec<u8>,
    /// `true` если это video keyframe (I-frame / IDR). Игнорируется для audio.
    ///
    /// `true` if this is a video keyframe (I-frame / IDR). Ignored for audio.
    pub is_keyframe: bool,
}

/// `Debug` скрывает payload кадра: аудио/видео тоже приватные данные.
/// `Debug` redacts frame payload: audio/video bytes are private data too.
impl core::fmt::Debug for MediaFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MediaFrame")
            .field("timestamp_rtp", &self.timestamp_rtp)
            .field("sequence_number", &self.sequence_number)
            .field("codec", &self.codec)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<redacted>")
            .field("is_keyframe", &self.is_keyframe)
            .finish()
    }
}

/// `MediaSource` — native-side pulls encoded frames from capture pipeline.
/// Реализуется iOS/Android-bridge в блоках 7.8/7.9.
///
/// `MediaSource` — native side pulls encoded frames from the capture
/// pipeline. Implemented by the iOS/Android bridges in Blocks 7.8/7.9.
#[async_trait]
pub trait MediaSource: Send + Sync {
    /// Pull next encoded audio frame (Opus 48k by default).
    ///
    /// # Ошибки / Errors
    ///
    /// Любой вариант [`MediaError`] — propagates из native encoder.
    ///
    /// Pull next encoded audio frame (Opus 48k by default).
    ///
    /// # Errors
    ///
    /// Any [`MediaError`] variant — propagated from the native encoder.
    async fn pull_audio_frame(&self) -> Result<MediaFrame, MediaError>;

    /// Pull next encoded video frame (H.264 by default).
    ///
    /// # Ошибки / Errors
    ///
    /// Любой вариант [`MediaError`] — propagates из native encoder.
    ///
    /// Pull next encoded video frame (H.264 by default).
    ///
    /// # Errors
    ///
    /// Any [`MediaError`] variant — propagated from the native encoder.
    async fn pull_video_frame(&self) -> Result<MediaFrame, MediaError>;
}

/// `MediaSink` — native-side pushes decrypted frames to playback pipeline.
/// Реализуется iOS/Android-bridge в блоках 7.8/7.9.
///
/// `MediaSink` — native side pushes decrypted frames to the playback
/// pipeline. Implemented by the iOS/Android bridges in Blocks 7.8/7.9.
#[async_trait]
pub trait MediaSink: Send + Sync {
    /// Push decrypted audio frame to native decoder/playback.
    ///
    /// # Ошибки / Errors
    ///
    /// Любой вариант [`MediaError`] — propagates из native decoder.
    ///
    /// Push a decrypted audio frame into the native decoder/playback chain.
    ///
    /// # Errors
    ///
    /// Any [`MediaError`] variant — propagated from the native decoder.
    async fn push_audio_frame(&self, frame: MediaFrame) -> Result<(), MediaError>;

    /// Push decrypted video frame to native decoder/playback.
    ///
    /// # Ошибки / Errors
    ///
    /// Любой вариант [`MediaError`] — propagates из native decoder.
    ///
    /// Push a decrypted video frame into the native decoder/playback chain.
    ///
    /// # Errors
    ///
    /// Any [`MediaError`] variant — propagated from the native decoder.
    async fn push_video_frame(&self, frame: MediaFrame) -> Result<(), MediaError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_codec_variants_distinct() {
        assert_ne!(MediaCodec::Opus48k, MediaCodec::H264);
        assert_ne!(MediaCodec::H264, MediaCodec::Vp9);
    }

    #[test]
    fn media_error_display_includes_inner() {
        let e = MediaError::Codec("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn media_frame_fields_roundtrip() {
        let f = MediaFrame {
            timestamp_rtp: 0xDEADBEEF,
            sequence_number: 0xABCD,
            codec: MediaCodec::H264,
            payload: vec![1, 2, 3],
            is_keyframe: true,
        };
        assert_eq!(f.timestamp_rtp, 0xDEADBEEF);
        assert_eq!(f.sequence_number, 0xABCD);
        assert_eq!(f.codec, MediaCodec::H264);
        assert_eq!(f.payload, vec![1, 2, 3]);
        assert!(f.is_keyframe);
    }

    #[test]
    fn media_frame_debug_redacts_encoded_payload() {
        let frame = MediaFrame {
            timestamp_rtp: 7,
            sequence_number: 8,
            codec: MediaCodec::Opus48k,
            payload: b"secret-opus-frame".to_vec(),
            is_keyframe: false,
        };

        let debug = format!("{frame:?}");

        assert!(
            !debug.contains("115, 101, 99, 114, 101, 116"),
            "Debug output must not leak encoded media payload bytes: {debug}"
        );
        assert!(
            debug.contains("payload_len"),
            "Debug output should keep payload length metadata for diagnostics: {debug}"
        );
    }
}
