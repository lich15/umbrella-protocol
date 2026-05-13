//! Framed streaming поверх Noise transport cipher.
//! Framed streaming over the Noise transport cipher.
//!
//! Transfer snapshot разбивается на frame'ы `<u32 len><opaque>` и каждый
//! шифруется через snow `TransportState::write_message`. Frame payload size
//! ограничен 1 MiB до encryption (защита от resource exhaustion).
//!
//! Snapshot is split into frames `<u32 len><opaque>`, each encrypted via
//! snow `TransportState::write_message`. Frame payload is bounded to 1 MiB
//! before encryption (resource-exhaustion guard).

use snow::TransportState;

use crate::error::BackupError;

/// Максимальный размер plaintext одной frame payload (до шифрования), 1 MiB.
/// Maximum plaintext frame payload size (pre-encryption), 1 MiB.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Overhead одной Noise frame: AEAD tag (16 bytes) + длина-prefix (4 bytes).
/// Single Noise frame overhead: AEAD tag (16 B) + length prefix (4 B).
pub const FRAME_OVERHEAD: usize = 4 + 16;

/// Максимальный размер ciphertext-frame: payload + length prefix + tag.
/// Max ciphertext frame size: payload + length prefix + tag.
pub const MAX_FRAME_CIPHERTEXT: usize = MAX_FRAME_PAYLOAD + FRAME_OVERHEAD;

/// Сессия потокового трансфера поверх Noise transport cipher.
///
/// Streaming transfer session over Noise transport cipher.
///
/// Обёртка над `snow::TransportState`: `encode_frame` шифрует plaintext +
/// prepend length prefix; `decode_frame` parsed length + расшифровывает.
/// Состояние инкрементируется на каждом frame (nonce counter в snow).
///
/// Wraps `snow::TransportState`: `encode_frame` encrypts plaintext + prefixes
/// length; `decode_frame` parses length + decrypts. State advances on each
/// frame (internal nonce counter in snow).
pub struct TransferSession {
    transport: TransportState,
    handshake_hash: Vec<u8>,
}

impl TransferSession {
    /// Создать сессию из готового `TransportState` (после handshake completion).
    /// Wrap a `TransportState` obtained after handshake completion.
    ///
    /// `handshake_hash` должен быть взят **до** `into_transport_mode` через
    /// [`crate::device_transfer::handshake::TransferHandshakeResult::handshake_hash`].
    ///
    /// `handshake_hash` must be captured **before** `into_transport_mode`
    /// using `TransferHandshakeResult::handshake_hash`.
    #[must_use]
    pub fn new(transport: TransportState, handshake_hash: Vec<u8>) -> Self {
        Self {
            transport,
            handshake_hash,
        }
    }

    /// Зашифровать plaintext → ciphertext frame `<u32 len><opaque>`.
    /// Encrypt plaintext → ciphertext frame `<u32 len><opaque>`.
    ///
    /// # Errors
    /// - [`BackupError::StreamFrameTooLarge`] если plaintext > `MAX_FRAME_PAYLOAD`.
    /// - [`BackupError::HandshakeFailed`] если snow write вернул ошибку.
    pub fn encode_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
        if plaintext.len() > MAX_FRAME_PAYLOAD {
            return Err(BackupError::StreamFrameTooLarge {
                limit: MAX_FRAME_PAYLOAD,
                actual: plaintext.len(),
            });
        }
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| BackupError::HandshakeFailed("transport write"))?;
        buf.truncate(n);

        // Prepend length prefix (u32 BE).
        let mut out = Vec::with_capacity(4 + n);
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Parse length prefix + декрипт frame → plaintext.
    ///
    /// Принимает **ровно одну frame** начинающуюся с length prefix. Если в
    /// буфере больше данных — возвращает количество consumed байт через
    /// [`Self::decode_frame_consuming`].
    ///
    /// # Errors
    /// - [`BackupError::StreamUnexpectedEof`] если буфер короче объявленной длины.
    /// - [`BackupError::StreamFrameTooLarge`] если объявленная длина превышает лимит.
    /// - [`BackupError::HandshakeFailed`] если snow read вернул ошибку (tamper, wrong key).
    pub fn decode_frame(&mut self, wire: &[u8]) -> Result<Vec<u8>, BackupError> {
        let (plaintext, _) = self.decode_frame_consuming(wire)?;
        Ok(plaintext)
    }

    /// Parse length prefix + декрипт; возвращает (plaintext, consumed_bytes).
    ///
    /// # Errors
    /// - [`BackupError::StreamUnexpectedEof`] если буфер короче объявленной длины.
    /// - [`BackupError::StreamFrameTooLarge`] если объявленная длина превышает лимит.
    /// - [`BackupError::HandshakeFailed`] если snow read вернул ошибку.
    pub fn decode_frame_consuming(&mut self, wire: &[u8]) -> Result<(Vec<u8>, usize), BackupError> {
        if wire.len() < 4 {
            return Err(BackupError::StreamUnexpectedEof);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&wire[..4]);
        let cipher_len = u32::from_be_bytes(len_bytes) as usize;

        if cipher_len > MAX_FRAME_PAYLOAD + 16 {
            return Err(BackupError::StreamFrameTooLarge {
                limit: MAX_FRAME_PAYLOAD,
                actual: cipher_len.saturating_sub(16),
            });
        }
        let total = 4 + cipher_len;
        if wire.len() < total {
            return Err(BackupError::StreamUnexpectedEof);
        }

        let ct = &wire[4..total];
        let mut out = vec![0u8; cipher_len];
        let n = self
            .transport
            .read_message(ct, &mut out)
            .map_err(|_| BackupError::HandshakeFailed("transport read"))?;
        out.truncate(n);
        Ok((out, total))
    }

    /// Получить handshake hash сессии (snapshot'нут при создании).
    /// Return the session's handshake hash (captured at creation).
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

    use crate::device_transfer::handshake::{PairingInitiator, PairingResponder};
    use crate::device_transfer::qr::{build_signed_qr, PAIRING_CHALLENGE_LEN};

    /// Собрать пару `(initiator_session, responder_session)` через полный
    /// handshake Noise_IK. Возвращает обе сессии готовые к streaming.
    fn paired_sessions() -> (TransferSession, TransferSession) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let resp_sk = SigningKey::from_bytes(&seed);
        let resp_vk = resp_sk.verifying_key();

        let resp_eph_secret = XStatic::random_from_rng(OsRng);
        let resp_eph_pub = XPub::from(&resp_eph_secret).to_bytes();

        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);

        let qr = build_signed_qr(
            resp_vk.to_bytes(),
            resp_eph_pub,
            chal,
            u64::MAX / 2,
            |payload| Ok(resp_sk.sign(payload).to_bytes()),
        )
        .unwrap();

        let init_secret = XStatic::random_from_rng(OsRng);
        let mut initiator = PairingInitiator::new(&qr, &init_secret.to_bytes()).unwrap();
        let mut responder =
            PairingResponder::new(&resp_eph_secret.to_bytes(), &qr.pairing_challenge).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let (msg2, resp_result) = responder.write_message_2_and_finalize().unwrap();
        let init_result = initiator.read_message_2_and_finalize(&msg2).unwrap();

        (
            TransferSession::new(init_result.transport, init_result.handshake_hash.to_vec()),
            TransferSession::new(resp_result.transport, resp_result.handshake_hash.to_vec()),
        )
    }

    #[test]
    fn frame_encode_decode_roundtrip_small() {
        let (mut init, mut resp) = paired_sessions();
        // Responder шлёт → initiator читает.
        let plaintext = b"hello, world";
        let wire = resp.encode_frame(plaintext).unwrap();
        let decoded = init.decode_frame(&wire).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn frame_encode_decode_roundtrip_empty() {
        let (mut init, mut resp) = paired_sessions();
        let wire = resp.encode_frame(&[]).unwrap();
        let decoded = init.decode_frame(&wire).unwrap();
        assert_eq!(decoded.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn frame_encode_decode_roundtrip_large() {
        let (mut init, mut resp) = paired_sessions();
        let plaintext = vec![0x42u8; 65_000];
        let wire = resp.encode_frame(&plaintext).unwrap();
        let decoded = init.decode_frame(&wire).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn frame_rejects_oversize_plaintext() {
        let (_init, mut resp) = paired_sessions();
        let plaintext = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let err = resp.encode_frame(&plaintext).unwrap_err();
        assert!(matches!(err, BackupError::StreamFrameTooLarge { .. }));
    }

    #[test]
    fn frame_decode_detects_truncated_prefix() {
        let (mut init, _resp) = paired_sessions();
        let err = init.decode_frame(&[0u8; 3]).unwrap_err();
        assert!(matches!(err, BackupError::StreamUnexpectedEof));
    }

    #[test]
    fn frame_decode_detects_truncated_payload() {
        let (mut init, mut resp) = paired_sessions();
        let plaintext = b"some payload";
        let wire = resp.encode_frame(plaintext).unwrap();
        // Truncate last byte of ciphertext.
        let truncated = &wire[..wire.len() - 1];
        let err = init.decode_frame(truncated).unwrap_err();
        assert!(matches!(err, BackupError::StreamUnexpectedEof));
    }

    #[test]
    fn frame_decode_rejects_tampered_ciphertext() {
        let (mut init, mut resp) = paired_sessions();
        let plaintext = b"hello";
        let mut wire = resp.encode_frame(plaintext).unwrap();
        // Flip bit in ciphertext body (past the 4-byte len prefix).
        wire[6] ^= 1;
        let err = init.decode_frame(&wire).unwrap_err();
        assert!(matches!(err, BackupError::HandshakeFailed(_)));
    }

    #[test]
    fn frame_decode_rejects_oversize_length_prefix() {
        let (mut init, _resp) = paired_sessions();
        let mut wire = Vec::new();
        wire.extend_from_slice(&((MAX_FRAME_PAYLOAD + 1000) as u32).to_be_bytes());
        wire.extend_from_slice(&[0u8; 100]);
        let err = init.decode_frame(&wire).unwrap_err();
        assert!(matches!(err, BackupError::StreamFrameTooLarge { .. }));
    }

    #[test]
    fn frame_decode_consuming_reports_total_bytes() {
        let (mut init, mut resp) = paired_sessions();
        let plaintext = b"bi-directional";
        let wire = resp.encode_frame(plaintext).unwrap();
        let (_decoded, consumed) = init.decode_frame_consuming(&wire).unwrap();
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn bidirectional_transfer_multiple_frames() {
        let (mut init, mut resp) = paired_sessions();

        // Responder → initiator stream с тремя frame'ами.
        let frames_from_resp: [&[u8]; 3] = [b"frame1", b"second", b"third frame"];
        let mut wire_stream: Vec<u8> = Vec::new();
        for f in &frames_from_resp {
            let w = resp.encode_frame(f).unwrap();
            wire_stream.extend_from_slice(&w);
        }

        let mut cursor: &[u8] = &wire_stream;
        for expected in &frames_from_resp {
            let (decoded, consumed) = init.decode_frame_consuming(cursor).unwrap();
            assert_eq!(&decoded[..], *expected);
            cursor = &cursor[consumed..];
        }
        assert!(cursor.is_empty());

        // И обратный канал: initiator → responder одно сообщение.
        let reply = b"ack from initiator";
        let w = init.encode_frame(reply).unwrap();
        let decoded = resp.decode_frame(&w).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn handshake_hash_matches_between_sides() {
        let (init, resp) = paired_sessions();
        assert_eq!(init.handshake_hash(), resp.handshake_hash());
        assert!(!init.handshake_hash().is_empty());
    }
}
