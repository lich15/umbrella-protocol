//! Структурная валидация MLSMessage: тип body, group_id, epoch, message_hash. Без расшифровки.
//! Structural MLSMessage validation: body kind, group_id, epoch, message_hash. No decryption.
//!
//! Эти поля — единственное, что сервер legitimately видит в wire-format. Всё остальное
//! (ciphertext, sender identity, payload) остаётся приватным для участников группы.
//!
//! These fields are the only things the server legitimately sees in the wire format.
//! Everything else (ciphertext, sender identity, payload) stays private to the group members.

use std::panic::AssertUnwindSafe;

use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Минимальный размер TLS-кодированного MLS Message per RFC 9420 §6 framing
/// (protocol_version u16 + wire_format u16 + minimal body framing). Mirrors
/// `umbrella-mls::parser::MLS_MESSAGE_MIN_BYTES` (block 10.8 F-37 closure). Lower-bound
/// для bounds-check pre-parse; обвиозно truncated input отвергается до передачи `tls_codec`
/// parser. F-37 attack vector — 5 байт `[0,0,0,1,192]` — блокируется этой проверкой.
///
/// Minimum size of a TLS-encoded MLS Message per RFC 9420 §6 framing
/// (protocol_version u16 + wire_format u16 + minimal body framing). Mirrors
/// `umbrella-mls::parser::MLS_MESSAGE_MIN_BYTES` (block 10.8 F-37 closure). Lower bound for
/// bounds-check pre-parse; obviously truncated input is rejected before reaching the
/// `tls_codec` parser. The F-37 attack vector — 5 bytes `[0,0,0,1,192]` — is blocked by
/// this check.
pub const MLS_MESSAGE_MIN_BYTES: usize = 8;

/// Тип MLSMessage по wire-format. MLSMessage kind by wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// Зашифрованный handshake или application payload.
    /// Encrypted handshake or application payload.
    PrivateMessage,
    /// Незашифрованный handshake (используется только при policy != PURE_CIPHERTEXT).
    /// Unencrypted handshake (used only when policy != PURE_CIPHERTEXT).
    PublicMessage,
    /// Приглашение новому участнику.
    /// Welcome message for a new member.
    Welcome,
    /// Публичная информация о группе (для external init; Umbrella Private не использует).
    /// Public group info (for external init; Umbrella Private does not use).
    GroupInfo,
    /// Публичный «пропуск» устройства.
    /// Public device KeyPackage.
    KeyPackage,
}

/// Результат парсинга MLSMessage для серверной маршрутизации.
/// Result of parsing an MLSMessage for server-side routing.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedEnvelope {
    /// Тип body. Body kind.
    pub kind: EnvelopeKind,
    /// Group ID — есть только у PrivateMessage/PublicMessage (handshake + application).
    /// Welcome/KeyPackage/GroupInfo маршрутизируются по-другому.
    /// Group ID — only for PrivateMessage/PublicMessage (handshake + application).
    /// Welcome/KeyPackage/GroupInfo are routed differently.
    pub group_id: Option<Vec<u8>>,
    /// Epoch — есть только у handshake/application messages.
    /// Epoch — only for handshake/application messages.
    pub epoch: Option<u64>,
    /// Размер оригинальных байт. Size of the original bytes.
    pub wire_len: usize,
    /// SHA-256 от оригинальных байт — используется для anti-replay.
    /// SHA-256 of the original bytes — used for anti-replay.
    pub message_hash: [u8; 32],
}

/// `Debug` скрывает routing identifiers и replay hash.
/// `Debug` redacts routing identifiers and replay hash.
impl core::fmt::Debug for ParsedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedEnvelope")
            .field("kind", &self.kind)
            .field("group_id_len", &self.group_id.as_ref().map(Vec::len))
            .field("group_id", &"<redacted>")
            .field("epoch", &self.epoch)
            .field("wire_len", &self.wire_len)
            .field("message_hash_len", &self.message_hash.len())
            .field("message_hash", &"<redacted>")
            .finish()
    }
}

/// Ошибки парсинга wire-format. Wire-format parsing errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Байты не парсятся как MLSMessage (битый TLS codec).
    /// Bytes do not parse as MLSMessage (malformed TLS codec).
    #[error("malformed MLSMessage wire-format")]
    Malformed,
    /// Body-тип не поддерживается этим сервером (никогда не должно случаться на вход).
    /// Body kind not supported by this server (should never happen in practice).
    #[error("unsupported MLSMessage body kind")]
    UnsupportedKind,
    /// `tls_codec` parser panic'нул на malformed wire input. F-37-class regression
    /// в backend `tls_codec-0.4.2`. Block 10.14 inline-fix mirrors block 10.8 closure
    /// в `umbrella-mls::parser::parse_mls_message_safe`. Caller получает explicit `Err`
    /// с diagnostic category и должен log + reject (не silent fallback per постулат 14).
    ///
    /// `tls_codec` parser panicked on malformed wire input. F-37-class regression in the
    /// backend `tls_codec-0.4.2`. Block 10.14 inline-fix mirrors the block 10.8 closure in
    /// `umbrella-mls::parser::parse_mls_message_safe`. The caller receives an explicit `Err`
    /// with a diagnostic category and must log + reject (no silent fallback per postulate 14).
    #[error("MLS wire-format parser panicked: {kind}")]
    ParserPanic {
        /// Категория для diagnostics (e.g., "MlsMessageIn"). Diagnostics category.
        kind: &'static str,
    },
}

/// Валидирует wire-format MLSMessage и извлекает маршрутизационные метаданные.
/// Validates MLSMessage wire-format and extracts routing metadata.
///
/// Никакой криптооперации (decrypt/verify) не выполняется — только структурная валидация.
/// No crypto operation (decrypt/verify) is performed — structural validation only.
///
/// ## F-37 защита (block 10.14 inline-fix; mirrors block 10.8 `umbrella-mls::parser`)
///
/// Транзитивная зависимость `tls_codec-0.4.2` (через `openmls 0.8`) panic'ит на
/// 5-байтовом malformed input `[0,0,0,1,192]` в `quic_vec.rs:53` assertion
/// `len_len_log <= MAX_LEN_LEN_LOG`. На сервере single malformed wire frame от
/// uncontrolled adversary = remote process termination (DoS) для всех concurrent
/// sessions — недопустимо. Защита layered:
///
/// 1. **Bounds-check** (cheap O(1)): отвергаем input короче `MLS_MESSAGE_MIN_BYTES`
///    до передачи `tls_codec`. Блокирует known F-37 attack vector + similar-class
///    truncation.
/// 2. **`std::panic::catch_unwind`** (defensive): catch any panic не покрытый bounds-check
///    и преобразуем в `EnvelopeError::ParserPanic { kind }`. AssertUnwindSafe применён
///    осознанно — closure не share mutable state с outer scope (`bytes` — &[u8] read-only).
///
/// `umbrella-server-blind-postman` намеренно НЕ зависит от `umbrella-mls` (ADR-001
/// architectural separation: server-side compile-time isolation от identity / MLS state),
/// поэтому fix применён локально вместо re-export через umbrella-mls.
///
/// ## F-37 protection (block 10.14 inline-fix; mirrors block 10.8 `umbrella-mls::parser`)
///
/// The transitive dependency `tls_codec-0.4.2` (via `openmls 0.8`) panics on the 5-byte
/// malformed input `[0,0,0,1,192]` at `quic_vec.rs:53` assertion `len_len_log <=
/// MAX_LEN_LEN_LOG`. On the server, a single malformed wire frame from an uncontrolled
/// adversary equals remote process termination (DoS) for all concurrent sessions — not
/// acceptable. The defence is layered:
///
/// 1. **Bounds check** (cheap O(1)): reject input shorter than `MLS_MESSAGE_MIN_BYTES`
///    before passing it to `tls_codec`. Blocks the known F-37 attack vector and similar
///    truncation classes.
/// 2. **`std::panic::catch_unwind`** (defensive): catch any panic not covered by the bounds
///    check and convert it to `EnvelopeError::ParserPanic { kind }`. `AssertUnwindSafe`
///    is applied deliberately — the closure does not share mutable state with the outer
///    scope (`bytes` is a read-only `&[u8]`).
///
/// `umbrella-server-blind-postman` deliberately does NOT depend on `umbrella-mls` (ADR-001
/// architectural separation: server-side compile-time isolation from identity / MLS state),
/// therefore the fix is applied locally rather than re-exported via umbrella-mls.
pub fn parse_mls_envelope(bytes: &[u8]) -> Result<ParsedEnvelope, EnvelopeError> {
    let wire_len = bytes.len();

    // F-37 защита layer 1: bounds-check ДО передачи tls_codec parser. F-37 attack vector
    // (5-байтовый input [0,0,0,1,192]) и любая similar-class truncation отвергаются здесь.
    // F-37 protection layer 1: bounds-check before passing bytes to the tls_codec parser.
    // The F-37 attack vector (the 5-byte input [0,0,0,1,192]) and any similar-class
    // truncation are rejected here.
    if wire_len < MLS_MESSAGE_MIN_BYTES {
        return Err(EnvelopeError::Malformed);
    }

    let message_hash = compute_hash(bytes);

    // F-37 защита layer 2: defensive `std::panic::catch_unwind` для catch any panic
    // pattern не покрытый bounds-check. Постулат 14 «no silent fallback» — caller получает
    // explicit `EnvelopeError::ParserPanic` с diagnostic category вместо silent abort.
    // F-37 protection layer 2: defensive `std::panic::catch_unwind` for any panic pattern
    // not covered by the bounds check. Postulate 14 «no silent fallback» — the caller
    // receives an explicit `EnvelopeError::ParserPanic` with a diagnostic category instead
    // of a silent abort.
    let panic_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        MlsMessageIn::tls_deserialize_exact(bytes)
    }));

    let message = match panic_result {
        Ok(Ok(msg)) => msg,
        Ok(Err(_)) => return Err(EnvelopeError::Malformed),
        Err(_) => {
            return Err(EnvelopeError::ParserPanic {
                kind: "MlsMessageIn::tls_deserialize_exact panicked",
            })
        }
    };

    let kind = match message.wire_format() {
        openmls::framing::WireFormat::PrivateMessage => EnvelopeKind::PrivateMessage,
        openmls::framing::WireFormat::PublicMessage => EnvelopeKind::PublicMessage,
        openmls::framing::WireFormat::Welcome => EnvelopeKind::Welcome,
        openmls::framing::WireFormat::GroupInfo => EnvelopeKind::GroupInfo,
        openmls::framing::WireFormat::KeyPackage => EnvelopeKind::KeyPackage,
    };

    let (group_id, epoch) = match message.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => {
            let protocol: ProtocolMessage = ProtocolMessage::from(m);
            (
                Some(protocol.group_id().as_slice().to_vec()),
                Some(protocol.epoch().as_u64()),
            )
        }
        MlsMessageBodyIn::PublicMessage(m) => {
            let protocol: ProtocolMessage = ProtocolMessage::from(m);
            (
                Some(protocol.group_id().as_slice().to_vec()),
                Some(protocol.epoch().as_u64()),
            )
        }
        MlsMessageBodyIn::Welcome(_)
        | MlsMessageBodyIn::GroupInfo(_)
        | MlsMessageBodyIn::KeyPackage(_) => (None, None),
    };

    Ok(ParsedEnvelope {
        kind,
        group_id,
        epoch,
        wire_len,
        message_hash,
    })
}

/// SHA-256 хэш сырых байт — идентификатор сообщения для anti-replay.
/// SHA-256 hash of the raw bytes — a message identifier for anti-replay.
pub fn compute_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_bytes_rejected() {
        assert_eq!(
            parse_mls_envelope(b"\x00\x01garbage").unwrap_err(),
            EnvelopeError::Malformed
        );
        assert_eq!(
            parse_mls_envelope(&[]).unwrap_err(),
            EnvelopeError::Malformed
        );
    }

    #[test]
    fn truncated_private_message_rejected() {
        // Префикс валидного TLS wire-format MlsMessage (version 1 + body tag 2 для
        // PrivateMessage), но без тела — парсер должен упасть.
        // Prefix of valid TLS wire-format MlsMessage (version 1 + body tag 2 for
        // PrivateMessage) but without body — parser must fail.
        let bytes = [0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            parse_mls_envelope(&bytes).unwrap_err(),
            EnvelopeError::Malformed
        );
    }

    #[test]
    fn compute_hash_is_sha256_of_input() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = compute_hash(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn parsed_envelope_debug_redacts_routing_identifiers() {
        let parsed = ParsedEnvelope {
            kind: EnvelopeKind::PrivateMessage,
            group_id: Some(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            epoch: Some(7),
            wire_len: 1024,
            message_hash: [0xEE; 32],
        };

        let debug = format!("{parsed:?}");

        assert!(
            !debug.contains("group_id: Some(["),
            "Debug output must not leak group routing bytes: {debug}"
        );
        assert!(
            !debug.contains("message_hash: ["),
            "Debug output must not leak replay/correlation hash bytes: {debug}"
        );
        assert!(
            debug.contains("group_id_len") && debug.contains("message_hash_len"),
            "Debug output should keep safe diagnostic lengths: {debug}"
        );
    }

    #[test]
    fn compute_hash_changes_on_single_bit_flip() {
        let base = b"hello";
        let h_base = compute_hash(base);
        let mut flipped = base.to_vec();
        flipped[0] ^= 0x01;
        let h_flip = compute_hash(&flipped);
        assert_ne!(h_base, h_flip);
    }
}
