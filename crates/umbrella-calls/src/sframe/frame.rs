//! Высокоуровневый SFrame API: [`SframeContext`] с 3-эпохальным кешем,
//! per-KID derivation cache, per-`(sender, epoch)` replay window, а также
//! свободные функции [`compute_kid`] / [`parse_kid`].
//!
//! ## Поток encrypt
//!
//! ```text
//! plaintext
//!   ├──> compute_kid(sender, current_epoch)
//!   ├──> derive_per_kid или cache hit
//!   ├──> SframeHeader::serialize(kid, counter) → AAD
//!   ├──> build_nonce(salt, counter)
//!   └──> AES-256-GCM(key, nonce, aad, plaintext) → ciphertext||tag
//!        wire = header || ciphertext||tag
//! ```
//!
//! ## Поток decrypt
//!
//! ```text
//! wire_bytes
//!   ├──> SframeHeader::parse → header + ciphertext||tag
//!   ├──> lookup epoch по KID.epoch16 в VecDeque cache (иначе StaleEpoch)
//!   ├──> replay window per-(sender, full_epoch).check_and_update (иначе Replay)
//!   ├──> derive_per_kid или cache hit
//!   ├──> build_nonce(salt, counter)
//!   └──> AES-256-GCM verify → plaintext (иначе AeadAuthFailure)
//! ```
//!
//! ## Forward secrecy
//!
//! При MLS `remove` эвиктнутый участник теряет доступ к новому `exporter_secret`
//! и не может derive новый `SframeBaseKey`. 3-эпохальный cache покрывает
//! MLS commit + network jitter окно ~5-10 секунд; более старые эпохи → `StaleEpoch`.
//!
//! High-level SFrame API: [`SframeContext`] with a 3-epoch cache, per-KID
//! derivation cache, per-`(sender, epoch)` replay window, plus free functions
//! [`compute_kid`] / [`parse_kid`].
//!
//! ## Encrypt flow
//!
//! ```text
//! plaintext
//!   ├──> compute_kid(sender, current_epoch)
//!   ├──> derive_per_kid or cache hit
//!   ├──> SframeHeader::serialize(kid, counter) → AAD
//!   ├──> build_nonce(salt, counter)
//!   └──> AES-256-GCM(key, nonce, aad, plaintext) → ciphertext||tag
//!        wire = header || ciphertext||tag
//! ```
//!
//! ## Decrypt flow
//!
//! ```text
//! wire_bytes
//!   ├──> SframeHeader::parse → header + ciphertext||tag
//!   ├──> look up epoch by KID.epoch16 in the VecDeque cache (else StaleEpoch)
//!   ├──> replay window per-(sender, full_epoch).check_and_update (else Replay)
//!   ├──> derive_per_kid or cache hit
//!   ├──> build_nonce(salt, counter)
//!   └──> AES-256-GCM verify → plaintext (else AeadAuthFailure)
//! ```
//!
//! ## Forward secrecy
//!
//! On MLS `remove`, the evicted member loses access to the new
//! `exporter_secret` and cannot derive a new `SframeBaseKey`. The 3-epoch
//! cache covers the MLS commit + network jitter window (~5-10 s); older
//! epochs become `StaleEpoch`.

use std::collections::{HashMap, VecDeque};

use crate::error::{CallError, Result};
use crate::sframe::aead::{aes256gcm_decrypt, aes256gcm_encrypt, build_nonce};
use crate::sframe::ciphersuite::AEAD_TAG_LEN;
use crate::sframe::derive::{PerKidKey, SframeBaseKey};
use crate::sframe::replay::ReplayWindow;
use crate::sframe::wire::{SframeHeader, MAX_HEADER_LEN};

/// Максимальная длина plaintext кадра = 1 MiB. SPEC-06 §6.3: двукратный запас
/// над 4K H.265 keyframe (~500 KiB). Выше — `CallError::FrameTooLarge`.
///
/// Maximum plaintext frame length = 1 MiB. SPEC-06 §6.3: 2× headroom over
/// a 4K H.265 keyframe (~500 KiB). Above this — `CallError::FrameTooLarge`.
pub const MAX_FRAME_PLAINTEXT_LEN: usize = 1024 * 1024;

/// Число одновременно закешированных эпох в [`SframeContext`]. ADR-009 решение 5:
/// 3 эпохи — баланс между UX (покрытие reorder + MLS commit) и forward secrecy.
///
/// Number of simultaneously cached epochs in [`SframeContext`]. ADR-009
/// decision 5: 3 epochs — balance between UX (reorder + MLS commit window)
/// and forward secrecy.
pub const EPOCH_CACHE_SIZE: usize = 3;

/// Канонический upper bound на wire-длину принимаемого кадра.
/// Используется для DoS-mitigation в [`SframeContext::decrypt_frame`]:
/// любой пакет длиннее отвергается **до** AEAD verify (экономия CPU).
///
/// Canonical upper bound on accepted wire-frame length. Used for DoS
/// mitigation in [`SframeContext::decrypt_frame`]: packets longer than this
/// are rejected **before** AEAD verification (saves CPU).
pub const MAX_FRAME_WIRE_LEN: usize = MAX_FRAME_PLAINTEXT_LEN + MAX_HEADER_LEN + AEAD_TAG_LEN;

/// Формула KID из draft-ietf-mls-sframe §3:
/// `kid = (sender_leaf_index_u32 << 16) | (epoch_u64 & 0xFFFF)`.
///
/// 48 старших bit = sender_leaf (u32 shifted на 16), 16 младших = truncated epoch.
/// 16-битное переполнение обрабатывается как full-group rekey (SPEC-06 §5.3).
///
/// KID formula from draft-ietf-mls-sframe §3:
/// `kid = (sender_leaf_index_u32 << 16) | (epoch_u64 & 0xFFFF)`.
///
/// Upper 48 bits = sender_leaf (u32 shifted left by 16), lower 16 = truncated
/// epoch. 16-bit overflow is handled as a full-group rekey (SPEC-06 §5.3).
pub fn compute_kid(sender_leaf_index: u32, epoch: u64) -> u64 {
    (u64::from(sender_leaf_index) << 16) | (epoch & 0xFFFF)
}

/// Обратная операция к [`compute_kid`]: восстанавливает `(sender_leaf, epoch16)`.
/// Полную эпоху восстанавливает [`SframeContext`] по 3-эпохальному cache.
///
/// Inverse of [`compute_kid`]: recovers `(sender_leaf, epoch16)`. The full
/// epoch is recovered by [`SframeContext`] from the 3-epoch cache.
pub fn parse_kid(kid: u64) -> (u32, u16) {
    let sender = (kid >> 16) as u32;
    let epoch16 = (kid & 0xFFFF) as u16;
    (sender, epoch16)
}

/// Результат успешной расшифровки кадра.
/// Result of a successful frame decryption.
pub struct DecryptedFrame {
    /// Расшифрованный plaintext. Decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// KID из wire-заголовка. KID from the wire header.
    pub kid: u64,
    /// Counter кадра. Frame counter.
    pub counter: u64,
    /// Sender leaf index (из KID). Sender leaf index (from KID).
    pub sender_leaf: u32,
    /// Полная эпоха (из [`SframeContext`] cache, не из обрезанного KID).
    /// Full epoch (from the [`SframeContext`] cache, not the truncated KID).
    pub epoch: u64,
}

/// `Debug` скрывает расшифрованный кадр: звонки нельзя случайно унести в журналы.
/// `Debug` redacts decrypted frame bytes: calls must not leak into logs.
impl core::fmt::Debug for DecryptedFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedFrame")
            .field("plaintext_len", &self.plaintext.len())
            .field("plaintext", &"<redacted>")
            .field("kid", &self.kid)
            .field("counter", &self.counter)
            .field("sender_leaf", &self.sender_leaf)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Активный SFrame encryption context одного участника группы.
///
/// Держит до 3 базовых ключей эпох (newest на front), кеш per-KID производных
/// ключей и per-(sender, epoch) replay window. Потокобезопасность — caller'а:
/// структура `!Sync`; для параллельных медиа-потоков создавайте свои экземпляры.
///
/// Active SFrame encryption context for one group participant.
///
/// Holds up to 3 epoch base keys (newest at front), a per-KID derived-key
/// cache, and per-(sender, epoch) replay windows. Thread-safety is the
/// caller's responsibility: the struct is `!Sync`; use separate instances
/// for parallel media streams.
pub struct SframeContext {
    epochs: VecDeque<SframeBaseKey>,
    per_kid_cache: HashMap<u64, PerKidKey>,
    replay: HashMap<(u32, u64), ReplayWindow>,
}

impl SframeContext {
    /// Создаёт пустой контекст. Вызов [`encrypt_frame`](Self::encrypt_frame) до
    /// первого [`advance_epoch`](Self::advance_epoch) вернёт
    /// [`CallError::MlsExporterUnavailable`].
    ///
    /// Creates an empty context. Calling [`encrypt_frame`](Self::encrypt_frame)
    /// before the first [`advance_epoch`](Self::advance_epoch) returns
    /// [`CallError::MlsExporterUnavailable`].
    pub fn new() -> Self {
        Self {
            epochs: VecDeque::with_capacity(EPOCH_CACHE_SIZE),
            per_kid_cache: HashMap::new(),
            replay: HashMap::new(),
        }
    }

    /// Добавляет новую эпоху (обычно после MLS `commit`). Новейшая эпоха
    /// размещается во front, при превышении лимита [`EPOCH_CACHE_SIZE`]
    /// эвиктится oldest — её per-KID derivations и replay window удаляются.
    ///
    /// Adds a new epoch (usually after an MLS `commit`). The newest epoch
    /// is placed at the front; when [`EPOCH_CACHE_SIZE`] is exceeded the
    /// oldest is evicted — its per-KID derivations and replay windows are
    /// dropped.
    pub fn advance_epoch(&mut self, base_key: SframeBaseKey) {
        self.epochs.push_front(base_key);
        while self.epochs.len() > EPOCH_CACHE_SIZE {
            if let Some(evicted) = self.epochs.pop_back() {
                let evicted_full = evicted.epoch();
                let evicted_e16 = (evicted_full & 0xFFFF) as u16;

                // Cleanup replay windows для полного epoch (точный match).
                // Cleanup replay windows by full epoch (exact match).
                self.replay.retain(|&(_, e), _| e != evicted_full);

                // Cleanup per-KID cache: KID содержит только epoch16. Если среди
                // оставшихся эпох нет ни одной с тем же epoch16 — safe удалить все
                // записи с этим epoch16. Иначе (wrap-around after 65 536 commits)
                // оставляем — они либо валидны под collision, либо будут тихо
                // replaced при новом derive.
                //
                // Cleanup per-KID cache: KID only carries epoch16. If no remaining
                // epoch shares this epoch16, it is safe to drop all entries with
                // this epoch16. Otherwise (wrap-around after 65 536 commits) keep
                // them — they are either valid under a collision or will be
                // silently replaced at the next derive.
                let collision = self
                    .epochs
                    .iter()
                    .any(|bk| (bk.epoch() & 0xFFFF) as u16 == evicted_e16);
                if !collision {
                    self.per_kid_cache
                        .retain(|&kid, _| (kid & 0xFFFF) as u16 != evicted_e16);
                }
            }
        }
    }

    /// Текущая (новейшая) эпоха в cache, либо `None` если ни одной не было.
    /// Current (newest) epoch in the cache, or `None` if none is present.
    pub fn current_epoch(&self) -> Option<u64> {
        self.epochs.front().map(SframeBaseKey::epoch)
    }

    /// Число эпох в cache (0..=[`EPOCH_CACHE_SIZE`]).
    /// Number of epochs in the cache (0..=[`EPOCH_CACHE_SIZE`]).
    pub fn epoch_count(&self) -> usize {
        self.epochs.len()
    }

    /// Lookup per-KID ключа: cache hit → immediate, miss → derive + insert.
    /// Look up a per-KID key: cache hit → immediate, miss → derive + insert.
    fn get_or_derive(&mut self, kid: u64) -> Result<&PerKidKey> {
        if !self.per_kid_cache.contains_key(&kid) {
            let epoch16 = (kid & 0xFFFF) as u16;
            // Найти матчирующую эпоху (clone-free поиск по `epoch() & 0xFFFF`).
            // Find the matching epoch (allocation-free by `epoch() & 0xFFFF`).
            let derived = match self
                .epochs
                .iter()
                .find(|bk| (bk.epoch() & 0xFFFF) as u16 == epoch16)
            {
                Some(bk) => bk.derive_per_kid(kid),
                None => {
                    let oldest = self.epochs.back().map(SframeBaseKey::epoch).unwrap_or(0);
                    return Err(CallError::StaleEpoch {
                        frame_epoch: u64::from(epoch16),
                        oldest_cached: oldest,
                    });
                }
            };
            self.per_kid_cache.insert(kid, derived);
        }
        self.per_kid_cache
            .get(&kid)
            .ok_or(CallError::UnknownKid(kid))
    }

    /// Шифрует `plaintext` для указанных `sender_leaf` и `counter` под
    /// текущей (`front`) эпохой. Возвращает wire-bytes `header || ct || tag`.
    ///
    /// Caller обязан монотонно увеличивать `counter` в рамках `(sender_leaf,
    /// current_epoch)` — это гарантия nonce-uniqueness для AES-GCM и
    /// поддержки anti-replay.
    ///
    /// # Ошибки
    ///
    /// - [`CallError::FrameTooLarge`] — `plaintext.len() > MAX_FRAME_PLAINTEXT_LEN`.
    /// - [`CallError::MlsExporterUnavailable`] — контекст пустой
    ///   (`advance_epoch` ещё не вызван).
    /// - [`CallError::AeadAuthFailure`] — внутренний AEAD сбой (extremely rare).
    ///
    /// Encrypts `plaintext` for the given `sender_leaf` and `counter` under
    /// the current (`front`) epoch. Returns the wire bytes
    /// `header || ct || tag`.
    ///
    /// The caller must monotonically increase `counter` within
    /// `(sender_leaf, current_epoch)` — this guarantees AES-GCM nonce
    /// uniqueness and anti-replay support.
    ///
    /// # Errors
    ///
    /// - [`CallError::FrameTooLarge`] — `plaintext.len() > MAX_FRAME_PLAINTEXT_LEN`.
    /// - [`CallError::MlsExporterUnavailable`] — empty context
    ///   (`advance_epoch` has not been called yet).
    /// - [`CallError::AeadAuthFailure`] — internal AEAD failure (extremely rare).
    pub fn encrypt_frame(
        &mut self,
        sender_leaf: u32,
        counter: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_FRAME_PLAINTEXT_LEN {
            return Err(CallError::FrameTooLarge {
                limit: MAX_FRAME_PLAINTEXT_LEN,
                actual: plaintext.len(),
            });
        }
        let epoch = self
            .current_epoch()
            .ok_or(CallError::MlsExporterUnavailable)?;
        let kid = compute_kid(sender_leaf, epoch);

        let per_kid = self.get_or_derive(kid)?;

        let mut hdr_buf = [0u8; MAX_HEADER_LEN];
        let hdr_len = SframeHeader::serialize(kid, counter, &mut hdr_buf);
        let aad = &hdr_buf[..hdr_len];

        // sframe_key передаётся по ссылке прямо из `SecretBox` через
        // `expose_secret`-обёртку — никакой stack-копии секрета не создаётся
        // (F-56 closure блок 10.15; F-46 pattern; SPEC-06 §5.1 promise
        // «sframe_key в SecretBox<[u8; 32]> с ZeroizeOnDrop»). Salt — не секрет
        // per SPEC-06 §5.2, но передаётся по ссылке для симметрии и нулевого
        // дополнительного копирования.
        //
        // sframe_key is passed by reference directly from the `SecretBox`
        // through the `expose_secret` wrapper — no stack copy of the secret
        // is created (F-56 closure block 10.15; F-46 pattern; SPEC-06 §5.1
        // promise "sframe_key in SecretBox<[u8; 32]> with ZeroizeOnDrop").
        // The salt is not secret per SPEC-06 §5.2 but is also passed by
        // reference for symmetry and zero extra copying.
        let nonce = build_nonce(per_kid.salt_bytes(), counter);
        let ct_tag = aes256gcm_encrypt(per_kid.key_bytes(), &nonce, aad, plaintext)?;

        let mut out = Vec::with_capacity(hdr_len + ct_tag.len());
        out.extend_from_slice(aad);
        out.extend_from_slice(&ct_tag);
        Ok(out)
    }

    /// Расшифровывает wire-кадр.
    ///
    /// Порядок проверок — важен: parse header → lookup epoch → replay → derive → AEAD.
    /// Replay check идёт до AEAD чтобы не тратить ~0.5 µs CPU на заведомый replay
    /// (SRTP делает так же — accepted trade-off «replay vs AeadAuth» на уровне
    /// side-channel).
    ///
    /// # Ошибки
    ///
    /// - [`CallError::InvalidHeader`] — битый wire.
    /// - [`CallError::FrameTooLarge`] — `bytes.len() > MAX_FRAME_WIRE_LEN`
    ///   (DoS mitigation — отвергается до AEAD verify).
    /// - [`CallError::StaleEpoch`] — эпоха не в 3-эпохальном cache.
    /// - [`CallError::Replay`] / [`CallError::OutOfReplayWindow`] — anti-replay.
    /// - [`CallError::AeadAuthFailure`] — подмена ciphertext/tag/AAD или
    ///   неверный ключ/nonce.
    ///
    /// Decrypts a wire frame.
    ///
    /// Check order matters: parse header → look up epoch → replay → derive →
    /// AEAD. The replay check runs before AEAD to avoid spending ~0.5 µs of
    /// CPU on an obvious replay (SRTP does the same — accepted "replay vs
    /// AeadAuth" side-channel trade-off).
    ///
    /// # Errors
    ///
    /// - [`CallError::InvalidHeader`] — malformed wire.
    /// - [`CallError::FrameTooLarge`] — `bytes.len() > MAX_FRAME_WIRE_LEN`
    ///   (DoS mitigation — rejected before AEAD verify).
    /// - [`CallError::StaleEpoch`] — the epoch is not in the 3-epoch cache.
    /// - [`CallError::Replay`] / [`CallError::OutOfReplayWindow`] — anti-replay.
    /// - [`CallError::AeadAuthFailure`] — ciphertext/tag/AAD tampering or
    ///   wrong key/nonce.
    pub fn decrypt_frame(&mut self, bytes: &[u8]) -> Result<DecryptedFrame> {
        if bytes.len() > MAX_FRAME_WIRE_LEN {
            return Err(CallError::FrameTooLarge {
                limit: MAX_FRAME_WIRE_LEN,
                actual: bytes.len(),
            });
        }
        let (header, rest) = SframeHeader::parse(bytes)?;
        if rest.len() < AEAD_TAG_LEN {
            return Err(CallError::InvalidHeader("ciphertext shorter than AEAD tag"));
        }

        let (sender_leaf, epoch16) = parse_kid(header.kid);
        let full_epoch = self
            .epochs
            .iter()
            .find(|bk| (bk.epoch() & 0xFFFF) as u16 == epoch16)
            .map(SframeBaseKey::epoch)
            .ok_or_else(|| {
                let oldest = self.epochs.back().map(SframeBaseKey::epoch).unwrap_or(0);
                CallError::StaleEpoch {
                    frame_epoch: u64::from(epoch16),
                    oldest_cached: oldest,
                }
            })?;

        // Replay check per (sender, full_epoch). Scope borrow, затем derive+AEAD.
        // Replay check per (sender, full_epoch). Scope the borrow before derive+AEAD.
        {
            let window = self
                .replay
                .entry((sender_leaf, full_epoch))
                .or_insert_with(|| ReplayWindow::new(sender_leaf));
            window.check_and_update(header.counter)?;
        }

        let per_kid = self.get_or_derive(header.kid)?;

        // sframe_key + salt передаются по ссылке из `SecretBox`/struct field
        // — никаких stack-копий секрета (F-56 closure блок 10.15; зеркалит
        // фикс в encrypt_frame). Salt non-secret per SPEC-06 §5.2.
        //
        // sframe_key + salt are passed by reference from `SecretBox`/struct
        // field — no stack copy of the secret (F-56 closure block 10.15;
        // mirrors the fix in encrypt_frame). Salt is non-secret per
        // SPEC-06 §5.2.
        let nonce = build_nonce(per_kid.salt_bytes(), header.counter);
        let aad = &bytes[..header.header_len];
        let ct_with_tag = &bytes[header.header_len..];

        let plaintext = aes256gcm_decrypt(per_kid.key_bytes(), &nonce, aad, ct_with_tag)?;
        Ok(DecryptedFrame {
            plaintext,
            kid: header.kid,
            counter: header.counter,
            sender_leaf,
            epoch: full_epoch,
        })
    }
}

impl Default for SframeContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sframe::ciphersuite::SframeCiphersuite;
    use proptest::prelude::*;

    fn ctx_with_epoch(epoch: u64, base_byte: u8) -> SframeContext {
        let mut ctx = SframeContext::new();
        ctx.advance_epoch(SframeBaseKey::from_mls_exporter(
            [base_byte; 64],
            SframeCiphersuite::Aes256GcmSha512,
            epoch,
        ));
        ctx
    }

    #[test]
    fn decrypted_frame_debug_redacts_plaintext() {
        let frame = DecryptedFrame {
            plaintext: b"private-sframe-media".to_vec(),
            kid: 11,
            counter: 12,
            sender_leaf: 13,
            epoch: 14,
        };

        let debug = format!("{frame:?}");

        assert!(
            !debug.contains("112, 114, 105, 118, 97, 116, 101"),
            "Debug output must not leak decrypted SFrame plaintext bytes: {debug}"
        );
        assert!(
            debug.contains("plaintext_len"),
            "Debug output should keep plaintext length metadata for diagnostics: {debug}"
        );
    }

    #[test]
    fn compute_kid_combines_sender_and_epoch() {
        // `(sender_u32 << 16) | epoch16` укладывается в младшие 48 бит u64.
        // `(sender_u32 << 16) | epoch16` fits into the lower 48 bits of u64.
        assert_eq!(compute_kid(0x1234, 0x5678), 0x0000_0000_1234_5678);
        assert_eq!(compute_kid(0, 0), 0);
        assert_eq!(compute_kid(u32::MAX, u64::MAX), 0x0000_FFFF_FFFF_FFFF);
        // Младшие 16 бит epoch сохраняются; верхние теряются (ADR-009 / SPEC-06 §5.3).
        // Lower 16 epoch bits kept; upper bits dropped (ADR-009 / SPEC-06 §5.3).
        assert_eq!(compute_kid(1, 0x1_0000), compute_kid(1, 0));
    }

    #[test]
    fn parse_kid_is_inverse_of_compute_kid() {
        let kid = compute_kid(0x0100_0000, 0x0005);
        let (sender, epoch16) = parse_kid(kid);
        assert_eq!(sender, 0x0100_0000);
        assert_eq!(epoch16, 0x0005);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_same_context() {
        let mut ctx = ctx_with_epoch(0, 0x42);
        let ct = ctx.encrypt_frame(3, 5, b"hello media frame").unwrap();
        let dec = ctx.decrypt_frame(&ct).unwrap();
        assert_eq!(dec.plaintext, b"hello media frame");
        assert_eq!(dec.counter, 5);
        assert_eq!(dec.sender_leaf, 3);
        assert_eq!(dec.epoch, 0);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_separate_contexts() {
        // Отправитель и получатель — независимые `SframeContext`, но общий base_key.
        // Sender and receiver are independent `SframeContext`s sharing a base_key.
        let mut tx = ctx_with_epoch(7, 0xAB);
        let mut rx = ctx_with_epoch(7, 0xAB);
        let ct = tx.encrypt_frame(1, 100, b"separate contexts").unwrap();
        let dec = rx.decrypt_frame(&ct).unwrap();
        assert_eq!(dec.plaintext, b"separate contexts");
        assert_eq!(dec.epoch, 7);
    }

    #[test]
    fn encrypt_without_epoch_fails() {
        let mut ctx = SframeContext::new();
        let err = ctx.encrypt_frame(0, 0, b"x").unwrap_err();
        assert!(matches!(err, CallError::MlsExporterUnavailable));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let mut tx = ctx_with_epoch(0, 0x42);
        let mut rx = ctx_with_epoch(0, 0x42);
        let mut ct = tx.encrypt_frame(0, 0, b"data").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let err = rx.decrypt_frame(&ct).unwrap_err();
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_tampered_counter_in_header_fails() {
        let mut tx = ctx_with_epoch(0, 0x42);
        let mut rx = ctx_with_epoch(0, 0x42);
        // sender_leaf=0, epoch16=0 → KID=0 inline (K=0, X=0). Counter=5 → 1 байт.
        // Header = CONFIG(1) + CTR(1) = 2 bytes. Positions: 0=CONFIG, 1=CTR.
        //
        // sender_leaf=0, epoch16=0 → KID=0 inline (K=0, X=0). Counter=5 → 1 byte.
        // Header = CONFIG(1) + CTR(1) = 2 bytes. Positions: 0=CONFIG, 1=CTR.
        let mut ct = tx.encrypt_frame(0, 5, b"data").unwrap();
        ct[1] ^= 0x01;
        let err = rx.decrypt_frame(&ct).unwrap_err();
        // Подменённый counter → AAD меняется → AEAD fail. Либо Replay если new counter
        // совпал со старым — но rx никогда не видел этого, так что AEAD fail гарантирован.
        //
        // Tampered counter → AAD changes → AEAD fail. Or Replay if the new counter
        // matches a prior one — but rx has not seen it, so AEAD failure is guaranteed.
        assert!(matches!(err, CallError::AeadAuthFailure));
    }

    #[test]
    fn decrypt_stale_epoch_fails() {
        let mut tx = ctx_with_epoch(5, 0x42);
        let ct = tx.encrypt_frame(0, 0, b"data").unwrap();
        // Новый rx-контекст с совсем другой epoch (epoch16 отличается).
        // Fresh rx context with a completely different epoch (different epoch16).
        let mut rx = SframeContext::new();
        rx.advance_epoch(SframeBaseKey::from_mls_exporter(
            [0x99; 64],
            SframeCiphersuite::Aes256GcmSha512,
            100,
        ));
        let err = rx.decrypt_frame(&ct).unwrap_err();
        assert!(matches!(err, CallError::StaleEpoch { .. }));
    }

    #[test]
    fn replay_same_frame_rejected() {
        let mut tx = ctx_with_epoch(0, 0x42);
        let mut rx = ctx_with_epoch(0, 0x42);
        let ct = tx.encrypt_frame(0, 5, b"data").unwrap();
        rx.decrypt_frame(&ct).unwrap();
        let err = rx.decrypt_frame(&ct).unwrap_err();
        assert!(matches!(err, CallError::Replay { .. }));
    }

    #[test]
    fn encrypt_too_large_rejected() {
        let mut ctx = ctx_with_epoch(0, 0x42);
        let huge = vec![0u8; MAX_FRAME_PLAINTEXT_LEN + 1];
        let err = ctx.encrypt_frame(0, 0, &huge).unwrap_err();
        assert!(matches!(
            err,
            CallError::FrameTooLarge {
                limit: MAX_FRAME_PLAINTEXT_LEN,
                ..
            }
        ));
    }

    #[test]
    fn decrypt_oversized_wire_rejected_before_aead() {
        let mut rx = ctx_with_epoch(0, 0x42);
        let huge = vec![0u8; MAX_FRAME_WIRE_LEN + 1];
        let err = rx.decrypt_frame(&huge).unwrap_err();
        assert!(matches!(
            err,
            CallError::FrameTooLarge {
                limit: MAX_FRAME_WIRE_LEN,
                ..
            }
        ));
    }

    #[test]
    fn advance_epoch_evicts_oldest_at_size_4() {
        let mut ctx = SframeContext::new();
        for e in 0..4 {
            ctx.advance_epoch(SframeBaseKey::from_mls_exporter(
                [e as u8; 64],
                SframeCiphersuite::Aes256GcmSha512,
                e as u64,
            ));
        }
        assert_eq!(ctx.epoch_count(), 3);
        assert_eq!(ctx.current_epoch(), Some(3));
    }

    #[test]
    fn decrypt_empty_bytes_fails() {
        let mut ctx = ctx_with_epoch(0, 0x42);
        let err = ctx.decrypt_frame(&[]).unwrap_err();
        assert!(matches!(err, CallError::InvalidHeader(_)));
    }

    #[test]
    fn decrypt_header_only_no_ciphertext_fails() {
        // Только 2-байтный header без ciphertext и tag.
        // Only a 2-byte header, no ciphertext or tag.
        let mut ctx = ctx_with_epoch(0, 0x42);
        let err = ctx.decrypt_frame(&[0x00, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            CallError::InvalidHeader("ciphertext shorter than AEAD tag")
        ));
    }

    #[test]
    fn reorder_within_window_accepted() {
        let mut tx = ctx_with_epoch(0, 0x42);
        let ct_5 = tx.encrypt_frame(0, 5, b"five").unwrap();
        let ct_3 = tx.encrypt_frame(0, 3, b"three").unwrap();
        let ct_8 = tx.encrypt_frame(0, 8, b"eight").unwrap();
        let ct_1 = tx.encrypt_frame(0, 1, b"one").unwrap();
        let mut rx = ctx_with_epoch(0, 0x42);
        assert_eq!(rx.decrypt_frame(&ct_5).unwrap().plaintext, b"five");
        assert_eq!(rx.decrypt_frame(&ct_3).unwrap().plaintext, b"three");
        assert_eq!(rx.decrypt_frame(&ct_8).unwrap().plaintext, b"eight");
        assert_eq!(rx.decrypt_frame(&ct_1).unwrap().plaintext, b"one");
    }

    #[test]
    fn per_kid_cache_hit_path() {
        // Повторный encrypt на той же паре (sender, epoch, counter-range) → cache hit.
        // Проверяем что cache действительно не re-derive — по наличию key в HashMap.
        //
        // Repeat encrypt on the same (sender, epoch, counter-range) → cache hit.
        // Verify the cache does not re-derive — by the key presence in the HashMap.
        let mut ctx = ctx_with_epoch(0, 0x42);
        let _ = ctx.encrypt_frame(7, 1, b"a").unwrap();
        let kid = compute_kid(7, 0);
        assert!(ctx.per_kid_cache.contains_key(&kid));
        let _ = ctx.encrypt_frame(7, 2, b"b").unwrap();
        // После двух frames от того же sender в той же эпохе — ровно одна запись.
        // After two frames from the same sender in the same epoch — exactly one entry.
        assert_eq!(
            ctx.per_kid_cache.len(),
            1,
            "exactly one KID derivation per (sender, epoch)"
        );
    }

    #[test]
    fn eviction_clears_per_kid_cache_for_evicted_epoch() {
        let mut ctx = SframeContext::new();
        // epoch16 уникальны: 0, 1, 2, 3.
        // Unique epoch16 values: 0, 1, 2, 3.
        for e in 0..4 {
            ctx.advance_epoch(SframeBaseKey::from_mls_exporter(
                [e as u8; 64],
                SframeCiphersuite::Aes256GcmSha512,
                e,
            ));
            let _ = ctx.encrypt_frame(0, 0, b"f").unwrap();
        }
        // После 4 commit'ов остаются эпохи 1, 2, 3 — KID из эпохи 0 должен быть эвиктнут.
        // After 4 commits epochs 1, 2, 3 remain — epoch-0 KID must be evicted.
        let evicted_kid = compute_kid(0, 0);
        assert!(!ctx.per_kid_cache.contains_key(&evicted_kid));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_tamper_any_byte_rejected_or_different_plaintext(
            pt in prop::collection::vec(any::<u8>(), 1..256),
            position_seed in 0usize..512,
            bit in 0u8..8,
        ) {
            let mut tx = ctx_with_epoch(0, 0x42);
            let mut ct = tx.encrypt_frame(3, 7, &pt).unwrap();
            let pos = position_seed % ct.len();
            ct[pos] ^= 1u8 << bit;
            let mut rx = ctx_with_epoch(0, 0x42);
            let result = rx.decrypt_frame(&ct);
            if let Ok(dec) = result {
                prop_assert_ne!(
                    dec.plaintext, pt,
                    "tampered ciphertext decoded to SAME plaintext — AEAD forgery"
                );
            }
        }

        #[test]
        fn prop_random_payload_roundtrips(
            pt in prop::collection::vec(any::<u8>(), 0..4096),
            sender in any::<u32>(),
            counter in any::<u64>(),
        ) {
            prop_assume!(pt.len() <= MAX_FRAME_PLAINTEXT_LEN);
            let mut tx = ctx_with_epoch(0, 0x42);
            let ct = tx.encrypt_frame(sender, counter, &pt).unwrap();
            let mut rx = ctx_with_epoch(0, 0x42);
            let dec = rx.decrypt_frame(&ct).unwrap();
            prop_assert_eq!(&dec.plaintext, &pt);
            prop_assert_eq!(dec.counter, counter);
            prop_assert_eq!(dec.sender_leaf, sender);
        }
    }
}
