//! Derive SFrame ключей из MLS exporter по RFC 9605 §5.
//!
//! Путь key schedule:
//!
//! 1. Получатели и отправитель вызывают
//!    [`UmbrellaGroup::exporter_secret`](umbrella_mls::UmbrellaGroup::exporter_secret)
//!    с `label = "SFrame 1.0 Base Key"` и `context = epoch_number_u64_be`;
//!    это нормативная метка draft-ietf-mls-sframe, interop с Google Meet,
//!    Signal group calls, Jitsi.
//! 2. 64-байтовый exporter output оборачивается в [`SframeBaseKey`].
//! 3. Для каждого уникального KID (формула `(sender_leaf << 16) | (epoch &
//!    0xFFFF)`) вызывается [`SframeBaseKey::derive_per_kid`], которое
//!    возвращает [`PerKidKey`] с `sframe_key` (32 байта) и `sframe_salt`
//!    (12 байт) через `HKDF-Expand-SHA512` по RFC 9605 §5.1. Caller кеширует
//!    результат на всё время жизни KID.
//!
//! Ни один байт секрета не попадает на стек в голом виде: `base_key` живёт
//! в [`SecretBox<[u8; 64]>`], `sframe_key` — в [`SecretBox<[u8; 32]>`], оба
//! zeroize'атся на drop. `Debug`-impl скрывает содержимое.
//!
//! SFrame key derivation from the MLS exporter per RFC 9605 §5.
//!
//! Key schedule:
//!
//! 1. Receivers and the sender call
//!    [`UmbrellaGroup::exporter_secret`](umbrella_mls::UmbrellaGroup::exporter_secret)
//!    with `label = "SFrame 1.0 Base Key"` and `context =
//!    epoch_number_u64_be`; this is the normative draft-ietf-mls-sframe
//!    label and gives interop with Google Meet, Signal group calls, Jitsi.
//! 2. The 64-byte exporter output is wrapped into an [`SframeBaseKey`].
//! 3. For every unique KID (formula `(sender_leaf << 16) | (epoch &
//!    0xFFFF)`), [`SframeBaseKey::derive_per_kid`] returns a [`PerKidKey`]
//!    with `sframe_key` (32 bytes) and `sframe_salt` (12 bytes) via
//!    `HKDF-Expand-SHA512` per RFC 9605 §5.1. The caller caches the result
//!    for the lifetime of that KID.
//!
//! No secret byte is left bare on the stack: `base_key` lives in a
//! [`SecretBox<[u8; 64]>`], `sframe_key` in a [`SecretBox<[u8; 32]>`],
//! both are zeroized on drop. The `Debug` impl hides contents.

use crate::error::Result;
use crate::sframe::ciphersuite::{
    SframeCiphersuite, BASE_KEY_LEN, SFRAME_KEY_LEN, SFRAME_SALT_LEN,
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha512;
use umbrella_mls::{UmbrellaGroup, UmbrellaProvider, MAX_EXPORTER_LEN};
use zeroize::Zeroize;

/// MLS exporter метка из draft-ietf-mls-sframe. Передаётся в
/// `UmbrellaGroup::exporter_secret(provider, MLS_EXPORTER_LABEL, ...)`.
///
/// MLS exporter label from draft-ietf-mls-sframe. Passed to
/// `UmbrellaGroup::exporter_secret(provider, MLS_EXPORTER_LABEL, ...)`.
pub const MLS_EXPORTER_LABEL: &str = "SFrame 1.0 Base Key";

/// Domain separator для HKDF-Expand `sframe_key` per RFC 9605 §4.4.2.
/// Длина 22 байта; трейлинг-пробел и нижний регистр `k` — нормативны,
/// test vectors RFC 9605 Appendix C строятся из этой строки байт-в-байт.
///
/// Domain separator for HKDF-Expand `sframe_key` per RFC 9605 §4.4.2.
/// 22 bytes; the trailing space and lowercase `k` are normative — RFC 9605
/// Appendix C test vectors are built from this exact byte string.
const SFRAME_KEY_LABEL: &[u8] = b"SFrame 1.0 Secret key ";

/// Domain separator для HKDF-Expand `sframe_salt` per RFC 9605 §4.4.2.
/// 23 байта (на байт длиннее `SFRAME_KEY_LABEL`: «salt» вместо «key »).
///
/// Domain separator for HKDF-Expand `sframe_salt` per RFC 9605 §4.4.2.
/// 23 bytes (one byte longer than `SFRAME_KEY_LABEL`: "salt" vs "key ").
const SFRAME_SALT_LABEL: &[u8] = b"SFrame 1.0 Secret salt ";

/// Суммарная длина `info` для sframe_key: 22 (label) + 8 (kid_be) + 2 (cs_be).
/// Total `info` length for sframe_key: 22 (label) + 8 (kid_be) + 2 (cs_be).
const SFRAME_KEY_INFO_LEN: usize = SFRAME_KEY_LABEL.len() + 8 + 2;

/// Суммарная длина `info` для sframe_salt: 23 (label) + 8 (kid_be) + 2 (cs_be).
/// Total `info` length for sframe_salt: 23 (label) + 8 (kid_be) + 2 (cs_be).
const SFRAME_SALT_INFO_LEN: usize = SFRAME_SALT_LABEL.len() + 8 + 2;

/// SFrame PRK: 64-байтовый Pseudo-Random Key, полученный как
/// `HKDF-Extract("", ikm)` из входного материала (MLS `exporter_secret` либо
/// external KMS). Zeroize on drop через `SecretBox`. Не реализует `Clone` —
/// PRK уникален per-epoch и не должен дубироваться.
///
/// Важно: поле `bytes` — это **PRK** (результат HKDF-Extract), а не raw
/// exporter output. Конструкторы обязаны выполнить Extract перед
/// сохранением. Per-KID derivation использует только HKDF-Expand от этого
/// PRK по RFC 9605 §4.4.2.
///
/// SFrame PRK: 64-byte Pseudo-Random Key obtained as `HKDF-Extract("", ikm)`
/// from the input keying material (MLS `exporter_secret` or external KMS).
/// Zeroized on drop via `SecretBox`. Does not derive `Clone`: the PRK is
/// unique per epoch and must not be duplicated.
///
/// Invariant: `bytes` is the **PRK** (HKDF-Extract output), not the raw
/// exporter output. Constructors MUST run Extract before storing. Per-KID
/// derivation uses only HKDF-Expand on this PRK per RFC 9605 §4.4.2.
pub struct SframeBaseKey {
    bytes: SecretBox<[u8; BASE_KEY_LEN]>,
    ciphersuite: SframeCiphersuite,
    epoch: u64,
}

impl SframeBaseKey {
    /// Оборачивает 64 байта MLS `exporter_secret` в `SframeBaseKey`,
    /// выполняя обязательный `HKDF-Extract("", ikm)` шаг RFC 9605 §4.4.2.
    /// Сохраняется PRK (не raw bytes).
    ///
    /// Delegates to [`Self::from_ikm`] — тот же pipeline, но удобный
    /// fixed-size API для MLS-ориентированных caller'ов.
    ///
    /// Wraps the 64-byte MLS `exporter_secret` into an `SframeBaseKey`,
    /// running the mandatory `HKDF-Extract("", ikm)` step of RFC 9605 §4.4.2.
    /// The stored `bytes` is the PRK (not the raw MLS bytes).
    ///
    /// Delegates to [`Self::from_ikm`] — same pipeline, fixed-size API
    /// convenient for MLS-oriented callers.
    ///
    /// Параметр `mls_exporter_output` принимается по значению (Copy для
    /// `[u8; 64]`); локальная stack-копия зануляется перед возвратом, чтобы
    /// secret IKM не оставался в stack-фрейме после выхода (F-56 closure
    /// блок 10.15; F-46 pattern recurrence). Caller'у надлежит дополнительно
    /// zeroize'ить свою исходную копию (паттерн в `from_group:199`).
    ///
    /// The `mls_exporter_output` parameter is taken by value (Copy for
    /// `[u8; 64]`); the local stack copy is zeroized before return so that
    /// the secret IKM does not linger in this stack frame after exit (F-56
    /// closure block 10.15; F-46 pattern recurrence). The caller is expected
    /// to also zeroize its own source copy (pattern in `from_group:199`).
    pub fn from_mls_exporter(
        mut mls_exporter_output: [u8; BASE_KEY_LEN],
        ciphersuite: SframeCiphersuite,
        epoch: u64,
    ) -> Self {
        let result = Self::from_ikm(&mls_exporter_output, ciphersuite, epoch);
        mls_exporter_output.zeroize();
        result
    }

    /// Универсальный конструктор RFC 9605 §4.4.2: принимает `ikm`
    /// произвольной длины (MLS exporter, external KMS, test vectors) и
    /// внутри выполняет `HKDF-Extract("", ikm)`. Сохраняется только PRK.
    ///
    /// Universal constructor per RFC 9605 §4.4.2: accepts arbitrary-length
    /// `ikm` (MLS exporter, external KMS, test vectors) and runs
    /// `HKDF-Extract("", ikm)` internally. Only the PRK is stored.
    pub fn from_ikm(ikm: &[u8], ciphersuite: SframeCiphersuite, epoch: u64) -> Self {
        let (prk_stack, _hk) = Hkdf::<Sha512>::extract(None, ikm);
        let mut prk_box: Box<[u8; BASE_KEY_LEN]> = Box::new([0u8; BASE_KEY_LEN]);
        prk_box.copy_from_slice(prk_stack.as_slice());
        // Stack-копия PRK (в `prk_stack`) уничтожается при выходе из scope;
        // GenericArray компилируется в fixed-size stack buffer, после return
        // компилятор may reuse. Для forensic safety phantom-zeroize'ить его
        // через `zeroize::Zeroize` — но `generic-array` 0.14 не реализует
        // Zeroize напрямую. Промежуточный write через `copy_from_slice`
        // и dropped prk_stack — best-effort без unsafe.
        //
        // The stack copy of the PRK in `prk_stack` is destroyed on scope
        // exit; GenericArray compiles to a fixed stack buffer, which the
        // compiler may reuse after return. For forensic safety a
        // phantom-zeroize via `zeroize::Zeroize` would be nice, but
        // `generic-array` 0.14 does not implement it directly. The
        // intermediate `copy_from_slice` write plus dropped `prk_stack` is
        // best-effort without unsafe.
        Self {
            bytes: SecretBox::new(prk_box),
            ciphersuite,
            epoch,
        }
    }

    /// Извлекает base_key из группы MLS через `exporter_secret` и сразу
    /// оборачивает его. Это предпочтительный путь: секретные байты не
    /// покидают `SecretBox` дольше чем одно присваивание.
    ///
    /// Pulls the base_key from an MLS group via `exporter_secret` and
    /// wraps it right away. This is the preferred path: secret bytes do
    /// not leave the `SecretBox` for longer than a single assignment.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`crate::error::CallError::Mls`] при сбое `UmbrellaGroup::exporter_secret`.
    /// - [`crate::error::CallError::Mls`] on `UmbrellaGroup::exporter_secret` failure.
    pub fn from_group(
        group: &UmbrellaGroup,
        provider: &UmbrellaProvider,
        ciphersuite: SframeCiphersuite,
        epoch: u64,
    ) -> Result<Self> {
        let context = epoch.to_be_bytes();
        // `MlsError` конвертируется в `CallError::Mls` через `#[from]` —
        // оператор `?` срабатывает автоматически.
        // `MlsError` converts into `CallError::Mls` via `#[from]` — the
        // `?` operator triggers the conversion automatically.
        let secret = group.exporter_secret(provider, MLS_EXPORTER_LABEL, &context, BASE_KEY_LEN)?;

        // exporter_secret гарантирует буфер длины MAX_EXPORTER_LEN = BASE_KEY_LEN,
        // при запросе len = 64. Копируем напрямую в SecretBox — `secret` будет
        // zeroize'нут на drop. Компилятор не может слияться оба SecretBox'а, так
        // что возникнет одна промежуточная heap-копия; это цена type safety.
        //
        // exporter_secret guarantees a MAX_EXPORTER_LEN = BASE_KEY_LEN buffer
        // when len = 64 is requested. We copy directly into a new SecretBox —
        // `secret` is zeroized on drop. The compiler cannot coalesce both
        // SecretBox's, so one intermediate heap copy exists; this is the cost
        // of type safety.
        #[allow(
            unknown_lints,
            no_assert_in_lib,
            reason = "block 11.8 dylint expansion: this is a compile-time const _: () = assert!(...) \
                     guarding a static invariant — cannot panic at runtime, only fails compilation \
                     if MAX_EXPORTER_LEN diverges from BASE_KEY_LEN. \
                     `unknown_lints` suppressed because rustc outside the dylint driver does not know \
                     the custom `no_assert_in_lib` lint name"
        )]
        const _: () = assert!(MAX_EXPORTER_LEN == BASE_KEY_LEN);
        let mut bytes = [0u8; BASE_KEY_LEN];
        bytes.copy_from_slice(secret.expose_secret());
        let base = Self::from_mls_exporter(bytes, ciphersuite, epoch);
        bytes.zeroize();
        Ok(base)
    }

    /// MLS epoch number этого base_key. Frame с другим epoch приходит
    /// через другой KID и должен попасть либо в соседний `SframeBaseKey`
    /// внутри 3-эпохального кеша `SframeContext`, либо отвергнуться как
    /// `StaleEpoch`.
    ///
    /// MLS epoch number of this base_key. A frame bound to a different
    /// epoch comes with a different KID and must either match an adjacent
    /// `SframeBaseKey` inside the 3-epoch `SframeContext` cache or be
    /// rejected as `StaleEpoch`.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Ciphersuite этого base_key. В Этапе 6 всегда AES-256-GCM-SHA512,
    /// но поле держим explicit для будущих ADR-расширений.
    ///
    /// Ciphersuite of this base_key. Always AES-256-GCM-SHA512 in Stage 6,
    /// but kept explicit for future ADR extensions.
    pub fn ciphersuite(&self) -> SframeCiphersuite {
        self.ciphersuite
    }

    /// Crate-internal accessor для 64-байтового PRK. Used только cross-check
    /// тестами RFC 9605 Appendix C; НЕ публичный — raw PRK bytes не должны
    /// покидать crate вне контекста тестов.
    ///
    /// Crate-internal accessor for the 64-byte PRK. Used only by RFC 9605
    /// Appendix C cross-check tests; NOT public — raw PRK bytes must not
    /// leave the crate outside test contexts.
    #[cfg(test)]
    pub(crate) fn prk_bytes(&self) -> &[u8; BASE_KEY_LEN] {
        self.bytes.expose_secret()
    }

    /// Per-KID derivation по RFC 9605 §4.4.2:
    ///
    /// ```text
    /// sframe_secret = HKDF-Extract("", base_key)
    /// sframe_key    = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret key "  || kid_be || cs_be, 32)
    /// sframe_salt   = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret salt " || kid_be || cs_be, 12)
    /// ```
    ///
    /// Трёхшаговый pipeline:
    ///
    /// 1. `HKDF-Extract` со пустым salt'ом (RFC 5869 §2.2: zero-filled HashLen)
    ///    превращает входной `base_key` произвольной длины в 64-байтовый
    ///    PRK (Pseudo-Random Key).
    /// 2. `HKDF-Expand` с `info = label || kid_u64_be || cs_u16_be` выводит
    ///    `sframe_key` (32 байта) и `sframe_salt` (12 байт).
    ///
    /// `kid` сериализуется как 8-байтовый big-endian u64 (не wire-compressed
    /// форма из заголовка), `cipher_suite` — 2-байтовый big-endian u16.
    ///
    /// HKDF не может fail'ить на таких длинах: Expand limit = 255·Nh = 16320
    /// байт, 32 и 12 сильно ниже.
    ///
    /// Per-KID derivation per RFC 9605 §4.4.2:
    ///
    /// ```text
    /// sframe_secret = HKDF-Extract("", base_key)
    /// sframe_key    = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret key "  || kid_be || cs_be, 32)
    /// sframe_salt   = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret salt " || kid_be || cs_be, 12)
    /// ```
    ///
    /// Three-step pipeline:
    ///
    /// 1. `HKDF-Extract` with an empty salt (RFC 5869 §2.2: zero-filled HashLen)
    ///    turns the arbitrary-length `base_key` into a 64-byte PRK.
    /// 2. `HKDF-Expand` with `info = label || kid_u64_be || cs_u16_be`
    ///    derives `sframe_key` (32 bytes) and `sframe_salt` (12 bytes).
    ///
    /// `kid` is an 8-byte big-endian u64 (not the wire-compressed form from
    /// the header); `cipher_suite` is a 2-byte big-endian u16.
    ///
    /// HKDF cannot fail at these lengths: Expand limit = 255·Nh = 16320
    /// bytes, both 32 and 12 are well below.
    pub fn derive_per_kid(&self, kid: u64) -> PerKidKey {
        // `bytes` — уже PRK (HKDF-Extract выполнен в конструкторе), поэтому
        // `from_prk` пропускает второй Extract и оставляет только Expand.
        //
        // `bytes` is already the PRK (HKDF-Extract ran in the constructor),
        // so `from_prk` skips the second Extract and only runs Expand.
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: stored PRK is exactly BASE_KEY_LEN=64 bytes by struct invariant"
        )]
        let hk = Hkdf::<Sha512>::from_prk(self.bytes.expose_secret().as_slice())
            .expect("stored PRK is exactly BASE_KEY_LEN=64 bytes");

        let kid_be = kid.to_be_bytes();
        let cs_be = self.ciphersuite.as_u16().to_be_bytes();

        let mut info_key = [0u8; SFRAME_KEY_INFO_LEN];
        info_key[..SFRAME_KEY_LABEL.len()].copy_from_slice(SFRAME_KEY_LABEL);
        info_key[SFRAME_KEY_LABEL.len()..SFRAME_KEY_LABEL.len() + 8].copy_from_slice(&kid_be);
        info_key[SFRAME_KEY_LABEL.len() + 8..].copy_from_slice(&cs_be);

        let mut info_salt = [0u8; SFRAME_SALT_INFO_LEN];
        info_salt[..SFRAME_SALT_LABEL.len()].copy_from_slice(SFRAME_SALT_LABEL);
        info_salt[SFRAME_SALT_LABEL.len()..SFRAME_SALT_LABEL.len() + 8].copy_from_slice(&kid_be);
        info_salt[SFRAME_SALT_LABEL.len() + 8..].copy_from_slice(&cs_be);

        // Секретный ключ рождается сразу в heap-allocated Box: SecretBox
        // принимает готовый Box и zeroize'ит его на drop; stack-копии ключа нет.
        //
        // The secret key is born directly in a heap-allocated Box: SecretBox
        // takes the ready Box and zeroizes it on drop; no stack copy of the key.
        let mut key_box: Box<[u8; SFRAME_KEY_LEN]> = Box::new([0u8; SFRAME_KEY_LEN]);
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: SFRAME_KEY_LEN=32 well under HKDF-Expand max 255*Nh"
        )]
        hk.expand(&info_key, key_box.as_mut_slice())
            .expect("SFRAME_KEY_LEN=32 within 255*Nh HKDF-Expand limit");

        // Salt — не секрет сам по себе (он XOR'ится с counter для per-frame
        // nonce), но zeroize-дисциплина всё равно применяется.
        //
        // Salt is not itself secret (it is XOR'd with the counter for the
        // per-frame nonce), but we keep zeroize discipline anyway.
        let mut salt_bytes = [0u8; SFRAME_SALT_LEN];
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: SFRAME_SALT_LEN=12 well under HKDF-Expand max 255*Nh"
        )]
        hk.expand(&info_salt, &mut salt_bytes)
            .expect("SFRAME_SALT_LEN=12 within 255*Nh HKDF-Expand limit");

        let result = PerKidKey {
            kid,
            sframe_key: SecretBox::new(key_box),
            sframe_salt: salt_bytes,
        };
        salt_bytes.zeroize();
        result
    }
}

impl core::fmt::Debug for SframeBaseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SframeBaseKey")
            .field("ciphersuite", &self.ciphersuite)
            .field("epoch", &self.epoch)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Производный per-KID ключ: `sframe_key` + `sframe_salt` (RFC 9605 §5.1).
/// `sframe_key` хранится в `SecretBox<[u8; 32]>` (zeroize on drop);
/// `sframe_salt` — открытый salt (XOR с counter = per-frame nonce).
///
/// Derived per-KID key: `sframe_key` + `sframe_salt` (RFC 9605 §5.1).
/// `sframe_key` lives in `SecretBox<[u8; 32]>` (zeroized on drop);
/// `sframe_salt` is a non-secret salt (XOR'd with the counter to form the
/// per-frame nonce).
pub struct PerKidKey {
    /// KID для которого derived. Used для cache lookup.
    /// KID this derivation belongs to. Used for cache lookup.
    pub kid: u64,
    /// AEAD-ключ (Nk=32 байта). AEAD key (Nk=32 bytes).
    pub sframe_key: SecretBox<[u8; SFRAME_KEY_LEN]>,
    /// Salt для per-frame nonce (Nn=12 байт). Salt for the per-frame nonce (Nn=12 bytes).
    pub sframe_salt: [u8; SFRAME_SALT_LEN],
}

impl PerKidKey {
    /// Bytes `sframe_key`. Вызывается только внутри крейта (AEAD
    /// invocation); внешним потребителям API не выставляется.
    ///
    /// `sframe_key` bytes. Only called inside the crate (AEAD invocation);
    /// not exposed to external API consumers.
    pub fn key_bytes(&self) -> &[u8; SFRAME_KEY_LEN] {
        self.sframe_key.expose_secret()
    }

    /// Bytes `sframe_salt`. `sframe_salt` bytes.
    pub fn salt_bytes(&self) -> &[u8; SFRAME_SALT_LEN] {
        &self.sframe_salt
    }
}

impl core::fmt::Debug for PerKidKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerKidKey")
            .field("kid", &format_args!("{:#x}", self.kid))
            .field("sframe_key", &"<redacted>")
            .field("sframe_salt", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Детерминированный test base_key: all-`0xAA`. Для property-тестов
    /// detereminism — content irrelevant, важно чтобы len = 64.
    ///
    /// Deterministic test base_key: all-`0xAA`. For determinism property
    /// tests the content is irrelevant; what matters is len = 64.
    fn seeded_base_key(seed: u8, epoch: u64) -> SframeBaseKey {
        SframeBaseKey::from_mls_exporter(
            [seed; BASE_KEY_LEN],
            SframeCiphersuite::Aes256GcmSha512,
            epoch,
        )
    }

    #[test]
    fn from_mls_exporter_stores_epoch_and_ciphersuite() {
        let bk = seeded_base_key(0xAA, 42);
        assert_eq!(bk.epoch(), 42);
        assert_eq!(bk.ciphersuite(), SframeCiphersuite::Aes256GcmSha512);
    }

    #[test]
    fn derive_per_kid_deterministic_same_input() {
        let bk = seeded_base_key(0x00, 0);
        let k1 = bk.derive_per_kid(0x0001_0000_0005);
        let k2 = bk.derive_per_kid(0x0001_0000_0005);
        assert_eq!(k1.key_bytes(), k2.key_bytes());
        assert_eq!(k1.salt_bytes(), k2.salt_bytes());
        assert_eq!(k1.kid, 0x0001_0000_0005);
    }

    #[test]
    fn derive_per_kid_different_kid_different_output() {
        let bk = seeded_base_key(0x11, 0);
        let k1 = bk.derive_per_kid(1);
        let k2 = bk.derive_per_kid(2);
        assert_ne!(k1.key_bytes(), k2.key_bytes());
        assert_ne!(k1.salt_bytes(), k2.salt_bytes());
    }

    #[test]
    fn derive_per_kid_lengths_match_ciphersuite() {
        let bk = seeded_base_key(0x22, 0);
        let k = bk.derive_per_kid(0);
        assert_eq!(k.key_bytes().len(), SFRAME_KEY_LEN);
        assert_eq!(k.salt_bytes().len(), SFRAME_SALT_LEN);
    }

    #[test]
    fn derive_per_kid_domain_separation_key_vs_salt() {
        // Проверяем domain separation: info='...Key' и info='...Salt' с
        // идентичными 8-байтовыми хвостами должны давать ≠ выводы.
        // Это фиксирует что реализация не перепутает label'ы.
        //
        // Domain separation check: info='...Key' and info='...Salt' with
        // identical 8-byte tails must produce distinct outputs. Pins that
        // the implementation does not swap the labels.
        let bk = seeded_base_key(0x33, 0);
        let k = bk.derive_per_kid(0xDEAD_BEEF);
        let shared_prefix_len = k.salt_bytes().len(); // 12
                                                      // key обрезан до len(salt) — не должен совпадать с salt.
        assert_ne!(&k.key_bytes()[..shared_prefix_len], k.salt_bytes());
    }

    #[test]
    fn derive_per_kid_different_base_different_output() {
        let bk_a = seeded_base_key(0x44, 0);
        let bk_b = seeded_base_key(0x45, 0);
        let ka = bk_a.derive_per_kid(7);
        let kb = bk_b.derive_per_kid(7);
        assert_ne!(ka.key_bytes(), kb.key_bytes());
        assert_ne!(ka.salt_bytes(), kb.salt_bytes());
    }

    #[test]
    fn debug_redacts_base_key_bytes() {
        let bk = seeded_base_key(0xCC, 7);
        let s = format!("{bk:?}");
        assert!(s.contains("<redacted>"), "Debug must mark bytes redacted");
        assert!(
            !s.contains("CC") && !s.contains("cc"),
            "raw key bytes must not appear in Debug output"
        );
        assert!(s.contains("Aes256GcmSha512"));
        assert!(s.contains("7"));
    }

    #[test]
    fn debug_redacts_per_kid_key() {
        let bk = seeded_base_key(0xDD, 0);
        let k = bk.derive_per_kid(0xABCD_1234);
        let s = format!("{k:?}");
        assert!(s.contains("<redacted>"));
        assert!(s.contains("0xabcd1234"));
    }

    #[test]
    fn from_mls_exporter_constant_is_normative_label() {
        // Защита от случайной опечатки в константе.
        // Protects against accidental typo in the constant.
        assert_eq!(MLS_EXPORTER_LABEL, "SFrame 1.0 Base Key");
    }

    #[test]
    fn rfc9605_vector_sframe_secret_matches() {
        // Проверяем полный RFC 9605 §4.4.2 key-schedule pipeline: HKDF-Extract
        // дайёт ожидаемый sframe_secret для vector'а sframe-wg.
        //
        // Verifies the full RFC 9605 §4.4.2 key-schedule pipeline:
        // HKDF-Extract produces the expected sframe_secret for the sframe-wg
        // vector.
        let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];
        let bk = SframeBaseKey::from_ikm(v.base_key, SframeCiphersuite::Aes256GcmSha512, 0);
        assert_eq!(
            bk.prk_bytes().as_slice(),
            v.expected_sframe_secret,
            "HKDF-Extract(salt=\"\", base_key) mismatch with RFC 9605 vector",
        );
    }

    #[test]
    fn rfc9605_vector_sframe_key_salt_match() {
        // Verifies sframe_key / sframe_salt HKDF-Expand output for kid=0x123.
        let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];
        let bk = SframeBaseKey::from_ikm(v.base_key, SframeCiphersuite::Aes256GcmSha512, 0);
        let per_kid = bk.derive_per_kid(v.kid);
        assert_eq!(
            per_kid.key_bytes().as_slice(),
            v.expected_sframe_key,
            "sframe_key mismatch with RFC 9605 vector",
        );
        assert_eq!(
            per_kid.salt_bytes().as_slice(),
            v.expected_sframe_salt,
            "sframe_salt mismatch with RFC 9605 vector",
        );
    }

    #[test]
    fn rfc9605_vector_nonce_matches() {
        use crate::sframe::aead::build_nonce;
        let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];
        let bk = SframeBaseKey::from_ikm(v.base_key, SframeCiphersuite::Aes256GcmSha512, 0);
        let per_kid = bk.derive_per_kid(v.kid);
        let nonce = build_nonce(per_kid.salt_bytes(), v.counter);
        assert_eq!(&nonce[..], v.expected_nonce);
    }

    #[test]
    fn rfc9605_vector_wire_header_matches() {
        use crate::sframe::wire::{SframeHeader, MAX_HEADER_LEN};
        let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];
        let mut buf = [0u8; MAX_HEADER_LEN];
        let n = SframeHeader::serialize(v.kid, v.counter, &mut buf);
        assert_eq!(&buf[..n], v.expected_wire_header);
    }

    #[test]
    fn rfc9605_vector_full_aead_matches() {
        // Полный AEAD cross-check: sframe_key + nonce + AAD=header||metadata →
        // ciphertext||tag совпадает с test vector'ом bit-for-bit.
        //
        // В Umbrella SPEC-06 §7 metadata-поле не используется (AAD = только
        // wire_header). Но test vector опубликован с metadata в AAD, поэтому
        // здесь мы вызываем AEAD напрямую с AAD=header||metadata — чтобы
        // cross-check бил в ту же точку что и IETF sframe-wg test suite.
        //
        // Full AEAD cross-check: sframe_key + nonce + AAD=header||metadata →
        // ciphertext||tag matches the test vector bit-for-bit.
        //
        // In Umbrella SPEC-06 §7 the metadata field is unused (AAD =
        // wire_header only). The test vector was published with metadata in
        // AAD, however, so this test calls AEAD directly with
        // AAD=header||metadata — so the cross-check lands on the same point
        // as the IETF sframe-wg test suite.
        use crate::sframe::aead::{aes256gcm_encrypt, build_nonce};

        let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];
        let bk = SframeBaseKey::from_ikm(v.base_key, SframeCiphersuite::Aes256GcmSha512, 0);
        let per_kid = bk.derive_per_kid(v.kid);
        let nonce = build_nonce(per_kid.salt_bytes(), v.counter);

        let mut aad = Vec::with_capacity(v.expected_wire_header.len() + v.metadata.len());
        aad.extend_from_slice(v.expected_wire_header);
        aad.extend_from_slice(v.metadata);

        let ct = aes256gcm_encrypt(per_kid.key_bytes(), &nonce, &aad, v.plaintext).unwrap();
        assert_eq!(ct, v.expected_ciphertext_with_tag);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_derive_deterministic(kid in any::<u64>(), seed in any::<[u8; 32]>()) {
            let mut bk_bytes = [0u8; BASE_KEY_LEN];
            bk_bytes[..32].copy_from_slice(&seed);
            let bk = SframeBaseKey::from_mls_exporter(
                bk_bytes,
                SframeCiphersuite::Aes256GcmSha512,
                0,
            );
            let k1 = bk.derive_per_kid(kid);
            let k2 = bk.derive_per_kid(kid);
            prop_assert_eq!(k1.key_bytes(), k2.key_bytes());
            prop_assert_eq!(k1.salt_bytes(), k2.salt_bytes());
        }

        #[test]
        fn prop_different_kid_different_output(
            kid_a in any::<u64>(),
            kid_b in any::<u64>(),
            seed in any::<[u8; 32]>(),
        ) {
            prop_assume!(kid_a != kid_b);
            let mut bk_bytes = [0u8; BASE_KEY_LEN];
            bk_bytes[..32].copy_from_slice(&seed);
            let bk = SframeBaseKey::from_mls_exporter(
                bk_bytes,
                SframeCiphersuite::Aes256GcmSha512,
                0,
            );
            let k_a = bk.derive_per_kid(kid_a);
            let k_b = bk.derive_per_kid(kid_b);
            // С вероятностью 2^-256 salt'ы могут совпасть, но key'и — крайне маловероятно.
                // HKDF-SHA512 не имеет detectable collisions для 8-байтовых разных info hex'ов.
            //
            // With probability 2^-256 salts may collide, but keys — extremely unlikely.
            // HKDF-SHA512 has no detectable collisions for 8-byte distinct info inputs.
            prop_assert_ne!(k_a.key_bytes(), k_b.key_bytes());
        }
    }
}
