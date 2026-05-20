//! [`MaxRatchetGroup`] — обёртка над [`UmbrellaGroup`] с максимальным режимом ratchet'а.
//!
//! Включает 4 техники защиты по умолчанию (см. модульная документация `mod.rs`):
//! - агрессивный DH-храповик на каждое сообщение,
//! - таймер 5 минут принудительного rekey,
//! - flag PQ X-Wing ratchet на каждом 3-м commit,
//! - SPQR HMAC отрицаемая аутентификация поверх каждого ciphertext.
//!
//! [`MaxRatchetGroup`] is a wrapper around [`UmbrellaGroup`] that turns on the maximum
//! ratchet mode. It enables 4 protection techniques by default (see the module doc in
//! `mod.rs`): aggressive DH ratchet per message, 5-minute forced-rekey timer, PQ X-Wing
//! ratchet flag every 3rd commit, and SPQR HMAC deniable authentication per ciphertext.

use openmls_traits::OpenMlsProvider;

use umbrella_identity::KeyStore;

use crate::error::{MlsError, Result};
use crate::group::UmbrellaGroup;

use super::config::MaxRatchetConfig;

/// Группа с максимальным режимом ratchet'а + отрицаемая аутентификация.
///
/// Оборачивает [`UmbrellaGroup`] и оркестрирует 4 защиты автоматически. См. `mod.rs` для
/// полной концепции.
///
/// Group with maximum ratchet mode + deniable authentication. Wraps [`UmbrellaGroup`] and
/// orchestrates 4 defences automatically.
pub struct MaxRatchetGroup {
    inner: UmbrellaGroup,
    config: MaxRatchetConfig,
    commit_counter: u32,
    last_timer_check_unix: u64,
}

impl MaxRatchetGroup {
    /// Создаёт обёртку над существующей [`UmbrellaGroup`] с дефолтной конфигурацией
    /// (максимум всех защит).
    ///
    /// Creates a wrapper around an existing [`UmbrellaGroup`] using the default
    /// configuration (all defences at maximum).
    pub fn new(inner: UmbrellaGroup) -> Self {
        Self::with_config(inner, MaxRatchetConfig::default())
    }

    /// Создаёт обёртку с явно указанной конфигурацией. Используется только для тестов
    /// либо tier-aware профилей.
    ///
    /// Creates a wrapper with an explicit configuration. Used for tests or tier-aware
    /// profiles only.
    pub fn with_config(inner: UmbrellaGroup, config: MaxRatchetConfig) -> Self {
        Self {
            inner,
            config,
            commit_counter: 0,
            last_timer_check_unix: 0,
        }
    }

    /// Возвращает базовую [`UmbrellaGroup`] для read-only операций (epoch, member_count, etc).
    /// Returns the underlying [`UmbrellaGroup`] for read-only accessors.
    pub fn inner(&self) -> &UmbrellaGroup {
        &self.inner
    }

    /// Mutable доступ к базовой [`UmbrellaGroup`] для операций которые MaxRatchetGroup не
    /// проксирует (add_members, remove_members, process_incoming).
    ///
    /// Mutable access to the underlying [`UmbrellaGroup`] for operations that
    /// MaxRatchetGroup does not proxy (add_members, remove_members, process_incoming).
    pub fn inner_mut(&mut self) -> &mut UmbrellaGroup {
        &mut self.inner
    }

    /// Текущая конфигурация защит. Current defence configuration.
    pub fn config(&self) -> MaxRatchetConfig {
        self.config
    }

    /// Текущий счётчик commits. Используется для PQ ratchet каждые N commits.
    /// Current commit counter; drives the «PQ ratchet every N» logic.
    pub fn commit_counter(&self) -> u32 {
        self.commit_counter
    }

    /// True если следующий commit должен включать PQ X-Wing combine.
    /// True iff the next commit should include a PQ X-Wing combine.
    pub fn should_trigger_pq_ratchet(&self) -> bool {
        super::counter::should_trigger_pq(
            self.commit_counter,
            self.config.pq_ratchet_every_n_commits,
        )
    }

    /// Шифрует application-сообщение с обязательным DH-храповиком перед ним.
    ///
    /// Поток (при `aggressive_dh_per_message = true`):
    /// 1. Вызов [`UmbrellaGroup::force_rekey`] — продвигает MLS epoch
    /// 2. Увеличение `commit_counter`
    /// 3. Проверка [`should_trigger_pq_ratchet`](Self::should_trigger_pq_ratchet) — устанавливает
    ///    флаг `pq_extension_used` в outgoing
    /// 4. Шифрование сообщения в новом epoch через [`UmbrellaGroup::encrypt_application`]
    /// 5. Возвращает [`MaxRatchetOutgoing`] с commit + ciphertext + epoch + флагом PQ
    ///
    /// Encrypts an application message with a mandatory DH ratchet step before it. See
    /// the Russian doc for full flow description.
    pub fn encrypt_with_rekey(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut commit_bytes_opt = None;
        let mut pq_extension_used = false;

        if self.config.aggressive_dh_per_message {
            let commit = self.inner.force_rekey(provider, keystore, now_unix)?;
            self.commit_counter = self.commit_counter.saturating_add(1);

            // Classical path: только flag устанавливается без real X-Wing combine. Для real
            // PQ keying используйте [`encrypt_with_rekey_pq_authenticated`] под feature `pq` —
            // он принимает `UmbrellaXWingProvider` + вызывает `force_rekey_with_pq` который
            // извлекает PQ-derived secret из exporter нового epoch'a.
            // Classical path: only the flag is set, no real X-Wing combine. Use
            // `encrypt_with_rekey_pq_authenticated` under feature `pq` for the real PQ
            // keying — it takes `UmbrellaXWingProvider` and calls `force_rekey_with_pq`,
            // which extracts a PQ-derived secret from the new epoch's exporter.
            if super::counter::should_trigger_pq(
                self.commit_counter,
                self.config.pq_ratchet_every_n_commits,
            ) {
                pq_extension_used = true;
            }

            commit_bytes_opt = Some(commit);
        }

        let ciphertext = self
            .inner
            .encrypt_application(provider, keystore, plaintext)?;

        Ok(MaxRatchetOutgoing {
            commit_bytes: commit_bytes_opt,
            ciphertext_bytes: ciphertext,
            epoch_after_send: self.inner.epoch(),
            pq_extension_used,
            spqr_mac: None,
        })
    }

    /// Шифрует с rekey + добавляет SPQR HMAC для отрицаемой аутентификации.
    ///
    /// Полный поток (default-on для всех v3 пользователей):
    /// 1. [`encrypt_with_rekey`](Self::encrypt_with_rekey) — получаем commit + ciphertext +
    ///    новый epoch
    /// 2. Извлекаем `exporter_secret` нового epoch'а через
    ///    [`UmbrellaGroup::exporter_secret`] с label `"umbrellax-spqr-deniable-auth"`
    /// 3. Выводим `epoch_secret` через [`derive_epoch_secret_from_exporter`](super::spqr::derive_epoch_secret_from_exporter)
    /// 4. (classical path: `pq_extension_used` остаётся flag-only. Для real X-Wing keying
    ///    используйте [`encrypt_with_rekey_pq_authenticated`](Self::encrypt_with_rekey_pq_authenticated)
    ///    под feature `pq`.)
    /// 5. Вычисляем `compute_hmac(epoch_secret, ciphertext_bytes)` → 32 байта
    /// 6. Возвращаем outgoing.spqr_mac = Some(hmac)
    ///
    /// Encrypts with rekey + appends an SPQR HMAC for deniable authentication. Full flow
    /// (default-on for all v3 users) is described in the Russian doc above.
    pub fn encrypt_with_rekey_authenticated(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut outgoing = self.encrypt_with_rekey(provider, keystore, plaintext, now_unix)?;

        if !self.config.spqr_deniable_auth {
            return Ok(outgoing);
        }

        // Извлекаем 32-байтовый exporter_secret из текущего epoch'a.
        // Extract 32-byte exporter_secret from current epoch.
        let exporter =
            self.inner
                .exporter_secret(provider, "umbrellax-spqr-deniable-auth", b"", 32)?;

        let epoch_secret = super::spqr::derive_epoch_secret_from_exporter(&exporter.expose()[..32])
            .map_err(|_| MlsError::GroupOperation {
                kind: "SPQR epoch secret HKDF derivation failed",
            })?;

        let mac = super::spqr::compute_hmac(&epoch_secret, &outgoing.ciphertext_bytes);
        outgoing.spqr_mac = Some(mac.to_vec());

        Ok(outgoing)
    }

    /// Шифрует с rekey + добавляет SPQR HMAC с **реальной X-Wing PQ-extension**
    /// epoch secret когда `pq_ratchet_every_n_commits` триггерит (default = каждый 3-й commit).
    ///
    /// Отличия от [`encrypt_with_rekey_authenticated`](Self::encrypt_with_rekey_authenticated):
    /// - Принимает PQ-capable provider (например
    ///   [`UmbrellaXWingProvider`](crate::provider::UmbrellaXWingProvider)) вместо обычного
    ///   `UmbrellaProvider`.
    /// - При `should_trigger_pq=true` вызывает
    ///   [`UmbrellaGroup::force_rekey_with_pq`](crate::group::UmbrellaGroup::force_rekey_with_pq)
    ///   — извлекает **реальный** PQ-derived shared secret из exporter нового epoch'a.
    /// - SPQR HMAC на trigger-commits использует [`pq_extend_epoch_secret`](super::spqr::pq_extend_epoch_secret) для combine
    ///   classical_secret + pq_shared → keying material от которого нельзя восстановить
    ///   classical-only secret даже под compromised X25519.
    ///
    /// **Требование к группе:** ciphersuite 0x004D (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`).
    /// Под non-PQ ciphersuite (например default 0x0003) force_rekey_with_pq всё равно работает
    /// но pq_shared_secret будет X25519-derived только — нет реального PQ benefit'а.
    /// Caller responsibility — выбрать ciphersuite при `UmbrellaGroup::create_private`.
    ///
    /// Encrypts with rekey and attaches a SPQR HMAC keyed with the **real X-Wing
    /// PQ-extension** of the epoch secret when `pq_ratchet_every_n_commits` fires (default
    /// = every 3rd commit). See the Russian doc for differences against
    /// [`encrypt_with_rekey_authenticated`](Self::encrypt_with_rekey_authenticated) and the
    /// ciphersuite requirement (0x004D + `UmbrellaXWingProvider`).
    #[cfg(feature = "pq")]
    pub fn encrypt_with_rekey_pq_authenticated(
        &mut self,
        pq_provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut commit_bytes_opt = None;
        let mut pq_extension_used = false;
        let mut pq_shared: Option<[u8; 32]> = None;

        if self.config.aggressive_dh_per_message {
            let (commit, pq_secret) =
                self.inner
                    .force_rekey_with_pq(pq_provider, keystore, now_unix)?;
            self.commit_counter = self.commit_counter.saturating_add(1);

            if super::counter::should_trigger_pq(
                self.commit_counter,
                self.config.pq_ratchet_every_n_commits,
            ) {
                pq_extension_used = true;
                pq_shared = Some(pq_secret);
            }
            // Non-trigger cycle: pq_secret extracted но не используется в SPQR HMAC.
            // Под ciphersuite 0x004D force_rekey уже выполнил X-Wing combine в HPKE encaps,
            // так что MLS-protocol-level PQ защита есть на каждом commit'e regardless of flag.
            // Non-trigger cycle: pq_secret is extracted but not used in the SPQR HMAC. Under
            // ciphersuite 0x004D force_rekey already performed an X-Wing combine inside HPKE
            // encaps, so MLS-protocol-level PQ protection holds on every commit regardless
            // of the flag.

            commit_bytes_opt = Some(commit);
        }

        let ciphertext = self
            .inner
            .encrypt_application(pq_provider, keystore, plaintext)?;

        let mut spqr_mac = None;
        if self.config.spqr_deniable_auth {
            let exporter =
                self.inner
                    .exporter_secret(pq_provider, "umbrellax-spqr-deniable-auth", b"", 32)?;
            let classical_secret = super::spqr::derive_epoch_secret_from_exporter(
                &exporter.expose()[..32],
            )
            .map_err(|_| MlsError::GroupOperation {
                kind: "SPQR epoch secret HKDF derivation failed",
            })?;

            let epoch_secret = if let Some(pq) = pq_shared.as_ref() {
                super::spqr::pq_extend_epoch_secret(&classical_secret, pq).map_err(|_| {
                    MlsError::GroupOperation {
                        kind: "SPQR PQ-extension HKDF derivation failed",
                    }
                })?
            } else {
                classical_secret
            };

            let mac = super::spqr::compute_hmac(&epoch_secret, &ciphertext);
            spqr_mac = Some(mac.to_vec());
        }

        Ok(MaxRatchetOutgoing {
            commit_bytes: commit_bytes_opt,
            ciphertext_bytes: ciphertext,
            epoch_after_send: self.inner.epoch(),
            pq_extension_used,
            spqr_mac,
        })
    }

    /// Проверяет таймер и если прошло `timer_rekey_seconds` — делает принудительный rekey.
    ///
    /// Эту функцию следует вызывать перед любой операцией приёма/отправки + опционально
    /// периодически в фоновом таске для устройств которые долго бездействуют.
    ///
    /// Возвращает true если rekey произошёл (commit нужно отправить получателям).
    /// Возвращает false если таймер ещё не сработал.
    ///
    /// Checks the timer and, if `timer_rekey_seconds` have elapsed, forces a rekey.
    pub fn check_timer_and_rekey(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        now_unix: u64,
    ) -> Result<Option<Vec<u8>>> {
        let last_rekey = self.inner.last_rekey_at_unix();
        let should_trigger = super::timer::check_should_trigger(
            last_rekey,
            now_unix,
            self.config.timer_rekey_seconds,
        );

        if !should_trigger {
            return Ok(None);
        }

        let commit_bytes = self.inner.force_rekey(provider, keystore, now_unix)?;
        self.commit_counter = self.commit_counter.saturating_add(1);
        self.last_timer_check_unix = now_unix;
        Ok(Some(commit_bytes))
    }
}

/// Результат шифрования через [`MaxRatchetGroup::encrypt_with_rekey`] либо
/// [`MaxRatchetGroup::encrypt_with_rekey_authenticated`].
///
/// `Debug` redacts wire payloads — длины метаданные есть, сами байты не выводятся в логи.
///
/// Output of [`MaxRatchetGroup::encrypt_with_rekey`] or
/// [`MaxRatchetGroup::encrypt_with_rekey_authenticated`]. `Debug` redacts wire payloads.
#[derive(Clone)]
pub struct MaxRatchetOutgoing {
    /// MLS commit байты которые **должны быть отправлены первыми** получателям перед
    /// `ciphertext_bytes`. `None` если `aggressive_dh_per_message = false`.
    ///
    /// MLS commit bytes that **must be sent first** to recipients before
    /// `ciphertext_bytes`. `None` if `aggressive_dh_per_message = false`.
    pub commit_bytes: Option<Vec<u8>>,
    /// Зашифрованное application-сообщение (TLS-serialized MlsMessage).
    /// Encrypted application message (TLS-serialized MlsMessage).
    pub ciphertext_bytes: Vec<u8>,
    /// Group epoch после отправки (для диагностики / тестов).
    /// Group epoch after send (diagnostics / tests).
    pub epoch_after_send: u64,
    /// True если этот commit должен включать PQ X-Wing combine.
    /// True if this commit should include a PQ X-Wing combine.
    pub pq_extension_used: bool,
    /// SPQR HMAC (32 байта HMAC-SHA256 поверх `ciphertext_bytes`). `None` если
    /// `spqr_deniable_auth = false`.
    ///
    /// SPQR HMAC (32 bytes of HMAC-SHA256 over `ciphertext_bytes`). `None` if
    /// `spqr_deniable_auth = false`.
    pub spqr_mac: Option<Vec<u8>>,
}

impl core::fmt::Debug for MaxRatchetOutgoing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let commit_len = self.commit_bytes.as_ref().map(Vec::len);
        let mac_len = self.spqr_mac.as_ref().map(Vec::len);
        f.debug_struct("MaxRatchetOutgoing")
            .field("commit_len", &commit_len)
            .field("commit_bytes", &"<redacted>")
            .field("ciphertext_len", &self.ciphertext_bytes.len())
            .field("ciphertext_bytes", &"<redacted>")
            .field("epoch_after_send", &self.epoch_after_send)
            .field("pq_extension_used", &self.pq_extension_used)
            .field("spqr_mac_len", &mac_len)
            .field("spqr_mac", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_debug_redacts_wire_payloads() {
        let outgoing = MaxRatchetOutgoing {
            commit_bytes: Some(b"mls-commit-secret-bytes".to_vec()),
            ciphertext_bytes: b"private-mls-ciphertext".to_vec(),
            epoch_after_send: 42,
            pq_extension_used: true,
            spqr_mac: Some(vec![1u8; 32]),
        };

        let debug = format!("{outgoing:?}");

        assert!(
            !debug.contains("109, 108, 115"),
            "Debug must not leak commit wire bytes: {debug}"
        );
        assert!(
            !debug.contains("112, 114, 105, 118"),
            "Debug must not leak ciphertext bytes: {debug}"
        );
        assert!(
            debug.contains("commit_len"),
            "Debug must keep commit length"
        );
        assert!(
            debug.contains("ciphertext_len"),
            "Debug must keep ciphertext length"
        );
        assert!(debug.contains("epoch_after_send"), "Debug must keep epoch");
        assert!(
            debug.contains("pq_extension_used"),
            "Debug must keep PQ flag"
        );
    }
}
