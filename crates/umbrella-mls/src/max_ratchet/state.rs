//! [`MaxRatchetState`] — borrowing-mode реализация max ratchet режима.
//!
//! В отличие от [`MaxRatchetGroup`](crate::max_ratchet::MaxRatchetGroup) которая владеет
//! [`UmbrellaGroup`] (single-thread / single-chat usage), `MaxRatchetState` хранит только
//! state защит (`config` + `commit_counter` + `last_timer_check_unix`) и принимает
//! `&mut UmbrellaGroup` параметром в каждом методе. Это позволяет facade-слою
//! (`CloudChat` / `SecretChat`) держать `MaxRatchetState` и `UmbrellaGroup` под
//! раздельными locks/storage в `ClientCore` без conflict с existing API.
//!
//! [`MaxRatchetGroup`] делегирует все операции в `MaxRatchetState` — оба варианта shared
//! одну и ту же оркестрацию защит.
//!
//! [`MaxRatchetState`] is the borrowing-mode counterpart of [`MaxRatchetGroup`]. It
//! stores only the defence state (`config` + `commit_counter` + `last_timer_check_unix`)
//! and accepts `&mut UmbrellaGroup` as a parameter in every method. This lets the facade
//! layer (`CloudChat` / `SecretChat`) hold `MaxRatchetState` and `UmbrellaGroup` under
//! independent locks/storage in `ClientCore` without conflicting with the existing API.

use openmls_traits::OpenMlsProvider;

use umbrella_identity::KeyStore;

use crate::error::{MlsError, Result};
use crate::group::UmbrellaGroup;

use super::config::MaxRatchetConfig;
use super::group::MaxRatchetOutgoing;

/// State защит max ratchet режима без ownership группы. Используется в facade-слое.
///
/// Параллельно [`MaxRatchetGroup`](super::MaxRatchetGroup) которая владеет
/// [`UmbrellaGroup`]; в production facade ClientCore хранит группу отдельно от state'а
/// (под двумя `Arc<Mutex<...>>`), поэтому состав state'а вынесен в отдельный struct.
///
/// Defence state without group ownership; the production facade in `ClientCore` keeps
/// the group separate from the state under independent locks.
#[derive(Debug, Clone)]
pub struct MaxRatchetState {
    config: MaxRatchetConfig,
    commit_counter: u32,
    last_timer_check_unix: u64,
}

impl Default for MaxRatchetState {
    fn default() -> Self {
        Self::with_config(MaxRatchetConfig::default())
    }
}

impl MaxRatchetState {
    /// Создаёт state с дефолтной конфигурацией (все 4 защиты ON).
    /// Creates a state with the default configuration (all 4 defences enabled).
    pub fn new() -> Self {
        Self::default()
    }

    /// Создаёт state с явной конфигурацией. Используется для тестов либо tier-aware профилей.
    /// Creates a state with an explicit configuration; for tests or tier-aware profiles.
    pub fn with_config(config: MaxRatchetConfig) -> Self {
        Self {
            config,
            commit_counter: 0,
            last_timer_check_unix: 0,
        }
    }

    /// Текущая конфигурация. Current configuration.
    pub fn config(&self) -> MaxRatchetConfig {
        self.config
    }

    /// Текущий счётчик commits. Current commit counter.
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

    /// Шифрует application-сообщение с агрессивным DH-храповиком на borrow'нутой группе.
    ///
    /// См. [`MaxRatchetGroup::encrypt_with_rekey`](super::MaxRatchetGroup::encrypt_with_rekey)
    /// для полного описания потока.
    ///
    /// Encrypts an application message with an aggressive DH ratchet step on a borrowed
    /// group; see [`MaxRatchetGroup::encrypt_with_rekey`] for the full flow.
    pub fn encrypt_with_rekey(
        &mut self,
        group: &mut UmbrellaGroup,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut commit_bytes_opt = None;
        let mut pq_extension_used = false;

        if self.config.aggressive_dh_per_message {
            let commit = group.force_rekey(provider, keystore, now_unix)?;
            self.commit_counter = self.commit_counter.saturating_add(1);

            if super::counter::should_trigger_pq(
                self.commit_counter,
                self.config.pq_ratchet_every_n_commits,
            ) {
                pq_extension_used = true;
            }

            commit_bytes_opt = Some(commit);
        }

        let ciphertext = group.encrypt_application(provider, keystore, plaintext)?;

        Ok(MaxRatchetOutgoing {
            commit_bytes: commit_bytes_opt,
            ciphertext_bytes: ciphertext,
            epoch_after_send: group.epoch(),
            pq_extension_used,
            spqr_mac: None,
        })
    }

    /// Шифрует с rekey + добавляет SPQR HMAC поверх ciphertext (default-on для всех v3).
    ///
    /// Encrypts with rekey and appends the SPQR HMAC over the ciphertext (default-on for
    /// all v3 users).
    pub fn encrypt_with_rekey_authenticated(
        &mut self,
        group: &mut UmbrellaGroup,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut outgoing =
            self.encrypt_with_rekey(group, provider, keystore, plaintext, now_unix)?;

        if !self.config.spqr_deniable_auth {
            return Ok(outgoing);
        }

        let exporter = group.exporter_secret(provider, "umbrellax-spqr-deniable-auth", b"", 32)?;
        let epoch_secret = super::spqr::derive_epoch_secret_from_exporter(&exporter.expose()[..32])
            .map_err(|_| MlsError::GroupOperation {
                kind: "SPQR epoch secret HKDF derivation failed",
            })?;
        let mac = super::spqr::compute_hmac(&epoch_secret, &outgoing.ciphertext_bytes);
        outgoing.spqr_mac = Some(mac.to_vec());

        Ok(outgoing)
    }

    /// Borrowed-mode parallel `MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`: шифрует
    /// с aggressive DH rekey + добавляет SPQR HMAC с **реальной X-Wing PQ-extension** epoch
    /// secret когда `pq_ratchet_every_n_commits` триггерит (default = каждый 3-й commit).
    ///
    /// Используется facade-слоем (CloudChat / SecretChat) когда `pq_provider` доступен в
    /// `ClientCore` и группа создана на ciphersuite 0x004D — см. также
    /// [`MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`](super::MaxRatchetGroup::encrypt_with_rekey_pq_authenticated)
    /// для owned-mode варианта.
    ///
    /// **Требование к группе:** ciphersuite 0x004D (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`).
    /// Под non-PQ ciphersuite (например default 0x0003) `force_rekey_with_pq` всё равно работает
    /// но pq_shared_secret будет X25519-derived только — нет реального PQ benefit'а.
    /// Caller responsibility — выбрать ciphersuite при `UmbrellaGroup::create_private`.
    ///
    /// Borrowed-mode parallel to
    /// [`MaxRatchetGroup::encrypt_with_rekey_pq_authenticated`](super::MaxRatchetGroup::encrypt_with_rekey_pq_authenticated).
    /// Encrypts with rekey and attaches a SPQR HMAC keyed with the **real X-Wing PQ-extension**
    /// of the epoch secret when `pq_ratchet_every_n_commits` fires (default = every 3rd commit).
    /// Used by the facade layer (`CloudChat` / `SecretChat`) once `pq_provider` becomes
    /// available in `ClientCore` and the group is created with ciphersuite 0x004D. See the
    /// owned-mode method for the full flow description and ciphersuite requirements.
    #[cfg(feature = "pq")]
    pub fn encrypt_with_rekey_pq_authenticated(
        &mut self,
        group: &mut UmbrellaGroup,
        pq_provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
        now_unix: u64,
    ) -> Result<MaxRatchetOutgoing> {
        let mut commit_bytes_opt = None;
        let mut pq_extension_used = false;
        let mut pq_shared: Option<[u8; 32]> = None;

        if self.config.aggressive_dh_per_message {
            let (commit, pq_secret) = group.force_rekey_with_pq(pq_provider, keystore, now_unix)?;
            self.commit_counter = self.commit_counter.saturating_add(1);

            if super::counter::should_trigger_pq(
                self.commit_counter,
                self.config.pq_ratchet_every_n_commits,
            ) {
                pq_extension_used = true;
                pq_shared = Some(pq_secret);
            }
            // Non-trigger cycle: pq_secret extracted но не используется в SPQR HMAC. Под
            // ciphersuite 0x004D `force_rekey` уже выполнил X-Wing combine в HPKE encaps,
            // так что MLS-protocol-level PQ защита есть на каждом commit'e regardless of flag.
            // Non-trigger cycle: pq_secret extracted but not used in the SPQR HMAC.

            commit_bytes_opt = Some(commit);
        }

        let ciphertext = group.encrypt_application(pq_provider, keystore, plaintext)?;

        let mut spqr_mac = None;
        if self.config.spqr_deniable_auth {
            let exporter =
                group.exporter_secret(pq_provider, "umbrellax-spqr-deniable-auth", b"", 32)?;
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
            epoch_after_send: group.epoch(),
            pq_extension_used,
            spqr_mac,
        })
    }

    /// Проверяет таймер на borrow'нутой группе и принудительно делает rekey если elapsed.
    ///
    /// Checks the timer on a borrowed group and forces a rekey if elapsed.
    pub fn check_timer_and_rekey(
        &mut self,
        group: &mut UmbrellaGroup,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        now_unix: u64,
    ) -> Result<Option<Vec<u8>>> {
        let last_rekey = group.last_rekey_at_unix();
        let should_trigger = super::timer::check_should_trigger(
            last_rekey,
            now_unix,
            self.config.timer_rekey_seconds,
        );

        if !should_trigger {
            return Ok(None);
        }

        let commit_bytes = group.force_rekey(provider, keystore, now_unix)?;
        self.commit_counter = self.commit_counter.saturating_add(1);
        self.last_timer_check_unix = now_unix;
        Ok(Some(commit_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_config() {
        let state = MaxRatchetState::new();
        assert!(state.config().aggressive_dh_per_message);
        assert!(state.config().spqr_deniable_auth);
        assert_eq!(state.config().timer_rekey_seconds, 300);
        assert_eq!(state.config().pq_ratchet_every_n_commits, 3);
        assert_eq!(state.commit_counter(), 0);
    }

    #[test]
    fn with_config_uses_explicit_values() {
        let cfg = MaxRatchetConfig {
            aggressive_dh_per_message: false,
            spqr_deniable_auth: false,
            timer_rekey_seconds: 60,
            pq_ratchet_every_n_commits: 0,
        };
        let state = MaxRatchetState::with_config(cfg);
        assert_eq!(state.config(), cfg);
        assert!(!state.config().aggressive_dh_per_message);
    }
}
