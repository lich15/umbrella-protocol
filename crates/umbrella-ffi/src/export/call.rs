//! `CallSessionHandle` — uniffi wrapper над
//! [`umbrella_client::call::CallSession`].
//!
//! `CallStateFfi` — flat enum (без вложенных payload'ов) для ABI-стабильности
//! Swift / Kotlin биндингов. `Terminated(CallTerminationReason)` развёрнут
//! в `TerminatedLocalHangup` / `TerminatedRemoteHangup` / … — ABI-stable
//! представление. Ремоут-side decoding к Rust enum'у через
//! [`From<CallState> for CallStateFfi`].
//!
//! В блоке 7.7 экспортируются только `state` / `hangup` / `call_id_bytes` —
//! полный lifecycle (`start_call` через FFI, ICE/DTLS event callbacks)
//! приходит в блок 7.10 milestone, который интегрирует webrtc-rs handshake
//! с реальным TURN allocation через `ClientCore::call_relay_transport`.
//!
//! `CallSessionHandle` — uniffi wrapper around
//! [`umbrella_client::call::CallSession`].
//!
//! `CallStateFfi` — flat enum (no nested payloads) for ABI stability across
//! Swift / Kotlin bindings. `Terminated(CallTerminationReason)` is unfolded
//! into `TerminatedLocalHangup` / `TerminatedRemoteHangup` / … — an
//! ABI-stable representation. Remote-side decoding back into the Rust enum
//! flows through [`From<CallState> for CallStateFfi`].
//!
//! Block 7.7 exports only `state` / `hangup` / `call_id_bytes` — the full
//! lifecycle (FFI `start_call`, ICE/DTLS event callbacks) lands in the
//! Block 7.10 milestone integrating webrtc-rs handshake with real TURN
//! allocation via `ClientCore::call_relay_transport`.

use umbrella_client::call::{CallSession, CallState, CallTerminationReason};

use crate::error::UmbrellaError;

/// FFI представление [`CallState`]. Flat — `Terminated(reason)` развёрнут
/// в отдельные варианты per reason.
///
/// FFI representation of [`CallState`]. Flat — `Terminated(reason)` is
/// unfolded into per-reason variants.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CallStateFfi {
    /// Offer/answer обмен через blind-postman-svc.
    /// Signalling offer/answer via blind-postman-svc.
    Signalling,
    /// ICE gathering.
    /// ICE gathering.
    IceGathering,
    /// ICE connectivity checks.
    /// ICE connectivity checks.
    IceChecking,
    /// DTLS 1.3 handshake.
    /// DTLS 1.3 handshake.
    DtlsHandshake,
    /// Call connected — media flows.
    /// Call connected — media flows.
    Connected,
    /// Temporary disconnection — ICE restart.
    /// Temporary disconnection — ICE restart.
    Reconnecting,
    /// Локальный hangup.
    /// Local hangup.
    TerminatedLocalHangup,
    /// Удалённый hangup.
    /// Remote hangup.
    TerminatedRemoteHangup,
    /// ICE failure.
    /// ICE failure.
    TerminatedIceFailure,
    /// DTLS handshake failure.
    /// DTLS handshake failure.
    TerminatedDtlsFailure,
    /// Identity binding mismatch.
    /// Identity binding mismatch.
    TerminatedIdentityMismatch,
    /// Сетевая ошибка.
    /// Network error.
    TerminatedNetworkError,
}

impl From<CallState> for CallStateFfi {
    fn from(s: CallState) -> Self {
        use CallTerminationReason as R;
        match s {
            CallState::Signalling => CallStateFfi::Signalling,
            CallState::IceGathering => CallStateFfi::IceGathering,
            CallState::IceChecking => CallStateFfi::IceChecking,
            CallState::DtlsHandshake => CallStateFfi::DtlsHandshake,
            CallState::Connected => CallStateFfi::Connected,
            CallState::Reconnecting => CallStateFfi::Reconnecting,
            CallState::Terminated(R::LocalHangup) => CallStateFfi::TerminatedLocalHangup,
            CallState::Terminated(R::RemoteHangup) => CallStateFfi::TerminatedRemoteHangup,
            CallState::Terminated(R::IceFailure) => CallStateFfi::TerminatedIceFailure,
            CallState::Terminated(R::DtlsFailure) => CallStateFfi::TerminatedDtlsFailure,
            CallState::Terminated(R::IdentityMismatch) => CallStateFfi::TerminatedIdentityMismatch,
            CallState::Terminated(R::NetworkError) => CallStateFfi::TerminatedNetworkError,
        }
    }
}

/// FFI handle над `CallSession`. Создаётся через `start_call` API
/// (появится в блоке 7.10); в 7.7 — только тип-определение и базовые
/// методы наблюдения.
///
/// FFI handle over `CallSession`. Built through the `start_call` API
/// (lands in Block 7.10); Block 7.7 ships only the type definition and
/// basic observation methods.
#[derive(uniffi::Object)]
pub struct CallSessionHandle {
    inner: CallSession,
}

impl CallSessionHandle {
    /// Внутренний конструктор — будет использован FFI `start_call` в
    /// Блоке 7.10.
    ///
    /// Internal constructor — the FFI `start_call` of Block 7.10 will use it.
    #[allow(dead_code)]
    pub(crate) fn new(inner: CallSession) -> Self {
        Self { inner }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl CallSessionHandle {
    /// Текущее состояние сессии.
    ///
    /// Current session state.
    pub async fn state(&self) -> CallStateFfi {
        self.inner.state().await.into()
    }

    /// Локальный hangup — переводит state в `TerminatedLocalHangup`.
    ///
    /// Local hangup — transitions state to `TerminatedLocalHangup`.
    pub async fn hangup(&self) -> Result<(), UmbrellaError> {
        self.inner.hangup().await?;
        Ok(())
    }

    /// 16-байтовый call id.
    ///
    /// 16-byte call id.
    pub fn call_id_bytes(&self) -> Vec<u8> {
        self.inner.call_id().0.to_vec()
    }
}
