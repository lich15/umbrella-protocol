//! uniffi `Object` exports — handles, экспонируемые в Swift / Kotlin.
//!
//! Все async-методы помечены `#[uniffi::export(async_runtime = "tokio")]`
//! (ADR-010 Решение 3). Type-safety разграничения CloudChat / SecretChat
//! сохраняется на FFI уровне: `SecretChatHandle` физически не имеет
//! `cloud_sync_history` / `add_bot` (ADR-006 Вариант C — Swift / Kotlin
//! не увидят этих методов).
//!
//! uniffi `Object` exports — handles surfaced to Swift / Kotlin.
//!
//! Every async method is annotated `#[uniffi::export(async_runtime =
//! "tokio")]` (ADR-010 Decision 3). Type-safe CloudChat / SecretChat
//! separation persists at the FFI layer: `SecretChatHandle` physically
//! lacks `cloud_sync_history` / `add_bot` (ADR-006 Variant C — Swift /
//! Kotlin will not see these methods).

pub mod call;
pub mod client;
pub mod cloud_chat;
pub mod onboarding;
pub mod secret_chat;

pub use call::{CallSessionHandle, CallStateFfi};
pub use client::{ClientConfigFfi, UmbrellaClientHandle};
pub use cloud_chat::CloudChatHandle;
pub use onboarding::{BootstrapOutputFfi, OnboardingHandle, UnlockResultFfi};
// F-FFI-2 closure: test-rig type re-exported only under the `test-utils`
// feature so production builds do not surface it (the `#[uniffi::export]`
// impl block carrying `unlock_with_pin_for_test_rig` is also gated and
// disappears from scaffolding when the feature is off).
#[cfg(any(test, feature = "test-utils"))]
pub use onboarding::UnlockResultTestRigFfi;
pub use secret_chat::SecretChatHandle;
