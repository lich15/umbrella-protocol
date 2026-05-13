# Production Platform Verifiers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить локальный строгий слой платформенных проверяющих для Айос, Андроида и веба, не открывая публичный запуск клиента.

**Architecture:** Новый малый Rust-крейт `umbrella-platform-verifier` хранит общие типы, ошибки и платформенные проверки. Веб-путь получает настоящую локальную проверку вызова, сайта, подписи и счётчика. Айос и Андроид получают строгие проверяющие с локальными проверками настроек и закрытым отказом там, где нужны внешние корни доверия, ключи Гугл или полный разбор живого платформенного токена.

**Tech Stack:** Rust 1.95 workspace, `sha2`, `serde`, `serde_json`, `base64ct`, `ed25519-dalek`, `umbrella-backup`, `umbrella-oprf`, Cargo locked tests.

---

## Источники правды

- `docs/WORKING_RULES.md`
- `docs/superpowers/specs/2026-05-13-production-platform-verifiers-design.md`
- `docs/security/production-readiness-boundaries.md`
- `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- `crates/umbrella-oprf/src/attestation.rs`
- `crates/umbrella-ffi/src/export/client.rs`

Свежие внешние источники, проверенные 2026-05-13:

- Apple App Attest: <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>
- Google Play Integrity: <https://developer.android.com/google/play/integrity/classic?hl=en>
- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>

## File Structure

- Create `crates/umbrella-platform-verifier/Cargo.toml`: новый внутренний крейт.
- Create `crates/umbrella-platform-verifier/src/lib.rs`: публичные экспорты крейта.
- Create `crates/umbrella-platform-verifier/src/error.rs`: точные ошибки платформенной проверки.
- Create `crates/umbrella-platform-verifier/src/types.rs`: общие входы, настройки, платформы, состояние ключа.
- Create `crates/umbrella-platform-verifier/src/web.rs`: локальная WebAuthn-проверка подписи и счётчика.
- Create `crates/umbrella-platform-verifier/src/apple.rs`: строгий Айос-проверяющий, который закрыто отказывает без полного App Attest trust material.
- Create `crates/umbrella-platform-verifier/src/android.rs`: строгий Андроид-проверяющий, который закрыто отказывает без ключей или server-side проверки Гугл.
- Modify `Cargo.toml`: добавить крейт в workspace и зависимости.
- Modify `crates/umbrella-backup/Cargo.toml`: подключить новый крейт.
- Modify `crates/umbrella-oprf/Cargo.toml`: подключить новый крейт.
- Modify `crates/umbrella-backup/src/error.rs`: добавить мостовую ошибку платформенного слоя.
- Modify `crates/umbrella-oprf/src/error.rs`: добавить мостовую ошибку платформенного слоя.
- Modify `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`: добавить адаптер нового слоя к `ProductionPlatformVerifier`.
- Modify `crates/umbrella-oprf/src/attestation.rs`: добавить адаптер нового слоя к `ProductionPlatformVerifier`.
- Modify `README.md`, `docs/README.md`, `docs/security/production-readiness-boundaries.md`: обновить честную границу.

## Task 1: Workspace And Crate Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/umbrella-platform-verifier/Cargo.toml`
- Create: `crates/umbrella-platform-verifier/src/lib.rs`
- Create: `crates/umbrella-platform-verifier/src/error.rs`
- Create: `crates/umbrella-platform-verifier/src/types.rs`

- [ ] **Step 1: Confirm clean starting point**

Run:

```bash
git status --short --branch
cargo check --workspace --all-targets --all-features --locked
```

Expected:

```text
## codex/production-attestation-gate
Finished `dev` profile
```

- [ ] **Step 2: Add workspace member and dependencies**

In root `Cargo.toml`, add `crates/umbrella-platform-verifier` to `members` after `crates/umbrella-kt`:

```toml
    "crates/umbrella-platform-verifier",
```

In `[workspace.dependencies]`, add the internal crate:

```toml
umbrella-platform-verifier = { path = "crates/umbrella-platform-verifier", version = "1.0.0" }
```

Add base64 decoding dependency near util dependencies:

```toml
base64ct = { version = "1.8", features = ["alloc"] }
```

- [ ] **Step 3: Create new crate manifest**

Create `crates/umbrella-platform-verifier/Cargo.toml`:

```toml
[package]
name = "umbrella-platform-verifier"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
description = "Local fail-closed platform attestation verifiers for Umbrella Protocol."

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
unwrap_used = "warn"
expect_used = "warn"

[dependencies]
base64ct = { workspace = true }
ed25519-dalek = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
rand_core = { workspace = true, features = ["getrandom"] }
```

- [ ] **Step 4: Create library root**

Create `crates/umbrella-platform-verifier/src/lib.rs`:

```rust
//! Локальные платформенные проверяющие Umbrella Protocol.
//! Local platform verifiers for Umbrella Protocol.
//!
//! Крейт проверяет только то, что можно честно проверить локально. Айос и
//! Андроид закрыто отказывают без полного trust material. Веб-путь проверяет
//! WebAuthn-подобное утверждение через сохранённый ключ.
//!
//! The crate verifies only what can be verified honestly on the local server.
//! iOS and Android fail closed without complete trust material. The web path
//! verifies a WebAuthn-like assertion with the stored credential key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod android;
pub mod apple;
pub mod error;
pub mod types;
pub mod web;

pub use android::{AndroidPlayIntegrityConfig, AndroidPlayIntegrityVerifier};
pub use apple::{AppleAppAttestConfig, AppleAppAttestEnvironment, AppleAppAttestVerifier};
pub use error::{PlatformVerifierError, Result};
pub use types::{
    DevicePublicKey, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, RegisteredPlatformKey, ServerNonce,
};
pub use web::WebAuthnVerifier;
```

- [ ] **Step 5: Create error enum**

Create `crates/umbrella-platform-verifier/src/error.rs`:

```rust
//! Ошибки платформенной проверки.
//! Platform verification errors.

use thiserror::Error;

/// Результат платформенной проверки.
/// Result alias for platform verification.
pub type Result<T> = core::result::Result<T, PlatformVerifierError>;

/// Точная причина отказа платформенного проверяющего.
/// Precise platform-verifier rejection reason.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlatformVerifierError {
    /// Токен пустой. Token is empty.
    #[error("platform token is empty")]
    EmptyToken,
    /// Токен слишком большой. Token is too large.
    #[error("platform token too large: {got} > {max}")]
    TokenTooLarge {
        /// Фактический размер. Actual size.
        got: usize,
        /// Максимум. Maximum.
        max: usize,
    },
    /// Платформа не совпала с проверяющим. Platform mismatch.
    #[error("platform mismatch")]
    PlatformMismatch,
    /// Не удалось разобрать токен. Token shape is invalid.
    #[error("invalid platform token shape")]
    InvalidTokenShape,
    /// Серверный вызов не совпал. Server nonce mismatch.
    #[error("server nonce mismatch")]
    ServerNonceMismatch,
    /// Приложение или сайт не совпали. App or site mismatch.
    #[error("app or site mismatch")]
    AppOrSiteMismatch,
    /// Ключ устройства не совпал. Device key mismatch.
    #[error("device key mismatch")]
    DeviceKeyMismatch,
    /// Подпись платформенного доказательства не прошла.
    /// Platform proof signature failed.
    #[error("platform proof signature failed")]
    SignatureFailed,
    /// Счётчик не вырос. Counter did not increase.
    #[error("platform counter did not increase")]
    CounterDidNotIncrease,
    /// Доказательство слишком старое. Proof is too old.
    #[error("platform proof expired")]
    ProofExpired,
    /// Настройки неполные. Configuration is incomplete.
    #[error("production platform verifier configuration is incomplete: {0}")]
    IncompleteConfiguration(&'static str),
    /// Нужен внешний корень доверия или ключ проверки.
    /// External trust material is required.
    #[error("external trust material is not wired: {0}")]
    ExternalTrustMaterialRequired(&'static str),
}
```

- [ ] **Step 6: Create common types**

Create `crates/umbrella-platform-verifier/src/types.rs`:

```rust
//! Общие типы платформенной проверки.
//! Common platform-verification types.

use crate::error::Result;

/// Максимальный размер платформенного токена.
/// Maximum accepted platform token size.
pub const MAX_PLATFORM_TOKEN_BYTES: usize = 4096;

/// Серверный одноразовый вызов.
/// Server-issued one-time nonce.
pub type ServerNonce = [u8; 32];

/// Публичный ключ устройства.
/// Device public key bytes.
pub type DevicePublicKey = [u8; 32];

/// Платформа проверяемого доказательства.
/// Platform of the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKind {
    /// Apple App Attest. Apple App Attest.
    AppleAppAttest,
    /// Android Play Integrity. Android Play Integrity.
    AndroidPlayIntegrity,
    /// WebAuthn. WebAuthn.
    WebAuthn,
}

/// Сохранённый платформенный ключ или запись.
/// Stored platform key or record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredPlatformKey {
    /// Публичный ключ проверки подписи. Public signature verification key.
    pub public_key: DevicePublicKey,
    /// Последний принятый счётчик. Last accepted counter.
    pub last_counter: u32,
}

/// Вход платформенного проверяющего.
/// Input for a platform verifier.
#[derive(Debug, Clone)]
pub struct PlatformVerificationContext<'a> {
    /// Ожидаемая платформа. Expected platform.
    pub platform: PlatformKind,
    /// Токен платформы. Platform token bytes.
    pub token: &'a [u8],
    /// Серверный вызов. Server nonce.
    pub server_nonce: &'a ServerNonce,
    /// Публичный ключ устройства. Device public key.
    pub device_pubkey: &'a DevicePublicKey,
    /// Ожидаемое имя приложения или сайта. Expected app id or site.
    pub app_or_site: &'a str,
    /// Текущее серверное время. Current server time.
    pub now_unix_millis: u64,
    /// Сохранённая платформенная запись. Stored platform record.
    pub registered_key: Option<&'a RegisteredPlatformKey>,
}

/// Успешный результат проверки.
/// Successful verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformVerifierOutput {
    /// Новый счётчик, который сервер должен сохранить.
    /// New counter the server should store.
    pub new_counter: Option<u32>,
}

/// Общий интерфейс платформенного проверяющего.
/// Common platform verifier interface.
pub trait PlatformVerifier: core::fmt::Debug {
    /// Проверить платформенное доказательство.
    /// Verify a platform proof.
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput>;
}
```

- [ ] **Step 7: Update lockfile once, run skeleton check, and commit**

Run:

```bash
cargo check -p umbrella-platform-verifier
cargo check -p umbrella-platform-verifier --locked
```

Expected:

```text
Finished `dev` profile
```

Then commit:

```bash
git add Cargo.toml crates/umbrella-platform-verifier
git add Cargo.lock docs/superpowers/plans/2026-05-13-production-platform-verifiers.md
git commit -m "platform: add verifier crate skeleton"
```

## Task 2: Shared Validation Helpers

**Files:**
- Modify: `crates/umbrella-platform-verifier/src/types.rs`
- Modify: `crates/umbrella-platform-verifier/src/lib.rs`

- [ ] **Step 1: Add failing tests for common token guards**

Append this test module to `crates/umbrella-platform-verifier/src/types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformVerifierError;

    #[test]
    fn token_guard_rejects_empty() {
        let err = validate_token_size(&[], MAX_PLATFORM_TOKEN_BYTES).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::EmptyToken));
    }

    #[test]
    fn token_guard_rejects_oversize() {
        let token = vec![0u8; MAX_PLATFORM_TOKEN_BYTES + 1];
        let err = validate_token_size(&token, MAX_PLATFORM_TOKEN_BYTES).unwrap_err();
        assert!(matches!(
            err,
            PlatformVerifierError::TokenTooLarge { got, max }
                if got == MAX_PLATFORM_TOKEN_BYTES + 1 && max == MAX_PLATFORM_TOKEN_BYTES
        ));
    }

    #[test]
    fn token_guard_accepts_non_empty_within_limit() {
        validate_token_size(b"x", MAX_PLATFORM_TOKEN_BYTES).unwrap();
    }
}
```

- [ ] **Step 2: Run red test**

Run:

```bash
cargo test -p umbrella-platform-verifier token_guard --locked
```

Expected red signal:

```text
cannot find function `validate_token_size`
```

- [ ] **Step 3: Add helper**

Add to `crates/umbrella-platform-verifier/src/types.rs` after constants:

```rust
use crate::error::PlatformVerifierError;

/// Проверить размер токена.
/// Validate platform token size.
pub fn validate_token_size(token: &[u8], max: usize) -> Result<()> {
    if token.is_empty() {
        return Err(PlatformVerifierError::EmptyToken);
    }
    if token.len() > max {
        return Err(PlatformVerifierError::TokenTooLarge {
            got: token.len(),
            max,
        });
    }
    Ok(())
}
```

- [ ] **Step 4: Export helper and verify**

In `src/lib.rs`, add `validate_token_size` to the `pub use types::{...}` list.

Run:

```bash
cargo test -p umbrella-platform-verifier token_guard --locked
```

Expected:

```text
test result: ok
```

Commit:

```bash
git add crates/umbrella-platform-verifier/src
git commit -m "platform: add shared token guards"
```

## Task 3: WebAuthn Local Verifier

**Files:**
- Modify: `crates/umbrella-platform-verifier/src/web.rs`
- Modify: `crates/umbrella-platform-verifier/src/lib.rs`

- [ ] **Step 1: Write failing WebAuthn attack tests**

Create `crates/umbrella-platform-verifier/src/web.rs` with tests first:

```rust
//! WebAuthn-проверяющий для веб-клиентов.
//! WebAuthn verifier for web clients.

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::error::PlatformVerifierError;
    use crate::types::{
        DevicePublicKey, PlatformKind, PlatformVerificationContext, RegisteredPlatformKey,
        ServerNonce,
    };

    fn keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn b64(data: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(data)
    }

    fn authenticator_data(site: &str, counter: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Sha256::digest(site.as_bytes()));
        out.push(0x05);
        out.extend_from_slice(&counter.to_be_bytes());
        out
    }

    fn signed_token(sk: &SigningKey, site: &str, nonce: &ServerNonce, counter: u32) -> Vec<u8> {
        let auth_data = authenticator_data(site, counter);
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": b64(nonce),
            "origin": format!("https://{site}")
        }))
        .unwrap();
        let client_hash = Sha256::digest(&client_data);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_hash);
        let sig = sk.sign(&signed).to_bytes();
        serde_json::to_vec(&json!({
            "client_data_json": b64(&client_data),
            "authenticator_data": b64(&auth_data),
            "signature": b64(&sig)
        }))
        .unwrap()
    }

    fn context<'a>(
        token: &'a [u8],
        nonce: &'a ServerNonce,
        device_pubkey: &'a DevicePublicKey,
        registered_key: &'a RegisteredPlatformKey,
        site: &'a str,
    ) -> PlatformVerificationContext<'a> {
        PlatformVerificationContext {
            platform: PlatformKind::WebAuthn,
            token,
            server_nonce: nonce,
            device_pubkey,
            app_or_site: site,
            now_unix_millis: 1_700_000_000_000,
            registered_key: Some(registered_key),
        }
    }

    #[test]
    fn webauthn_accepts_matching_site_challenge_signature_and_counter() {
        let sk = keypair();
        let vk = sk.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "app.umbrella.example", &nonce, 2);
        let registered = RegisteredPlatformKey {
            public_key: vk,
            last_counter: 1,
        };

        let out = WebAuthnVerifier::default()
            .verify(context(&token, &nonce, &vk, &registered, "app.umbrella.example"))
            .unwrap();
        assert_eq!(out.new_counter, Some(2));
    }

    #[test]
    fn webauthn_rejects_wrong_challenge() {
        let sk = keypair();
        let vk = sk.verifying_key().to_bytes();
        let token = signed_token(&sk, "app.umbrella.example", &[1u8; 32], 2);
        let registered = RegisteredPlatformKey {
            public_key: vk,
            last_counter: 1,
        };
        let err = WebAuthnVerifier::default()
            .verify(context(&token, &[2u8; 32], &vk, &registered, "app.umbrella.example"))
            .unwrap_err();
        assert!(matches!(err, PlatformVerifierError::ServerNonceMismatch));
    }

    #[test]
    fn webauthn_rejects_wrong_site() {
        let sk = keypair();
        let vk = sk.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "evil.example", &nonce, 2);
        let registered = RegisteredPlatformKey {
            public_key: vk,
            last_counter: 1,
        };
        let err = WebAuthnVerifier::default()
            .verify(context(&token, &nonce, &vk, &registered, "app.umbrella.example"))
            .unwrap_err();
        assert!(matches!(err, PlatformVerifierError::AppOrSiteMismatch));
    }

    #[test]
    fn webauthn_rejects_bad_signature() {
        let sk = keypair();
        let other = keypair();
        let vk = other.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "app.umbrella.example", &nonce, 2);
        let registered = RegisteredPlatformKey {
            public_key: vk,
            last_counter: 1,
        };
        let err = WebAuthnVerifier::default()
            .verify(context(&token, &nonce, &vk, &registered, "app.umbrella.example"))
            .unwrap_err();
        assert!(matches!(err, PlatformVerifierError::SignatureFailed));
    }

    #[test]
    fn webauthn_rejects_counter_rollback() {
        let sk = keypair();
        let vk = sk.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "app.umbrella.example", &nonce, 1);
        let registered = RegisteredPlatformKey {
            public_key: vk,
            last_counter: 1,
        };
        let err = WebAuthnVerifier::default()
            .verify(context(&token, &nonce, &vk, &registered, "app.umbrella.example"))
            .unwrap_err();
        assert!(matches!(err, PlatformVerifierError::CounterDidNotIncrease));
    }
}
```

- [ ] **Step 2: Run red tests**

Run:

```bash
cargo test -p umbrella-platform-verifier webauthn_ --locked
```

Expected red signal:

```text
cannot find type `WebAuthnVerifier`
```

- [ ] **Step 3: Implement verifier**

Add above the tests in `web.rs`:

```rust
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{PlatformVerifierError, Result};
use crate::types::{
    validate_token_size, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, MAX_PLATFORM_TOKEN_BYTES,
};

/// WebAuthn-проверяющий для сохранённого Ed25519 credential key.
/// WebAuthn verifier for a stored Ed25519 credential key.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebAuthnVerifier;

#[derive(Debug, Deserialize)]
struct WebAuthnToken {
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

impl PlatformVerifier for WebAuthnVerifier {
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput> {
        if ctx.platform != PlatformKind::WebAuthn {
            return Err(PlatformVerifierError::PlatformMismatch);
        }
        validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)?;

        let registered = ctx
            .registered_key
            .ok_or(PlatformVerifierError::IncompleteConfiguration("missing webauthn credential"))?;

        if &registered.public_key != ctx.device_pubkey {
            return Err(PlatformVerifierError::DeviceKeyMismatch);
        }

        let token: WebAuthnToken =
            serde_json::from_slice(ctx.token).map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let client_data = Base64UrlUnpadded::decode_vec(&token.client_data_json)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let auth_data = Base64UrlUnpadded::decode_vec(&token.authenticator_data)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let sig_bytes = Base64UrlUnpadded::decode_vec(&token.signature)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;

        if auth_data.len() < 37 || sig_bytes.len() != 64 {
            return Err(PlatformVerifierError::InvalidTokenShape);
        }

        let client: ClientData =
            serde_json::from_slice(&client_data).map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        if client.kind != "webauthn.get" {
            return Err(PlatformVerifierError::InvalidTokenShape);
        }
        let challenge = Base64UrlUnpadded::decode_vec(&client.challenge)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        if challenge.as_slice() != ctx.server_nonce {
            return Err(PlatformVerifierError::ServerNonceMismatch);
        }

        let expected_origin = format!("https://{}", ctx.app_or_site);
        if client.origin != expected_origin {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }

        let expected_rp_hash = Sha256::digest(ctx.app_or_site.as_bytes());
        if &auth_data[0..32] != expected_rp_hash.as_slice() {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }

        let counter = u32::from_be_bytes(
            auth_data[33..37]
                .try_into()
                .map_err(|_| PlatformVerifierError::InvalidTokenShape)?,
        );
        if counter <= registered.last_counter {
            return Err(PlatformVerifierError::CounterDidNotIncrease);
        }

        let vk = VerifyingKey::from_bytes(&registered.public_key)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let sig = Signature::from_bytes(&sig_arr);
        let client_hash = Sha256::digest(&client_data);
        let mut signed = auth_data;
        signed.extend_from_slice(&client_hash);
        vk.verify(&signed, &sig)
            .map_err(|_| PlatformVerifierError::SignatureFailed)?;

        Ok(PlatformVerifierOutput {
            new_counter: Some(counter),
        })
    }
}
```

- [ ] **Step 4: Verify and commit**

Run:

```bash
cargo test -p umbrella-platform-verifier webauthn_ --locked
cargo test -p umbrella-platform-verifier --locked
```

Expected:

```text
test result: ok
```

Commit:

```bash
git add crates/umbrella-platform-verifier/src
git commit -m "platform: verify webauthn assertions"
```

## Task 4: Apple And Android Fail-Closed Verifiers

**Files:**
- Modify: `crates/umbrella-platform-verifier/src/apple.rs`
- Modify: `crates/umbrella-platform-verifier/src/android.rs`

- [ ] **Step 1: Add failing Apple tests**

Create `crates/umbrella-platform-verifier/src/apple.rs`:

```rust
//! Apple App Attest проверяющий.
//! Apple App Attest verifier.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformVerifierError;
    use crate::types::{PlatformKind, PlatformVerificationContext};

    fn ctx<'a>(token: &'a [u8], app: &'a str) -> PlatformVerificationContext<'a> {
        PlatformVerificationContext {
            platform: PlatformKind::AppleAppAttest,
            token,
            server_nonce: &[7u8; 32],
            device_pubkey: &[9u8; 32],
            app_or_site: app,
            now_unix_millis: 1_700_000_000_000,
            registered_key: None,
        }
    }

    #[test]
    fn apple_rejects_missing_bundle_id_config() {
        let verifier = AppleAppAttestVerifier::new(AppleAppAttestConfig {
            team_id: "TEAMID1234".into(),
            bundle_id: "".into(),
            environment: AppleAppAttestEnvironment::Production,
            trust_roots_configured: false,
        });
        let err = verifier.verify(ctx(b"token", "TEAMID1234.com.umbrella.app")).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::IncompleteConfiguration(_)));
    }

    #[test]
    fn apple_rejects_wrong_app_id_before_trust_work() {
        let verifier = AppleAppAttestVerifier::new(AppleAppAttestConfig {
            team_id: "TEAMID1234".into(),
            bundle_id: "com.umbrella.app".into(),
            environment: AppleAppAttestEnvironment::Production,
            trust_roots_configured: false,
        });
        let err = verifier.verify(ctx(b"token", "OTHER.com.umbrella.app")).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::AppOrSiteMismatch));
    }

    #[test]
    fn apple_fails_closed_without_trust_roots() {
        let verifier = AppleAppAttestVerifier::new(AppleAppAttestConfig {
            team_id: "TEAMID1234".into(),
            bundle_id: "com.umbrella.app".into(),
            environment: AppleAppAttestEnvironment::Production,
            trust_roots_configured: false,
        });
        let err = verifier
            .verify(ctx(b"real-looking-cbor", "TEAMID1234.com.umbrella.app"))
            .unwrap_err();
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }
}
```

- [ ] **Step 2: Add failing Android tests**

Create `crates/umbrella-platform-verifier/src/android.rs`:

```rust
//! Android Play Integrity проверяющий.
//! Android Play Integrity verifier.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformVerifierError;
    use crate::types::{PlatformKind, PlatformVerificationContext};

    fn ctx<'a>(token: &'a [u8], package: &'a str) -> PlatformVerificationContext<'a> {
        PlatformVerificationContext {
            platform: PlatformKind::AndroidPlayIntegrity,
            token,
            server_nonce: &[7u8; 32],
            device_pubkey: &[9u8; 32],
            app_or_site: package,
            now_unix_millis: 1_700_000_000_000,
            registered_key: None,
        }
    }

    #[test]
    fn android_rejects_missing_package_name() {
        let verifier = AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
            package_name: "".into(),
            google_verification_configured: false,
        });
        let err = verifier.verify(ctx(b"token", "com.umbrella.app")).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::IncompleteConfiguration(_)));
    }

    #[test]
    fn android_rejects_wrong_package_before_google_work() {
        let verifier = AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
            package_name: "com.umbrella.app".into(),
            google_verification_configured: false,
        });
        let err = verifier.verify(ctx(b"token", "com.evil.app")).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::AppOrSiteMismatch));
    }

    #[test]
    fn android_fails_closed_without_google_verification() {
        let verifier = AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
            package_name: "com.umbrella.app".into(),
            google_verification_configured: false,
        });
        let err = verifier.verify(ctx(b"nested-jwe-jws", "com.umbrella.app")).unwrap_err();
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }
}
```

- [ ] **Step 3: Run red tests**

Run:

```bash
cargo test -p umbrella-platform-verifier apple_ --locked
cargo test -p umbrella-platform-verifier android_ --locked
```

Expected red signal:

```text
cannot find type `AppleAppAttestVerifier`
cannot find type `AndroidPlayIntegrityVerifier`
```

- [ ] **Step 4: Implement Apple verifier**

Add above tests in `apple.rs`:

```rust
use crate::error::{PlatformVerifierError, Result};
use crate::types::{
    validate_token_size, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, MAX_PLATFORM_TOKEN_BYTES,
};

/// Среда App Attest.
/// App Attest environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleAppAttestEnvironment {
    /// Разработка. Development.
    Development,
    /// Бой. Production.
    Production,
}

/// Настройки Apple App Attest.
/// Apple App Attest config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestConfig {
    /// Team ID. Team ID.
    pub team_id: String,
    /// Bundle ID. Bundle ID.
    pub bundle_id: String,
    /// Среда. Environment.
    pub environment: AppleAppAttestEnvironment,
    /// Подключены ли корни доверия Apple.
    /// Whether Apple trust roots are wired.
    pub trust_roots_configured: bool,
}

/// Строгий Apple App Attest проверяющий.
/// Strict Apple App Attest verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestVerifier {
    config: AppleAppAttestConfig,
}

impl AppleAppAttestVerifier {
    /// Создать проверяющий. Create verifier.
    #[must_use]
    pub fn new(config: AppleAppAttestConfig) -> Self {
        Self { config }
    }
}

impl PlatformVerifier for AppleAppAttestVerifier {
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput> {
        if ctx.platform != PlatformKind::AppleAppAttest {
            return Err(PlatformVerifierError::PlatformMismatch);
        }
        validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)?;
        if self.config.team_id.is_empty() || self.config.bundle_id.is_empty() {
            return Err(PlatformVerifierError::IncompleteConfiguration(
                "apple team_id and bundle_id are required",
            ));
        }
        let expected_app_id = format!("{}.{}", self.config.team_id, self.config.bundle_id);
        if ctx.app_or_site != expected_app_id {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }
        if !self.config.trust_roots_configured {
            return Err(PlatformVerifierError::ExternalTrustMaterialRequired(
                "apple app attest root chain and attestation/assertion parser",
            ));
        }
        Err(PlatformVerifierError::ExternalTrustMaterialRequired(
            "apple app attest full verification not implemented in this local phase",
        ))
    }
}
```

- [ ] **Step 5: Implement Android verifier**

Add above tests in `android.rs`:

```rust
use crate::error::{PlatformVerifierError, Result};
use crate::types::{
    validate_token_size, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, MAX_PLATFORM_TOKEN_BYTES,
};

/// Настройки Android Play Integrity.
/// Android Play Integrity config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidPlayIntegrityConfig {
    /// Имя пакета. Package name.
    pub package_name: String,
    /// Подключена ли проверка Гугл или локальные ключи.
    /// Whether Google verification or local keys are wired.
    pub google_verification_configured: bool,
}

/// Строгий Android Play Integrity проверяющий.
/// Strict Android Play Integrity verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidPlayIntegrityVerifier {
    config: AndroidPlayIntegrityConfig,
}

impl AndroidPlayIntegrityVerifier {
    /// Создать проверяющий. Create verifier.
    #[must_use]
    pub fn new(config: AndroidPlayIntegrityConfig) -> Self {
        Self { config }
    }
}

impl PlatformVerifier for AndroidPlayIntegrityVerifier {
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput> {
        if ctx.platform != PlatformKind::AndroidPlayIntegrity {
            return Err(PlatformVerifierError::PlatformMismatch);
        }
        validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)?;
        if self.config.package_name.is_empty() {
            return Err(PlatformVerifierError::IncompleteConfiguration(
                "android package name is required",
            ));
        }
        if ctx.app_or_site != self.config.package_name {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }
        if !self.config.google_verification_configured {
            return Err(PlatformVerifierError::ExternalTrustMaterialRequired(
                "google play integrity decode/verify path or local keys",
            ));
        }
        Err(PlatformVerifierError::ExternalTrustMaterialRequired(
            "android play integrity full verification not implemented in this local phase",
        ))
    }
}
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
cargo test -p umbrella-platform-verifier apple_ --locked
cargo test -p umbrella-platform-verifier android_ --locked
cargo test -p umbrella-platform-verifier --locked
```

Expected:

```text
test result: ok
```

Commit:

```bash
git add crates/umbrella-platform-verifier/src
git commit -m "platform: fail closed for apple and android"
```

## Task 5: Backup And OPRF Adapters

**Files:**
- Modify: `crates/umbrella-backup/Cargo.toml`
- Modify: `crates/umbrella-oprf/Cargo.toml`
- Modify: `crates/umbrella-backup/src/error.rs`
- Modify: `crates/umbrella-oprf/src/error.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- Modify: `crates/umbrella-oprf/src/attestation.rs`

- [ ] **Step 1: Add crate dependencies**

In `crates/umbrella-backup/Cargo.toml` dependencies, add:

```toml
umbrella-platform-verifier = { workspace = true }
```

In `crates/umbrella-oprf/Cargo.toml` dependencies, add:

```toml
umbrella-platform-verifier = { workspace = true }
```

- [ ] **Step 2: Add bridge error variants**

In `crates/umbrella-backup/src/error.rs`, after `ProductionAttestationVerifierUnavailable`, add:

```rust
    /// Платформенная проверка закрыто отказала.
    /// Platform verification failed closed.
    #[error("production platform verification failed: {0}")]
    ProductionPlatformVerificationFailed(String),
```

In `crates/umbrella-oprf/src/error.rs`, after `ProductionAttestationVerifierUnavailable`, add:

```rust
    /// Платформенная проверка закрыто отказала.
    /// Platform verification failed closed.
    #[error("production platform verification failed: {0}")]
    ProductionPlatformVerificationFailed(String),
```

- [ ] **Step 3: Add adapter tests in backup**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, inside tests, add a test that proves web verification can be reached through the production context:

```rust
#[test]
    fn production_context_web_platform_uses_shared_platform_verifier() {
    let (sk, vk) = make_device_keypair();
    let nonce = fresh_nonce();
    let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
    let verifier = SharedPlatformVerifierForBackup::web_for_test(
        "app.umbrella.example",
        [0x11u8; DEVICE_PUBKEY_LEN],
        1,
    );
    let ctx = production_context(
        &verifier,
        nonce,
        1_700_000_000_000,
        1_700_000_000_100,
        active_device_state(),
    );
    let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
    assert!(matches!(err, BackupError::ProductionPlatformVerificationFailed(_)));
}
```

This test intentionally uses an iOS-shaped request with a web verifier so the first adapter implementation proves shared verifier errors are mapped to a backup error instead of silently accepting the request.

- [ ] **Step 4: Add adapter tests in OPRF**

In `crates/umbrella-oprf/src/attestation.rs`, inside tests, add:

```rust
#[test]
fn production_context_android_platform_uses_shared_platform_verifier() {
    let (sk, vk) = make_device_keypair();
    let nonce = fresh_nonce();
    let signed = production_android_oprf_request(&sk, &vk, nonce);
    let verifier = SharedPlatformVerifierForOprf::android_for_test("com.umbrella.app", false);
    let ctx = production_context(
        &verifier,
        nonce,
        1_700_000_000_000,
        1_700_000_000_100,
        active_device_state(),
    );
    let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
    assert!(matches!(err, OprfError::ProductionPlatformVerificationFailed(_)));
}
```

- [ ] **Step 5: Run red adapter tests**

Run:

```bash
cargo test -p umbrella-backup shared_platform_verifier --all-features --locked
cargo test -p umbrella-oprf shared_platform_verifier --all-features --locked
```

Expected red signal:

```text
cannot find type `SharedPlatformVerifierForBackup`
cannot find type `SharedPlatformVerifierForOprf`
```

- [ ] **Step 6: Implement backup adapter**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, import:

```rust
use umbrella_platform_verifier::{
    AndroidPlayIntegrityConfig, AndroidPlayIntegrityVerifier, AppleAppAttestConfig,
    AppleAppAttestVerifier, DevicePublicKey, PlatformKind, PlatformVerificationContext,
    PlatformVerifier, RegisteredPlatformKey, WebAuthnVerifier,
};
```

Add after `UnavailableProductionPlatformVerifier`:

```rust
/// Адаптер общего платформенного слоя для cloud unwrap.
/// Shared platform-verifier adapter for cloud unwrap.
#[derive(Debug, Clone)]
pub enum SharedPlatformVerifierForBackup {
    /// Apple App Attest. Apple App Attest.
    Apple(AppleAppAttestVerifier),
    /// Android Play Integrity. Android Play Integrity.
    Android(AndroidPlayIntegrityVerifier),
    /// WebAuthn. WebAuthn.
    Web {
        /// Проверяющий. Verifier.
        verifier: WebAuthnVerifier,
        /// Ожидаемый сайт. Expected site.
        site: String,
        /// Сохраненный ключ. Stored key.
        registered_key: RegisteredPlatformKey,
    },
}

impl SharedPlatformVerifierForBackup {
    /// Создать WebAuthn adapter для тестов.
    /// Create a WebAuthn adapter for tests.
    #[cfg(test)]
    fn web_for_test(site: &str, public_key: DevicePublicKey, last_counter: u32) -> Self {
        Self::Web {
            verifier: WebAuthnVerifier::default(),
            site: site.to_string(),
            registered_key: RegisteredPlatformKey {
                public_key,
                last_counter,
            },
        }
    }
}

impl ProductionPlatformVerifier for SharedPlatformVerifierForBackup {
    fn kind(&self) -> PlatformVerifierKind {
        match self {
            Self::Apple(_) => PlatformVerifierKind::AppleAppAttest,
            Self::Android(_) => PlatformVerifierKind::AndroidPlayIntegrity,
            Self::Web { .. } => PlatformVerifierKind::WebAuthn,
        }
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), BackupError> {
        let map_err = |e: umbrella_platform_verifier::PlatformVerifierError| {
            BackupError::ProductionPlatformVerificationFailed(e.to_string())
        };
        match self {
            Self::Apple(verifier) => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AppleAppAttest,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: "",
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(map_err),
            Self::Android(verifier) => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AndroidPlayIntegrity,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: "",
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(map_err),
            Self::Web {
                verifier,
                site,
                registered_key,
            } => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::WebAuthn,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: site,
                    now_unix_millis: input.now_unix_millis,
                    registered_key: Some(registered_key),
                })
                .map(|_| ())
                .map_err(map_err),
        }
    }
}
```

- [ ] **Step 7: Implement OPRF adapter**

In `crates/umbrella-oprf/src/attestation.rs`, import:

```rust
use umbrella_platform_verifier::{
    AndroidPlayIntegrityConfig, AndroidPlayIntegrityVerifier, AppleAppAttestConfig,
    AppleAppAttestVerifier, DevicePublicKey, PlatformKind, PlatformVerificationContext,
    PlatformVerifier, RegisteredPlatformKey, WebAuthnVerifier,
};
```

Add after `UnavailableProductionPlatformVerifier`:

```rust
/// Адаптер общего платформенного слоя для OPRF.
/// Shared platform-verifier adapter for OPRF.
#[derive(Debug, Clone)]
pub enum SharedPlatformVerifierForOprf {
    /// Apple App Attest. Apple App Attest.
    Apple(AppleAppAttestVerifier),
    /// Android Play Integrity. Android Play Integrity.
    Android(AndroidPlayIntegrityVerifier),
    /// WebAuthn. WebAuthn.
    Web {
        /// Проверяющий. Verifier.
        verifier: WebAuthnVerifier,
        /// Ожидаемый сайт. Expected site.
        site: String,
        /// Сохраненный ключ. Stored key.
        registered_key: RegisteredPlatformKey,
    },
}

impl SharedPlatformVerifierForOprf {
    /// Создать Android adapter для тестов.
    /// Create an Android adapter for tests.
    #[cfg(test)]
    fn android_for_test(package_name: &str, google_verification_configured: bool) -> Self {
        Self::Android(AndroidPlayIntegrityVerifier::new(
            AndroidPlayIntegrityConfig {
                package_name: package_name.to_string(),
                google_verification_configured,
            },
        ))
    }
}

impl ProductionPlatformVerifier for SharedPlatformVerifierForOprf {
    fn kind(&self) -> PlatformVerifierKind {
        match self {
            Self::Apple(_) => PlatformVerifierKind::AppleAppAttest,
            Self::Android(_) => PlatformVerifierKind::AndroidPlayIntegrity,
            Self::Web { .. } => PlatformVerifierKind::WebAuthn,
        }
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError> {
        let map_err = |e: umbrella_platform_verifier::PlatformVerifierError| {
            OprfError::ProductionPlatformVerificationFailed(e.to_string())
        };
        match self {
            Self::Apple(verifier) => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AppleAppAttest,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: "",
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(map_err),
            Self::Android(verifier) => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AndroidPlayIntegrity,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: "",
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(map_err),
            Self::Web {
                verifier,
                site,
                registered_key,
            } => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::WebAuthn,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: site,
                    now_unix_millis: input.now_unix_millis,
                    registered_key: Some(registered_key),
                })
                .map(|_| ())
                .map_err(map_err),
        }
    }
}
```

- [ ] **Step 8: Verify adapters and commit**

Run:

```bash
cargo test -p umbrella-backup shared_platform_verifier --all-features --locked
cargo test -p umbrella-oprf shared_platform_verifier --all-features --locked
cargo test -p umbrella-backup production_context_ --all-features --locked
cargo test -p umbrella-oprf production_context_ --all-features --locked
```

Expected:

```text
test result: ok
```

Commit:

```bash
git add crates/umbrella-backup crates/umbrella-oprf
git commit -m "platform: wire shared verifiers into server gates"
```

## Task 6: Documentation And Final Gates

**Files:**
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/security/production-readiness-boundaries.md`

- [ ] **Step 1: Update production boundary docs**

In `docs/security/production-readiness-boundaries.md`, update the platform verifier bullet in both languages to say:

```markdown
- Platform attestation verifiers: `Platform::Testing` is rejected by production
  verifiers. A local verifier crate now enforces shared token-size, app/site,
  nonce, key, signature, and counter rules where enough material is available.
  WebAuthn has local assertion verification. Apple App Attest and Android Play
  Integrity remain fail-closed until their external trust material, platform
  token parsers, and mobile/server integration are wired.
```

Russian:

```markdown
- Платформенные проверяющие: `Platform::Testing` отвергается боевыми
  проверяющими. Новый локальный крейт проверяет общие правила размера токена,
  приложения или сайта, серверного вызова, ключа, подписи и счётчика там, где
  для этого хватает данных. WebAuthn имеет локальную проверку утверждения.
  Apple App Attest и Android Play Integrity остаются закрыты отказом, пока не
  подключены внешние корни доверия, разбор платформенного токена и
  мобильная/серверная связка.
```

- [ ] **Step 2: Update README docs**

Update `README.md` and `docs/README.md` current-status paragraphs with the same truthful wording: WebAuthn local verifier exists; Apple and Android still fail closed without external trust material.

- [ ] **Step 3: Run docs audit**

Run:

```bash
bash scripts/audit-public-access-notices.sh
```

Expected:

```text
public access notices audit passed
```

- [ ] **Step 4: Run final verification**

Run:

```bash
cargo fmt --all -- --check
cargo test -p umbrella-platform-verifier --locked
cargo test -p umbrella-backup --all-features --locked
cargo test -p umbrella-oprf --all-features --locked
cargo test -p umbrella-client --all-features --locked
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
cargo test --workspace --all-features --locked
```

Expected:

```text
all commands exit 0
```

- [ ] **Step 5: Commit docs and final status**

Run:

```bash
git add README.md docs/README.md docs/security/production-readiness-boundaries.md
git commit -m "docs: update platform verifier boundaries"
git status --short --branch
```

Expected:

```text
## codex/production-attestation-gate
```

## Self-Review Checklist

- [ ] Spec coverage: common local layer, WebAuthn verification, Apple fail-closed, Android fail-closed, backup/OPRF adapters, docs, and final gates are covered.
- [ ] Placeholder scan: no empty markers, no vague future-work wording, no copied-step references without exact target.
- [ ] Type consistency: `PlatformVerificationContext`, `PlatformVerifier`, `RegisteredPlatformKey`, and adapter names match tasks.
- [ ] Scope honesty: public FFI bootstrap remains closed; Apple and Android do not claim production acceptance without external trust material.
