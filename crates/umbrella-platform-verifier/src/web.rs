//! WebAuthn-проверяющий для веб-клиентов.
//! WebAuthn verifier for web clients.

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

        let registered =
            ctx.registered_key
                .ok_or(PlatformVerifierError::IncompleteConfiguration(
                    "missing webauthn credential",
                ))?;

        if &registered.public_key != ctx.device_pubkey {
            return Err(PlatformVerifierError::DeviceKeyMismatch);
        }

        let token: WebAuthnToken = serde_json::from_slice(ctx.token)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let client_data = Base64UrlUnpadded::decode_vec(&token.client_data_json)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let auth_data = Base64UrlUnpadded::decode_vec(&token.authenticator_data)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
        let sig_bytes = Base64UrlUnpadded::decode_vec(&token.signature)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;

        if auth_data.len() < 37 || sig_bytes.len() != 64 {
            return Err(PlatformVerifierError::InvalidTokenShape);
        }

        let client: ClientData = serde_json::from_slice(&client_data)
            .map_err(|_| PlatformVerifierError::InvalidTokenShape)?;
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

        let expected_rp_hash: [u8; 32] = Sha256::digest(ctx.app_or_site.as_bytes()).into();
        if &auth_data[0..32] != expected_rp_hash.as_slice() {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }

        let flags = auth_data[32];
        if flags & 0x01 == 0 {
            return Err(PlatformVerifierError::InvalidTokenShape);
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
        let client_hash: [u8; 32] = Sha256::digest(&client_data).into();
        let mut signed = auth_data;
        signed.extend_from_slice(&client_hash);
        vk.verify(&signed, &sig)
            .map_err(|_| PlatformVerifierError::SignatureFailed)?;

        Ok(PlatformVerifierOutput {
            new_counter: Some(counter),
        })
    }
}

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
        DevicePublicKey, PlatformKind, PlatformVerificationContext, PlatformVerifier,
        RegisteredPlatformKey, ServerNonce,
    };

    fn keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn b64(data: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(data)
    }

    fn json_bytes(value: serde_json::Value, label: &str) -> Vec<u8> {
        match serde_json::to_vec(&value) {
            Ok(bytes) => bytes,
            Err(err) => panic!("{label} must serialize: {err}"),
        }
    }

    fn authenticator_data(site: &str, counter: u32) -> Vec<u8> {
        let rp_hash: [u8; 32] = Sha256::digest(site.as_bytes()).into();
        let mut out = Vec::new();
        out.extend_from_slice(&rp_hash);
        out.push(0x05);
        out.extend_from_slice(&counter.to_be_bytes());
        out
    }

    fn signed_token(sk: &SigningKey, site: &str, nonce: &ServerNonce, counter: u32) -> Vec<u8> {
        let auth_data = authenticator_data(site, counter);
        let client_data = json_bytes(
            json!({
                "type": "webauthn.get",
                "challenge": b64(nonce),
                "origin": format!("https://{site}")
            }),
            "test client data",
        );
        let client_hash: [u8; 32] = Sha256::digest(&client_data).into();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_hash);
        let sig = sk.sign(&signed).to_bytes();
        json_bytes(
            json!({
                "client_data_json": b64(&client_data),
                "authenticator_data": b64(&auth_data),
                "signature": b64(&sig)
            }),
            "test token",
        )
    }

    fn verified_output(ctx: PlatformVerificationContext<'_>) -> PlatformVerifierOutput {
        match WebAuthnVerifier.verify(ctx) {
            Ok(out) => out,
            Err(err) => panic!("matching assertion must verify: {err:?}"),
        }
    }

    fn rejected_error(ctx: PlatformVerificationContext<'_>, label: &str) -> PlatformVerifierError {
        match WebAuthnVerifier.verify(ctx) {
            Ok(out) => panic!("{label} must be rejected, got {out:?}"),
            Err(err) => err,
        }
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

        let out = verified_output(context(
            &token,
            &nonce,
            &vk,
            &registered,
            "app.umbrella.example",
        ));
        assert_eq!(out.new_counter, Some(2));
    }

    #[test]
    fn webauthn_rejects_context_device_key_not_registered_key() {
        let sk = keypair();
        let registered_pubkey = sk.verifying_key().to_bytes();
        let attacker = keypair();
        let attacker_pubkey = attacker.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "app.umbrella.example", &nonce, 2);
        let registered = RegisteredPlatformKey {
            public_key: registered_pubkey,
            last_counter: 1,
        };

        let err = rejected_error(
            context(
                &token,
                &nonce,
                &attacker_pubkey,
                &registered,
                "app.umbrella.example",
            ),
            "context device key mismatch",
        );

        assert!(matches!(err, PlatformVerifierError::DeviceKeyMismatch));
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
        let err = rejected_error(
            context(&token, &[2u8; 32], &vk, &registered, "app.umbrella.example"),
            "wrong challenge",
        );
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
        let err = rejected_error(
            context(&token, &nonce, &vk, &registered, "app.umbrella.example"),
            "wrong site",
        );
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
        let err = rejected_error(
            context(&token, &nonce, &vk, &registered, "app.umbrella.example"),
            "bad signature",
        );
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
        let err = rejected_error(
            context(&token, &nonce, &vk, &registered, "app.umbrella.example"),
            "counter rollback",
        );
        assert!(matches!(err, PlatformVerifierError::CounterDidNotIncrease));
    }
}
