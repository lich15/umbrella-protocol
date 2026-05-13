//! Проверки честности публичного FFI-запуска клиента.
//!
//! Public FFI bootstrap honesty checks.

use umbrella_ffi::{ClientConfigFfi, UmbrellaClientHandle, UmbrellaError};

const VALID_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

fn valid_config() -> ClientConfigFfi {
    ClientConfigFfi {
        sealed_server_urls: vec![
            "https://sealed-0.example.invalid".into(),
            "https://sealed-1.example.invalid".into(),
            "https://sealed-2.example.invalid".into(),
            "https://sealed-3.example.invalid".into(),
            "https://sealed-4.example.invalid".into(),
        ],
        postman_url: "https://postman.example.invalid".into(),
        kt_url: "https://kt.example.invalid".into(),
        call_relay_url: "https://relay.example.invalid".into(),
        kt_monitor_interval_secs: 3600,
        main_pubkey: vec![0x11; 32],
        server_pubkeys: vec![vec![0x22; 32]; 5],
        wrapping_version: 1,
    }
}

fn assert_production_bootstrap_unavailable(err: UmbrellaError) {
    match err {
        UmbrellaError::Internal(message) => {
            assert!(message.contains("production bootstrap is not available"));
            assert!(message.contains("test constructors"));
            assert!(message.contains("production HTTP/2 transport gate"));
            assert!(message.contains("production attestation verifier"));
        }
        other => panic!("expected Internal production-bootstrap error, got {other:?}"),
    }
}

#[tokio::test]
async fn public_bootstrap_does_not_call_test_constructor() {
    let result = UmbrellaClientHandle::bootstrap(valid_config(), VALID_MNEMONIC.into()).await;
    match result {
        Ok(_) => panic!("public bootstrap must fail fast instead of returning a test handle"),
        Err(err) => assert_production_bootstrap_unavailable(err),
    }
}

#[cfg(not(feature = "pq"))]
#[tokio::test]
async fn public_bootstrap_classical_does_not_call_test_constructor() {
    let result =
        UmbrellaClientHandle::bootstrap_classical(valid_config(), VALID_MNEMONIC.into()).await;
    match result {
        Ok(_) => {
            panic!("public bootstrap_classical must fail fast instead of returning a test handle")
        }
        Err(err) => assert_production_bootstrap_unavailable(err),
    }
}

#[cfg(feature = "pq")]
#[tokio::test]
async fn public_bootstrap_pq_does_not_call_test_constructor() {
    let result = UmbrellaClientHandle::bootstrap_pq(valid_config(), VALID_MNEMONIC.into()).await;
    match result {
        Ok(_) => panic!("public bootstrap_pq must fail fast instead of returning a test handle"),
        Err(err) => assert_production_bootstrap_unavailable(err),
    }
}
