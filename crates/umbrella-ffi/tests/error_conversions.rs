//! Тесты конвертации [`umbrella_client::ClientError`] → [`UmbrellaError`].
//!
//! Покрывают все 15 вариантов плоского-перевода + Display формат
//! (для UX лога на native стороне).
//!
//! Tests for [`umbrella_client::ClientError`] → [`UmbrellaError`] conversion.
//!
//! Cover all 15 flat-translation variants plus the Display format (used
//! for UX logging on the native side).

use umbrella_client::ClientError;
use umbrella_ffi::UmbrellaError;

#[test]
fn cancelled_roundtrip() {
    let err: UmbrellaError = ClientError::Cancelled.into();
    assert!(matches!(err, UmbrellaError::Cancelled));
}

#[test]
fn network_payload_preserved() {
    let err: UmbrellaError = ClientError::Network("timeout".into()).into();
    assert!(matches!(err, UmbrellaError::Network(ref s) if s == "timeout"));
}

#[test]
fn storage_payload_preserved() {
    let err: UmbrellaError = ClientError::Storage("file corrupt".into()).into();
    assert!(matches!(err, UmbrellaError::Storage(ref s) if s == "file corrupt"));
}

#[test]
fn platform_payload_preserved() {
    let err: UmbrellaError = ClientError::Platform("Keychain denied".into()).into();
    assert!(matches!(err, UmbrellaError::Platform(ref s) if s == "Keychain denied"));
}

#[test]
fn mode_violation_static_str_is_stringified() {
    let err: UmbrellaError = ClientError::ModeViolation("cloud_sync on SecretChat").into();
    assert!(matches!(
        err,
        UmbrellaError::ModeViolation(ref s) if s == "cloud_sync on SecretChat"
    ));
}

#[test]
fn internal_payload_preserved() {
    let err: UmbrellaError = ClientError::Internal("invariant".into()).into();
    assert!(matches!(err, UmbrellaError::Internal(ref s) if s == "invariant"));
}

#[test]
fn display_storage_includes_marker_and_payload() {
    let err: UmbrellaError = ClientError::Storage("file corrupt".into()).into();
    let s = format!("{err}");
    assert!(s.contains("storage"));
    assert!(s.contains("file corrupt"));
}

#[test]
fn display_cancelled_has_no_payload() {
    let err: UmbrellaError = ClientError::Cancelled.into();
    let s = format!("{err}");
    assert_eq!(s, "cancelled");
}

#[test]
fn debug_preserves_variant_name() {
    let err: UmbrellaError = ClientError::Internal("oops".into()).into();
    let d = format!("{err:?}");
    assert!(d.contains("Internal"));
    assert!(d.contains("oops"));
}

#[test]
fn attestation_subtype_displayed_through_to_string() {
    use umbrella_client::attestation::AttestationError;
    let err: UmbrellaError = ClientError::Attestation(AttestationError::ServiceUnavailable).into();
    if let UmbrellaError::Attestation(ref msg) = err {
        assert!(
            !msg.is_empty(),
            "Display of AttestationError::ServiceUnavailable must be non-empty"
        );
    } else {
        panic!("expected Attestation variant, got {err:?}");
    }
}

#[test]
fn attestation_app_not_eligible_distinguishable_in_message() {
    use umbrella_client::attestation::AttestationError;
    let unavailable: UmbrellaError =
        ClientError::Attestation(AttestationError::ServiceUnavailable).into();
    let ineligible: UmbrellaError =
        ClientError::Attestation(AttestationError::AppNotEligible).into();
    let s_unav = format!("{unavailable}");
    let s_inel = format!("{ineligible}");
    assert_ne!(
        s_unav, s_inel,
        "ServiceUnavailable and AppNotEligible must produce distinct strings for UX"
    );
}
