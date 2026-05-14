#!/usr/bin/env bash
set -euo pipefail

failed=0

require_pattern() {
  local file="$1"
  local pattern="$2"

  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    failed=1
    return
  fi

  if ! grep -Eqi "$pattern" "$file"; then
    echo "$file does not contain required protocol gate: $pattern" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-oprf/src/attestation.rs" "ProductionNonceReplayGuard"
require_pattern "crates/umbrella-oprf/src/error.rs" "ProductionServerNonceReplay"
require_pattern "crates/umbrella-backup/src/cloud_wrap/signed_request.rs" "ProductionNonceReplayGuard"
require_pattern "crates/umbrella-backup/src/error.rs" "ProductionServerNonceReplay"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "100\\.64|is_forbidden_production_ip"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "169\\.254|is_link_local"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "::ffff:127\\.0\\.0\\.1"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "production_client_builds_with_real_pinning_verifier"
require_pattern "crates/umbrella-client/src/transport/pinning.rs" "matching_pin_does_not_bypass_inner_certificate_failure"
require_pattern "crates/umbrella-client/src/transport/pinning.rs" "wrong_key_for_same_server_is_rejected_after_inner_accepts"
require_pattern "crates/umbrella-platform-verifier/src/web.rs" "webauthn_rejects_context_device_key_not_registered_key"
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "threshold_compromised_views_can_verify_but_safety_numbers_diverge"
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1"
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check"
require_pattern "crates/umbrella-backup/src/cloud_wrap/unwrap.rs" "unwrap_fails_on_tampered_aad"
require_pattern "crates/umbrella-backup/src/cloud_wrap/pq_wrap.rs" "v2_unwrap_rejects_tampered_canonical_aad"
require_pattern "crates/umbrella-oprf/src/threshold.rs" "threshold_combine_rejects_duplicate_index"
require_pattern "crates/umbrella-oprf/src/threshold.rs" "threshold_tampered_share_breaks_combine"
require_pattern "crates/umbrella-sealed-sender/src/hybrid_envelope.rs" "forged_inner_signature_rejected_after_successful_v2_decrypt"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_attack_cross_version_replay_v1_to_v2_blocked"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_fuzz_v2_unseal_100k_random_bytes_no_panic_no_silent_accept"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_attack_replay_envelope_to_different_recipient_aad_blocks"
require_pattern "docs/security/protocol-core-attack-gates.md" "повтор серверного вызова"
require_pattern "docs/security/protocol-core-attack-gates.md" "split-view"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_witness_verification_has_no_shared_state_corruption"
require_pattern "scripts/audit-local-release-hardening.sh" "secret-looking structs derive Debug"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "split-view"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "protocol core attack gates OK"
