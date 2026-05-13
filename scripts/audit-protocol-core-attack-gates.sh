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
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_attack_cross_version_replay_v1_to_v2_blocked"
require_pattern "docs/security/protocol-core-attack-gates.md" "повтор серверного вызова"
require_pattern "docs/security/protocol-core-attack-gates.md" "split-view"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "protocol core attack gates OK"
