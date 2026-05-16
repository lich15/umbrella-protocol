#!/usr/bin/env bash
set -euo pipefail

evidence_dir="${1:-target/audit-evidence/local-release-hardening/manual}"
mkdir -p "$evidence_dir"

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
    echo "$file does not contain required local hardening evidence: $pattern" >&2
    failed=1
  fi
}

reject_logging_macros() {
  local output="$evidence_dir/logging-macro-candidates.txt"
  if rg -n "println!|eprintln!|dbg!|tracing::|log::" \
    crates/umbrella-{backup,calls,client,crypto-primitives,ffi,identity,kt,mls,oprf,padding,platform-verifier,pq,sealed-sender,server-blind-postman}/src \
    >"$output"; then
    echo "production logging/debug macros found; inspect $output" >&2
    failed=1
  fi
}

reject_secret_debug_derives() {
  local output="$evidence_dir/secret-debug-derive-candidates.txt"
  perl -0ne 'while(/#\[derive\([^\]]*Debug[^\]]*\)\]\s*(?:pub\s+)?struct\s+([A-Za-z0-9_]*(?:Secret|Private|Seed|Mnemonic)[A-Za-z0-9_]*)/g){ print "$ARGV:$1\n" }' \
    $(rg --files crates/umbrella-{backup,calls,client,crypto-primitives,ffi,identity,kt,mls,oprf,padding,platform-verifier,pq,sealed-sender,server-blind-postman}/src -g '*.rs') \
    >"$output"
  if [[ -s "$output" ]]; then
    echo "secret-looking structs derive Debug; inspect $output" >&2
    failed=1
  fi
}

reject_prod_todo_unimplemented() {
  local output="$evidence_dir/prod-todo-unimplemented.txt"
  if rg -n "^[[:space:]]*[^/[:space:]].*\\b(todo!|unimplemented!)\\(" \
    crates/umbrella-{backup,calls,client,crypto-primitives,ffi,identity,kt,mls,oprf,padding,platform-verifier,pq,sealed-sender,server-blind-postman}/src \
    >"$output"; then
    echo "production todo/unimplemented found; inspect $output" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-identity/src/seed.rs" "debug_does_not_leak_seed"
require_pattern "crates/umbrella-identity/src/seed.rs" "bip39_derivation_temporaries_are_zeroizing"
require_pattern "crates/umbrella-identity/src/derive.rs" "slip10_derivation_temporaries_are_zeroized"
require_pattern "crates/umbrella-identity/src/code_recovery.rs" "code_recovery_temporaries_are_zeroizing"
require_pattern "crates/umbrella-backup/src/cloud_wrap/pq_wrap.rs" "v2_inner_wrapped_key_plaintext_is_zeroizing"
require_pattern "crates/umbrella-client/src/keystore/row_cipher.rs" "decrypt_row_zeroizing_returns_zeroizing_plaintext"
require_pattern "crates/umbrella-client/src/keystore/row_cipher.rs" "row_cipher_sensitive_temporaries_are_zeroizing"
require_pattern "crates/umbrella-kt/src/observation.rs" "does not store account id"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "public_observation_encoding_round_trips_without_private_account_data"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "witness_signing_ledger_rejects_second_different_root_for_same_epoch"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_witness_verification_has_no_shared_state_corruption"
require_pattern "scripts/run-local-release-hardening.sh" "verify-formal-production-readiness"
require_pattern "scripts/run-local-release-hardening.sh" "run-fuzz-overnight"
require_pattern "scripts/audit-test-only-production-boundary.sh" "production HTTP/2 bootstrap is closed"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "локальная нагрузка не равна серверной проверке"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "отсутствуют, это отказ"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "production_transport_rejects_reserved_dns_test_names"
require_pattern "crates/umbrella-tests/tests/stage2_milestone.rs" "rate_limited_unique_messages_do_not_fill_replay_window"
require_pattern "crates/umbrella-server-blind-postman/src/envelope.rs" "parsed_envelope_debug_redacts_routing_identifiers"
require_pattern "crates/umbrella-sealed-sender/src/lib.rs" "opened_envelope_debug_redacts_message_plaintext"
require_pattern "crates/umbrella-sealed-sender/src/lib.rs" "opened_envelope_message_is_zeroizing_wrapper"
require_pattern "crates/umbrella-client/src/transport/retry.rs" "retry_jitter_uses_system_rng_not_thread_rng"
require_pattern "crates/umbrella-mls/src/group.rs" "incoming_message_debug_redacts_application_payload"
require_pattern "crates/umbrella-oprf/src/attestation.rs" "signed_oprf_request_debug_redacts_replayable_request_material"
require_pattern "crates/umbrella-backup/src/cloud_wrap/signed_request.rs" "signed_unwrap_request_debug_redacts_replayable_request_material"
require_pattern "crates/umbrella-platform-verifier/src/web.rs" "webauthn_debug_redacts_assertion_material"
require_pattern "crates/umbrella-ffi/src/types/message.rs" "message_ffi_debug_redacts_plaintext"
require_pattern "crates/umbrella-padding/src/lib.rs" "zeroizing_payload_debug_redacts_bytes"
require_pattern "docs/audits/security-hardening-audit-2026-05-15.md" "rate-limit"
require_pattern "docs/audits/security-hardening-audit-2026-05-15.md" "Debug"

reject_logging_macros
reject_secret_debug_derives
reject_prod_todo_unimplemented

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "local release hardening audit OK"
