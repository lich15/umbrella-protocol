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
    crates/umbrella-{backup,client,identity,kt,oprf,sealed-sender,server-blind-postman,pq,crypto-primitives}/src \
    >"$output"; then
    echo "production logging/debug macros found; inspect $output" >&2
    failed=1
  fi
}

reject_secret_debug_derives() {
  local output="$evidence_dir/secret-debug-derive-candidates.txt"
  perl -0ne 'while(/#\[derive\([^\]]*Debug[^\]]*\)\]\s*(?:pub\s+)?struct\s+([A-Za-z0-9_]*(?:Secret|Private|Seed|Mnemonic)[A-Za-z0-9_]*)/g){ print "$ARGV:$1\n" }' \
    $(rg --files crates/umbrella-{backup,client,identity,kt,oprf,sealed-sender,server-blind-postman,pq,crypto-primitives}/src -g '*.rs') \
    >"$output"
  if [[ -s "$output" ]]; then
    echo "secret-looking structs derive Debug; inspect $output" >&2
    failed=1
  fi
}

reject_prod_todo_unimplemented() {
  local output="$evidence_dir/prod-todo-unimplemented.txt"
  if rg -n "todo!\(|unimplemented!\(" \
    crates/umbrella-{backup,client,identity,kt,oprf,sealed-sender,server-blind-postman,pq,crypto-primitives}/src \
    >"$output"; then
    echo "production todo/unimplemented found; inspect $output" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-identity/src/seed.rs" "debug_does_not_leak_seed"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_witness_verification_has_no_shared_state_corruption"
require_pattern "scripts/run-local-release-hardening.sh" "verify-formal-production-readiness"
require_pattern "scripts/run-local-release-hardening.sh" "run-fuzz-overnight"
require_pattern "scripts/audit-test-only-production-boundary.sh" "production HTTP/2 bootstrap is closed"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "локальная нагрузка не равна серверной проверке"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "отсутствуют, это отказ"

reject_logging_macros
reject_secret_debug_derives
reject_prod_todo_unimplemented

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "local release hardening audit OK"
