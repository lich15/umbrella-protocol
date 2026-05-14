#!/usr/bin/env bash
set -uo pipefail

mode="${1:-short}"
case "$mode" in
  short) fuzz_seconds="${LOCAL_HARDENING_FUZZ_SECONDS:-5}" ;;
  long) fuzz_seconds="${LOCAL_HARDENING_FUZZ_SECONDS:-1800}" ;;
  *)
    echo "usage: $0 [short|long]" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +"%Y%m%d-%H%M%S")"
evidence_dir="target/audit-evidence/local-release-hardening/$timestamp"
mkdir -p "$evidence_dir"
summary="$evidence_dir/summary.txt"

failed=0

run_gate() {
  local name="$1"
  shift
  local log="$evidence_dir/${name}.log"
  echo "== $name ==" | tee -a "$summary"
  echo "command: $*" | tee -a "$summary"
  if "$@" >"$log" 2>&1; then
    echo "status: PASS" | tee -a "$summary"
  else
    local code="$?"
    echo "status: FAIL ($code), see $log" | tee -a "$summary"
    failed=1
  fi
  echo "" | tee -a "$summary"
}

echo "Umbrella local release hardening" | tee "$summary"
echo "mode: $mode" | tee -a "$summary"
echo "started: $(date -u)" | tee -a "$summary"
echo "evidence: $evidence_dir" | tee -a "$summary"
echo "" | tee -a "$summary"

run_gate formal-readiness bash scripts/verify-formal-production-readiness.sh "$evidence_dir/formal-readiness"
run_gate proverif-models bash scripts/verify-proverif-models.sh
run_gate tamarin-models bash scripts/verify-tamarin-models.sh
run_gate kt-split-view cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked
run_gate local-load cargo test -p umbrella-tests local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots --all-features --locked
run_gate local-race-replay cargo test -p umbrella-tests concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest --all-features --locked
run_gate local-race-witness cargo test -p umbrella-tests concurrent_witness_verification_has_no_shared_state_corruption --all-features --locked
run_gate protocol-attack-audit bash scripts/audit-protocol-core-attack-gates.sh
run_gate test-only-boundary-audit bash scripts/audit-test-only-production-boundary.sh
run_gate local-hardening-audit bash scripts/audit-local-release-hardening.sh "$evidence_dir/local-hardening-audit"
run_gate miri-local-gates bash scripts/run-miri-local-gates.sh "$evidence_dir/miri-local"

if command -v cargo-fuzz >/dev/null 2>&1 && cargo +nightly --version >/dev/null 2>&1; then
  run_gate fuzz-smoke bash scripts/run-fuzz-overnight.sh "$fuzz_seconds" kt_entry_v2_parser sealed_sender_v2_parser wrapped_key_v2_parser oprf_parse_blinded_request
else
  echo "== fuzz-smoke ==" | tee -a "$summary"
  echo "status: FAIL" | tee -a "$summary"
  echo "reason: cargo-fuzz or nightly Rust is missing; this is not counted as success" | tee -a "$summary"
  echo "" | tee -a "$summary"
  failed=1
fi

echo "finished: $(date -u)" | tee -a "$summary"
echo "failed: $failed" | tee -a "$summary"

exit "$failed"
