#!/usr/bin/env bash
# Локальные Miri-ворота для путей, которые реально исполнимы под интерпретатором.
# Local Miri gates for paths that are practical under the interpreter.

set -euo pipefail

if ! cargo +nightly miri --version >/dev/null 2>&1; then
  echo "error: nightly Miri is required; run: rustup +nightly component add miri" >&2
  exit 1
fi

evidence_dir="${1:-target/audit-evidence/miri-local/$(date -u +"%Y%m%d-%H%M%S")}"
mkdir -p "$evidence_dir"
summary_file="$evidence_dir/summary.txt"

echo "Umbrella local Miri gates" | tee "$summary_file"
echo "evidence: $evidence_dir" | tee -a "$summary_file"
echo "" | tee -a "$summary_file"

run_gate() {
  local name="$1"
  shift
  local log_file="$evidence_dir/${name}.log"

  echo "== $name ==" | tee -a "$summary_file"
  echo "command: $*" | tee -a "$summary_file"
  if "$@" >"$log_file" 2>&1; then
    echo "status: PASS" | tee -a "$summary_file"
  else
    echo "status: FAIL — see $log_file" | tee -a "$summary_file"
    tail -n 80 "$log_file" >&2 || true
    exit 1
  fi
  echo "" | tee -a "$summary_file"
}

run_gate ffi \
  cargo +nightly miri test -p umbrella-ffi

# OPRF full package under Miri is intentionally not a release gate: Ristretto255
# property/threshold paths are covered by native locked tests and are too slow
# under interpretation. These focused filters keep UB coverage on production
# fail-closed, bad wire, and one small OPRF roundtrip.
#
# Полный OPRF-пакет под Miri намеренно не является выпускными воротами:
# Ristretto255 property/threshold пути покрыты обычными locked тестами и слишком
# медленные под интерпретатором. Эти фильтры оставляют проверку скрытых ошибок
# памяти на production fail-closed, плохом wire и одном коротком OPRF roundtrip.
run_gate oprf-production-fail-closed \
  cargo +nightly miri test -p umbrella-oprf --all-features \
    production_context_rejects_test_only_platform_verifier

run_gate oprf-bad-wire \
  cargo +nightly miri test -p umbrella-oprf --all-features \
    blinded_request_from_bytes_rejects_invalid_point

run_gate oprf-small-roundtrip \
  cargo +nightly miri test -p umbrella-oprf --all-features \
    round_trip_single_byte

echo "Miri local gates OK" | tee -a "$summary_file"
