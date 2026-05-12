#!/usr/bin/env bash
set -euo pipefail

results_dir="${1:-target/production-readiness/formal}"
timeout_seconds="${FORMAL_TIMEOUT_SECONDS:-600}"
mkdir -p "$results_dir"

failed=0

run_with_timeout() {
  local seconds="$1"
  shift
  perl -e 'alarm shift @ARGV; exec @ARGV' "$seconds" "$@"
}

proverif_cmd() {
  if command -v proverif >/dev/null 2>&1; then
    proverif "$@"
  elif command -v opam >/dev/null 2>&1 && opam exec -- proverif -help >/dev/null 2>&1; then
    opam exec -- proverif "$@"
  else
    return 127
  fi
}

run_proverif() {
  local model="$1"
  local name
  name="$(basename "$model" .pv)"
  local out="$results_dir/${name}.proverif.txt"

  if ! proverif_cmd "$model" >"$out" 2>&1; then
    echo "FAIL proverif $name" >&2
    failed=1
    return
  fi

  if grep -Eq "RESULT .* is false" "$out"; then
    echo "FAIL proverif $name: false query" >&2
    failed=1
    return
  fi

  local true_count
  true_count="$(grep -Ec "RESULT .* is true" "$out" || true)"
  if [[ "$true_count" -lt 3 ]]; then
    echo "FAIL proverif $name: expected at least 3 true results, got $true_count" >&2
    failed=1
    return
  fi

  echo "OK proverif $name ($true_count true results)"
}

run_tamarin_lemma() {
  local model="$1"
  local lemma="$2"
  local out="$results_dir/$(basename "$model" .spthy).${lemma}.tamarin.txt"

  if ! command -v tamarin-prover >/dev/null 2>&1; then
    echo "missing tamarin-prover" | tee "$out" >&2
    failed=1
    return
  fi

  if ! run_with_timeout "$timeout_seconds" tamarin-prover --prove="$lemma" "$model" >"$out" 2>&1; then
    echo "FAIL tamarin $lemma" >&2
    failed=1
    return
  fi

  if grep -q "falsified" "$out"; then
    echo "FAIL tamarin $lemma: falsified" >&2
    failed=1
    return
  fi

  if grep -Eq "WARNING:|wellformedness checks failed|analysis results might be wrong" "$out"; then
    echo "FAIL tamarin $lemma: wellformedness warning" >&2
    failed=1
    return
  fi

  if ! grep -Eq "[[:space:]]${lemma} \\([^)]*\\): verified" "$out"; then
    echo "FAIL tamarin $lemma: no verified marker" >&2
    failed=1
    return
  fi

  echo "OK tamarin $lemma"
}

run_proverif crates/umbrella-formal-verification/models/oprf_ristretto255.pv

downgrade_model="crates/umbrella-formal-verification/models/downgrade_resistance.spthy"
run_tamarin_lemma "$downgrade_model" adversary_cannot_force_silent_downgrade
run_tamarin_lemma "$downgrade_model" explicit_chatsettings_override_allowed
run_tamarin_lemma "$downgrade_model" default_ciphersuite_respected
run_tamarin_lemma "$downgrade_model" no_silent_fallback_under_capability_mismatch
run_tamarin_lemma "$downgrade_model" honest_setup_executable

exit "$failed"
