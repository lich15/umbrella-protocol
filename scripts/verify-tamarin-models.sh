#!/usr/bin/env bash
# Verify all Tamarin Prover models in the umbrella-formal-verification crate.
#
# Запускается weekly CI job (.github/workflows/formal-verification.yml) либо
# локально для верификации отдельных моделей. Поэтапно итерирует все .spthy
# файлы в crates/umbrella-formal-verification/models/, запускает
# `tamarin-prover --prove`, проверяет что output содержит "verified" для
# каждой lemma и сохраняет artefacts в target/tamarin-results/.
#
# Запускайте из корня репо. Требует `tamarin-prover` 1.10.0+ в PATH.
#
# Runs as a weekly CI job (.github/workflows/formal-verification.yml) or
# locally to verify individual models. Iterates over all .spthy files in
# crates/umbrella-formal-verification/models/, runs `tamarin-prover --prove`,
# checks that the output contains "verified" for each lemma, and saves
# artefacts in target/tamarin-results/.
#
# Run from the repo root. Requires `tamarin-prover` 1.10.0+ in PATH.

set -euo pipefail

MODELS_DIR="crates/umbrella-formal-verification/models"
RESULTS_DIR="target/tamarin-results"

if [ ! -d "$MODELS_DIR" ]; then
    echo "error: models directory not found: $MODELS_DIR" >&2
    exit 1
fi

if ! command -v tamarin-prover >/dev/null 2>&1; then
    echo "error: tamarin-prover not in PATH (install via stack install tamarin-prover or GitHub release)" >&2
    exit 127
fi

mkdir -p "$RESULTS_DIR"

shopt -s nullglob
models=("$MODELS_DIR"/*.spthy)
shopt -u nullglob

if [ ${#models[@]} -eq 0 ]; then
    echo "warning: no .spthy models found in $MODELS_DIR — nothing to verify"
    exit 0
fi

failed=0
for model in "${models[@]}"; do
    name=$(basename "$model" .spthy)
    out="$RESULTS_DIR/$name.txt"
    echo "==> Verifying $name"
    if tamarin-prover --prove "$model" >"$out" 2>&1; then
        if grep -q "verified" "$out"; then
            echo "    OK: $name verified"
        else
            echo "    FAIL: $name — no 'verified' marker in output" >&2
            tail -n 50 "$out" >&2
            failed=$((failed + 1))
        fi
    else
        echo "    FAIL: $name — tamarin-prover non-zero exit" >&2
        tail -n 50 "$out" >&2
        failed=$((failed + 1))
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "$failed model(s) failed verification" >&2
    exit 1
fi
echo "All ${#models[@]} Tamarin model(s) verified."
