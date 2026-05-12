#!/usr/bin/env bash
# Verify all ProVerif models in the umbrella-formal-verification crate.
#
# Запускается weekly CI job (.github/workflows/formal-verification.yml) либо
# локально для верификации отдельных моделей. Поэтапно итерирует все .pv
# файлы в crates/umbrella-formal-verification/models/, запускает `proverif`
# на каждом, проверяет что output содержит "RESULT ... is true" либо
# "cannot be proved false" и сохраняет artefacts в target/proverif-results/.
#
# Сейчас директория .pv файлов пустая — первая ProVerif модель создаётся в
# блоке 9.4 (sealed-sender V2 + backup wrap V2 confidentiality). Скрипт
# gracefully handles empty directory: выходит с кодом 0 и informational
# сообщением.
#
# Запускайте из корня репо. Требует `proverif` 2.05+ в PATH.
#
# Runs as a weekly CI job (.github/workflows/formal-verification.yml) or
# locally to verify individual models. Iterates over all .pv files in
# crates/umbrella-formal-verification/models/, runs `proverif` on each,
# checks that the output contains "RESULT ... is true" or "cannot be proved
# false", and saves artefacts in target/proverif-results/.
#
# Currently the .pv files directory is empty — the first ProVerif model is
# The script gracefully handles an empty directory: it exits with code 0
# and an informational message.
#
# Run from the repo root. Requires `proverif` 2.05+ in PATH.

set -euo pipefail

MODELS_DIR="crates/umbrella-formal-verification/models"
RESULTS_DIR="target/proverif-results"

if [ ! -d "$MODELS_DIR" ]; then
    echo "error: models directory not found: $MODELS_DIR" >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"

shopt -s nullglob
models=("$MODELS_DIR"/*.pv)
shopt -u nullglob

if [ ${#models[@]} -eq 0 ]; then
    echo "info: no .pv models found in $MODELS_DIR — no ProVerif models found"
    exit 0
fi

if ! command -v proverif >/dev/null 2>&1; then
    echo "error: proverif not in PATH (install via opam install proverif or apt-get install proverif)" >&2
    exit 127
fi

failed=0
for model in "${models[@]}"; do
    name=$(basename "$model" .pv)
    out="$RESULTS_DIR/$name.txt"
    echo "==> Verifying $name"
    if proverif "$model" >"$out" 2>&1; then
        if grep -Eq "RESULT.*is true|cannot be proved false" "$out"; then
            echo "    OK: $name verified"
        else
            echo "    FAIL: $name — no positive RESULT marker in output" >&2
            tail -n 50 "$out" >&2
            failed=$((failed + 1))
        fi
    else
        echo "    FAIL: $name — proverif non-zero exit" >&2
        tail -n 50 "$out" >&2
        failed=$((failed + 1))
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "$failed model(s) failed verification" >&2
    exit 1
fi
echo "All ${#models[@]} ProVerif model(s) verified."
