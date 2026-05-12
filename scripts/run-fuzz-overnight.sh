#!/usr/bin/env bash
# Локальный overnight runner для всех cargo-fuzz таргетов в umbrella-fuzz.
# Local overnight runner for all cargo-fuzz targets in umbrella-fuzz.
#
#
# Назначение: альтернатива Google OSS-Fuzz CI до момента submission в
# google/oss-fuzz repo. Запускает каждый fuzz target, который возвращает
# `cargo +nightly fuzz list`, на ограниченное время через
# `cargo +nightly fuzz run -- -max_total_time=<N>` и собирает crashes / coverage
# stats в `target/fuzz-overnight/<timestamp>/`.
#
# Purpose: alternative to Google OSS-Fuzz CI until the submission to the
# google/oss-fuzz repo lands. Runs each fuzz target returned by
# `cargo +nightly fuzz list` for a bounded time via
# `cargo +nightly fuzz run -- -max_total_time=<N>` and collects crashes /
# coverage stats in `target/fuzz-overnight/<timestamp>/`.
#
# Использование:
#   scripts/run-fuzz-overnight.sh                  # дефолт 1800 sec/target × all discovered targets
#   scripts/run-fuzz-overnight.sh 3600             # 1 час/target = ~24 часа всего
#   scripts/run-fuzz-overnight.sh 600 xwing_pubkey_parser hybrid_signature_parser
#                                                  # 10 min × 2 specific targets = ~20 min
#
# Usage:
#   scripts/run-fuzz-overnight.sh                  # default 1800 sec/target × all discovered targets
#   scripts/run-fuzz-overnight.sh 3600             # 1 hour/target = ~24 hours total
#   scripts/run-fuzz-overnight.sh 600 xwing_pubkey_parser hybrid_signature_parser
#                                                  # 10 min × 2 specific targets = ~20 min
#
# Pre-requisites:
#   * Nightly Rust toolchain — `rustup toolchain install nightly`.
#   * cargo-fuzz binary    — `cargo install cargo-fuzz` (один раз).
#   * Запускайте из корня репо.
#
# Run from the repo root. Requires nightly Rust + cargo-fuzz binary in PATH.

set -uo pipefail
# Не используем `-e`: все ошибки обрабатываем через if/else блоки explicitly.
# `-e` ломает скрипт на любом non-zero exit (например grep без match'а в
# статистике libFuzzer); это создаёт false-positive failures когда сами
#
# We don't use `-e`: all errors handled via explicit if/else blocks.
# `-e` kills the script on any non-zero exit (e.g. grep without a match in
# libFuzzer stats); this caused false-positive failures when fuzz targets

# Default: 30 минут на каждый target.
# Override через первый позиционный аргумент.
# Default: 30 minutes per target.
# Overridable via the first positional argument.
TIME_PER_TARGET="${1:-1800}"
shift || true

case "$TIME_PER_TARGET" in
    ''|*[!0-9]*)
        echo "error: time per target must be a positive integer number of seconds" >&2
        exit 2
        ;;
esac

if [ "$TIME_PER_TARGET" -le 0 ]; then
    echo "error: time per target must be greater than zero; libFuzzer treats 0 as unbounded" >&2
    exit 2
fi

# Sanity checks для требуемого toolchain + cargo-fuzz binary.
# Sanity checks for required toolchain + cargo-fuzz binary.
if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not in PATH" >&2
    exit 1
fi

if ! cargo +nightly --version >/dev/null 2>&1; then
    echo "error: nightly toolchain not installed; run 'rustup toolchain install nightly'" >&2
    exit 1
fi

if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "error: cargo-fuzz not installed; run 'cargo install cargo-fuzz'" >&2
    exit 1
fi

FUZZ_DIR="crates/umbrella-fuzz/fuzz"
if [ ! -d "$FUZZ_DIR" ]; then
    echo "error: fuzz sub-workspace not found: $FUZZ_DIR (run from repo root)" >&2
    exit 1
fi

# Обнаруживаем targets через cargo-fuzz, чтобы weekly CI не отставал от
# `Cargo.toml` при добавлении новых harness'ов.
#
# Discover targets through cargo-fuzz so weekly CI cannot drift behind
# `Cargo.toml` when new harnesses are added.
ALL_TARGETS=()
while IFS= read -r TARGET_NAME; do
    if [ -n "$TARGET_NAME" ]; then
        ALL_TARGETS+=("$TARGET_NAME")
    fi
done < <(cd "$FUZZ_DIR" && cargo +nightly fuzz list)
if [ "${#ALL_TARGETS[@]}" -eq 0 ]; then
    echo "error: cargo-fuzz returned zero targets" >&2
    exit 1
fi

# Если переданы additional positional args — использовать их как target list.
# Otherwise — full discovered target sweep.
#
# If additional positional args are passed, use them as the target list.
# Otherwise, run a full discovered target sweep.
if [ "$#" -gt 0 ]; then
    TARGETS=("$@")
else
    TARGETS=("${ALL_TARGETS[@]}")
fi

TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
RESULTS_DIR="target/fuzz-overnight/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

echo "=== umbrella-fuzz overnight runner ===" | tee "$SUMMARY_FILE"
echo "Started: $(date -u)" | tee -a "$SUMMARY_FILE"
echo "Time per target: ${TIME_PER_TARGET}s" | tee -a "$SUMMARY_FILE"
echo "Targets: ${#TARGETS[@]}" | tee -a "$SUMMARY_FILE"
echo "Results: $RESULTS_DIR" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

OVERALL_FAIL=0

for TARGET in "${TARGETS[@]}"; do
    TARGET_LOG="$RESULTS_DIR/${TARGET}.log"
    echo "--- $TARGET (max ${TIME_PER_TARGET}s) ---" | tee -a "$SUMMARY_FILE"

    # cargo +nightly fuzz run использует libFuzzer -max_total_time опцию для
    # bounded execution. Без этого — бесконечный прогон.
    #
    # cargo +nightly fuzz run uses the libFuzzer -max_total_time option for
    # bounded execution. Without it the run is unbounded.
    if (cd "$FUZZ_DIR" && cargo +nightly fuzz run "$TARGET" -- \
            -max_total_time="$TIME_PER_TARGET" \
            -print_final_stats=1 \
            >"../../../$TARGET_LOG" 2>&1); then
        echo "  PASS (no crash in ${TIME_PER_TARGET}s)" | tee -a "$SUMMARY_FILE"
    else
        echo "  FAIL — see $TARGET_LOG" | tee -a "$SUMMARY_FILE"
        OVERALL_FAIL=$((OVERALL_FAIL + 1))
    fi

    # Извлечь финальные stats — count of executed inputs + coverage edges.
    # `|| echo "?"` гарантирует graceful fallback если libFuzzer формат stats
    # отличается между nightly versions либо grep не находит pattern.
    #
    # Extract final stats — count of executed inputs + coverage edges.
    # `|| echo "?"` ensures graceful fallback if libFuzzer stats format
    # differs across nightly versions or grep finds no pattern.
    EXECS=$(grep "stat::number_of_executed_units" "$TARGET_LOG" 2>/dev/null | tail -1 | awk '{print $NF}' || echo "?")
    COVERAGE=$(grep "stat::edge_coverage" "$TARGET_LOG" 2>/dev/null | tail -1 | awk '{print $NF}' || echo "?")
    echo "  Executions: ${EXECS:-?}, edges: ${COVERAGE:-?}" | tee -a "$SUMMARY_FILE"

    echo "" | tee -a "$SUMMARY_FILE"
done

echo "=== Done at $(date -u) ===" | tee -a "$SUMMARY_FILE"
echo "Failed: $OVERALL_FAIL / ${#TARGETS[@]}" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"
echo "Если есть FAIL — смотрите $RESULTS_DIR/<target>.log + crash artefacts" | tee -a "$SUMMARY_FILE"
echo "в crates/umbrella-fuzz/fuzz/artifacts/<target>/." | tee -a "$SUMMARY_FILE"
echo "If any FAIL — see $RESULTS_DIR/<target>.log + crash artefacts in" | tee -a "$SUMMARY_FILE"
echo "crates/umbrella-fuzz/fuzz/artifacts/<target>/." | tee -a "$SUMMARY_FILE"

exit "$OVERALL_FAIL"
