#!/usr/bin/env bash
set -euo pipefail

evidence_dir="${1:-target/audit-evidence}"
mkdir -p "$evidence_dir"

tree_file="$evidence_dir/bincode-tree.txt"
cargo tree -e normal -i bincode >"$tree_file" 2>&1 || true

if grep -q "bincode v" "$tree_file"; then
  echo "bincode remains in normal dependency tree" >&2
  cat "$tree_file" >&2
  exit 1
fi

echo "bincode absent from normal dependency tree"

deny_file="$evidence_dir/cargo-deny-check.txt"
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "cargo-deny is required for the local release gate" | tee "$deny_file" >&2
  exit 1
fi

cargo deny check >"$deny_file" 2>&1
echo "cargo-deny check OK"
