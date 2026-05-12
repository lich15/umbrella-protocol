#!/usr/bin/env bash
set -euo pipefail

root="${1:-.github/workflows}"
failed=0

if [[ ! -d "$root" ]]; then
  echo "workflow directory not found: $root" >&2
  exit 2
fi

while IFS= read -r -d '' workflow; do
  if ! grep -Eq '^permissions:' "$workflow"; then
    echo "missing top-level permissions: $workflow" >&2
    failed=1
  fi

  if grep -Eq '^[[:space:]]*pull_request_target:' "$workflow"; then
    echo "pull_request_target is not allowed without explicit security approval: $workflow" >&2
    failed=1
  fi

  while IFS= read -r line; do
    raw="${line%%#*}"
    ref="${raw#*uses:}"
    ref="$(printf '%s' "$ref" | xargs)"

    case "$ref" in
      ""|./*|docker://*)
        continue
        ;;
    esac

    if [[ "$ref" != *@* ]]; then
      echo "GitHub Action reference missing @ pin: $workflow: $ref" >&2
      failed=1
      continue
    fi

    version="${ref##*@}"
    if [[ ! "$version" =~ ^[0-9a-fA-F]{40}$ ]]; then
      echo "mutable GitHub Action reference: $workflow: $ref" >&2
      failed=1
    fi
  done < <(grep -E '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*' "$workflow" || true)
done < <(find "$root" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)

exit "$failed"
