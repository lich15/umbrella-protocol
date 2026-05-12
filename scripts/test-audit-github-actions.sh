#!/usr/bin/env bash
set -euo pipefail

mutable_root="scripts/fixtures/github-actions/mutable-action/.github/workflows"
pinned_root="scripts/fixtures/github-actions/pinned-action/.github/workflows"

if bash scripts/audit-github-actions.sh "$mutable_root" >/tmp/umbrella-actions-mutable.out 2>&1; then
  echo "mutable action fixture unexpectedly passed" >&2
  cat /tmp/umbrella-actions-mutable.out >&2
  exit 1
fi

if ! grep -q "mutable GitHub Action reference" /tmp/umbrella-actions-mutable.out; then
  echo "mutable fixture failed for the wrong reason" >&2
  cat /tmp/umbrella-actions-mutable.out >&2
  exit 1
fi

bash scripts/audit-github-actions.sh "$pinned_root" >/tmp/umbrella-actions-pinned.out 2>&1
