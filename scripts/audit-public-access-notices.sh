#!/usr/bin/env bash
set -euo pipefail

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
    echo "$file does not contain required notice: $pattern" >&2
    failed=1
  fi
}

require_pattern "LICENSE" "NOT AN OPEN-SOURCE LICENSE"
require_pattern "LICENSE" "COMMERCIAL USE"
require_pattern "LICENSE" "PROHIBITED"
require_pattern "LICENSE" "FUZZING|FORMAL VERIFICATION|CRYPTOGRAPHIC TESTING"

require_pattern "PUBLIC_ACCESS.md" "source-available.*cryptographic"
require_pattern "PUBLIC_ACCESS.md" "not open-source"
require_pattern "PUBLIC_ACCESS.md" "Not Allowed Without Written Permission"

require_pattern "README.md" "Исходный код доступен для чтения"
require_pattern "README.md" "source-available, not open-source"
require_pattern "README.md" "PUBLIC_ACCESS.md"
require_pattern "README.md" "бизнес-продукт"
require_pattern "README.md" "embedding in a business product"

require_pattern "SECURITY.md" "fuzzing"
require_pattern "SECURITY.md" "does not grant commercial use"
require_pattern "CONTRIBUTING.md" "PUBLIC_ACCESS.md"
require_pattern "CONTRIBUTING.md" "Commercial use"

require_pattern "docs/README.md" "protocol-compliance hardening|приведение к документам"
require_pattern "docs/README.md" "private protocol specifications"
require_pattern "docs/security/release-manifest-v1.0.0.txt" "Public Access"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "public access notices OK"
