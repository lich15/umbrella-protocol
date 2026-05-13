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
    echo "$file does not contain required boundary: $pattern" >&2
    failed=1
  fi
}

reject_pattern() {
  local file="$1"
  local pattern="$2"

  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    failed=1
    return
  fi

  if grep -Eqi "$pattern" "$file"; then
    echo "$file contains forbidden production-looking test path: $pattern" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-ffi/src/export/client.rs" "production_bootstrap_unavailable"
require_pattern "crates/umbrella-ffi/src/export/client.rs" "public FFI must not use test constructors"
require_pattern "crates/umbrella-client/src/core.rs" "production HTTP/2 bootstrap is closed"
require_pattern "crates/umbrella-client/src/core.rs" "does not carry SPKI pins"
require_pattern "crates/umbrella-client/src/core.rs" "postman/KT/call relay stubs"
require_pattern "docs/security/production-readiness-boundaries.md" "new_with_http2"
require_pattern "docs/security/current-status.md" "new_with_http2"
require_pattern "docs/security/protocol-core-attack-gates.md" "new_with_http2"

reject_pattern "crates/umbrella-client/src/core.rs" 'production \[`ClientCore::new_with_http2`\]'
reject_pattern "crates/umbrella-client/src/core.rs" 'production \[`UmbrellaClient::bootstrap_for_test`\]'

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "test-only production boundary OK"
