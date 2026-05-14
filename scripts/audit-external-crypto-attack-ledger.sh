#!/usr/bin/env bash
set -euo pipefail

ledger="docs/security/external-crypto-attack-ledger-2026-05-14.md"
failed=0

require_file() {
  if [[ ! -f "$ledger" ]]; then
    echo "missing external crypto attack ledger: $ledger" >&2
    exit 1
  fi
}

require_pattern() {
  local pattern="$1"
  if ! grep -Eqi "$pattern" "$ledger"; then
    echo "$ledger missing required pattern: $pattern" >&2
    failed=1
  fi
}

reject_pattern() {
  local pattern="$1"
  if grep -Eqi "$pattern" "$ledger"; then
    echo "$ledger contains forbidden wording: $pattern" >&2
    failed=1
  fi
}

require_file

require_pattern "RFC 9497"
require_pattern "RFC 9420"
require_pattern "RFC 9180"
require_pattern "RFC 9605"
require_pattern "RFC 8446"
require_pattern "FIPS 203"
require_pattern "FIPS 204"
require_pattern "FIPS 205"
require_pattern "WebAuthn"
require_pattern "Apple App Attest"
require_pattern "Android Play Integrity"
require_pattern "Signal"
require_pattern "KyberSlash"
require_pattern "RustSec"
require_pattern "cargo-deny"
require_pattern "SLSA"

require_pattern "OPRF"
require_pattern "KT"
require_pattern "TLS"
require_pattern "PQ"
require_pattern "Backup"
require_pattern "Sealed Sender"
require_pattern "MLS"
require_pattern "SFrame"
require_pattern "Устройства"
require_pattern "Зависимости"

require_pattern "закрыто тестом"
require_pattern "закрыто отказом"
require_pattern "граница выпуска"
require_pattern "неприменимо"

reject_pattern "TBD|TODO|FIXME"
reject_pattern "100%|невозможно взломать|абсолютно безопас"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "external crypto attack ledger OK"
