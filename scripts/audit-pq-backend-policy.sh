#!/usr/bin/env bash
set -euo pipefail

failed=0
backend_tree="$(mktemp -t umbrella-pq-backend-tree.XXXXXX)"
trap 'rm -f "$backend_tree"' EXIT

require_toml_pin() {
  local crate="$1"
  local version="$2"

  if ! grep -Eq "${crate}[[:space:]]*=.*version[[:space:]]*=[[:space:]]*\"=${version}\"" Cargo.toml; then
    echo "missing exact workspace pin ${crate} =${version}" >&2
    failed=1
  fi
}

lock_version() {
  local crate="$1"
  awk -v crate="$crate" '
    $0 == "[[package]]" { in_pkg = 0 }
    $1 == "name" && $3 == "\"" crate "\"" { in_pkg = 1 }
    in_pkg && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.lock
}

require_lock_version() {
  local crate="$1"
  local version="$2"
  local actual

  actual="$(lock_version "$crate")"
  if [[ "$actual" != "$version" ]]; then
    echo "Cargo.lock has ${crate} ${actual:-<missing>}, expected ${version}" >&2
    failed=1
  fi
}

require_toml_pin "libcrux-ml-dsa" "0.0.8"
require_toml_pin "libcrux-ml-kem" "0.0.8"
require_toml_pin "libcrux-kem" "0.0.7"
require_toml_pin "fips205" "0.4.1"

require_lock_version "libcrux-ml-dsa" "0.0.8"
require_lock_version "libcrux-ml-kem" "0.0.8"
require_lock_version "libcrux-kem" "0.0.7"
require_lock_version "fips205" "0.4.1"

if ! cargo tree -p umbrella-pq --features full -e normal >"$backend_tree"; then
  echo "failed to inspect umbrella-pq dependency tree" >&2
  failed=1
else
  for crate in libcrux-ml-dsa libcrux-ml-kem libcrux-kem fips205; do
    if ! grep -q "$crate v" "$backend_tree"; then
      echo "umbrella-pq full feature tree does not contain $crate" >&2
      failed=1
    fi
  done
fi

if ! cargo audit; then
  echo "cargo audit reported a vulnerability" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "PQ backend policy OK"
echo "libcrux-ml-dsa 0.0.8 includes fixes for verifier norm and hint-counter bugs"
echo "libcrux-ml-kem 0.0.8, libcrux-kem 0.0.7, fips205 0.4.1 pinned exactly"
