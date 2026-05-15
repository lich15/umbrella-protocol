#!/usr/bin/env bash
set -euo pipefail

mode="${1:---local}"
failed=0

watchlist="docs/security/crypto-source-watchlist.json"
doc="docs/security/crypto-source-watchlist.md"
workflow=".github/workflows/crypto-source-monitor.yml"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required crypto source monitor file: $path" >&2
    failed=1
  fi
}

require_grep() {
  local path="$1"
  local pattern="$2"
  local message="$3"
  if [[ ! -f "$path" ]]; then
    echo "cannot check missing file: $path" >&2
    failed=1
    return
  fi
  if ! grep -Eq "$pattern" "$path"; then
    echo "$message: $path" >&2
    failed=1
  fi
}

require_file "$watchlist"
require_file "$doc"
require_file "$workflow"

require_grep "$workflow" "cron: '20 \\*/6 \\* \\* \\*'" \
  "crypto source monitor must run every six hours"
require_grep "$workflow" "scripts/audit-crypto-source-watchlist.sh --online" \
  "crypto source monitor must run the online watchlist audit"
require_grep "$doc" "код автоматически" \
  "crypto source doc must forbid automatic code updates"
require_grep "$doc" "X-Wing" \
  "crypto source doc must mention X-Wing"
require_grep "$doc" "официальные криптографические источники" \
  "crypto source doc must describe official sources"

if [[ -f "$watchlist" ]]; then
  jq -e '.sources | length >= 8' "$watchlist" >/dev/null || {
    echo "crypto watchlist must track at least eight official sources" >&2
    failed=1
  }
  jq -e '.sources[] | select(.id == "xwing-kem-draft") | .kind == "ietf_datatracker_draft" and .expected_rev == "10"' "$watchlist" >/dev/null || {
    echo "crypto watchlist must pin the current known X-Wing draft revision" >&2
    failed=1
  }
  jq -e '.sources[] | select(.id == "mls-rfc9420")' "$watchlist" >/dev/null || {
    echo "crypto watchlist must track MLS RFC 9420" >&2
    failed=1
  }
  jq -e '.sources[] | select(.id == "oprf-rfc9497")' "$watchlist" >/dev/null || {
    echo "crypto watchlist must track OPRF RFC 9497" >&2
    failed=1
  }
fi

if [[ "$mode" == "--online" && "$failed" -eq 0 ]]; then
  while IFS=$'\t' read -r id kind url expected_rev patterns_json; do
    echo "checking official crypto source: $id"
    body="$(curl --fail --silent --show-error --location --max-time 30 "$url")"

    case "$kind" in
      ietf_datatracker_draft)
        actual_rev="$(printf '%s' "$body" | jq -r '.rev')"
        if [[ "$actual_rev" != "$expected_rev" ]]; then
          echo "official draft changed: $id expected rev $expected_rev, got $actual_rev" >&2
          failed=1
        fi
        ;;
      html_contains)
        while IFS= read -r pattern; do
          [[ -z "$pattern" ]] && continue
          if ! grep -Fq "$pattern" <<<"$body"; then
            echo "official source content changed or unavailable: $id missing '$pattern'" >&2
            failed=1
          fi
        done < <(jq -r '.[]' <<<"$patterns_json")
        ;;
      *)
        echo "unknown crypto source kind for $id: $kind" >&2
        failed=1
        ;;
    esac
  done < <(
    jq -r '.sources[] | [.id, .kind, .url, (.expected_rev // ""), (.required_contains // [] | @json)] | @tsv' "$watchlist"
  )
fi

exit "$failed"
