#!/usr/bin/env bash
set -euo pipefail

failed=0

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required monitoring file: $path" >&2
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

require_file ".github/dependabot.yml"
require_file ".github/workflows/dependency-monitor.yml"
require_file "docs/security/dependency-monitoring.md"

# RU: Dependabot должен готовить ветки/PR, а не менять main напрямую.
# EN: Dependabot must prepare branches/PRs, not mutate main directly.
require_grep ".github/dependabot.yml" "package-ecosystem: \"cargo\"" \
  "dependabot must monitor Rust crates"
require_grep ".github/dependabot.yml" "directory: \"/crates/umbrella-fuzz/fuzz\"" \
  "dependabot must monitor the fuzz lockfile separately"
require_grep ".github/dependabot.yml" "version-update:semver-major" \
  "dependabot must avoid silent major upgrades"

# RU: Ежедневный сторож должен проверять уязвимости, оба lockfile и локальные ворота.
# EN: The daily sentinel must check advisories, both lockfiles, and local gates.
require_grep ".github/workflows/dependency-monitor.yml" "cron:" \
  "dependency monitor must run on a schedule"
require_grep ".github/workflows/dependency-monitor.yml" "cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock" \
  "dependency monitor must audit fuzz Cargo.lock"
require_grep ".github/workflows/dependency-monitor.yml" "scripts/audit-pq-backend-policy.sh" \
  "dependency monitor must enforce PQ/backend policy"
require_grep ".github/workflows/dependency-monitor.yml" "cargo update --dry-run" \
  "dependency monitor must report available dependency updates without applying them"
require_grep ".github/workflows/dependency-monitor.yml" "permissions:[[:space:]]*$" \
  "dependency monitor must declare top-level permissions"

# RU: Документ должен явно запрещать автоматическое вливание обновлений.
# EN: The document must explicitly forbid automatic merge of dependency updates.
require_grep "docs/security/dependency-monitoring.md" "не вливает.*main" \
  "dependency monitoring doc must say updates are not merged into main automatically"
require_grep "docs/security/dependency-monitoring.md" "Dependabot" \
  "dependency monitoring doc must mention Dependabot"
require_grep "docs/security/dependency-monitoring.md" "cargo audit" \
  "dependency monitoring doc must mention cargo audit"

exit "$failed"
