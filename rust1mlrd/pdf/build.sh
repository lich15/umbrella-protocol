#!/usr/bin/env bash
# build.sh — Umbrella Protocol whitepaper compiler
# Compiles both Russian and English Typst sources to PDF.
#
# Usage:
#   ./build.sh                # compile both versions
#   ./build.sh ru             # only Russian
#   ./build.sh en             # only English
#   ./build.sh --watch        # rebuild on file change (both)
#
# Output directory: ./out/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Pretty logging
# ---------------------------------------------------------------------------

COL_BLUE=$'\033[1;34m'
COL_GREEN=$'\033[1;32m'
COL_YELLOW=$'\033[1;33m'
COL_RED=$'\033[1;31m'
COL_RESET=$'\033[0m'

log()   { printf '%s\n' "${COL_BLUE}[build]${COL_RESET} $*"; }
ok()    { printf '%s\n' "${COL_GREEN}[ok]${COL_RESET}    $*"; }
warn()  { printf '%s\n' "${COL_YELLOW}[warn]${COL_RESET}  $*"; }
fail()  { printf '%s\n' "${COL_RED}[fail]${COL_RESET}  $*" >&2; }

# ---------------------------------------------------------------------------
# Verify / install typst
# ---------------------------------------------------------------------------

ensure_typst() {
  if command -v typst >/dev/null 2>&1; then
    local v
    v="$(typst --version 2>&1 | head -1)"
    ok "typst found — $v"
    return 0
  fi
  warn "typst is not installed."

  case "$(uname -s)" in
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        log "Attempting: brew install typst"
        if brew install typst; then
          ok "typst installed via Homebrew"
          return 0
        fi
        fail "brew install typst failed."
      else
        fail "Homebrew not present. Install Homebrew first: https://brew.sh"
      fi
      ;;
    Linux)
      fail "On Linux, install typst manually:"
      fail "  cargo install --git https://github.com/typst/typst --locked typst-cli"
      fail "  or download a binary from https://github.com/typst/typst/releases"
      ;;
    *)
      fail "Unsupported platform $(uname -s). Install typst manually:"
      fail "  https://github.com/typst/typst#installation"
      ;;
  esac

  fail "Cannot proceed without typst. Re-run after install."
  return 1
}

# ---------------------------------------------------------------------------
# Compile one file
# ---------------------------------------------------------------------------

compile_one() {
  local src="$1"
  local lang="$2"
  local out_pdf="$OUT_DIR/$(basename "${src%.typ}").pdf"

  log "Compiling $lang: $src → $out_pdf"
  if typst compile --root "$SCRIPT_DIR" "$src" "$out_pdf"; then
    local size
    size="$(du -h "$out_pdf" | awk '{print $1}')"
    ok "$lang PDF built — $out_pdf ($size)"
    return 0
  else
    fail "$lang compile failed"
    return 1
  fi
}

watch_all() {
  log "Watch mode — rebuilds on save (Ctrl-C to stop)"
  typst watch --root "$SCRIPT_DIR" umbrella-whitepaper-ru.typ "$OUT_DIR/umbrella-whitepaper-ru.pdf" &
  local pid_ru=$!
  typst watch --root "$SCRIPT_DIR" umbrella-whitepaper-en.typ "$OUT_DIR/umbrella-whitepaper-en.pdf" &
  local pid_en=$!
  trap 'kill "$pid_ru" "$pid_en" 2>/dev/null || true' EXIT INT TERM
  wait
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

target="${1:-both}"

ensure_typst || exit 1

case "$target" in
  ru)
    compile_one umbrella-whitepaper-ru.typ "Russian"
    ;;
  en)
    compile_one umbrella-whitepaper-en.typ "English"
    ;;
  --watch|watch)
    watch_all
    ;;
  both|"")
    compile_one umbrella-whitepaper-ru.typ "Russian" || true
    compile_one umbrella-whitepaper-en.typ "English" || true
    ;;
  *)
    fail "Unknown target: $target"
    fail "Usage: $0 [ru|en|both|--watch]"
    exit 2
    ;;
esac

# Summary
log "Output directory: $OUT_DIR"
if compgen -G "$OUT_DIR/*.pdf" >/dev/null; then
  ls -lh "$OUT_DIR"/*.pdf
fi
