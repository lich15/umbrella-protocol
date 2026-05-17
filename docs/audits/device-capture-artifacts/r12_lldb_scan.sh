#!/bin/bash
# R12 device-capture lldb scan — runs r12_ratchet_lldb_target under lldb,
# stops at named breakpoints around session_live + after_drop, dumps writable
# regions, searches for the 32-byte application_secret needle written to
# /tmp/r12_needle.bin at process start.
#
# Round-5 closure: with MlockedSecret<[u8; 32]> + inline-never cipher helper +
# stack scrub, expected outcome is 0 hits both stack and heap after drop.
#
# Usage:
#   cargo build --profile r6-release --example r12_ratchet_lldb_target -p umbrella-client
#   ./docs/audits/device-capture-artifacts/r12_lldb_scan.sh

set -eo pipefail

BINARY="target/r6-release/examples/r12_ratchet_lldb_target"
if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run: cargo build --profile r6-release --example r12_ratchet_lldb_target -p umbrella-client"
    exit 1
fi
SCAN_OUT="$(dirname "$0")/r12_lldb_output.txt"

# Pre-run to populate /tmp/r12_needle.bin so the lldb python module can load it.
# Quick start; binary parks itself if R12_PAUSE=1, otherwise it runs to
# completion. We do NOT use R12_PAUSE here — we use breakpoint hits and the
# lldb-side breakpoint commands run the scan, then resume the process.
# (Note: r12_lldb_script imports the needle file at module load — so the
# binary must already have written it BEFORE we import. We pre-run it once
# to materialize /tmp/r12_needle.bin, then start the scan run.)
echo "[r12_scan] pre-run to materialize needle file"
"$BINARY" > /dev/null 2>&1 || true

cp "$(dirname "$0")/r12_lldb_script.py" /tmp/r12_lldb_script.py

cat > /tmp/r12_lldb_commands.txt <<'LLDB_EOF'
target create target/r6-release/examples/r12_ratchet_lldb_target
command script import /tmp/r12_lldb_script.py
breakpoint set -n r12_phase_session_live
breakpoint command add 1
r12_scan_live
continue
DONE
breakpoint set -n r12_phase_after_drop
breakpoint command add 2
r12_scan_drop
continue
DONE
run
LLDB_EOF

lldb -b -s /tmp/r12_lldb_commands.txt 2>&1 | tee "$SCAN_OUT"

echo ""
echo "==================== R12 SCAN SUMMARY ===================="
grep -E "R12 lldb" "$SCAN_OUT" || true
echo "==========================================================="
echo "Full output: $SCAN_OUT"
