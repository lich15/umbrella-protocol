#!/bin/bash
# R6 lldb scan harness — runs r6_zeroize_lldb_target under lldb, stops at
# function breakpoints around xwing_keygen, dumps all writable memory regions
# and searches for the 32-byte seed pattern (0xAA repeated) which is the
# input seed that should have been zeroize'd after keygen returned.
#
# Usage:
#   ./docs/audits/reality-pass-artifacts/r6_lldb_scan.sh

set -eo pipefail

BINARY="target/r6-release/examples/r6_zeroize_lldb_target"
if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run: cargo build --profile r6-release --example r6_zeroize_lldb_target -p umbrella-pq --features ml-kem"
    exit 1
fi
SCAN_OUT="$(dirname "$0")/r6_lldb_output.txt"

# Ensure /tmp has a copy of the lldb script (repo copy is the canonical source).
cp "$(dirname "$0")/r6_lldb_script.py" /tmp/r6_lldb_script.py

cat > /tmp/r6_lldb_commands.txt <<'LLDB_EOF'
target create target/r6-release/examples/r6_zeroize_lldb_target
command script import /tmp/r6_lldb_script.py
breakpoint set -n r6_break_after_fill --auto-continue true --command r6_scan_pos
breakpoint set -n r6_phase_before_keygen --auto-continue true --command r6_scan_before
breakpoint set -n r6_phase_after_keygen --auto-continue true --command r6_scan_after
breakpoint set -n r6_phase_after_drop --auto-continue true --command r6_scan_drop
run
LLDB_EOF

lldb -b -s /tmp/r6_lldb_commands.txt 2>&1 | tee "$SCAN_OUT"

echo ""
echo "==================== R6 SCAN SUMMARY ===================="
grep -E "R6 lldb" "$SCAN_OUT" || true
echo "========================================================"
echo "Full output saved to: $SCAN_OUT"
