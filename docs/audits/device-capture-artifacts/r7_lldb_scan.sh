#!/bin/bash
# R7 device-capture lldb scan — runs r7_identity_lldb_target under lldb,
# stops at named breakpoints around bootstrap_identity + sqlite store open,
# dumps writable regions, searches for the 32-byte 0xCD entropy needle AND
# the 32-byte 0xDC master_key needle.
#
# Usage:
#   cargo build --profile r6-release --example r7_identity_lldb_target -p umbrella-client
#   ./docs/audits/device-capture-artifacts/r7_lldb_scan.sh

set -eo pipefail

BINARY="target/r6-release/examples/r7_identity_lldb_target"
if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run: cargo build --profile r6-release --example r7_identity_lldb_target -p umbrella-client"
    exit 1
fi
SCAN_OUT="$(dirname "$0")/r7_lldb_output.txt"

cp "$(dirname "$0")/r7_lldb_script.py" /tmp/r7_lldb_script.py

# Use the `breakpoint command add` form with `continue` explicit at the end
# (proven in round-2 R6 — `--auto-continue true --command` form occasionally
# deadlocks on Xcode 16 lldb when the Python callback walks huge writable
# regions; explicit continue inside the command list avoids the deadlock).
cat > /tmp/r7_lldb_commands.txt <<'LLDB_EOF'
target create target/r6-release/examples/r7_identity_lldb_target
command script import /tmp/r7_lldb_script.py
breakpoint set -n r7_break_after_needle_alive
breakpoint command add 1
r7_scan_pos
continue
DONE
breakpoint set -n r7_phase_before_bootstrap
breakpoint command add 2
r7_scan_before
continue
DONE
breakpoint set -n r7_phase_live_identity
breakpoint command add 3
r7_scan_live
continue
DONE
breakpoint set -n r7_phase_after_drop
breakpoint command add 4
r7_scan_drop
continue
DONE
run
LLDB_EOF

lldb -b -s /tmp/r7_lldb_commands.txt 2>&1 | tee "$SCAN_OUT"

echo ""
echo "==================== R7 SCAN SUMMARY ===================="
grep -E "R7 lldb" "$SCAN_OUT" || true
echo "========================================================="
echo "Full output: $SCAN_OUT"
