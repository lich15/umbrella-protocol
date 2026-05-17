#!/bin/bash
# R20 device-capture lldb scan — round-6 distributed identity zero-trace audit.
# Runs r20_distributed_identity_lldb_target under lldb, stops at named
# breakpoints around bootstrap + unlock, dumps writable regions, searches for:
#   - identity_sk needle (32 × 0xDB) — must yield 0 hits (no SK on device).
#   - identity_pk needle (32 × 0xCA) — positive control, ≥1 hit expected.
#
# Usage:
#   cargo build --profile r6-release --example r20_distributed_identity_lldb_target -p umbrella-client
#   ./docs/audits/device-capture-artifacts/r20_lldb_scan.sh

set -eo pipefail

BINARY="target/r6-release/examples/r20_distributed_identity_lldb_target"
if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run: cargo build --profile r6-release --example r20_distributed_identity_lldb_target -p umbrella-client"
    exit 1
fi
SCAN_OUT="$(dirname "$0")/r20_lldb_output.txt"

cp "$(dirname "$0")/r20_lldb_script.py" /tmp/r20_lldb_script.py

cat > /tmp/r20_lldb_commands.txt <<'LLDB_EOF'
target create target/r6-release/examples/r20_distributed_identity_lldb_target
command script import /tmp/r20_lldb_script.py
breakpoint set -n r20_phase_before_bootstrap
breakpoint command add 1
r20_scan_before
continue
DONE
breakpoint set -n r20_phase_after_bootstrap
breakpoint command add 2
r20_scan_after_bootstrap
continue
DONE
breakpoint set -n r20_phase_after_unlock
breakpoint command add 3
r20_scan_after_unlock
continue
DONE
run
quit
LLDB_EOF

lldb -b -s /tmp/r20_lldb_commands.txt 2>&1 | tee "$SCAN_OUT"
echo
echo "=== R20 SUMMARY lines ==="
grep -F "[R20 lldb] SUMMARY" "$SCAN_OUT" || echo "no summary lines found"
echo
echo "=== R20 LEAK lines (must be empty) ==="
grep -F "[R20 lldb] LEAK" "$SCAN_OUT" || echo "no leaks (good — identity_sk never on device)"
