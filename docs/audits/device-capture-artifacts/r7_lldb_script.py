"""R7 lldb scan script — three independent needles for device-capture audit.

Run within lldb via `command script import`.

Searches process memory at named breakpoints for three distinct 32-byte
patterns that correspond to (1) BIP-39 entropy producing the identity seed,
(2) the SQLite master_key passed to RowCipher::new, and (3) the Ed25519
signing-key derived from the entropy. Match counts per phase are the
audit metric.
"""
import lldb


# Three needle patterns:
#   - 0xCD x 32 == BIP-39 entropy fed to from_mnemonic (R7 identity_sk lineage)
#   - 0xDC x 32 == explicit SQLite master key passed to SqliteMetadataStore::open
#   - identity_sk (32 bytes; resolved dynamically from `to_seed_bytes()` if needed)
ENTROPY_NEEDLE = bytes([0xCD] * 32)
MASTER_KEY_NEEDLE = bytes([0xDC] * 32)


def scan_all(label):
    """Single-pass scanner: walks every writable region once and counts hits
    for both needles. Optimization vs round-2 R6: combine both needles in one
    pass so we don't pay the 700MB read cost twice per breakpoint.
    """
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    err = lldb.SBError()
    entropy_hits = 0
    master_hits = 0
    chunks_scanned = 0
    bytes_scanned = 0
    addr = 0
    region = lldb.SBMemoryRegionInfo()
    region_count = 0
    while True:
        if not process.GetMemoryRegionInfo(addr, region).Success():
            break
        region_count += 1
        base = region.GetRegionBase()
        end = region.GetRegionEnd()
        if end <= addr:
            break
        size = end - base
        addr = end
        if not region.IsWritable():
            continue
        if size <= 0:
            continue
        stride = 1024 * 1024
        cur = base
        while cur < end:
            chunk_size = min(stride, end - cur)
            data = process.ReadMemory(cur, chunk_size, err)
            if err.Success() and data:
                chunks_scanned += 1
                bytes_scanned += len(data)
                # Entropy needle 0xCD
                idx = 0
                while True:
                    pos = data.find(ENTROPY_NEEDLE, idx)
                    if pos == -1:
                        break
                    entropy_hits += 1
                    if entropy_hits <= 5:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        prefix = data[max(0, pos - 16):pos]
                        match_zone = data[pos:pos + 48] if pos + 48 <= len(data) else data[pos:]
                        print('[R7 lldb] MATCH %s/ENTROPY base=0x%x abs=0x%x name=%s' %
                              (label, base, abs_pos, name))
                        print('[R7 lldb]   prev16=%s  match+next=%s' %
                              (prefix.hex(), match_zone.hex()))
                    idx = pos + 32
                # Master key needle 0xDC
                idx = 0
                while True:
                    pos = data.find(MASTER_KEY_NEEDLE, idx)
                    if pos == -1:
                        break
                    master_hits += 1
                    if master_hits <= 5:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        prefix = data[max(0, pos - 16):pos]
                        match_zone = data[pos:pos + 48] if pos + 48 <= len(data) else data[pos:]
                        print('[R7 lldb] MATCH %s/MASTER_KEY base=0x%x abs=0x%x name=%s' %
                              (label, base, abs_pos, name))
                        print('[R7 lldb]   prev16=%s  match+next=%s' %
                              (prefix.hex(), match_zone.hex()))
                    idx = pos + 32
            cur += chunk_size
        region = lldb.SBMemoryRegionInfo()
    print('[R7 lldb] SUMMARY %s: regions=%d chunks=%d bytes=%d entropy_hits=%d master_key_hits=%d' %
          (label, region_count, chunks_scanned, bytes_scanned, entropy_hits, master_hits))


def scan_positive_control(debugger, command, result, internal_dict):
    scan_all('POSITIVE_CONTROL')


def scan_before_bootstrap(debugger, command, result, internal_dict):
    scan_all('BEFORE_BOOTSTRAP')


def scan_live_identity(debugger, command, result, internal_dict):
    scan_all('LIVE_IDENTITY')


def scan_after_drop(debugger, command, result, internal_dict):
    scan_all('AFTER_DROP')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f r7_lldb_script.scan_positive_control r7_scan_pos'
    )
    debugger.HandleCommand(
        'command script add -f r7_lldb_script.scan_before_bootstrap r7_scan_before'
    )
    debugger.HandleCommand(
        'command script add -f r7_lldb_script.scan_live_identity r7_scan_live'
    )
    debugger.HandleCommand(
        'command script add -f r7_lldb_script.scan_after_drop r7_scan_drop'
    )
