"""R20 lldb scan script — round-6 distributed identity zero-trace audit.

Run within lldb via `command script import`.

Searches process memory at named breakpoints for two needles:

- **identity_sk needle (negative claim)** — 32 × 0xDB. Under round-6 there is
  no identity_sk on device (FROST DKG keeps it sharded across 5 servers,
  client receives only public material). Expected: **0 hits**.
- **identity_pk needle (positive control)** — 32 × 0xCA. The 32-byte Ed25519
  public key. By design IS on device. Expected: ≥1 hit.

Stride-read methodology per round-5 R7: 1 MB chunks of every writable memory
region; `data.find(needle, idx)` per 32-byte slice. Found-count is the
empirical metric.
"""
import lldb


IDENTITY_SK_NEEDLE = bytes([0xDB] * 32)
IDENTITY_PK_NEEDLE = bytes([0xCA] * 32)


def scan_all(label):
    """Single-pass: walks every writable region once and counts hits for
    both needles.
    """
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    err = lldb.SBError()
    sk_hits = 0
    pk_hits = 0
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
                # identity_sk needle (must be 0 hits — negative claim).
                idx = 0
                while True:
                    pos = data.find(IDENTITY_SK_NEEDLE, idx)
                    if pos == -1:
                        break
                    sk_hits += 1
                    if sk_hits <= 5:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        prefix = data[max(0, pos - 16):pos]
                        match_zone = (
                            data[pos:pos + 48] if pos + 48 <= len(data) else data[pos:]
                        )
                        print(
                            '[R20 lldb] LEAK %s/IDENTITY_SK base=0x%x abs=0x%x name=%s'
                            % (label, base, abs_pos, name)
                        )
                        print(
                            '[R20 lldb]   prev16=%s  match+next=%s'
                            % (prefix.hex(), match_zone.hex())
                        )
                    idx = pos + 32
                # identity_pk needle (positive control).
                idx = 0
                while True:
                    pos = data.find(IDENTITY_PK_NEEDLE, idx)
                    if pos == -1:
                        break
                    pk_hits += 1
                    if pk_hits <= 5:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        prefix = data[max(0, pos - 16):pos]
                        match_zone = (
                            data[pos:pos + 48] if pos + 48 <= len(data) else data[pos:]
                        )
                        print(
                            '[R20 lldb] POS_CTRL %s/IDENTITY_PK base=0x%x abs=0x%x name=%s'
                            % (label, base, abs_pos, name)
                        )
                        print(
                            '[R20 lldb]   prev16=%s  match+next=%s'
                            % (prefix.hex(), match_zone.hex())
                        )
                    idx = pos + 32
            cur += chunk_size
        region = lldb.SBMemoryRegionInfo()
    print(
        '[R20 lldb] SUMMARY %s: regions=%d chunks=%d bytes=%d sk_hits=%d pk_hits=%d'
        % (label, region_count, chunks_scanned, bytes_scanned, sk_hits, pk_hits)
    )


def scan_before(debugger, command, result, internal_dict):
    scan_all('BEFORE_BOOTSTRAP')


def scan_after_bootstrap(debugger, command, result, internal_dict):
    scan_all('AFTER_BOOTSTRAP')


def scan_after_unlock(debugger, command, result, internal_dict):
    scan_all('AFTER_UNLOCK')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f r20_lldb_script.scan_before r20_scan_before'
    )
    debugger.HandleCommand(
        'command script add -f r20_lldb_script.scan_after_bootstrap r20_scan_after_bootstrap'
    )
    debugger.HandleCommand(
        'command script add -f r20_lldb_script.scan_after_unlock r20_scan_after_unlock'
    )
