"""R6 lldb scan script — invoked via `command script import`."""
import lldb


def scan_regions(label):
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    err = lldb.SBError()
    needle = bytes([0xAA] * 32)
    matches = 0
    chunks_scanned = 0
    bytes_scanned = 0
    # Address-walk via GetMemoryRegionInfo iteration: covers darwin sparse
    # regions that GetMemoryRegions() may aggregate into multi-GB blocks.
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
        # Chunk-read in 1 MB strides; unbacked pages fail silently, backed
        # pages are scanned.
        stride = 1024 * 1024
        cur = base
        while cur < end:
            chunk_size = min(stride, end - cur)
            data = process.ReadMemory(cur, chunk_size, err)
            if err.Success() and data:
                chunks_scanned += 1
                bytes_scanned += len(data)
                idx = 0
                while True:
                    pos = data.find(needle, idx)
                    if pos == -1:
                        break
                    matches += 1
                    if matches <= 30:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        # Dump 16 bytes BEFORE the match (heap header) + 64 bytes match+after.
                        prefix_start = max(0, pos - 16)
                        prefix = data[prefix_start:pos]
                        match_zone = data[pos:pos + 64] if pos + 64 <= len(data) else data[pos:]
                        print('[R6 lldb] MATCH %s base=0x%x abs=0x%x name=%s' %
                              (label, base, abs_pos, name))
                        print('[R6 lldb]   prev16=%s  match+next=%s' %
                              (prefix.hex(), match_zone.hex()))
                    idx = pos + 32
            cur += chunk_size
        region = lldb.SBMemoryRegionInfo()
    print('[R6 lldb] SUMMARY %s: regions_walked=%d chunks_with_data=%d bytes_scanned=%d matches_32-byte-AA=%d' %
          (label, region_count, chunks_scanned, bytes_scanned, matches))


def scan_positive_control(debugger, command, result, internal_dict):
    scan_regions('POSITIVE_CONTROL')


def scan_before_keygen(debugger, command, result, internal_dict):
    scan_regions('BEFORE_KEYGEN')


def scan_after_keygen(debugger, command, result, internal_dict):
    scan_regions('AFTER_KEYGEN')


def scan_after_drop(debugger, command, result, internal_dict):
    scan_regions('AFTER_DROP')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f r6_lldb_script.scan_positive_control r6_scan_pos'
    )
    debugger.HandleCommand(
        'command script add -f r6_lldb_script.scan_before_keygen r6_scan_before'
    )
    debugger.HandleCommand(
        'command script add -f r6_lldb_script.scan_after_keygen r6_scan_after'
    )
    debugger.HandleCommand(
        'command script add -f r6_lldb_script.scan_after_drop r6_scan_drop'
    )
