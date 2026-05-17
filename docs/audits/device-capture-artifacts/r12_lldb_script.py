"""R12 lldb scan script — search for the dynamic ratchet application_secret.

The 32-byte needle is the HKDF-SHA512 derived application_secret written
to `/tmp/.../r12_needle.bin` by the target binary at startup. We read it
once at module import time.
"""
import lldb
import os
import tempfile

_NEEDLE_PATH = os.path.join(tempfile.gettempdir(), 'r12_needle.bin')
if os.path.exists(_NEEDLE_PATH):
    with open(_NEEDLE_PATH, 'rb') as fh:
        APP_SECRET_NEEDLE = fh.read()
    assert len(APP_SECRET_NEEDLE) == 32, 'needle must be 32 bytes'
else:
    APP_SECRET_NEEDLE = None  # will fail at scan time


def _scan(label):
    if APP_SECRET_NEEDLE is None:
        print('[R12 lldb] needle file MISSING at %s - run target first' % _NEEDLE_PATH)
        return
    needle = APP_SECRET_NEEDLE
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    err = lldb.SBError()
    matches = 0
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
                idx = 0
                while True:
                    pos = data.find(needle, idx)
                    if pos == -1:
                        break
                    matches += 1
                    if matches <= 6:
                        name = region.GetName() or ''
                        abs_pos = cur + pos
                        prefix = data[max(0, pos - 16):pos]
                        match_zone = data[pos:pos + 32]
                        print('[R12 lldb] MATCH %s base=0x%x abs=0x%x name=%s' %
                              (label, base, abs_pos, name))
                        print('[R12 lldb]   prev16=%s  match=%s' %
                              (prefix.hex(), match_zone.hex()))
                    idx = pos + 32
            cur += chunk_size
        region = lldb.SBMemoryRegionInfo()
    print('[R12 lldb] SUMMARY %s: regions=%d chunks=%d bytes=%d app_secret_hits=%d' %
          (label, region_count, chunks_scanned, bytes_scanned, matches))


def scan_live(debugger, command, result, internal_dict):
    _scan('SESSION_LIVE')


def scan_drop(debugger, command, result, internal_dict):
    _scan('AFTER_DROP')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f r12_lldb_script.scan_live r12_scan_live')
    debugger.HandleCommand('command script add -f r12_lldb_script.scan_drop r12_scan_drop')
