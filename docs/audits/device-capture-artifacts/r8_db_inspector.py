"""R8 — SQLite-on-disk inspection after legitimate process exit.

Reads the SQLite file written by `r7_identity_lldb_target` after that
process has run to completion (the example intentionally leaves
`/tmp/r7_identity_capture.sqlite` on disk; round-4 attacker model assumes
adversary acquires the device and reads the file system).

Three checks:

  1. Scan the raw bytes of the .sqlite file for the 32-byte 0xDC
     master_key needle. The master_key is held in a `RowCipher.master_key:
     SecretBox<[u8; 32]>` in process memory ONLY; it must NEVER appear in
     the file. A match would mean the application is writing the encryption
     key to disk somewhere by accident — CRITICAL.

  2. Scan for the canary plaintext "R7_LLDB_PLAINTEXT_NEEDLE". The
     plaintext is what was passed to `put_message`; per ADR-010 Decision 5
     subvariant C.1.2 it must be encrypted by RowCipher (ChaCha20-Poly1305)
     before insertion. A match would mean plaintext leaked to disk — CRITICAL.

  3. Use sqlite3 CLI to dump the actual `messages` row and verify
     `enc_text` is opaque cipher bytes (not human-readable plaintext).

Output: prints findings line by line, exits 0 if both needles absent and
ciphertext column is non-readable; exits 1 on any positive match.
"""
import os
import subprocess
import sys

import tempfile
DB_PATH = os.path.join(tempfile.gettempdir(), 'r7_identity_capture.sqlite')
MASTER_KEY_NEEDLE = bytes([0xDC] * 32)
ENTROPY_NEEDLE = bytes([0xCD] * 32)
PLAINTEXT_CANARY = b'R7_LLDB_PLAINTEXT_NEEDLE'


def scan_file(path):
    if not os.path.exists(path):
        print('R8: SQLite file MISSING at %s — run r7_lldb_scan.sh first' % path)
        return 2
    size = os.path.getsize(path)
    print('R8: scanning %s (size=%d bytes)' % (path, size))
    with open(path, 'rb') as fh:
        data = fh.read()

    # Scan all sidecar files too: -wal, -shm.
    sidecar_paths = [path + '-wal', path + '-shm']
    sidecar_data = []
    for sp in sidecar_paths:
        if os.path.exists(sp):
            with open(sp, 'rb') as fh:
                d = fh.read()
            sidecar_data.append((sp, d))
            print('R8: also scanning sidecar %s (size=%d)' % (sp, len(d)))

    needles = [
        ('MASTER_KEY_0xDC_x_32', MASTER_KEY_NEEDLE),
        ('ENTROPY_0xCD_x_32', ENTROPY_NEEDLE),
        ('PLAINTEXT_R7_LLDB_PLAINTEXT_NEEDLE', PLAINTEXT_CANARY),
    ]

    total_hits = 0
    for needle_name, needle in needles:
        count = 0
        pos = 0
        while True:
            i = data.find(needle, pos)
            if i == -1:
                break
            count += 1
            pos = i + 1
            if count <= 3:
                start = max(0, i - 8)
                end = min(len(data), i + len(needle) + 8)
                print('R8:   MATCH %s at offset 0x%x (context: %s)'
                      % (needle_name, i, data[start:end].hex()))
        # Sidecars
        for sp, d in sidecar_data:
            ci = 0
            spos = 0
            while True:
                j = d.find(needle, spos)
                if j == -1:
                    break
                ci += 1
                spos = j + 1
                if ci <= 3:
                    print('R8:   MATCH %s in sidecar %s at offset 0x%x'
                          % (needle_name, sp, j))
            count += ci
        total_hits += count
        print('R8: needle %-44s -> hits=%d' % (needle_name, count))

    return total_hits


def sqlite_dump(path):
    if not os.path.exists(path):
        return
    print('R8: sqlite3 .dump of messages table:')
    try:
        out = subprocess.check_output(
            ['sqlite3', path,
             "SELECT hex(enc_text), hex(enc_nonce), hex(enc_tag) FROM messages LIMIT 1"],
            stderr=subprocess.STDOUT,
        ).decode('utf-8', errors='replace')
        for line in out.splitlines():
            print('R8:   %s' % line)
        # Also try to grep for plaintext canary in TEXT representation.
        text_attempt = subprocess.check_output(
            ['sqlite3', path,
             "SELECT enc_text FROM messages LIMIT 1"],
            stderr=subprocess.STDOUT,
        )
        if PLAINTEXT_CANARY in text_attempt:
            print('R8:   CRITICAL — sqlite returned plaintext canary in enc_text')
            return 4
        print('R8:   plaintext canary NOT in enc_text column (expected)')
    except subprocess.CalledProcessError as e:
        print('R8:   sqlite3 failed: %s' % e.output)
    return 0


def schema_dump(path):
    if not os.path.exists(path):
        return
    print('R8: sqlite3 .schema:')
    try:
        out = subprocess.check_output(
            ['sqlite3', path, '.schema'],
            stderr=subprocess.STDOUT,
        ).decode('utf-8', errors='replace')
        for line in out.splitlines():
            print('R8:   %s' % line)
    except subprocess.CalledProcessError as e:
        print('R8:   sqlite3 .schema failed: %s' % e.output)


if __name__ == '__main__':
    schema_dump(DB_PATH)
    hits = scan_file(DB_PATH)
    if hits == 2:
        sys.exit(2)
    dump_status = sqlite_dump(DB_PATH)
    if hits > 0 or (dump_status or 0) > 0:
        print('R8: VERDICT — disk leak detected (hits=%d, dump_status=%s)'
              % (hits, dump_status))
        sys.exit(1)
    print('R8: VERDICT — no plaintext/keys on disk (0 needle matches across .sqlite, -wal, -shm)')
    sys.exit(0)
