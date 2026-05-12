#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-docs/security/kt-witness-deployment.csv}"

python3 - "$manifest" <<'PY'
import csv
import itertools
import re
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
required = [
    "witness_id",
    "public_key_hex",
    "organization",
    "admin_domain",
    "cloud_account",
    "signing_hsm",
    "release_repo",
    "monitoring_channel",
    "jurisdiction",
    "public_observation_url",
]
independence_fields = [
    "organization",
    "admin_domain",
    "cloud_account",
    "signing_hsm",
    "release_repo",
    "monitoring_channel",
    "jurisdiction",
]

if not manifest.exists():
    raise SystemExit(
        f"missing {manifest}; copy docs/security/kt-witness-deployment.example.csv "
        "to the real deployment path and replace every example value"
    )

with manifest.open(newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    if reader.fieldnames != required:
        raise SystemExit(
            f"{manifest} header mismatch; expected: {','.join(required)}"
        )
    rows = list(reader)

if len(rows) != 5:
    raise SystemExit(f"{manifest} must define exactly 5 witnesses, got {len(rows)}")

seen_ids = set()
seen_keys = set()
for index, row in enumerate(rows, start=2):
    for field in required:
        value = (row.get(field) or "").strip()
        if not value:
            raise SystemExit(f"{manifest}:{index}: empty {field}")
        if "example" in value.lower() or value.endswith(".invalid"):
            raise SystemExit(f"{manifest}:{index}: replace example value in {field}")
        row[field] = value

    witness_id = row["witness_id"]
    if witness_id in seen_ids:
        raise SystemExit(f"{manifest}:{index}: duplicate witness_id {witness_id}")
    seen_ids.add(witness_id)

    public_key = row["public_key_hex"]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", public_key):
        raise SystemExit(f"{manifest}:{index}: public_key_hex must be 32 bytes hex")
    if public_key in seen_keys:
        raise SystemExit(f"{manifest}:{index}: duplicate public_key_hex")
    seen_keys.add(public_key)

for combo in itertools.combinations(rows, 3):
    if all(len({row[field] for row in combo}) == 3 for field in independence_fields):
        print(f"KT witness deployment OK: independent threshold {[row['witness_id'] for row in combo]}")
        break
else:
    raise SystemExit(
        "no 3-witness threshold has distinct organization, admin_domain, "
        "cloud_account, signing_hsm, release_repo, monitoring_channel, and jurisdiction"
    )
PY
