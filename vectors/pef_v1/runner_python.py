"""
pef_v1 runner (Python).

Validates the Payment Evidence Frame (PEF) vectors in pef_v1.json byte-for-byte
using the corpus canonicalizer (algovoi-substrate). For each vector it checks:

  - the preimage JCS canonical bytes  (expected_preimage_jcs_bytes_b64)
  - the receipt  JCS canonical bytes  (expected_receipt_jcs_bytes_b64)
  - the receipt content hash          (expected_receipt_hash)
  - the frame id = SHA-256 of the preimage JCS bytes (expected_frame_id)

No network, no issuer contact: SHA-256 + JCS (RFC 8785) only.

Usage:
    pip install algovoi-substrate
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import canonicalize

VECTORS_FILE = Path(__file__).parent / "pef_v1.json"


def _canon_bytes(obj) -> bytes:
    c = canonicalize(obj)
    return c.encode("utf-8") if isinstance(c, str) else c


def _sha256_prefixed(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    failures: list[str] = []

    print("pef_v1 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(vectors)}")
    print()

    for v in vectors:
        vid = v["vector_id"]
        pre_bytes = _canon_bytes(v["preimage"])
        rcpt_bytes = _canon_bytes(v["receipt"])

        checks = {
            "preimage_jcs": base64.b64encode(pre_bytes).decode("ascii")
            == v["expected_preimage_jcs_bytes_b64"],
            "receipt_jcs": base64.b64encode(rcpt_bytes).decode("ascii")
            == v["expected_receipt_jcs_bytes_b64"],
            "receipt_hash": _sha256_prefixed(rcpt_bytes) == v["expected_receipt_hash"],
            "frame_id": _sha256_prefixed(pre_bytes) == v["expected_frame_id"],
        }
        bad = [k for k, ok in checks.items() if not ok]
        if bad:
            failures.append(f"{vid}: {', '.join(bad)}")
            print(f"  {vid}: FAIL ({', '.join(bad)})")
        else:
            print(f"  {vid}: PASS  frame_id={v['expected_frame_id'][:23]}...")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: {len(vectors)} vectors validated byte-for-byte against algovoi-substrate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
