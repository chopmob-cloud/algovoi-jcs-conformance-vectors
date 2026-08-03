#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
"""
jcs_edge_v1 runner (Python / rfc8785 reference).

For every vector: recompute base64(JCS(preimage)) and sha256(JCS(preimage)) and
compare byte-for-byte against expected_jcs_bytes_b64 and expected_sha256. Then
check the two pair invariants (1.0 == 1; the non-BMP key order is UTF-16, proven
by the emoji key preceding the U+FFFF key in the canonical bytes).

Usage:
    pip install rfc8785
    python runner_python.py
"""
from __future__ import annotations
import base64, hashlib, json, sys
from pathlib import Path
import rfc8785

VECTORS_FILE = Path(__file__).parent / "jcs_edge_v1.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}
    failures: list[str] = []

    print("jcs_edge_v1 runner (Python / rfc8785)")
    print(f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}")

    for vid, v in vectors.items():
        b = rfc8785.dumps(v["preimage"])
        if base64.b64encode(b).decode("ascii") != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            continue
        if hashlib.sha256(b).hexdigest() != v["expected_sha256"]:
            failures.append(f"{vid}: SHA-256 mismatch")
        # Validate EVERY declared hash, incl. the expected_content_hash alias, so a
        # forgery of any load-bearing field is caught (not just expected_sha256).
        if "expected_content_hash" in v and hashlib.sha256(b).hexdigest() != v["expected_content_hash"]:
            failures.append(f"{vid}: content-hash mismatch")

    # pair invariants
    for pi in data["pair_invariants"]:
        if pi["relation"] == "equal_sha256":
            if vectors[pi["a"]]["expected_sha256"] != vectors[pi["b"]]["expected_sha256"]:
                failures.append(f"{pi['name']}: sha256 not equal")
        elif pi["relation"] == "emoji_key_precedes_ffff":
            cb = base64.b64decode(vectors[pi["vector"]]["expected_jcs_bytes_b64"])
            if cb.index(b"\xf0\x9f\x98\x80") >= cb.index(b"\xef\xbf\xbf"):
                failures.append(f"{pi['name']}: emoji key not before U+FFFF")

    if failures:
        for f in failures:
            print(f"  FAIL {f}")
        print(f"FAIL: {len(failures)} failures")
        return 1
    print(f"PASS: {len(vectors)} vectors + {len(data['pair_invariants'])} pair invariants byte-for-byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
