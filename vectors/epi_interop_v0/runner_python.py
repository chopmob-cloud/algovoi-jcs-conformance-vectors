"""
epi_interop_v0 runner (Python).

Recomputes frame_id and JCS bytes for every vector in epi_interop_v0.json
straight from the input, with the same RFC 8785 implementation that backs
the AlgoVoi conformance corpus, and asserts they match the published values.

Usage:
    pip install rfc8785>=0.1.2
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "epi_interop_v0.json"), encoding="utf-8"))
    failures = 0
    for v in doc["vectors"]:
        jcs = rfc8785.dumps(v["input"])
        b64 = base64.b64encode(jcs).decode("ascii")
        frame_id = "sha256:" + hashlib.sha256(jcs).hexdigest()
        ok = b64 == v["expected_jcs_bytes_b64"] and frame_id == v["frame_id"]
        print(("PASS" if ok else "FAIL"), v["id"], v["source_name"], v["frame_id"])
        if not ok:
            failures += 1
    print(f"\n{len(doc['vectors']) - failures}/{len(doc['vectors'])} vectors reproduce")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
