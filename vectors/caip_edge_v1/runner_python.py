#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE beside this file.
"""
caip_edge_v1 runner (Python reference).

Independently re-implements the CAIP-2/10/19 validators (it does NOT import any AlgoVoi
package), decodes each vector's exact UTF-8 bytes from input_b64, and asserts the
validator's accept/reject verdict matches the vector's expectation.

The anchors are \\A and \\Z, never ^ and $: in Python $ also matches just before a
trailing newline, so ^...$ would wrongly accept "eip155:1\\n". See runner_python_naive.py
for a runnable demonstration of that divergence.

Usage:  python runner_python.py
"""
from __future__ import annotations
import base64
import json
import re
import sys
from pathlib import Path

VECTORS_FILE = Path(__file__).parent / "caip_edge_v1.json"

_CHAIN = r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}"
_RE = {
    "caip2": re.compile(rf"\A{_CHAIN}\Z"),
    "caip10": re.compile(rf"\A{_CHAIN}:[-.%a-zA-Z0-9]{{1,128}}\Z"),
    "caip19": re.compile(rf"\A{_CHAIN}/[-a-z0-9]{{3,8}}:[-.%a-zA-Z0-9]{{1,128}}(/[-.%a-zA-Z0-9]{{1,78}})?\Z"),
}


def valid(kind: str, s: str) -> bool:
    return bool(_RE[kind].match(s))


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    failures = []
    print("caip_edge_v1 runner (Python, independent \\A..\\Z reference)")
    print(f"vectors: {len(vectors)}")
    for v in vectors:
        s = base64.b64decode(v["input_b64"]).decode("utf-8")
        got = valid(v["kind"], s)
        want = v["expectation"] == "accept"
        if got != want:
            failures.append(f"{v['vector_id']}: got {'accept' if got else 'reject'}, want {v['expectation']}")
    if failures:
        for f in failures:
            print(f"  FAIL {f}")
        print(f"FAIL: {len(failures)}/{len(vectors)}")
        return 1
    print(f"PASS: {len(vectors)}/{len(vectors)} vectors match expectation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
