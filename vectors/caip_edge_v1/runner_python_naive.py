#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE beside this file.
"""
caip_edge_v1 NAIVE Python runner: the Python anchor trap, demonstrated and checked.

Identical to runner_python.py except the regexes anchor with ^ and $ instead of \\A and
\\Z. Because Python's $ (no MULTILINE) also matches just before a trailing newline, this
validator ACCEPTS the single-trailing-\\n vectors that MUST be rejected, and so diverges
from both the correct Python reference and the JavaScript runner. This runner is EXPECTED
to diverge; the divergence is the finding.

It self-checks two things and exits 0 only if both hold:
  1. its live ^...$ verdict reproduces the `naive_py_caret_dollar` field baked into each
     vector at generation time (so the recorded prediction is reproducible), and
  2. every divergence from the true `expectation` is an OVER-ACCEPTANCE (it never wrongly
     rejects a valid identifier), and the diverging set equals the recorded count.

Usage:  python runner_python_naive.py
"""
from __future__ import annotations
import base64
import json
import re
import sys
from pathlib import Path

VECTORS_FILE = Path(__file__).parent / "caip_edge_v1.json"

_CHAIN = r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}"
_RE = {  # NAIVE: ^...$ instead of \A..\Z
    "caip2": re.compile(rf"^{_CHAIN}$"),
    "caip10": re.compile(rf"^{_CHAIN}:[-.%a-zA-Z0-9]{{1,128}}$"),
    "caip19": re.compile(rf"^{_CHAIN}/[-a-z0-9]{{3,8}}:[-.%a-zA-Z0-9]{{1,128}}(/[-.%a-zA-Z0-9]{{1,78}})?$"),
}


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    diverged, mispredicted, under_rejections = [], [], []
    for v in data["vectors"]:
        s = base64.b64decode(v["input_b64"]).decode("utf-8")
        got = "accept" if _RE[v["kind"]].match(s) else "reject"
        if got != v["naive_py_caret_dollar"]:
            mispredicted.append(v["vector_id"])
        if got != v["expectation"]:
            diverged.append(v["vector_id"])
            if v["expectation"] == "accept":      # naive wrongly rejected a valid id
                under_rejections.append(v["vector_id"])

    print("caip_edge_v1 NAIVE Python runner (^...$ -- expected to over-accept)")
    print(f"vectors: {len(data['vectors'])}, diverged: {len(diverged)}")
    for vid in diverged:
        print(f"  DIVERGE {vid}")

    fail = False
    if mispredicted:
        print(f"FAIL: recorded naive_py_caret_dollar not reproduced for {mispredicted}")
        fail = True
    if under_rejections:
        print(f"FAIL: naive validator UNDER-rejected valid ids {under_rejections}")
        fail = True
    expected = data["counts"]["naive_py_caret_dollar_divergences"]
    if len(diverged) != expected:
        print(f"FAIL: expected {expected} divergences, got {len(diverged)}")
        fail = True
    if fail:
        return 1
    print(f"PASS: {len(diverged)} over-acceptances (all trailing-newline), 0 under-rejections, "
          f"prediction reproduced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
