#!/usr/bin/env python3
"""Corpus runner (python) for trust_gate_v1 -- no algovoi import.

Reimplements _trust_gate_blocks from the rule alone and checks every vector's
expected allow/deny. Exit 0 only when all verdicts match.

    python runner_python.py trust_gate_v1.json
"""
from __future__ import annotations
import json
import os
import sys

DENY = {
    "block_untrusted": {"UNTRUSTED"},
    "require_trusted": {"UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"},
}


def blocks(mode, verdict) -> bool:
    if not mode or mode == "off":
        return False
    return verdict in DENY.get(mode, set())


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "trust_gate_v1.json")
    d = json.load(open(path, encoding="utf-8"))
    ok, fails = 0, []
    for v in d["vectors"]:
        got = blocks(v["mode"], v["verdict"])
        if got == v["expected_blocks"]:
            ok += 1
        else:
            fails.append(f"{v['id']}: got blocks={got} expected {v['expected_blocks']}")
    total = len(d["vectors"])
    for f in fails:
        print("  FAIL", f)
    if fails:
        print(f"FAIL ({len(fails)}/{total})")
        return 1
    print(f"PASS {ok}/{total} -- trust-gate deny table matches for every verdict x mode + fail-open edges.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
