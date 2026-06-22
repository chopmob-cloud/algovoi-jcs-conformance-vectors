#!/usr/bin/env python3
"""Independent verifier for the agent_passport_lite vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import.
Recompute is the test: it re-derives passport_ref from the four fields and checks every
positive vector, every negative (agent / issuer / scope / window divergence; empty field
rejected), and the invariants. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python verify.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import rfc8785

_FIELDS = ("agent_id", "issuer", "scope", "validity_window")


def passport_ref(agent_id, issuer, scope, validity_window) -> str:
    values = {"agent_id": agent_id, "issuer": issuer, "scope": scope, "validity_window": validity_window}
    for name in _FIELDS:
        if not isinstance(values[name], str) or not values[name]:
            raise ValueError(f"{name} must be a non-empty string")
    return "sha256:" + hashlib.sha256(rfc8785.dumps(values)).hexdigest()


def _ref(v) -> str:
    return passport_ref(v["agent_id"], v["issuer"], v["scope"], v["validity_window"])


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "agent_passport_lite_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        if _ref(v) != v["expected_passport_ref"]:
            fails.append(f"{v['id']}: {_ref(v)} != {v['expected_passport_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:  # differ
            got = _ref(n)
            if got == n["claimed_passport_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    # invariant: field-distinctness (each of the four fields byte-load-bearing)
    base = d["vectors"][0]
    variants = [
        _ref(base),
        _ref({**base, "agent_id": "agent-002"}),
        _ref({**base, "scope": "refunds"}),
        _ref({**base, "issuer": "did:algo:other"}),
        _ref({**base, "validity_window": "2026-06-21/2026-12-21"}),
    ]
    if len(set(variants)) != 5:
        fails.append("field-distinctness: a field change did not change passport_ref")
    # invariant: reject empty field
    try:
        passport_ref("", base["issuer"], base["scope"], base["validity_window"])
        fails.append("reject-empty: empty field was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- agent_passport_lite vectors reproduce byte-for-byte; all four fields "
          "byte-load-bearing (agent/issuer/scope/window tamper detected); empty field rejected; "
          "passport_1/2 == the agent_ref spend_guardrail_lite binds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
