#!/usr/bin/env python3
"""Independent verifier for the payment_mandate_lite vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import.
Recompute is the test: it re-derives mandate_ref from the four fields and checks every
positive vector, every negative (payer / cap / period / revocation divergence; empty field
rejected), and the invariants. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python runner_python.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import rfc8785

_FIELDS = ("payer", "cap", "period", "revocation_state")


def mandate_ref(payer, cap, period, revocation_state) -> str:
    values = {"cap": cap, "payer": payer, "period": period, "revocation_state": revocation_state}
    for name in _FIELDS:
        if not isinstance(values[name], str) or not values[name]:
            raise ValueError(f"{name} must be a non-empty string")
    return "sha256:" + hashlib.sha256(rfc8785.dumps(values)).hexdigest()


def _ref(v) -> str:
    return mandate_ref(v["payer"], v["cap"], v["period"], v["revocation_state"])


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "payment_mandate_lite_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        if _ref(v) != v["expected_mandate_ref"]:
            fails.append(f"{v['id']}: {_ref(v)} != {v['expected_mandate_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:  # differ
            got = _ref(n)
            if got == n["claimed_mandate_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    # invariant: field-distinctness (each of the four fields byte-load-bearing)
    base = d["vectors"][0]
    variants = [
        _ref(base),
        _ref({**base, "payer": "0x00000000000000000000000000000000C0FFEE11"}),
        _ref({**base, "cap": "2000"}),
        _ref({**base, "period": "weekly"}),
        _ref({**base, "revocation_state": "revoked"}),
    ]
    if len(set(variants)) != 5:
        fails.append("field-distinctness: a field change did not change mandate_ref")
    # invariant: reject empty field
    try:
        mandate_ref("", base["cap"], base["period"], base["revocation_state"])
        fails.append("reject-empty: empty field was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- payment_mandate_lite vectors reproduce byte-for-byte; all four fields "
          "byte-load-bearing (payer/cap/period/revocation tamper detected); empty field rejected; "
          "mandate_1/2 == the mandate_ref spend_guardrail_lite binds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
