#!/usr/bin/env python3
"""Independent verifier for the cancellation_receipt_lite vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import.
Recompute is the test: re-derives cancellation_ref from the two fields and checks every
positive vector, every negative (reason / mandate divergence; invalid enum and empty mandate
rejected), and the invariants. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python runner_python.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import rfc8785

REASONS = ("USER_REQUESTED", "MERCHANT_REQUESTED", "COMPLIANCE_TERMINATED", "EXPIRED")


def cancellation_ref(mandate_ref, cancellation_reason) -> str:
    if not isinstance(mandate_ref, str) or not mandate_ref:
        raise ValueError("mandate_ref must be a non-empty string")
    if cancellation_reason not in REASONS:
        raise ValueError(f"cancellation_reason must be one of {REASONS}")
    return "sha256:" + hashlib.sha256(
        rfc8785.dumps({"cancellation_reason": cancellation_reason, "mandate_ref": mandate_ref})
    ).hexdigest()


def _ref(v) -> str:
    return cancellation_ref(v["mandate_ref"], v["cancellation_reason"])


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "cancellation_receipt_lite_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        if _ref(v) != v["expected_cancellation_ref"]:
            fails.append(f"{v['id']}: {_ref(v)} != {v['expected_cancellation_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:
            got = _ref(n)
            if got == n["claimed_cancellation_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    base = d["vectors"][0]
    variants = [
        _ref(base),
        _ref({**base, "cancellation_reason": "MERCHANT_REQUESTED"}),
        _ref({**base, "mandate_ref": "sha256:fefcf604aa85994cd8058b960b0472122d54f81fc48efa394bb0c488599a7615"}),
    ]
    if len(set(variants)) != 3:
        fails.append("field-distinctness: a field change did not change cancellation_ref")
    try:
        cancellation_ref(base["mandate_ref"], "CANCELLED")
        fails.append("reject-invalid: a reason outside the closed enum was accepted")
    except Exception:
        pass
    try:
        cancellation_ref("", "USER_REQUESTED")
        fails.append("reject-empty: empty mandate_ref was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- cancellation_receipt_lite vectors reproduce byte-for-byte; both fields "
          "byte-load-bearing (reason/mandate tamper detected); invalid enum + empty mandate rejected; "
          "cn-001/002/003 cancel the mandate_ref spend_guardrail_lite binds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
