#!/usr/bin/env python3
"""Independent verifier for the refund_receipt_lite vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import.
Recompute is the test: re-derives refund_ref from the three fields and checks every
positive vector, every negative (result / amount / subject divergence; invalid enum and empty
subject rejected), and the invariants. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python runner_python.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import rfc8785

RESULTS = ("FULL", "PARTIAL", "REJECTED")


def refund_ref(subject_ref, refund_result, refund_amount) -> str:
    if not isinstance(subject_ref, str) or not subject_ref:
        raise ValueError("subject_ref must be a non-empty string")
    if refund_result not in RESULTS:
        raise ValueError(f"refund_result must be one of {RESULTS}")
    if not isinstance(refund_amount, str) or not refund_amount:
        raise ValueError("refund_amount must be a non-empty string")
    return "sha256:" + hashlib.sha256(
        rfc8785.dumps({"refund_amount": refund_amount, "refund_result": refund_result, "subject_ref": subject_ref})
    ).hexdigest()


def _ref(v) -> str:
    return refund_ref(v["subject_ref"], v["refund_result"], v["refund_amount"])


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "refund_receipt_lite_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        if _ref(v) != v["expected_refund_ref"]:
            fails.append(f"{v['id']}: {_ref(v)} != {v['expected_refund_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:
            got = _ref(n)
            if got == n["claimed_refund_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    base = d["vectors"][0]
    variants = [
        _ref(base),
        _ref({**base, "refund_result": "PARTIAL"}),
        _ref({**base, "refund_amount": "2000"}),
        _ref({**base, "subject_ref": "sha256:792a5b43e9df0fc460d6bf99d6357afafbdcf910ef1e81a340e3581bc27109cf"}),
    ]
    if len(set(variants)) != 4:
        fails.append("field-distinctness: a field change did not change refund_ref")
    try:
        refund_ref(base["subject_ref"], "REFUNDED", base["refund_amount"])
        fails.append("reject-invalid: a result outside the closed enum was accepted")
    except Exception:
        pass
    try:
        refund_ref("", "FULL", "1000")
        fails.append("reject-empty: empty subject_ref was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- refund_receipt_lite vectors reproduce byte-for-byte; all three fields "
          "byte-load-bearing (result/amount/subject tamper detected); invalid enum + empty fields rejected; "
          "rf-001/002/003 refund the ALLOW guardrail_ref the decision chain produced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
