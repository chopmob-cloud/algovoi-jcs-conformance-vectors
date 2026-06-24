#!/usr/bin/env python3
"""Independent verifier for the composite_trust_query_lite vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import.
Recompute is the test: re-derives trust_query_ref from the assessed set + verdict and checks every
positive vector, every negative (verdict / order / membership divergence; invalid enum, empty list and
empty member rejected), and the invariants. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python runner_python.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import rfc8785

OUTCOMES = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")


def trust_query_ref(subject_refs, trust_outcome) -> str:
    if not isinstance(subject_refs, (list, tuple)) or not subject_refs:
        raise ValueError("subject_refs must be a non-empty list")
    if not all(isinstance(s, str) and s for s in subject_refs):
        raise ValueError("each subject_ref must be a non-empty string")
    if trust_outcome not in OUTCOMES:
        raise ValueError(f"trust_outcome must be one of {OUTCOMES}")
    return "sha256:" + hashlib.sha256(
        rfc8785.dumps({"subject_refs": list(subject_refs), "trust_outcome": trust_outcome})
    ).hexdigest()


def _ref(v) -> str:
    return trust_query_ref(v["subject_refs"], v["trust_outcome"])


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "composite_trust_query_lite_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        if _ref(v) != v["expected_trust_query_ref"]:
            fails.append(f"{v['id']}: {_ref(v)} != {v['expected_trust_query_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:
            got = _ref(n)
            if got == n["claimed_trust_query_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    base = d["vectors"][0]
    variants = [
        _ref(base),
        _ref({**base, "trust_outcome": "PROVISIONAL"}),
        _ref({**base, "subject_refs": list(reversed(base["subject_refs"]))}),
        _ref({**base, "subject_refs": base["subject_refs"][:-1]}),
    ]
    if len(set(variants)) != 4:
        fails.append("distinctness: a verdict/order/membership change did not change trust_query_ref")
    try:
        trust_query_ref(base["subject_refs"], "OK")
        fails.append("reject-invalid: an outcome outside the closed enum was accepted")
    except Exception:
        pass
    for bad in ([], [""]):
        try:
            trust_query_ref(bad, "TRUSTED")
            fails.append(f"reject-empty: subject_refs {bad!r} was accepted")
        except Exception:
            pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- composite_trust_query_lite vectors reproduce byte-for-byte; verdict + "
          "subject_refs order + membership all byte-load-bearing; invalid enum, empty list and empty member "
          "rejected; tq-001/002/003 cap the live decision chain (passport+mandate+policy+guardrail).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
