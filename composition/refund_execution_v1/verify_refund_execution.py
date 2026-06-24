#!/usr/bin/env python3
"""
refund_execution_v1 -- composition proof: a refund binds to the keystone execution tier.

Proves, offline from raw fields only (RFC 8785 JCS + SHA-256, no package import):
  1. execution_ref recomputes and equals the keystone golden.
  2. the refund's subject_ref IS that execution_ref (refund of the committed payment).
  3. refund_ref recomputes ({refund_amount, refund_result, subject_ref}; refund_receipt_lite_v1 shape).
  4. anchor distinctness: refund-over-execution != refund-over-decision (anchor is byte-load-bearing).
  5. tamper: a FAILED execution diverges execution_ref, which diverges the refund.

Run:  pip install rfc8785 ; python verify_refund_execution.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

TRACE = Path(__file__).parent / "refund_execution_trace.json"


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


def refund_ref(subject_ref: str, refund_result: str, refund_amount: str) -> str:
    return _ref({"refund_amount": refund_amount, "refund_result": refund_result, "subject_ref": subject_ref})


def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    ex = t["execution"]
    rf = t["refund"]
    ad = t["anchor_distinctness"]
    tw = t["tamper"]
    checks: list[tuple[bool, str, str]] = []

    execution_ref = _ref({
        "decision_ref": ex["decision_ref"], "action_type": ex["action_type"],
        "scope": ex["scope"], "outcome": ex["outcome"], "executed_at_ms": ex["executed_at_ms"],
    })
    checks.append((execution_ref == ex["expected_execution_ref"],
                   "execution_ref recomputes, equals the keystone golden", execution_ref))

    checks.append((rf["subject_ref"] == execution_ref,
                   "refund subject_ref IS the execution_ref (refund of the committed payment)", rf["subject_ref"]))

    rref = refund_ref(rf["subject_ref"], rf["refund_result"], rf["refund_amount"])
    checks.append((rref == rf["expected_refund_ref"],
                   "refund_ref recomputes (refund_receipt_lite_v1 shape)", rref))

    rref_dec = refund_ref(t["decision_ref"], rf["refund_result"], rf["refund_amount"])
    checks.append((rref_dec == ad["refund_over_decision"] and rref_dec != rref,
                   "anchor distinctness: refund-over-execution != refund-over-decision (anchor byte-load-bearing)", rref_dec))

    failed_ref = _ref({**{k: ex[k] for k in ("decision_ref", "action_type", "scope", "executed_at_ms")}, "outcome": "FAILED"})
    rref_failed = refund_ref(failed_ref, rf["refund_result"], rf["refund_amount"])
    tamper_ok = (failed_ref == tw["failed_execution_ref"] and failed_ref != execution_ref
                 and rref_failed == tw["refund_over_failed"] and rref_failed != rref)
    checks.append((tamper_ok,
                   "tamper: FAILED execution diverges execution_ref, which diverges the refund", "divergent"))

    print("=" * 74)
    print("REFUND EXECUTION -- composition proof (refund binds to the executed payment)")
    print("composed from raw fields only; no new hash, no package import")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- the refund binds to the payment that committed.")
    return 0 if npass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
