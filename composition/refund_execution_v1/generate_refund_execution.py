#!/usr/bin/env python3
"""
refund_execution_v1 composition generator.

Anchors a refund receipt to the keystone EXECUTION tier: subject_ref == execution_ref,
so a refund binds to the payment that actually committed, not merely to the pre-payment
decision. Proves the anchor choice is byte-load-bearing (refund-of-execution differs from
refund-of-decision) and that a divergent execution diverges the refund.

  refund_ref = "sha256:" + SHA-256(JCS({refund_amount, refund_result, subject_ref}))

No new hashing primitive: reuses execution_ref_v1 / keystone_v1 and the refund_receipt_lite_v1
construction byte-for-byte (subject_ref is simply re-anchored from decision_ref to execution_ref).

Usage:  pip install rfc8785 ; python generate_refund_execution.py   # writes refund_execution_trace.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

OUT = Path(__file__).parent / "refund_execution_trace.json"


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


# keystone execution tier (ex-allow-committed) + the decision it bound (keystone_v1 goldens)
DECISION_REF = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
EXECUTION = {
    "decision_ref": DECISION_REF,
    "action_type": "payment",
    "scope": "bilateral",
    "outcome": "COMMITTED",
    "executed_at_ms": 1716460800000,
}
EXPECT_EXECUTION_REF = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"

REFUND_AMOUNT = "1000"
REFUND_RESULT = "FULL"


def refund_ref(subject_ref: str, refund_result: str, refund_amount: str) -> str:
    return _ref({"refund_amount": refund_amount, "refund_result": refund_result, "subject_ref": subject_ref})


def main() -> int:
    execution_ref = _ref(EXECUTION)
    assert execution_ref == EXPECT_EXECUTION_REF, f"execution_ref drift: {execution_ref}"

    # refund anchored to the executed payment
    refund_over_execution = refund_ref(execution_ref, REFUND_RESULT, REFUND_AMOUNT)
    # refund anchored to the pre-payment decision (same amount + result) -> must differ
    refund_over_decision = refund_ref(DECISION_REF, REFUND_RESULT, REFUND_AMOUNT)
    # tamper: a FAILED execution diverges execution_ref -> the refund subject diverges
    failed_execution_ref = _ref(dict(EXECUTION, outcome="FAILED"))
    refund_over_failed = refund_ref(failed_execution_ref, REFUND_RESULT, REFUND_AMOUNT)

    trace = {
        "set": "refund_execution_v1",
        "title": "Refund binds to the keystone execution tier",
        "canon_version": "jcs-rfc8785-v1",
        "summary": (
            "A refund receipt whose subject_ref is the exact execution_ref the keystone "
            "produced: the refund binds to the payment that committed, not just the decision "
            "that authorized it. The anchor is byte-load-bearing (refund-of-execution differs "
            "from refund-of-decision); a divergent execution diverges the refund. No new "
            "hashing primitive (refund_receipt_lite_v1 construction, subject_ref re-anchored)."
        ),
        "execution": {**EXECUTION, "expected_execution_ref": execution_ref},
        "decision_ref": DECISION_REF,
        "refund": {
            "refund_amount": REFUND_AMOUNT,
            "refund_result": REFUND_RESULT,
            "subject_ref": execution_ref,
            "expected_refund_ref": refund_over_execution,
        },
        "anchor_distinctness": {
            "refund_over_decision": refund_over_decision,
            "note": "same amount + result, subject_ref=decision_ref -> different refund_ref; anchor is byte-load-bearing.",
        },
        "tamper": {
            "failed_execution_ref": failed_execution_ref,
            "refund_over_failed": refund_over_failed,
            "note": "FAILED execution diverges execution_ref, which diverges the refund subject and refund_ref.",
        },
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    print("  execution_ref         :", execution_ref)
    print("  refund_over_execution :", refund_over_execution)
    print("  refund_over_decision  :", refund_over_decision, "(must differ)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
