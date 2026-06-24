#!/usr/bin/env python3
"""
cancellation_keystone_v1 composition generator.

The authority-side closure of the keystone, the mirror of refund_execution_v1: a cancellation
receipt whose mandate_ref is the exact mandate the keystone used, closing the authority BEFORE
execution (where refund closes the payment AFTER execution).

  cancellation_ref = "sha256:" + SHA-256(JCS({cancellation_reason, mandate_ref}))

No new hashing primitive: reuses cancellation_receipt_lite_v1 (published cn-001 golden over the
keystone mandate) and the keystone mandate_ref.

Usage:  pip install rfc8785 ; python generate_cancellation_keystone.py
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

OUT = Path(__file__).parent / "cancellation_keystone_trace.json"
MANDATE = "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"
EXECUTION = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"
EXPECT = {
    "cancel_user":     "sha256:9f2913d20750e1bc0c57002e372bc47af44e0ecf53752e05015f2707a24ec218",
    "cancel_merchant": "sha256:5de4ae35cee0b820a30eda323a6918ef0f96d2293e6e71f95efbda0442b679ba",
}

def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()
def _ref(o): return "sha256:" + _h(o)

def cancellation_ref(reason, mandate_ref):
    return _ref({"cancellation_reason": reason, "mandate_ref": mandate_ref})

def main() -> int:
    cancel_user = cancellation_ref("USER_REQUESTED", MANDATE)
    assert cancel_user == EXPECT["cancel_user"], cancel_user
    cancel_merchant = cancellation_ref("MERCHANT_REQUESTED", MANDATE)
    assert cancel_merchant == EXPECT["cancel_merchant"], cancel_merchant

    trace = {
        "set": "cancellation_keystone_v1",
        "title": "Cancellation closes the keystone authority (mirror of refund)",
        "canon_version": "jcs-rfc8785-v1",
        "summary": (
            "A cancellation receipt whose mandate_ref is the exact mandate the keystone used, closing "
            "the authority before execution. The authority-side mirror of refund_execution_v1 (which "
            "binds the execution after the payment commits). Reason is byte-load-bearing. Published "
            "cancellation_receipt_lite_v1 golden; no new hashing primitive."
        ),
        "mandate_ref": MANDATE,
        "execution_ref": EXECUTION,
        "cancellation": {"cancellation_reason": "USER_REQUESTED", "mandate_ref": MANDATE,
                         "expected_cancellation_ref": cancel_user,
                         "binds": "mandate_ref == keystone mandate (authority tier, pre-execution)"},
        "mirror": {"cancellation_binds": "mandate_ref (authority, pre-execution)",
                   "refund_binds": "execution_ref (payment, post-execution)"},
        "tamper": {"cancel_merchant": cancel_merchant,
                   "note": "MERCHANT_REQUESTED over the same mandate diverges cancellation_ref; the closed-enum reason is byte-load-bearing."},
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    print("  cancellation_ref (USER):", cancel_user, "(over keystone mandate_ref)")
    print("  cancel_merchant         :", cancel_merchant, "(must differ)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
