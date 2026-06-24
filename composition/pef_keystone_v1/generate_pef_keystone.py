#!/usr/bin/env python3
"""
pef_keystone_v1 composition generator.

Proves PEF (Payment Evidence Frame) is the signed-transport layer over the
keystone: a PEF frame wraps a keystone record (the settlement-bound execution
accountability object) and pins it, so the frame_id commits to the exact
keystone position.

  receipt        = the execution_binding record {execution_ref, settlement_ref,
                   retention_chain_ref, binding_ref}  (a keystone fact)
  receipt_hash   = "sha256:" + SHA-256(JCS(receipt))         (PEF pins the payload)
  frame_id       = "sha256:" + SHA-256(JCS(preimage))        (PEF commits to the frame)

No new hashing primitive: reuses execution_ref_v1 / keystone_v1, settlement_binding_v1
(execution_binding), and the pef_v1 frame_id construction byte-for-byte. The only PEF
schema change is an additive claim_type value ("payment_execution"); the preimage shape
is identical to pef_v1.

Usage:  pip install rfc8785 ; python generate_pef_keystone.py   # writes pef_keystone_trace.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

OUT = Path(__file__).parent / "pef_keystone_trace.json"
URN = "urn:x402:canonicalisation:jcs-rfc8785-v1"


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


# ---- keystone execution tier (ex-allow-committed; keystone_v1 golden) ----------
EXECUTION = {
    "decision_ref": "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",
    "action_type": "payment",
    "scope": "bilateral",
    "outcome": "COMMITTED",
    "executed_at_ms": 1716460800000,
}
EXPECT_EXECUTION_REF = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"
# settlement_binding_v1 golden:
EXPECT_BINDING_REF = "sha256:820954e57aa9f9cba662c14bbf37d79ae90d0d3e05d905d228ee1b91a58286b8"


def settlement_receipt(settled_payment_ref: str) -> dict:
    return {
        "canon_version": "jcs-rfc8785-v1",
        "jurisdiction_flags": ["UK", "EU"],
        "settled_payment_ref": settled_payment_ref,
        "settlement_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
        "settlement_chain": "ethereum:8453",
        "settlement_provider_did": "did:example:settlement-provider-1",
        "settlement_result": "SETTLED",
        "settlement_timestamp_ms": 1716494400000,
    }


def main() -> int:
    # rebuild the settlement-bound keystone fact (same as settlement_binding_v1)
    execution_ref = _ref(EXECUTION)
    assert execution_ref == EXPECT_EXECUTION_REF, f"execution_ref drift: {execution_ref}"
    receipt_sa = settlement_receipt(execution_ref)
    settlement_ref = "sha256:" + _h(receipt_sa)
    retention_chain_ref = _ref({"content_hash": _h(receipt_sa), "prev_hash": "0" * 64, "row_number": 1})
    binding_ref = _ref({
        "execution_ref": execution_ref,
        "settlement_ref": settlement_ref,
        "retention_chain_ref": retention_chain_ref,
    })
    assert binding_ref == EXPECT_BINDING_REF, f"binding_ref drift: {binding_ref}"

    # the keystone record carried inside the PEF frame
    keystone_receipt = {
        "binding_ref": binding_ref,
        "canon_version": URN,
        "execution_ref": execution_ref,
        "retention_chain_ref": retention_chain_ref,
        "settlement_ref": settlement_ref,
    }
    receipt_hash = "sha256:" + _h(keystone_receipt)

    # the PEF frame preimage (pef_v1 shape; claim_type extended to payment_execution)
    preimage = {
        "canon_version": URN,
        "claim_type": "payment_execution",
        "frame_provider_did": "did:web:api.algovoi.co.uk",
        "frame_timestamp_ms": 1748534600000,
        "pef_version": "1",
        "receipt": keystone_receipt,
        "receipt_format": "execution-binding-v1",
        "receipt_hash": receipt_hash,
    }
    frame_id = "sha256:" + _h(preimage)

    # tamper witness: flip the carried binding_ref -> receipt_hash + frame_id diverge
    tampered_receipt = dict(keystone_receipt, binding_ref="sha256:" + "f" * 64)
    tampered_receipt_hash = "sha256:" + _h(tampered_receipt)
    tampered_frame_id = "sha256:" + _h(dict(preimage, receipt=tampered_receipt, receipt_hash=tampered_receipt_hash))

    trace = {
        "set": "pef_keystone_v1",
        "title": "PEF is the signed-transport layer over the keystone",
        "canon_version": URN,
        "summary": (
            "A Payment Evidence Frame wraps the settlement-bound keystone record "
            "(execution_binding output) and pins it: receipt_hash commits to the "
            "keystone fact and frame_id commits to the frame. Tamper any carried "
            "keystone reference and both diverge. PEF is the envelope, not a new "
            "spine link; the preimage is byte-identical to pef_v1."
        ),
        "keystone_fact": {
            "execution": {**EXECUTION, "expected_execution_ref": execution_ref},
            "settlement_ref": settlement_ref,
            "retention_chain_ref": retention_chain_ref,
            "expected_binding_ref": binding_ref,
        },
        "pef_frame": {
            "receipt": keystone_receipt,
            "expected_receipt_hash": receipt_hash,
            "preimage": preimage,
            "expected_frame_id": frame_id,
            "binds_ref": "receipt.binding_ref (the keystone position this frame attests)",
        },
        "tamper": {
            "tampered_receipt_hash": tampered_receipt_hash,
            "tampered_frame_id": tampered_frame_id,
            "note": "flipping receipt.binding_ref diverges receipt_hash, which diverges frame_id.",
        },
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    print("  execution_ref :", execution_ref)
    print("  binding_ref   :", binding_ref)
    print("  receipt_hash  :", receipt_hash)
    print("  frame_id      :", frame_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
