#!/usr/bin/env python3
"""
audit_chain_of_frames_v1 composition generator (keystone capstone).

The whole post-decision lifecycle as a chain of signed-transport frames:

  Frame 1 (payment_execution)  wraps the execution preimage   -> receipt_hash == execution_ref
  Frame 2 (payment_settlement) wraps the settlement receipt   -> receipt_hash == settlement_ref
  Frame 3 (payment_refund)     wraps the refund preimage       -> receipt_hash == refund_ref

Because each frame wraps the exact preimage of a keystone reference, its PEF receipt_hash
EQUALS that reference: the chain provably transports the keystone refs themselves. The frames
are linked into an audit chain (row N prev_hash == row N-1 row hash) and capped by one
trust_query_ref over the ordered frame ids. Tamper any frame and both the chain and the cap
diverge.

No new hashing primitive: reuses the pef_v1 frame construction, the execution_ref_v1 /
settlement_attestation_v1 / refund_receipt_lite_v1 receipt shapes, the audit-chain row shape,
and trust_query_ref. All byte-for-byte.

Usage:  pip install rfc8785 ; python generate_audit_chain_of_frames.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

OUT = Path(__file__).parent / "audit_chain_trace.json"
URN = "urn:x402:canonicalisation:jcs-rfc8785-v1"
PROVIDER = "did:web:api.algovoi.co.uk"
ZERO = "0" * 64


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


# ---- keystone lifecycle facts (keystone_v1 / settlement_binding_v1 / refund_execution_v1) ----
DECISION_REF = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
EXECUTION = {
    "decision_ref": DECISION_REF, "action_type": "payment", "scope": "bilateral",
    "outcome": "COMMITTED", "executed_at_ms": 1716460800000,
}
EXPECT = {
    "execution_ref": "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a",
    "settlement_ref": "sha256:d0ec6b76020c40b06dc40573c884ef27399e91002718d647345d4ecba12921c9",
    "refund_ref": "sha256:d788dca372c121c27c6babc767fa8d842112ab87e5b76406f7c9303a7970b941",
}


def frame(claim_type, receipt_format, receipt, frame_ts):
    receipt_hash = "sha256:" + _h(receipt)
    preimage = {
        "canon_version": URN, "claim_type": claim_type, "frame_provider_did": PROVIDER,
        "frame_timestamp_ms": frame_ts, "pef_version": "1", "receipt": receipt,
        "receipt_format": receipt_format, "receipt_hash": receipt_hash,
    }
    return ("sha256:" + _h(preimage)), receipt_hash, preimage


def chain_row(content_ref, prev_hash, row_number):
    row = {"content_hash": content_ref, "prev_hash": prev_hash, "row_number": row_number}
    return row, _h(row)  # bare hex row hash (settlement_attestation_v1 row shape)


def trust_query_ref(subject_refs, trust_outcome):
    return "sha256:" + _h({"subject_refs": list(subject_refs), "trust_outcome": trust_outcome})


def settlement_receipt(settled_payment_ref):
    return {
        "canon_version": "jcs-rfc8785-v1", "jurisdiction_flags": ["UK", "EU"],
        "settled_payment_ref": settled_payment_ref,
        "settlement_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
        "settlement_chain": "ethereum:8453", "settlement_provider_did": "did:example:settlement-provider-1",
        "settlement_result": "SETTLED", "settlement_timestamp_ms": 1716494400000,
    }


def main() -> int:
    execution_ref = _ref(EXECUTION)
    assert execution_ref == EXPECT["execution_ref"], execution_ref

    # the three lifecycle receipts (each is the exact preimage of a keystone ref)
    rcpt_exec = dict(EXECUTION)
    rcpt_settle = settlement_receipt(execution_ref)
    rcpt_refund = {"refund_amount": "1000", "refund_result": "FULL", "subject_ref": execution_ref}

    f1_id, f1_rh, f1_pre = frame("payment_execution", "execution-ref-v1", rcpt_exec, 1716460800000)
    f2_id, f2_rh, f2_pre = frame("payment_settlement", "settlement-attestation-v1", rcpt_settle, 1716494400000)
    f3_id, f3_rh, f3_pre = frame("payment_refund", "refund-receipt-lite-v1", rcpt_refund, 1716508800000)

    # each frame's receipt_hash equals the keystone ref it carries
    assert f1_rh == EXPECT["execution_ref"], f1_rh
    assert f2_rh == EXPECT["settlement_ref"], f2_rh
    assert f3_rh == EXPECT["refund_ref"], f3_rh

    # link the frames into an audit chain
    r1, r1h = chain_row(f1_id, ZERO, 1)
    r2, r2h = chain_row(f2_id, r1h, 2)
    r3, r3h = chain_row(f3_id, r2h, 3)

    # cap the ordered frame ids with one trust verdict
    cap = trust_query_ref([f1_id, f2_id, f3_id], "TRUSTED")

    # tamper witness: a REVERSED settlement reshapes frame 2 -> chain + cap diverge
    f2t_id, f2t_rh, _ = frame("payment_settlement", "settlement-attestation-v1",
                              dict(rcpt_settle, settlement_result="REVERSED"), 1716494400000)
    _, r2t_h = chain_row(f2t_id, r1h, 2)
    _, r3t_h = chain_row(f3_id, r2t_h, 3)
    cap_t = trust_query_ref([f1_id, f2t_id, f3_id], "TRUSTED")

    trace = {
        "set": "audit_chain_of_frames_v1",
        "title": "Keystone lifecycle as a chain of signed-transport frames, capped by one verdict",
        "canon_version": URN,
        "summary": (
            "execution -> settlement -> refund, each carried as a PEF frame whose receipt_hash "
            "equals the keystone reference it transports, linked into an audit chain by prev_hash "
            "and capped by one trust_query_ref over the ordered frame ids. Tamper any frame and "
            "both the chain and the cap diverge. No new hashing primitive."
        ),
        "execution": {**EXECUTION, "expected_execution_ref": execution_ref},
        "frames": [
            {"role": "execution", "frame_id": f1_id, "receipt_hash": f1_rh,
             "carries_ref": "execution_ref", "preimage": f1_pre},
            {"role": "settlement", "frame_id": f2_id, "receipt_hash": f2_rh,
             "carries_ref": "settlement_ref", "preimage": f2_pre},
            {"role": "refund", "frame_id": f3_id, "receipt_hash": f3_rh,
             "carries_ref": "refund_ref", "preimage": f3_pre},
        ],
        "carries": EXPECT,
        "audit_chain": [
            {"row": r1, "expected_row_hash": r1h},
            {"row": r2, "expected_row_hash": r2h},
            {"row": r3, "expected_row_hash": r3h},
        ],
        "cap": {"subject_refs": [f1_id, f2_id, f3_id], "trust_outcome": "TRUSTED",
                "expected_trust_query_ref": cap},
        "tamper": {
            "reversed_frame2_id": f2t_id, "reversed_row2_hash": r2t_h,
            "reversed_row3_hash": r3t_h, "reversed_cap": cap_t,
            "note": "REVERSED settlement reshapes frame 2 -> frame_id, rows 2-3, and the cap all diverge.",
        },
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    for f in trace["frames"]:
        print(f"  {f['role']:11s} frame_id={f['frame_id'][:24]}...  receipt_hash==({f['carries_ref']})")
    print("  chain row3 hash :", r3h)
    print("  cap (trust_query_ref):", cap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
