#!/usr/bin/env python3
"""
audit_chain_of_frames_v1 -- composition proof (keystone capstone).

Proves, offline from raw fields only (RFC 8785 JCS + SHA-256, no package import):
  1-3. each frame's receipt_hash equals the keystone ref it carries (execution/settlement/refund),
       and each frame_id recomputes (pef_v1 construction).
  4.   the frames link into an audit chain (row N prev_hash == row N-1 row hash; genesis 64 zeros).
  5.   one trust_query_ref over the ordered frame ids caps the chain (TRUSTED).
  6.   tamper: a REVERSED settlement reshapes frame 2 -> frame_id, rows 2-3, and the cap all diverge.

Run:  pip install rfc8785 ; python verify_audit_chain_of_frames.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

TRACE = Path(__file__).parent / "audit_chain_trace.json"
ZERO = "0" * 64


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _row_hash(content_ref, prev_hash, row_number) -> str:
    return _h({"content_hash": content_ref, "prev_hash": prev_hash, "row_number": row_number})


def _frame_id(preimage) -> str:
    return "sha256:" + _h(preimage)


def _tq(subject_refs, trust_outcome) -> str:
    return "sha256:" + _h({"subject_refs": list(subject_refs), "trust_outcome": trust_outcome})


def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    frames = t["frames"]
    carries = t["carries"]
    chain = t["audit_chain"]
    cap = t["cap"]
    tw = t["tamper"]
    checks: list[tuple[bool, str, str]] = []

    ref_by_role = {"execution": "execution_ref", "settlement": "settlement_ref", "refund": "refund_ref"}
    for f in frames:
        role = f["role"]
        recomputed_id = _frame_id(f["preimage"])
        # receipt_hash inside the preimage must equal the keystone ref AND the recomputed receipt hash
        rh = "sha256:" + _h(f["preimage"]["receipt"])
        ok = (rh == carries[ref_by_role[role]]
              and rh == f["preimage"]["receipt_hash"]
              and recomputed_id == f["frame_id"])
        checks.append((ok, f"frame[{role}] receipt_hash == {ref_by_role[role]} and frame_id recomputes (pef_v1)",
                       f["frame_id"]))

    # chain linkage
    r1 = _row_hash(frames[0]["frame_id"], ZERO, 1)
    r2 = _row_hash(frames[1]["frame_id"], r1, 2)
    r3 = _row_hash(frames[2]["frame_id"], r2, 3)
    chain_ok = (chain[0]["row"]["prev_hash"] == ZERO
                and r1 == chain[0]["expected_row_hash"]
                and chain[1]["row"]["prev_hash"] == r1 and r2 == chain[1]["expected_row_hash"]
                and chain[2]["row"]["prev_hash"] == r2 and r3 == chain[2]["expected_row_hash"])
    checks.append((chain_ok, "frames link into an audit chain (prev_hash == prior row hash; genesis 64 zeros)", r3))

    # cap
    cap_val = _tq(cap["subject_refs"], cap["trust_outcome"])
    cap_ok = (cap["subject_refs"] == [f["frame_id"] for f in frames]
              and cap_val == cap["expected_trust_query_ref"])
    checks.append((cap_ok, "one trust_query_ref over the ordered frame ids caps the chain (TRUSTED)", cap_val))

    # tamper
    f2t = _frame_id(dict(frames[1]["preimage"],
                         receipt=dict(frames[1]["preimage"]["receipt"], settlement_result="REVERSED"),
                         receipt_hash="sha256:" + _h(dict(frames[1]["preimage"]["receipt"], settlement_result="REVERSED"))))
    r2t = _row_hash(f2t, r1, 2)
    r3t = _row_hash(frames[2]["frame_id"], r2t, 3)
    capt = _tq([frames[0]["frame_id"], f2t, frames[2]["frame_id"]], "TRUSTED")
    tamper_ok = (f2t == tw["reversed_frame2_id"] and f2t != frames[1]["frame_id"]
                 and r2t == tw["reversed_row2_hash"] and r3t == tw["reversed_row3_hash"] and r3t != r3
                 and capt == tw["reversed_cap"] and capt != cap_val)
    checks.append((tamper_ok, "tamper: REVERSED settlement diverges frame 2, rows 2-3, and the cap", "divergent"))

    print("=" * 74)
    print("AUDIT CHAIN OF FRAMES -- composition proof (keystone capstone)")
    print("execution -> settlement -> refund as signed-transport frames, chained + capped")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- the lifecycle is one tamper-evident, capped chain of frames.")
    return 0 if npass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
