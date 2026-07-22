#!/usr/bin/env python3
"""
pef_keystone_v1 -- composition proof: PEF is the signed-transport layer over the keystone.

Proves, offline from raw fields only (RFC 8785 JCS + SHA-256, no package import):
  1. execution_ref recomputes and equals the keystone golden.
  2. binding_ref recomputes (execution_binding) and equals the settlement_binding_v1 golden.
  3. the PEF receipt carries exactly that keystone fact (execution_ref + binding_ref).
  4. receipt_hash = "sha256:"+SHA256(JCS(receipt)) recomputes (PEF pins the payload; pef_v1 shape).
  5. frame_id = "sha256:"+SHA256(JCS(preimage)) recomputes (PEF frame_id; byte-identical to pef_v1).
  6. tamper: flipping the carried binding_ref diverges receipt_hash, which diverges frame_id.

Run:  pip install rfc8785 ; python verify_pef_keystone.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

TRACE = Path(__file__).parent / "pef_keystone_trace.json"


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    kf = t["keystone_fact"]
    ex = kf["execution"]
    frame = t["pef_frame"]
    tw = t["tamper"]
    checks: list[tuple[bool, str, str]] = []

    # 1. execution tier
    execution_ref = _ref({
        "decision_ref": ex["decision_ref"], "action_type": ex["action_type"],
        "scope": ex["scope"], "outcome": ex["outcome"], "executed_at_ms": ex["executed_at_ms"],
    })
    checks.append((execution_ref == ex["expected_execution_ref"],
                   "execution_ref recomputes, equals the keystone golden", execution_ref))

    # 2. binding_ref (execution_binding) == settlement_binding_v1 golden
    binding_ref = _ref({
        "execution_ref": execution_ref,
        "settlement_ref": kf["settlement_ref"],
        "retention_chain_ref": kf["retention_chain_ref"],
    })
    checks.append((binding_ref == kf["expected_binding_ref"],
                   "binding_ref recomputes (execution_binding), equals the settlement_binding_v1 golden", binding_ref))

    # 3. the PEF receipt carries that exact keystone fact
    rc = frame["receipt"]
    checks.append((rc.get("execution_ref") == execution_ref and rc.get("binding_ref") == binding_ref,
                   "PEF receipt carries the exact keystone fact (execution_ref + binding_ref)",
                   rc.get("binding_ref", "")))

    # 4. receipt_hash pins the payload
    receipt_hash = "sha256:" + _h(rc)
    checks.append((receipt_hash == frame["expected_receipt_hash"],
                   "receipt_hash recomputes (PEF pins the keystone payload; pef_v1 shape)", receipt_hash))

    # 5. frame_id commits to the frame, computed over the preimage AS PUBLISHED.
    #
    # This previously overwrote pre["receipt"] and pre["receipt_hash"] with the values
    # verified above before hashing, which discarded the published copies: the receipt
    # nested in the preimage, and its receipt_hash, were never compared to anything and
    # could carry different references entirely while frame_id still matched.
    pre = frame["preimage"]
    checks.append((pre.get("receipt") == rc and pre.get("receipt_hash") == receipt_hash,
                   "the preimage's own receipt and receipt_hash are the verified ones (not a second, unchecked copy)",
                   pre.get("receipt_hash")))

    frame_id = "sha256:" + _h(pre)
    checks.append((frame_id == frame["expected_frame_id"],
                   "frame_id recomputes over the preimage as published (PEF frame_id; byte-identical to pef_v1)", frame_id))

    # 6. tamper diverges
    tampered_receipt = dict(rc, binding_ref="sha256:" + "f" * 64)
    t_rh = "sha256:" + _h(tampered_receipt)
    t_fid = "sha256:" + _h(dict(pre, receipt=tampered_receipt, receipt_hash=t_rh))
    tamper_ok = (t_rh == tw["tampered_receipt_hash"] and t_rh != receipt_hash
                 and t_fid == tw["tampered_frame_id"] and t_fid != frame_id)
    checks.append((tamper_ok,
                   "tamper: flipping the carried binding_ref diverges receipt_hash, which diverges frame_id", "divergent"))

    print("=" * 74)
    print("PEF KEYSTONE -- composition proof (PEF wraps + pins a keystone fact)")
    print("composed from raw fields only; no new hash, no package import")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- a PEF frame commits to the exact keystone position it carries.")
    return 0 if npass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
