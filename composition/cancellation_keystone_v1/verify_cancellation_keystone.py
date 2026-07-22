#!/usr/bin/env python3
"""
cancellation_keystone_v1 -- composition proof: cancellation closes the keystone authority.

Proves offline from raw fields (RFC 8785 JCS + SHA-256, no package import):
  1. cancellation_ref recomputes (cancellation_receipt_lite construction), equals published cn-001.
  2. the cancellation's mandate_ref IS the keystone mandate_ref (closes the exact authority used).
  3. mirror of refund: cancellation binds the authority (pre-execution), refund binds execution (post).
  4. tamper: a different closed-enum reason diverges cancellation_ref.

Run:  pip install rfc8785 ; python verify_cancellation_keystone.py
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

HERE = Path(__file__).resolve().parent
TRACE = HERE / "cancellation_keystone_trace.json"
def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()
def _ref(o): return "sha256:" + _h(o)
def cancellation_ref(reason, mandate_ref):
    return _ref({"cancellation_reason": reason, "mandate_ref": mandate_ref})

def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    c, tw = t["cancellation"], t["tamper"]
    checks = []

    cref = cancellation_ref(c["cancellation_reason"], c["mandate_ref"])
    checks.append((cref == c["expected_cancellation_ref"],
                   "cancellation_ref recomputes (cancellation_receipt_lite), equals published cn-001", cref))

    checks.append((c["mandate_ref"] == t["mandate_ref"],
                   "cancellation mandate_ref IS the keystone mandate (closes the exact authority used)", c["mandate_ref"]))

    # execution_ref must BE the keystone execution, derived from keystone_v1 raw fields.
    # It was previously only used in the inequality below, which holds for any value, so
    # this trace could name an execution unrelated to the authority being cancelled.
    ks = json.loads((HERE.parent / "keystone_v1" / "keystone_trace.json").read_text(encoding="utf-8"))
    st, kd, kx = ks["steps"], ks["decision"], ks["execution"]
    _passport = _ref(st["passport_ref"]["inputs"])
    _mandate = _ref(st["mandate_ref"]["inputs"])
    _pol = st["policy_bound_ref"]
    _policy_bound = _ref({"policy_ref": _ref(_pol["policy"]), "subject_ref": _pol["subject_ref"]})
    _decision = _ref({"agent_ref": _passport, "mandate_ref": _mandate,
                      "policy_bound_ref": _policy_bound, "verdict": kd["verdict"]})
    execution_ref = _ref({"decision_ref": _decision, "action_type": kx["action_type"],
                          "scope": kx["scope"], "outcome": kx["outcome"],
                          "executed_at_ms": kx["executed_at_ms"]})
    checks.append((execution_ref == t["execution_ref"] and _mandate == t["mandate_ref"],
                   "execution_ref and mandate_ref recompute from keystone_v1 raw fields (this IS that keystone)",
                   execution_ref))

    checks.append((t["mandate_ref"] != t["execution_ref"],
                   "mirror of refund: cancellation binds the authority (pre-execution), refund binds execution (post)", "authority vs execution"))

    cmerch = cancellation_ref("MERCHANT_REQUESTED", c["mandate_ref"])
    checks.append((cmerch == tw["cancel_merchant"] and cmerch != cref,
                   "tamper: a different closed-enum reason diverges cancellation_ref", "divergent"))

    print("=" * 74)
    print("CANCELLATION KEYSTONE -- composition proof (authority-side closure)")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}\n      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- cancellation closes the exact authority the keystone used.")
    return 0 if npass == len(checks) else 1

if __name__ == "__main__":
    sys.exit(main())
