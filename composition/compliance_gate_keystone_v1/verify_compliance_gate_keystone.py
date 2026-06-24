#!/usr/bin/env python3
"""
compliance_gate_keystone_v1 -- composition proof: the compliance verdict binds the keystone decision.

Proves offline from raw fields (RFC 8785 JCS + SHA-256, no package import):
  1. decision_ref recomputes (keystone decision), equals the published value.
  2. gate_ref recomputes (compliance_gate_lite construction), equals the published cg-allow-P golden.
  3. the gate's subject_ref IS the decision's policy_bound_ref (compliance assessed the policy in force).
  4. a compliance-spanning trust_query over [passport, mandate, policy, gate, decision, execution] caps it.
  5. tamper: a REFER verdict diverges gate_ref (decision is bound to the ALLOW verdict specifically).

Run:  pip install rfc8785 ; python verify_compliance_gate_keystone.py
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

TRACE = Path(__file__).parent / "compliance_gate_keystone_trace.json"
def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()
def _ref(o): return "sha256:" + _h(o)

def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    d, g, cap, tw = t["decision"], t["compliance_gate"], t["compliance_cap"], t["tamper"]
    checks = []

    decision_ref = _ref({"agent_ref": d["agent_ref"], "mandate_ref": d["mandate_ref"],
                         "policy_bound_ref": d["policy_bound_ref"], "verdict": d["verdict"]})
    checks.append((decision_ref == d["expected_decision_ref"],
                   "decision_ref recomputes (keystone decision)", decision_ref))

    gate_ref = _ref({"payer_ref": g["payer_ref"], "subject_ref": g["subject_ref"], "verdict": g["verdict"]})
    checks.append((gate_ref == g["expected_gate_ref"],
                   "gate_ref recomputes (compliance_gate_lite construction), equals published cg-allow-P", gate_ref))

    checks.append((g["subject_ref"] == d["policy_bound_ref"],
                   "gate subject_ref IS the decision policy_bound_ref (compliance assessed the policy in force)", g["subject_ref"]))

    span_cap = _ref({"subject_refs": cap["subject_refs"], "trust_outcome": cap["trust_outcome"]})
    ok_cap = (span_cap == cap["expected_trust_query_ref"]
              and cap["subject_refs"][3] == gate_ref and cap["subject_refs"][4] == decision_ref)
    checks.append((ok_cap, "compliance-spanning trust_query caps [passport, mandate, policy, gate, decision, execution]", span_cap))

    gate_refer = _ref({"payer_ref": g["payer_ref"], "subject_ref": g["subject_ref"], "verdict": "REFER"})
    checks.append((gate_refer == tw["gate_refer"] and gate_refer != gate_ref,
                   "tamper: REFER verdict diverges gate_ref (decision bound to the ALLOW verdict)", "divergent"))

    print("=" * 74)
    print("COMPLIANCE GATE KEYSTONE -- composition proof (compliance verdict binds the decision)")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}\n      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- the keystone decision was admitted under the compliance verdict in force.")
    return 0 if npass == len(checks) else 1

if __name__ == "__main__":
    sys.exit(main())
