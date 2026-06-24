#!/usr/bin/env python3
"""
compliance_gate_keystone_v1 composition generator.

Binds the COMPLIANCE verdict into the keystone decision: the keystone proves agent + authority +
policy -> decision, and this composition proves the compliance gate (ALLOW / REFER / DENY) assessed
the EXACT policy_bound_ref the decision used, so the decision was admitted under the compliance
verdict in force. A compliance-spanning trust_query then caps the chain including the gate.

No new hashing primitive: reuses compliance_gate_lite_v1 (`gate_ref`), the keystone decision_ref,
and trust_query_ref. Every asserted gate value is a published compliance_gate_lite golden.

Usage:  pip install rfc8785 ; python generate_compliance_gate_keystone.py
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

OUT = Path(__file__).parent / "compliance_gate_keystone_trace.json"

PASSPORT = "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"
MANDATE  = "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"
POLICY   = "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21"
EXECUTION= "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"
PAYER    = "sha256:8637798158677e9aa7d218d81713db9af656e2f28a5bcce97b4f2a73286f5765"
EXPECT = {
    "decision_ref":  "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",
    "gate_allow":    "sha256:43d8d8cb0ba6ccbd3c36167a28075a3fd5b8858ce0414f6871a22a96f86f96a5",
    "gate_refer":    "sha256:9a25b3d9d9c1ff4ba1c9c1da66668c59caf8164d4a081df30826c007d9b6b845",
}

def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()
def _ref(o): return "sha256:" + _h(o)

def main() -> int:
    decision_ref = _ref({"agent_ref": PASSPORT, "mandate_ref": MANDATE, "policy_bound_ref": POLICY, "verdict": "ALLOW"})
    assert decision_ref == EXPECT["decision_ref"], decision_ref
    gate_allow = _ref({"payer_ref": PAYER, "subject_ref": POLICY, "verdict": "ALLOW"})
    assert gate_allow == EXPECT["gate_allow"], gate_allow
    gate_refer = _ref({"payer_ref": PAYER, "subject_ref": POLICY, "verdict": "REFER"})
    assert gate_refer == EXPECT["gate_refer"], gate_refer
    # compliance-spanning cap: gate inserted after the policy tier it assessed
    span = [PASSPORT, MANDATE, POLICY, gate_allow, decision_ref, EXECUTION]
    compliance_cap = _ref({"subject_refs": span, "trust_outcome": "TRUSTED"})

    trace = {
        "set": "compliance_gate_keystone_v1",
        "title": "Compliance gate verdict binds the keystone decision",
        "canon_version": "jcs-rfc8785-v1",
        "summary": (
            "The compliance gate (ALLOW/REFER/DENY) assessed the exact policy_bound_ref the keystone "
            "decision used, so the decision was admitted under the compliance verdict in force. A "
            "compliance-spanning trust_query caps the chain including the gate. Published "
            "compliance_gate_lite_v1 goldens; no new hashing primitive."
        ),
        "decision": {"agent_ref": PASSPORT, "mandate_ref": MANDATE, "policy_bound_ref": POLICY,
                     "verdict": "ALLOW", "expected_decision_ref": decision_ref},
        "compliance_gate": {"payer_ref": PAYER, "subject_ref": POLICY, "verdict": "ALLOW",
                            "expected_gate_ref": gate_allow,
                            "binds": "subject_ref == decision.policy_bound_ref"},
        "compliance_cap": {"subject_refs": span, "trust_outcome": "TRUSTED",
                           "expected_trust_query_ref": compliance_cap},
        "tamper": {"gate_refer": gate_refer,
                   "note": "a REFER verdict over the same payer + policy diverges gate_ref; the admitted decision is bound to the ALLOW verdict specifically."},
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    print("  decision_ref   :", decision_ref)
    print("  gate_ref(ALLOW):", gate_allow, "(over keystone policy_bound_ref)")
    print("  compliance_cap :", compliance_cap)
    return 0

if __name__ == "__main__":
    sys.exit(main())
