#!/usr/bin/env python3
"""
Full keystone flow: end-to-end composition proof through the execution tier.

Proves, offline and from already-published conformance vectors only, that the
whole keystone composes into one recomputable chain:

    identity   passport_ref     (agent_passport_lite_v1)  binds as agent_ref
    authority  mandate_ref      (payment_mandate_lite_v1) binds as mandate_ref
    policy     policy_bound_ref (policy_binding_v1)        binds as policy_bound_ref
      -> decision   guardrail_ref / decision_ref (spend_guardrail_lite_v1, ALLOW)
      -> execution  execution_ref (execution_ref_v1, ex-allow-committed)
      -> cap        trust_query_ref over [passport, mandate, policy, decision, execution]
                    (composite_trust_query_lite_v1, tq-keystone)

The execution tier is the new link: execution_ref is recomputed over the EXACT
decision_ref the chain produced, so the proof shows the executed action is
consistent with the decision that authorized it. Every asserted value is an
existing published expected output; no new hashing primitive, no package import
(a JCS library + SHA-256 are the whole dependency).

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent.parent / "vectors"


def ref(obj) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _load(set_name: str) -> dict:
    return json.loads((VECTORS / set_name / f"{set_name}.json").read_text(encoding="utf-8"))


def _vec(s: dict, vid: str, key: str) -> str:
    for v in s["vectors"]:
        if v["id"] == vid:
            return v[key]
    raise SystemExit(f"{set_name} vector {vid} not found")


def main() -> int:
    t = json.loads((HERE / "keystone_trace.json").read_text(encoding="utf-8"))
    steps, dec, ex, cap = t["steps"], t["decision"], t["execution"], t["cap"]

    passport = _load("agent_passport_lite_v1")
    mandate = _load("payment_mandate_lite_v1")
    policy = _load("policy_binding_v1")
    guardrail = _load("spend_guardrail_lite_v1")
    execution = _load("execution_ref_v1")
    trust = _load("composite_trust_query_lite_v1")

    sg_allow = next(v for v in guardrail["vectors"] if v["id"] == dec["source_vector"])
    checks: list[tuple[str, bool, str]] = []

    # 1. identity
    s = steps["passport_ref"]
    agent_ref = ref(s["inputs"])
    pub = next(v["expected_passport_ref"] for v in passport["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "passport_ref recomputes from raw identity fields, equals agent_passport_lite, is the agent_ref the decision binds",
        agent_ref == s["expected"] == pub == sg_allow["agent_ref"], agent_ref,
    ))

    # 2. authority
    s = steps["mandate_ref"]
    mandate_ref = ref(s["inputs"])
    pub = next(v["expected_mandate_ref"] for v in mandate["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "mandate_ref recomputes from raw authority fields, equals payment_mandate_lite, is the mandate_ref the decision binds",
        mandate_ref == s["expected"] == pub == sg_allow["mandate_ref"], mandate_ref,
    ))

    # 3. policy (two-step)
    s = steps["policy_bound_ref"]
    policy_ref = ref(s["policy"])
    policy_bound_ref = ref({"policy_ref": policy_ref, "subject_ref": s["subject_ref"]})
    pub = next(v["expected_policy_bound_ref"] for v in policy["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "policy_ref then policy_bound_ref recompute from raw policy + subject, equal policy_binding, are what the decision binds",
        policy_ref == s["expected_policy_ref"]
        and policy_bound_ref == s["expected"] == pub == sg_allow["policy_bound_ref"], policy_bound_ref,
    ))

    # 4. decision: guardrail_ref / decision_ref from the composed chain (ALLOW)
    decision_ref = ref({
        "agent_ref": agent_ref, "mandate_ref": mandate_ref,
        "policy_bound_ref": policy_bound_ref, "verdict": dec["verdict"],
    })
    checks.append((
        "decision_ref (ALLOW) recomputed from the composed chain matches the published spend_guardrail_lite reference",
        decision_ref == dec["expected"] == sg_allow["expected_guardrail_ref"], decision_ref,
    ))

    # 5. execution: execution_ref over the EXACT decision_ref the chain produced
    execution_ref = ref({
        "decision_ref": decision_ref,
        "action_type": ex["action_type"],
        "scope": ex["scope"],
        "outcome": ex["outcome"],
        "executed_at_ms": ex["executed_at_ms"],
    })
    ex_pub = next(v["expected_execution_ref"] for v in execution["vectors"] if v["id"] == ex["source_vector"])
    checks.append((
        "execution_ref recomputes over the EXACT decision_ref the chain produced, equals the published execution_ref_v1 reference "
        "(executed action consistent with the authorizing decision, not merely correlated)",
        execution_ref == ex["expected"] == ex_pub
        and execution["vectors"][0]["decision_ref"] == decision_ref, execution_ref,
    ))

    # 6. cap: trust_query_ref over the full ordered chain incl execution_ref
    trust_query_ref = ref({
        "subject_refs": [agent_ref, mandate_ref, policy_bound_ref, decision_ref, execution_ref],
        "trust_outcome": cap["trust_outcome"],
    })
    tpub = next(v["expected_trust_query_ref"] for v in trust["vectors"] if v["id"] == cap["source_vector"])
    checks.append((
        "trust_query_ref assesses the full chain [passport, mandate, policy, decision, execution] in order, "
        "equals the published composite_trust_query_lite tq-keystone reference, capping the whole flow as one verdict",
        trust_query_ref == cap["expected"] == tpub, trust_query_ref,
    ))

    width = 74
    print("=" * width)
    print("FULL KEYSTONE FLOW -- composition proof (through execution tier)")
    print("composed from published vectors only; no new hash, no package import")
    print("=" * width)
    all_ok = True
    for i, (desc, ok, value) in enumerate(checks, 1):
        all_ok = all_ok and ok
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {value}")

    print("\n" + "-" * width)
    if all_ok:
        print(f"PASS {len(checks)}/{len(checks)} -- the keystone composes end-to-end, byte-for-byte:")
        print("     identity -> authority -> policy -> decision -> execution -> trust verdict,")
        print("     each reference recomputed first-principles, the execution bound to its decision,")
        print("     and one trust_query_ref capping all five composed references in order.")
        return 0
    print(f"FAIL ({sum(1 for _, ok, _ in checks if not ok)}/{len(checks)}) -- keystone composition broken.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
