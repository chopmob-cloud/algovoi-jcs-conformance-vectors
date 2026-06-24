#!/usr/bin/env python3
"""
Open pre-payment decision chain: end-to-end composition proof.

Proves, offline and from already-published conformance vectors only, that the
open lite decision chain composes into a single recomputable decision. It
introduces NO new vectors and NO new hashing primitive: every value it asserts
is the published expected output of an existing AlgoVoi lite conformance set.

The chain (raw inputs -> reference -> decision):

    identity   passport_ref      (agent_passport_lite_v1, ap-001)   binds as agent_ref
    authority  mandate_ref       (payment_mandate_lite_v1, pm-001)  binds as mandate_ref
    policy     policy_bound_ref  (policy_binding_v1, pb-sab-v1-P)   binds as policy_bound_ref
      -> decision  guardrail_ref (spend_guardrail_lite_v1, sg-allow-P / sg-deny-P)

For each of the three inputs the proof: (a) recomputes the reference from its
raw fields with RFC 8785 JCS + SHA-256, (b) checks it equals the published
output of its own lite set, and (c) checks it is exactly the reference the
Spend Guardrail decision binds. Then it recomputes guardrail_ref from the three
composed references plus the verdict and matches the published reference
byte-for-byte, for ALLOW and DENY.

No package import: a JCS library (rfc8785) and SHA-256 are the whole dependency,
so any independent implementation reproduces this.

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


def _guardrail_positive(sg: dict, vid: str) -> dict:
    for v in sg["vectors"]:
        if v["id"] == vid:
            return v
    raise SystemExit(f"spend_guardrail vector {vid} not found")


def main() -> int:
    trace = json.loads((HERE / "chain_trace.json").read_text(encoding="utf-8"))
    steps = trace["steps"]
    dec = trace["decision"]

    passport = _load("agent_passport_lite_v1")
    mandate = _load("payment_mandate_lite_v1")
    policy = _load("policy_binding_v1")
    guardrail = _load("spend_guardrail_lite_v1")
    cancellation = _load("cancellation_receipt_lite_v1")
    refund = _load("refund_receipt_lite_v1")
    trust = _load("composite_trust_query_lite_v1")

    sg_allow = _guardrail_positive(guardrail, dec["verdicts"]["ALLOW"]["source_vector"])
    sg_deny = _guardrail_positive(guardrail, dec["verdicts"]["DENY"]["source_vector"])

    checks: list[tuple[str, bool, str]] = []

    # --- 1. identity: passport_ref ---
    s = steps["passport_ref"]
    agent_ref = ref(s["inputs"])
    pub = next(v["expected_passport_ref"] for v in passport["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "passport_ref recomputes from raw identity fields, equals agent_passport_lite output, "
        "and is the agent_ref Spend Guardrail binds",
        agent_ref == s["expected"] == pub == sg_allow["agent_ref"] == sg_deny["agent_ref"],
        agent_ref,
    ))

    # --- 2. authority: mandate_ref ---
    s = steps["mandate_ref"]
    mandate_ref = ref(s["inputs"])
    pub = next(v["expected_mandate_ref"] for v in mandate["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "mandate_ref recomputes from raw authority fields, equals payment_mandate_lite output, "
        "and is the mandate_ref Spend Guardrail binds",
        mandate_ref == s["expected"] == pub == sg_allow["mandate_ref"] == sg_deny["mandate_ref"],
        mandate_ref,
    ))

    # --- 3. policy: policy_bound_ref (two-step) ---
    s = steps["policy_bound_ref"]
    policy_ref = ref(s["policy"])
    policy_bound_ref = ref({"policy_ref": policy_ref, "subject_ref": s["subject_ref"]})
    pub = next(v["expected_policy_bound_ref"] for v in policy["vectors"] if v["id"] == s["source_vector"])
    checks.append((
        "policy_ref then policy_bound_ref recompute from the raw policy + subject, equal the "
        "policy_binding output, and are the policy_bound_ref Spend Guardrail binds",
        policy_ref == s["expected_policy_ref"]
        and policy_bound_ref == s["expected"] == pub == sg_allow["policy_bound_ref"] == sg_deny["policy_bound_ref"],
        policy_bound_ref,
    ))

    # --- 4. decision: guardrail_ref recomputed from the composed chain (ALLOW + DENY) ---
    for verdict, sg_vec in (("ALLOW", sg_allow), ("DENY", sg_deny)):
        g = ref({
            "agent_ref": agent_ref,
            "mandate_ref": mandate_ref,
            "policy_bound_ref": policy_bound_ref,
            "verdict": verdict,
        })
        exp = dec["verdicts"][verdict]["expected"]
        checks.append((
            f"guardrail_ref ({verdict}) recomputed from the composed chain matches the published "
            "spend_guardrail_lite_v1 reference",
            g == exp == sg_vec["expected_guardrail_ref"],
            g,
        ))

    # --- 5. lifecycle: cancellation_ref binds the SAME mandate_ref the chain used ---
    lc = trace["lifecycle"]["cancellation"]
    cancellation_ref = ref({"cancellation_reason": lc["cancellation_reason"], "mandate_ref": mandate_ref})
    cpub = next(v["expected_cancellation_ref"] for v in cancellation["vectors"] if v["id"] == lc["source_vector"])
    checks.append((
        "cancellation_ref recomputes over the SAME mandate_ref the chain used, equals the published "
        "cancellation_receipt_lite reference, and closes the lifecycle on the authority",
        cancellation_ref == lc["expected"] == cpub,
        cancellation_ref,
    ))

    # --- 6. lifecycle: refund_ref refunds the SAME guardrail_ref (ALLOW) the chain produced ---
    rf = trace["lifecycle"]["refund"]
    refund_ref = ref({"refund_amount": rf["refund_amount"], "refund_result": rf["refund_result"], "subject_ref": rf["subject_ref"]})
    rpub = next(v["expected_refund_ref"] for v in refund["vectors"] if v["id"] == rf["source_vector"])
    checks.append((
        "refund_ref recomputes over the SAME guardrail_ref the ALLOW decision produced, equals the published "
        "refund_receipt_lite reference, and closes the lifecycle after settlement",
        refund_ref == rf["expected"] == rpub and rf["subject_ref"] == dec["verdicts"]["ALLOW"]["expected"],
        refund_ref,
    ))

    # --- 7. cap: trust_query_ref assesses the full composed chain in order ---
    cap = trace["cap"]
    allow_guardrail = dec["verdicts"]["ALLOW"]["expected"]
    trust_query_ref = ref({"subject_refs": [agent_ref, mandate_ref, policy_bound_ref, allow_guardrail], "trust_outcome": cap["trust_outcome"]})
    tpub = next(v["expected_trust_query_ref"] for v in trust["vectors"] if v["id"] == cap["source_vector"])
    checks.append((
        "trust_query_ref assesses the full composed chain [passport_ref, mandate_ref, policy_bound_ref, "
        "guardrail_ref(ALLOW)] in order, equals the published composite_trust_query_lite reference, and caps the lifecycle",
        trust_query_ref == cap["expected"] == tpub,
        trust_query_ref,
    ))

    width = 74
    print("=" * width)
    print("OPEN PRE-PAYMENT DECISION CHAIN -- composition proof")
    print("composed from published lite vectors only; no new vectors, no new hash")
    print("=" * width)
    all_ok = True
    for i, (desc, ok, value) in enumerate(checks, 1):
        all_ok = all_ok and ok
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {value}")

    print("\n" + "-" * width)
    if all_ok:
        print(f"PASS {len(checks)}/{len(checks)} -- the chain composes end-to-end, byte-for-byte.")
        print("     passport_ref + mandate_ref + policy_bound_ref -> guardrail_ref -> cancellation_ref + refund_ref;")
        print("     identity, authority, and policy each recomputed from raw fields, each the")
        print("     reference the decision binds, decision reproduced for ALLOW and DENY, the")
        print("     cancellation closing the lifecycle over the same authority, the refund")
        print("     closing the lifecycle over the same authorized payment after settlement, and")
        print("     trust_query_ref capping the chain by assessing all four composed references in order.")
        return 0
    print(f"FAIL ({sum(1 for _, ok, _ in checks if not ok)}/{len(checks)}) -- composition broken.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
