"""
governance_decision_v1 runner (Python reference impl).

Conformance vectors for the crewAI GovernanceDecision contract (PR #6030). Independently
recomputes the five RFC 8785 (JCS) + SHA-256 digest constructions and confirms each equals
the published value; reproduces the contract's route-validation and seq/seal contiguity rules
for the negative and completeness vectors. A PASS here against the same expected hashes the
Node runner checks proves byte-for-byte Python + Node parity.

    params_hash           = "sha256:" + SHA-256(JCS(tool_params))
    intent_digest         = "sha256:" + SHA-256(JCS({agent_id, tool, params_hash, target_state_digest}))
    intent_ref            = "sha256:" + SHA-256(JCS({agent_id, tool, normalized_scope, intent_digest, idempotency_key}))
    receipt_ref           = "sha256:" + SHA-256(JCS({...intent_ref fields, issued_at}))
    decision_context_hash = "sha256:" + SHA-256(JCS({agent_id, tool, params_hash, intent_digest, seq,
                              retrieved_policy_refs, policy_digest, credential_scope, credential_tier,
                              expires_at, revalidate_if}))

    pip install algovoi-substrate>=0.4.0
    python runner_python.py [governance_decision_v1.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs, canonicalize


def H(obj) -> str:
    return "sha256:" + sha256_jcs(obj)


def refs_for(d: dict) -> dict:
    params_hash = H(d["tool_params"])
    intent_digest = H({"agent_id": d["agent_id"], "tool": d["tool"],
                       "params_hash": params_hash, "target_state_digest": d["target_state_digest"]})
    intent_ref = H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
                    "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"]})
    receipt_ref = H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
                     "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"],
                     "issued_at": d["issued_at"]})
    decision_context_hash = H({"agent_id": d["agent_id"], "tool": d["tool"], "params_hash": params_hash,
                               "intent_digest": intent_digest, "seq": d["seq"],
                               "retrieved_policy_refs": d["retrieved_policy_refs"], "policy_digest": d["policy_digest"],
                               "credential_scope": d["credential_scope"], "credential_tier": d["credential_tier"],
                               "expires_at": d["expires_at"], "revalidate_if": d["revalidate_if"]})
    return {"params_hash": params_hash, "intent_digest": intent_digest, "intent_ref": intent_ref,
            "receipt_ref": receipt_ref, "decision_context_hash": decision_context_hash}


def validate_governance_decision(d: dict) -> tuple[bool, list[str]]:
    """Reproduces the route-specific rules of the contract's validate_governance_decision."""
    errors: list[str] = []
    decision = d.get("decision")
    if not decision:
        return (False, ["'decision' field is required"])
    if not d.get("decision_id"):
        errors.append(f"'{decision}' requires 'decision_id'")
    if decision in ("allow", "require_approval"):
        for field in ("agent_id", "tool", "issued_at"):
            if not d.get(field):
                errors.append(f"'{decision}' requires '{field}'")
        if not d.get("intent_ref") and not d.get("params_hash"):
            errors.append(f"'{decision}' requires 'intent_ref' or 'params_hash' for intent binding")
        if not d.get("policy_refs"):
            errors.append(f"'{decision}' requires at least one entry in 'policy_refs'")
    elif decision == "deny":
        if not d.get("tool"):
            errors.append("'deny' requires 'tool'")
        if not d.get("reason"):
            errors.append("'deny' requires 'reason'")
    elif decision == "revise":
        if not d.get("tool"):
            errors.append("'revise' requires 'tool'")
        if not d.get("reason"):
            errors.append("'revise' requires 'reason'")
        if not d.get("revalidate_if"):
            errors.append("'revise' requires 'revalidate_if' conditions")
    return (len(errors) == 0, errors)


def verify_contiguity(records: list[dict], seal: dict | None) -> bool:
    """Reproduces the contract's verify_contiguity: contiguous 0..N-1, running_count==seq+1, count==total."""
    seq_records = [r for r in records if not r.get("sealed")]
    seqs = sorted(r["seq"] for r in seq_records)
    if seqs != list(range(len(seqs))):
        return False
    for r in seq_records:
        if r.get("running_count") != r["seq"] + 1:
            return False
    if seal is not None and len(seq_records) != int(seal.get("total", -1)):
        return False
    return True


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "governance_decision_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []

    # 1. digest vectors: all five constructions recompute to the published values
    for v in d["vectors"]:
        got = refs_for(v)
        for field, exp_key in (("params_hash", "expected_params_hash"),
                               ("intent_digest", "expected_intent_digest"),
                               ("intent_ref", "expected_intent_ref"),
                               ("receipt_ref", "expected_receipt_ref"),
                               ("decision_context_hash", "expected_decision_context_hash")):
            if got[field] != v[exp_key]:
                fails.append(f"{v['id']}:{field}")

    # 2. normalization vectors: JCS canonical bytes + sha256 reproduce exactly
    for nv in d["normalization_vectors"]:
        if canonicalize(nv["preimage"]) != nv["expected_canonical_jcs"]:
            fails.append(f"{nv['id']}:jcs")
        if "sha256:" + sha256_jcs(nv["preimage"]) != nv["expected_sha256"]:
            fails.append(f"{nv['id']}:sha256")

    # 3. negative vectors: route validation must reject, with the expected reason
    for nv in d["negative_vectors"]:
        ok, errors = validate_governance_decision(nv["record"])
        if ok or not any(nv["expect_error_contains"] in e for e in errors):
            fails.append(f"{nv['id']}:not-rejected")

    # 4. contiguity vectors: valid run complete, gap run incomplete
    cv = d["contiguity_vectors"]
    if verify_contiguity(cv["valid"]["records"], cv["valid"]["seal"]) is not cv["valid"]["expected_complete"]:
        fails.append("contig-valid")
    if verify_contiguity(cv["gap"]["records"], cv["gap"]["seal"]) is not cv["gap"]["expected_complete"]:
        fails.append("contig-gap")

    n = (len(d["vectors"]) * 5 + len(d["normalization_vectors"]) * 2
         + len(d["negative_vectors"]) + 2)
    if fails:
        print("governance_decision_v1: FAIL ->", ", ".join(fails))
        return 1
    print(f"governance_decision_v1: {n}/{n} PASS "
          f"({len(d['vectors'])} decisions x 5 digests + "
          f"{len(d['normalization_vectors'])} JCS-norm + "
          f"{len(d['negative_vectors'])} route-rejections + 2 contiguity), byte-for-byte.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
