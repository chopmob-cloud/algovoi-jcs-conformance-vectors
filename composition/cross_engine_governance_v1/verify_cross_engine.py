# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
# The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
"""
cross_engine_governance_v1 (Python verifier).

Honest claim under test: a crewAI integration and a Strands integration process the SAME
authorized intent but with their OWN runtime-local state (different decision_id, request_id,
and seq counter). The contract's `intent_ref`, which excludes every runtime-local field, is
byte-identical across both frameworks and equals the published `governance_decision_v1` value,
so it is a true cross-runtime join key. The runtime-local-bearing ref `decision_context_hash`
(it includes seq) correctly DIFFERS between the two, and the full records differ (different
decision_id). We do not force the records equal; that would prove nothing.

  - NOT shared: crewai_emit.py and strands_emit.py (different native event shapes, different
    runtime state, no shared code).
  - Shared by design: the contract field set and RFC 8785 as the canonicalization standard.
    verify_cross_engine.mjs re-proves this under a second independent RFC 8785 implementation.

    pip install algovoi-substrate>=0.4.0
    python verify_cross_engine.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs, canonicalize

sys.path.insert(0, str(Path(__file__).parent))
from crewai_emit import emit_from_crewai
from strands_emit import emit_from_strands


def H(obj) -> str:
    return "sha256:" + sha256_jcs(obj)


def intent_ref_preimage(d: dict) -> dict:
    params_hash = H(d["tool_params"])
    intent_digest = H({"agent_id": d["agent_id"], "tool": d["tool"],
                       "params_hash": params_hash, "target_state_digest": d["target_state_digest"]})
    return {"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
            "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"]}


def refs_for(d: dict) -> dict:
    params_hash = H(d["tool_params"])
    intent_digest = H({"agent_id": d["agent_id"], "tool": d["tool"],
                       "params_hash": params_hash, "target_state_digest": d["target_state_digest"]})
    intent_ref = H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
                    "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"]})
    decision_context_hash = H({"agent_id": d["agent_id"], "tool": d["tool"], "params_hash": params_hash,
                               "intent_digest": intent_digest, "seq": d["seq"],
                               "retrieved_policy_refs": d["retrieved_policy_refs"], "policy_digest": d["policy_digest"],
                               "credential_scope": d["credential_scope"], "credential_tier": d["credential_tier"],
                               "expires_at": d["expires_at"], "revalidate_if": d["revalidate_if"]})
    return {"params_hash": params_hash, "intent_digest": intent_digest,
            "intent_ref": intent_ref, "decision_context_hash": decision_context_hash}


def outcome_receipt(d: dict, completed_at: str) -> str:
    return H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
              "intent_digest": refs_for(d)["intent_digest"], "idempotency_key": d["idempotency_key"],
              "completed_at": completed_at})


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / ".." / ".." / "vectors" / "governance_decision_v1" / "governance_decision_v1.json"
    corpus = json.loads(Path(vf).read_text(encoding="utf-8"))
    gd_allow = next(v for v in corpus["vectors"] if v["id"] == "gd-allow")
    out_exec = next(o for o in corpus["outcome_vectors"] if o["id"] == "out-executed")

    # Engine grant for this intent (same authorized intent for both frameworks).
    grant = {
        "decision": gd_allow["decision"],
        "target_state_digest": gd_allow["target_state_digest"],
        "normalized_scope": gd_allow["normalized_scope"],
        "idempotency_key": gd_allow["idempotency_key"],
        "issued_at": gd_allow["issued_at"],
        "retrieved_policy_refs": gd_allow["retrieved_policy_refs"],
        "policy_refs": gd_allow["retrieved_policy_refs"],
        "policy_digest": gd_allow["policy_digest"],
        "credential_scope": gd_allow["credential_scope"],
        "credential_tier": gd_allow["credential_tier"],
        "expires_at": gd_allow["expires_at"],
        "revalidate_if": gd_allow["revalidate_if"],
        "execution": {
            "outcome": out_exec["outcome_record"]["outcome"],
            "tool_output": out_exec["outcome_record"]["tool_output"],
            "completed_at": out_exec["outcome_record"]["completed_at"],
        },
    }
    # DIFFERENT runtime-local state per framework (this is the honest part).
    crewai_runtime = {"decision_id": "crewai-3f9c2a17", "request_id": "crewai-req-0001", "seq": gd_allow["seq"]}
    strands_runtime = {"decision_id": "strands-b8d14e60", "request_id": "strands-req-0001", "seq": gd_allow["seq"] + 7}

    # Same intent, two DIFFERENT native event shapes (note differing key order in the args).
    crewai_event = {"agent": {"id": gd_allow["agent_id"], "role": "Researcher"},
                    "tool": {"name": gd_allow["tool"]},
                    "tool_input": {"format": "csv", "region": "eu", "limit": 1000}}
    strands_event = {"tool_use": {"toolUseId": "tu_8831", "name": gd_allow["tool"],
                                  "input": {"limit": 1000, "format": "csv", "region": "eu"}},
                     "agent": {"agent_id": gd_allow["agent_id"], "role": "Researcher"}}

    crewai = emit_from_crewai(crewai_event, grant, crewai_runtime)
    strands = emit_from_strands(strands_event, grant, strands_runtime)
    cr, sr = refs_for(crewai["decision"]), refs_for(strands["decision"])
    fails: list[str] = []

    # 1-3. cross-runtime-STABLE refs: identical across frameworks AND equal to the published vector
    if not (cr["params_hash"] == sr["params_hash"] == gd_allow["expected_params_hash"]):
        fails.append("params_hash")
    if not (cr["intent_digest"] == sr["intent_digest"] == gd_allow["expected_intent_digest"]):
        fails.append("intent_digest")
    if not (cr["intent_ref"] == sr["intent_ref"] == gd_allow["expected_intent_ref"]):
        fails.append("intent_ref")  # THE normative cross-runtime join key

    # 4. the intent_ref preimage canonicalizes to identical bytes across the two frameworks
    if canonicalize(intent_ref_preimage(crewai["decision"])) != canonicalize(intent_ref_preimage(strands["decision"])):
        fails.append("intent_ref_preimage_bytes")

    # 5-7. runtime-local divergence is REAL, not forced equal
    if crewai["decision"]["decision_id"] == strands["decision"]["decision_id"]:
        fails.append("decision_id-should-differ")
    if canonicalize(crewai["decision"]) == canonicalize(strands["decision"]):
        fails.append("full-record-should-differ")
    if cr["decision_context_hash"] == sr["decision_context_hash"]:
        fails.append("decision_context_hash-should-differ-on-seq")  # includes seq -> not a cross-runtime key

    # 8-13. outcome join holds across frameworks; receipt_ref + tool_output_hash recompute (profile)
    for eng, emit in (("crewai", crewai), ("strands", strands)):
        if refs_for(emit["decision"])["intent_ref"] != gd_allow["expected_intent_ref"]:
            fails.append(f"{eng}:outcome-join")
        if outcome_receipt(emit["decision"], emit["outcome"]["completed_at"]) != out_exec["expected_receipt_ref"]:
            fails.append(f"{eng}:outcome-receipt_ref")
        if H(emit["outcome"]["tool_output"]) != out_exec["expected_tool_output_hash"]:
            fails.append(f"{eng}:tool_output_hash")

    if fails:
        print("cross_engine_governance_v1: FAIL ->", ", ".join(fails))
        return 1
    n = 13
    print(f"cross_engine_governance_v1: {n}/{n} PASS")
    print(f"  crewAI seq={crewai['decision']['seq']} id={crewai['decision']['decision_id']} | "
          f"Strands seq={strands['decision']['seq']} id={strands['decision']['decision_id']} (runtime-local, differ)")
    print(f"  SAME cross-runtime join key intent_ref: {cr['intent_ref']}")
    print(f"  decision_context_hash differs by design (it includes seq): "
          f"crewAI {cr['decision_context_hash'][:19]}.. != Strands {sr['decision_context_hash'][:19]}..")
    print(f"  both recompute the published governance_decision_v1 intent_ref + outcome, two JCS impls, no shared agent runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
