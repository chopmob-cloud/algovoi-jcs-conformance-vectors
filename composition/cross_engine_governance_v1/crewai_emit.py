# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
# The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
"""
crewAI-side governance integration (independent emitter).

Maps a crewAI `before_tool_call` event into the GovernanceDecision + GovernanceOutcome
contract (PR #6030). Knows ONLY crewAI's native event shape and crewAI's own runtime-local
state (its decision_id / request_id / seq counter). Shares no code with the Strands emitter.

The point of the cross-engine proof is NOT that the whole record matches (it does not, and
should not: decision_id and seq are runtime-local). It is that the contract's `intent_ref`,
which by construction excludes every runtime-local field, is identical across frameworks.
"""
from __future__ import annotations


def emit_from_crewai(event: dict, grant: dict, runtime: dict) -> dict:
    """crewAI event + engine grant + crewAI runtime-local state -> {decision, outcome} dicts."""
    agent_id = event["agent"]["id"]
    agent_role = event["agent"]["role"]
    tool = event["tool"]["name"]
    tool_params = dict(event["tool_input"])

    g = grant
    decision = {
        # runtime-local (crewAI's own; differ from Strands on purpose)
        "decision_id": runtime["decision_id"],
        "request_id": runtime["request_id"],
        "seq": runtime["seq"],
        # framework-extracted
        "agent_id": agent_id,
        "agent_role": agent_role,
        "tool": tool,
        "tool_params": tool_params,
        # engine grant (same authorized intent for both frameworks)
        "decision": g["decision"],
        "target_state_digest": g["target_state_digest"],
        "normalized_scope": g["normalized_scope"],
        "idempotency_key": g["idempotency_key"],
        "issued_at": g["issued_at"],
        "retrieved_policy_refs": g["retrieved_policy_refs"],
        "policy_refs": g["policy_refs"],
        "policy_digest": g["policy_digest"],
        "credential_scope": g["credential_scope"],
        "credential_tier": g["credential_tier"],
        "expires_at": g["expires_at"],
        "revalidate_if": g["revalidate_if"],
    }
    outcome = {
        "decision_id": runtime["decision_id"],
        "seq": runtime["seq"],
        "outcome": g["execution"]["outcome"],
        "tool_output": g["execution"].get("tool_output"),
        "completed_at": g["execution"]["completed_at"],
    }
    return {"decision": decision, "outcome": outcome, "engine": "crewai"}
