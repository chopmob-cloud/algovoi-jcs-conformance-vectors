# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
# The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
"""
Strands-side governance integration (independent emitter).

Maps a Strands `BeforeToolCallEvent` into the SAME contract. Knows ONLY Strands' native event
shape (`tool_use.name` / `tool_use.input` / `agent.agent_id`) and Strands' own runtime-local
state. Different native field names, different nesting, and a different seq counter than crewAI.
Shares no code with the crewAI emitter.

`strands_event_from_sdk` adapts a real `strands-agents` BeforeToolCallEvent object into the
native dict this module consumes, so the proof can run from a genuine SDK hook object (the VM2
gauntlet does exactly this against the installed SDK).
"""
from __future__ import annotations


def emit_from_strands(event: dict, grant: dict, runtime: dict) -> dict:
    """Strands BeforeToolCallEvent (native) + grant + Strands runtime-local state -> {decision, outcome}."""
    tu = event["tool_use"]
    agent_id = event["agent"]["agent_id"]
    agent_role = event["agent"]["role"]
    tool = tu["name"]
    tool_params = dict(tu["input"])

    g = grant
    decision = {
        "decision_id": runtime["decision_id"],
        "request_id": runtime["request_id"],
        "seq": runtime["seq"],
        "agent_id": agent_id,
        "agent_role": agent_role,
        "tool": tool,
        "tool_params": tool_params,
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
    return {"decision": decision, "outcome": outcome, "engine": "strands"}


def strands_event_from_sdk(before_tool_call_event) -> dict:
    """Adapt a real strands.hooks BeforeToolCallEvent into the native dict above.

    Tolerant of SDK shape: tool use may be on .tool_use as a dict or an object with
    toolUseId / name / input. Used by the VM2 gauntlet against the installed SDK.
    """
    tu = getattr(before_tool_call_event, "tool_use", None)
    if tu is None:
        tu = {}
    if not isinstance(tu, dict):
        tu = {"toolUseId": getattr(tu, "toolUseId", None),
              "name": getattr(tu, "name", None),
              "input": dict(getattr(tu, "input", {}) or {})}
    agent = getattr(before_tool_call_event, "agent", None)
    agent_id = getattr(agent, "agent_id", None) or getattr(agent, "name", None)
    role = getattr(agent, "role", None) or "Researcher"
    return {"tool_use": tu, "agent": {"agent_id": agent_id, "role": role}}
