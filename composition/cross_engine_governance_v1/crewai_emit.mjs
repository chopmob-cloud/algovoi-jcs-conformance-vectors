// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
// The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
// crewAI-side governance integration (independent emitter, JS). Mirror of crewai_emit.py.
export function emitFromCrewai(event, grant, runtime) {
  const agent_id = event.agent.id;
  const agent_role = event.agent.role;
  const tool = event.tool.name;
  const tool_params = { ...event.tool_input };
  const g = grant;
  const decision = {
    decision_id: runtime.decision_id, request_id: runtime.request_id, seq: runtime.seq,
    agent_id, agent_role, tool, tool_params,
    decision: g.decision, target_state_digest: g.target_state_digest, normalized_scope: g.normalized_scope,
    idempotency_key: g.idempotency_key, issued_at: g.issued_at, retrieved_policy_refs: g.retrieved_policy_refs,
    policy_refs: g.policy_refs, policy_digest: g.policy_digest, credential_scope: g.credential_scope,
    credential_tier: g.credential_tier, expires_at: g.expires_at, revalidate_if: g.revalidate_if,
  };
  const outcome = {
    decision_id: runtime.decision_id, seq: runtime.seq, outcome: g.execution.outcome,
    tool_output: g.execution.tool_output ?? null, completed_at: g.execution.completed_at,
  };
  return { decision, outcome, engine: "crewai" };
}
