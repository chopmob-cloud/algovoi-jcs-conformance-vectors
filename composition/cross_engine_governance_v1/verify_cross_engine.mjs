// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
// The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
//
// cross_engine_governance_v1 (Node verifier, second independent JCS implementation).
// Re-runs the honest Python proof under Node @algovoi/substrate: same authorized intent, DIFFERENT
// runtime-local state per framework; intent_ref identical, decision_context_hash correctly differs.
//
//   npm install @algovoi/substrate
//   node verify_cross_engine.mjs
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";
import { emitFromCrewai } from "./crewai_emit.mjs";
import { emitFromStrands } from "./strands_emit.mjs";

const H = (obj) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(obj), "utf-8")).digest("hex");

function intentRefPreimage(d) {
  const params_hash = H(d.tool_params);
  const intent_digest = H({ agent_id: d.agent_id, tool: d.tool, params_hash, target_state_digest: d.target_state_digest });
  return { agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope, intent_digest, idempotency_key: d.idempotency_key };
}
function refsFor(d) {
  const params_hash = H(d.tool_params);
  const intent_digest = H({ agent_id: d.agent_id, tool: d.tool, params_hash, target_state_digest: d.target_state_digest });
  const intent_ref = H({ agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope, intent_digest, idempotency_key: d.idempotency_key });
  const decision_context_hash = H({
    agent_id: d.agent_id, tool: d.tool, params_hash, intent_digest, seq: d.seq,
    retrieved_policy_refs: d.retrieved_policy_refs, policy_digest: d.policy_digest,
    credential_scope: d.credential_scope, credential_tier: d.credential_tier,
    expires_at: d.expires_at, revalidate_if: d.revalidate_if,
  });
  return { params_hash, intent_digest, intent_ref, decision_context_hash };
}
const outcomeReceipt = (d, completed_at) => H({
  agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope,
  intent_digest: refsFor(d).intent_digest, idempotency_key: d.idempotency_key, completed_at,
});

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "..", "..", "vectors", "governance_decision_v1", "governance_decision_v1.json");
const corpus = JSON.parse(readFileSync(vf, "utf-8"));
const gdAllow = corpus.vectors.find((v) => v.id === "gd-allow");
const outExec = corpus.outcome_vectors.find((o) => o.id === "out-executed");

const grant = {
  decision: gdAllow.decision, target_state_digest: gdAllow.target_state_digest, normalized_scope: gdAllow.normalized_scope,
  idempotency_key: gdAllow.idempotency_key, issued_at: gdAllow.issued_at, retrieved_policy_refs: gdAllow.retrieved_policy_refs,
  policy_refs: gdAllow.retrieved_policy_refs, policy_digest: gdAllow.policy_digest, credential_scope: gdAllow.credential_scope,
  credential_tier: gdAllow.credential_tier, expires_at: gdAllow.expires_at, revalidate_if: gdAllow.revalidate_if,
  execution: { outcome: outExec.outcome_record.outcome, tool_output: outExec.outcome_record.tool_output, completed_at: outExec.outcome_record.completed_at },
};
const crewaiRuntime = { decision_id: "crewai-3f9c2a17", request_id: "crewai-req-0001", seq: gdAllow.seq };
const strandsRuntime = { decision_id: "strands-b8d14e60", request_id: "strands-req-0001", seq: gdAllow.seq + 7 };
const crewaiEvent = { agent: { id: gdAllow.agent_id, role: "Researcher" }, tool: { name: gdAllow.tool }, tool_input: { format: "csv", region: "eu", limit: 1000 } };
const strandsEvent = { tool_use: { toolUseId: "tu_8831", name: gdAllow.tool, input: { limit: 1000, format: "csv", region: "eu" } }, agent: { agent_id: gdAllow.agent_id, role: "Researcher" } };

const crewai = emitFromCrewai(crewaiEvent, grant, crewaiRuntime);
const strands = emitFromStrands(strandsEvent, grant, strandsRuntime);
const cr = refsFor(crewai.decision), sr = refsFor(strands.decision);
const fails = [];

if (!(cr.params_hash === sr.params_hash && sr.params_hash === gdAllow.expected_params_hash)) fails.push("params_hash");
if (!(cr.intent_digest === sr.intent_digest && sr.intent_digest === gdAllow.expected_intent_digest)) fails.push("intent_digest");
if (!(cr.intent_ref === sr.intent_ref && sr.intent_ref === gdAllow.expected_intent_ref)) fails.push("intent_ref");
if (canonicalize(intentRefPreimage(crewai.decision)) !== canonicalize(intentRefPreimage(strands.decision))) fails.push("intent_ref_preimage_bytes");
if (crewai.decision.decision_id === strands.decision.decision_id) fails.push("decision_id-should-differ");
if (canonicalize(crewai.decision) === canonicalize(strands.decision)) fails.push("full-record-should-differ");
if (cr.decision_context_hash === sr.decision_context_hash) fails.push("decision_context_hash-should-differ-on-seq");
for (const [eng, emit] of [["crewai", crewai], ["strands", strands]]) {
  if (refsFor(emit.decision).intent_ref !== gdAllow.expected_intent_ref) fails.push(`${eng}:outcome-join`);
  if (outcomeReceipt(emit.decision, emit.outcome.completed_at) !== outExec.expected_receipt_ref) fails.push(`${eng}:outcome-receipt_ref`);
  if (H(emit.outcome.tool_output) !== outExec.expected_tool_output_hash) fails.push(`${eng}:tool_output_hash`);
}

if (fails.length) { console.error("cross_engine_governance_v1: FAIL ->", fails.join(", ")); process.exit(1); }
console.log(`cross_engine_governance_v1: 13/13 PASS (Node == Python JCS)`);
console.log(`  crewAI seq=${crewai.decision.seq} | Strands seq=${strands.decision.seq} (runtime-local, differ)`);
console.log(`  SAME cross-runtime join key intent_ref: ${cr.intent_ref}`);
console.log(`  decision_context_hash differs by design (includes seq): ${cr.decision_context_hash.slice(0, 19)}.. != ${sr.decision_context_hash.slice(0, 19)}..`);
