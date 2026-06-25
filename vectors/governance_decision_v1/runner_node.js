/**
 * governance_decision_v1 runner (Node.js / TypeScript reference impl).
 *
 * Conformance vectors for the crewAI GovernanceDecision contract (PR #6030). Independently
 * recomputes the five RFC 8785 (JCS) + SHA-256 digest constructions and the contract's
 * route-validation + seq/seal contiguity rules. A PASS here against the same expected hashes
 * the Python runner checks proves byte-for-byte Python + Node parity, which is the whole point:
 * intent_ref / receipt_ref / params_hash recompute identically no matter who computes them.
 *
 *   npm install @algovoi/substrate
 *   node runner_node.js [governance_decision_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const H = (obj) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(obj), "utf-8")).digest("hex");

function refsFor(d) {
  const params_hash = H(d.tool_params);
  const intent_digest = H({ agent_id: d.agent_id, tool: d.tool, params_hash, target_state_digest: d.target_state_digest });
  const intent_ref = H({ agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope, intent_digest, idempotency_key: d.idempotency_key });
  const receipt_ref = H({ agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope, intent_digest, idempotency_key: d.idempotency_key, issued_at: d.issued_at });
  const decision_context_hash = H({
    agent_id: d.agent_id, tool: d.tool, params_hash, intent_digest, seq: d.seq,
    retrieved_policy_refs: d.retrieved_policy_refs, policy_digest: d.policy_digest,
    credential_scope: d.credential_scope, credential_tier: d.credential_tier,
    expires_at: d.expires_at, revalidate_if: d.revalidate_if,
  });
  return { params_hash, intent_digest, intent_ref, receipt_ref, decision_context_hash };
}

function validateGovernanceDecision(d) {
  const errors = [];
  const decision = d.decision;
  if (!decision) return [false, ["'decision' field is required"]];
  if (!d.decision_id) errors.push(`'${decision}' requires 'decision_id'`);
  if (decision === "allow" || decision === "require_approval") {
    for (const f of ["agent_id", "tool", "issued_at"]) if (!d[f]) errors.push(`'${decision}' requires '${f}'`);
    if (!d.intent_ref && !d.params_hash) errors.push(`'${decision}' requires 'intent_ref' or 'params_hash' for intent binding`);
    if (!d.policy_refs || d.policy_refs.length === 0) errors.push(`'${decision}' requires at least one entry in 'policy_refs'`);
  } else if (decision === "deny") {
    if (!d.tool) errors.push("'deny' requires 'tool'");
    if (!d.reason) errors.push("'deny' requires 'reason'");
  } else if (decision === "revise") {
    if (!d.tool) errors.push("'revise' requires 'tool'");
    if (!d.reason) errors.push("'revise' requires 'reason'");
    if (!d.revalidate_if || d.revalidate_if.length === 0) errors.push("'revise' requires 'revalidate_if' conditions");
  }
  return [errors.length === 0, errors];
}

function verifyContiguity(records, seal) {
  const seqRecords = records.filter((r) => !r.sealed);
  const seqs = seqRecords.map((r) => r.seq).sort((a, b) => a - b);
  for (let i = 0; i < seqs.length; i++) if (seqs[i] !== i) return false;
  for (const r of seqRecords) if (r.running_count !== r.seq + 1) return false;
  if (seal && seqRecords.length !== Number(seal.total)) return false;
  return true;
}

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "governance_decision_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];

// 1. digest vectors
for (const v of d.vectors) {
  const got = refsFor(v);
  const checks = [
    ["params_hash", "expected_params_hash"], ["intent_digest", "expected_intent_digest"],
    ["intent_ref", "expected_intent_ref"], ["receipt_ref", "expected_receipt_ref"],
    ["decision_context_hash", "expected_decision_context_hash"],
  ];
  for (const [field, expKey] of checks) if (got[field] !== v[expKey]) fails.push(`${v.id}:${field}`);
}

// 2. normalization vectors
for (const nv of d.normalization_vectors) {
  if (canonicalize(nv.preimage) !== nv.expected_canonical_jcs) fails.push(`${nv.id}:jcs`);
  if ("sha256:" + createHash("sha256").update(Buffer.from(canonicalize(nv.preimage), "utf-8")).digest("hex") !== nv.expected_sha256) fails.push(`${nv.id}:sha256`);
}

// 3. negative vectors
for (const nv of d.negative_vectors) {
  const [ok, errors] = validateGovernanceDecision(nv.record);
  if (ok || !errors.some((e) => e.includes(nv.expect_error_contains))) fails.push(`${nv.id}:not-rejected`);
}

// 4. completeness vectors (contiguous complete; mid-gap + tail-drop caught; tail-unsealed = honest residual)
for (const cv of d.contiguity_vectors) {
  if (verifyContiguity(cv.records, cv.seal) !== cv.expected_complete) fails.push(cv.id);
}

const n = d.vectors.length * 5 + d.normalization_vectors.length * 2 + d.negative_vectors.length + d.contiguity_vectors.length;
if (fails.length) {
  console.error("governance_decision_v1: FAIL ->", fails.join(", "));
  process.exit(1);
}
console.log(`governance_decision_v1: ${n}/${n} PASS (Node == Python), byte-for-byte.`);
