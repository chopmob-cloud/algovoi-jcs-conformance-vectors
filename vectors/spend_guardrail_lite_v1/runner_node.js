/**
 * spend_guardrail_lite_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the 2 verdict vectors + 6 negatives + 2 invariants in
 * spend_guardrail_lite_v1.json:
 *
 *   guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
 *
 * Uses @algovoi/substrate's `canonicalize` (RFC 8785) for the JCS bytes, then
 * reconstructs the ref independently (SHA-256 + "sha256:" prefix). A PASS here with
 * the same expected hashes the Python runner checks proves byte-for-byte parity.
 *
 * Usage:
 *   npm install @algovoi/substrate
 *   node runner_node.js [spend_guardrail_lite_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const VERDICTS = ["ALLOW", "DENY"];
const REF_RE = /^sha256:[0-9a-f]{64}$/;
const prefixed = (v) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(v), "utf-8")).digest("hex");

function guardrailRef(verdict, agentRef, mandateRef, policyBoundRef) {
  if (!VERDICTS.includes(verdict)) throw new Error("verdict out of set");
  for (const [name, val] of [["agent_ref", agentRef], ["mandate_ref", mandateRef], ["policy_bound_ref", policyBoundRef]]) {
    if (typeof val !== "string" || !REF_RE.test(val)) throw new Error(`${name} must be a sha256: ref`);
  }
  return prefixed({ agent_ref: agentRef, mandate_ref: mandateRef, policy_bound_ref: policyBoundRef, verdict });
}

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "spend_guardrail_lite_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];

for (const v of d.vectors) {
  if (guardrailRef(v.verdict, v.agent_ref, v.mandate_ref, v.policy_bound_ref) !== v.expected_guardrail_ref) fails.push(v.id);
}
for (const n of d.negatives) {
  if (n.must === "reject") {
    let rejected = false;
    try { guardrailRef(n.verdict, n.agent_ref, n.mandate_ref, n.policy_bound_ref); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id} (accepted, should reject)`);
  } else {
    const got = guardrailRef(n.verdict, n.agent_ref, n.mandate_ref, n.policy_bound_ref);
    if (got === n.claimed_guardrail_ref) fails.push(`${n.id} (tamper not detected)`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(n.id);
  }
}
const v0 = d.vectors[0];
if (new Set(VERDICTS.map((w) => guardrailRef(w, v0.agent_ref, v0.mandate_ref, v0.policy_bound_ref))).size !== VERDICTS.length) fails.push("verdict-distinctness");
let enumOk = false;
try { guardrailRef("BLOCK", v0.agent_ref, v0.mandate_ref, v0.policy_bound_ref); } catch { enumOk = true; }
if (!enumOk) fails.push("closed-enum");

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log(`${total}/${total} PASS`);
