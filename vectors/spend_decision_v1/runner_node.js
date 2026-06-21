/**
 * spend_decision_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the commercial Spend Guardrail decision chain construction:
 *
 *   decision_ref    = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
 *   prev_entry_hash = "sha256:" + SHA-256(JCS(previous_decision_payload))
 *
 * verdict is the closed enum {ALLOW, DENY, REFER}. A PASS here against the same expected hashes the
 * Python runner checks proves byte-for-byte Python+TypeScript parity. ALLOW/DENY recompute identically
 * to spend_guardrail_lite_v1 (the open lite tier composes into the commercial product).
 *
 *   npm install @algovoi/substrate
 *   node runner_node.js [spend_decision_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const VERDICTS = ["ALLOW", "DENY", "REFER"];
const prefixed = (v) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(v), "utf-8")).digest("hex");

function decisionRef(verdict, agentRef, mandateRef, policyBoundRef) {
  if (!VERDICTS.includes(verdict)) throw new Error("verdict out of set");
  return prefixed({ agent_ref: agentRef, mandate_ref: mandateRef, policy_bound_ref: policyBoundRef, verdict });
}

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "spend_decision_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];

// 1. decision_ref construction (incl REFER)
for (const v of d.vectors) {
  if (decisionRef(v.verdict, v.agent_ref, v.mandate_ref, v.policy_bound_ref) !== v.expected_decision_ref) fails.push(v.id);
}

// 2. closed enum
const v0 = d.vectors[0];
let enumOk = false;
try { decisionRef("BLOCK", v0.agent_ref, v0.mandate_ref, v0.policy_bound_ref); } catch { enumOk = true; }
if (!enumOk) fails.push("closed-enum");

// 3. chain linkage: prev_entry_hash == JCS hash of the prior payload; entry_hash recomputes
let prev = null;
for (const c of d.chain) {
  if ((c.payload.prev_entry_hash ?? null) !== prev) fails.push(`chain-prev@${c.seq}`);
  const h = prefixed(c.payload);
  if (h !== c.entry_hash) fails.push(`chain-hash@${c.seq}`);
  prev = h;
}

const total = d.vectors.length + 1 + d.chain.length;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log(`${total}/${total} PASS`);
