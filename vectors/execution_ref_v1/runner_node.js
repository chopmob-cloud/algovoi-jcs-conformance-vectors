/**
 * execution_ref_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the decision-bound execution-evidence primitive:
 *
 *   execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope,
 *                                           outcome, executed_at_ms}))
 *
 * A PASS here against the same expected hashes the Python runner checks proves
 * byte-for-byte Python+TypeScript parity. Checks: positive construction; closed
 * outcome enum; each negative recomputes DIFFERENT; an RFC 3339 string timestamp
 * is REJECTED (Substrate Rule 2); cross-set composition vs spend_decision_v1.
 *
 *   npm install @algovoi/substrate
 *   node runner_node.js [execution_ref_v1.json]
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { executionRef, ExecutionRefError } from "@algovoi/substrate";

const ref = (v) =>
  executionRef({
    decision_ref: v.decision_ref,
    action_type: v.action_type,
    scope: v.scope,
    outcome: v.outcome,
    executed_at_ms: v.executed_at_ms,
  });

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "execution_ref_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];
let total = 0;

// 1. positive construction
for (const v of d.vectors) {
  total += 1;
  if (ref(v) !== v.expected_execution_ref) fails.push(v.id);
}

// 2. closed outcome enum
total += 1;
const v0 = d.vectors[0];
let enumOk = false;
try {
  executionRef({ decision_ref: v0.decision_ref, action_type: "p", scope: "s", outcome: "DONE", executed_at_ms: 0 });
} catch (e) {
  if (e instanceof ExecutionRefError) enumOk = true;
}
if (!enumOk) fails.push("closed-enum");

// 3 + 4. negatives
for (const n of d.negatives) {
  total += 1;
  if (n.must === "differ") {
    const got = ref(n);
    if (got === n.claimed_execution_ref || got !== n.recomputes_to) fails.push(n.id);
  } else if (n.must === "reject") {
    let rejected = false;
    try { ref(n); } catch (e) { if (e instanceof ExecutionRefError) rejected = true; }
    if (!rejected) fails.push(`${n.id} (accepted, should reject)`);
  }
}

// 5. cross-set composition vs spend_decision_v1
total += 1;
const sd = JSON.parse(readFileSync(join(here, "..", "spend_decision_v1", "spend_decision_v1.json"), "utf-8"));
const sdRefs = new Set(sd.vectors.map((x) => x.expected_decision_ref));
const used = d.vectors.map((v) => v.decision_ref);
if (!used.every((r) => sdRefs.has(r))) fails.push("cross-set-composition");

if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log(`${total}/${total} PASS`);
