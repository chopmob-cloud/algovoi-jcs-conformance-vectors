/**
 * policy_binding_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the 3 policy_ref + 6 policy_bound_ref vectors + 3 rotation negatives + 2
 * invariants in policy_binding_v1.json. Additive policy-snapshot binding:
 *
 *   policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
 *   policy_bound_ref = "sha256:" + SHA-256(JCS({policy_ref, subject_ref}))
 *
 * Uses @algovoi/substrate's `canonicalize` (RFC 8785) for the JCS bytes. A PASS here
 * with the same expected hashes the Python runner checks proves byte-for-byte parity.
 *
 * Usage:
 *   npm install @algovoi/substrate
 *   node runner_node.js [policy_binding_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const prefixed = (v) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(v), "utf-8")).digest("hex");
const policyRef = (doc) => prefixed(doc);
const policyBoundRef = (subjectRef, pref) => prefixed({ policy_ref: pref, subject_ref: subjectRef });

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "policy_binding_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const policies = d.policies;
const fails = [];

for (const [name, exp] of Object.entries(d.expected_policy_ref)) {
  if (policyRef(policies[name]) !== exp) fails.push(`policy_ref[${name}]`);
}
for (const v of d.vectors) {
  if (policyBoundRef(v.subject_ref, policyRef(policies[v.policy])) !== v.expected_policy_bound_ref) fails.push(v.id);
}
for (const n of d.negative_rotation) {
  const sealed = policyBoundRef(n.subject_ref, policyRef(policies[n.sealed_under]));
  const reverif = policyBoundRef(n.subject_ref, policyRef(policies[n.verified_under]));
  if (sealed === reverif) fails.push(`${n.id} (rotation not detected)`);
}
if (policyRef(policies.P) !== policyRef(policies.P_shuffled)) fails.push("key-order-invariance");
const p = policyRef(policies.P);
const bound = Object.values(d.subjects).map((r) => policyBoundRef(r, p));
if (new Set(bound).size !== bound.length) fails.push("subject-binding");

const total = Object.keys(d.expected_policy_ref).length + d.vectors.length + d.negative_rotation.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log(`${total}/${total} PASS`);
