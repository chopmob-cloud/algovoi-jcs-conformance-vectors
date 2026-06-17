/**
 * settlement_action_binding_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the 6 vectors + 5 pair invariants in settlement_action_binding_v1.json.
 * Composes action_ref_exactly_once_v1, settlement_attestation_v1 and retention_chain_v1
 * into one post-settlement accountability binding:
 *
 *   binding_ref = "sha256:" + SHA-256(JCS({action_ref, transition_hash,
 *                                          settlement_ref, retention_chain_ref}))
 *
 * Uses @algovoi/substrate's `canonicalize` (RFC 8785) for the JCS bytes, then
 * reconstructs binding_ref independently (SHA-256 + "sha256:" prefix). This is an
 * independent JS reconstruction of the binding primitive — the dedicated
 * `settlementActionBinding` helper lands in @algovoi/substrate 0.4.0.
 *
 * Usage:
 *   npm install @algovoi/substrate@^0.3.0
 *   node runner_node.js
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize } from "@algovoi/substrate";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_FILE = join(__dirname, "settlement_action_binding_v1.json");

function main() {
  const data = JSON.parse(readFileSync(VECTORS_FILE, "utf-8"));
  const vectors = Object.fromEntries(data.vectors.map((v) => [v.vector_id, v]));
  const failures = [];

  console.log("settlement_action_binding_v1 runner (Node / @algovoi/substrate)");
  console.log(`vectors: ${data.vectors.length}, pair invariants: ${data.pair_invariants.length}`);
  console.log();

  for (const v of data.vectors) {
    const canon = canonicalize(v.preimage);
    const canonBytes = Buffer.from(canon, "utf-8");
    if (canonBytes.toString("base64") !== v.expected_jcs_bytes_b64) {
      failures.push(`${v.vector_id}: JCS bytes b64 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (b64 mismatch)`);
      continue;
    }
    const digest = createHash("sha256").update(canonBytes).digest("hex");
    if (digest !== v.expected_content_sha256) {
      failures.push(`${v.vector_id}: bare SHA-256 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (SHA-256 mismatch)`);
      continue;
    }
    const bindingRef = `sha256:${digest}`;
    if (bindingRef !== v.expected_binding_ref) {
      failures.push(`${v.vector_id}: binding_ref reconstruction mismatch`);
      console.log(`  ${v.vector_id}: FAIL (binding_ref reconstruction)`);
      continue;
    }
    console.log(`  ${v.vector_id}: PASS  ${v.pair_group.padEnd(10)} ${bindingRef}`);
  }
  console.log();

  const ref = (vid) => vectors[vid].expected_binding_ref;
  for (const pair of data.pair_invariants) {
    const lh = ref(pair.left), rh = ref(pair.right);
    if (pair.type === "different_hash_from") {
      if (lh === rh) { failures.push(`${pair.id}: different_hash_from violated`); console.log(`  ${pair.id}: FAIL (collide)`); }
      else console.log(`  ${pair.id}: PASS  ${pair.left} != ${pair.right}`);
    } else if (pair.type === "same_hash_as") {
      if (lh !== rh) { failures.push(`${pair.id}: same_hash_as violated`); console.log(`  ${pair.id}: FAIL (differ)`); }
      else console.log(`  ${pair.id}: PASS  ${pair.left} == ${pair.right} (stable)`);
    }
  }

  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} issue(s)`);
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
  console.log(`PASS: ${data.vectors.length} vectors + ${data.pair_invariants.length} pair invariants validated (JCS via @algovoi/substrate).`);
}

main();
