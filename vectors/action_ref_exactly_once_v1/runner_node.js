/**
 * action_ref_exactly_once_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the 6 vectors + 5 pair invariants in action_ref_exactly_once_v1.json
 * using @algovoi/substrate (>=0.3.0). Supersets action_ref_transactional_v0 — adds
 * the PENDING/COMMITTED/REVERSED lifecycle plus the SKIP-on-retry idempotency
 * (`same_hash_as`) and action_ref replay-binding (`different_hash_from`) invariants.
 *
 * Usage:
 *   npm install @algovoi/substrate@^0.3.0
 *   node runner_node.js
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { actionRef, transitionHash, canonicalize } from "@algovoi/substrate";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_FILE = join(__dirname, "action_ref_exactly_once_v1.json");

function main() {
  const data = JSON.parse(readFileSync(VECTORS_FILE, "utf-8"));
  const vectors = Object.fromEntries(data.vectors.map((v) => [v.vector_id, v]));
  const failures = [];

  console.log("action_ref_exactly_once_v1 runner (Node / @algovoi/substrate)");
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

    let expected, label, recomputed;
    if (v.pair_group === "identity") {
      expected = v.expected_action_ref;
      label = "action_ref";
      recomputed = actionRef({
        agent_id: v.preimage.agent_id,
        action_type: v.preimage.action_type,
        scope: v.preimage.scope,
        timestamp_ms: v.preimage.timestamp_ms,
      });
      if (recomputed !== expected) {
        failures.push(`${v.vector_id}: actionRef primitive mismatch`);
        console.log(`  ${v.vector_id}: FAIL (actionRef primitive)`);
        continue;
      }
    } else {
      expected = v.expected_transition_hash;
      label = "transition_hash";
      recomputed = transitionHash({
        action_ref: v.preimage.action_ref,
        state: v.preimage.state,
        transition_timestamp_ms: v.preimage.transition_timestamp_ms,
        authority_verified_at_ms: v.preimage.authority_verified_at_ms,
        revocation_check_at_ms: v.preimage.revocation_check_at_ms,
      });
      if (recomputed !== expected) {
        failures.push(`${v.vector_id}: transitionHash primitive mismatch`);
        console.log(`  ${v.vector_id}: FAIL (transitionHash primitive)`);
        continue;
      }
    }

    if (digest !== expected) {
      failures.push(`${v.vector_id}: SHA-256 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (SHA-256 mismatch)`);
      continue;
    }
    const stateOrId = v.preimage.state ?? "<identity>";
    console.log(`  ${v.vector_id}: PASS  ${label} state='${String(stateOrId).padEnd(10)}' digest=${digest.slice(0, 16)}...`);
  }
  console.log();

  const h = (vid) => vectors[vid].expected_transition_hash ?? vectors[vid].expected_action_ref;
  for (const pair of data.pair_invariants) {
    const lh = h(pair.left), rh = h(pair.right);
    if (pair.type === "different_hash_from") {
      if (lh === rh) { failures.push(`${pair.id}: different_hash_from violated`); console.log(`  ${pair.id}: FAIL (collide)`); }
      else console.log(`  ${pair.id}: PASS  ${pair.left} != ${pair.right}`);
    } else if (pair.type === "same_hash_as") {
      if (lh !== rh) { failures.push(`${pair.id}: same_hash_as violated`); console.log(`  ${pair.id}: FAIL (differ)`); }
      else console.log(`  ${pair.id}: PASS  ${pair.left} == ${pair.right} (idempotent)`);
    }
  }

  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} issue(s)`);
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
  console.log(`PASS: ${data.vectors.length} vectors + ${data.pair_invariants.length} pair invariants validated against @algovoi/substrate.`);
}

main();
