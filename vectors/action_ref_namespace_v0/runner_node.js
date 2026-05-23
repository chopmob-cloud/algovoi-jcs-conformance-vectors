/**
 * action_ref_namespace_v0 runner (Node.js / TypeScript reference impl).
 *
 * Validates the 8 vectors + 4 pair invariants in action_ref_namespace_v0.json
 * using @algovoi/substrate (>=0.2.1) on npm.
 *
 * Usage:
 *   npm install @algovoi/substrate@^0.2.1
 *   node runner_node.js
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize, actionRef } from "@algovoi/substrate";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_FILE = join(__dirname, "action_ref_namespace_v0.json");

function main() {
  const data = JSON.parse(readFileSync(VECTORS_FILE, "utf-8"));
  const vectors = Object.fromEntries(data.vectors.map((v) => [v.vector_id, v]));
  const failures = [];

  console.log("action_ref_namespace_v0 runner (Node / @algovoi/substrate)");
  console.log(
    `vectors: ${data.vectors.length}, pair invariants: ${data.pair_invariants.length}`,
  );
  console.log();

  // Per-vector validation
  for (const v of data.vectors) {
    // 1. canonicalise preimage
    const jcs = canonicalize(v.preimage);
    const jcsBytes = Buffer.from(jcs, "utf-8");

    // 2. base64 of JCS bytes
    const actualB64 = jcsBytes.toString("base64");
    if (actualB64 !== v.expected_jcs_bytes_b64) {
      failures.push(`${v.vector_id}: JCS bytes b64 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (b64 mismatch)`);
      continue;
    }

    // 3. SHA-256 of JCS bytes
    const digest = createHash("sha256").update(jcsBytes).digest("hex");
    if (digest !== v.expected_action_ref) {
      failures.push(`${v.vector_id}: SHA-256 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (SHA-256 mismatch)`);
      continue;
    }

    // 4. cross-check via the substrate's actionRef primitive
    const ar = actionRef({
      agent_id: v.preimage.agent_id,
      action_type: v.preimage.action_type,
      scope: v.preimage.scope,
      timestamp_ms: v.preimage.timestamp_ms,
    });
    if (ar !== v.expected_action_ref) {
      failures.push(`${v.vector_id}: actionRef() mismatch`);
      console.log(`  ${v.vector_id}: FAIL (actionRef primitive mismatch)`);
      continue;
    }

    console.log(
      `  ${v.vector_id}: PASS  scope='${v.scope}'  digest=${digest.slice(0, 16)}...`,
    );
  }
  console.log();

  // Pair invariants
  for (const pair of data.pair_invariants) {
    const left = vectors[pair.left].expected_action_ref;
    const right = vectors[pair.right].expected_action_ref;
    if (pair.type === "different_hash_from") {
      if (left === right) {
        failures.push(`${pair.id}: pair invariant violated`);
        console.log(`  ${pair.id}: FAIL (digests collide)`);
      } else {
        console.log(`  ${pair.id}: PASS  ${pair.left} != ${pair.right}`);
      }
    } else {
      failures.push(`${pair.id}: unknown pair type '${pair.type}'`);
    }
  }

  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} issue(s)`);
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }

  console.log(
    `PASS: ${data.vectors.length} vectors + ${data.pair_invariants.length} pair invariants validated against @algovoi/substrate.`,
  );
}

main();
