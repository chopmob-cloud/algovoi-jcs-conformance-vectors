/**
 * settlement_attestation_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates 8 vectors + 5 pair invariants + 3 chain invariants in
 * settlement_attestation_v1.json using @algovoi/substrate (>=0.3.0).
 *
 * Anchors to IETF draft-hopley-x402-settlement-attestation-00.
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
const VECTORS_FILE = join(__dirname, "settlement_attestation_v1.json");

function getNested(obj, path) {
  return path.split(".").reduce((acc, k) => acc?.[k], obj);
}

// settlement_round rule, reimplemented from the contract (see SCHEMA.md).
// Present -> MUST be a positive integer; JSON boolean/string are rejected.
// Mirrors substrate2.receipts._common.require_positive_int.
function roundOk(value) {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function main() {
  const data = JSON.parse(readFileSync(VECTORS_FILE, "utf-8"));
  const vectors = Object.fromEntries(data.vectors.map((v) => [v.vector_id, v]));
  const failures = [];

  console.log("settlement_attestation_v1 runner (Node / @algovoi/substrate)");
  console.log(
    `vectors: ${data.vectors.length}, pair invariants: ${data.pair_invariants.length}, chain invariants: ${data.chain_invariants.length}`,
  );
  console.log();

  for (const v of data.vectors) {
    const payload = v.receipt ?? v.row;
    const canon = canonicalize(payload);
    const canonBytes = Buffer.from(canon, "utf-8");

    const actualB64 = canonBytes.toString("base64");
    if (actualB64 !== v.expected_jcs_bytes_b64) {
      failures.push(`${v.vector_id}: JCS bytes b64 mismatch`);
      console.log(`  ${v.vector_id}: FAIL (b64 mismatch)`);
      continue;
    }

    const digest = createHash("sha256").update(canonBytes).digest("hex");
    const expected = v.expected_content_hash ?? v.expected_row_content_hash;
    const label = v.receipt ? "content_hash" : "row_content_hash";

    if (digest !== expected) {
      failures.push(`${v.vector_id}: SHA-256 mismatch (${label})`);
      console.log(`  ${v.vector_id}: FAIL (SHA-256 mismatch)`);
      continue;
    }

    if (v.receipt && "settlement_round" in v.receipt) {
      if (!roundOk(v.receipt.settlement_round)) {
        failures.push(`${v.vector_id}: positive vector carries invalid settlement_round`);
        console.log(`  ${v.vector_id}: FAIL (invalid settlement_round in positive vector)`);
        continue;
      }
    }

    if (v.receipt) {
      console.log(
        `  ${v.vector_id}: PASS  result=${v.receipt.settlement_result.padEnd(18)} ${label.slice(0, 14)}=${digest.slice(0, 16)}...`,
      );
    } else {
      console.log(
        `  ${v.vector_id}: PASS  row=${v.row.row_number}     ${label.slice(0, 14)}=${digest.slice(0, 16)}...`,
      );
    }
  }
  console.log();

  for (const pair of data.pair_invariants) {
    const left = vectors[pair.left].expected_content_hash;
    const right = vectors[pair.right].expected_content_hash;
    if (pair.type === "different_hash_from") {
      if (left === right) {
        failures.push(`${pair.id}: pair invariant violated`);
        console.log(`  ${pair.id}: FAIL`);
      } else {
        console.log(`  ${pair.id}: PASS  ${pair.left} != ${pair.right}`);
      }
    }
  }
  console.log();

  for (const ch of data.chain_invariants) {
    if (ch.type === "field_equals") {
      const v = vectors[ch.vector];
      const actual = getNested(v, ch.field);
      if (actual !== ch.value) {
        failures.push(`${ch.id}: field_equals violated`);
        console.log(`  ${ch.id}: FAIL`);
      } else {
        console.log(`  ${ch.id}: PASS  ${ch.field} = expected`);
      }
    } else if (ch.type === "field_equals_other") {
      const lv = vectors[ch.left_vector];
      const rv = vectors[ch.right_vector];
      const lf = getNested(lv, ch.left_field);
      const rf = getNested(rv, ch.right_field);
      if (lf !== rf) {
        failures.push(`${ch.id}: linkage violated`);
        console.log(`  ${ch.id}: FAIL`);
      } else {
        console.log(
          `  ${ch.id}: PASS  ${ch.left_vector}.${ch.left_field} = ${ch.right_vector}.${ch.right_field}`,
        );
      }
    }
  }
  console.log();

  const rejectVectors = data.settlement_round_reject_vectors ?? [];
  for (const rv of rejectVectors) {
    const bad = rv.receipt?.settlement_round;
    if (roundOk(bad)) {
      failures.push(`${rv.vector_id}: reject vector was ACCEPTED (escape): ${JSON.stringify(bad)}`);
      console.log(`  ${rv.vector_id}: FAIL (accepted bad settlement_round ${JSON.stringify(bad)})`);
    } else {
      console.log(`  ${rv.vector_id}: PASS  refused settlement_round=${JSON.stringify(bad)} (${rv.bad_kind})`);
    }
  }
  console.log();

  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} issue(s)`);
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }

  console.log(
    `PASS: ${data.vectors.length} vectors + ${data.pair_invariants.length} pair invariants + ${data.chain_invariants.length} chain invariants + ${rejectVectors.length} settlement_round reject vectors validated against @algovoi/substrate.`,
  );
}

main();
