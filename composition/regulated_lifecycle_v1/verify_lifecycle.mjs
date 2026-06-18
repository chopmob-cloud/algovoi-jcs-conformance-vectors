/*
 * Regulated Agentic Payment Lifecycle: end-to-end composition proof (Node/TS).
 *
 * Byte-for-byte twin of verify_lifecycle.py. Proves, offline and from
 * already-published vectors only, that the full regulated agentic-payment
 * lifecycle composes into one self-verifiable chain:
 *
 *   action_ref -> transition_hash (COMMITTED) -> settlement_ref
 *     -> retention_chain_ref -> binding_ref
 *
 * The four inputs to settlement_action_binding_v1 are byte-identical to the
 * published expected_* outputs of the four upstream sets, and recomputing the
 * binding with @algovoi/substrate reproduces the published reference.
 *
 * Run:  npm install   then   node verify_lifecycle.mjs
 *
 * Apache-2.0. (c) AlgoVoi. Retain NOTICE on redistribution.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { settlementActionBinding } from "@algovoi/substrate";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(__dirname, "..", "..", "vectors");
const load = (s) => JSON.parse(readFileSync(join(VECTORS, s, `${s}.json`), "utf-8"));

const aro = load("action_ref_exactly_once_v1");
const sat = load("settlement_attestation_v1");
const rc = load("retention_chain_v1");
const sab = load("settlement_action_binding_v1");

const actionRefs = new Set(
  aro.vectors.filter((v) => v.expected_action_ref).map((v) => v.expected_action_ref),
);
const committed = new Set(
  aro.vectors
    .filter((v) => v.expected_transition_hash && v.preimage && v.preimage.state === "COMMITTED")
    .map((v) => v.expected_transition_hash),
);
const settlements = new Set(
  sat.vectors.filter((v) => v.expected_content_hash).map((v) => v.expected_content_hash),
);
const chains = new Set(
  rc.vectors.filter((v) => v.expected_chain_ref).map((v) => v.expected_chain_ref),
);

const ref = sab.vectors.find((v) => v.vector_id === "sab-v1-001");
const pre = ref.preimage;

const REG = {
  action_ref: "MiCA Art 80 (transaction reconstruction: stable action identity)",
  transition_hash: "DORA Art 14 (operational integrity: exactly-once COMMITTED state)",
  settlement_ref: "AMLR Art 56 (record retention: the settled payment attested)",
  retention_chain_ref: "MiCA Art 80 / DORA Art 14 (tamper-evident audit position)",
  binding_ref: "MiCA 80 + DORA 14 + AMLR 56 (the four bound into one auditable record)",
};

const recomputed = settlementActionBinding({
  action_ref: pre.action_ref,
  transition_hash: pre.transition_hash,
  settlement_ref: pre.settlement_ref,
  retention_chain_ref: pre.retention_chain_ref,
});

const checks = [
  ["action_ref traces to action_ref_exactly_once_v1.expected_action_ref",
    actionRefs.has(pre.action_ref), pre.action_ref, REG.action_ref],
  ["transition_hash traces to a COMMITTED action_ref_exactly_once_v1 output",
    committed.has(pre.transition_hash), pre.transition_hash, REG.transition_hash],
  ["settlement_ref traces to settlement_attestation_v1.expected_content_hash",
    settlements.has(pre.settlement_ref), pre.settlement_ref, REG.settlement_ref],
  ["retention_chain_ref traces to retention_chain_v1.expected_chain_ref",
    chains.has(pre.retention_chain_ref), pre.retention_chain_ref, REG.retention_chain_ref],
  ["binding_ref recomputed from the composed chain matches the published reference",
    recomputed === ref.expected_binding_ref, recomputed, REG.binding_ref],
];

const width = 72;
console.log("=".repeat(width));
console.log("REGULATED AGENTIC PAYMENT LIFECYCLE -- composition proof (Node)");
console.log("composed from published vectors only; no new vectors, no new hash");
console.log("=".repeat(width));

let allOk = true;
checks.forEach(([desc, ok, value, reg], i) => {
  allOk = allOk && ok;
  console.log(`\n[${i + 1}] ${ok ? "PASS" : "FAIL"}  ${desc}`);
  console.log(`      value : ${value}`);
  console.log(`      maps  : ${reg}`);
});

console.log("\n" + "-".repeat(width));
if (allOk) {
  console.log("RESULT: PASS -- the full lifecycle composes end-to-end, byte-for-byte.");
  console.log(`        final binding_ref = ${ref.expected_binding_ref}`);
  process.exit(0);
} else {
  console.log("RESULT: FAIL -- composition broken; see failed checks above.");
  process.exit(1);
}
