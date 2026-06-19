/**
 * compliance_gate_lite_v1 runner (Node.js / TypeScript reference impl).
 *
 * Validates the payer_ref + 3 verdict vectors + 5 negatives + 2 invariants in
 * compliance_gate_lite_v1.json:
 *
 *   payer_ref = "sha256:" + SHA-256(JCS({address, network}))            (no PII out)
 *   gate_ref  = "sha256:" + SHA-256(JCS({payer_ref, subject_ref, verdict}))
 *
 * Uses @algovoi/substrate's `canonicalize` (RFC 8785) for the JCS bytes, then
 * reconstructs the refs independently (SHA-256 + "sha256:" prefix). A PASS here with
 * the same expected hashes the Python runner checks proves byte-for-byte parity.
 *
 * Usage:
 *   npm install @algovoi/substrate
 *   node runner_node.js [compliance_gate_lite_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const VERDICTS = ["ALLOW", "REFER", "DENY"];
const REF_RE = /^sha256:[0-9a-f]{64}$/;
const prefixed = (v) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(v), "utf-8")).digest("hex");

function payerRef(network, address) {
  if (typeof network !== "string" || !network || typeof address !== "string" || !address) {
    throw new Error("network and address must be non-empty strings");
  }
  return prefixed({ address, network });
}
function gateRef(verdict, payerRefValue, subjectRef) {
  if (!VERDICTS.includes(verdict)) throw new Error("verdict out of set");
  for (const [name, val] of [["payer_ref", payerRefValue], ["subject_ref", subjectRef]]) {
    if (typeof val !== "string" || !REF_RE.test(val)) throw new Error(`${name} must be a sha256: ref`);
  }
  return prefixed({ payer_ref: payerRefValue, subject_ref: subjectRef, verdict });
}

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "compliance_gate_lite_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];

for (const [name, exp] of Object.entries(d.expected_payer_ref)) {
  const p = d.payers[name];
  if (payerRef(p.network, p.address) !== exp) fails.push(`payer_ref[${name}]`);
}
for (const v of d.vectors) {
  if (gateRef(v.verdict, v.payer_ref, v.subject_ref) !== v.expected_gate_ref) fails.push(v.id);
}
for (const n of d.negatives) {
  if (n.must === "reject") {
    let rejected = false;
    try { gateRef(n.verdict, n.payer_ref, n.subject_ref); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id} (accepted, should reject)`);
  } else {
    const got = gateRef(n.verdict, n.payer_ref, n.subject_ref);
    if (got === n.claimed_gate_ref) fails.push(`${n.id} (tamper not detected)`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(n.id);
  }
}
const p0 = d.vectors[0];
if (new Set(VERDICTS.map((w) => gateRef(w, p0.payer_ref, p0.subject_ref))).size !== 3) fails.push("verdict-distinctness");
let enumOk = false;
try { gateRef("BLOCK", p0.payer_ref, p0.subject_ref); } catch { enumOk = true; }
if (!enumOk) fails.push("closed-enum");

const total = Object.keys(d.expected_payer_ref).length + d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`);
  process.exit(1);
}
console.log(`${total}/${total} PASS`);
