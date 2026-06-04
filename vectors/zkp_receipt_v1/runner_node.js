// ZKP receipt v1 conformance vector runner (Node.js / @algovoi/substrate).
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalize } from "../../_attestations/2026-05-25-8-impl-5-format-cross-validation/node_modules/@algovoi/substrate/dist/index.js";

const data = JSON.parse(readFileSync("zkp_receipt_v1.json", "utf-8"));
let pass = 0, fail = 0;
for (const v of data.vectors) {
  const payload = v.receipt;
  const canon = canonicalize(payload);
  const canonBytes = Buffer.from(canon, "utf-8");
  const b64 = canonBytes.toString("base64");
  const digest = createHash("sha256").update(canonBytes).digest("hex");
  if (b64 === v.expected_jcs_bytes_b64 && digest === v.expected_content_hash) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL ${v.vector_id}`);
  }
}
console.log(`${pass}/${pass + fail} PASS`);
process.exit(fail ? 1 : 0);
