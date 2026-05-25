// Generic vector-set runner (Node / canonicalize@3.0.0 via @algovoi/substrate).
//
// Usage: node runner_node.js <vector_set_json>

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";

const data = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let pass = 0, fail = 0;
for (const v of data.vectors) {
  const payload = v.receipt ?? v.response ?? v.row;
  if (!payload) continue;
  const canon = canonicalize(payload);
  const canonBytes = Buffer.from(canon, "utf-8");
  const b64 = canonBytes.toString("base64");
  const digest = createHash("sha256").update(canonBytes).digest("hex");
  const expectedHash = v.expected_content_hash ?? v.expected_row_content_hash;
  if (b64 === v.expected_jcs_bytes_b64 && digest === expectedHash) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL ${v.vector_id}`);
  }
}
console.log(`${pass}/${pass + fail} PASS`);
process.exit(fail ? 1 : 0);
