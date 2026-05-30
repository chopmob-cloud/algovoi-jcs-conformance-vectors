// PEF v1 vector runner -- Node.js / canonicalize@1.0.8 (@algovoi/pef dep)
//
// Validates sha256(JCS(receipt)) == expected_receipt_hash and
//           sha256(JCS(preimage)) == expected_frame_id
//
// Usage: node runner_node.js <vector_set_json>

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

function sha256Jcs(obj) {
  const canon = canonicalize(obj);
  const buf   = Buffer.from(canon, "utf-8");
  return {
    b64:    buf.toString("base64"),
    digest: "sha256:" + createHash("sha256").update(buf).digest("hex"),
  };
}

const data = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let pass = 0, fail = 0;

for (const v of data.vectors) {
  const rr = sha256Jcs(v.receipt);
  const pr = sha256Jcs(v.preimage);

  const receiptOk  = rr.b64    === v.expected_receipt_jcs_bytes_b64 &&
                     rr.digest === v.expected_receipt_hash;
  const preimageOk = pr.b64    === v.expected_preimage_jcs_bytes_b64 &&
                     pr.digest === v.expected_frame_id;

  if (receiptOk && preimageOk) {
    pass++;
  } else {
    fail++;
    if (!receiptOk)  console.log(`  FAIL ${v.vector_id} receipt_hash`);
    if (!preimageOk) console.log(`  FAIL ${v.vector_id} frame_id (got ${pr.digest})`);
  }
}

console.log(`${pass}/${pass + fail} PASS`);
process.exit(fail ? 1 : 0);
