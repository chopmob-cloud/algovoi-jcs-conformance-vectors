// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
// Retention Chain v1 vector runner -- Node.js / canonicalize@1.0.8
//
// Validates sha256(JCS(preimage)) == expected_chain_ref
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
  const { b64, digest } = sha256Jcs(v.preimage);
  const b64Ok = b64    === v.expected_jcs_bytes_b64;
  const refOk = digest === v.expected_chain_ref;
  if (b64Ok && refOk) {
    pass++;
  } else {
    fail++;
    if (!b64Ok) console.log(`  FAIL ${v.vector_id} jcs_bytes_b64 mismatch`);
    if (!refOk) console.log(`  FAIL ${v.vector_id} chain_ref (got ${digest})`);
  }
}

console.log(`${pass}/${pass + fail} PASS`);
process.exit(fail ? 1 : 0);
