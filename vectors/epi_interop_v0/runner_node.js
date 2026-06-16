// epi_interop_v0 runner -- Node.js / canonicalize@1.0.8
//
// Validates sha256(JCS(input)) == frame_id for each vector
//
// Usage: node runner_node.js
//   (run from epi_interop_v0/ directory; reads epi_interop_v0.json)

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import canonicalize from "canonicalize";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "epi_interop_v0.json"), "utf-8"));

let pass = 0, fail = 0;

for (const v of data.vectors) {
  const canon = canonicalize(v.input);
  const buf   = Buffer.from(canon, "utf-8");
  const b64   = buf.toString("base64");
  const ref   = "sha256:" + createHash("sha256").update(buf).digest("hex");

  const b64Ok = b64 === v.expected_jcs_bytes_b64;
  const refOk = ref === v.frame_id;

  if (b64Ok && refOk) {
    pass++;
  } else {
    fail++;
    if (!b64Ok) console.log(`  FAIL ${v.id} jcs_bytes_b64 mismatch`);
    if (!refOk) console.log(`  FAIL ${v.id} frame_id (got ${ref})`);
  }
}

console.log(`${pass}/${pass + fail} PASS`);
process.exit(fail ? 1 : 0);
