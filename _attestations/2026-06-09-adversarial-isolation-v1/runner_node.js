// Generic input runner (Node / canonicalize). Claim 1 (input bytes) only.
// Usage: node runner_node.js <set.json>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

const data = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let p = 0, q = 0;
for (const v of data.vectors) {
  if (v.input === undefined) continue;
  const buf = Buffer.from(canonicalize(v.input), "utf-8");
  if (buf.toString("base64") === v.input_jcs_bytes_b64 && createHash("sha256").update(buf).digest("hex") === v.input_content_sha256) p++;
  else { q++; console.log("  FAIL " + v.vector_id); }
}
console.log(`${p}/${p + q} PASS`);
process.exit(q ? 1 : 0);
