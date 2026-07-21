// Generic preimage runner (Node / canonicalize). Usage: node runner_node.js <set.json>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
const data = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let p=0,q=0;
for (const v of data.vectors) {
  if (!v.preimage) continue;
  const c = canonicalize(v.preimage); const buf = Buffer.from(c, "utf-8");
  const b64 = buf.toString("base64"); const dg = createHash("sha256").update(buf).digest("hex");
  const eh = v.expected_content_sha256 ?? v.expected_transition_hash ?? v.expected_action_ref;
  if (b64===v.expected_jcs_bytes_b64 && dg===eh) p++; else { q++; console.log("  FAIL "+v.vector_id); }
}
console.log(`${p}/${p+q} PASS`); process.exit(q?1:0);
