// Differential adversarial substrate -- Node canon probe (canonicalize@^1).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

const d = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const lines = [];
for (const c of d.cases) {
  let v;
  try {
    const val = JSON.parse(c.raw);          // native parser, default settings
    try {
      const cs = canonicalize(val);
      if (cs === undefined) throw new Error("uncanonicalizable");
      v = "h:" + createHash("sha256").update(Buffer.from(cs, "utf-8")).digest("hex");
    } catch { v = "R:canon"; }
  } catch { v = "R:parse"; }
  lines.push(`${c.id}\t${v}`);
}
process.stdout.write(lines.join("\n") + "\n");
