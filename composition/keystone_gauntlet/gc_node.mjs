// Keystone L3 gauntlet -- guard_context, Node impl (canonicalize).
// Usage: node gc_node.mjs <keystone_guard_context_v1.json>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

const REF = /^sha256:[0-9a-f]{64}$/;

function guardContextRef(ts, policy_ref, mandate_ref, passport_credential_ref) {
  if (typeof ts !== "number" || !Number.isInteger(ts) || ts < 0) throw new Error("guard_timestamp_ms must be non-negative int");
  for (const [n, v] of [["policy_ref", policy_ref], ["mandate_ref", mandate_ref], ["passport_credential_ref", passport_credential_ref]]) {
    if (typeof v !== "string" || !REF.test(v)) throw new Error(`${n} must be sha256: ref`);
  }
  const obj = { canon_version: "jcs-rfc8785-v1", type: "guard_context", guard_timestamp_ms: ts, policy_ref, mandate_ref, passport_credential_ref };
  return "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(obj), "utf-8")).digest("hex");
}

const d = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let ok = 0; const fails = [];
for (const v of d.vectors) {
  const got = guardContextRef(v.guard_timestamp_ms, v.policy_ref, v.mandate_ref, v.passport_credential_ref);
  got === v.expected_guard_context_ref ? ok++ : fails.push(`${v.id}: accept-mismatch`);
}
for (const n of d.negatives) {
  if (n.must === "reject") {
    try { guardContextRef(n.guard_timestamp_ms, n.policy_ref, n.mandate_ref, n.passport_credential_ref); fails.push(`${n.id}: invalid ACCEPTED`); }
    catch { ok++; }
  } else {
    const got = guardContextRef(n.guard_timestamp_ms, n.policy_ref, n.mandate_ref, n.passport_credential_ref);
    got !== n.claimed_guard_context_ref ? ok++ : fails.push(`${n.id}: tamper NOT detected`);
  }
}
const v0 = d.vectors[0];
const a = guardContextRef(v0.guard_timestamp_ms, v0.policy_ref, v0.mandate_ref, v0.passport_credential_ref);
const b = guardContextRef(v0.guard_timestamp_ms + 1, v0.policy_ref, v0.mandate_ref, v0.passport_credential_ref);
a !== b ? ok++ : fails.push("moment-distinctness collision");
try { guardContextRef(1720000000000.5, v0.policy_ref, v0.mandate_ref, v0.passport_credential_ref); fails.push("float-ts accepted"); }
catch { ok++; }

const total = d.vectors.length + d.negatives.length + 2;
for (const f of fails) console.log("  FAIL", f);
console.log(`KEYSTONE-GAUNTLET-GC node ${ok}/${total}`);
process.exit(ok === total && fails.length === 0 ? 0 : 1);
