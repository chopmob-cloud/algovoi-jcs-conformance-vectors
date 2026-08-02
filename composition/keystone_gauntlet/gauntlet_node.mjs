// Keystone L3 fail-closed gauntlet -- Node impl (canonicalize@^1).
// Independent reimplementation of decision_audit_ref (no algovoi import):
// "sha256:" + SHA-256(JCS({decision_ref, passport_credential_ref, mandate_ref,
// policy_bound_ref, [screen_binding_ref]})), sha256: ref-form enforced.
// Usage: node gauntlet_node.mjs <keystone_decision_audit_v1.json>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

const REF = /^sha256:[0-9a-f]{64}$/;

function decisionAuditRef(dr, pcr, mr, pbr, sbr) {
  const obj = { decision_ref: dr, passport_credential_ref: pcr, mandate_ref: mr, policy_bound_ref: pbr };
  for (const [name, val] of Object.entries(obj)) {
    if (typeof val !== "string" || !REF.test(val)) throw new Error(`${name} must be sha256: ref`);
  }
  if (sbr !== undefined && sbr !== null) {
    if (typeof sbr !== "string" || !REF.test(sbr)) throw new Error("screen_binding_ref must be sha256: ref");
    obj.screen_binding_ref = sbr;
  }
  const canon = Buffer.from(canonicalize(obj), "utf-8");
  return "sha256:" + createHash("sha256").update(canon).digest("hex");
}

const d = JSON.parse(readFileSync(process.argv[2], "utf-8"));
let ok = 0;
const fails = [];
for (const v of d.vectors) {
  const got = decisionAuditRef(v.decision_ref, v.passport_credential_ref, v.mandate_ref, v.policy_bound_ref, v.screen_binding_ref);
  if (got === v.expected_decision_audit_ref) ok++; else fails.push(`${v.id}: accept-mismatch`);
}
for (const n of d.negatives) {
  if (n.must === "reject") {
    try { decisionAuditRef(n.decision_ref, n.passport_credential_ref, n.mandate_ref, n.policy_bound_ref, n.screen_binding_ref); fails.push(`${n.id}: invalid ACCEPTED`); }
    catch { ok++; }
  } else {
    const got = decisionAuditRef(n.decision_ref, n.passport_credential_ref, n.mandate_ref, n.policy_bound_ref, n.screen_binding_ref);
    if (got !== n.claimed_decision_audit_ref) ok++; else fails.push(`${n.id}: tamper NOT detected`);
  }
}
const v0 = d.vectors[0];
const a = decisionAuditRef(v0.decision_ref, v0.passport_credential_ref, v0.mandate_ref, v0.policy_bound_ref, v0.screen_binding_ref);
const b = decisionAuditRef(v0.decision_ref, v0.passport_credential_ref, v0.mandate_ref, v0.policy_bound_ref, null);
if (a !== b) ok++; else fails.push("screen-distinctness collision");
try { decisionAuditRef("bad", v0.passport_credential_ref, v0.mandate_ref, v0.policy_bound_ref); fails.push("malformed-ref accepted"); }
catch { ok++; }

const total = d.vectors.length + d.negatives.length + 2;
for (const f of fails) console.log("  FAIL", f);
console.log(`KEYSTONE-GAUNTLET node ${ok}/${total}`);
process.exit(ok === total && fails.length === 0 ? 0 : 1);
