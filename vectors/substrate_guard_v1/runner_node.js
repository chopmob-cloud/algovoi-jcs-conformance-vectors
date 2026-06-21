/**
 * substrate_guard_v1 runner (Node.js / TypeScript reference impl).
 *
 *   profile_ref = "sha256:" + SHA-256(JCS(profile))
 *   guard(value, profile) -> accept, or reject with a named code, BEFORE canonicalization
 *
 * Independent reimplementation against the published @algovoi/substrate canonicalizer. A PASS here
 * against the same expected profile_refs and reject codes the Python runner checks proves byte-for-byte
 * Python+TypeScript parity: two independent impls enforce the same structural bounds identically.
 *
 *   npm install @algovoi/substrate
 *   node runner_node.js [substrate_guard_v1.json]
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "@algovoi/substrate";

const SAFE_INT = 2 ** 53 - 1;
const canonBytes = (v) => Buffer.from(canonicalize(v), "utf-8");
const profileRef = (p) => "sha256:" + createHash("sha256").update(canonBytes(p)).digest("hex");

class GuardError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function guard(value, p) {
  let nodes = 0;
  const walk = (v, depth) => {
    nodes += 1;
    if (nodes > p.max_total_nodes) throw new GuardError("REJECT_OVER_NODES");
    if (depth > p.max_depth) throw new GuardError("REJECT_OVER_DEPTH");
    if (v === null || typeof v === "boolean") return;
    if (typeof v === "number") {
      if (p.number_safety && (!Number.isFinite(v) || Math.abs(v) > SAFE_INT)) throw new GuardError("REJECT_UNSAFE_NUMBER");
    } else if (typeof v === "string") {
      if (v.length > p.max_string_length) throw new GuardError("REJECT_OVER_STRING");
    } else if (Array.isArray(v)) {
      if (v.length > p.max_array_length) throw new GuardError("REJECT_OVER_ARRAY");
      for (const item of v) walk(item, depth + 1);
    } else if (typeof v === "object") {
      const keys = Object.keys(v);
      if (keys.length > p.max_object_keys) throw new GuardError("REJECT_TOO_MANY_KEYS");
      for (const k of keys) {
        if (k.length > p.max_string_length) throw new GuardError("REJECT_OVER_STRING");
        walk(v[k], depth + 1);
      }
    } else {
      throw new GuardError("REJECT_UNSAFE_NUMBER");
    }
  };
  walk(value, 1);
  if (canonBytes(value).length > p.max_bytes) throw new GuardError("REJECT_OVER_SIZE");
  return true;
}

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, "substrate_guard_v1.json");
const d = JSON.parse(readFileSync(vf, "utf-8"));
const fails = [];

if (profileRef(d.default_profile) !== d.expected_default_profile_ref) fails.push("default_profile_ref");
for (const v of d.profile_ref_vectors) {
  if (profileRef(v.profile) !== v.expected_profile_ref) fails.push(v.id);
}
for (const a of d.accept) {
  try { guard(a.value, a.profile); } catch (e) { fails.push(`${a.id} (rejected ${e.code}, should accept)`); }
}
for (const r of d.reject) {
  try { guard(r.value, r.profile); fails.push(`${r.id} (accepted, should reject ${r.expected_code})`); }
  catch (e) { if (e.code !== r.expected_code) fails.push(`${r.id} (got ${e.code}, want ${r.expected_code})`); }
}
const snap = d.default_profile;
const reordered = {};
for (const k of Object.keys(snap).reverse()) reordered[k] = snap[k];
if (profileRef(reordered) !== d.expected_default_profile_ref) fails.push("inv-key-order");

const total = 1 + d.profile_ref_vectors.length + d.accept.length + d.reject.length + 1;
if (fails.length) { console.log(`FAIL (${fails.length}/${total}): ${fails.join(", ")}`); process.exit(1); }
console.log(`${total}/${total} PASS`);
