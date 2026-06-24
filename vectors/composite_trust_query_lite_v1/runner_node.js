#!/usr/bin/env node
// Independent verifier for the composite_trust_query_lite vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'composite_trust_query_lite_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const OUTCOMES = ['TRUSTED', 'PROVISIONAL', 'INSUFFICIENT_EVIDENCE', 'UNTRUSTED'];
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function trustQueryRef(o) {
  if (!Array.isArray(o.subject_refs) || o.subject_refs.length === 0) throw new Error('subject_refs must be a non-empty list');
  if (!o.subject_refs.every((s) => typeof s === 'string' && s.length > 0)) throw new Error('each subject_ref must be a non-empty string');
  if (!OUTCOMES.includes(o.trust_outcome)) throw new Error('trust_outcome must be one of the closed enum');
  return prefixed({ subject_refs: o.subject_refs, trust_outcome: o.trust_outcome });
}

const fails = [];
for (const v of d.vectors) {
  const got = trustQueryRef(v);
  if (got !== v.expected_trust_query_ref) fails.push(`${v.id}: ${got} != ${v.expected_trust_query_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { trustQueryRef(n); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = trustQueryRef(n);
    if (got === n.claimed_trust_query_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
const b = d.vectors[0];
const variants = [
  trustQueryRef(b),
  trustQueryRef({ ...b, trust_outcome: 'PROVISIONAL' }),
  trustQueryRef({ ...b, subject_refs: [...b.subject_refs].reverse() }),
  trustQueryRef({ ...b, subject_refs: b.subject_refs.slice(0, -1) }),
];
if (new Set(variants).size !== 4) fails.push('distinctness: a verdict/order/membership change did not change trust_query_ref');
let enumOk = false;
try { trustQueryRef({ ...b, trust_outcome: 'OK' }); } catch { enumOk = true; }
if (!enumOk) fails.push('reject-invalid: an outcome outside the closed enum was accepted');
for (const bad of [[], ['']]) {
  let rej = false;
  try { trustQueryRef({ ...b, subject_refs: bad }); } catch { rej = true; }
  if (!rej) fails.push(`reject-empty: subject_refs ${JSON.stringify(bad)} accepted`);
}

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- composite_trust_query_lite vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity.`);
