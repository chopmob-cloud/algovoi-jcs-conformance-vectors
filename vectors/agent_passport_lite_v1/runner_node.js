#!/usr/bin/env node
// Independent verifier for the agent_passport_lite vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'agent_passport_lite_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const FIELDS = ['agent_id', 'issuer', 'scope', 'validity_window'];
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function passportRef(o) {
  const values = { agent_id: o.agent_id, issuer: o.issuer, scope: o.scope, validity_window: o.validity_window };
  for (const name of FIELDS) {
    if (typeof values[name] !== 'string' || values[name].length === 0) throw new Error(`${name} must be a non-empty string`);
  }
  return prefixed(values);
}

const fails = [];

for (const v of d.vectors) {
  const got = passportRef(v);
  if (got !== v.expected_passport_ref) fails.push(`${v.id}: ${got} != ${v.expected_passport_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { passportRef(n); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = passportRef(n);
    if (got === n.claimed_passport_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
// invariant: field-distinctness
const b = d.vectors[0];
const variants = [
  passportRef(b),
  passportRef({ ...b, agent_id: 'agent-002' }),
  passportRef({ ...b, scope: 'refunds' }),
  passportRef({ ...b, issuer: 'did:algo:other' }),
  passportRef({ ...b, validity_window: '2026-06-21/2026-12-21' }),
];
if (new Set(variants).size !== 5) fails.push('field-distinctness: a field change did not change passport_ref');
// invariant: reject empty field
let emptyOk = false;
try { passportRef({ ...b, agent_id: '' }); } catch { emptyOk = true; }
if (!emptyOk) fails.push('reject-empty: empty field accepted');

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- agent_passport_lite vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity.`);
