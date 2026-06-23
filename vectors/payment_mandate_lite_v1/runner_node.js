#!/usr/bin/env node
// Independent verifier for the payment_mandate_lite vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'payment_mandate_lite_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const FIELDS = ['payer', 'cap', 'period', 'revocation_state'];
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function mandateRef(o) {
  const values = { cap: o.cap, payer: o.payer, period: o.period, revocation_state: o.revocation_state };
  for (const name of FIELDS) {
    if (typeof values[name] !== 'string' || values[name].length === 0) throw new Error(`${name} must be a non-empty string`);
  }
  return prefixed(values);
}

const fails = [];

for (const v of d.vectors) {
  const got = mandateRef(v);
  if (got !== v.expected_mandate_ref) fails.push(`${v.id}: ${got} != ${v.expected_mandate_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { mandateRef(n); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = mandateRef(n);
    if (got === n.claimed_mandate_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
// invariant: field-distinctness
const b = d.vectors[0];
const variants = [
  mandateRef(b),
  mandateRef({ ...b, payer: '0x00000000000000000000000000000000C0FFEE11' }),
  mandateRef({ ...b, cap: '2000' }),
  mandateRef({ ...b, period: 'weekly' }),
  mandateRef({ ...b, revocation_state: 'revoked' }),
];
if (new Set(variants).size !== 5) fails.push('field-distinctness: a field change did not change mandate_ref');
// invariant: reject empty field
let emptyOk = false;
try { mandateRef({ ...b, payer: '' }); } catch { emptyOk = true; }
if (!emptyOk) fails.push('reject-empty: empty field accepted');

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- payment_mandate_lite vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity.`);
