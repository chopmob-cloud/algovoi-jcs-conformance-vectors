#!/usr/bin/env node
// Independent verifier for the refund_receipt_lite vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'refund_receipt_lite_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const RESULTS = ['FULL', 'PARTIAL', 'REJECTED'];
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function refundRef(o) {
  if (typeof o.subject_ref !== 'string' || o.subject_ref.length === 0) throw new Error('subject_ref must be a non-empty string');
  if (!RESULTS.includes(o.refund_result)) throw new Error('refund_result must be one of the closed enum');
  if (typeof o.refund_amount !== 'string' || o.refund_amount.length === 0) throw new Error('refund_amount must be a non-empty string');
  return prefixed({ refund_amount: o.refund_amount, refund_result: o.refund_result, subject_ref: o.subject_ref });
}

const fails = [];
for (const v of d.vectors) {
  const got = refundRef(v);
  if (got !== v.expected_refund_ref) fails.push(`${v.id}: ${got} != ${v.expected_refund_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { refundRef(n); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = refundRef(n);
    if (got === n.claimed_refund_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
const b = d.vectors[0];
const variants = [
  refundRef(b),
  refundRef({ ...b, refund_result: 'PARTIAL' }),
  refundRef({ ...b, refund_amount: '2000' }),
  refundRef({ ...b, subject_ref: 'sha256:792a5b43e9df0fc460d6bf99d6357afafbdcf910ef1e81a340e3581bc27109cf' }),
];
if (new Set(variants).size !== 4) fails.push('field-distinctness: a field change did not change refund_ref');
let enumOk = false;
try { refundRef({ ...b, refund_result: 'REFUNDED' }); } catch { enumOk = true; }
if (!enumOk) fails.push('reject-invalid: a result outside the closed enum was accepted');
let emptyOk = false;
try { refundRef({ ...b, subject_ref: '' }); } catch { emptyOk = true; }
if (!emptyOk) fails.push('reject-empty: empty subject_ref accepted');

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- refund_receipt_lite vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity.`);
