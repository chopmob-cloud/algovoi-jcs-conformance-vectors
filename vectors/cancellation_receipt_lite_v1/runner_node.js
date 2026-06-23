#!/usr/bin/env node
// Independent verifier for the cancellation_receipt_lite vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'cancellation_receipt_lite_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const REASONS = ['USER_REQUESTED', 'MERCHANT_REQUESTED', 'COMPLIANCE_TERMINATED', 'EXPIRED'];
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function cancellationRef(o) {
  if (typeof o.mandate_ref !== 'string' || o.mandate_ref.length === 0) throw new Error('mandate_ref must be a non-empty string');
  if (!REASONS.includes(o.cancellation_reason)) throw new Error('cancellation_reason must be one of the closed enum');
  return prefixed({ cancellation_reason: o.cancellation_reason, mandate_ref: o.mandate_ref });
}

const fails = [];
for (const v of d.vectors) {
  const got = cancellationRef(v);
  if (got !== v.expected_cancellation_ref) fails.push(`${v.id}: ${got} != ${v.expected_cancellation_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { cancellationRef(n); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = cancellationRef(n);
    if (got === n.claimed_cancellation_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
const b = d.vectors[0];
const variants = [
  cancellationRef(b),
  cancellationRef({ ...b, cancellation_reason: 'MERCHANT_REQUESTED' }),
  cancellationRef({ ...b, mandate_ref: 'sha256:fefcf604aa85994cd8058b960b0472122d54f81fc48efa394bb0c488599a7615' }),
];
if (new Set(variants).size !== 3) fails.push('field-distinctness: a field change did not change cancellation_ref');
let enumOk = false;
try { cancellationRef({ ...b, cancellation_reason: 'CANCELLED' }); } catch { enumOk = true; }
if (!enumOk) fails.push('reject-invalid: a reason outside the closed enum was accepted');
let emptyOk = false;
try { cancellationRef({ ...b, mandate_ref: '' }); } catch { emptyOk = true; }
if (!emptyOk) fails.push('reject-empty: empty mandate_ref accepted');

const total = d.vectors.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- cancellation_receipt_lite vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity.`);
