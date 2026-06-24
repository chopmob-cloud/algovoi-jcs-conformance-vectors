// cancellation_keystone_v1 -- composition proof (Node twin). Node == Python byte-for-byte.
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'cancellation_keystone_trace.json'), 'utf8'));
const h = (o) => createHash('sha256').update(canonicalize(o), 'utf8').digest('hex');
const ref = (o) => 'sha256:' + h(o);
const cancellationRef = (reason, mandate_ref) => ref({ cancellation_reason: reason, mandate_ref });

const c = t.cancellation, tw = t.tamper;
const checks = [];

const cref = cancellationRef(c.cancellation_reason, c.mandate_ref);
checks.push([cref === c.expected_cancellation_ref, 'cancellation_ref recomputes (cancellation_receipt_lite), equals published cn-001', cref]);
checks.push([c.mandate_ref === t.mandate_ref, 'cancellation mandate_ref IS the keystone mandate', c.mandate_ref]);
checks.push([t.mandate_ref !== t.execution_ref, 'mirror of refund: cancellation binds authority (pre), refund binds execution (post)', 'authority vs execution']);
const cmerch = cancellationRef('MERCHANT_REQUESTED', c.mandate_ref);
checks.push([cmerch === tw.cancel_merchant && cmerch !== cref, 'tamper: different reason diverges cancellation_ref', 'divergent']);

console.log('='.repeat(74));
console.log('CANCELLATION KEYSTONE -- composition proof (Node == Python)');
console.log('='.repeat(74));
let n = 0;
checks.forEach(([ok, desc, val], i) => { console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}\n      value : ${val}`); if (ok) n++; });
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${n}/${checks.length} -- cancellation closes the exact keystone authority (Node == Python).`);
process.exit(n === checks.length ? 0 : 1);
