#!/usr/bin/env node
// Independent verifier for the delegation_ref vector set (Node + canonicalize, no package import).
// The expected hashes were produced by the Python package, so a PASS here proves byte-for-byte
// Python/TS parity. Recompute is the test.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'delegation_ref_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

const REF_RE = /^sha256:[0-9a-f]{64}$/;
const prefixed = (v) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(v), 'utf-8')).digest('hex');

function delegationRef(env) {
  const obj = {};
  for (const name of ['delegator_id', 'delegate_id', 'scope']) {
    const val = env[name];
    if (typeof val !== 'string' || val.length === 0) throw new Error(`${name} must be a non-empty string`);
    obj[name] = val;
  }
  for (const name of ['not_before_ms', 'not_after_ms']) {
    const val = env[name];
    if (typeof val !== 'number' || !Number.isInteger(val) || val < 0) throw new Error(`${name} must be a non-negative integer`);
    obj[name] = val;
  }
  if (obj.not_after_ms <= obj.not_before_ms) throw new Error('not_after_ms must be greater than not_before_ms');
  const prev = env.prev_delegation_ref ?? '';
  if (prev !== '' && !REF_RE.test(prev)) throw new Error('prev_delegation_ref must be "" or a sha256 64-hex ref');
  obj.prev_delegation_ref = prev;
  return prefixed({
    delegate_id: obj.delegate_id, delegator_id: obj.delegator_id,
    not_after_ms: obj.not_after_ms, not_before_ms: obj.not_before_ms,
    prev_delegation_ref: obj.prev_delegation_ref, scope: obj.scope,
  });
}

function verifyChain(envelopes) {
  const refs = []; let prev = '';
  for (let i = 0; i < envelopes.length; i++) {
    if ((envelopes[i].prev_delegation_ref ?? '') !== prev) throw new Error(`chain break at link ${i}`);
    const ref = delegationRef(envelopes[i]); refs.push(ref); prev = ref;
  }
  return refs;
}

const fails = [];

for (const v of d.positives) {
  let got;
  try { got = delegationRef(v.envelope); } catch (e) { fails.push(`${v.id}: unexpected reject (${e.message})`); continue; }
  if (got !== v.expected_delegation_ref) fails.push(`${v.id}: ${got} != ${v.expected_delegation_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try { delegationRef(n.envelope); } catch { rejected = true; }
    if (!rejected) fails.push(`${n.id}: malformed envelope ACCEPTED (should reject)`);
  } else {
    let got;
    try { got = delegationRef(n.envelope); } catch (e) { fails.push(`${n.id}: unexpected reject (${e.message})`); continue; }
    if (got === n.claimed_delegation_ref) fails.push(`${n.id}: tamper NOT detected (recompute == claimed)`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
// invariant: key-order
const root = d.root_envelope;
const reordered = Object.fromEntries(Object.entries(root).reverse());
if (delegationRef(root) !== delegationRef(reordered)) fails.push('key-order-invariance: ref(root) != ref(reordered)');
// invariant: chain integrity
try {
  const chain = verifyChain([d.root_envelope, d.chain_envelope]);
  if (chain[0] !== d.root_delegation_ref || chain[1] !== d.chain_delegation_ref) fails.push('chain-integrity: unexpected refs');
} catch (e) { fails.push(`chain-integrity: verifyChain raised (${e.message})`); }

const total = d.positives.length + d.negatives.length + 2;
if (fails.length) {
  console.log(`FAIL (${fails.length}/${total}):`);
  for (const f of fails) console.log('  -', f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- delegation_ref vectors reproduce byte-for-byte (TS via canonicalize); Python/TS parity; tamper detected; malformed bound rejected; key-order + chain integrity.`);
