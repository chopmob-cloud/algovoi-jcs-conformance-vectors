// pef_keystone_v1 -- composition proof (Node twin).
// Recomputes execution_ref, binding_ref (execution_binding), the PEF receipt_hash
// and frame_id from raw fields, asserting each equals the published trace value.
// Expected values were produced by the Python substrate, so Node matching them
// proves Python/Node byte-for-byte parity. (Node + canonicalize, no package import.)
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'pef_keystone_trace.json'), 'utf8'));

const h = (obj) => createHash('sha256').update(canonicalize(obj), 'utf8').digest('hex');
const ref = (obj) => 'sha256:' + h(obj);

const kf = t.keystone_fact, ex = kf.execution, frame = t.pef_frame, tw = t.tamper;
const checks = [];

const executionRef = ref({
  decision_ref: ex.decision_ref, action_type: ex.action_type, scope: ex.scope,
  outcome: ex.outcome, executed_at_ms: ex.executed_at_ms,
});
checks.push([executionRef === ex.expected_execution_ref,
  'execution_ref recomputes, equals the keystone golden', executionRef]);

const bindingRef = ref({
  execution_ref: executionRef, settlement_ref: kf.settlement_ref, retention_chain_ref: kf.retention_chain_ref,
});
checks.push([bindingRef === kf.expected_binding_ref,
  'binding_ref recomputes (execution_binding), equals the settlement_binding_v1 golden', bindingRef]);

const rc = frame.receipt;
checks.push([rc.execution_ref === executionRef && rc.binding_ref === bindingRef,
  'PEF receipt carries the exact keystone fact (execution_ref + binding_ref)', rc.binding_ref]);

const receiptHash = 'sha256:' + h(rc);
checks.push([receiptHash === frame.expected_receipt_hash,
  'receipt_hash recomputes (PEF pins the keystone payload; pef_v1 shape)', receiptHash]);

const pre = { ...frame.preimage, receipt: rc, receipt_hash: receiptHash };
const frameId = 'sha256:' + h(pre);
checks.push([frameId === frame.expected_frame_id,
  'frame_id recomputes over the preimage (PEF frame_id; byte-identical to pef_v1)', frameId]);

const tampered = { ...rc, binding_ref: 'sha256:' + 'f'.repeat(64) };
const tRh = 'sha256:' + h(tampered);
const tFid = 'sha256:' + h({ ...pre, receipt: tampered, receipt_hash: tRh });
const tamperOk = tRh === tw.tampered_receipt_hash && tRh !== receiptHash
  && tFid === tw.tampered_frame_id && tFid !== frameId;
checks.push([tamperOk,
  'tamper: flipping the carried binding_ref diverges receipt_hash, which diverges frame_id', 'divergent']);

console.log('='.repeat(74));
console.log('PEF KEYSTONE -- composition proof (Node == Python)');
console.log('='.repeat(74));
let npass = 0;
checks.forEach(([ok, desc, val], i) => {
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${val}`);
  if (ok) npass++;
});
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${npass}/${checks.length} -- PEF commits to the exact keystone position (Node == Python).`);
process.exit(npass === checks.length ? 0 : 1);
