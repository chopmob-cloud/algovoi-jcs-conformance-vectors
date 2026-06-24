// refund_execution_v1 -- composition proof (Node twin).
// Recomputes execution_ref and refund_ref from raw fields, asserting each equals the
// published trace value. Expected values were produced by the Python substrate, so Node
// matching them proves Python/Node byte-for-byte parity. (Node + canonicalize.)
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'refund_execution_trace.json'), 'utf8'));

const h = (obj) => createHash('sha256').update(canonicalize(obj), 'utf8').digest('hex');
const ref = (obj) => 'sha256:' + h(obj);
const refundRef = (subject_ref, refund_result, refund_amount) =>
  ref({ refund_amount, refund_result, subject_ref });

const ex = t.execution, rf = t.refund, ad = t.anchor_distinctness, tw = t.tamper;
const checks = [];

const executionRef = ref({
  decision_ref: ex.decision_ref, action_type: ex.action_type, scope: ex.scope,
  outcome: ex.outcome, executed_at_ms: ex.executed_at_ms,
});
checks.push([executionRef === ex.expected_execution_ref,
  'execution_ref recomputes, equals the keystone golden', executionRef]);

checks.push([rf.subject_ref === executionRef,
  'refund subject_ref IS the execution_ref (refund of the committed payment)', rf.subject_ref]);

const rref = refundRef(rf.subject_ref, rf.refund_result, rf.refund_amount);
checks.push([rref === rf.expected_refund_ref,
  'refund_ref recomputes (refund_receipt_lite_v1 shape)', rref]);

const rrefDec = refundRef(t.decision_ref, rf.refund_result, rf.refund_amount);
checks.push([rrefDec === ad.refund_over_decision && rrefDec !== rref,
  'anchor distinctness: refund-over-execution != refund-over-decision (anchor byte-load-bearing)', rrefDec]);

const failedRef = ref({
  decision_ref: ex.decision_ref, action_type: ex.action_type, scope: ex.scope,
  outcome: 'FAILED', executed_at_ms: ex.executed_at_ms,
});
const rrefFailed = refundRef(failedRef, rf.refund_result, rf.refund_amount);
const tamperOk = failedRef === tw.failed_execution_ref && failedRef !== executionRef
  && rrefFailed === tw.refund_over_failed && rrefFailed !== rref;
checks.push([tamperOk,
  'tamper: FAILED execution diverges execution_ref, which diverges the refund', 'divergent']);

console.log('='.repeat(74));
console.log('REFUND EXECUTION -- composition proof (Node == Python)');
console.log('='.repeat(74));
let npass = 0;
checks.forEach(([ok, desc, val], i) => {
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${val}`);
  if (ok) npass++;
});
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${npass}/${checks.length} -- refund binds to the executed payment (Node == Python).`);
process.exit(npass === checks.length ? 0 : 1);
