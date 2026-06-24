// settlement_binding_v1 -- composition proof (Node twin).
// Recomputes execution_ref, the settlement attestation content_hash, a
// retention-chain head, and execution_binding from raw fields, asserting each
// equals the published trace value. The expected values were produced by the
// Python substrate, so Node matching them proves Python/Node byte-for-byte parity.
// (Node + canonicalize, no package import.)  npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'binding_trace.json'), 'utf8'));

const h = (obj) => createHash('sha256').update(canonicalize(obj), 'utf8').digest('hex');
const ref = (obj) => 'sha256:' + h(obj);

const ex = t.execution, sa = t.settlement_attestation, rc = t.retention_chain,
      eb = t.execution_binding, tw = t.tamper;
const checks = [];

const executionRef = ref({
  decision_ref: ex.decision_ref, action_type: ex.action_type, scope: ex.scope,
  outcome: ex.outcome, executed_at_ms: ex.executed_at_ms,
});
checks.push([executionRef === ex.expected_execution_ref,
  'execution_ref recomputes from committed-execution fields, equals the keystone execution_ref', executionRef]);

checks.push([sa.receipt.settled_payment_ref === ex.expected_execution_ref,
  'settlement attestation settled_payment_ref IS the execution_ref (settled payment binds to the executed action)',
  sa.receipt.settled_payment_ref]);

const settlementContent = h(sa.receipt);
const settlementRef = 'sha256:' + settlementContent;
checks.push([settlementContent === sa.expected_content_hash && settlementRef === sa.expected_settlement_ref,
  'settlement attestation content_hash recomputes (settlement_attestation_v1 shape)', settlementRef]);

const retentionChainRef = ref(rc.row);
checks.push([rc.row.content_hash === settlementContent && retentionChainRef === rc.expected_retention_chain_ref,
  'retention-chain head recomputes over the settlement attestation (audit-chain row shape)', retentionChainRef]);

const bindingRef = ref({
  execution_ref: executionRef, settlement_ref: settlementRef, retention_chain_ref: retentionChainRef,
});
checks.push([bindingRef === eb.expected_binding_ref,
  'execution_binding recomputes over (execution_ref, settlement_ref, retention_chain_ref) into one accountability reference', bindingRef]);

const failedRef = ref({
  decision_ref: ex.decision_ref, action_type: ex.action_type, scope: ex.scope,
  outcome: 'FAILED', executed_at_ms: ex.executed_at_ms,
});
const reversedSettlementRef = 'sha256:' + h({ ...sa.receipt, settlement_result: 'REVERSED' });
const tamperOk = failedRef === tw.failed_execution_ref && failedRef !== executionRef
  && reversedSettlementRef === tw.reversed_settlement_ref && reversedSettlementRef !== settlementRef;
checks.push([tamperOk,
  'tamper witnesses diverge: FAILED execution and REVERSED settlement both change the chain (byte-load-bearing)', 'divergent']);

console.log('='.repeat(74));
console.log('SETTLEMENT BINDING -- composition proof (Node == Python)');
console.log('='.repeat(74));
let npass = 0;
checks.forEach(([ok, desc, val], i) => {
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${val}`);
  if (ok) npass++;
});
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${npass}/${checks.length} -- settled payment binds to the executed action (Node == Python).`);
process.exit(npass === checks.length ? 0 : 1);
