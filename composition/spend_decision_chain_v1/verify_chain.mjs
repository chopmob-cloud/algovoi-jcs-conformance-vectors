#!/usr/bin/env node
// Open pre-payment decision chain: end-to-end composition proof (Node + canonicalize, no package import).
// Recomputes passport_ref + mandate_ref + policy_bound_ref from raw fields, checks each equals its
// published lite-set output and is the reference Spend Guardrail binds, then recomputes guardrail_ref
// from the composed chain and matches the published spend_guardrail_lite_v1 reference (ALLOW + DENY).
// The expected hashes were produced by the Python substrate, so a PASS here proves Python/Node parity.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, '..', '..', 'vectors');

const ref = (o) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(o), 'utf-8')).digest('hex');
const load = (s) => JSON.parse(readFileSync(join(VECTORS, s, `${s}.json`), 'utf-8'));
const find = (arr, id) => arr.find((v) => v.id === id);

const trace = JSON.parse(readFileSync(join(HERE, 'chain_trace.json'), 'utf-8'));
const steps = trace.steps;
const dec = trace.decision;

const passport = load('agent_passport_lite_v1');
const mandate = load('payment_mandate_lite_v1');
const policy = load('policy_binding_v1');
const guardrail = load('spend_guardrail_lite_v1');
const cancellation = load('cancellation_receipt_lite_v1');
const refund = load('refund_receipt_lite_v1');

const sgAllow = find(guardrail.vectors, dec.verdicts.ALLOW.source_vector);
const sgDeny = find(guardrail.vectors, dec.verdicts.DENY.source_vector);

const checks = [];

// 1. identity
let s = steps.passport_ref;
const agentRef = ref(s.inputs);
const pPub = find(passport.vectors, s.source_vector).expected_passport_ref;
checks.push([
  'passport_ref recomputes from raw identity fields, equals agent_passport_lite output, and is the agent_ref Spend Guardrail binds',
  agentRef === s.expected && agentRef === pPub && agentRef === sgAllow.agent_ref && agentRef === sgDeny.agent_ref,
  agentRef,
]);

// 2. authority
s = steps.mandate_ref;
const mandateRef = ref(s.inputs);
const mPub = find(mandate.vectors, s.source_vector).expected_mandate_ref;
checks.push([
  'mandate_ref recomputes from raw authority fields, equals payment_mandate_lite output, and is the mandate_ref Spend Guardrail binds',
  mandateRef === s.expected && mandateRef === mPub && mandateRef === sgAllow.mandate_ref && mandateRef === sgDeny.mandate_ref,
  mandateRef,
]);

// 3. policy (two-step)
s = steps.policy_bound_ref;
const policyRef = ref(s.policy);
const policyBoundRef = ref({ policy_ref: policyRef, subject_ref: s.subject_ref });
const pbPub = find(policy.vectors, s.source_vector).expected_policy_bound_ref;
checks.push([
  'policy_ref then policy_bound_ref recompute from the raw policy + subject, equal the policy_binding output, and are the policy_bound_ref Spend Guardrail binds',
  policyRef === s.expected_policy_ref &&
    policyBoundRef === s.expected && policyBoundRef === pbPub &&
    policyBoundRef === sgAllow.policy_bound_ref && policyBoundRef === sgDeny.policy_bound_ref,
  policyBoundRef,
]);

// 4. decision (ALLOW + DENY)
for (const [verdict, sgVec] of [['ALLOW', sgAllow], ['DENY', sgDeny]]) {
  const g = ref({ agent_ref: agentRef, mandate_ref: mandateRef, policy_bound_ref: policyBoundRef, verdict });
  const exp = dec.verdicts[verdict].expected;
  checks.push([
    `guardrail_ref (${verdict}) recomputed from the composed chain matches the published spend_guardrail_lite_v1 reference`,
    g === exp && g === sgVec.expected_guardrail_ref,
    g,
  ]);
}

// 5. lifecycle: cancellation_ref binds the SAME mandate_ref the chain used
const lc = trace.lifecycle.cancellation;
const cancellationRef = ref({ cancellation_reason: lc.cancellation_reason, mandate_ref: mandateRef });
const cPub = find(cancellation.vectors, lc.source_vector).expected_cancellation_ref;
checks.push([
  'cancellation_ref recomputes over the SAME mandate_ref the chain used, equals the published cancellation_receipt_lite reference, and closes the lifecycle on the authority',
  cancellationRef === lc.expected && cancellationRef === cPub,
  cancellationRef,
]);

// 6. lifecycle: refund_ref refunds the SAME guardrail_ref (ALLOW) the chain produced
const rf = trace.lifecycle.refund;
const refundRef = ref({ refund_amount: rf.refund_amount, refund_result: rf.refund_result, subject_ref: rf.subject_ref });
const rPub = find(refund.vectors, rf.source_vector).expected_refund_ref;
checks.push([
  'refund_ref recomputes over the SAME guardrail_ref the ALLOW decision produced, equals the published refund_receipt_lite reference, and closes the lifecycle after settlement',
  refundRef === rf.expected && refundRef === rPub && rf.subject_ref === dec.verdicts.ALLOW.expected,
  refundRef,
]);

const width = 74;
console.log('='.repeat(width));
console.log('OPEN PRE-PAYMENT DECISION CHAIN -- composition proof (Node parity)');
console.log('='.repeat(width));
let allOk = true;
checks.forEach(([desc, ok, value], i) => {
  allOk = allOk && ok;
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${value}`);
});
console.log('\n' + '-'.repeat(width));
if (allOk) {
  console.log(`PASS ${checks.length}/${checks.length} -- chain composes end-to-end, byte-for-byte (Python/Node parity).`);
  process.exit(0);
}
console.log(`FAIL (${checks.filter(([, ok]) => !ok).length}/${checks.length}) -- composition broken.`);
process.exit(1);
