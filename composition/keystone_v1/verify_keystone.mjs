#!/usr/bin/env node
// Full keystone flow: end-to-end composition proof through the execution tier
// (Node + canonicalize, no package import). Recomputes passport_ref + mandate_ref
// + policy_bound_ref from raw fields, the decision_ref from the composed chain,
// the execution_ref over the EXACT decision_ref produced, and the trust_query_ref
// over the full ordered chain. Expected hashes were produced by the Python
// substrate, so a PASS here proves Python/Node parity.
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

const t = JSON.parse(readFileSync(join(HERE, 'keystone_trace.json'), 'utf-8'));
const { steps, decision: dec, execution: ex, cap } = t;

const passport = load('agent_passport_lite_v1');
const mandate = load('payment_mandate_lite_v1');
const policy = load('policy_binding_v1');
const guardrail = load('spend_guardrail_lite_v1');
const execution = load('execution_ref_v1');
const trust = load('composite_trust_query_lite_v1');

const sgAllow = find(guardrail.vectors, dec.source_vector);
const checks = [];

// 1. identity
let s = steps.passport_ref;
const agentRef = ref(s.inputs);
checks.push([
  'passport_ref recomputes, equals agent_passport_lite, is the agent_ref the decision binds',
  agentRef === s.expected && agentRef === find(passport.vectors, s.source_vector).expected_passport_ref && agentRef === sgAllow.agent_ref,
  agentRef,
]);

// 2. authority
s = steps.mandate_ref;
const mandateRef = ref(s.inputs);
checks.push([
  'mandate_ref recomputes, equals payment_mandate_lite, is the mandate_ref the decision binds',
  mandateRef === s.expected && mandateRef === find(mandate.vectors, s.source_vector).expected_mandate_ref && mandateRef === sgAllow.mandate_ref,
  mandateRef,
]);

// 3. policy
s = steps.policy_bound_ref;
const policyRef = ref(s.policy);
const policyBoundRef = ref({ policy_ref: policyRef, subject_ref: s.subject_ref });
checks.push([
  'policy_ref then policy_bound_ref recompute, equal policy_binding, are what the decision binds',
  policyRef === s.expected_policy_ref && policyBoundRef === s.expected
    && policyBoundRef === find(policy.vectors, s.source_vector).expected_policy_bound_ref && policyBoundRef === sgAllow.policy_bound_ref,
  policyBoundRef,
]);

// 4. decision
const decisionRef = ref({ agent_ref: agentRef, mandate_ref: mandateRef, policy_bound_ref: policyBoundRef, verdict: dec.verdict });
checks.push([
  'decision_ref (ALLOW) recomputed from the composed chain matches spend_guardrail_lite',
  decisionRef === dec.expected && decisionRef === sgAllow.expected_guardrail_ref,
  decisionRef,
]);

// 5. execution: bound to the EXACT decision_ref the chain produced
const executionRef = ref({ decision_ref: decisionRef, action_type: ex.action_type, scope: ex.scope, outcome: ex.outcome, executed_at_ms: ex.executed_at_ms });
checks.push([
  'execution_ref recomputes over the EXACT decision_ref the chain produced, equals execution_ref_v1 (consistency, not correlation)',
  executionRef === ex.expected && executionRef === find(execution.vectors, ex.source_vector).expected_execution_ref
    && execution.vectors[0].decision_ref === decisionRef,
  executionRef,
]);

// 6. cap: trust_query_ref over the full ordered chain incl execution_ref
const trustQueryRef = ref({ subject_refs: [agentRef, mandateRef, policyBoundRef, decisionRef, executionRef], trust_outcome: cap.trust_outcome });
checks.push([
  'trust_query_ref assesses [passport, mandate, policy, decision, execution] in order, equals tq-keystone, caps the flow',
  trustQueryRef === cap.expected && trustQueryRef === find(trust.vectors, cap.source_vector).expected_trust_query_ref,
  trustQueryRef,
]);

const width = 74;
console.log('='.repeat(width));
console.log('FULL KEYSTONE FLOW -- composition proof (Node parity)');
console.log('='.repeat(width));
let allOk = true;
checks.forEach(([desc, ok, value], i) => {
  allOk = allOk && ok;
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${value}`);
});
console.log('\n' + '-'.repeat(width));
if (allOk) {
  console.log(`PASS ${checks.length}/${checks.length} -- keystone composes end-to-end, byte-for-byte (Node == Python).`);
  process.exit(0);
}
console.log(`FAIL -- keystone composition broken.`);
process.exit(1);
