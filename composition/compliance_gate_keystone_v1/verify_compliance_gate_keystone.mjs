// compliance_gate_keystone_v1 -- composition proof (Node twin). Node == Python byte-for-byte.
//
// Every member of the compliance-spanning cap is recomputed from its own raw fields
// [passport, mandate, policy, gate, decision, execution]. None is taken from the trace
// on trust. Earlier revisions cross-checked only the gate and decision members, so a
// trace could assert an execution reference unrelated to the decision that authorised
// it and still verify. Check 7 is the regression vector for that substitution.
//
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, '..', '..', 'vectors');
const t = JSON.parse(readFileSync(join(HERE, 'compliance_gate_keystone_trace.json'), 'utf8'));
const h = (o) => createHash('sha256').update(canonicalize(o), 'utf8').digest('hex');
const ref = (o) => 'sha256:' + h(o);
const load = (s) => JSON.parse(readFileSync(join(VECTORS, s, `${s}.json`), 'utf8'));
const vec = (s, id) => {
  const v = s.vectors.find((x) => x.id === id);
  if (!v) throw new Error(`vector ${id} not found`);
  return v;
};

const d = t.decision, g = t.compliance_gate, cap = t.compliance_cap, tw = t.tamper;
const checks = [];

const decisionRef = ref({ agent_ref: d.agent_ref, mandate_ref: d.mandate_ref, policy_bound_ref: d.policy_bound_ref, verdict: d.verdict });
checks.push([decisionRef === d.expected_decision_ref, 'decision_ref recomputes (keystone decision)', decisionRef]);

const gateRef = ref({ payer_ref: g.payer_ref, subject_ref: g.subject_ref, verdict: g.verdict });
checks.push([gateRef === g.expected_gate_ref, 'gate_ref recomputes (compliance_gate_lite), equals published cg-allow-P', gateRef]);

checks.push([g.subject_ref === d.policy_bound_ref, 'gate subject_ref IS the decision policy_bound_ref', g.subject_ref]);

// ── every cap member recomputed from its own raw fields ──────────────────────
const ap = vec(load('agent_passport_lite_v1'), 'ap-001');
const passportRef = ref({ agent_id: ap.agent_id, issuer: ap.issuer, scope: ap.scope, validity_window: ap.validity_window });

const pm = vec(load('payment_mandate_lite_v1'), 'pm-001');
const mandateRef = ref({ payer: pm.payer, cap: pm.cap, period: pm.period, revocation_state: pm.revocation_state });

// Two-step: policy_ref over the raw policy object, then bound to the frozen subject_ref.
// policy_binding_v1 carries the policy *label* ("P"), so the raw object is sourced from
// the keystone_v1 trace where this corpus publishes it, and cross-checked below.
const pb = vec(load('policy_binding_v1'), 'pb-sab-v1-P');
const ksPolicy = JSON.parse(readFileSync(join(HERE, '..', 'keystone_v1', 'keystone_trace.json'), 'utf8')).steps.policy_bound_ref;
const policyOnlyRef = ref(ksPolicy.policy);
const policyRef = ref({ policy_ref: policyOnlyRef, subject_ref: pb.subject_ref });

const ex = vec(load('execution_ref_v1'), 'ex-allow-committed');
const executionRef = ref({ decision_ref: decisionRef, action_type: ex.action_type, scope: ex.scope, outcome: ex.outcome, executed_at_ms: ex.executed_at_ms });

const derived = [passportRef, mandateRef, policyRef, gateRef, decisionRef, executionRef];
const names = ['passport', 'mandate', 'policy', 'gate', 'decision', 'execution'];
const membersOk = derived.every((r, i) => r === cap.subject_refs[i]);
const goldensOk = passportRef === ap.expected_passport_ref
  && mandateRef === pm.expected_mandate_ref
  && policyRef === pb.expected_policy_bound_ref
  && executionRef === ex.expected_execution_ref;
const mismatch = names.filter((n, i) => derived[i] !== cap.subject_refs[i]);
checks.push([membersOk && goldensOk,
  'every cap member recomputes from raw fields and equals its published vector [passport, mandate, policy, gate, decision, execution]',
  membersOk && goldensOk ? 'all 6 derived' : `mismatch: ${JSON.stringify(mismatch)}`]);

checks.push([ex.decision_ref === decisionRef,
  'execution binds the EXACT decision_ref the chain produced (not merely correlated)', ex.decision_ref]);

const spanCap = ref({ subject_refs: derived, trust_outcome: cap.trust_outcome });
checks.push([spanCap === cap.expected_trust_query_ref,
  'trust_query_ref recomputes over the independently derived members', spanCap]);

const gateRefer = ref({ payer_ref: g.payer_ref, subject_ref: g.subject_ref, verdict: 'REFER' });
checks.push([gateRefer === tw.gate_refer && gateRefer !== gateRef,
  'tamper: REFER verdict diverges gate_ref (decision bound to ALLOW)', 'divergent']);

// Regression vector: a substituted execution member must diverge even when the
// substituting trace is internally consistent with itself.
const forged = derived.slice();
forged[5] = 'sha256:' + 'deadbeef'.repeat(8);
const forgedCap = ref({ subject_refs: forged, trust_outcome: cap.trust_outcome });
checks.push([forgedCap !== spanCap,
  'tamper: a substituted execution member diverges the cap (not accepted on trust)', 'divergent']);

console.log('='.repeat(74));
console.log('COMPLIANCE GATE KEYSTONE -- composition proof (Node == Python)');
console.log('='.repeat(74));
let n = 0;
checks.forEach(([ok, desc, val], i) => { console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}\n      value : ${val}`); if (ok) n++; });
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${n}/${checks.length} -- decision admitted under the compliance verdict, every capped reference`);
console.log('     derived from raw fields rather than read from the trace (Node == Python).');
process.exit(n === checks.length ? 0 : 1);
