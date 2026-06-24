// compliance_gate_keystone_v1 -- composition proof (Node twin). Node == Python byte-for-byte.
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'compliance_gate_keystone_trace.json'), 'utf8'));
const h = (o) => createHash('sha256').update(canonicalize(o), 'utf8').digest('hex');
const ref = (o) => 'sha256:' + h(o);

const d = t.decision, g = t.compliance_gate, cap = t.compliance_cap, tw = t.tamper;
const checks = [];

const decisionRef = ref({ agent_ref: d.agent_ref, mandate_ref: d.mandate_ref, policy_bound_ref: d.policy_bound_ref, verdict: d.verdict });
checks.push([decisionRef === d.expected_decision_ref, 'decision_ref recomputes (keystone decision)', decisionRef]);

const gateRef = ref({ payer_ref: g.payer_ref, subject_ref: g.subject_ref, verdict: g.verdict });
checks.push([gateRef === g.expected_gate_ref, 'gate_ref recomputes (compliance_gate_lite), equals published cg-allow-P', gateRef]);

checks.push([g.subject_ref === d.policy_bound_ref, 'gate subject_ref IS the decision policy_bound_ref', g.subject_ref]);

const spanCap = ref({ subject_refs: cap.subject_refs, trust_outcome: cap.trust_outcome });
checks.push([spanCap === cap.expected_trust_query_ref && cap.subject_refs[3] === gateRef && cap.subject_refs[4] === decisionRef,
  'compliance-spanning trust_query caps [passport, mandate, policy, gate, decision, execution]', spanCap]);

const gateRefer = ref({ payer_ref: g.payer_ref, subject_ref: g.subject_ref, verdict: 'REFER' });
checks.push([gateRefer === tw.gate_refer && gateRefer !== gateRef,
  'tamper: REFER verdict diverges gate_ref (decision bound to ALLOW)', 'divergent']);

console.log('='.repeat(74));
console.log('COMPLIANCE GATE KEYSTONE -- composition proof (Node == Python)');
console.log('='.repeat(74));
let n = 0;
checks.forEach(([ok, desc, val], i) => { console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}\n      value : ${val}`); if (ok) n++; });
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${n}/${checks.length} -- decision admitted under the compliance verdict (Node == Python).`);
process.exit(n === checks.length ? 0 : 1);
