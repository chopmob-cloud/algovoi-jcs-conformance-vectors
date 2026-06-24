// audit_chain_of_frames_v1 -- composition proof (Node twin).
// Recomputes each frame_id, the audit-chain row hashes, and the trust_query_ref cap from
// raw fields, asserting each equals the published trace value. Expected values were produced
// by the Python substrate, so Node matching them proves Python/Node byte-for-byte parity.
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'audit_chain_trace.json'), 'utf8'));
const ZERO = '0'.repeat(64);

const h = (obj) => createHash('sha256').update(canonicalize(obj), 'utf8').digest('hex');
const frameId = (preimage) => 'sha256:' + h(preimage);
const rowHash = (content_hash, prev_hash, row_number) => h({ content_hash, prev_hash, row_number });
const tq = (subject_refs, trust_outcome) => 'sha256:' + h({ subject_refs, trust_outcome });

const frames = t.frames, carries = t.carries, chain = t.audit_chain, cap = t.cap, tw = t.tamper;
const checks = [];
const refByRole = { execution: 'execution_ref', settlement: 'settlement_ref', refund: 'refund_ref' };

for (const f of frames) {
  const rh = 'sha256:' + h(f.preimage.receipt);
  const ok = rh === carries[refByRole[f.role]] && rh === f.preimage.receipt_hash && frameId(f.preimage) === f.frame_id;
  checks.push([ok, `frame[${f.role}] receipt_hash == ${refByRole[f.role]} and frame_id recomputes (pef_v1)`, f.frame_id]);
}

const r1 = rowHash(frames[0].frame_id, ZERO, 1);
const r2 = rowHash(frames[1].frame_id, r1, 2);
const r3 = rowHash(frames[2].frame_id, r2, 3);
const chainOk = chain[0].row.prev_hash === ZERO && r1 === chain[0].expected_row_hash
  && chain[1].row.prev_hash === r1 && r2 === chain[1].expected_row_hash
  && chain[2].row.prev_hash === r2 && r3 === chain[2].expected_row_hash;
checks.push([chainOk, 'frames link into an audit chain (prev_hash == prior row hash; genesis 64 zeros)', r3]);

const capVal = tq(cap.subject_refs, cap.trust_outcome);
const capOk = JSON.stringify(cap.subject_refs) === JSON.stringify(frames.map((f) => f.frame_id))
  && capVal === cap.expected_trust_query_ref;
checks.push([capOk, 'one trust_query_ref over the ordered frame ids caps the chain (TRUSTED)', capVal]);

const tamperedReceipt = { ...frames[1].preimage.receipt, settlement_result: 'REVERSED' };
const f2t = frameId({ ...frames[1].preimage, receipt: tamperedReceipt, receipt_hash: 'sha256:' + h(tamperedReceipt) });
const r2t = rowHash(f2t, r1, 2);
const r3t = rowHash(frames[2].frame_id, r2t, 3);
const capt = tq([frames[0].frame_id, f2t, frames[2].frame_id], 'TRUSTED');
const tamperOk = f2t === tw.reversed_frame2_id && f2t !== frames[1].frame_id
  && r2t === tw.reversed_row2_hash && r3t === tw.reversed_row3_hash && r3t !== r3
  && capt === tw.reversed_cap && capt !== capVal;
checks.push([tamperOk, 'tamper: REVERSED settlement diverges frame 2, rows 2-3, and the cap', 'divergent']);

console.log('='.repeat(74));
console.log('AUDIT CHAIN OF FRAMES -- composition proof (Node == Python)');
console.log('='.repeat(74));
let npass = 0;
checks.forEach(([ok, desc, val], i) => {
  console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}`);
  console.log(`      value : ${val}`);
  if (ok) npass++;
});
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${npass}/${checks.length} -- lifecycle is one tamper-evident, capped chain of frames (Node == Python).`);
process.exit(npass === checks.length ? 0 : 1);
