// guard_keystone_v1 -- composition proof (Node twin). Node == Python byte-for-byte.
// npm install canonicalize
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = JSON.parse(readFileSync(join(HERE, 'guard_keystone_trace.json'), 'utf8'));
const h = (o) => createHash('sha256').update(canonicalize(o), 'utf8').digest('hex');

function metrics(v, depth = 1) {
  const m = { depth, nodes: 1, max_array: 0, max_string: 0, max_keys: 0, numbers_safe: true };
  const merge = (c) => {
    m.depth = Math.max(m.depth, c.depth); m.nodes += c.nodes;
    m.max_array = Math.max(m.max_array, c.max_array); m.max_string = Math.max(m.max_string, c.max_string);
    m.max_keys = Math.max(m.max_keys, c.max_keys); m.numbers_safe = m.numbers_safe && c.numbers_safe;
  };
  if (typeof v === 'boolean') { /* not a number */ }
  else if (Array.isArray(v)) { m.max_array = v.length; for (const x of v) merge(metrics(x, depth + 1)); }
  else if (v !== null && typeof v === 'object') { const ks = Object.keys(v); m.max_keys = ks.length; for (const k of ks) merge(metrics(v[k], depth + 1)); }
  else if (typeof v === 'string') { m.max_string = v.length; }
  else if (typeof v === 'number') { m.numbers_safe = Number.isInteger(v) ? Math.abs(v) <= Number.MAX_SAFE_INTEGER : false; }
  return m;
}

const P = t.profile, rec = t.keystone_record, exp = t.measured;
const checks = [];

const profileRef = 'sha256:' + h(P);
checks.push([profileRef === t.expected_profile_ref, 'profile_ref recomputes, equals the published substrate_guard default', profileRef]);

const byteLen = Buffer.byteLength(canonicalize(rec), 'utf8');
const m = metrics(rec);
const same = byteLen === exp.byte_len && ['depth','nodes','max_array','max_string','max_keys','numbers_safe'].every((k) => m[k] === exp[k]);
checks.push([same, 'keystone record metrics recompute to the recorded values', JSON.stringify({ byte_len: byteLen, ...m })]);

const within = byteLen <= P.max_bytes && m.depth <= P.max_depth && m.max_keys <= P.max_object_keys
  && m.max_array <= P.max_array_length && m.max_string <= P.max_string_length && m.nodes <= P.max_total_nodes && m.numbers_safe;
checks.push([within && t.verdict === 'ACCEPT', 'every metric within the profile bounds -> guard ACCEPTS the keystone record', 'ACCEPT']);

console.log('='.repeat(74));
console.log('GUARD KEYSTONE -- composition proof (Node == Python)');
console.log('='.repeat(74));
let n = 0;
checks.forEach(([ok, desc, val], i) => { console.log(`\n[${i + 1}] ${ok ? 'PASS' : 'FAIL'}  ${desc}\n      value : ${val}`); if (ok) n++; });
console.log('\n' + '-'.repeat(74));
console.log(`PASS ${n}/${checks.length} -- keystone record admitted under the guard profile (Node == Python).`);
process.exit(n === checks.length ? 0 : 1);
