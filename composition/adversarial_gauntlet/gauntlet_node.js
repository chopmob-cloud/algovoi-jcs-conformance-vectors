#!/usr/bin/env node
// Adversarial gauntlet runner -- Node (independent reimplementation, no algovoi import).
// Same three checks as gauntlet_python.py; must accept the control and reject all 11 mutations.
// Usage: node gauntlet_node.js /path/to/adversarial_isolation_v1.json
'use strict';
const fs = require('fs');
const crypto = require('crypto');

const isHex64 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const isUint = (x) => typeof x === 'number' && Number.isInteger(x) && x >= 0;
const nonEmptyStr = (x) => typeof x === 'string' && x.length > 0;

function jcsFlat(o) {
  // sorted-key compact JSON; byte-identical to RFC 8785 JCS for ASCII/int payloads.
  const keys = Object.keys(o).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(o[k])).join(',') + '}';
}

function checkTransitionPreimage(o) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
  if (!isHex64(o.action_ref)) return false;
  if (!nonEmptyStr(o.state)) return false;
  for (const k of ['transition_timestamp_ms', 'authority_verified_at_ms', 'revocation_check_at_ms']) {
    if (!isUint(o[k])) return false;
  }
  return true;
}

function checkActionRef(o) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
  for (const k of ['agent_id', 'action_type', 'scope']) {
    if (!nonEmptyStr(o[k])) return false;
  }
  return isUint(o.timestamp_ms);
}

function checkAuditChain(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return false;
  let prev = null;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (r === null || typeof r !== 'object') return false;
    if (r.chain_position !== i) return false;
    if (i === 0) {
      if (r.prev_hash !== null) return false;
    } else if (r.prev_hash !== prev) return false;
    const recomputed = crypto.createHash('sha256').update(jcsFlat(r.payload)).digest('hex');
    if (recomputed !== r.content_hash) return false;
    prev = r.content_hash;
  }
  return true;
}

const CHECKS = {
  transition_preimage: checkTransitionPreimage,
  action_ref: checkActionRef,
  audit_chain: checkAuditChain,
};

const data = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let ok = 0;
let total = 0;
for (const v of data.vectors) {
  total += 1;
  const verdict = CHECKS[v.check](v.input) ? 'accept' : 'reject';
  const expected = v.expectation === 'reject' ? 'reject' : 'accept';
  const good = verdict === expected;
  if (good) ok += 1;
  console.log(`${v.vector_id} ${verdict} expect=${expected} ${good ? 'OK' : 'MISMATCH'}`);
}
console.log(`GAUNTLET node ${ok}/${total}`);
process.exit(ok === total ? 0 : 1);
