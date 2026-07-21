// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE beside this file.
//
// caip_edge_v1 NAIVE Node runner: the JavaScript m-flag anchor trap, demonstrated.
//
// Compiled WITH the 'm' (multiline) flag. Under /m, ^ and $ match at every line boundary,
// so ^id$ matches when ANY line of the input is a valid identifier. The validator then
// accepts trailing line terminators (LF CR U+2028 U+2029, CRLF), leading newlines, AND
// newline-injection payloads like "eip155:1<LF><script>": the first line is a valid id, so
// the whole malformed string passes. That injection bypass is the severe form of the trap
// and is why the m flag must never appear on an identifier validator. Correct JS is ^..$
// without m; correct Python is the \A..\Z sibling.
//
// Pure ASCII, backslash-u escapes only. A literal U+2028 in a // comment would end the
// comment and break the parse, the same hazard one layer up.
//
// Exits 0 only if every divergence is an OVER-ACCEPTANCE whose input has some line that is
// a valid identifier (it never wrongly rejects a valid id).
// Usage:  node runner_node_naive.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const CHAIN = '[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}';
const RE = {   // NAIVE: 'm' flag present
  caip2: new RegExp(`^${CHAIN}$`, 'm'),
  caip10: new RegExp(`^${CHAIN}:[-.%a-zA-Z0-9]{1,128}$`, 'm'),
  caip19: new RegExp(`^${CHAIN}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?$`, 'm'),
};
const OK = {
  caip2: new RegExp(`^${CHAIN}$`),
  caip10: new RegExp(`^${CHAIN}:[-.%a-zA-Z0-9]{1,128}$`),
  caip19: new RegExp(`^${CHAIN}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?$`),
};
// A divergence is expected iff some line (split on JS line terminators) is a valid id;
// that is precisely what the m flag lets through.
const LT = new RegExp('\r\n|[\n\r\u2028\u2029]');
const hasValidLine = (kind, s) => s.split(LT).some((line) => OK[kind].test(line));

const data = JSON.parse(readFileSync(join(HERE, 'caip_edge_v1.json'), 'utf-8'));
const diverged = [], underRejections = [], unsafe = [];
for (const v of data.vectors) {
  const s = Buffer.from(v.input_b64, 'base64').toString('utf-8');
  const got = RE[v.kind].test(s) ? 'accept' : 'reject';
  if (got !== v.expectation) {
    diverged.push(v.vector_id);
    if (v.expectation === 'accept') underRejections.push(v.vector_id);
    else if (!hasValidLine(v.kind, s)) unsafe.push(v.vector_id);
  }
}

console.log('caip_edge_v1 NAIVE Node runner (^..$ WITH m flag -- expected to over-accept)');
console.log(`vectors: ${data.vectors.length}, diverged: ${diverged.length}`);
for (const vid of diverged) console.log(`  DIVERGE ${vid}`);
let fail = false;
if (diverged.length === 0) { console.log('FAIL: expected the m-flag trap to diverge'); fail = true; }
if (underRejections.length) { console.log(`FAIL: under-rejected valid ids ${underRejections}`); fail = true; }
if (unsafe.length) { console.log(`FAIL: over-accepted inputs with no valid line ${unsafe}`); fail = true; }
if (fail) process.exit(1);
console.log(`PASS: ${diverged.length} over-acceptances (trailing/leading terminators + newline-injection), 0 under-rejections`);
