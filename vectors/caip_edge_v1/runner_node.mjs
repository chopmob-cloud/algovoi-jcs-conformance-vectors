// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE beside this file.
//
// caip_edge_v1 runner (Node / JavaScript reference).
//
// Independently re-implements the CAIP-2/10/19 validators (it imports no AlgoVoi
// package), decodes each vector's exact UTF-8 bytes from input_b64, and asserts the
// verdict matches the vector's expectation.
//
// The anchors are ^ and $ WITHOUT the 'm' flag: in JavaScript, $ without multiline
// matches only the end of input, so "eip155:1\n" is correctly rejected. This is the
// language-appropriate counterpart to the Python \A..\Z anchors: same grammar, same
// accept/reject set, different anchor idiom.
//
// Usage:  node runner_node.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const CHAIN = '[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}';
const RE = {
  caip2: new RegExp(`^${CHAIN}$`),
  caip10: new RegExp(`^${CHAIN}:[-.%a-zA-Z0-9]{1,128}$`),
  caip19: new RegExp(`^${CHAIN}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?$`),
};

const valid = (kind, s) => RE[kind].test(s);

const data = JSON.parse(readFileSync(join(HERE, 'caip_edge_v1.json'), 'utf-8'));
const vectors = data.vectors;
const failures = [];
console.log('caip_edge_v1 runner (Node, independent ^..$ no-m reference)');
console.log(`vectors: ${vectors.length}`);
for (const v of vectors) {
  const s = Buffer.from(v.input_b64, 'base64').toString('utf-8');
  const got = valid(v.kind, s);
  const want = v.expectation === 'accept';
  if (got !== want) {
    failures.push(`${v.vector_id}: got ${got ? 'accept' : 'reject'}, want ${v.expectation}`);
  }
}
if (failures.length) {
  for (const f of failures) console.log(`  FAIL ${f}`);
  console.log(`FAIL: ${failures.length}/${vectors.length}`);
  process.exit(1);
}
console.log(`PASS: ${vectors.length}/${vectors.length} vectors match expectation`);
