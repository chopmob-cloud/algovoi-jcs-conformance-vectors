#!/usr/bin/env node
/**
 * runner_node.js -- RFC 9421 + RFC 9530 cross-validation runner for the
 * rfc9421_proxy_chain_v0 fixture.
 *
 * Uses the published `@algovoi/rfc9421-verifier` npm package. Install with:
 *   npm install @algovoi/rfc9421-verifier
 *
 * Run from the directory containing request.fixture.json:
 *   node runner_node.js
 *
 * Exit code 0 = PASS, 1 = FAIL.
 */

import { readFileSync } from "node:fs";
import { verifyRequest } from "@algovoi/rfc9421-verifier";

const fix = JSON.parse(readFileSync("request.fixture.json", "utf-8"));
const req = fix.request;

const result = await verifyRequest({
  method: req.method,
  authority: req.authority,
  path: req.path,
  headers: req.headers,
  body: new Uint8Array(),
  publicKey: fix.keypair.public_key_hex,
});

if (!result.valid) {
  console.log("[FAIL] verifyRequest returned invalid:");
  for (const e of result.errors) console.log("  -", e);
  process.exit(1);
}
if (result.signing_base !== fix.signing.signing_base) {
  console.log("[FAIL] signing base mismatch");
  process.exit(1);
}

console.log("[OK] signing base byte-identical to fixture");
console.log("[OK] RFC 9530 content-digest verified");
console.log("[OK] Ed25519 signature verified");
console.log("PASS (TypeScript: @algovoi/rfc9421-verifier on @noble/ed25519)");
