#!/usr/bin/env node
/**
 * runner_node.js -- RFC 9421 §2.5-CONFORMANT cross-validation runner for the
 * rfc9421_proxy_chain_v1 fixture. Independent reimplementation (no AlgoVoi
 * package): rebuilds the conformant signing base from scratch and verifies
 * with Node's built-in crypto (Ed25519 via SPKI-wrapped raw key).
 *
 * Run: node runner_node.js   (from the dir containing request.fixture.json)
 */
import { readFileSync } from "node:fs";
import crypto from "node:crypto";

const fix = JSON.parse(readFileSync("request.fixture.json", "utf-8"));
const r = fix.request;

const method = r.method;                       // PRESERVE case
const authority = r.authority.toLowerCase();
const path = r.path;
const cd = r.headers["content-digest"];
const si = r.headers["signature-input"];
const sigHeader = r.headers["signature"];
const expected = fix.signing.signing_base;

// Post-label portion of Signature-Input: after the first '='.
const paramsRaw = si.slice(si.indexOf("=") + 1);
const inner = paramsRaw.slice(1, paramsRaw.indexOf(")"));
const covered = [...inner.matchAll(/"([^"]+)"/g)].map((m) => m[1]);

const lines = covered.map((name) => {
  let val;
  switch (name) {
    case "@method": val = method; break;
    case "@authority": val = authority; break;
    case "@path": val = path; break;
    case "content-digest": val = cd; break;
    default: console.error("unexpected covered component:", name); process.exit(1);
  }
  return `"${name}": ${val}`;
});
lines.push(`"@signature-params": ${paramsRaw}`);
const base = lines.join("\n");

if (base !== expected) {
  console.log("[FAIL] signing base mismatch");
  console.log("  expected:", JSON.stringify(expected));
  console.log("  got:     ", JSON.stringify(base));
  process.exit(1);
}
console.log("[OK] signing base byte-identical to fixture (rfc9421 conformant)");

const expectedCd = `sha-256=:${crypto.createHash("sha256").update("").digest("base64")}:`;
if (expectedCd !== cd) { console.log("[FAIL] content-digest mismatch"); process.exit(1); }
console.log("[OK] RFC 9530 content-digest verified");

// Wrap the 32-byte raw Ed25519 public key in a DER SPKI header.
const rawPub = Buffer.from(fix.keypair.public_key_hex, "hex");
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),
  rawPub,
]);
const pubKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });

const body = sigHeader.slice(sigHeader.indexOf("=:") + 2).replace(/:$/, "");
const sig = Buffer.from(body, "base64");
const ok = crypto.verify(null, Buffer.from(base, "utf-8"), pubKey, sig);
if (!ok) { console.log("[FAIL] Ed25519 verify failed"); process.exit(1); }
console.log("[OK] Ed25519 signature verified");
console.log("PASS (Node: inline conformant base + node:crypto Ed25519)");
