// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
//
// jws_anchor_v1 runner (Node). Independent of the Python runner: verifies each
// signed token under the RFC 8032 section 7.1 public key, recomputes every anchor
// from the token/object bytes, and checks the negatives and invariants.
//
// Usage: node runner_node.js [jws_anchor_v1.json]

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";

const path = process.argv[2] || "jws_anchor_v1.json";
const d = JSON.parse(readFileSync(path, "utf-8"));
const V = Object.fromEntries(d.vectors.map((v) => [v.vector_id, v]));

const b64uDec = (s) => Buffer.from(s, "base64url");
const anchor = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");
const jcsAnchor = (obj) => anchor(Buffer.from(canonicalize(obj), "utf-8"));
const decodedPayload = (jws) => JSON.parse(b64uDec(jws.split(".")[1]).toString("utf-8"));

function pubKey(hex) {
  const x = Buffer.from(hex, "hex").toString("base64url");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
}
function verifySig(jws, hex) {
  const [h, p, s] = jws.split(".");
  return edVerify(null, Buffer.from(`${h}.${p}`, "ascii"), pubKey(hex), b64uDec(s));
}

let ok = 0, fail = 0;
const check = (cond, label) => { if (cond) ok++; else { fail++; console.log("  FAIL", label); } };

for (const v of d.vectors) {
  const { vector_id: id, case: c } = v;
  if (c === "signed_jws_anchor" || c === "canon_sensitive_signed") {
    check(verifySig(v.input, v.signing.public_key_hex), `${id} sig`);
    check(anchor(Buffer.from(v.input, "ascii")) === v.expected_anchor, `${id} anchor`);
    if (v.recanon_of_decoded_payload) {
      const rec = jcsAnchor(decodedPayload(v.input));
      check(rec === v.recanon_of_decoded_payload, `${id} recanon-value`);
      check(rec !== v.expected_anchor, `${id} recanon-diverges`);
    }
  } else if (c === "recanon_negative") {
    const rec = jcsAnchor(decodedPayload(V[v.ties_to].input));
    check(rec === v.recanon_of_decoded_payload, `${id} recanon-value`);
    check(rec !== v.must_not_equal, `${id} != signed anchor`);
  } else if (c === "sd_jwt_issuer") {
    check(verifySig(v.issuer_jwt, v.signing.public_key_hex), `${id} sig`);
    check(anchor(Buffer.from(v.issuer_jwt, "ascii")) === v.expected_anchor, `${id} anchor`);
  } else if (c === "sd_jwt_presentation") {
    const issuer = V[v.ties_to];
    const ph = anchor(Buffer.from(v.presentation, "ascii"));
    const ih = anchor(Buffer.from(issuer.issuance_form, "ascii"));
    check(ph === v.presentation_hash, `${id} presentation-hash`);
    check(ih === v.issuance_hash, `${id} issuance-hash`);
    check(ph !== v.must_not_equal, `${id} presentation != issuer JWT`);
    check(ih !== v.must_not_equal, `${id} issuance != issuer JWT`);
    check(ph !== ih, `${id} presentation != issuance`);
  } else if (c === "unsigned_jcs") {
    check(jcsAnchor(v.input) === v.expected_anchor, `${id} jcs-anchor`);
  } else {
    check(false, `${id} unknown case ${c}`);
  }
}

check(V["jws-anchor-002"].recanon_of_decoded_payload !== V["jws-anchor-001"].expected_anchor, "I1");
check(V["jws-anchor-004"].presentation_hash !== V["jws-anchor-003"].expected_anchor
  && V["jws-anchor-004"].issuance_hash !== V["jws-anchor-003"].expected_anchor, "I2");
check(V["jws-anchor-006"].recanon_of_decoded_payload !== V["jws-anchor-006"].expected_anchor, "I4");

console.log(fail ? `${ok}/${ok + fail} PASS, ${fail} FAIL` : `${ok}/${ok + fail} PASS`);
process.exit(fail ? 1 : 0);
