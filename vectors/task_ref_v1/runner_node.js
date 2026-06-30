// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance layer, Apache-2.0.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";
const taskRef = (cardRef, instructionsHash, createdAtMs) => {
  const p = { card_ref: cardRef, created_at_ms: createdAtMs, instructions_hash: instructionsHash };
  return "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(p), "utf-8")).digest("hex");
};
const d = JSON.parse(readFileSync(new URL("./task_ref_v1.json", import.meta.url), "utf-8"));
const refs = {}; let p = 0, t = 0;
for (const v of d.vectors) { t++; const r = taskRef(v.card_ref, v.instructions_hash, v.created_at_ms); refs[v.id] = r; const ok = r === v.expected_task_ref; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
for (const v of d.invariant_vectors) { t++; const ok = taskRef(v.card_ref, v.instructions_hash, v.created_at_ms) === refs[v.equals_ref_of]; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
for (const v of (d.negative_vectors||[])) { t++; const ok = taskRef(v.card_ref, v.instructions_hash, v.created_at_ms) !== refs[v.diverges_from]; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
console.log(`NODE task_ref_v1: ${p}/${t}`); process.exit(p===t?0:1);
