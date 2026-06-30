// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance layer, Apache-2.0.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";
const artifactRef = (taskRef, outputHash, artifactType, producedAtMs) => {
  const p = { artifact_type: artifactType, output_hash: outputHash, produced_at_ms: producedAtMs, task_ref: taskRef };
  return "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(p), "utf-8")).digest("hex");
};
const d = JSON.parse(readFileSync(new URL("./artifact_ref_v1.json", import.meta.url), "utf-8"));
const refs = {}; let p = 0, t = 0;
for (const v of d.vectors) { t++; const r = artifactRef(v.task_ref, v.output_hash, v.artifact_type, v.produced_at_ms); refs[v.id] = r; const ok = r === v.expected_artifact_ref; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
for (const v of (d.type_coverage_vectors||[])) { t++; const r = artifactRef(v.task_ref, v.output_hash, v.artifact_type, v.produced_at_ms); refs[v.id] = r; const ok = r === v.expected_artifact_ref && r !== refs[v.diverges_from]; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
for (const v of (d.invariant_vectors||[])) { t++; const ok = artifactRef(v.task_ref, v.output_hash, v.artifact_type, v.produced_at_ms) === refs[v.equals_ref_of]; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
for (const v of (d.negative_vectors||[])) { t++; const ok = artifactRef(v.task_ref, v.output_hash, v.artifact_type, v.produced_at_ms) !== refs[v.diverges_from]; p += ok; console.log((ok?"  PASS ":"  FAIL ")+v.id); }
console.log(`NODE artifact_ref_v1: ${p}/${t}`); process.exit(p===t?0:1);
