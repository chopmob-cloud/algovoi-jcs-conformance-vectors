// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
// The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
//
// cross_engine_governance_v1 benchmark (Node). Two measurements:
//   1. throughput -- governance intent_ref/sec under the independent Node JCS impl.
//   2. cross-impl handoff -- read /tmp/bench_handoff.json (written by bench.py) and confirm Node
//      recomputes the SAME intent_ref Python did, for every intent (divergences must be 0).
//
//   node bench.mjs
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";

const H = (obj) => "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(obj), "utf-8")).digest("hex");
function intentRef(d) {
  const params_hash = H(d.tool_params);
  const intent_digest = H({ agent_id: d.agent_id, tool: d.tool, params_hash, target_state_digest: d.target_state_digest });
  return H({ agent_id: d.agent_id, tool: d.tool, normalized_scope: d.normalized_scope, intent_digest, idempotency_key: d.idempotency_key });
}

const rows = JSON.parse(readFileSync("/tmp/bench_handoff.json", "utf-8"));
const n = rows.length;

// throughput
let t0 = process.hrtime.bigint();
for (const r of rows) intentRef(r.d);
let t1 = process.hrtime.bigint();
const tput = n / (Number(t1 - t0) / 1e9);

// cross-impl: Node intent_ref must equal Python's for every intent
let div = 0;
for (const r of rows) if (intentRef(r.d) !== r.intent_ref) div++;

console.log(`NODE throughput          : ${tput.toLocaleString("en-US", { maximumFractionDigits: 0 })} intent_ref/sec, N=${n}`);
console.log(`NODE cross-impl vs Python: divergences=${div}/${n} (byte-identical intent_ref at scale)`);
process.exit(div ? 1 : 0);
