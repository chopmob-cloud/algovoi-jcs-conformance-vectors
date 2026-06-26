# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance + cross-engine layer.
# The GovernanceDecision / GovernanceOutcome schema is crewAI's (crewAIInc/crewAI PR #6030).
"""
cross_engine_governance_v1 benchmark / stress test (Python).

Three honest, reproducible measurements:
  1. throughput  -- governance decisions/sec (compute all 5 RFC 8785 + SHA-256 refs).
  2. cross-engine determinism -- N random intents emitted via BOTH the crewAI and Strands
     adapters (different runtime-local state); count intent_ref divergences (must be 0).
  3. cross-impl handoff -- write (intent, intent_ref) for N intents to a file so bench.mjs
     can recompute under an independent JCS impl and confirm 0 divergence at scale.

    python bench.py [N]   (default 20000)
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

from algovoi_substrate import sha256_jcs

sys.path.insert(0, str(Path(__file__).parent))
from crewai_emit import emit_from_crewai
from strands_emit import emit_from_strands

H = lambda o: "sha256:" + sha256_jcs(o)
TOOLS = ["customer_export", "transfer_funds", "delete_database", "post_message", "search"]
SCOPES = ["customers/eu", "payments/transfer", "prod/delete", "messaging/public", "search/all"]
REGIONS = ["eu", "us", "apac", "café-region"]  # include unicode to exercise JCS UTF-8


def refs_for(d):
    params_hash = H(d["tool_params"])
    intent_digest = H({"agent_id": d["agent_id"], "tool": d["tool"],
                       "params_hash": params_hash, "target_state_digest": d["target_state_digest"]})
    intent_ref = H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
                    "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"]})
    receipt_ref = H({"agent_id": d["agent_id"], "tool": d["tool"], "normalized_scope": d["normalized_scope"],
                     "intent_digest": intent_digest, "idempotency_key": d["idempotency_key"], "issued_at": d["issued_at"]})
    dch = H({"agent_id": d["agent_id"], "tool": d["tool"], "params_hash": params_hash, "intent_digest": intent_digest,
             "seq": d["seq"], "retrieved_policy_refs": d["retrieved_policy_refs"], "policy_digest": d["policy_digest"],
             "credential_scope": d["credential_scope"], "credential_tier": d["credential_tier"],
             "expires_at": d["expires_at"], "revalidate_if": d["revalidate_if"]})
    return params_hash, intent_digest, intent_ref, receipt_ref, dch


def grant_for(it):
    return {"decision": "allow", "target_state_digest": "sha256:" + "1" * 64,
            "normalized_scope": it["scope"], "idempotency_key": it["idem"],
            "issued_at": "2026-06-25T05:00:00Z", "retrieved_policy_refs": ["policy:gdpr-export-v3"],
            "policy_refs": ["policy:gdpr-export-v3"], "policy_digest": "sha256:policy-v1-hash",
            "credential_scope": "read-only", "credential_tier": "human-delegated",
            "expires_at": "2026-06-25T05:05:00Z", "revalidate_if": ["argument_change"],
            "execution": {"outcome": "executed", "tool_output": {"rows": it["limit"]}, "completed_at": "2026-06-25T05:00:02Z"}}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    random.seed(42)
    intents = [{"tool": random.choice(TOOLS), "scope": random.choice(SCOPES),
                "params": {"format": "csv", "region": random.choice(REGIONS), "limit": random.randint(1, 100000)},
                "agent": f"agent_{i % 1000}", "idem": f"idem_{i}", "limit": random.randint(1, 100000)} for i in range(n)]

    # 1. throughput: build a decision and compute all 5 refs
    t0 = time.perf_counter()
    for i, it in enumerate(intents):
        ev = {"agent": {"id": it["agent"], "role": "Researcher"}, "tool": {"name": it["tool"]}, "tool_input": it["params"]}
        d = emit_from_crewai(ev, grant_for(it), {"decision_id": f"d{i}", "request_id": f"r{i}", "seq": i % 64})["decision"]
        refs_for(d)
    t1 = time.perf_counter()
    tput = n / (t1 - t0)

    # 2. cross-engine determinism: crewAI vs Strands intent_ref over N (different runtime state)
    handoff = []
    div = 0
    t2 = time.perf_counter()
    for i, it in enumerate(intents):
        g = grant_for(it)
        ev_c = {"agent": {"id": it["agent"], "role": "Researcher"}, "tool": {"name": it["tool"]}, "tool_input": it["params"]}
        ev_s = {"tool_use": {"toolUseId": f"tu_{i}", "name": it["tool"], "input": dict(reversed(list(it["params"].items())))},
                "agent": {"agent_id": it["agent"], "role": "Researcher"}}
        c = emit_from_crewai(ev_c, g, {"decision_id": f"c{i}", "request_id": f"cr{i}", "seq": 0})["decision"]
        s = emit_from_strands(ev_s, g, {"decision_id": f"s{i}", "request_id": f"sr{i}", "seq": 7})["decision"]
        ir_c, ir_s = refs_for(c)[2], refs_for(s)[2]
        if ir_c != ir_s:
            div += 1
        handoff.append({"d": c, "intent_ref": ir_c})
    t3 = time.perf_counter()
    xeng = n / (t3 - t2)

    Path("/tmp/bench_handoff.json").write_text(json.dumps(handoff), encoding="utf-8")
    print(f"PY throughput            : {tput:,.0f} governance decisions/sec (5 refs each), N={n}")
    print(f"PY cross-engine determinism: {xeng:,.0f} crewAI-vs-Strands intent_ref pairs/sec, divergences={div}/{n}")
    print(f"PY handoff written        : /tmp/bench_handoff.json ({n} intents for the Node cross-impl check)")
    return 1 if div else 0


if __name__ == "__main__":
    sys.exit(main())
