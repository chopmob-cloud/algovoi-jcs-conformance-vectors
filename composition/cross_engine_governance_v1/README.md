# cross_engine_governance_v1

Two independent agent frameworks, one cross-runtime join key.

## What this proves (and what it does not)

A crewAI integration and a Strands integration process the **same authorized intent** but with
their **own runtime-local state**: different `decision_id`, different `request_id`, and a
different `seq` counter. The proof is:

- The contract's **`intent_ref`** is **byte-identical** across both frameworks and equals the
  published, cross-validated `governance_decision_v1` value. By construction it excludes every
  runtime-local field (no timestamp, no `decision_id`, no `seq`), so it is a true cross-runtime
  join key: an outcome emitted by one framework provably references a decision emitted by the
  other.
- The **full records differ** (different `decision_id`) and **`decision_context_hash` differs**
  (it includes `seq`). We do **not** force them equal. Forcing them equal would prove nothing;
  showing `intent_ref` survive the divergence while the context hash correctly moves is the
  actual, honest result, and it is exactly how the contract intends the two refs to behave.

```
intent_ref = sha256(JCS({agent_id, tool, normalized_scope, intent_digest, idempotency_key}))   # cross-runtime stable
decision_context_hash = sha256(JCS({..., seq, ...}))                                            # per-context, moves with seq
```

## Run

```
pip install algovoi-substrate>=0.4.0          # Python, RFC 8785 via rfc8785
python verify_cross_engine.py

npm install @algovoi/substrate                 # Node, independent RFC 8785 impl
node verify_cross_engine.mjs
```

Both print `13/13 PASS`, the same `intent_ref`, and `decision_context_hash` values that differ
between crewAI (`seq=0`) and Strands (`seq=7`). Two independent JCS implementations agreeing on
the `intent_ref` is the point: the agreement is on the bytes (the standard), not on one library.

### Benchmark / stress

```
python bench.py 50000      # throughput + cross-engine determinism, writes a handoff file
node bench.mjs             # recomputes the same intents under the independent Node JCS impl
```

Reference run (single-core AMD EPYC, clean box, published packages, N=50,000): 0/50,000
cross-engine divergences (crewAI vs Strands `intent_ref`), 0/50,000 cross-impl divergences
(Python vs Node), ~15,600 full governance decisions/sec in Python, ~52,800 `intent_ref`/sec in Node.

## What is shared and what is not

- **Not shared:** `crewai_emit.py` and `strands_emit.py` are independent. They read different
  native event shapes (`event.tool.name` / `event.tool_input` vs `event.tool_use.name` /
  `event.tool_use.input`), carry different runtime-local state, and receive the tool arguments
  in **different key order**. JCS normalization, not copy-paste, makes `intent_ref` converge.
- **Shared by design:** the contract field set and RFC 8785 as the canonicalization standard.
  The Node verifier re-proves the result under a second, independent RFC 8785 implementation.

## Honest scope

- The emitters are **integration adapters** modeling each framework's documented hook event
  (`before_tool_call` for crewAI, `BeforeToolCallEvent` + `cancel_tool` for Strands).
  `strands_emit.strands_event_from_sdk` adapts a real `strands-agents` `BeforeToolCallEvent`
  object; the VM2 gauntlet confirms that class exists in the installed SDK and runs the proof
  through it. The harness does not start a live LLM-driven agent.
- "No shared agent runtime" refers to the two frameworks. A third party reproduces every digest
  from the records alone.
- The decision-side constructions (`params_hash`, `intent_digest`, `intent_ref`,
  `decision_context_hash`) are the contract's, JCS-bound. The outcome `receipt_ref` and
  `tool_output_hash` are computed under the declared `jcs-sha256` profile (see
  `receipt_ref_profile` in `governance_decision_v1`), which the contract permits but does not
  mandate. Labeled as profile choices, not contract MUSTs.

## License

Apache-2.0. Copyright (c) 2026 AlgoVoi (chopmob-cloud), Christopher Hopley. See the repo
`LICENSE` and `NOTICE`. The conformance vectors, runners, emitters, and this cross-engine proof
are AlgoVoi's. The `GovernanceDecision` / `GovernanceOutcome` **schema** is crewAI's
(crewAIInc/crewAI PR #6030), referenced for interop and not claimed by AlgoVoi.
