# execution_ref_v1

Conformance vectors for **execution_ref**, the decision-bound execution-evidence primitive.

```
execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope, outcome, executed_at_ms}))
```

Identity proves *who* an agent is; a `decision_ref` proves an action was *authorized*. `execution_ref`
closes the remaining gap: it proves *what the agent did* and binds that execution back to the exact
decision that authorized it, so a verifier can confirm the executed action is **consistent** with the
decision, not merely correlated with an identity.

- `decision_ref` is a load-bearing field. Its inputs here are the **byte-identical
  `expected_decision_ref` values from `spend_decision_v1`** (`sd-allow` / `sd-deny` / `sd-refer`), so the
  keystone composes: `passport_ref` -> `mandate_ref` -> `decision_ref` (PRE-payment) -> `execution_ref`
  (POST-execution). Swap the authorizing decision and the `execution_ref` diverges.
- `outcome` is the closed enum **{COMMITTED, SKIPPED, FAILED, REVERSED}**. `SKIPPED` is the exactly-once
  dedupe result.
- `executed_at_ms` is an **epoch-millisecond integer hashed directly** (Substrate Rule 2). An RFC 3339
  string timestamp is **rejected**, not converted then hashed (negative `ex-neg-rfc3339-timestamp`): the
  distinctive, reproducible AlgoVoi form a non-conformant lineage cannot reproduce.
- No raw `agent_id` appears in the preimage (it is already bound inside `decision_ref`), so `execution_ref`
  is **no-PII** by construction.

The vectors anchor the **content-addressing + composition** only. The commercial product's value
(Falcon-1024 + ML-DSA-65 signing of the execution tier, CCC-ingestable `execution_evidence`, the offline
verifier) is not part of these public vectors.

Run: `pip install algovoi-substrate>=1.0.0 && python runner_python.py`
Cross-validated: Python + TypeScript byte-for-byte (2026-06-24, 11/11 each).
