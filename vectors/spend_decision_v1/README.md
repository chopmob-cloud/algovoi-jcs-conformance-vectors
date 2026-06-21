# spend_decision_v1

Conformance vectors for the **commercial Spend Guardrail** decision chain.

```
decision_ref    = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
prev_entry_hash = "sha256:" + SHA-256(JCS(previous_decision_payload))
```

- `verdict` is the closed enum **{ALLOW, DENY, REFER}**. `ALLOW`/`DENY` `decision_ref` are **byte-identical
  to `spend_guardrail_lite_v1`** (`sg-allow-P` / `sg-deny-P`) — the open lite tier an AP2/A2A adopter pins
  composes, unchanged, into the commercial product. `REFER` is the commercial review/step-up verdict.
- The `chain` section anchors the append-only linkage: each `spend_decision` entry commits to the JCS hash
  of the entry before it, so a single altered or dropped decision breaks the chain from that point on.

The vectors anchor the **content-addressing + chain construction** only. The commercial product's value —
Falcon-1024 (+ optional ML-DSA-65) signing, the offline chain verifier, the enforcement engine
(fail-closed revocation, velocity, REFER), durable persistence, and the gateway payout binding — is not
part of these public vectors.

Run: `pip install algovoi-substrate>=0.4.0 && python runner_python.py`
