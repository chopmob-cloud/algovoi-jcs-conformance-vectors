# artifact_ref_v1

Conformance vectors for artifact_ref, a content addressed reference to an A2A Task output.

    artifact_ref = "sha256:" + SHA-256(JCS({artifact_type, output_hash, produced_at_ms, task_ref}))

JCS (RFC 8785) sorts keys lexicographically, so the preimage field order is always: artifact_type, output_hash, produced_at_ms, task_ref. Recomputes offline with RFC 8785 + SHA-256, no JWS or JWKS.

## Vectors

- positives: ar-001 (TEXT output from analysis task), ar-002 (DATA output from settlement task)
- type coverage: tc-FILE and tc-ERROR confirm all four artifact_type values produce distinct hashes
- invariants: field insertion order does not change artifact_ref (JCS is order-independent)
- negatives: changed task_ref diverges, changed output_hash diverges, changed artifact_type diverges, 1ms timestamp change diverges

## Composition

artifact_ref composes transitively onto the full three-ref chain: card_ref (who the agent is) -> task_ref (what they were asked) -> artifact_ref (what they produced). All three recompute offline from retained bytes.

## Run

    python runner_python.py
    node runner_node.js

Both reproduce 9/9 byte for byte. Python + Node cross-validated (2026-06-30).

Apache 2.0. Copyright (c) 2026 AlgoVoi (chopmob-cloud).
