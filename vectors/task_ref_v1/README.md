# task_ref_v1

Conformance vectors for task_ref, a content addressed reference to an A2A Task delegation.

    task_ref = "sha256:" + SHA-256(JCS({card_ref, created_at_ms, instructions_hash}))

JCS (RFC 8785) sorts keys lexicographically, so the preimage field order is always: card_ref, created_at_ms, instructions_hash. Recomputes offline with RFC 8785 + SHA-256, no JWS or JWKS.

## Vectors

- positives: tr-001 (Example Agent analysis task), tr-002 (Pay Agent settlement task)
- invariants: field insertion order does not change task_ref (JCS is order-independent)
- negatives: changed card_ref diverges, changed instructions_hash diverges, 1ms timestamp change diverges

## Composition

task_ref composes onto card_ref (AlgoVoi-A2A-Card): the card_ref field is the card_ref_v1 reference to the assigned agent. artifact_ref (artifact_ref_v1) composes onto task_ref.

## Run

    python runner_python.py
    node runner_node.js

Both reproduce 6/6 byte for byte. Python + Node cross-validated (2026-06-30).

Apache 2.0. Copyright (c) 2026 AlgoVoi (chopmob-cloud).
