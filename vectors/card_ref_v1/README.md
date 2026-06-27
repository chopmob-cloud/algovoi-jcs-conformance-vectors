# card_ref_v1

Conformance vectors for card_ref, a content addressed reference to an A2A AgentCard.

    card_ref = "sha256:" + SHA-256(JCS(AgentCard without the signatures field))

The preimage is exactly the A2A spec 8.4.2 signing payload (signatures excluded), so card_ref is the content address of the same bytes A2A canonicalizes under RFC 8785 for AgentCard signing (spec 8.4.1).

## Vectors

- positives: cr-example (the A2A Example Agent card; its card_ref is the canonical bytes hash A2A itself signs), cr-multiskill
- invariants: a signatures field does not change card_ref, key reorder does not change it
- negatives: a changed skill diverges, a changed security scheme diverges

## Run

    python runner_python.py
    node runner_node.js

Both reproduce 6/6 byte for byte. Validated locally and on a VM2 clean box against the published algovoi-substrate and @algovoi/substrate.

Apache 2.0. Copyright (c) 2026 AlgoVoi (chopmob-cloud).
