# agent_passport_lite_v1

Conformance vectors for AlgoVoi Agent Passport (lite): a content-addressed reference to an agent's identity claim.

    passport_ref = "sha256:" + SHA-256(JCS({ agent_id, issuer, scope, validity_window }))

11 vectors: 3 positive, 6 negative (agent / issuer / scope / window divergence, plus empty-field reject), and 2 invariants (field-distinctness, reject-empty). `passport_1` and `passport_2` equal `agent_ref_1` / `agent_ref_2` in `spend_guardrail_lite_v1` (the `agent_ref` the pre-payment decision binds).

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
