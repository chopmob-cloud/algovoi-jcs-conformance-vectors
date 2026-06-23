# payment_mandate_lite_v1

Conformance vectors for AlgoVoi Payment Mandate (lite): a content-addressed reference to the terms of a spend authority.

    mandate_ref = "sha256:" + SHA-256(JCS({ cap, payer, period, revocation_state }))

11 vectors: 3 positive, 6 negative (payer / cap / period / revocation divergence, plus empty-field reject), and 2 invariants (field-distinctness, reject-empty). `mandate_1` and `mandate_2` equal `mandate_1` / `mandate_2` in `spend_guardrail_lite_v1` (the `mandate_ref` the pre-payment decision binds), so the decision chain composes.

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
