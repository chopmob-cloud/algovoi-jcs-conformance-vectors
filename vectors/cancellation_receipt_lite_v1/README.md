# cancellation_receipt_lite_v1

Conformance vectors for AlgoVoi Cancellation Receipt (lite): a content-addressed reference to the cancellation of a spend authority.

    cancellation_ref = "sha256:" + SHA-256(JCS({ cancellation_reason, mandate_ref }))

10 vectors: 4 positive, 4 negative (reason swap / mandate swap [differ], invalid enum / empty mandate [reject]), and 2 invariants (field-distinctness, reject-invalid). `cancellation_reason` is a closed enum `{USER_REQUESTED, MERCHANT_REQUESTED, COMPLIANCE_TERMINATED, EXPIRED}`. `cn-001`, `cn-002` and `cn-003` cancel `mandate_1` (`sha256:a4f8cb5e…`), the `mandate_ref` in `spend_guardrail_lite_v1` / `payment_mandate_lite_v1`, so the cancellation composes onto the decision chain.

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
