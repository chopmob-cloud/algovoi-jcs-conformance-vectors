# refund_receipt_lite_v1

Conformance vectors for AlgoVoi Refund Receipt (lite): a content-addressed reference to the refund of a prior payment or decision.

    refund_ref = "sha256:" + SHA-256(JCS({ refund_amount, refund_result, subject_ref }))

11 vectors: 4 positive, 5 negative (result swap / amount tamper / subject swap [differ], invalid enum / empty subject [reject]), and 2 invariants (field-distinctness, reject-invalid). `refund_result` is a closed enum `{FULL, PARTIAL, REJECTED}`. `rf-001`, `rf-002` and `rf-003` refund subject `sha256:2a444c62…`, the ALLOW `guardrail_ref` in `spend_guardrail_lite_v1` / `spend_decision_chain_v1`, so the refund composes onto the decision chain and closes the lifecycle after settlement.

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
