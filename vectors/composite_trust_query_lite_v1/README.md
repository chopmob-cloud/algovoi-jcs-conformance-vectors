# composite_trust_query_lite_v1

Conformance vectors for AlgoVoi Composite Trust Query (lite): a content-addressed reference to a trust verdict over a set of pinned references.

    trust_query_ref = "sha256:" + SHA-256(JCS({ subject_refs, trust_outcome }))

12 vectors: 4 positive, 6 negative (verdict swap / order swap / membership drop [differ], invalid enum / empty list / empty member [reject]), and 2 invariants (outcome-distinctness, subject-distinctness). `trust_outcome` is a closed enum `{TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, UNTRUSTED}`. Both the order and the membership of `subject_refs` are byte-load-bearing. `tq-001`, `tq-002` and `tq-003` assess the full live chain `[passport_ref, mandate_ref, policy_bound_ref, guardrail_ref(ALLOW)]` from `spend_decision_chain_v1`, so the verdict caps the open lifecycle.

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
