# delegation_ref_v1

Conformance vectors for AlgoVoi Delegation Ref (lite): a content-addressed, tamper-evident reference to a cross-party authority delegation.

    delegation_ref = "sha256:" + SHA-256(JCS({ delegate_id, delegator_id, not_after_ms, not_before_ms, prev_delegation_ref, scope }))

10 checks: 3 positive (root, reordered-keys which JCS absorbs, chained second link), 5 negative (scope widen / expiry extend / delegate swap / chain-link break which must differ, malformed RFC 3339 validity bound which must reject), and 2 invariants (key-order invariance, chain integrity A to B). Validity bounds are integer milliseconds; `not_after_ms` must exceed `not_before_ms`; `prev_delegation_ref` is `""` (root) or a `"sha256:"`-prefixed 64-hex ref. Delegations chain via `prev_delegation_ref`, giving a tamper-evident A to B to C authority chain. The cross-party scope-consistency proof (executed scope a subset of delegated scope at every hop) is the commercial AlgoVoi Orchestrator capability, not this lite set.

Run an independent reimplementation against the published canonicalizer:

    pip install rfc8785 ; python runner_python.py
    node runner_node.js
