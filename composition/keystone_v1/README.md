# keystone_v1 (full keystone flow composition)

End-to-end composition proof of the **whole AlgoVoi keystone**, through the post-decision
execution-evidence tier:

```
identity   passport_ref      (agent_passport_lite_v1)   binds as agent_ref
authority  mandate_ref       (payment_mandate_lite_v1)  binds as mandate_ref
policy     policy_bound_ref  (policy_binding_v1)         binds as policy_bound_ref
  -> decision   decision_ref / guardrail_ref (spend_guardrail_lite_v1, ALLOW)
  -> execution  execution_ref (execution_ref_v1, ex-allow-committed)
  -> cap        trust_query_ref over [passport, mandate, policy, decision, execution]
                (composite_trust_query_lite_v1, tq-keystone)
```

Every reference is recomputed first-principles (RFC 8785 JCS + SHA-256, no package import) and
shown to equal the published output of its conformance set. The new link is the **execution
tier**: `execution_ref` is recomputed over the **exact `decision_ref` the chain produced**, so
the proof shows the executed action is consistent with the decision that authorized it, not
merely correlated with an identity. `trust_query_ref` then caps all five composed references in
order as one verdict.

No new vectors, no new hashing primitive: every asserted value is an existing published expected
output. The expected hashes were produced by the Python substrate, so the Node verifier passing
the same values proves Python/Node byte-for-byte parity.

Run:
```
python verify_keystone.py      # pip install rfc8785
node   verify_keystone.mjs     # npm install canonicalize
```
