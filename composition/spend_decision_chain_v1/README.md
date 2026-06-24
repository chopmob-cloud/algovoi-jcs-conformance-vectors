# spend_decision_chain_v1 (composition keystone)

End-to-end composition proof of the open pre-payment decision chain. It introduces no new vectors and no new hashing primitive: every value asserted is the published expected output of an existing lite conformance set.

```
identity   passport_ref      (agent_passport_lite_v1, ap-001)   binds as agent_ref
authority  mandate_ref       (payment_mandate_lite_v1, pm-001)  binds as mandate_ref
policy     policy_bound_ref  (policy_binding_v1, pb-sab-v1-P)    binds as policy_bound_ref
  -> decision  guardrail_ref (spend_guardrail_lite_v1, sg-allow-P / sg-deny-P)
  -> lifecycle cancellation_ref (cancellation_receipt_lite_v1, cn-001)  closes the authority
  -> lifecycle refund_ref       (refund_receipt_lite_v1, rf-001)        closes the authorized payment after settlement
```

For each of the three inputs the proof: (a) recomputes the reference from its raw fields with RFC 8785 JCS + SHA-256, (b) checks it equals the published output of its own lite set, and (c) checks it is exactly the reference the Spend Guardrail decision binds. Then it recomputes `guardrail_ref` from the three composed references plus the verdict and matches the published reference byte-for-byte, for both `ALLOW` and `DENY`.

Run an independent reimplementation:

    pip install rfc8785 ; python verify_chain.py
    node verify_chain.mjs

No package import: a JCS library and SHA-256 are the whole dependency. `chain_trace.json` carries the raw inputs and expected references; the runners recompute and cross-check against the published sets in `../../vectors/`.

Apache-2.0. (c) AlgoVoi. Preserve NOTICE attribution in any distribution.
