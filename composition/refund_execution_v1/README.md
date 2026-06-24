# refund_execution_v1 (refund binds to the keystone execution tier)

Composition proof that a refund receipt anchors to the **execution** tier of the keystone:

```
refund_ref = "sha256:" + SHA-256(JCS({refund_amount, refund_result, subject_ref}))
                                                                     │
                                                  subject_ref == execution_ref (the committed payment)
```

The upgrade over the shipped `refund_receipt_lite_v1` (whose `subject_ref` anchors the
pre-payment `decision_ref`) is to re-anchor `subject_ref` to the `execution_ref` the keystone
produced. A refund then binds to the payment that actually **committed**, not merely to the
decision that authorized it. The anchor is byte-load-bearing: refund-of-execution and
refund-of-decision produce different `refund_ref` values, and a divergent execution (e.g.
outcome FAILED) diverges the refund.

No new hashing primitive: the `refund_receipt_lite_v1` construction unchanged, `subject_ref`
simply re-anchored; `execution_ref` from `execution_ref_v1` / `keystone_v1`.

Run:
```
python verify_refund_execution.py    # pip install rfc8785
node   verify_refund_execution.mjs   # npm install canonicalize
```
Both reproduce `refund_ref` byte-for-byte and report PASS 5/5.

`refund_execution_trace.json` is regenerated deterministically by `generate_refund_execution.py`.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
