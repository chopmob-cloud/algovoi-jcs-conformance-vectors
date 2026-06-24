# audit_chain_of_frames_v1 (keystone capstone)

The whole post-decision lifecycle as one tamper-evident, capped chain of signed-transport frames:

```
Frame 1 payment_execution   wraps the execution preimage   ->  receipt_hash == execution_ref
Frame 2 payment_settlement  wraps the settlement receipt   ->  receipt_hash == settlement_ref
Frame 3 payment_refund      wraps the refund preimage       ->  receipt_hash == refund_ref
        │ frame_id                │ frame_id                       │ frame_id
        └─ row1 (prev=0*64) ── row2 (prev=row1) ── row3 (prev=row2)   (audit chain)
                                    │
                trust_query_ref([frame1_id, frame2_id, frame3_id], TRUSTED)   (one cap)
```

Each PEF frame wraps the **exact preimage** of a keystone reference, so its `receipt_hash`
*equals* that reference: the chain provably transports the keystone refs (`execution_ref`,
`settlement_ref`, `refund_ref`) themselves, not copies. The frames link into an audit chain
(`prev_hash` = prior row hash, genesis 64 zeros) and one `trust_query_ref` over the ordered
frame ids caps the lifecycle as a single verdict. Tamper any frame (e.g. a REVERSED settlement)
and its `frame_id`, the downstream rows, and the cap all diverge.

This is the capstone of the keystone roadmap: it composes everything below it. No new hashing
primitive, it reuses:
- the `pef_v1` frame construction (`receipt_hash`, `frame_id`),
- the `execution_ref_v1` / `settlement_attestation_v1` / `refund_receipt_lite_v1` receipt shapes,
- the `settlement_attestation_v1` audit-chain row shape,
- `trust_query_ref` (the keystone cap).

Run:
```
python verify_audit_chain_of_frames.py    # pip install rfc8785
node   verify_audit_chain_of_frames.mjs   # npm install canonicalize
```
Both reproduce every frame id, row hash, and the cap byte-for-byte and report PASS 6/6.

`audit_chain_trace.json` is regenerated deterministically by `generate_audit_chain_of_frames.py`.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
