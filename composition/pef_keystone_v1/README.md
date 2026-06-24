# pef_keystone_v1 (PEF is the signed-transport layer over the keystone)

Composition proof that a **Payment Evidence Frame (PEF)** wraps and pins a keystone fact, so
the frame commits to the exact keystone position it carries:

```
keystone fact:   execution_binding{execution_ref, settlement_ref, retention_chain_ref, binding_ref}
                          │  (carried verbatim as the PEF receipt)
PEF receipt_hash = "sha256:" + SHA-256(JCS(receipt))          # pins the keystone payload
PEF frame_id     = "sha256:" + SHA-256(JCS(preimage))         # commits to the whole frame
```

PEF is the **envelope**, not a new link in the byte-for-byte spine. The keystone gives
content-addressed, recomputable facts; PEF turns any one of them into a signed, attributable,
routable frame (it carries `frame_provider_did`, `frame_timestamp_ms`, and in the commercial
tier a signature). Here the open/unsigned frame is proven to commit to its keystone payload:
tamper any carried reference and both `receipt_hash` and `frame_id` diverge.

Reused shapes (no new construction):
- `execution_ref` from `execution_ref_v1` / `keystone_v1`.
- `execution_binding` (the `binding_ref`) from `settlement_binding_v1`.
- the PEF `frame_id` / `receipt_hash` construction from `pef_v1`, byte-identical.

The only PEF schema change is additive: a `claim_type` value `payment_execution` for the
execution tier. The preimage shape is identical to `pef_v1`. The keystone position the frame
attests is `receipt.binding_ref` (an explicit top-level `binds_ref` field is a clean PEF v1.1
follow-on for routing without parsing the receipt).

Run:
```
python verify_pef_keystone.py    # pip install rfc8785
node   verify_pef_keystone.mjs   # npm install canonicalize
```
Both reproduce the receipt_hash and frame_id byte-for-byte and report PASS 6/6.

`pef_keystone_trace.json` is regenerated deterministically by `generate_pef_keystone.py`.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
