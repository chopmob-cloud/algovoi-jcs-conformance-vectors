# settlement_binding_v1 (settlement tier binds to the keystone execution tier)

Composition proof that the **settlement** tier binds to the **execution** tier of the
keystone, capped by one accountability reference:

```
keystone:  passport -> mandate -> policy -> decision -> execution
                                                            │
                          settlement_attestation            │  settled_payment_ref == execution_ref
                          (settlement_attestation_v1 shape) ─┘
                                                            │
                          retention-chain head over the settlement
                                                            │
              execution_binding(execution_ref, settlement_ref, retention_chain_ref)
                          = one decision-bound accountability reference
```

The new seam is `settled_payment_ref == execution_ref`: the settlement attests the exact
action the keystone executed, not merely an identity or an off-chain correlation. The
`execution_binding` socket (shipped in `algovoi-execution-ref`) then ties the executed
action, its settlement attestation, and its retention-chain head into one reference. This
is the execution-tier replacement for the old `action_ref + transition_hash` settlement
binding: one decision-bound reference instead of two.

Every reference is recomputed first-principles (RFC 8785 JCS + SHA-256, no package import)
and shown to equal a published expected value. No new hashing primitive. The expected
hashes were produced by the Python substrate, so the Node verifier passing the same values
proves Python/Node byte-for-byte parity.

Reused shapes (no new construction):
- `execution_ref` from `execution_ref_v1` (ex-allow-committed) / `keystone_v1`.
- settlement attestation receipt from `settlement_attestation_v1`.
- audit-chain row (retention head) from `settlement_attestation_v1` rows 006-008.
- `execution_binding` from `algovoi-execution-ref`.

Run:
```
python verify_settlement_binding.py    # pip install rfc8785
node   verify_settlement_binding.mjs   # npm install canonicalize
```
Both reproduce all references byte-for-byte and report PASS 6/6.

`binding_trace.json` is regenerated deterministically by `generate_settlement_binding.py`.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
