# `compliance_gate_lite_v1`

AlgoVoi-authored conformance set for **Compliance Gate (lite)** — the open,
content-addressed origination tier of the commercial
[Compliance Gate](https://docs.algovoi.co.uk/compliance-gate-v2). A categorical
screening verdict (`ALLOW` / `REFER` / `DENY`) from your own provider is bound to a
**no-PII** payer reference and a **pinned subject reference**:

```
payer_ref = "sha256:" + SHA-256(JCS({ address, network }))             (address in, only the hash out)
gate_ref  = "sha256:" + SHA-256(JCS({ payer_ref, subject_ref, verdict }))
```

`subject_ref` is imported by hash — a `policy_bound_ref` (from `policy_binding`), a
settlement-action `binding_ref`, or a `retention_chain` ref. Because the verdict is
bound to the subject, **a decision made under one policy snapshot does not recompute
under a rotated policy** — the verdict is provably tied to the policy in force.

This is the **lite** tier: content-addressed and offline-recomputable, no signature.
The commercial Compliance Gate (v2) adds Falcon-1024 signing, the maintained verifier,
and the Proofs (zero-knowledge) layer.

## Vectors (12)

- **payer_ref** — 2 no-PII payer references (the address is never emitted, only `sha256(JCS({address, network}))`).
- **3 verdicts** — `ALLOW` / `REFER` / `DENY` over one payer + one `policy_bound_ref`, each byte-distinct.
- **5 negatives** — verdict swap, policy rotation (subject under `P'`), payer swap (each diverges); invalid verdict and malformed ref (each rejected, not hashed).
- **2 invariants** — verdict distinctness; closed enumeration `{ALLOW, REFER, DENY}`.

## Verify

```bash
pip install algovoi-substrate>=0.4.0
python runner_python.py            # 12/12 PASS

npm install @algovoi/substrate
node runner_node.js                # 12/12 PASS — byte-identical to Python
```

Both runners recompute `payer_ref` and `gate_ref` from inputs and check every vector
against the published hashes. The expected hashes are produced by the
`algovoi-compliance-gate-lite` package (PyPI + npm).

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
