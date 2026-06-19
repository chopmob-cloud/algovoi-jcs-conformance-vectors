# `policy_binding_v1`

AlgoVoi-authored conformance set for **Policy Binding** — additive policy-snapshot
binding over a frozen subject reference. Proves which policy was in force when a
record was sealed, and makes a silent policy rotation detectable from the record
alone.

```
policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
policy_bound_ref = "sha256:" + SHA-256(JCS({ policy_ref, subject_ref }))
```

`subject_ref` is imported by hash — a settlement-action `binding_ref`, or a
`retention_chain` ref (v0|v1). The construction is identical over every version, so
the canonicalisation base and the underlying binding/chain stay frozen. A record
sealed under policy `P` fails recomputation under a rotated `P'`.

## Vectors (14)

- **3 policy_ref** — `P`, `P'`, and `P` key-shuffled (`policy_ref(P) == policy_ref(P_shuffled)` — JCS absorbs key order).
- **6 policy_bound_ref** — every subject (retention_chain v0, retention_chain v1, settlement_action binding_ref) under both `P` and `P'`.
- **3 rotation negatives** — a record sealed under `P` does not recompute under `P'`, on each subject.
- **2 invariants** — key-order invariance; subject binding (the same policy bound to distinct subjects yields distinct refs).

## Verify

```bash
pip install algovoi-substrate>=0.4.0
python runner_python.py            # 14/14 PASS

npm install @algovoi/substrate
node runner_node.js                # 14/14 PASS — byte-identical to Python
```

Both runners recompute `policy_ref` and `policy_bound_ref` from inputs and check every
vector against the published hashes, produced by the `algovoi-policy-binding` package
(PyPI + npm). Specified in `draft-hopley-x402-retention-chain` §7.7 / §8.10.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
