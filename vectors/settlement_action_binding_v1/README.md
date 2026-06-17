# `settlement_action_binding_v1`

AlgoVoi-authored conformance vector set for the **post-settlement accountability
binding**. A settlement attestation proves a *payment* occurred; on its own it
does not prove *which verified agent action* the payment corresponds to, nor that
the correspondence is recorded in a tamper-evident chain. This set pins the
canonical `binding_ref` that closes that gap by binding four already-published
substrate artifacts into one record.

## Primitive (substrate-1)

```
binding_ref = "sha256:" + SHA-256(JCS({
    action_ref,            # verified agent-action identity        (action_ref_exactly_once_v1)
    transition_hash,       # the COMMITTED lifecycle transition     (action_ref_exactly_once_v1)
    settlement_ref,        # settlement attestation content_hash    (settlement_attestation_v1)
    retention_chain_ref,   # tamper-evident chain position          (retention_chain_v1)
}))
```

No new hashing primitive is introduced: the binding is the substrate's existing
JCS (RFC 8785) + SHA-256 over the four references. The output carries the
`sha256:` algorithm prefix, consistent with `retention_chain_ref`, signalling a
content-addressed reference.

This set **composes** with the sets that produce its inputs — every anchor is
reused verbatim, so a verifier can trace each field back to its origin set:

| Field | Origin set | Value used |
|---|---|---|
| `action_ref` | `action_ref_exactly_once_v1` | `7528529a…` (agent_alpha); `57e861cb…` (agent_beta, probe) |
| `transition_hash` | `action_ref_exactly_once_v1` | `f49faa7c…` (COMMITTED 003); `0957638b…` (PENDING 002, probe) |
| `settlement_ref` | `settlement_attestation_v1` | `0ead75bf…` (001); `e7777a9a…` (002, probe) |
| `retention_chain_ref` | `retention_chain_v1` | `sha256:d23aeb00…` (001); `sha256:43f888f0…` (002, probe) |

## What this set proves

Six reference bindings + five pair invariants:

1. **Binding stability** (`sab-v1-001` == `sab-v1-002`, `same_hash_as`). Identical
   inputs reproduce the binding_ref byte-for-byte — re-derivation is idempotent,
   never a second binding.
2. **Settlement-binding** (`sab-v1-003` != `001`). A different `settlement_ref`
   diverges — a settlement cannot be re-pointed to another action's record.
3. **Action-binding** (`sab-v1-004` != `001`). A different `action_ref` diverges —
   an action cannot claim another identity's settlement.
4. **State-binding** (`sab-v1-005` != `001`). The PENDING transition_hash (not
   COMMITTED) diverges — only the exact COMMITTED transition binds; a non-committed
   state cannot masquerade as settled-bound.
5. **Chain-binding** (`sab-v1-006` != `001`). A different `retention_chain_ref`
   diverges — the chain position recording the record is load-bearing.

**Lineage-binding (consequence).** `action_ref` and `transition_hash` derive from
epoch-millisecond-integer preimages (Substrate Rule 2). An RFC 3339 string
timestamp anywhere upstream yields a different `action_ref`, hence a different
binding — an implementation on a non-conformant lineage **cannot reproduce the
binding bytes**. See `adversarial_isolation_v1` vector `adv-v1-001-ts-rfc3339`.

## Anchor digests

| Vector | group | `binding_ref` |
|---|---|---|
| `sab-v1-001` | reference | `sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca` |
| `sab-v1-002` | stability | `sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca` (== 001) |
| `sab-v1-003` | settlement | `sha256:cf6eb49236702195b0a8b960929ffa993d38d3ddbbb302a1f68f32e54bab23ca` |
| `sab-v1-004` | action | `sha256:0bae722c5489179921d8cb3e747f9457d42036f50642fab0e8617ec89d41d5c2` |
| `sab-v1-005` | state | `sha256:d1d3b29e5d081f091376f886bfd11f0bb85034df7e6104a1726ed3929dfa2af3` |
| `sab-v1-006` | chain | `sha256:c9cb63c77330d7a3bd9f6252ffe7f3b5d967d4594984cf2120f80b146dc43d76` |

## How to validate against this set

### Python
```bash
pip install algovoi-substrate>=0.4.0
python runner_python.py
```
Re-canonicalises each preimage, checks the JCS bytes + bare SHA-256 + `sha256:`-prefixed
`binding_ref`, cross-checks against the substrate primitive `settlement_action_binding(...)`,
and verifies all five pair invariants. Expect PASS on 6 vectors + 5 invariants.

### Node.js / TypeScript
```bash
npm install @algovoi/substrate@^0.4.0
node runner_node.js
```
Uses `@algovoi/substrate`'s `canonicalize` (RFC 8785) for the JCS bytes and reconstructs
`binding_ref` independently. The dedicated `settlementActionBinding` helper ships in
`@algovoi/substrate` 0.4.0.

### Manual / any RFC 8785 impl
For each vector, take the four-field `preimage` verbatim, canonicalise under RFC 8785,
base64-encode → MUST equal `expected_jcs_bytes_b64`; SHA-256 (lowercase hex) → MUST equal
`expected_content_sha256`; prepend `sha256:` → MUST equal `expected_binding_ref`. Then verify
pairs: 001 == 002; 001 != {003, 004, 005, 006}.

`generate.py` regenerates this file deterministically (fixed inputs, no clock / UUID /
randomness) — re-running reproduces byte-identical output.

## Cross-implementation validation

8 independent JCS RFC 8785 implementations reproduce all six canonical byte-strings,
digests and `binding_ref` values, **48/48 byte-for-byte** (2026-06-18): Python, Node/TS,
Ruby, PHP, Go, Rust, Java, .NET. The Python and TypeScript reference runners additionally
cross-check against the substrate primitive `settlement_action_binding(...)`. See
[`_attestations/2026-06-18-settlement-action-binding-v1.md`](../../_attestations/2026-06-18-settlement-action-binding-v1.md).

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud). Composes `action_ref_exactly_once_v1`,
  `settlement_attestation_v1`, and `retention_chain_v1`.
- **Normative anchor**: IETF Internet-Drafts
  [`draft-hopley-x402-retention-chain-02`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/)
  §7 (Payment Action Lifecycle) and
  [`draft-hopley-x402-settlement-attestation-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/).
- **Reference implementations**: Python `algovoi-substrate>=0.4.0` (PyPI);
  TypeScript `@algovoi/substrate>=0.4.0` (npm).

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
