# 8-implementation cross-validation attestation -- settlement_action_binding_v1 -- 2026-06-18

This document attests the byte-for-byte cross-validation of the
**`settlement_action_binding_v1` post-settlement accountability vector set** across
**eight independent JCS RFC 8785 implementations in eight programming languages**.

**Result: 48/48 byte-for-byte agreements (6 vectors x 8 languages).**

The set binds four already-published substrate artifacts -- `action_ref` +
`transition_hash` (`action_ref_exactly_once_v1`), `settlement_ref`
(`settlement_attestation_v1`), and `retention_chain_ref` (`retention_chain_v1`) --
into one content-addressed `binding_ref`. No new hashing primitive is introduced;
the binding is JCS (RFC 8785) + SHA-256 over the four references, with a `sha256:`
algorithm prefix on the output.

## Vector set

| Field | Value |
|---|---|
| Vector set ID | `settlement_action_binding_v1` |
| Vectors | 6 |
| Pair invariants | 5 (incl. 1 `same_hash_as` stability) |
| Composes with | `action_ref_exactly_once_v1`, `settlement_attestation_v1`, `retention_chain_v1` |
| Canonicalisation pin | `jcs-rfc8785-v1` |
| Vector file | [`vectors/settlement_action_binding_v1/settlement_action_binding_v1.json`](../vectors/settlement_action_binding_v1/settlement_action_binding_v1.json) |

### Reference binding_ref values

| Vector | group | `binding_ref` |
|---|---|---|
| `sab-v1-001` | reference | `sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca` |
| `sab-v1-002` | stability | `sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca` (== 001) |
| `sab-v1-003` | settlement | `sha256:cf6eb49236702195b0a8b960929ffa993d38d3ddbbb302a1f68f32e54bab23ca` |
| `sab-v1-004` | action | `sha256:0bae722c5489179921d8cb3e747f9457d42036f50642fab0e8617ec89d41d5c2` |
| `sab-v1-005` | state | `sha256:d1d3b29e5d081f091376f886bfd11f0bb85034df7e6104a1726ed3929dfa2af3` |
| `sab-v1-006` | chain | `sha256:c9cb63c77330d7a3bd9f6252ffe7f3b5d967d4594984cf2120f80b146dc43d76` |

## Implementations

Each runner canonicalises every vector's four-field `preimage` under RFC 8785,
base64-encodes the bytes (checked against `expected_jcs_bytes_b64`), and takes the
lowercase-hex SHA-256 (checked against `expected_content_sha256`). The `binding_ref`
is that digest with the `sha256:` prefix. Generic byte-runners in
[`2026-06-18-settlement-action-binding-v1/`](./2026-06-18-settlement-action-binding-v1/).

| Runtime | JCS library | Result |
|---|---|---|
| Python 3.12 | `rfc8785` (via `algovoi-substrate`) | 6/6 PASS |
| Node 24 / TypeScript | `canonicalize@3.0.0` (via `@algovoi/substrate`) | 6/6 PASS |
| Ruby 3.4 | `json-canonicalization` | 6/6 PASS |
| PHP 8.4 | inline JCS RFC 8785 | 6/6 PASS |
| Go 1.26 | `gowebpki/jcs` | 6/6 PASS |
| Rust 1.95 (gnu) | `serde_jcs@0.2.0` | 6/6 PASS |
| Java 17 | `cyberphone/java-json-canonicalization` | 6/6 PASS |
| .NET 9 | `Baqhub.Packages.JsonCanonicalization` | 6/6 PASS |

**Total: 48/48 byte-for-byte (6 vectors x 8 languages).**

The Python and TypeScript reference runners additionally cross-check against the
substrate primitive `settlement_action_binding(...)` / `settlementActionBinding(...)`
in `algovoi-substrate` 0.4.0 / `@algovoi/substrate` 0.4.0.

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud).
- **Normative anchor**: `draft-hopley-x402-retention-chain-02` §7 + `draft-hopley-x402-settlement-attestation-00`.
- **Reference implementations**: Python `algovoi-substrate>=0.4.0` (PyPI); TypeScript `@algovoi/substrate>=0.4.0` (npm).

## Licence

Apache 2.0. See [`LICENSE`](../LICENSE) at the repository root.
