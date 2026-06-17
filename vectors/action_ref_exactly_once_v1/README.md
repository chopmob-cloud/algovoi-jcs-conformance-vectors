# `action_ref_exactly_once_v1`

AlgoVoi-authored conformance vector set for the **exactly-once `action_ref`
lifecycle**. A strict **superset of [`action_ref_transactional_v0`](../action_ref_transactional_v0/)**:
identical `transition_hash` primitive, extended from the
authorisation→settlement→refund example to the full exactly-once lifecycle
vocabulary **PENDING → COMMITTED → REVERSED**, and pinning the two
load-bearing exactly-once invariants — **SKIP-on-retry idempotency** and
**`action_ref` replay-binding**.

## Primitives (substrate-1)

```
action_ref      = SHA-256(JCS({ agent_id, action_type, scope, timestamp_ms }))
transition_hash = SHA-256(JCS({ action_ref, state, transition_timestamp_ms,
                                authority_verified_at_ms,
                                revocation_check_at_ms }))
```

No new primitive is introduced. Every digest is the output of the existing
substrate-1 `transition_hash` over a five-field preimage; `state` simply ranges
over the exactly-once lifecycle vocabulary.

## What this set proves

Six reference digests + five pair invariants:

1. **`action_ref` stability across the lifecycle.** Vector 001 is the
   `action_ref` identity; 002–006 reference that same `action_ref` (or a second
   one for the binding probe) and never recompute it from a different preimage.

2. **Lifecycle state distinctness.** 002 `PENDING`, 003 `COMMITTED`, 004
   `REVERSED` — distinct timestamps per state, three distinct `transition_hash`
   digests.

3. **SKIP-on-retry idempotency (the exactly-once guarantee).** Vector 005
   re-presents `COMMITTED` with an **identical** `(action_ref, state,
   transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms)`
   tuple to 003 and reproduces 003's `transition_hash` **byte-for-byte**. A
   retry is idempotent: it yields the same digest, never a second effect.
   (Pair invariant `pair-eo-003`, `same_hash_as`.)

4. **`action_ref` replay-binding.** Vector 006 repeats 003's state and
   timestamps under a **different** `action_ref` and produces a different
   `transition_hash` — a replay under another identity cannot collide.
   (Pair invariant `pair-eo-004`, `different_hash_from`.)

5. **`action_ref` and `transition_hash` are byte-distinct** (`pair-eo-005`).

Any implementation claiming substrate-layer interop at the exactly-once
`action_ref` layer MUST reproduce all six digests verbatim and all five pair
invariants MUST hold.

## Anchor digests

| Vector | `state` | `expected_transition_hash` |
|---|---|---|
| 001 (identity) | — | `7528529a8be2044488e603b7913efaa4f83620dbcc63010d4a1478cf7e9a473c` (`expected_action_ref`) |
| 002 | `PENDING` | `0957638b64c790292c11d90e9ae15576a6454f37f23a0aade222acf9e2ea18b0` |
| 003 | `COMMITTED` | `f49faa7c4f82bd842705374311f5f6af073826539d519d0b65de3263258eac5f` |
| 004 | `REVERSED` | `681a6026dbbac7555c46282eaf617d3f02560925ed8b44c31e3c854fcfc1f613` |
| 005 | `COMMITTED` (retry of 003) | `f49faa7c4f82bd842705374311f5f6af073826539d519d0b65de3263258eac5f` (== 003) |
| 006 | `COMMITTED` (different action_ref) | `97124ca25721d0aa31c8e30095d067c5bb1655ab10e573a08eb2f9d5f2c6a46d` |

Vector 001 reuses `action_ref_transactional_v0`'s fixed identity
(`agent_alpha` / `payment` / `vauban:stark_settlement` / `1716494400000`); 006
uses the `agent_beta` binding identity. The exactly-once set is anchored on the
same identities as v0, so the two sets compose.

## How to validate against this set

### Python
```bash
pip install algovoi-substrate>=0.3.0
python runner_python.py
```

### Node.js / TypeScript
```bash
npm install @algovoi/substrate@^0.3.0
node runner_node.js
```

Both runners recompute the JCS canonical bytes and the SHA-256 digest for each
preimage, cross-check against the substrate's `action_ref` / `transition_hash`
primitives, and verify all five pair invariants — including the `same_hash_as`
idempotency invariant (005 == 003) and the `different_hash_from` binding
invariant (006 != 003). Expect PASS on all 6 vectors + 5 invariants.

### Manual / any RFC 8785 impl
1. For each transition vector, take the five-field `preimage` verbatim,
   canonicalise under RFC 8785, base64-encode → MUST equal
   `expected_jcs_bytes_b64`; SHA-256 (lowercase hex) → MUST equal
   `expected_transition_hash`.
2. For 001, canonicalise the four-field identity preimage → MUST equal
   `expected_action_ref`.
3. Verify pairs: 003 == 005 (idempotent retry); 006 != 003 (binding).

`generate.py` regenerates this file deterministically (fixed inputs, no clock /
UUID / randomness) — re-running reproduces byte-identical output.

## Cross-implementation validation

8 independent JCS RFC 8785 implementations reproduce all six canonical
byte-strings and digests, **48/48 byte-for-byte** (2026-06-09): Python, Node/TS,
Ruby, PHP, Go, Rust, Java, .NET. See
[`_attestations/2026-06-09-action-ref-exactly-once-v1.md`](../../_attestations/2026-06-09-action-ref-exactly-once-v1.md).

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud). Supersets the transactional
  `action_ref` lifecycle (`action_ref_transactional_v0`).
- **Normative anchor**: IETF Internet-Draft
  [`draft-hopley-x402-retention-chain-02`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/)
  Section 7 (Payment Action Lifecycle), 17 June 2026.
- **Reference implementations**: Python `algovoi-substrate>=0.3.0` (PyPI);
  TypeScript `@algovoi/substrate>=0.3.0` (npm).

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
