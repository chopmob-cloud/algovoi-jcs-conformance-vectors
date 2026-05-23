# `action_ref_transactional_v0`

AlgoVoi-authored conformance vector set for the **transactional
`action_ref` lifecycle**. Pins the byte-level invariants that make
`action_ref` composable across multi-state transactional flows: the
`action_ref` digest is stable across every state transition; per-transition
lifecycle metadata sits outside the preimage; the `transition_hash`
primitive is cryptographically bound to its `action_ref`.

## What this vector set proves

The substrate defines two primitives:

```
action_ref      = SHA-256(JCS({ agent_id, action_type, scope, timestamp_ms }))
transition_hash = SHA-256(JCS({ action_ref, state, transition_timestamp_ms,
                                authority_verified_at_ms,
                                revocation_check_at_ms }))
```

The vector set pins eight reference digests + five pair invariants that
together demonstrate the load-bearing properties of the transactional
lifecycle:

1. **`action_ref` stability across the lifecycle.** Vector 001 is the
   `action_ref` identity for the fixed preimage. Vectors 002 to 008 all
   reference this same `action_ref` (or a second `action_ref` in the
   binding vector) and never recompute it from a different preimage.

2. **Per-transition byte-determinism.** Vectors 002 to 004 are a
   realistic three-state payment lifecycle (authorisation → settlement
   → refund) with distinct timestamps per state.

3. **State is byte-load-bearing in the preimage.** Vectors 005 to 007
   are the state-distinctness probe set: identical `action_ref` and
   identical timestamps under three different states, producing three
   distinct `transition_hash` digests.

4. **`transition_hash` is bound to its `action_ref`.** Vector 008
   reproduces vector 005 (authorisation, probe timestamps) under a
   **different** `action_ref` and produces a different `transition_hash`,
   confirming the binding.

5. **`action_ref` and `transition_hash` are byte-distinct.** Pair
   invariant 005 asserts vector 001 (identity) differs from vector 005
   (transition).

Any implementation claiming substrate-layer interop at the transactional
`action_ref` layer MUST reproduce all eight digests verbatim and all five
pair invariants MUST hold.

## Anchor digests

### Identity (the stable action_ref across the lifecycle)

| Vector | preimage `(agent_id, action_type, scope, timestamp_ms)` | `expected_action_ref` |
|---|---|---|
| 001 | `agent_alpha`, `payment`, `vauban:stark_settlement`, `1716494400000` | `7528529a8be2044488e603b7913efaa4f83620dbcc63010d4a1478cf7e9a473c` |

### Lifecycle (realistic three-state payment, distinct timestamps per state)

| Vector | `state` | `transition_timestamp_ms` | `expected_transition_hash` |
|---|---|---|---|
| 002 | `authorisation` | `1716494400000` | `84ff7ea191b62cb738643e65bc7422d103f4122e8537a50d23cc8111fa5b136b` |
| 003 | `settlement` | `1716494500000` | `62922e5bfad7e8f401bd598b8589f3ebc2caf2ebc7cc8b19b787ebd35b447aa3` |
| 004 | `refund` | `1716494600000` | `8983999a8e4d9b62400b4dc59ee20ad52cd6b3cb85cea6d9e8d64d40dd1b0034` |

### Probe (state-distinctness: identical action_ref, identical timestamps, varying state)

All three use `transition_timestamp_ms = 1700000000000`,
`authority_verified_at_ms = 1700000000500`,
`revocation_check_at_ms = 1700000000800`.

| Vector | `state` | `expected_transition_hash` |
|---|---|---|
| 005 | `authorisation` | `8ad232f02d68c76643916174a571b5fbdaf3c94ccf0721326704c2ca7baa908b` |
| 006 | `settlement` | `9cf0bf1f6315ada54cf3ff3ba87eeaa609e0d2841b587332c31283ce2c65c120` |
| 007 | `refund` | `94bf85f8a3ced6dc72866487b591fa1eb889e9a66557d8a517507dee5ba1aefb` |

### Binding (same state + timestamps, DIFFERENT action_ref)

Action_ref for the binding identity (agent_id = `agent_beta`,
other fields identical): `57e861cb0929fe602823a15e2bc5a5587f0b9c3bd39147baa49819dd014c56a6`.

| Vector | `state` | `transition_timestamp_ms` | `expected_transition_hash` |
|---|---|---|---|
| 008 | `authorisation` | `1700000000000` | `b59293b5f471b2c9b7dd848b4f930921057dc77d651010869ffa29f8133e6409` |

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

Both runners load `action_ref_transactional_v0.json`, recompute the JCS
canonical bytes and the SHA-256 digest for each preimage, cross-check
against the substrate's primitives (`action_ref` for the identity vector;
`transition_hash` / `transitionHash` for transition vectors), and verify
the five pair invariants. Output is one line per vector and one line per
invariant. Both runners expect to PASS all 13 checks (8 vectors + 5 pair
invariants).

### Manual verification (any RFC 8785 impl)

1. For each transition vector (002 to 008), take the five-field
   `preimage` object verbatim.
2. Canonicalise it under RFC 8785.
3. base64-encode the JCS bytes; MUST equal `expected_jcs_bytes_b64`.
4. SHA-256 the JCS bytes, lowercase hex; MUST equal
   `expected_transition_hash`.
5. For vector 001, canonicalise the four-field identity preimage and
   verify against `expected_action_ref`.
6. Verify pair invariants: each `different_hash_from` pair MUST produce
   distinct digests.

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud). The transactional
  `action_ref` lifecycle is documented in the non-normative section of
  the canonicalisation discipline in
  [x402-foundation/x402 PR #2436](https://github.com/x402-foundation/x402/pull/2436)
  (commit f81f2fe4).
- **Substrate docs**: <https://docs.algovoi.co.uk/canonicalisation-substrate>
- **Reference implementations**:
  - Python: `algovoi-substrate>=0.3.0` on PyPI
  - TypeScript: `@algovoi/substrate>=0.3.0` on npm
- **Primitive modules**:
  - Python: `algovoi_substrate.transactional` (`transition_hash`,
    `build_transactional_action_chain`)
  - TypeScript: `@algovoi/substrate`
    (`transitionHash`, `buildTransactionalActionChain`)
- **Cross-impl validation date**: 2026-05-23. Both reference impls
  produce byte-identical digests for all eight preimages and the five
  pair invariants hold under both.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
