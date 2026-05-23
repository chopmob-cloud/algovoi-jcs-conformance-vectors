# `action_ref_namespace_v0`

AlgoVoi-authored conformance vector set for the `action_ref` namespace-prefixing
convention. Pins the four production-anchor digests cited in the AlgoVoi
scope-conventions documentation so downstream emitters and verifiers have a
byte-level reference to validate against.

## What this vector set proves

The substrate's `action_ref` atomic primitive is:

```
action_ref = SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))
```

At the canonicalisation layer the `scope` field is a non-empty string with
no closed enum. A production convention has emerged across the substrate's
emitter set, and AlgoVoi recommends `<emitter>:<scope>` namespace prefixing
as the portable cross-emitter form.

This vector set:

1. **Pins the four production anchor digests** for the namespace-prefixed
   examples (`algovoi:compliance_screen`, `vauban:stark_settlement`,
   `agent_os:committed_claim`, `aura:reputation_observe`).
2. **Pins four unprefixed equivalents** (`compliance_screen`,
   `stark_settlement`, `committed_claim`, `reputation_observe`).
3. **Asserts byte-distinctness** between each prefixed and unprefixed pair,
   proving the namespace prefix is byte-load-bearing in the canonicalisation.

Any implementation claiming to interoperate with the AlgoVoi substrate at
the `action_ref` layer MUST reproduce all eight digests verbatim for the
preimages given in `action_ref_namespace_v0.json`.

## Anchor digests

| `scope` | `expected_action_ref` |
|---|---|
| `algovoi:compliance_screen` | `c7ab8acba5c14f792b4b17b1475b51626488d31fcf449a15675894a9469cdbfb` |
| `vauban:stark_settlement` | `749abf7610205f3b430748b811060653c102bcef2cfcc375c26a6d9fb2ac49d6` |
| `agent_os:committed_claim` | `f80c62e25e6f4f2480c3d9d9bc141e2a3c063f2c523382778d528bee426f9e48` |
| `aura:reputation_observe` | `7bf8afdc27dce3b9e9684b35de23977a348658052180f600f140db067208c3bb` |
| `compliance_screen` | `3a028e43a3020711a8bfcc8630f0c4b923ec8faa7baa7be205cf61fabd7cd4d8` |
| `stark_settlement` | `0df5918bd4205d5770d0353f1717b14f43d82dd3248a1f8d64ce23e7fb429ad1` |
| `committed_claim` | `f4fb4c7a8f31b2ed995360419680c029f35beae37061bc998e76f2abe8894b18` |
| `reputation_observe` | `e6cdc50be4cdc1cd98478b8d07fe9d609287e32e62f458b95bc4fd82982fa355` |

Fixed preimage fields across all vectors:

```json
{
  "agent_id": "agent_alpha",
  "action_type": "screen",
  "timestamp_ms": 1716494400000
}
```

Only `scope` varies between vectors.

## How to validate against this set

### Python

```bash
pip install algovoi-substrate>=0.2.1
python runner_python.py
```

### Node.js / TypeScript

```bash
npm install @algovoi/substrate@^0.2.1
node runner_node.js
```

Both runners load `action_ref_namespace_v0.json`, recompute the JCS
canonical bytes and the SHA-256 digest for each preimage, cross-check
against the substrate's `action_ref` primitive, and verify the four pair
invariants. Output is one line per vector and one line per invariant. Both
runners expect to PASS all 12 checks (8 vectors + 4 pair invariants).

### Manual verification (any RFC 8785 impl)

1. For each vector, take the `preimage` object verbatim.
2. Canonicalise it under RFC 8785 (any of the five reference impls in the
   substrate matrix: `rfc8785@0.1.4`, `canonicalize@3.0.0`,
   `gowebpki/jcs v1.0.1`, `cyberphone/json-canonicalization`,
   `serde_jcs@0.2.0`).
3. base64-encode the JCS bytes; MUST equal `expected_jcs_bytes_b64`.
4. SHA-256 the JCS bytes, lowercase hex; MUST equal `expected_action_ref`.
5. Verify pair invariants: each `different_hash_from` pair MUST produce
   distinct digests.

If any step fails, the implementation has a canonicalisation drift relative
to the AlgoVoi substrate at the `action_ref` layer.

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud). First published in response to
  AURA's scope-enum question on
  [x402#2332 comment 4526409528](https://github.com/x402-foundation/x402/issues/2332#issuecomment-4526409528).
- **Spec PR**: recommendation also being proposed as a non-normative
  paragraph in the canonicalisation spec text
  ([x402#2436](https://github.com/x402-foundation/x402/pull/2436)).
- **Substrate docs**: <https://docs.algovoi.co.uk/canonicalisation-substrate>
- **Reference implementations**:
  - Python: `algovoi-substrate>=0.2.1` on PyPI
  - TypeScript: `@algovoi/substrate>=0.2.1` on npm
- **Cross-impl validation date**: 2026-05-23. Both reference impls produce
  byte-identical digests for all eight preimages.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
