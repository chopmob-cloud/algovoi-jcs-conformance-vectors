<!--
  Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
  Part of the AlgoVoi agentic-payments substrate. Retain NOTICE on redistribution.
-->

# regulated_lifecycle_v1

**The end-to-end composition proof.** This is the keystone: a single offline
check that the full regulated agentic-payment lifecycle composes into one
self-verifiable chain, built from already-published vectors only.

Python:

```bash
pip install algovoi-substrate
python verify_lifecycle.py
```

Node / TypeScript (byte-identical result, same `binding_ref`):

```bash
npm install
node verify_lifecycle.mjs
```

## What it proves

A settlement attestation proves a payment happened. On its own it does not prove
which verified action the payment settles, nor that the correspondence is
recorded. The lifecycle closes that, and this proof shows every link is a
published conformance output - nothing invented in between:

| Step | Primitive | Source set (published output) | Obligation |
| --- | --- | --- | --- |
| 1 | `action_ref` | `action_ref_exactly_once_v1.expected_action_ref` | MiCA Art 80 |
| 2 | `transition_hash` (COMMITTED) | `action_ref_exactly_once_v1.expected_transition_hash` | DORA Art 14 |
| 3 | `settlement_ref` | `settlement_attestation_v1.expected_content_hash` | AMLR Art 56 |
| 4 | `retention_chain_ref` | `retention_chain_v1.expected_chain_ref` | MiCA 80 / DORA 14 |
| 5 | `binding_ref` | recomputed, matches `settlement_action_binding_v1` (sab-v1-001) | all three |

The check is non-circular: the four inputs to the binding are byte-identical to
the four upstream sets' published outputs, and recomputing the binding from those
composed values reproduces the published reference:

```
binding_ref = sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca
```

## Files

- [`verify_lifecycle.py`](./verify_lifecycle.py) - the proof in Python. Exit `0` on 5/5.
- [`verify_lifecycle.mjs`](./verify_lifecycle.mjs) - the same proof in Node/TS, via
  `@algovoi/substrate`. Produces the identical `binding_ref`, proving the
  composition is reproducible across languages, not just within one runtime.
- [`lifecycle_trace.json`](./lifecycle_trace.json) - deterministic evidence pack:
  the full golden trace as data, re-derivable by hand with SHA-256 + JCS.

## Anchor

Specified in IETF Internet-Draft `draft-hopley-x402-retention-chain`, Section 7
(Payment Action Lifecycle and Settlement-Action Binding). No new vector and no new
hashing primitive are introduced here; this is composition over the existing
corpus.

Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi. Retain
[`NOTICE`](../../NOTICE) on redistribution.
