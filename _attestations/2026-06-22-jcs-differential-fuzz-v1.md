# JCS differential fuzz, v1

**Date:** 2026-06-22. **Author:** AlgoVoi (chopmob-cloud). **License:** Apache 2.0 (same as this repository).

## Summary

Adversarial differential fuzzing of RFC 8785 (JCS) canonicalisation across nine independent
implementations confirms that for every in-domain input, all nine produce identical canonical bytes.
Across 20000 randomised in-domain inputs under two seeds, agreement is byte for byte with zero
divergence. Across an adversarial corpus that deliberately includes out-of-domain inputs, every byte
divergence is confined to inputs outside the defined safe domain, and the reference canonicalisation
fails closed on all of them. There are zero in-domain divergences.

## Implementations (nine)

Each adapter wraps the implementation's own certified canonicaliser, the same set this repository uses in
its cross-validation matrix:

| Language | Canonicaliser |
|---|---|
| Python | rfc8785 0.1.4 (direct) |
| Python | rfc8785 via `algovoi_substrate` |
| Node.js | canonicalize 3.0.0 via `@algovoi/substrate` |
| Ruby | json-canonicalization 1.0.0 |
| PHP | stdlib JCS |
| Go | gowebpki/jcs 1.0.1 |
| Rust | serde_jcs 0.2.0 |
| Java | erdtman/java-json-canonicalization 1.1 |
| .NET | Baqhub.Packages.JsonCanonicalization 1.0.1 |

Each adapter reads one JSON document, canonicalises it with that library, and emits the SHA-256 of the
canonical UTF-8 bytes, or a typed error. The harness feeds identical input to all nine and compares.

## Method

Two input sources:

- A **curated adversarial corpus** exercising the known hard cases: object key ordering under UTF-16
  code-unit order (astral plane vs BMP, combining sequences), NFC vs NFD strings, escaped vs literal
  equivalents, lone surrogates, integers across the IEEE 754 safe-integer boundary and beyond, negative
  zero, exponent forms, duplicate member names, empty object vs empty array, deep nesting, insignificant
  whitespace, and top-level scalars.
- **Randomised generation** over the same atom space, in two modes: in-domain (safe) and adversarial.

Two divergence classes are distinguished: **byte divergence** (two implementations both accept an input
but emit different canonical bytes) and **accept or reject split** (some accept, some reject).

## Results

In-domain (safe) mode, 20000 inputs, seeds 20260622 and 7:

| Metric | Value |
|---|---|
| consensus accept (all nine, identical bytes) | 20000 of 20000 |
| byte divergence | 0 |
| accept or reject split | 0 |

Adversarial mode, 8051 inputs (51 curated + 8000 randomised):

| Metric | Value |
|---|---|
| consensus accept (all nine, identical bytes) | 2656 |
| byte divergence | 373 |
| of those, reference canonicalisation fails closed | 373 of 373 |
| **in-domain byte divergences** | **0** |

Every byte divergence occurs on an input outside the safe domain (an integer beyond the safe-integer
range, or a string that is not a valid Unicode scalar sequence). The reference canonicalisation rejects
each such input rather than producing bytes.

## The safe domain

Within this domain the nine implementations agree byte for byte:

- integers with absolute value below 2^53 (the JSON safe-integer range); larger magnitudes and
  non-finite numbers are out of domain;
- strings that are sequences of Unicode scalar values; a lone surrogate is not a scalar value and is out
  of domain;
- objects and arrays as JSON permits, with unique member names.

Outside this domain, behaviour is implementation defined: some implementations accept and some reject,
and accepting implementations may differ. Canonicalisation is therefore specified only over the safe
domain, and an input outside it should be rejected before canonicalisation rather than canonicalised.
The AlgoVoi substrate enforces these bounds at the input gate (safe-integer range and UTF-8 scalar
validity), so out-of-domain input is refused with a named code before any canonicaliser sees it. See
[Substrate Guard](https://docs.algovoi.co.uk/substrate-guard).

## Reproduction

Drive the nine canonicalisers above with identical input, compare the SHA-256 of each canonical form,
classify divergences as byte divergence or accept-or-reject split, and define the safe domain as the set
of inputs over which all nine agree. The headline claim is falsifiable: a single in-domain input on which
two conforming implementations emit different canonical bytes would refute it. Across the runs recorded
here, that count is zero.
