# `refund_receipt_v1`

AlgoVoi-authored conformance vector set for the **refund receipt format**
specified in IETF Internet-Draft
[`draft-hopley-x402-refund-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/)
(Independent Submission, Informational; AlgoVoi-authored).

Composes with [`compliance_receipt_v1`](../compliance_receipt_v1/) via the
`original_payment_ref` linkage: a refund receipt anchors back to the
admission-time compliance decision it reverses, and a verifier walking
the audit chain can confirm the full payment lifecycle from admission
through settlement to refund under one byte-deterministic canonicalisation
pin.

Pins byte-level reference digests for the receipt format, the closed
categorical enumeration, the canonicalisation discipline, and the
audit-chain linkage property so anyone implementing the I-D has runnable
test fixtures to validate their implementation.

## What this vector set proves

The refund receipt is a seven-field JSON object canonicalised under
RFC 8785 (JCS). Its `content_hash` is the SHA-256 of the canonical bytes:

```
content_hash = SHA-256(JCS(receipt))
```

The vector set pins eight byte-level reference vectors + five pair
invariants + three chain invariants to demonstrate the load-bearing
properties of the receipt format:

1. **The `refund_result` field is a closed three-element enumeration
   {FULL, PARTIAL, REJECTED} and is byte-load-bearing.** Vectors 001 to
   003 are otherwise-identical receipts varying only `refund_result`.
   Pair invariants assert all three pairwise digests differ. The
   load-bearing property under consumer-rights and PSD2 statutes: a
   REJECTED outcome carries dispute-evidence obligations distinct from
   FULL/PARTIAL, and the receipt format preserves the operational
   distinction at the canonical-bytes level rather than collapsing it
   to a numeric tier or score projection.

2. **The `jurisdiction_flags` array is ordered and byte-load-bearing.**
   Vector 004 differs from vector 001 only in array order
   (`["EU","UK"]` vs `["UK","EU"]`) and pair invariant 001-004 asserts
   the digests differ. JCS RFC 8785 does not normalise array order.

3. **The `canon_version` pin is byte-load-bearing.** Vector 005 differs
   from vector 001 only in `canon_version` (`jcs-rfc8785-v2` vs
   `jcs-rfc8785-v1`) and pair invariant 001-005 asserts the digests
   differ. A receipt emitted under one canonicalisation-rule version
   cannot be silently re-hashed under a successor rule.

4. **Audit chain rows link via `prev_hash`.** Vectors 006, 007, 008 are
   the three rows of a hash-linked chain anchoring the receipts in
   vectors 001, 002, 003 respectively. Chain invariants assert: row 1's
   `prev_hash` is the all-zero anchor; row 2's `prev_hash` equals row
   1's `row_content_hash`; row 3's `prev_hash` equals row 2's
   `row_content_hash`. A verifier walking the chain confirms linkage
   end-to-end.

Any implementation claiming conformance with
`draft-hopley-x402-refund-receipt-00` at the canonical-bytes layer
MUST reproduce all eight `expected_content_hash` /
`expected_row_content_hash` values verbatim and MUST honour all five
pair invariants and all three chain invariants.

## Receipt content_hashes (vectors 001 to 005)

Fixed receipt fields across vectors 001 to 005:

```json
{
  "original_payment_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "refund_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
  "refund_provider_did": "did:example:refund-provider-1",
  "refund_timestamp_ms": 1716494400000
}
```

| Vector | `refund_result` | `jurisdiction_flags` | `canon_version` | `expected_content_hash` |
|---|---|---|---|---|
| 001 | `FULL` | `["UK","EU"]` | `jcs-rfc8785-v1` | `7fdd283c3a8abb14d893999d1d16e2f7697ad0539250f2e0fc3e31ce89943dcb` |
| 002 | `PARTIAL` | `["UK","EU"]` | `jcs-rfc8785-v1` | `29d7acb47a1fda6b206d0d05b90168489316cfb40733d271fb03296adcce6475` |
| 003 | `REJECTED` | `["UK","EU"]` | `jcs-rfc8785-v1` | `af063e0d297c072bd574f7ae5360a0e90598ffbb9ee1a89abdae39882012f9a8` |
| 004 | `FULL` | `["EU","UK"]` | `jcs-rfc8785-v1` | `9b239dc006263f9012fc649e992ddbbd3f1785ca95195c43bd776dfa40da4db0` |
| 005 | `FULL` | `["UK","EU"]` | `jcs-rfc8785-v2` | `0496b68959f72515e4503f60fb97bf10ef050a8c49ca560edca76c3afe302a92` |

## Audit chain row_content_hashes (vectors 006 to 008)

Each row object has the shape:

```json
{
  "content_hash": "<from vectors 001/002/003>",
  "prev_hash": "<previous row's row_content_hash, or all-zero for row 1>",
  "row_number": 1 | 2 | 3
}
```

| Vector | row_number | content_hash anchor | prev_hash | `expected_row_content_hash` |
|---|---|---|---|---|
| 006 | 1 | vector 001 (`FULL`) | 64 zero hex chars | `14b8f0130ea78a7390fed954111cfc71f6bff5783bdff36a108c6cc73fc8ffb0` |
| 007 | 2 | vector 002 (`PARTIAL`) | row 1's `row_content_hash` | `6e9063716a7d3bb2a1f716592b781a4a7a78e26abb298110f72e14853fb818da` |
| 008 | 3 | vector 003 (`REJECTED`) | row 2's `row_content_hash` | `57545c5e2cac775c59e6a7a0be939d6b1ef6c4ab4a364ed557b09d4a44410f64` |

## Pair invariants (5)

| Pair | Type | Property |
|---|---|---|
| `pair-refund-001-002` | `different_hash_from` | Closed enumeration byte-load-bearing: FULL vs PARTIAL |
| `pair-refund-001-003` | `different_hash_from` | Closed enumeration byte-load-bearing: FULL vs REJECTED |
| `pair-refund-002-003` | `different_hash_from` | Closed enumeration byte-load-bearing: PARTIAL vs REJECTED |
| `pair-refund-001-004` | `different_hash_from` | `jurisdiction_flags` array-order byte-load-bearing |
| `pair-refund-001-005` | `different_hash_from` | `canon_version` pin byte-load-bearing |

## Chain invariants (3)

| Chain | Type | Property |
|---|---|---|
| `chain-refund-001` | `field_equals` | Row 1 `prev_hash` is all-zero (chain genesis) |
| `chain-refund-002` | `field_equals_other` | Row 2 `prev_hash` equals row 1 `row_content_hash` |
| `chain-refund-003` | `field_equals_other` | Row 3 `prev_hash` equals row 2 `row_content_hash` |

## Reference implementations

| Language | Package | How to run |
|---|---|---|
| Python | [`algovoi-substrate`](https://pypi.org/project/algovoi-substrate/) (>=0.4.0) | `pip install algovoi-substrate>=0.4.0 && python runner_python.py` |
| TypeScript | [`@algovoi/substrate`](https://www.npmjs.com/package/@algovoi/substrate) (>=0.4.0) | `npm install @algovoi/substrate@^0.4.0 && node runner_node.js` |

Each runner validates all eight vectors + five pair invariants + three
chain invariants and exits with status 0 if the implementation produces
byte-identical canonical bytes and hashes for every fixture.

## Cross-implementation matrix

The JCS RFC 8785 canonicalisation layer underneath this format is
attested across **eight independent JCS implementations in eight
programming languages** per
[`_attestations/2026-05-24-8-impl-cross-validation.md`](../../_attestations/2026-05-24-8-impl-cross-validation.md).
The refund receipt's `content_hash` and `row_content_hash` values
reproduce byte-identical under any of those eight implementations.

## Authorship

AlgoVoi-authored. Substrate authorship history is catalogued at
<https://docs.algovoi.co.uk/substrate-authorship-provenance>.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
