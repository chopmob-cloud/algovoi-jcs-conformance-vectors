# refund_receipt_v1 -- SCHEMA design + decision record

**Status**: design (pre-generation). Bytes-level reference hashes and the
public `README.md` are produced by `generate.py` once this schema is
locked.

**Companion**: this format composes with the compliance receipt format
specified in
[`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/).
The refund receipt is the post-settlement counterpart that records
**reversal-of-funds events** with the same canonicalisation discipline
(JCS RFC 8785) and the same audit-chain semantics. A receipt-format
acquirer who reads both specifications can verify the entire payment
lifecycle from admission-time screening through settlement to refund
under one byte-deterministic canonicalisation pin.

**Targeted IETF I-D**: `draft-hopley-x402-refund-receipt`
(Independent Submission, Informational).

## Authorship

AlgoVoi-authored. This document, the receipt format it specifies, the
conformance vectors derived from it, and the reference implementations
that produce it are AlgoVoi work. Substrate authorship history is
catalogued at
<https://docs.algovoi.co.uk/substrate-authorship-provenance>.

## Schema

The refund receipt is a seven-field JSON object canonicalised under
RFC 8785 (JCS). Field names are sorted lexicographically by RFC 8785
during canonicalisation; the receipt object itself uses arbitrary
authoring order.

```json
{
  "canon_version": "jcs-rfc8785-v1",
  "jurisdiction_flags": ["UK", "EU"],
  "original_payment_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "refund_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
  "refund_provider_did": "did:web:api.algovoi.co.uk",
  "refund_result": "FULL",
  "refund_timestamp_ms": 1716494400000
}
```

### Field specifications

| Field | Type | Required | Description |
|---|---|---|---|
| `canon_version` | string | yes | In-band canonicalisation rule pin. Fixed value `jcs-rfc8785-v1` for this version. Year-five auditability property: a verifier reading retained bytes can determine which canonicalisation rule applies without an external registry. |
| `jurisdiction_flags` | ordered array of string | yes | ISO-3166-1 alpha-2 country codes or ISO-3166-1 alpha-3 region codes identifying applicable regulatory frameworks. **Array order is significant**: `["UK","EU"]` and `["EU","UK"]` are distinct receipts under RFC 8785. Authoring convention: primary jurisdiction first (where the operating entity is licensed), secondary jurisdictions in order of regulatory precedence. |
| `original_payment_ref` | string | yes | Content-addressed reference to the payment being refunded. Format: `sha256:<lowercase-hex-64>` where the hex digest is SHA-256 of the JCS-canonical bytes of the original payment record (compliance receipt, settlement attestation, or operator-specific payment record). Composition with `compliance_receipt_v1`: when refunding a payment that was admitted under a compliance receipt, `original_payment_ref` MAY equal the `content_hash` of the compliance receipt itself. |
| `refund_amount` | object | yes | Two-field object: `{"amount_minor": string, "asset_id": string}`. The `amount_minor` is a decimal-digit string of the refunded value in the asset's minor unit (avoiding float-precision and JS-integer-overflow concerns; representable losslessly under JCS). The `asset_id` identifies the asset and its decimal precision (e.g., `USDC.6` for USDC with 6 decimals). For chain-native assets the convention is `<symbol>.<decimals>` (e.g., `ALGO.6`, `ETH.18`). For ASA-style assets the convention is `<chain>:<asset_id>.<decimals>` (e.g., `algo:31566704.6`). |
| `refund_provider_did` | string | yes | DID URI identifying the entity issuing the refund. For VC-class identities this is the issuer DID; for centralised gateway-class identities this is `did:web:<host>`. |
| `refund_result` | string (closed enum) | yes | Closed three-element enumeration `{FULL, PARTIAL, REJECTED}`. See "Closed enumeration semantics" below. |
| `refund_timestamp_ms` | integer | yes | Epoch milliseconds (UTC) of the refund event. **Substrate Rule 2**: MUST be an integer; RFC 3339 string forms are not accepted at the canonicalisation layer. Year-five auditability and cross-implementation byte-determinism are load-bearing on integer-millisecond encoding. |

### Closed enumeration semantics: `refund_result`

The receipt format pins three categorical outcomes:

| Value | Semantic | Regulatory significance |
|---|---|---|
| `FULL` | The entire original payment amount has been returned to the payer (or in cross-asset substitution cases, the substituted asset of equivalent value has been delivered). | Closes the original payment for the purposes of consumer-rights statutes (UK Consumer Rights Act 2015, EU Consumer Rights Directive 2011/83/EU Article 9). |
| `PARTIAL` | Less than the original payment amount has been returned. The `refund_amount` field carries the actual refunded value; the verifier compares against the original via `original_payment_ref` linkage. | Does not close the original payment under consumer-rights statutes; further refund obligations may remain. |
| `REJECTED` | A refund request was processed and denied. No funds moved. The receipt records the denial event so downstream dispute / chargeback chains can reference it. | Required for PSD2 (Directive 2015/2366) Article 89 unauthorised-payment refund disputes: a payer who is denied a refund must receive a documented denial. Also required for chargeback evidence chains in card-network and crypto-equivalent dispute systems. |

The three-element enumeration is byte-load-bearing under canonicalisation:
each value produces a byte-distinct `content_hash` from the other two,
preserving the regulatorily-significant distinction at the
canonical-bytes level rather than collapsing to a numeric tier or score
projection. This is the same discipline as the compliance receipt's
`{ALLOW, REFER, DENY}` enumeration.

A four-state extension to include `PENDING` was considered and
rejected for v1: a pending refund is an in-flight state, not a
recorded event. Pending refunds SHOULD be tracked at the operator
layer; only the final outcome is canonicalised into the receipt.

A separate `refund_reason` enum was considered (e.g., distinguishing
CONSUMER_DEMAND, MERCHANT_DECISION, REGULATORY_OR_FRAUD) and rejected
for v1 because: (a) the reason is recoverable from the linked
`original_payment_ref` + associated compliance-evidence chain rather
than requiring a separate enum on the refund receipt, and (b) keeping
the receipt to seven fields preserves the parallel with the
six-field compliance receipt and reduces canonical-bytes surface area
that downstream verifiers must validate.

## Load-bearing invariants under RFC 8785

The following properties MUST hold under any conforming implementation:

1. **`refund_result` is a closed three-element enumeration and is
   byte-load-bearing.** Three otherwise-identical receipts varying
   only `refund_result` ∈ {FULL, PARTIAL, REJECTED} MUST produce
   three byte-distinct `content_hash` values.

2. **`jurisdiction_flags` is ordered and byte-load-bearing.** Two
   otherwise-identical receipts varying only the array order of
   `jurisdiction_flags` MUST produce different `content_hash` values.
   RFC 8785 §3.2.3 does not normalise array order.

3. **`canon_version` is byte-load-bearing.** Two otherwise-identical
   receipts varying only `canon_version` MUST produce different
   `content_hash` values. The in-band rule pin is itself canonicalised
   and signed-over.

4. **`refund_timestamp_ms` is integer-only.** Implementations MUST
   reject RFC 3339 string forms at validation time before canonicalisation.
   This is Substrate Rule 2: integer-millisecond timestamp encoding
   under JCS canonicalisation, formalised in
   [x402-foundation/x402 PR #2436](https://github.com/x402-foundation/x402/pull/2436).

5. **`refund_amount` is a sub-object with stable field order under
   RFC 8785.** JCS sorts the sub-object's keys lexicographically:
   `amount_minor` then `asset_id`. Verifiers MUST treat
   `{"amount_minor":"100000","asset_id":"USDC.6"}` as equivalent to
   the same content produced by an authoring layer that emitted fields
   in `asset_id`-first order; the JCS canonicalisation removes the
   distinction.

6. **`original_payment_ref` is content-addressed.** The string
   `sha256:<hex>` prefix is part of the canonical bytes. Implementations
   MUST NOT strip the `sha256:` prefix during canonicalisation or
   verification.

7. **Audit chain linkage**. Refund receipts MAY participate in audit
   chains (refund-of-refund / partial-refund accumulation / disputed-refund
   reversal). Chain row format follows the compliance-receipt audit chain:
   `{row_index: integer, content_hash: string, prev_hash: string,
   row_content_hash: string}`. Row 1's `prev_hash` is 64 zero hex
   characters; row N's `prev_hash` equals row N-1's `row_content_hash`.

## Composition with compliance_receipt_v1

A refund receipt's `original_payment_ref` MAY reference the
`content_hash` of a compliance receipt (when the refund is for a
payment that was admitted via the compliance flow). In that case the
full lifecycle is byte-verifiable:

```
compliance_receipt (ALLOW) -> settlement (operator layer)
                                         |
                                         v
                              refund_receipt (FULL or PARTIAL)
                                         |
                                         v
                              refund chain row (audit linkage)
```

A verifier walking the audit chain confirms: (a) the original payment
was admitted, (b) the settlement happened, (c) the refund event is
authentic and links to the original via `original_payment_ref`, (d)
the chain rows preserve hash-linkage end-to-end.

## Year-five auditability

The same five properties pinned by `draft-hopley-x402-compliance-receipt`
§6 apply to the refund receipt verbatim:

1. **Self-describing canonicalisation pin** via `canon_version`.
2. **No external rule registry required** to re-verify retained bytes.
3. **Cross-implementation verifiability** under the same eight-impl
   JCS matrix that anchors the compliance receipt.
4. **Tamper detection** via per-row content_hash and prev_hash linkage.
5. **Regulatory distinction preserved** via the closed enumeration on
   `refund_result`.

## Conformance vectors planned

The `generate.py` script will produce 8 byte-level reference vectors:

| Vector | Group | What it pins |
|---|---|---|
| 001 | result-enum | FULL refund (baseline) |
| 002 | result-enum | PARTIAL refund (otherwise identical to 001) |
| 003 | result-enum | REJECTED refund (otherwise identical to 001) |
| 004 | jurisdiction-order | array-order probe `["EU","UK"]` vs 001's `["UK","EU"]` |
| 005 | canon-version-pin | `canon_version: "jcs-rfc8785-v2"` probe |
| 006 | audit-chain-row | row 1 anchoring FULL (vector 001) |
| 007 | audit-chain-row | row 2 anchoring PARTIAL (vector 002), prev_hash chain |
| 008 | audit-chain-row | row 3 anchoring REJECTED (vector 003), prev_hash chain |

Plus 5 pair invariants and 3 chain invariants matching the compliance
receipt's structure.

## Reference implementations planned

| Language | Package | New primitive | Notes |
|---|---|---|---|
| Python | `algovoi-substrate` (next release: 0.4.0) | `build_refund_receipt(...)` | Byte-for-byte parity with TypeScript. PyNaCl + rfc8785 deps already present. |
| TypeScript | `@algovoi/substrate` (next release: 0.4.0) | `buildRefundReceipt(...)` | Mirror of Python. canonicalize@3.0.0 already present. |

The eight-implementation cross-validation matrix (Python + TypeScript +
Go + Rust + Java + PHP + C#/.NET + Ruby) will be extended to cover the
refund_receipt_v1 vector set at the JCS canonicalisation layer using
the same per-language runners already proven on `compliance_receipt_v1`
and `action_ref_namespace_v0`.

## What this schema is NOT

- **Not a dispute resolution protocol.** Disputes are state-machines
  with multiple parties; the refund receipt records ONE state
  transition (refund happened, or was rejected). Dispute orchestration
  is operator-layer.
- **Not a cross-network settlement attestation.** Cross-chain refunds
  are supported in the sense that `refund_amount.asset_id` MAY differ
  from the original payment's asset (e.g., paid in USDC on Base,
  refunded in USDC on Solana), but the receipt does NOT specify the
  cross-chain mechanism. That is a separate substrate authorship area.
- **Not a chargeback / interchange format.** Card-network chargebacks
  use ISO 8583 and ISO 20022 message families. This format applies to
  agentic-payment receipts where the categorical refund outcome is the
  load-bearing primitive.
- **Not the only refund format.** Operators MAY emit richer receipts
  with additional fields (reason codes, internal references,
  attachments). This schema specifies the **minimum byte-load-bearing
  surface** required for cross-implementation verifiability under the
  canonicalisation pin.

## Licence

Apache 2.0.
