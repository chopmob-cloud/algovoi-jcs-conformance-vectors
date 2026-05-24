# cancellation_receipt_v1 -- SCHEMA design + decision record

**Status**: design (pre-generation). Bytes-level reference hashes and the
public `README.md` are produced by `generate.py` once this schema is locked.

**Lifecycle position**: mandate-termination event format. Records that
a recurring-payment mandate (or any standing authorisation between
payer and payee) has been cancelled, by whom, for what reason, and
with what effective date.

The format composes with the AlgoVoi receipt-format suite under the
same canonicalisation discipline pinned by IETF I-D
`draft-hopley-x402-canonicalisation-jcs-v1`.

**Targeted IETF I-D**: `draft-hopley-x402-cancellation-receipt-00`
(Independent Submission, Informational).

## Authorship

AlgoVoi-authored. Substrate authorship history is catalogued at
<https://docs.algovoi.co.uk/substrate-authorship-provenance>.
Welcomes downstream-adopter contributions per the established
Appendix C "Known Adopters" pattern.

## Schema

The cancellation receipt is a seven-field JSON object canonicalised
under RFC 8785 (JCS). Field names are sorted lexicographically by RFC
8785 during canonicalisation.

```json
{
  "canon_version": "jcs-rfc8785-v1",
  "cancellation_provider_did": "did:web:api.algovoi.co.uk",
  "cancellation_reason": "USER_REQUESTED",
  "cancellation_timestamp_ms": 1716494400000,
  "effective_from_ms": 1716537600000,
  "jurisdiction_flags": ["UK", "EU"],
  "mandate_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
}
```

### Field specifications

| Field | Type | Required | Description |
|---|---|---|---|
| `canon_version` | string | yes | In-band canonicalisation rule pin. Fixed `jcs-rfc8785-v1`. |
| `cancellation_provider_did` | string | yes | DID URI of the entity issuing the cancellation receipt. |
| `cancellation_reason` | string (closed enum) | yes | Closed four-element enumeration `{USER_REQUESTED, MERCHANT_REQUESTED, COMPLIANCE_TERMINATED, EXPIRED}`. See "Closed enumeration semantics" below. |
| `cancellation_timestamp_ms` | integer | yes | Epoch milliseconds when the cancellation event was recorded. **Substrate Rule 2**: MUST be integer. |
| `effective_from_ms` | integer | yes | Epoch milliseconds when the cancellation takes legal effect. MAY equal or differ from `cancellation_timestamp_ms`. PSD2 Article 64(3)(a) requires direct-debit revocations to be effective by end of the working day before the agreed debit date; the two timestamps support that operational separation. |
| `jurisdiction_flags` | ordered array of string | yes | ISO-3166-1 codes; primary jurisdiction first. Array order is significant under RFC 8785 §3.2.3. |
| `mandate_ref` | string | yes | Content-addressed reference (`sha256:<hex>`) to the mandate being cancelled. The mandate record itself may be a compliance receipt, an AP2 mandate object, an MPP subscription record, or an operator-specific mandate format. |

### Closed enumeration semantics: `cancellation_reason`

The receipt format pins four categorical outcomes:

| Value | Initiator | Regulatory significance |
|---|---|---|
| `USER_REQUESTED` | Payer | PSD2 (Directive 2015/2366) Article 64: payer's right to revoke a payment order. UK Consumer Rights Act 2015 consumer-revocation provisions. Triggers payer-side refund-window calculations for direct debits already settled. |
| `MERCHANT_REQUESTED` | Payee | PSD2 Article 72 + contractual terms. Merchant-initiated end of recurring billing. Does not trigger consumer-revocation refund-window obligations on already-settled debits. |
| `COMPLIANCE_TERMINATED` | Operator / regulatory | Cancellation forced by post-mandate compliance trigger: sanctions hit on payer, KYC failure, AML alert, court order, regulator directive. Triggers POCA s.330 / AML 5+6 audit-chain linkage back to the originating compliance event. |
| `EXPIRED` | None (time-based) | Mandate reached its agreed end-date or maximum-execution count. No party-initiated decision; the mandate's own terms terminated it. No additional regulatory action required beyond standard record-keeping. |

Each value produces a byte-distinct `content_hash`. The enum is
closed; implementations MUST reject any other value at validation
time before canonicalisation.

The four-value enum is one wider than the three-value enums used in
sibling formats (compliance, refund, settlement attestation) because
the regulatorily-load-bearing distinctions in mandate termination
genuinely are four-state: payer-vs-payee-vs-operator-vs-time. A
three-value collapse (e.g. PARTY_REQUESTED + AUTO_TERMINATED) would
lose the payer-vs-payee distinction that drives PSD2 refund-window
obligations.

### `effective_from_ms` semantics

The cancellation receipt records two timestamps:

- `cancellation_timestamp_ms`: when the cancellation event was
  observed and recorded by the issuing provider.
- `effective_from_ms`: when the cancellation takes legal effect.

For most cancellations these are equal. For mandate revocations
under PSD2 Article 64(3)(a) (direct debits), the receipt records
the agreed effective time, which is typically end-of-business-day
prior to the next scheduled execution. For COMPLIANCE_TERMINATED
events, the effective time may be immediate (recorded
simultaneously) or scheduled (regulator-directed).

`effective_from_ms` MUST be greater than or equal to
`cancellation_timestamp_ms`. Implementations MUST reject receipts
where the effective time precedes the recording time.

## Load-bearing invariants under RFC 8785

1. `cancellation_reason` is a closed four-element enumeration and is
   byte-load-bearing. Four otherwise-identical receipts varying only
   `cancellation_reason` MUST produce four byte-distinct
   `content_hash` values.

2. `jurisdiction_flags` is ordered and byte-load-bearing
   (RFC 8785 §3.2.3).

3. `canon_version` is byte-load-bearing.

4. `cancellation_timestamp_ms` and `effective_from_ms` are
   integer-only. Implementations MUST reject RFC 3339 string forms
   at validation time before canonicalisation. Substrate Rule 2,
   normatively specified in
   `draft-hopley-x402-canonicalisation-jcs-v1` Section 4.1.

5. `effective_from_ms` MUST be `>= cancellation_timestamp_ms`.

6. `mandate_ref` is content-addressed; the `sha256:` prefix is part
   of the canonical bytes and MUST NOT be stripped.

7. Audit chain linkage follows the same row shape as compliance /
   refund / settlement receipts.

## Composition with other receipt classes

### Compliance receipt → cancellation receipt

When a mandate was admitted under a compliance receipt and is
subsequently cancelled, the cancellation receipt's `mandate_ref`
MAY equal the compliance receipt's `content_hash`. The chain:

```
chain row N      chain row N+1
+------------+   +--------------+
| compliance |-->| cancellation |
| receipt    |   | receipt      |
| (ALLOW)    |   | (USER_REQ)   |
+------------+   +--------------+
```

### Cancellation receipt → refund receipt

When a USER_REQUESTED cancellation triggers a refund obligation
(e.g. PSD2 Article 64 revocation of a recently-settled direct
debit), the refund receipt's `original_payment_ref` MAY reference
the settled payment, and the cancellation receipt's `content_hash`
appears earlier in the chain establishing why the refund is owed.

### Full lifecycle with mandate cancellation

```
compliance receipt (ALLOW for mandate setup)
    |
    v   (settled_payment_ref or operator-layer link)
settlement attestation (recurring execution N)
    |
    v
cancellation receipt (USER_REQUESTED, effective from T+1 day)
    |
    v
refund receipt (FULL, if settled debit refunded per PSD2 Art. 64)
```

## Year-N auditability

Same six properties pinned by `draft-hopley-x402-canonicalisation-jcs-v1`
Section 5 apply, plus one cancellation-specific property:

7. **Mandate-cancellation evidence chain**. A verifier reading a
   retained cancellation receipt years after emission can determine
   (a) which mandate was cancelled (via `mandate_ref`), (b) who
   cancelled it (via `cancellation_reason` + `cancellation_provider_did`),
   (c) when the cancellation was recorded
   (`cancellation_timestamp_ms`), and (d) when it became effective
   (`effective_from_ms`), without dependence on the issuing
   operator's continued operation.

## Conformance vectors planned

8 byte-level reference vectors:

| Vector | Group | What it pins |
|---|---|---|
| 001 | reason-enum | USER_REQUESTED (baseline) |
| 002 | reason-enum | MERCHANT_REQUESTED |
| 003 | reason-enum | COMPLIANCE_TERMINATED |
| 004 | reason-enum | EXPIRED |
| 005 | canon-version-pin | `canon_version: "jcs-rfc8785-v2"` probe |
| 006 | audit-chain-row | row 1 anchoring USER_REQUESTED (vector 001) |
| 007 | audit-chain-row | row 2 anchoring MERCHANT_REQUESTED (vector 002) |
| 008 | audit-chain-row | row 3 anchoring COMPLIANCE_TERMINATED (vector 003) |

Plus 6 pair invariants (4-choose-2 + canon-pin + effective_from_ms
range) and 3 chain invariants.

## Reference implementations planned

| Language | Package | New primitive |
|---|---|---|
| Python | `algovoi-cancellation-receipt` (v0.1.0) | `build_cancellation_receipt(...)` |
| TypeScript | `@algovoi/cancellation-receipt` (v0.1.0) | `buildCancellationReceipt(...)` |

Both depend on `algovoi-substrate` / `@algovoi/substrate`. Apache 2.0.

## What this is NOT

- **Not a refund receipt**. Cancellation records the termination
  of a mandate; refund records the reversal of a settled payment.
  When a USER_REQUESTED cancellation triggers a refund, both
  receipts are emitted, chained via the audit-chain.
- **Not a dispute receipt**. Disputes are state machines over
  multiple parties; cancellation is a single state transition.
- **Not an attestation of mandate validity**. The receipt records
  the termination of a previously-valid mandate; the mandate itself
  is specified elsewhere.

## Licence

Apache 2.0.
