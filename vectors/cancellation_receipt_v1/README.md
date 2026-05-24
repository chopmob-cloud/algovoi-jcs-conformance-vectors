# `cancellation_receipt_v1`

AlgoVoi-authored conformance vector set for the **mandate cancellation
receipt format** specified in IETF Internet-Draft
[`draft-hopley-x402-cancellation-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/)
(Independent Submission, Informational; AlgoVoi-authored).

Records that a recurring-payment mandate (or any standing payer→payee
authorisation) has been cancelled, by whom, for what reason, and
with what effective date.

Composes with [`compliance_receipt_v1`](../compliance_receipt_v1/),
[`settlement_attestation_v1`](../settlement_attestation_v1/), and
[`refund_receipt_v1`](../refund_receipt_v1/) under the same JCS RFC
8785 canonicalisation pin (`urn:x402:canonicalisation:jcs-rfc8785-v1`).

## What this vector set proves

Eight byte-level reference vectors + seven pair invariants + three
chain invariants pin:

1. **`cancellation_reason` is a closed FOUR-element enumeration**
   {USER_REQUESTED, MERCHANT_REQUESTED, COMPLIANCE_TERMINATED, EXPIRED}.
   Four byte-distinct content_hashes. The four-value enum is one
   wider than sibling formats because mandate termination is
   genuinely four-state: payer / payee / operator / time.

2. **`canon_version` is byte-load-bearing.**

3. **Audit chain rows link via `prev_hash`.**

## Receipt content_hashes

Fixed receipt fields across vectors 001 to 005:

```json
{
  "cancellation_provider_did": "did:example:cancellation-provider-1",
  "cancellation_timestamp_ms": 1716494400000,
  "effective_from_ms": 1716537600000,
  "mandate_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
}
```

`jurisdiction_flags` is `["UK","EU"]` for vectors 001-005.

| Vector | `cancellation_reason` | `canon_version` | `expected_content_hash` |
|---|---|---|---|
| 001 | `USER_REQUESTED` | `jcs-rfc8785-v1` | `e50f8d4f9fcd8b0cf142bd65528a90d8814dd71127d4529ca77137b4b41ad407` |
| 002 | `MERCHANT_REQUESTED` | `jcs-rfc8785-v1` | `daa36f4fb78b51ea3e76c273fa31a39c01497a8fadb273c5968fed00135a918e` |
| 003 | `COMPLIANCE_TERMINATED` | `jcs-rfc8785-v1` | `d8b5c7a533d7b882f2284e28e6e081ec7b2222d74d195ae42681c9eae89bbaf9` |
| 004 | `EXPIRED` | `jcs-rfc8785-v1` | `e152ddee7c089165f4b0f5955ca4a9fa388dc4be7fcf543dee46ed419b61de51` |
| 005 | `USER_REQUESTED` | `jcs-rfc8785-v2` | `913f15d32bced7faa0b4d5411bca605635c0e4715a7bfbdad5628a95659dd2c7` |

## The closed enumeration: `cancellation_reason`

| Value | Initiator | Regulatory significance |
|---|---|---|
| `USER_REQUESTED` | Payer | PSD2 Article 64 right of revocation. UK Consumer Rights Act. May trigger refund obligation under Article 64 if recent debits already settled. |
| `MERCHANT_REQUESTED` | Payee | PSD2 Article 72 + contractual terms. Does not trigger consumer-revocation refund-window obligations. |
| `COMPLIANCE_TERMINATED` | Operator | Sanctions / KYC / AML / court order. Triggers POCA s.330 / AML 5+6 evidence chain. |
| `EXPIRED` | None | Mandate's own time-based end-state. Standard record-keeping only. |

## Reference implementations

| Language | Package | How to run |
|---|---|---|
| Python | [`algovoi-cancellation-receipt`](https://pypi.org/project/algovoi-cancellation-receipt/) (>=0.1.0) | `pip install algovoi-cancellation-receipt && python runner_python.py` |
| TypeScript | [`@algovoi/cancellation-receipt`](https://www.npmjs.com/package/@algovoi/cancellation-receipt) (>=0.1.0) | `npm install @algovoi/cancellation-receipt && node runner_node.js` |

## Composition

A cancellation receipt's `mandate_ref` MAY reference a compliance
receipt `content_hash` (mandate setup). A USER_REQUESTED
cancellation may chain forward to a refund receipt (PSD2 Article
64 refund of revoked settled debits). Full lifecycle including
cancellation:

```
compliance receipt (mandate ALLOW)
    |
    v   (settled_payment_ref)
settlement attestation (recurring execution N)
    |
    v   (some operator-layer link)
cancellation receipt (USER_REQUESTED, effective T+1)
    |
    v   (original_payment_ref)
refund receipt (FULL, if PSD2 Art. 64 refund owed)
```

## Authorship

AlgoVoi-authored. Welcomes downstream-adopter contributions per the
Appendix C "Known Adopters" pattern.

## Licence

Apache 2.0.
