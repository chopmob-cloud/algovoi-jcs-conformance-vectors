# `composite_trust_query_v1`

AlgoVoi-authored conformance vector set for the **composite trust
query response format** specified in IETF Internet-Draft
[`draft-hopley-x402-composite-trust-query`](https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/)
(Independent Submission, Informational; AlgoVoi-authored).

Records a verifier's categorical conclusion over an audit chain
composed of compliance, settlement, cancellation, and refund
receipts. The verifier walks the chain, applies a stated query, and
emits a single composite-trust-claim response anchoring the chain
by its content-addressed root.

Composes above [`compliance_receipt_v1`](../compliance_receipt_v1/),
[`settlement_attestation_v1`](../settlement_attestation_v1/),
[`cancellation_receipt_v1`](../cancellation_receipt_v1/), and
[`refund_receipt_v1`](../refund_receipt_v1/) under the same JCS RFC
8785 canonicalisation pin (`urn:x402:canonicalisation:jcs-rfc8785-v1`).

## What this vector set proves

Eight byte-level reference vectors + seven pair invariants + three
chain invariants pin:

1. **`trust_outcome` is a closed FOUR-element enumeration**
   {TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, UNTRUSTED}. Four
   byte-distinct content_hashes. The four-value enum captures
   the genuinely four-state decision space: proceed,
   proceed-with-caution, hold-pending-more-data, halt.

2. **`canon_version` is byte-load-bearing.**

3. **Audit chain rows link via `prev_hash`.** A CTQ response MAY
   itself be embedded in an audit chain, enabling the
   verifier-of-verifier pattern.

## Response content_hashes

Fixed response fields across vectors 001 to 005:

```json
{
  "chain_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "ctq_timestamp_ms": 1716494400000,
  "query_ref": "sha256:8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52",
  "verifier_did": "did:example:trust-verifier-1"
}
```

`jurisdiction_flags` is `["UK","EU"]` for vectors 001-005.

| Vector | `trust_outcome` | `canon_version` | `expected_content_hash` |
|---|---|---|---|
| 001 | `TRUSTED` | `jcs-rfc8785-v1` | `fd461c6c63330e0b15ed57b40d687ccadbd1ca2359cb5cf0f53e23c5d4f5c555` |
| 002 | `PROVISIONAL` | `jcs-rfc8785-v1` | `c4d0ff19946ec926475e340c73f0e0d61019fe8ef6fc6086c98e5e2efa88bd54` |
| 003 | `INSUFFICIENT_EVIDENCE` | `jcs-rfc8785-v1` | `7f295d3431a028ee2bd57125b4b30035b015c5af0371d02c411a3122cdd8a81e` |
| 004 | `UNTRUSTED` | `jcs-rfc8785-v1` | `6e7a95c85136549a67417da3b71b5f1cbbc8c9d4fb9d91e30674a727e274db51` |
| 005 | `TRUSTED` | `jcs-rfc8785-v2` | `c9217bca9d6c9d95f926384688a5321626ef035a32468aea0a98778d0ba17bd1` |

## The closed enumeration: `trust_outcome`

| Value | Semantic | Operator action |
|---|---|---|
| `TRUSTED` | Verified chain answers the query affirmatively. All anchored receipts present and consistent. | Proceed under asserted trust posture. |
| `PROVISIONAL` | Chain is partially complete; some receipts in `PENDING_FINALITY` or analogous non-terminal state. | Proceed cautiously; re-query after pending events finalise. |
| `INSUFFICIENT_EVIDENCE` | Chain does not contain enough evidence to answer the query (missing segments, external-state references, undereferenceable pointers). | Gather more evidence; do not proceed under TRUSTED. |
| `UNTRUSTED` | Chain contains evidence that negates the query (compliance-forced termination, settled-then-reversed transaction, REJECTED refund, expired mandate). | Halt the action the query was framed to authorise. |

## Reference implementations

| Language | Package | How to run |
|---|---|---|
| Python | [`algovoi-composite-trust-query`](https://pypi.org/project/algovoi-composite-trust-query/) (>=0.1.0) | `pip install algovoi-composite-trust-query && python runner_python.py` |
| TypeScript | [`@algovoi/composite-trust-query`](https://www.npmjs.com/package/@algovoi/composite-trust-query) (>=0.1.0) | `npm install @algovoi/composite-trust-query && node runner_node.js` |

## Composition

A CTQ response references an audit chain via `chain_ref`. The chain
itself is composed of the four receipt formats (compliance,
settlement, cancellation, refund). The verifier walks the chain,
applies a structured query, and emits a single composite-trust claim:

```
audit chain (admission -> settlement -> cancellation [-> refund])
        |
        v   (chain_ref)
CTQ response (TRUSTED | PROVISIONAL | INSUFFICIENT_EVIDENCE | UNTRUSTED)
```

A regulator, dashboard, or downstream agent consuming the CTQ
response gets a single byte-deterministic statement of the trust
posture without re-walking the underlying chain. The chain remains
independently verifiable at the `chain_ref` content-address.

## Authorship

AlgoVoi-authored. Welcomes downstream-adopter contributions per the
Appendix C "Known Adopters" pattern.

## Licence

Apache 2.0.
