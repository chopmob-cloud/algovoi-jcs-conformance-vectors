# composite_trust_query_v1 -- SCHEMA design + decision record

**Status**: design (pre-generation). Bytes-level reference hashes and the
public `README.md` are produced by `generate.py` once this schema is locked.

**Lifecycle position**: verifier-side response format. Top-of-stack
above the four receipt formats (compliance, settlement, cancellation,
refund). Records that a verifier has walked an audit chain and emitted
a single composite-trust claim against a stated query.

A composite-trust-query response answers a structured question about
an audit chain ("is this payment cleared for settlement under
jurisdiction X?", "is this mandate currently active?", "is this
chain free of compliance-forced terminations?") with a categorical
outcome plus the chain reference plus the verifier identity.

Composes with the AlgoVoi receipt-format suite under the same
canonicalisation discipline pinned by IETF I-D
`draft-hopley-x402-canonicalisation-jcs-v1`.

**Targeted IETF I-D**: `draft-hopley-x402-composite-trust-query`
(Independent Submission, Informational).

## Authorship

AlgoVoi-authored. Substrate authorship history is catalogued at
<https://docs.algovoi.co.uk/substrate-authorship-provenance>.
Welcomes downstream-adopter contributions per the established
Appendix C "Known Adopters" pattern.

## Schema

The composite-trust-query response is a seven-field JSON object
canonicalised under RFC 8785 (JCS). Field names are sorted
lexicographically by RFC 8785 during canonicalisation.

```json
{
  "canon_version": "jcs-rfc8785-v1",
  "chain_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "ctq_timestamp_ms": 1716494400000,
  "jurisdiction_flags": ["UK", "EU"],
  "query_ref": "sha256:abc123...",
  "trust_outcome": "TRUSTED",
  "verifier_did": "did:web:api.algovoi.co.uk"
}
```

### Field specifications

| Field | Type | Required | Description |
|---|---|---|---|
| `canon_version` | string | yes | In-band canonicalisation rule pin. Fixed `jcs-rfc8785-v1`. |
| `chain_ref` | string | yes | Content-addressed reference (`sha256:<hex>`) to the audit chain root the verifier walked. |
| `ctq_timestamp_ms` | integer | yes | Epoch milliseconds when the verifier emitted the response. **Substrate Rule 2**: MUST be integer. |
| `jurisdiction_flags` | ordered array of string | yes | ISO-3166-1 codes; primary jurisdiction first. Array order significant under RFC 8785 §3.2.3. |
| `query_ref` | string | yes | Content-addressed reference (`sha256:<hex>`) to the canonical bytes of the query that was answered. Caller-issued; opaque to the response format. |
| `trust_outcome` | string (closed enum) | yes | Closed four-element enumeration `{TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, UNTRUSTED}`. See "Closed enumeration semantics" below. |
| `verifier_did` | string | yes | DID URI of the verifier emitting the response. |

### Closed enumeration semantics: `trust_outcome`

The response format pins four categorical outcomes:

| Value | Semantic | Operator action |
|---|---|---|
| `TRUSTED` | The verified chain answers the query affirmatively. All anchored receipts are valid, present, and consistent. No revocation, reversal, or compliance-forced termination on the chain. | Proceed under the asserted trust posture. |
| `PROVISIONAL` | Chain is partially complete; some receipts in `PENDING_FINALITY` or analogous non-terminal state. Verifier can affirm partial state but not full settlement. | Proceed cautiously; re-query after the pending events finalise. |
| `INSUFFICIENT_EVIDENCE` | The chain does not contain enough evidence to answer the query. Either chain segments are missing, the query references state outside the chain, or the verifier cannot dereference required content-addressed pointers. | Gather more evidence; do not proceed under TRUSTED. |
| `UNTRUSTED` | Chain contains evidence that negates the query (compliance-forced termination, settled-then-reversed transaction, REJECTED refund, expired-without-renewal mandate). | Halt the action the query was framed to authorise. |

Each value produces a byte-distinct `content_hash`. The enum is
closed; implementations MUST reject any other value at validation
time before canonicalisation.

The four-value enum reflects a genuinely four-state decision space:
proceed, proceed-with-caution, hold-pending-more-data, halt.
Collapsing to three values loses the operationally-distinct
INSUFFICIENT_EVIDENCE state ("we couldn't verify either way") from
UNTRUSTED ("we verified and the answer is no"), which matters for
operator dashboards, regulator reporting, and downstream automated
decision-making.

## Load-bearing invariants under RFC 8785

1. `trust_outcome` is a closed four-element enumeration and is
   byte-load-bearing. Four otherwise-identical responses varying only
   `trust_outcome` MUST produce four byte-distinct `content_hash`
   values.

2. `jurisdiction_flags` is ordered and byte-load-bearing (RFC 8785
   §3.2.3).

3. `canon_version` is byte-load-bearing.

4. `ctq_timestamp_ms` is integer-only. Implementations MUST reject
   RFC 3339 string forms at validation time before canonicalisation
   (Substrate Rule 2).

5. `chain_ref` and `query_ref` are content-addressed; the `sha256:`
   prefix is part of the canonical bytes and MUST NOT be stripped.

6. Audit chain linkage follows the same row shape as compliance /
   refund / settlement / cancellation receipts.

## Composition with other receipt classes

### Audit chain → CTQ response

A CTQ response references an audit chain via `chain_ref`. The audit
chain is itself composed of compliance, settlement, cancellation, and
refund receipts, each linked via `prev_hash`. The verifier walks the
chain, applies the query, and emits a single CTQ response anchoring
the chain by its root `content_hash`:

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

### CTQ response in the audit chain itself

A CTQ response MAY ALSO be embedded as an audit-chain row, recording
the verifier event in the chain history. This is the
verifier-of-verifier pattern: a higher-level verifier can walk a
chain that includes prior CTQ responses and emit a meta-CTQ response
over the composite.

## Year-N auditability

Same six properties pinned by `draft-hopley-x402-canonicalisation-jcs-v1`
Section 5 apply, plus one CTQ-specific property:

7. **Verifier-decision evidence chain**. A consumer reading a
   retained CTQ response years after emission can determine
   (a) which chain was queried (via `chain_ref`),
   (b) which question was asked (via `query_ref`),
   (c) who emitted the response (via `verifier_did`),
   (d) when the response was emitted (`ctq_timestamp_ms`), and
   (e) the categorical answer (`trust_outcome`), without dependence
   on the verifier's continued operation.

## Conformance vectors planned

8 byte-level reference vectors:

| Vector | Group | What it pins |
|---|---|---|
| 001 | outcome-enum | TRUSTED (baseline) |
| 002 | outcome-enum | PROVISIONAL |
| 003 | outcome-enum | INSUFFICIENT_EVIDENCE |
| 004 | outcome-enum | UNTRUSTED |
| 005 | canon-version-pin | `canon_version: "jcs-rfc8785-v2"` probe |
| 006 | audit-chain-row | row 1 anchoring TRUSTED (vector 001) |
| 007 | audit-chain-row | row 2 anchoring PROVISIONAL (vector 002) |
| 008 | audit-chain-row | row 3 anchoring UNTRUSTED (vector 004) |

Plus 7 pair invariants (4-choose-2 + canon-pin) and 3 chain
invariants.

## Reference implementations planned

| Language | Package | New primitive |
|---|---|---|
| Python | `algovoi-composite-trust-query` (v0.1.0) | `build_ctq_response(...)` |
| TypeScript | `@algovoi/composite-trust-query` (v0.1.0) | `buildCtqResponse(...)` |

Both depend on `algovoi-substrate` / `@algovoi/substrate`. Apache 2.0.

## What this is NOT

- **Not a receipt.** Receipts record events that happened; a CTQ
  response records a verifier's categorical conclusion over an event
  chain. Receipts are emitted by participants in the event; CTQ
  responses are emitted by verifiers reading the event chain.
- **Not the query itself.** The query that was asked is identified
  by `query_ref` (content-addressed). The query format is opaque to
  the response format; callers MAY use any structured-question
  encoding. The response answers a particular query but does not
  embed it.
- **Not chain-finality semantics.** The verifier applies whatever
  finality semantics its risk model requires; the response records
  the verifier's categorical conclusion, not the underlying finality
  model.

## Licence

Apache 2.0.
