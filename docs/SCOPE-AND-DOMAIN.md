# Scope and Domain Clarification

This document records the specific JCS RFC 8785 application domain that this
repository covers. It exists to establish, for the public record, the boundary
between AlgoVoi's JCS work and other projects that use JCS for unrelated purposes.

## What this repository covers

This repository is a conformance vector corpus for **x402 payment receipt
canonicalisation** using JCS RFC 8785. The canonicalisation pin is
`urn:x402:canonicalisation:jcs-rfc8785-v1`, normatively defined in IETF
Internet-Draft [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/).

The JCS application in this corpus is: serialise a payment-lifecycle record
to a byte-deterministic canonical form so that the record can be signed,
stored, and independently re-verified -- including at a regulatory record-
keeping horizon (MiCA Article 80, DORA Article 14, UK MLRs 2017 Regulation 40).

The receipt formats this corpus pins are:

| Format | IETF I-D | Datatracker | Filed |
|---|---|---|---|
| `compliance-receipt-v1` | `draft-hopley-x402-compliance-receipt` | https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/ | 2026-05-23 |
| `settlement-attestation-v1` | `draft-hopley-x402-settlement-attestation` | https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/ | 2026-05-28 |
| `composite-trust-query-v1` | `draft-hopley-x402-composite-trust-query` | https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/ | 2026-05-28 |
| `cancellation-receipt-v1` | `draft-hopley-x402-cancellation-receipt` | https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/ | 2026-05-28 |
| `refund-receipt-v1` | `draft-hopley-x402-refund-receipt` | https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/ | 2026-05-28 |
| Canonicalisation pin | `draft-hopley-x402-canonicalisation-jcs-v1` | https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/ | 2026-05-28 |

All six are filed as Independent Submissions (Informational) on the IETF
datatracker. The filing dates above are the dates of first appearance in the
IETF submission system and are independently verifiable on the datatracker.

## What this repository does NOT cover

This repository does NOT define or pin JCS usage for:

- **Agent identity hashing** -- hashing an agent descriptor to produce a stable
  identity token. That is a different application of JCS with a different input
  schema, different canonicalisation semantics, and different threat model.
- **Transparency log commitments** -- using JCS to canonicalise a log entry
  before committing to a Merkle tree or RFC 9162 log. That is a different JCS
  application with a different signed-object shape.
- **Agent-to-agent message signing** -- signing A2A task envelopes per
  agent-to-agent protocols (e.g. the A2A spec or the Envoys signature/v1
  extension). A2A messages have a different envelope shape than x402 HTTP
  payment receipts. The RFC 9421 binding extension this repo also covers
  (see [`vectors/rfc9421_proxy_chain_v0/`](./vectors/rfc9421_proxy_chain_v0/))
  targets the x402 HTTP request/response shape, not A2A task envelopes.

JCS RFC 8785 is a general-purpose primitive. Many projects use it. The fact
that a project uses JCS does not imply any overlap with the x402 payment receipt
application this repository covers.

## Cross-implementation validation

The three IETF-I-D-anchored anchor sets
([`action_ref_namespace_v0`](./vectors/action_ref_namespace_v0/),
[`action_ref_transactional_v0`](./vectors/action_ref_transactional_v0/),
[`compliance_receipt_v1`](./vectors/compliance_receipt_v1/)) have been
independently validated to produce byte-identical canonical bytes across
**eight independent JCS implementations in eight programming languages** on
2026-05-24. Result: 192/192 byte-for-byte agreements. See
[`_attestations/2026-05-24-8-impl-cross-validation.md`](./_attestations/2026-05-24-8-impl-cross-validation.md).

A subsequent sweep expanded to **five receipt formats** across the same eight
implementations on 2026-05-25: 160/160 additional vector-implementation agreements.
See [`_attestations/2026-05-25-8-impl-5-format-cross-validation.md`](./_attestations/2026-05-25-8-impl-5-format-cross-validation.md).

The implementations span non-overlapping authoring entities including the RFC 8785
author himself (Anders Rundgren, via the Java implementation). The byte-determinism
of the canonicalisation pin is therefore independently verifiable by anyone with
a JCS implementation.

## Date provenance

The dates in this document are anchored to independently verifiable public records:

- IETF I-D filing dates: verifiable on `datatracker.ietf.org` (links above)
- Cross-validation date 2026-05-24: verifiable in the git commit history of
  [`_attestations/2026-05-24-8-impl-cross-validation.md`](./_attestations/2026-05-24-8-impl-cross-validation.md)
- Cross-validation date 2026-05-25: verifiable in the git commit history of
  [`_attestations/2026-05-25-8-impl-5-format-cross-validation.md`](./_attestations/2026-05-25-8-impl-5-format-cross-validation.md)

-- AlgoVoi (chopmob-cloud)
https://docs.algovoi.co.uk/acquisition
