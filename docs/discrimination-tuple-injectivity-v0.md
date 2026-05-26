# Discrimination-tuple injectivity rule — v0 substrate

**Status:** v0 — AlgoVoi-authored substrate, mirrored from primary framing on A2A #1734.
**Author:** AlgoVoi (chopmob-cloud).
**Origin:** [a2aproject/A2A#1734](https://github.com/a2aproject/A2A/discussions/1734), comment dated 2026-05-14.
**Related substrate:** [`urn:x402:canonicalisation:jcs-rfc8785-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/) (AlgoVoi canonicalisation discipline, IETF Independent Submission).
**License:** Apache 2.0 (same as the rest of this repository).

This file is the AlgoVoi-hosted canonical statement of the discrimination-tuple
injectivity rule and the verifier-side production angle. The rule was first
posted by AlgoVoi on A2A #1734 (2026-05-14) and is reproduced here under
AlgoVoi authorship so the substrate-author position has an
AlgoVoi-controlled host independent of any downstream composition document.

For downstream composition documents that incorporate this substrate under
named co-authorship discipline, see the
`semantic-divergence-boundary-v0` composition at
[`agentgraph-co/agentgraph` commit `229040bbf7b80c8f6abdcd62066b50a8d4be4793`](https://github.com/agentgraph-co/agentgraph/blob/229040bbf7b80c8f6abdcd62066b50a8d4be4793/docs/standards/semantic-divergence-boundary-v0.md)
(per kenneives, 2026-05-25, with named co-authorship of §2 on AlgoVoi per
A2A #1734 May 14 framing + May 23 co-authorship request).

---

## §1 — The problem the rule solves

Two URN-namespaced attestations may carry distinct semantic claims while
producing identical canonical-byte representations under JCS-RFC 8785 +
lowercase-hex SHA-256. The substrate layer has no semantic notion of what each
URN means; it only canonicalises bytes. A verifier that operates at the
substrate layer accepts both as conformant, leaving the semantic resolution to
downstream consumers — which may interpret them inconsistently.

This is the "byte-match identity, semantic divergence" gap. The rule below
closes it at substrate layer without requiring the substrate to understand
URN-level semantics.

---

## §2 — The discrimination-tuple injectivity rule

### §2.1 Statement

For every URN-namespaced attestation row in a cross-extension trust matrix
(or any downstream extension thereof), the tuple
`(claim_type, evidenceType, source_provider_did)` SHALL be unique. No two URNs
in the matrix may claim the same triple.

Where:

- `claim_type` ∈ a closed enumerated set defined by the consuming framework
  (e.g. for CTEF v0.3.1+: `{identity, transport, authority, continuity}`).
- `evidenceType` is the evidence taxonomy value declared by the issuer (e.g.
  for the Dominion taxonomy:
  `{behavioral, regulatory, self-attested, third-party, cryptographic, observational}`).
- `source_provider_did` is the URI-form DID of the attestation issuer (e.g.
  `did:web:registrar.example.com`).

### §2.2 Why this closes the gap

Two substrate-conformant URNs producing identical canonical bytes for the
**same** `(claim_type, evidenceType, source_provider_did)` tuple are by
construction asserting the same semantic claim, so substrate-level byte-match
equivalence is also semantic equivalence. The verifier's "accept on byte-match"
decision is semantically safe.

Two URNs producing identical canonical bytes for **different**
`(claim_type, evidenceType, source_provider_did)` tuples are asserting
different semantic claims, and the substrate verifier MUST detect the
discrimination-tuple mismatch as a canonical signal of semantic divergence —
even when the canonical-bytes layer reports match. The tuple-mismatch becomes
the audit signal that converts the silent verifier-disagreement gap into a
structured rejection at substrate layer.

### §2.3 Implementation

Injectivity is enforced via cross-impl JCS_hash comparison at
substrate-validation time. The check is cheap: compute the JCS_hash of the
discrimination tuple alongside the JCS_hash of the full envelope; reject any
pair where envelope hashes match but tuple hashes differ.

---

## §3 — Verifier-side production angle

The discrimination-tuple injectivity rule has a concrete production verifier
instance: AlgoVoi's `/compliance/screen` endpoint, which accepts byte-conformant
input and produces an ALLOW / REFER / DENY classification. A tuple mismatch
between the asserted `(claim_type, evidenceType, source_provider_did)` of the
input and what `/compliance/screen` recognises as a valid known-issuer triple
is exactly the failure mode the screening verifier MUST catch before admission.

The verifier rejects rather than coerces — same fail-closed discipline as
Substrate Rule 4 of the AlgoVoi canonicalisation discipline
(see [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/) §3.4).

The rule and its production verifier-instance compose to convert
"byte-match identity, semantic divergence" from a silent-failure mode into a
structured substrate-layer rejection at a known verifier endpoint.

---

## §4 — Scope notes

- This rule operates over the **existing** tuple shape. It does not propose a
  new closed-set extension to `claim_type` or `evidenceType`. The closed
  enumerations stay defined by the consuming framework; the injectivity rule
  is the substrate-layer invariant over whatever closed sets the framework
  picks.

- The verifier's downstream action on tuple-mismatch detection (reject vs warn
  vs surface to operator) is a verifier-policy decision, not a
  substrate-discipline decision. The substrate layer's contract is to **detect**
  the mismatch deterministically; the verifier's policy contract is to **act**
  on it.

- Specific row classifications (which URN sits at which tuple) evolve under
  the rule. The discrimination-tuple injectivity rule is the substrate-layer
  invariant; specific row classifications are downstream framework decisions.

---

## §5 — Cross-references

- **AlgoVoi canonicalisation discipline (substrate):** [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/) (IETF Independent Submission, Informational track).
- **Originating thread:** [a2aproject/A2A#1734](https://github.com/a2aproject/A2A/discussions/1734), AlgoVoi comment 2026-05-14.
- **Downstream composition document** (named co-authorship of §2 on AlgoVoi): [`agentgraph-co/agentgraph` commit `229040b`](https://github.com/agentgraph-co/agentgraph/blob/229040bbf7b80c8f6abdcd62066b50a8d4be4793/docs/standards/semantic-divergence-boundary-v0.md).
- **AlgoVoi cross-validation matrix** (substrate determinism evidence): see
  [`_attestations/`](../_attestations/) — 8 implementations × 7 vector sets,
  512/512 byte-for-byte agreements.

---

## §6 — Author note

This document is the AlgoVoi-hosted canonical statement. Downstream consumers
MAY cite either this document under its commit hash on
`chopmob-cloud/algovoi-jcs-conformance-vectors` or any composition document
that incorporates the rule with named AlgoVoi attribution. Either citation
chain is acceptable; the originating-contribution attribution to AlgoVoi via
A2A #1734 (2026-05-14) is preserved in both.

— AlgoVoi (chopmob-cloud)
