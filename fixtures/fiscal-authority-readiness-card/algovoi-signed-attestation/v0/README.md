# AlgoVoi-side `fiscal_authority_readiness_card_v0` fixture (signed-attestation discriminator)

This directory carries the AlgoVoi-filled instance of the
`fiscal_authority_readiness_card_v0` shape under discussion on
[x402-foundation/x402#2405](https://github.com/x402-foundation/x402/issues/2405).

## What this card is

A no-secret, public-fixture realisation of the fiscal-authority readiness card
designed for buyer-agent preflight evaluation. The card answers the question:
**can a buyer-agent spend against this resource without a human in the loop?**

The card is permanently `PARTIAL` in this sample form (no specific settlement
to bind to). In production, AlgoVoi APM (Agent Payment Module) emits the card
with all fields resolved against the actual settlement event.

## Discriminator coverage

The v0 card has two load-bearing discriminators that this fixture exercises:

| Field | Value in this card | Path it exercises |
|---|---|---|
| `cap.enforcement` | `facilitator_policy` | Non-cryptographic cap path; regulatory-policy enforcement at admission (EMR 2011 safeguarding) |
| `charge_evidence.type` | `signed_attestation` | Manifest-anchored evidence path (vs per-settlement `receipt`); resolves to AlgoVoi compliance attestation endpoint |

The companion Vauban Pay card at the same schema exercises the OTHER pair of
values (`cryptographic` cap + `receipt` evidence). Together the two fixtures
cover both branches of each discriminator without redundancy.

## How this composes with the x402 fixture sample

Per the convention agreed on the discussion thread, this card is **maintained
by AlgoVoi in the AlgoVoi-controlled conformance corpus**. The x402-foundation
repo fixture sample (`fixtures/fiscal-authority-readiness-card-sample/v0/`)
references this card by URL rather than co-locating bytes:

```
https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/blob/main/fixtures/fiscal-authority-readiness-card/algovoi-signed-attestation/v0/card.json
```

The discovery-index pattern mirrors how the
[Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters) handles
adoption records: each contributor maintains their own artefact in their own
controlled space; the registry is the cross-reference index.

## Canonicalisation discipline

The card is canonicalisable under
`urn:x402:canonicalisation:jcs-rfc8785-v1` (JCS RFC 8785 + the schema
normalisation requirements specified in
[`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/),
POSTED on IETF datatracker under sole AlgoVoi authorship).

The card's `charge_evidence.attestation_anchor` field, the `revocation.check_url`
endpoint, and the `audit_trail.reference_url` endpoint all resolve against
production AlgoVoi APM surfaces with no secrets, no API keys, no wallet, and
no dashboard access required.

## Authority

AlgoVoi-authored. Card content reflects production AlgoVoi APM
([`api.algovoi.co.uk`](https://api.algovoi.co.uk)) configuration values:

- EMR 2011 reg 20-21 safeguarding caps: £100/mandate, £300/account, max 3 mandates
- B2 Object Lock COMPLIANCE 7-year retention for audit-chain bytes
- `/compliance/screen` for revocation; `/compliance/attestation` for charge evidence
- JCS RFC 8785 canonicalisation discipline pin

The card is published under the same MIT/Apache 2.0 licensing as the rest of
the AlgoVoi conformance corpus.

## Reference

- IETF Internet-Draft: [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/)
- IETF Internet-Draft: [`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/) (for the ALLOW / REFER / DENY categorical enum used at the revocation surface)
- x402-foundation/x402 thread: [#2405](https://github.com/x402-foundation/x402/issues/2405)
- AlgoVoi APM landing: [`docs.algovoi.co.uk/platform/apm`](https://docs.algovoi.co.uk/platform/apm)
- AlgoVoi Substrate Adopters Registry: [`docs.algovoi.co.uk/adopters`](https://docs.algovoi.co.uk/adopters)

## Licence

Apache 2.0. See [`LICENSE`](../../../../LICENSE) at the repository root.
