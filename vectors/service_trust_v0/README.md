# service_trust_v0

Conformance vectors for the `service_trust` risk-check provider category.

## Provider

- **Name**: Supership
- **Operator**: Crest Deployment Systems LLC
- **Category**: `service_trust`
- **Discovery**: `https://supership.crestsystems.ai/.well-known/risk-check.json`
- **JWKS**: `https://supership.crestsystems.ai/.well-known/jwks.json`
- **Signing**: EdDSA (Ed25519)
- **Canon version**: `jcs-rfc8785-v1`

## Evidence basis

Trust scores derived from observed on-chain x402 USDC payment flows on Base mainnet. Signals: payment volume, payer diversity, anomaly detection, health observations. Services cannot self-register or inflate counts.

Not sanctions, AML, or identity verification. Complementary to `compliance_risk`.

## Vectors

| # | Name | Tests |
|---|------|-------|
| 1 | known-service-scored | In-index service returns real score + grade |
| 2 | unknown-service-null | Out-of-index service returns `score: null, recommendation: no_data` |
| 3 | timestamp-ms-canonicalization | JWS claims use epoch integers per #2326 convention |
| 4 | null-score-not-default | `null` is distinct from `0`, `50`, or `80` |
| 5 | batch-composition | Batch preserves per-query independence |

## Reproduce

```bash
curl -X POST https://supership.crestsystems.ai/v1/risk-check \
  -H "Content-Type: application/json" \
  -d '{"service_url":"https://api.exa.ai/search"}'
```

## Known limitations

- Scores reflect observed Base mainnet payment activity only. Services on other chains are not indexed.
- Score values may change as the index updates. The invariant is the schema, not the exact score.
- Unknown services return `score: null`. This is correct behavior, not a coverage gap.
- Receipt-powered scoring requires >= 10 receipts per service. Most services are observatory-only.

## Context

Per invitation from @chopmob-cloud on [x402-foundation/x402#2421](https://github.com/x402-foundation/x402/issues/2421#issuecomment-4526146125).
