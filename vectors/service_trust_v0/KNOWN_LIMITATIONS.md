# Known Limitations

These vectors test the `service_trust` risk-check category. They do NOT test:

- Sanctions or AML screening (that's `compliance_risk`)
- Identity verification or KYC
- Cross-chain payment activity (Base mainnet only)
- Real-time transaction monitoring
- Provider key rotation or revocation

## Score stability

Trust scores are derived from live on-chain data. Exact scores for indexed services may change between runs as payment volumes update. The conformance invariants are:

- In-index services return a numeric score (0-100) with tier and recommendation
- Out-of-index services return `score: null, recommendation: no_data`
- JWS attestations verify against the published JWKS
- `canon_version` matches `jcs-rfc8785-v1`

## What null means

`score: null` means "no observed x402 payment activity on Base mainnet." It does NOT mean:

- The service is untrustworthy
- The service failed a check
- The provider is unable to score

A year-five auditor seeing `null` can distinguish "Supership had no signal" from "Supership saw bad signal." This distinction is load-bearing for the retention-property clause in the shared canonicalization section (#2326 v3).
