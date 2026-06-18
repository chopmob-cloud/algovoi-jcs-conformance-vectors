<!--
  Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
  Part of the AlgoVoi agentic-payments substrate. Retain NOTICE on redistribution.
-->

# regulatory_audit_trail_v1

The apex composition: the full record a single regulated agentic payment produces
across its life, assembled from published conformance vectors only, verified
offline, and mapped to the IETF I-D that specifies each stage and the EU
obligation it satisfies.

```bash
pip install algovoi-substrate
python verify_audit_trail.py
```

## The trail

| Stage | Primitive | I-D | Obligation |
| --- | --- | --- | --- |
| admission | compliance receipt | `draft-hopley-x402-compliance-receipt` | MiCA Art 80 |
| action identity | `action_ref` | `draft-hopley-x402-retention-chain` Sec 7.1 | MiCA Art 80 |
| exactly-once commit | `transition_hash` (COMMITTED) | `draft-hopley-x402-retention-chain` Sec 7.2-7.3 | DORA Art 14 |
| settlement | `settlement_ref` | `draft-hopley-x402-settlement-attestation` | AMLR Art 56 |
| retention | `retention_chain_ref` | `draft-hopley-x402-retention-chain` Sec 4 | MiCA 80 / DORA 14 |
| binding | `binding_ref` | `draft-hopley-x402-retention-chain` Sec 7.6 | MiCA 80 + DORA 14 + AMLR 56 |

Each record reproduces byte-for-byte from its published vector; the
`binding_ref` is recomputed from the composed action, transition, settlement, and
retention values and matches `settlement_action_binding_v1` (`sab-v1-001`). No
new vector and no new hashing primitive are introduced. An auditor verifies the
whole trail with SHA-256 and a JSON parser, without contacting the issuer.

The constructions are public under Apache 2.0 (the JCS layer). The signed
companion (RFC 9421) and managed pack generation are separate.
