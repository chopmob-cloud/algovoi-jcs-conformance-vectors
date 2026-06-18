<!--
  Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
  Part of the AlgoVoi agentic-payments substrate. Retain NOTICE on redistribution.
-->

# regulatory_audit_trail_v1

The apex composition: the full record a single regulated agentic payment produces
across its life, assembled from published conformance vectors only, verified
offline, and mapped stage by stage to the IETF I-D that specifies it and to the
record-keeping obligations of the EU, UK, US, and the FATF global standard.

```bash
pip install algovoi-substrate
python verify_audit_trail.py
```

## Scope of the regulatory mapping

These constructions provide tamper-evident, offline-verifiable, retained
transaction records that **support the record-keeping, retention, and audit-trail
/ integrity obligations** of the regimes below. This maps that dimension only.
It does not, by itself, make any firm compliant; jurisdictional applicability is
fact-specific; and **this is not legal advice**. Citations are to the principal
record-keeping provision in each regime.

## The trail (technical)

| Stage | Primitive | I-D |
| --- | --- | --- |
| admission | compliance receipt | `draft-hopley-x402-compliance-receipt` |
| action identity | `action_ref` | `draft-hopley-x402-retention-chain` Sec 7.1 |
| exactly-once commit | `transition_hash` (COMMITTED) | `draft-hopley-x402-retention-chain` Sec 7.2-7.3 |
| settlement | `settlement_ref` | `draft-hopley-x402-settlement-attestation` |
| retention | `retention_chain_ref` | `draft-hopley-x402-retention-chain` Sec 4 |
| binding | `binding_ref` | `draft-hopley-x402-retention-chain` Sec 7.6 |

## The trail (record-keeping obligation it supports, by regime)

| Stage | EU | UK | US | FATF |
| --- | --- | --- | --- | --- |
| admission | MiCA Art 80 | MLR 2017 reg 40 | BSA 31 CFR 1010.430 | Rec 11 |
| action identity | MiCA Art 80 | MLR 2017 reg 40 | BSA 31 CFR 1010.430 | Rec 11 |
| exactly-once commit | DORA Art 14 | FCA SYSC 9 | BSA recordkeeping | Rec 11 |
| settlement | MiCA Art 80 | MLR 2017 reg 40 | BSA 31 CFR 1010.430 | Rec 16 (transfer info) |
| retention | AMLR Art 56 | MLR 2017 reg 40 (5 yr) | BSA 31 CFR 1010.430 (5 yr) | Rec 11 (>=5 yr) |
| binding | MiCA Art 80 + DORA Art 14 | MLR 2017 reg 40 + FCA SYSC 9 | BSA 31 CFR 1010.430 | Rec 11 |

Each record reproduces byte-for-byte from its published vector; the `binding_ref`
is recomputed from the composed action, transition, settlement, and retention
values and matches `settlement_action_binding_v1` (`sab-v1-001`). No new vector
and no new hashing primitive are introduced. An auditor verifies the whole trail
with SHA-256 and a JSON parser, without contacting the issuer.

The constructions are public under Apache 2.0 (the JCS layer). The signed
companion (RFC 9421) and managed pack generation are separate.
