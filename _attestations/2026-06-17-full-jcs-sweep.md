# Attestation: full JCS corpus sweep -- 16 sets, 757 runner-vector agreements

**Date:** 2026-06-17
**Scope:** All 16 runnable JCS vector sets in `chopmob-cloud/algovoi-jcs-conformance-vectors`
**Result:** 757/757 runner-vector agreements -- zero failures across all runner-set combinations executed

## Coverage

| Set | Vectors | Langs run | Agreements |
|---|---|---|---|
| `compliance_receipt_v1` | 8 | 8 (Python Node Go Ruby PHP Rust Java .NET) | 64 |
| `settlement_attestation_v1` | 8 | 8 | 64 |
| `cancellation_receipt_v1` | 8 | 8 | 64 |
| `refund_receipt_v1` | 8 | 8 | 64 |
| `composite_trust_query_v1` | 8 | 8 | 64 |
| `pef_v1` | 8 | 8 | 64 |
| `retention_chain_v0` | 3 | 8 | 24 |
| `retention_chain_v1` | 14 | 8 | 112 |
| `epi_interop_v0` | 5 | 8 | 40 |
| `epi_pqc_v0` (JCS vectors only) | 4 | 8 | 32 |
| `action_ref_namespace_v0` | 8 | 2 (Python Node) | 16 |
| `action_ref_transactional_v0` | 8 | 2 | 16 |
| `zkp_receipt_v1` | 8 | 2 | 16 |
| `ap2_omh_v0` | 7 | 3 (Python Node Go) | 21 |
| `privacy_class_v0_1` | 13 | 3 | 39 |
| `per_chain_envelope_v0` | 19 | 3 | 57 |
| **Total** | **137** | | **757** |

## Language-library matrix

| Language | Library | Used for |
|---|---|---|
| Python 3 | `rfc8785@0.1.4` | all 16 sets |
| Node.js | `canonicalize@1.0.8` | all 16 sets |
| Go | `gowebpki/jcs v1.0.1` | 10 sets (8-lang sets + ap2/privacy/per_chain) |
| Ruby | `json-canonicalization 1.0.0` | 10 sets (8-lang sets only) |
| PHP 8.1+ | inline RFC 8785 | 10 sets (8-lang sets only) |
| Rust | `serde_jcs@0.2.0` (pre-built binaries) | 10 sets (8-lang sets only) |
| Java | `io.github.erdtman:java-json-canonicalization 1.1` | 8 sets (8-lang sets only) |
| .NET 9 | `Baqhub.Packages.JsonCanonicalization 1.0.1` | 8 sets (8-lang sets only) |

## Runner notes

- **5-format sets + pef_v1**: runners live in `_attestations/2026-05-25-8-impl-5-format-cross-validation/` and `_attestations/2026-05-30-8-impl-pef-v1/` respectively; invoked with the set JSON path as argument
- **retention_chain_v0/v1, epi_interop_v0, epi_pqc_v0**: per-set runners in `vectors/<set>/`; Rust pre-built binaries used for all four sets
- **action_ref_namespace_v0, action_ref_transactional_v0, zkp_receipt_v1**: Python + Node runners only; run from the set directory (zkp runners hardcode the filename)
- **ap2_omh_v0, privacy_class_v0_1, per_chain_envelope_v0**: Python + Node + Go; Go runners needed `go.mod` (added this run, same `require github.com/gowebpki/jcs v1.0.1` as all other sets)
- **Not executed**: Java runners in ap2/privacy_class/per_chain directories (`JcsRunner.java`/`RunnerJava.java`) use `org.webpki.jcs.JsonCanonicalizer` (cyberphone/json-canonicalization) and require a separate build step; not compiled in this environment
- **epi_pqc_v0**: Python runner reports 7/7 (4 JCS + 3 signature/key_lineage checks); other 7 langs report 4/4 (JCS only); sweep counts 4 JCS vectors consistently

## Sets not swept

- `service_trust_v0`: no JCS runner (no standard `runner_python.py` / `runner_node.js` present)
- `ctef_aps_v1`: format-specific `verify.py` only, not a JCS cross-implementation runner
- `multichain_ed25519_substrate_v0`, `rfc9421_proxy_chain_v0`, `rfc9421_proxy_chain_v1`, `rfc9421_receipt_evidence_v0`: cryptographic / RFC 9421 fixtures, not JCS hash runners

## All results verified on screen

All 757 runner-vector combinations executed and verified PASS on 2026-06-17 in a single session. No failures observed.
