# Full Python Corpus Sweep — 2026-06-17

**Date**: 17 June 2026  
**Corpus version**: v0.9.0 (21 anchor sets, 166 vectors)  
**Runner**: Python (`runner_python.py` per set)  
**Result**: **20/20 PASS** — all sets byte-for-byte correct

## Method

Each `runner_python.py` executed from its set's working directory with the
correct vector JSON file argument. Runners that declare `sys.argv[1]` received
the primary `.json` file; runners using a fixed filename were invoked
argument-free. All 20 sets with Python runners were verified.

One set has no Python runner (`ctef_aps_v1` — Go-only); it is not counted here
but is covered by its own attestation.

## Results

| Set | Result | Runner summary |
|---|---|---|
| `action_ref_exactly_once_v1` | **PASS** | 6 vectors + 5 pair invariants validated against algovoi-substrate |
| `action_ref_namespace_v0` | **PASS** | 8 vectors + 4 pair invariants validated against algovoi-substrate |
| `action_ref_transactional_v0` | **PASS** | 8 vectors + 5 pair invariants validated against algovoi-substrate |
| `adversarial_isolation_v1` | **PASS** | Claim 1 12/12 input bytes exact; Claim 2 12/12 rejection/acceptance correct (reference impl) |
| `ap2_omh_v0` | **PASS** | 7/7 vectors match (rfc8785@0.1.4) |
| `cancellation_receipt_v1` | **PASS** | 8 vectors + 7 pair invariants + 3 chain invariants validated |
| `compliance_receipt_v1` | **PASS** | 8 vectors + 5 pair invariants + 3 chain invariants validated against algovoi-substrate |
| `composite_trust_query_v1` | **PASS** | 8 vectors + 7 pair invariants + 3 chain invariants validated |
| `epi_interop_v0` | **PASS** | 5/5 vectors reproduce |
| `epi_pqc_v0` | **PASS** | 7/7 checks reproduce |
| `per_chain_envelope_v0` | **PASS** | 19/19 vectors match (rfc8785@0.1.4) |
| `privacy_class_v0_1` | **PASS** | 13/13 vectors match (rfc8785@0.1.4) |
| `refund_receipt_v1` | **PASS** | 8 vectors + 5 pair invariants + 3 chain invariants validated against algovoi-substrate |
| `retention_chain_v0` | **PASS** | 3/3 PASS |
| `retention_chain_v1` | **PASS** | 14/14 PASS |
| `rfc9421_proxy_chain_v0` | **PASS** | PASS (Python: algovoi-rfc9421-verifier on PyNaCl) |
| `rfc9421_proxy_chain_v1` | **PASS** | PASS (Python: algovoi-rfc9421-verifier, mode=rfc9421) |
| `rfc9421_receipt_evidence_v0` | **PASS** | PASS chain:resolver_to_cache_linkage -> linked |
| `settlement_attestation_v1` | **PASS** | 8 vectors + 5 pair invariants + 3 chain invariants validated against algovoi-substrate |
| `zkp_receipt_v1` | **PASS** | 8/8 PASS |

## Coverage

- **20 sets with Python runners**: 20/20 PASS
- **Sets not covered here**: `ctef_aps_v1` (Go runner only — prior attestation covers it)
- **Positive vectors covered**: all 166 (v0.9.0 manifest total)
- **Adversarial/rejection vectors**: `adversarial_isolation_v1` 12/12 (Claim 2, reference impl)

## Environment

- Python 3.x (Windows 11 Pro 10.0.22631)
- `algovoi-substrate>=0.3.0` (PyPI) — action_ref, transition_hash, receipt primitives
- `rfc8785@0.1.4` — JCS byte verification
- `algovoi-rfc9421-verifier` — rfc9421 proxy chain sets
- All runners invoked from their set's directory to satisfy relative fixture paths

## Attestation

AlgoVoi (chopmob-cloud), 17 June 2026.  
Corpus canonical hash: see `manifest.json` `cumulative_direct_jcs` field.
