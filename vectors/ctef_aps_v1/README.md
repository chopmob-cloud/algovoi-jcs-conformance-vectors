# AlgoVoi §3.8 byte-match validation receipt — CTEF v0.3.1 + APS v1

Verifies that **AlgoVoi's JCS canonicalizer produces byte-identical output and
SHA-256 hashes** against the canonical CTEF v0.3.1 and APS v1 test vector sets.

This receipt is filed as evidence for the §3.8 implementations list in
agentgraph-co/agentgraph v0.3.2 layering figure.

**Outcome: 14/14 vectors byte-match. Zero drift.**

| Vector set | Source | Vectors | Pass |
|---|---|---|---|
| **CTEF v0.3.1** | `https://agentgraph.co/.well-known/cte-test-vectors.json` | 4 | 4 / 4 |
| **APS v1 bilateral-delegation** | `aeoess/agent-passport-system/fixtures/bilateral-delegation/canonicalize-fixture-v1.json` | 10 | 10 / 10 |
| **Total** | | **14** | **14 / 14** |

## Implementor

- **AlgoVoi** — multi-chain agentic-payments gateway
- **DID**: `did:web:api.algovoi.co.uk` ([resolves live](https://api.algovoi.co.uk/.well-known/did.json))
- **GitHub**: [@chopmob-cloud](https://github.com/chopmob-cloud)
- **Repo (audit verifier)**: [chopmob-cloud/algovoi-audit-verifier](https://github.com/chopmob-cloud/algovoi-audit-verifier) (MIT)

## Canonicalizer used

- **Library**: [rfc8785](https://pypi.org/project/rfc8785/) v0.1.4 (Python, pure RFC 8785 implementation)
- **Language**: Python 3.12
- **Production wrapper**: `shared/utils/jcs_canonical.py` in the AlgoVoi gateway codebase

The same canonicalizer is in production use at AlgoVoi for:

| Caller | Surface | Role |
|---|---|---|
| `gateway/app/routers/mpp.py` | MPP probe + subscription endpoints | x402 v2 envelope canonicalization |
| `gateway/app/routers/public_resource.py` | `/r/{tenant}/{resource}` | x402 v2 envelope |
| `shared/utils/audit_chain.py` | Audit bundle emission | Per-row `content_hash = SHA-256(JCS(canonical_fields))` |
| `shared/utils/jcs_canonical.py` | All cross-class callers | Shared helper, single canonicalization function |

All four production paths reduce to: `rfc8785.dumps(obj)` → SHA-256 → lowercase hex.
This is the rule locked in across the four-class JCS convergence in
[x402-foundation/x402#2322](https://github.com/x402-foundation/x402/pull/2322)
and [#2334](https://github.com/x402-foundation/x402/pull/2334).

## How to reproduce

```bash
pip install rfc8785
python verify.py
```

Expected output: `Summary: 14/14 vectors byte-match`, exit code 0.

## Files in this receipt

| File | Purpose |
|---|---|
| `verify.py` | The validation script. Loads both vector files, runs each input through `rfc8785.dumps()`, compares output bytes and SHA-256 to expected. |
| `ctef_vectors.json` | Mirror of `https://agentgraph.co/.well-known/cte-test-vectors.json` at the time of run |
| `aps_vectors.json` | Mirror of `aeoess/agent-passport-system/fixtures/bilateral-delegation/canonicalize-fixture-v1.json` at the time of run |
| `receipt.json` | Per-vector record: actual canonical bytes (hex), actual sha256, expected sha256, pass flag |
| `output_log.txt` | Full stdout of the validation run |

## Verification by reviewer

To independently verify this receipt:

1. `pip install rfc8785`
2. Re-run `python verify.py` against the included vector files (or freshly-fetched copies — both should match since the vectors are pinned)
3. Inspect `receipt.json` for any `pass: false` rows (there should be none)
4. Optionally diff `receipt.json` against this receipt — every `actual_sha256` should match every `expected_sha256`

## Cross-references

This receipt complements:
- AlgoVoi's [audit-bundle public verifier repo](https://github.com/chopmob-cloud/algovoi-audit-verifier) (also uses `rfc8785`)
- The four-class JCS convergence in [x402-foundation/x402 #2322](https://github.com/x402-foundation/x402/pull/2322) and [#2334](https://github.com/x402-foundation/x402/pull/2334) (single canonicalization rule across behavioral / regulatory / cryptographic / observational evidence classes)
- The two-canonicalization pattern discussion on [a2aproject/A2A #1829](https://github.com/a2aproject/A2A/issues/1829)
- AlgoVoi's compliance attestation at [`https://api.algovoi.co.uk/compliance/attestation`](https://api.algovoi.co.uk/compliance/attestation) (live)

## Liveness anchors

- DID document: https://api.algovoi.co.uk/.well-known/did.json
- Compliance attestation: https://api.algovoi.co.uk/compliance/attestation
- A2A agent card: https://api.algovoi.co.uk/.well-known/agent-card.json
- Pay-skills card (filed for listing): https://github.com/solana-foundation/pay-skills/pull/23

All four anchors are externally reachable as of receipt-generation date (2026-05-16).