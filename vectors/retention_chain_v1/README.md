# `retention_chain_v1`

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).

AlgoVoi-authored conformance vector set for the **Retention Chain Substrate** — a self-verifiable audit chain linking payment receipts without external infrastructure.

Specified in IETF Internet-Draft [`draft-hopley-x402-retention-chain-01`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/) (AlgoVoi, sole authorship, 16 June 2026).

## Algorithm

```
retention_chain_ref = "sha256:" + SHA-256(JCS(preimage))
```

Preimage (JCS RFC 8785 lexicographic key order):

```json
{
  "chain_seq":         <integer>,
  "issuer_id":         "<string>",
  "prev_receipt_hash": "<string>",
  "receipt_hash":      "<string>"
}
```

## Vector sets

14 vectors across three invariant classes:

**Part A** — 6-link extended chain (`issuer_id=algovoi:compliance`, seq 0–5)
- Verifies seq accumulation across deeper sequences

**Part B** — multi-issuer isolation (`issuer_a` and `issuer_b`, seq 0–1 each)
- Same `receipt_hash`, different `issuer_id` → chain_refs MUST differ at every position

**Part C** — seq-gap adversarial pair (`issuer_id=algovoi:compliance`, seq 0–2 + gap)
- Proper seq 2 vs gap seq 2 (wrong `prev_receipt_hash`) → chain_refs MUST differ

## Cross-validation

Cross-validated across **8 implementations in 8 programming languages** — all live-run 2026-06-17, 14/14 PASS each:

| Language | Library | Result |
|---|---|---|
| Python | `rfc8785@0.1.4` + `hashlib.sha256` | 14/14 |
| TypeScript | `canonicalize@2.0.0` + Node.js `crypto` | 14/14 |
| Go | stdlib SHA-256 + direct JCS construction | 14/14 |
| Ruby | stdlib + direct JCS construction | 14/14 |
| Rust | `serde_jcs` + `sha2` | 14/14 |
| C# (.NET) | stdlib SHA-256 + direct JCS construction | 14/14 |
| Java | stdlib SHA-256 + direct JCS construction | 14/14 |
| Kotlin | stdlib SHA-256 + direct JCS construction | 14/14 |

## Chain invariants

**Part A**
- `vector[N].prev_receipt_hash == vector[N-1].receipt_hash` for seq 1–5
- `vector[N].chain_seq == vector[N-1].chain_seq + 1`
- `vector[0].prev_receipt_hash == ""`

**Part B**
- `issuer_a.chain_ref[seq] != issuer_b.chain_ref[seq]` at every shared seq position

**Part C**
- `proper_seq2.chain_ref != gap_seq2.chain_ref`

## Regulatory applicability

MiCA Art. 80 / DORA Art. 14 / AMLR Art. 56 — see the IETF I-D for normative mapping.
