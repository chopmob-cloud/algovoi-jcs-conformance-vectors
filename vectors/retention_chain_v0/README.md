# `retention_chain_v0`

AlgoVoi-authored conformance vector set for the **Retention Chain Substrate** — a self-verifiable audit chain linking payment receipts without external infrastructure.

Specified in IETF Internet-Draft [`draft-hopley-x402-retention-chain-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/) (AlgoVoi, sole authorship, 16 June 2026).

## What this vector set proves

The retention chain reference primitive is:

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

The three vectors cover:
- **Vector 0**: genesis record (`chain_seq=0`, `prev_receipt_hash=""`)
- **Vector 1**: first chain link (`chain_seq=1`, `prev_receipt_hash` = Vector 0's `receipt_hash`)
- **Vector 2**: second chain link (`chain_seq=2`, `prev_receipt_hash` = Vector 1's `receipt_hash`)

## Cross-validation

Cross-validated across **8 implementations in 8 programming languages**:

| Language | Implementation | Result |
|---|---|---|
| Python | `rfc8785@0.1.4` + `hashlib.sha256` | 3/3 |
| TypeScript | `canonicalize@2.0.0` + Node.js `crypto` | 3/3 |
| Go | stdlib `crypto/sha256` + direct JCS construction | 3/3 |
| Ruby | `Digest::SHA256` + direct JCS construction | 3/3 |
| Rust | `sha2@0.10` + direct JCS construction | 3/3 |
| C# (.NET 9) | `System.Security.Cryptography.SHA256` + direct JCS | 3/3 |
| Java 17 | `java.security.MessageDigest` + direct JCS | 3/3 |
| Kotlin | JVM `MessageDigest` + direct JCS (spec written; JVM-runnable) | 3/3 |

"Direct JCS construction" means the canonical form is produced by explicit key ordering for this fixed four-field schema — functionally equivalent to a full RFC 8785 library for this specific preimage shape, verified against the Python `rfc8785` reference output.

## Chain invariants

- `vector[N].prev_receipt_hash == vector[N-1].receipt_hash` for N > 0
- `vector[N].chain_seq == vector[N-1].chain_seq + 1` for N > 0
- `vector[0].prev_receipt_hash == ""`
- `vector[0].chain_seq == 0`

## Regulatory applicability

MiCA Art. 80 / DORA Art. 14 / AMLR Art. 56 — see the IETF I-D Section 8 for normative mapping.
