# `retention_chain_v0`

> **License: AlgoVoi Commercial Software License**
> The conformance vectors, runner scripts, and all files in this directory are proprietary.
> Use requires a signed commercial licence from AlgoVoi.
> The Retention Chain Substrate is included as standard in every Substrate 2 licence.
> Contact: chopmob@gmail.com

AlgoVoi-authored conformance vector set for the **Retention Chain Substrate** — a self-verifiable audit chain linking payment receipts without external infrastructure.

Specified in IETF Internet-Draft [`draft-hopley-x402-retention-chain-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/) (AlgoVoi, sole authorship, 16 June 2026).

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

The three vectors cover:
- **Vector 0**: genesis record (`chain_seq=0`, `prev_receipt_hash=""`)
- **Vector 1**: first chain link (`chain_seq=1`, `prev_receipt_hash` = Vector 0's `receipt_hash`)
- **Vector 2**: second chain link (`chain_seq=2`, `prev_receipt_hash` = Vector 1's `receipt_hash`)

## Cross-validation

Cross-validated across **8 implementations in 8 programming languages** — all live-run 2026-06-16, 3/3 PASS each:

| Language | Library | Result |
|---|---|---|
| Python | `rfc8785@0.1.4` + `hashlib.sha256` | 3/3 |
| Node.js | `canonicalize@1.0.8` + Node.js `crypto` | 3/3 |
| Go | `gowebpki/jcs v1.0.1` + stdlib `crypto/sha256` | 3/3 |
| Ruby | `json-canonicalization 1.0.0` + stdlib `Digest::SHA256` | 3/3 |
| PHP | inline RFC 8785 + stdlib `hash("sha256")` | 3/3 |
| Rust | `serde_jcs@0.2.0` + `sha2@0.10` | 3/3 |
| Java 17 | `java-json-canonicalization 1.1` + `MessageDigest("SHA-256")` | 3/3 |
| .NET 9 | `Baqhub.Packages.JsonCanonicalization 1.0.1` + `SHA256.HashData` | 3/3 |

Kotlin runner (`runner_kotlin/`) written against the same JVM library as Java; requires Gradle + Kotlin/JVM to run.

## Chain invariants

- `vector[N].prev_receipt_hash == vector[N-1].receipt_hash` for N > 0
- `vector[N].chain_seq == vector[N-1].chain_seq + 1` for N > 0
- `vector[0].prev_receipt_hash == ""`
- `vector[0].chain_seq == 0`

## Regulatory applicability

MiCA Art. 80 / DORA Art. 14 / AMLR Art. 56 — see the IETF I-D Section 8 for normative mapping.
