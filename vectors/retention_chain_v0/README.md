# `retention_chain_v0`

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).

> **This is an L1 substrate.** `retention_chain_v0` is the genesis conformance set for AlgoVoi's
> Retention Chain Substrate, specified in `draft-hopley-x402-retention-chain-02` (sole authorship).
> **Build L2 layers on it freely**; the one ask is the licence's: attribute the L1 — keep the
> [`NOTICE`](../../NOTICE) and import this set **by hash**
> (`sha256: a1c8a3a591980917f2a5706097094a988715b5b674bd8a0837b5a5db74269da8`).
> See the corpus [README › Attribution](../../README.md#attribution) and [ADOPTERS.md](../../ADOPTERS.md).

AlgoVoi-authored conformance vector set for the **Retention Chain Substrate** — a self-verifiable audit chain linking payment receipts without external infrastructure.

Specified in IETF Internet-Draft [`draft-hopley-x402-retention-chain-02`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/) (AlgoVoi, sole authorship, 17 June 2026).

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

## Run

```bash
bash run_all.sh                          # all 8 runners
python runner_python.py retention_chain_v0.json   # pip install rfc8785
node   runner_node.js  retention_chain_v0.json    # npm install (canonicalize)
go run runner_go.go    retention_chain_v0.json
ruby   runner_ruby.rb  retention_chain_v0.json    # gem install json-canonicalization
php    runner_php.php  retention_chain_v0.json    # requires ext-sodium
```

## Chain invariants

- `vector[N].prev_receipt_hash == vector[N-1].receipt_hash` for N > 0
- `vector[N].chain_seq == vector[N-1].chain_seq + 1` for N > 0
- `vector[0].prev_receipt_hash == ""`
- `vector[0].chain_seq == 0`

## Regulatory applicability

MiCA Art. 80 / DORA Art. 14 / AMLR Art. 56 — see the IETF I-D Section 8 for normative mapping.
