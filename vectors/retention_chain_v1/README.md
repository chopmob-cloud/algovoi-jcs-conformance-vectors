# `retention_chain_v1`

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).

> **This is an L1 substrate.** `retention_chain_v1` is the extended conformance set for AlgoVoi's
> Retention Chain Substrate, specified in `draft-hopley-x402-retention-chain-01` (sole authorship).
> **Build L2 layers on it freely**; the one ask is the licence's: attribute the L1 — keep the
> [`NOTICE`](../../NOTICE) and import this set **by hash**
> (`sha256: 7db074ad0737468c29fcfad71d5d7e70354d3710a377603585e1a899d195602a`).
> See the corpus [README › Attribution](../../README.md#attribution) and [ADOPTERS.md](../../ADOPTERS.md).

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

## Invariant classes (14 vectors in three parts)

**Part A — 6-link extended chain** (`issuer_id=algovoi:compliance`, seq 0-5)

Each vector proves: `chain_ref[N]` depends on `prev_receipt_hash = receipt_hash[N-1]`.
The full chain can be re-verified from any contiguous subset.

**Part B — multi-issuer isolation** (4 vectors: issuer_a + issuer_b, seq 0-1 each)

Same `receipt_hash` values, different `issuer_id` — chain refs must diverge.
Proves: `issuer_id` is a mandatory separator; two issuers cannot produce colliding chain refs.

**Part C — seq-gap adversarial pair** (4 vectors: correct seq2 vs gap seq2)

A correct `prev_receipt_hash` and a tampered one at the same `chain_seq` — chain refs must differ.
Proves: a gap or substitution in the chain is detectable by any receipt-adjacent party.

## Chain invariants

- `vector[N].prev_receipt_hash == vector[N-1].receipt_hash` for N > 0 within the same issuer
- `vector[N].chain_seq == vector[N-1].chain_seq + 1` for N > 0 within the same issuer
- `vector[0].prev_receipt_hash == ""`
- `vector[0].chain_seq == 0`

## Cross-validation

Cross-validated across **8 implementations in 8 programming languages**, live-run 2026-06-17, 14/14 PASS each:

| Language | Library | Result |
|---|---|---|
| Python | `rfc8785@0.1.4` + `hashlib.sha256` | 14/14 |
| Node.js | `canonicalize@1.0.8` + Node.js `crypto` | 14/14 |
| Go | `gowebpki/jcs v1.0.1` + stdlib `crypto/sha256` | 14/14 |
| Ruby | `json-canonicalization 1.0.0` + stdlib `Digest::SHA256` | 14/14 |
| PHP | inline RFC 8785 + stdlib `hash("sha256")` | 14/14 |
| Rust | `serde_jcs@0.2.0` + `sha2@0.10` | 14/14 |
| Java 17 | `java-json-canonicalization 1.1` + `MessageDigest("SHA-256")` | 14/14 |
| .NET 9 | `Baqhub.Packages.JsonCanonicalization 1.0.1` + `SHA256.HashData` | 14/14 |

## Run

```bash
bash run_all.sh                          # all 8 runners
python runner_python.py retention_chain_v1.json   # pip install rfc8785
node   runner_node.js  retention_chain_v1.json    # npm install (canonicalize)
go run runner_go.go    retention_chain_v1.json
ruby   runner_ruby.rb  retention_chain_v1.json    # gem install json-canonicalization
php    runner_php.php  retention_chain_v1.json    # requires ext-sodium
```

Each prints `N/14 PASS` and exits 0 on success.

## Regulatory applicability

MiCA Art. 80 / DORA Art. 14 / AMLR Art. 56 — see the IETF I-D Section 8 for normative mapping.
