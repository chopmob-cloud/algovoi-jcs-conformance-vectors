# Attestation: `retention_chain_v1` -- 8-impl cross-validation

**Date:** 2026-06-17
**Set:** `retention_chain_v1`
**Vectors:** 14 (Part A: 6-link extended chain; Part B: 4 multi-issuer isolation; Part C: 4 seq-gap adversarial pair)
**Result:** 112/112 byte-for-byte agreements (14 vectors x 8 implementations)

## Algorithm

```
retention_chain_ref = "sha256:" + SHA-256(JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}))
```

JCS key order (RFC 8785 lexicographic): `chain_seq`, `issuer_id`, `prev_receipt_hash`, `receipt_hash`.

## Implementations

| # | Language | Library | Result |
|---|---|---|---|
| 1 | Python 3 | `rfc8785@0.1.4` + `hashlib.sha256` | 14/14 |
| 2 | Node.js | `canonicalize@1.0.8` + Node.js `crypto.createHash` | 14/14 |
| 3 | Go | `github.com/gowebpki/jcs v1.0.1` + stdlib `crypto/sha256` | 14/14 |
| 4 | Ruby | `json-canonicalization 1.0.0` gem + stdlib `Digest::SHA256` | 14/14 |
| 5 | PHP 8.1+ | inline RFC 8785 + stdlib `hash("sha256")` | 14/14 |
| 6 | Rust | `serde_jcs@0.2.0` + `sha2@0.10` (pre-built binary, same crate as v0) | 14/14 |
| 7 | Java 17 | `io.github.erdtman:java-json-canonicalization 1.1` + `MessageDigest("SHA-256")` | 14/14 |
| 8 | .NET 9 | `Baqhub.Packages.JsonCanonicalization 1.0.1` + `SHA256.HashData` | 14/14 |

## Runner scripts

All standalone runners live in `vectors/retention_chain_v1/`. Each reads the vector JSON file, JCS-canonicalises the `preimage` field with the named library, base64-encodes the canonical bytes and compares to `expected_jcs_bytes_b64`, then SHA-256 hashes and prefix-encodes and compares to `expected_chain_ref`. Exit 0 on full pass, exit 1 on any mismatch.

## Vectors verified

| vector_id | part | expected_chain_ref |
|---|---|---|
| retention-chain-v1-000 | A | `sha256:60081d57e585e6a7ee0b79e1204aae2be3739a539c6524074003408b3de1951e` |
| retention-chain-v1-001 | A | `sha256:d23aeb006c5f3db9dd96315916410393904f56c4c871593065eb73b783fff35f` |
| retention-chain-v1-002 | A | `sha256:43f888f00ea70e38fb8e38c205219b3fff51a90c62197d890b9f270f0f81fe42` |
| retention-chain-v1-003 | A | `sha256:deeb8fb8d1e59de0493c26c461bf015d1461320cb54d172d36a4a0384147ae5b` |
| retention-chain-v1-004 | A | `sha256:6c76bc81c6ed4101ab15d7c2ac1c0cac255cd774665c8807586e8407b832dad5` |
| retention-chain-v1-005 | A | `sha256:e91e6f680c8c92ca2b751d8d0dcb801f4eadcfd5e590e100f4591ea3031d0d57` |
| retention-chain-v1-006 | B | `sha256:52ef8da2c45178c5f2aef027d6c1e838d1f044dabb41596a639624cea5b57f83` |
| retention-chain-v1-007 | B | `sha256:ced0cd4cc8d9446b17fca7ff57ed9508a9d5b50fce45a93d4a7e83779012810e` |
| retention-chain-v1-008 | B | `sha256:683eb369f960cdea868414ebf8fb4d692af09afa9e5b94c91dc093448117a042` |
| retention-chain-v1-009 | B | `sha256:7aa77a429f476fee8d09e6e2044b7f4c40277cbc250d9676110fb6fb68441b90` |
| retention-chain-v1-010 | C | `sha256:073252f595f2c593a93b001a3d40325108ae697ca3e47a222414b29c5defaca2` |
| retention-chain-v1-011 | C | `sha256:7ed5deb4a4451181c255c0d3aaf963ecf0ee750d3f425211c725c9afc53e99ef` |
| retention-chain-v1-012 | C | `sha256:9c589d9657146e062d4a91cf3a4bf92c98cbb6fcde0d509a84e020675ad8c7ea` |
| retention-chain-v1-013 | C | `sha256:2277ec545e5540a60b54c706b533c8962df61fb9a9c92de417d3808bd7be3cef` |

## Invariants confirmed on screen

**Part B issuer isolation** (same receipt_hash, different issuer_id, different chain_ref):
- seq=0: issuer_a `sha256:52ef8...57f83` != issuer_b `sha256:ced0c...810e`
- seq=1: issuer_a `sha256:683eb...a042` != issuer_b `sha256:7aa77...1b90`

**Part C seq-gap pair** (same chain_seq=2, same receipt_hash, different prev_receipt_hash):
- proper seq2 `sha256:9c589...c7ea` != gap seq2 `sha256:2277e...3cef`

## Test frameworks

- Python: standalone `runner_python.py` using `rfc8785@0.1.4`
- Node.js: standalone `runner_node.js` using `canonicalize@1.0.8`
- Go: standalone `runner_go.go` using `gowebpki/jcs v1.0.1` (run from v0 dir, same go.mod)
- Ruby: standalone `runner_ruby.rb` using `json-canonicalization` gem
- PHP: standalone `runner_php.php` with inline RFC 8785
- Rust: pre-built `runner_rust.exe` from v0 `target/release/` (same crate, same binary, JSON format identical)
- Java: standalone `runner_java/` using bundled JARs (`java-json-canonicalization-1.1.jar` + Jackson 2.17)
- .NET: standalone `runner_dotnet/` using `Baqhub.Packages.JsonCanonicalization 1.0.1`

All 8 implementations executed live on 2026-06-17 against `retention_chain_v1.json`. Results verified on screen.

## Cumulative

This run adds 112 directly-executed agreements to the corpus. Cumulative directly-executed JCS total: **712/712** (600 prior to this session + 112 from this v1 attestation).
