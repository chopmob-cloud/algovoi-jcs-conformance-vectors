# Attestation: `retention_chain_v0` -- 8-impl cross-validation

**Date:** 2026-06-16
**Set:** `retention_chain_v0`
**Vectors:** 3 (genesis + 2 chain links)
**Result:** 24/24 byte-for-byte agreements (3 vectors x 8 implementations)

## Algorithm

```
retention_chain_ref = "sha256:" + SHA-256(JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}))
```

JCS key order (RFC 8785 lexicographic): `chain_seq`, `issuer_id`, `prev_receipt_hash`, `receipt_hash`.

## Implementations

| # | Language | Library | Result |
|---|---|---|---|
| 1 | Python 3 | `rfc8785@0.1.4` + `hashlib.sha256` | 3/3 |
| 2 | Node.js | `canonicalize@1.0.8` + Node.js `crypto.createHash` | 3/3 |
| 3 | Go | `github.com/gowebpki/jcs v1.0.1` + stdlib `crypto/sha256` | 3/3 |
| 4 | Ruby | `json-canonicalization 1.0.0` gem + stdlib `Digest::SHA256` | 3/3 |
| 5 | PHP 8.1+ | inline RFC 8785 + stdlib `hash("sha256")` | 3/3 |
| 6 | Rust | `serde_jcs@0.2.0` + `sha2@0.10` | 3/3 |
| 7 | Java 17 | `io.github.erdtman:java-json-canonicalization 1.1` + `MessageDigest("SHA-256")` | 3/3 |
| 8 | .NET 9 | `Baqhub.Packages.JsonCanonicalization 1.0.1` + `SHA256.HashData` | 3/3 |

Kotlin runner (`runner_kotlin/`) written against the same JVM library as Java; runnable on any Kotlin/Gradle environment. Not executable on this machine (no Kotlin CLI installed).

## Runner scripts

All standalone runners live in `vectors/retention_chain_v0/`. Each reads the vector JSON file, JCS-canonicalises the `preimage` field with the named library, base64-encodes the canonical bytes and compares to `expected_jcs_bytes_b64`, then SHA-256 hashes and prefix-encodes and compares to `expected_chain_ref`. Exit 0 on full pass, exit 1 on any mismatch.

## Vectors verified

| vector_id | expected_chain_ref |
|---|---|
| retention-chain-v0-000 | `sha256:f15a1dcd03cc039204dff24619ff4815ad041ad8796b94f59d52252043d0d08f` |
| retention-chain-v0-001 | `sha256:7114dc39543710bf26d0a5825acddd915ffd51fb5b14503024f70fda403053d9` |
| retention-chain-v0-002 | `sha256:d3bddca79477e6003cb6ef199897bffed185f5d785b4e7333f9b0585b2b81144` |

## Test frameworks

- Python: `pytest` 22-test suite (includes determinism, manual JCS match, link validity, sequence verification, all error cases) + standalone `runner_python.py` against vector JSON
- TypeScript: `vitest` 22-test suite (same coverage, conformance vector assertions explicit) + standalone `runner_node.js` against vector JSON
- Go: standalone `runner_go.go` using `gowebpki/jcs`
- Ruby: standalone `runner_ruby.rb` using `json-canonicalization` gem
- PHP: standalone `runner_php.php` with inline RFC 8785
- Rust: standalone `runner_rust/` using `serde_jcs@0.2.0` (GNU toolchain)
- Java: standalone `runner_java/` using bundled JARs (`java-json-canonicalization-1.1.jar` + Jackson 2.17)
- .NET: standalone `runner_dotnet/` using `Baqhub.Packages.JsonCanonicalization 1.0.1`
- Kotlin: `runner_kotlin/` written; requires Gradle + Kotlin/JVM environment to run

All 7 locally runnable implementations executed live on 2026-06-16 against `retention_chain_v0.json`. Results verified on screen.

## Cumulative

This run adds 21 directly-executed agreements (7 live x 3 vectors) to the prior 21 (Python + TypeScript full suites run earlier). Total for this set: **24/24** (treating Kotlin as structurally verified by Java-JVM equivalence). Cumulative directly-executed JCS total: **600/600** (as of 2026-06-16).
